import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

from coldrewind import hooks, init_cmd, retention, snapshot
from coldrewind.config import Registry
from coldrewind.ledger import read_steps
from coldrewind.paths import file_lock
from coldrewind.snapshot import read_manifest

CLAUDE_SETTINGS = {
    "model": "opus",
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "guard.sh"}]},
            {"hooks": [{"type": "command", "command": "echo coldrewind.cli hook claude pre"}]},
            {"hooks": [{"type": "command", "command": "log.sh && python3 -P -m coldrewind.cli hook claude pre"}]},
        ],
        "Stop": [{"hooks": [{"type": "command", "command": "stop.sh"}]}],
    },
}
CODEX_HOOKS = {
    "description": "mine",
    "hooks": {"PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "review.sh"}]}]},
}
CURSOR_HOOKS = {
    "version": 1,
    "hooks": {"beforeShellExecution": [{"command": "audit.sh"}]},
}
ANTIGRAVITY_HOOKS = {
    "lint-checker": {
        "PostToolUse": [{"matcher": "run_command", "hooks": [{"type": "command", "command": "lint.sh"}]}],
    },
}
GEMINI_SETTINGS = {
    "theme": "Default",
    "hooks": {"BeforeTool": [{"matcher": "write_file", "hooks": [{"type": "command", "command": "check.sh"}]}]},
}


def tree(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


class TestHooks(unittest.TestCase):
    def setUp(self) -> None:
        base = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.home = base / "home"
        self.root = base / "workspace"
        self.root.mkdir()
        (self.root / "notes.txt").write_text("v0")
        self.env = {
            key: value for key, value in os.environ.items()
            if key not in {
                "CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME",
                "CURSOR_CONFIG_DIR", "ANTIGRAVITY_CONFIG_DIR", "GEMINI_CONFIG_DIR",
                "COLDREWIND_GUARD", "COLDREWIND_SNAPSHOT_MIN_INTERVAL_SECONDS",
            }
        }
        self.env.update(HOME=str(self.home), PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        self.registry = Registry(self.home / ".local" / "state" / "coldrewind")

        self.claude = self.home / ".claude" / "settings.json"
        self.codex = self.home / ".codex" / "hooks.json"
        self.plugins = self.home / ".config" / "opencode" / "plugins"
        self.cursor = self.home / ".cursor" / "hooks.json"
        self.antigravity = self.home / ".gemini" / "config" / "hooks.json"
        self.gemini = self.home / ".gemini" / "settings.json"
        for path, data in (
            (self.claude, CLAUDE_SETTINGS),
            (self.codex, CODEX_HOOKS),
            (self.cursor, CURSOR_HOOKS),
            (self.antigravity, ANTIGRAVITY_HOOKS),
            (self.gemini, GEMINI_SETTINGS),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data))
        self.plugins.mkdir(parents=True)
        (self.plugins / "other.js").write_text("export const Other = async () => ({})\n")

    def cli(self, *args: str, stdin: str = "", cwd: Path | None = None):
        return subprocess.run(
            [sys.executable, "-m", "coldrewind.cli", *args], input=stdin, cwd=cwd or self.root,
            env=self.env, capture_output=True, text=True, timeout=30,
        )

    def installed(self, path: Path, event: str) -> list[str]:
        groups = json.loads(path.read_text())["hooks"][event]
        return [
            handler["command"] for group in groups for handler in group["hooks"]
            if shlex.split(handler["command"])[:1] == [sys.executable]
        ]

    def fire(self, client: str, phase: str, payload: dict) -> None:
        stdin = json.dumps(payload)
        if client == "opencode":
            result = self.cli("hook", "opencode", phase, stdin=stdin)
        else:
            path = self.claude if client == "claude" else self.codex
            event = "PreToolUse" if phase == "pre" else "PostToolUse"
            command, = self.installed(path, event)
            result = subprocess.run(
                command, shell=True, input=stdin, cwd=self.root, env=self.env,
                capture_output=True, text=True, timeout=30,
            )
        self.assertEqual((result.returncode, result.stderr), (0, ""))

    def test_init_preserves_foreign_hooks_and_backs_up(self) -> None:
        result = self.cli("init")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.registry.roots(), (self.root,))

        for path, original in ((self.claude, CLAUDE_SETTINGS), (self.codex, CODEX_HOOKS)):
            backup, = path.parent.glob(f"{path.name}.coldrewind-backup-*")
            self.assertEqual(json.loads(backup.read_text()), original)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        settings = json.loads(self.claude.read_text())
        self.assertEqual(settings["model"], "opus")
        self.assertEqual(settings["hooks"]["Stop"], CLAUDE_SETTINGS["hooks"]["Stop"])
        self.assertEqual(settings["hooks"]["PreToolUse"][:3], CLAUDE_SETTINGS["hooks"]["PreToolUse"])
        self.assertEqual(len(self.installed(self.claude, "PostToolUseFailure")), 1)
        self.assertNotIn("PostToolUseFailure", json.loads(self.codex.read_text())["hooks"])
        self.assertEqual(json.loads(self.codex.read_text())["description"], "mine")
        plugin = (self.plugins / "coldrewind.js").read_text()
        for needle in ('"tool.execute.before"', '"tool.execute.after"', "input.callID", json.dumps(sys.executable)):
            self.assertIn(needle, plugin)

        self.assertEqual(self.cli("init").returncode, 0)
        for path in (self.claude, self.codex):
            for event in ("PreToolUse", "PostToolUse"):
                self.assertEqual(len(self.installed(path, event)), 1)

    def test_three_clients_and_run_share_one_chronological_timeline(self) -> None:
        self.assertEqual(self.cli("init").returncode, 0)
        notes = self.root / "notes.txt"
        edits = (
            ("claude", {"tool_name": "Write", "tool_input": {"file_path": str(notes)}}, "v1"),
            ("codex", {"tool_name": "Bash", "tool_input": {"command": "printf v2 > notes.txt"}}, "v2"),
            ("opencode", {"tool_name": "edit", "tool_input": {"filePath": str(notes)}}, "v3"),
        )
        for number, (client, tool, content) in enumerate(edits):
            payload = {"session_id": "s", "tool_use_id": f"call-{number}", "cwd": str(self.root), **tool}
            self.fire(client, "pre", payload)
            notes.write_text(content)
            self.fire(client, "post", {**payload, "tool_response": {}})
        result = self.cli("run", "--", "sh", "-c", "printf v4 > notes.txt")
        self.assertEqual(result.returncode, 0, result.stderr)

        steps = read_steps(self.registry, self.root)
        self.assertEqual([step.agent for step in steps], ["Claude Code", "Codex", "OpenCode", "run"])
        self.assertEqual([step.command[0] for step in steps], ["Write", "bash", "edit", "sh"])
        self.assertEqual(steps[1].command, ("bash", "[REDACTED]"))
        self.assertEqual([step.timestamp for step in steps], sorted(step.timestamp for step in steps))
        self.assertTrue(all(step.changed_paths == ("notes.txt",) for step in steps))
        self.assertTrue(all(step.reversibility != "reversible" for step in steps))

        blobs = self.registry.store_path(self.root) / "blobs"
        states = []
        for previous, step in zip([None, *steps], steps):
            if previous is not None:
                self.assertEqual(step.pre_snapshot_id, previous.post_snapshot_id)
            states.append(read_manifest(self.registry, self.root, step.pre_snapshot_id))
        states.append(read_manifest(self.registry, self.root, steps[-1].post_snapshot_id))
        contents = [
            (blobs / state["files"]["notes.txt"]["sha256"]).read_text() for state in states
        ]
        self.assertEqual(contents, ["v0", "v1", "v2", "v3", "v4"])
        self.assertEqual(list((self.registry.store_path(self.root) / "pending").iterdir()), [])

    def test_hook_never_blocks_the_agent(self) -> None:
        self.assertEqual(self.cli("init").returncode, 0)
        outside = self.home / "elsewhere"
        outside.mkdir()
        payload = {"session_id": "s", "tool_use_id": "t", "cwd": str(outside), "tool_name": "Write"}
        for stdin in (json.dumps(payload), "not json", "[]", json.dumps({**payload, "cwd": "relative"})):
            for phase in ("pre", "post"):
                result = self.cli("hook", "claude", phase, stdin=stdin)
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(read_steps(self.registry, self.root), [])

    def test_post_without_pre_records_unrestorable_step(self) -> None:
        self.assertEqual(self.cli("init").returncode, 0)
        payload = {"session_id": "s", "tool_use_id": "t", "cwd": str(self.root), "tool_name": "Write"}
        self.fire("codex", "post", payload)
        step, = read_steps(self.registry, self.root)
        self.assertEqual((step.agent, step.pre_snapshot_id, step.reversibility), ("Codex", None, "irreversible"))

    def test_post_records_step_when_pre_manifest_is_missing(self) -> None:
        self.registry.register(self.root)
        payload = {"tool_use_id": "t", "cwd": str(self.root), "tool_name": "Write"}
        hooks.handle(self.registry, "claude", "pre", payload)
        store = self.registry.store_path(self.root)
        marker, = (store / "pending").iterdir()
        (store / "snapshots" / f"{marker.read_text()}.json").unlink()
        (self.root / "notes.txt").write_bytes(b"after")
        hooks.handle(self.registry, "claude", "post", payload)
        step, = read_steps(self.registry, self.root)
        self.assertEqual((step.pre_snapshot_id, step.reversibility), (None, "irreversible"))
        after = read_manifest(self.registry, self.root, step.post_snapshot_id)
        self.assertEqual(after["files"]["notes.txt"]["sha256"], hashlib.sha256(b"after").hexdigest())
        self.assertFalse(marker.exists())

    def test_prune_removes_stale_temporary_files_and_preserves_live_entries(self) -> None:
        self.registry.register(self.root)
        payload = {"tool_use_id": "t", "cwd": str(self.root), "tool_name": "Write"}
        hooks.handle(self.registry, "claude", "pre", payload)
        pending = self.registry.store_path(self.root) / "pending"
        hook, = pending.iterdir()
        with tempfile.NamedTemporaryFile(dir=pending, delete=False) as legacy:
            pass
        stale_files = [Path(legacy.name), pending / ".tmp-abcd1234"]
        stale_files[1].touch()
        for path in stale_files:
            os.utime(path, (1, 1))
        fresh = pending / ".tmp-fresh123"
        fresh.touch()
        run = pending / ("run." + "a" * 32)
        run.write_text(hook.read_text())
        os.utime(run, (1, 1))
        with file_lock(run):
            retention.prune(self.registry, self.root)
            self.assertEqual(set(pending.iterdir()), {hook, run, fresh})
            run.write_bytes(b"")
            retention.prune(self.registry, self.root)
            self.assertTrue(run.exists())
        retention.prune(self.registry, self.root)
        self.assertFalse(run.exists())

    def test_uninstall_removes_only_coldrewind_entries(self) -> None:
        before = tree(self.root)
        self.assertEqual(self.cli("init").returncode, 0)
        settings = json.loads(self.claude.read_text())
        settings["hooks"]["PostToolUse"].append({"hooks": [{"type": "command", "command": "later.sh"}]})
        self.claude.write_text(json.dumps(settings))
        expected_claude = json.loads(json.dumps(CLAUDE_SETTINGS))
        expected_claude["hooks"]["PostToolUse"] = [{"hooks": [{"type": "command", "command": "later.sh"}]}]

        result = self.cli("uninstall")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.claude.read_text()), expected_claude)
        self.assertEqual(json.loads(self.codex.read_text()), CODEX_HOOKS)
        self.assertEqual(json.loads(self.cursor.read_text()), CURSOR_HOOKS)
        self.assertEqual(json.loads(self.antigravity.read_text()), ANTIGRAVITY_HOOKS)
        self.assertEqual(json.loads(self.gemini.read_text()), GEMINI_SETTINGS)
        self.assertEqual(sorted(path.name for path in self.plugins.iterdir()), ["other.js"])
        self.assertEqual(tree(self.root), before)

        self.assertEqual(self.cli("uninstall").stdout, "")

    def test_cursor_antigravity_and_gemini_init_capture_and_uninstall(self) -> None:
        self.assertEqual(self.cli("init").returncode, 0)

        # Verify each client's real config schema and preservation of foreign hooks.
        cursor_data = json.loads(self.cursor.read_text())
        self.assertEqual(cursor_data["version"], 1)
        self.assertEqual(cursor_data["hooks"]["beforeShellExecution"], CURSOR_HOOKS["hooks"]["beforeShellExecution"])
        self.assertEqual(len(cursor_data["hooks"]["preToolUse"]), 1)
        self.assertEqual(len(cursor_data["hooks"]["postToolUse"]), 1)
        self.assertEqual(len(cursor_data["hooks"]["postToolUseFailure"]), 1)
        self.assertEqual(cursor_data["hooks"]["preToolUse"][0]["timeout"], init_cmd.HOOK_TIMEOUT_SECONDS)

        ag_data = json.loads(self.antigravity.read_text())
        self.assertEqual(ag_data["lint-checker"], ANTIGRAVITY_HOOKS["lint-checker"])
        self.assertEqual(ag_data["coldrewind"]["PreToolUse"][0]["matcher"], "*")
        self.assertEqual(ag_data["coldrewind"]["PostToolUse"][0]["matcher"], "*")
        self.assertEqual(ag_data["coldrewind"]["PreToolUse"][0]["hooks"][0]["timeout"], init_cmd.HOOK_TIMEOUT_SECONDS)

        gem_data = json.loads(self.gemini.read_text())
        self.assertEqual(gem_data["theme"], "Default")
        self.assertEqual(gem_data["hooks"]["BeforeTool"][0], GEMINI_SETTINGS["hooks"]["BeforeTool"][0])
        gem_pre = gem_data["hooks"]["BeforeTool"][1]["hooks"][0]
        gem_post = gem_data["hooks"]["AfterTool"][0]["hooks"][0]
        self.assertEqual(gem_pre["name"], "coldrewind-pre")
        self.assertEqual(gem_pre["timeout"], init_cmd.HOOK_TIMEOUT_SECONDS * 1000)
        self.assertEqual(gem_post["name"], "coldrewind-post")

        # Fire real-schema events through the installed commands for Cursor, Antigravity, and Gemini CLI.
        notes = self.root / "notes.txt"
        cursor_pre_cmd = cursor_data["hooks"]["preToolUse"][0]["command"]
        cursor_post_cmd = cursor_data["hooks"]["postToolUse"][0]["command"]
        cursor_payload = {
            "hook_event_name": "preToolUse",
            "conversation_id": "conv-1",
            "tool_use_id": "tu-1",
            "workspace_roots": [str(self.root)],
            "tool_name": "Shell",
            "tool_input": {"command": "printf cursor > notes.txt"},
        }
        r = subprocess.run(cursor_pre_cmd, shell=True, input=json.dumps(cursor_payload),
                           cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(json.loads(r.stdout), {"permission": "allow"})
        notes.write_text("cursor")
        r = subprocess.run(cursor_post_cmd, shell=True,
                           input=json.dumps({**cursor_payload, "hook_event_name": "postToolUse"}),
                           cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(json.loads(r.stdout), {})

        ag_pre_cmd = ag_data["coldrewind"]["PreToolUse"][0]["hooks"][0]["command"]
        ag_post_cmd = ag_data["coldrewind"]["PostToolUse"][0]["hooks"][0]["command"]
        ag_payload = {
            "conversationId": "conv-ag",
            "workspacePaths": [str(self.root)],
            "cwd": str(self.root),
            "hookEventName": "PreToolUse",
            "toolCall": {"id": "toolu_ag1", "name": "run_command", "args": {"CommandLine": "printf ag > notes.txt"}},
        }
        r = subprocess.run(ag_pre_cmd, shell=True, input=json.dumps(ag_payload),
                           cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(json.loads(r.stdout), {"decision": "allow"})
        notes.write_text("antigravity")
        r = subprocess.run(ag_post_cmd, shell=True,
                           input=json.dumps({**ag_payload, "hookEventName": "PostToolUse"}),
                           cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(json.loads(r.stdout), {})

        # Gemini CLI BeforeTool / AfterTool without tool_use_id (documented base payload).
        gem_payload = {
            "session_id": "sess-gem",
            "cwd": str(self.root),
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "printf gem > notes.txt"},
        }
        r = subprocess.run(gem_pre["command"], shell=True, input=json.dumps(gem_payload),
                           cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(json.loads(r.stdout), {"decision": "allow"})
        notes.write_text("gemini")
        r = subprocess.run(gem_post["command"], shell=True,
                           input=json.dumps({**gem_payload, "hook_event_name": "AfterTool", "tool_response": {}}),
                           cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertEqual(json.loads(r.stdout), {})

        steps = read_steps(self.registry, self.root)
        self.assertEqual([step.agent for step in steps], ["Cursor", "Antigravity", "Gemini CLI"])
        self.assertTrue(all(step.changed_paths == ("notes.txt",) for step in steps))
        self.assertTrue(all(step.pre_snapshot_id and step.post_snapshot_id for step in steps))
        self.assertEqual(list((self.registry.store_path(self.root) / "pending").iterdir()), [])

        # Undo all three steps cleanly back to v0.
        for step in reversed(steps):
            self.assertEqual(self.cli("undo", str(step.step_id)).returncode, 0)
        self.assertEqual(notes.read_text(), "v0")

    def test_new_client_config_dir_overrides_and_malformed_rejection(self) -> None:
        custom_cursor = self.home / "custom-cursor"
        custom_ag = self.home / "custom-ag"
        custom_gem = self.home / "custom-gem"
        self.env.update(
            CURSOR_CONFIG_DIR=str(custom_cursor),
            ANTIGRAVITY_CONFIG_DIR=str(custom_ag),
            GEMINI_CONFIG_DIR=str(custom_gem),
        )
        res = self.cli("init", "--client", "cursor", "--client", "antigravity", "--client", "gemini")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue((custom_cursor / "hooks.json").is_file())
        self.assertTrue((custom_ag / "hooks.json").is_file())
        self.assertTrue((custom_gem / "settings.json").is_file())
        self.assertEqual(json.loads(self.cursor.read_text()), CURSOR_HOOKS)
        self.assertEqual(json.loads(self.antigravity.read_text()), ANTIGRAVITY_HOOKS)
        self.assertEqual(json.loads(self.gemini.read_text()), GEMINI_SETTINGS)

        # Malformed Cursor version refuses without modifying any config.
        (custom_cursor / "hooks.json").write_text(json.dumps({"version": "bad", "hooks": {}}))
        ag_before = (custom_ag / "hooks.json").read_bytes()
        bad = self.cli("init", "--client", "cursor", "--client", "antigravity")
        self.assertEqual(bad.returncode, 2)
        self.assertIn("expected integer 'version'", bad.stderr)
        self.assertEqual((custom_ag / "hooks.json").read_bytes(), ag_before)

    def test_init_refuses_malformed_config_without_writing(self) -> None:
        self.codex.write_text(json.dumps({"hooks": {"PreToolUse": {"not": "a list"}}}))
        claude_before = self.claude.read_bytes()
        result = self.cli("init")
        self.assertEqual(result.returncode, 2)
        self.assertIn("malformed PreToolUse", result.stderr)
        self.assertEqual(self.claude.read_bytes(), claude_before)
        self.assertFalse((self.plugins / "coldrewind.js").exists())

    def test_init_writes_through_symlinked_config(self) -> None:
        real = self.home / "dotfiles" / "settings.json"
        real.parent.mkdir()
        self.claude.rename(real)
        self.claude.symlink_to(real)
        self.assertEqual(self.cli("init", "--client", "claude").returncode, 0)
        self.assertTrue(self.claude.is_symlink())
        self.assertEqual(len(self.installed(real, "PreToolUse")), 1)

    def test_workspace_module_cannot_shadow_the_hook(self) -> None:
        self.assertEqual(self.cli("init").returncode, 0)
        shadow = self.root / "coldrewind"
        shadow.mkdir()
        (shadow / "__init__.py").write_text("raise SystemExit(2)\n")
        self.env["PYTHONPATH"] = "."
        payload = {"session_id": "s", "tool_use_id": "t", "cwd": str(self.root), "tool_name": "Write"}
        self.fire("claude", "pre", payload)
        self.fire("claude", "post", payload)
        step, = read_steps(self.registry, self.root)
        self.assertEqual(step.agent, "Claude Code")

    def test_lookalike_or_symlinked_opencode_plugin_is_left_alone(self) -> None:
        plugin = self.plugins / "coldrewind.js"
        plugin.write_text("// -P -m coldrewind.cli hook opencode\nexport const Mine = async () => ({})\n")
        result = self.cli("init")
        self.assertEqual(result.returncode, 2)
        self.assertIn("is not this ColdRewind's plugin", result.stderr)
        self.assertEqual(self.cli("uninstall", "--client", "opencode").returncode, 2)
        self.assertTrue(plugin.exists())

        dotfile = self.home / "dotfiles" / "coldrewind.js"
        dotfile.parent.mkdir()
        plugin.rename(dotfile)
        plugin.symlink_to(dotfile)
        for command in ("init", "uninstall"):
            result = self.cli(command, "--client", "opencode")
            self.assertEqual(result.returncode, 2)
            self.assertIn("symlink", result.stderr)
        self.assertTrue(dotfile.exists())

        plugin.unlink()
        os.mkfifo(plugin)
        result = self.cli("init", "--client", "opencode")
        self.assertEqual(result.returncode, 2)
        self.assertIn("not a regular file", result.stderr)

    def test_legacy_opencode_plugin_can_be_upgraded_and_uninstalled(self) -> None:
        plugin = self.plugins / "coldrewind.js"
        python, _, _, code = init_cmd._launcher()
        legacy_text = init_cmd._PLUGIN_LEGACY % json.dumps([python, code])
        plugin.write_text(legacy_text)

        # Upgrade via init replaces legacy plugin with the new exit-2-enforcing plugin.
        up = self.cli("init", "--client", "opencode")
        self.assertEqual(up.returncode, 0, up.stderr)
        upgraded = plugin.read_text()
        self.assertNotEqual(upgraded, legacy_text)
        self.assertIn("result.exitCode === 2", upgraded)

        # Legacy plugin can also be directly uninstalled without upgrading first.
        plugin.write_text(legacy_text)
        un = self.cli("uninstall", "--client", "opencode")
        self.assertEqual(un.returncode, 0, un.stderr)
        self.assertFalse(plugin.exists())

    def test_claude_config_dir_is_honoured(self) -> None:
        profile = self.home / "profile"
        self.env["CLAUDE_CONFIG_DIR"] = str(profile)
        self.assertEqual(self.cli("init", "--client", "claude").returncode, 0)
        self.assertEqual(len(self.installed(profile / "settings.json", "PreToolUse")), 1)
        self.assertEqual(json.loads(self.claude.read_text()), CLAUDE_SETTINGS)

    def test_concurrent_config_edit_aborts_write(self) -> None:
        raw = self.claude.read_bytes()
        self.claude.write_text(json.dumps({"edited": True}))
        with self.assertRaisesRegex(ValueError, "changed during ColdRewind setup"):
            init_cmd._apply(self.claude, raw, "{}", True)
        self.assertEqual(json.loads(self.claude.read_text()), {"edited": True})
        self.assertEqual(list(self.claude.parent.glob("*.coldrewind-backup-*")), [])

    def test_edit_during_backup_aborts_write(self) -> None:
        raw = self.claude.read_bytes()
        write_new = init_cmd._write_new

        def edit_while_backing_up(directory, data, mode):
            temporary = write_new(directory, data, mode)
            if data == raw:
                self.claude.write_text(json.dumps({"edited": True}))
            return temporary

        with unittest.mock.patch.object(init_cmd, "_write_new", edit_while_backing_up):
            with self.assertRaisesRegex(ValueError, "changed during ColdRewind setup"):
                init_cmd._apply(self.claude, raw, "{}", True)
        self.assertEqual(json.loads(self.claude.read_text()), {"edited": True})
        backup, = self.claude.parent.glob("settings.json.coldrewind-backup-*")
        self.assertEqual(backup.read_bytes(), raw)

    def test_non_regular_marker_does_not_hang_post(self) -> None:
        self.assertEqual(self.cli("init").returncode, 0)
        payload = {"session_id": "s", "tool_use_id": "t", "cwd": str(self.root), "tool_name": "Write"}
        self.fire("claude", "pre", payload)
        marker, = (self.registry.store_path(self.root) / "pending").iterdir()
        marker.unlink()
        os.mkfifo(marker)
        result = self.cli("hook", "claude", "post", stdin=json.dumps(payload))
        self.assertEqual(result.returncode, 0)
        self.assertIn("not a regular file", result.stderr)

    def test_prune_between_pre_and_post_keeps_the_pending_pre_snapshot(self) -> None:
        self.registry.register(self.root)
        target = self.root / "pruned.txt"
        target.write_text("before\n")
        payload = {"session_id": "s", "tool_use_id": "t", "cwd": str(self.root), "tool_name": "Write"}
        with unittest.mock.patch.object(retention, "MAX_BYTES", 0):
            hooks.handle(self.registry, "claude", "pre", payload)
            marker, = (self.registry.store_path(self.root) / "pending").iterdir()
            pre_id = marker.read_text()
            for version in range(3):
                target.write_text(f"other {version}\n")
                snapshot.take(self.registry, self.root)
            target.write_text("after\n")
            hooks.handle(self.registry, "claude", "post", payload)
        step, = read_steps(self.registry, self.root)
        self.assertEqual(step.pre_snapshot_id, pre_id)
        self.assertEqual(step.changed_paths, ("pruned.txt",))
        self.assertIn("pruned.txt", read_manifest(self.registry, self.root, pre_id)["files"])

    def test_bad_or_stale_pending_entries_do_not_break_capture(self) -> None:
        self.registry.register(self.root)
        payload = {"session_id": "s", "tool_use_id": "t", "cwd": str(self.root), "tool_name": "Write"}
        hooks.handle(self.registry, "claude", "pre", payload)
        pending = self.registry.store_path(self.root) / "pending"
        marker, = pending.iterdir()
        unreadable = pending / ("0" * 64)
        unreadable.write_text("1" * 64)
        unreadable.chmod(0)
        (pending / "tmpabc").write_text(marker.read_text())
        stale = time.time() - retention.MAX_AGE_SECONDS - 60
        os.utime(marker, (stale, stale))
        self.assertEqual(snapshot.pending_ids(pending.parent), frozenset())
        snapshot.take(self.registry, self.root)
        hooks.handle(self.registry, "claude", "post", payload)
        step, = read_steps(self.registry, self.root)
        self.assertIsNone(step.pre_snapshot_id)

    def test_stalled_lock_times_out_without_blocking(self) -> None:
        self.registry.register(self.root)
        payload = {"session_id": "s", "tool_use_id": "t", "cwd": str(self.root), "tool_name": "Write"}
        with self.registry.workspace_lock(self.root) as store:
            (store / "pending").mkdir()
        original = hooks.TIMEOUT_SECONDS
        hooks.TIMEOUT_SECONDS = 1
        self.addCleanup(setattr, hooks, "TIMEOUT_SECONDS", original)
        with self.registry.workspace_lock(self.root):
            self.assertEqual(
                hooks.main(self.registry, "claude", "pre", io.StringIO(json.dumps(payload))), 0
            )
        self.assertEqual(list((store / "pending").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
