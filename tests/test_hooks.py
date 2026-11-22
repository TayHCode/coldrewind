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
            if key not in {"CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"}
        }
        self.env.update(HOME=str(self.home), PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        self.registry = Registry(self.home / ".local" / "state" / "coldrewind")

        self.claude = self.home / ".claude" / "settings.json"
        self.codex = self.home / ".codex" / "hooks.json"
        self.plugins = self.home / ".config" / "opencode" / "plugins"
        for path, data in ((self.claude, CLAUDE_SETTINGS), (self.codex, CODEX_HOOKS)):
            path.parent.mkdir(parents=True)
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
        self.assertEqual(sorted(path.name for path in self.plugins.iterdir()), ["other.js"])
        self.assertEqual(tree(self.root), before)

        self.assertEqual(self.cli("uninstall").stdout, "")

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
