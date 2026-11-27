import io
import json
import os
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from coldrewind import guard, hooks, ledger, snapshot
from coldrewind.config import Registry
from coldrewind.ledger import read_steps
from coldrewind.snapshot import read_manifest


class TestGuardClassifier(unittest.TestCase):
    def setUp(self) -> None:
        base = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.root = base / "workspace"
        self.subdir = self.root / "src"
        self.outside = base / "outside"
        self.subdir.mkdir(parents=True)
        self.outside.mkdir()

    def check(self, shell_cmd: str, *, cwd: Path | None = None) -> guard.GuardMatch | None:
        return guard.classify_guard(("bash", "-c", shell_cmd), root=self.root, cwd=cwd or self.root)

    def test_classifies_destructive_git_and_rm_commands(self) -> None:
        cases = [
            ("git reset --hard", "git reset --hard"),
            ("git reset --hard HEAD~1", "git reset --hard"),
            ("git -C src reset --hard", "git reset --hard"),
            ("git reset --merge ORIG_HEAD", "git reset --merge"),
            ("git clean -f", "git clean -f"),
            ("git clean -fd", "git clean -f"),
            ("git clean -fdx", "git clean -f"),
            ("git clean -dfx", "git clean -f"),
            ("git clean --force -d", "git clean -f"),
            ("git checkout -- .", "git checkout --"),
            ("git checkout HEAD -- README.md", "git checkout --"),
            ("git checkout .", "git checkout ."),
            ("git checkout -f main", "git checkout --force"),
            ("git restore .", "git restore"),
            ("git restore src/app.py", "git restore"),
            ("git restore --source=HEAD~1 src/app.py", "git restore"),
            ("git restore -SW src/app.py", "git restore"),
            ("git stash drop", "git stash drop"),
            ("git stash clear", "git stash clear"),
            ("rm -rf .", "rm -rf"),
            ("rm -fr src", "rm -rf"),
            ("rm -r -f src", "rm -rf"),
            ("rm --recursive --force src", "rm -rf"),
            ("rm -r src", "rm -r"),
            ("rm -R src", "rm -r"),
            ("rm --recursive src", "rm -r"),
            (f"rm -rf {self.root / 'src'}", "rm -rf"),
            (f"rm -rf {self.root.parent}", "rm -rf"),
            ("rm -rf /", "rm -rf"),
            ('rm -rf "$TARGET"', "rm -rf"),
            ("cd src && rm -rf .", "rm -rf"),
            ("find . -name '*.tmp' -delete", "find -delete"),
            ("echo ok && bash -c 'git reset --hard'", "git reset --hard"),
            ("echo ok\ngit reset --hard", "git reset --hard"),
            ("echo 'hello; world'\nrm -rf src", "rm -rf"),
            ("git \\\n  reset --hard", "git reset --hard"),
            ("cat <<-EOF\n\tgit reset --hard\n\tEOF\ngit clean -fdx", "git clean -f"),
            ("cat <<EOF && git reset --hard\nhello\nEOF", "git reset --hard"),
            ("cat <<EOF\n$(rm -rf src)\nEOF", "rm -rf"),
            ("cat <<< hi\ngit reset --hard", "git reset --hard"),
            ('cat <<< "git reset --hard"\ngit clean -fdx', "git clean -f"),
            ("FOO=1 env BAR=2 timeout 10 git clean -fdx", "git clean -f"),
            ("echo $(rm -rf src)", "rm -rf"),
            ('echo "$(git reset --hard)"', "git reset --hard"),
            ("sudo rm -f /etc/hosts", "sudo"),
            ("git push origin main", "git push"),
            ("git push --force", "git push"),
        ]
        for cmd, expected_rule in cases:
            with self.subTest(cmd=cmd):
                match = self.check(cmd)
                self.assertIsNotNone(match, f"expected guard match for {cmd!r}")
                self.assertEqual(match.rule, expected_rule)

    def test_unrecoverable_root_ancestor_and_git_deletions_set_always_block(self) -> None:
        for cmd in (
            "rm -rf .",
            "rm -rf ./",
            "rm -r .",
            "rm -r .git",
            "rm -R .git",
            f"rm -r {self.root}",
            f"rm --recursive {self.root}",
            f"rm -rf {self.root}",
            "rm -rf ..",
            "rm -r ..",
            f"rm -rf {self.root.parent}",
            "rm -rf /",
            "rm -rf .git",
            "rm -rf .git/objects",
            "git reset --hard && rm -rf ..",
        ):
            with self.subTest(cmd=cmd):
                match = self.check(cmd)
                self.assertIsNotNone(match, f"expected always_block match for {cmd!r}")
                self.assertTrue(match.always_block, f"expected always_block=True for {cmd!r}")

        subdir_match = self.check("rm -rf src")
        self.assertIsNotNone(subdir_match)
        self.assertFalse(subdir_match.always_block)
        self.assertFalse(self.check("rm -r src").always_block)

    def test_does_not_false_positive_on_safe_commands(self) -> None:
        safe = [
            "echo 'git reset --hard'",
            'echo "foo && git reset --hard"',
            "echo 'foo' ';' 'git reset --hard'",
            'echo "a | b; rm -rf ."',
            'printf "line1\\ngit reset --hard\\n"',
            "printf 'line1\ngit reset --hard\n'",
            "echo '$(rm -rf .)'",
            "# git reset --hard\necho safe",
            "cat <<'EOF' > notes.md\ngit reset --hard\nrm -rf /\n$(rm -rf .)\nEOF\necho done",
            'cat <<"EOF"\ngit clean -fdx\nEOF',
            "cat <<EOF\ngit reset --hard\nrm -r .git\nEOF",
            "cat <<-EOF\n\tgit reset --hard\n\tEOF",
            'cat <<< "git reset --hard"',
            "git commit -m 'guard against rm -rf; git clean -fdx && git reset --hard'",
            "git status",
            "git clean -nd",
            "git clean --dry-run -fd",
            "git clean -fdn",
            "git reset --soft HEAD~1",
            "git reset HEAD file.txt",
            "git checkout main",
            "git checkout -b feat/new-branch",
            "git checkout --detach -q",
            "git restore --staged file.py",
            "git restore -S file.py",
            "rm -f scratch.txt",
            f"rm -rf {self.outside}",
            f"cd {self.outside} && rm -rf build",
            "python3 -m unittest discover -s tests",
        ]
        for cmd in safe:
            with self.subTest(cmd=cmd):
                self.assertIsNone(self.check(cmd), f"unexpected guard match for {cmd!r}")
        self.assertIsNone(guard.classify_guard(("Write",), root=self.root, cwd=self.root))


class TestGuardHooks(unittest.TestCase):
    def setUp(self) -> None:
        base = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.home = base / "home"
        self.root = base / "workspace"
        self.home.mkdir()
        self.root.mkdir()
        self.registry = Registry(self.home / ".local" / "state" / "coldrewind")
        self.env = {
            key: value for key, value in os.environ.items()
            if key not in {
                "CLAUDE_CONFIG_DIR", "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME",
                "CURSOR_CONFIG_DIR", "ANTIGRAVITY_CONFIG_DIR", "GEMINI_CONFIG_DIR",
                "COLDREWIND_GUARD", "COLDREWIND_SNAPSHOT_MIN_INTERVAL_SECONDS",
            }
        }
        self.env.update(HOME=str(self.home), PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "fixture"], cwd=self.root, check=True)
        (self.root / "tracked.txt").write_text("committed\n")
        subprocess.run(["git", "add", "tracked.txt"], cwd=self.root, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=self.root, check=True)
        self.registry.register(self.root)

    def cli(self, *args: str, stdin: str = "", extra_env: dict[str, str] | None = None):
        env = {**self.env, **(extra_env or {})}
        return subprocess.run(
            [sys.executable, "-m", "coldrewind.cli", *args],
            input=stdin, cwd=self.root, env=env,
            capture_output=True, text=True, timeout=30,
        )

    def _claude_bash(self, command: str, call_id: str = "c1") -> str:
        return json.dumps({
            "cwd": str(self.root),
            "session_id": "s1",
            "tool_use_id": call_id,
            "tool_name": "Bash",
            "tool_input": {"command": command},
        })

    def test_checkpoint_mode_bypasses_throttle_and_restores_uncommitted_work(self) -> None:
        # Take an initial snapshot before uncommitted edits.
        init_payload = json.dumps({
            "cwd": str(self.root), "session_id": "s1", "tool_use_id": "init", "tool_name": "Write",
        })
        self.assertEqual(self.cli("hook", "claude", "pre", stdin=init_payload).returncode, 0)
        self.assertEqual(self.cli("hook", "claude", "post", stdin=init_payload).returncode, 0)
        initial_snap = read_steps(self.registry, self.root)[-1].post_snapshot_id

        # Create valuable uncommitted work (tracked modification + untracked file + directory).
        (self.root / "tracked.txt").write_text("uncommitted edit\n")
        (self.root / "draft.txt").write_text("untracked work\n")
        (self.root / "wip").mkdir()
        (self.root / "wip" / "note.txt").write_text("deep wip\n")

        throttle = {"COLDREWIND_SNAPSHOT_MIN_INTERVAL_SECONDS": "3600"}
        # Non-destructive pre-hook respects the throttle and reuses initial_snap.
        safe_payload = json.dumps({
            "cwd": str(self.root), "session_id": "s1", "tool_use_id": "safe", "tool_name": "Read",
        })
        self.assertEqual(self.cli("hook", "claude", "pre", stdin=safe_payload, extra_env=throttle).returncode, 0)
        pending = self.registry.store_path(self.root) / "pending"
        marker, = pending.iterdir()
        self.assertEqual(marker.read_text(), initial_snap)
        marker.unlink()

        # Destructive pre-hook MUST bypass throttle and force a fresh checkpoint!
        destructive = "git reset --hard && git clean -fdx && rm -rf wip"
        payload = self._claude_bash(destructive, call_id="boom")
        pre = self.cli("hook", "claude", "pre", stdin=payload, extra_env=throttle)
        self.assertEqual((pre.returncode, pre.stdout, pre.stderr), (0, "", ""))
        marker, = pending.iterdir()
        fresh_snap = marker.read_text()
        self.assertNotEqual(fresh_snap, initial_snap)
        fresh_manifest = read_manifest(self.registry, self.root, fresh_snap)
        self.assertIn("draft.txt", fresh_manifest["files"])
        self.assertIn("wip/note.txt", fresh_manifest["files"])

        # Execute the destructive command so all uncommitted work is wiped on disk.
        subprocess.run(["bash", "-c", destructive], cwd=self.root, check=True)
        self.assertEqual((self.root / "tracked.txt").read_text(), "committed\n")
        self.assertFalse((self.root / "draft.txt").exists())
        self.assertFalse((self.root / "wip").exists())

        post = self.cli("hook", "claude", "post", stdin=payload, extra_env=throttle)
        self.assertEqual((post.returncode, post.stderr), (0, ""))

        # Existing undo restores uncommitted tracked edits AND untracked files cleanly.
        undo = self.cli("undo")
        self.assertEqual(undo.returncode, 0, undo.stderr)
        self.assertEqual((self.root / "tracked.txt").read_text(), "uncommitted edit\n")
        self.assertEqual((self.root / "draft.txt").read_text(), "untracked work\n")
        self.assertEqual((self.root / "wip" / "note.txt").read_text(), "deep wip\n")

    def test_checkpoint_mode_fails_closed_when_force_checkpoint_fails(self) -> None:
        store = self.registry.store_path(self.root)
        store.mkdir(parents=True, exist_ok=True)
        (store / "pending").symlink_to(self.home, target_is_directory=True)

        # Destructive command fails closed (exit 2 + deny JSON).
        res = self.cli("hook", "claude", "pre", stdin=self._claude_bash("git reset --hard"))
        self.assertEqual(res.returncode, 2)
        self.assertIn("force-checkpoint failed before git reset --hard", res.stderr)
        out = json.loads(res.stdout)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

        status = json.loads(self.cli("status", "--json").stdout)
        self.assertEqual(status["last_capture_error"], "Hook capture failed")

        # Non-destructive command still fails open (exit 0).
        safe = json.dumps({
            "cwd": str(self.root), "session_id": "s1", "tool_use_id": "w1", "tool_name": "Write",
        })
        res_safe = self.cli("hook", "claude", "pre", stdin=safe)
        self.assertEqual(res_safe.returncode, 0)
        self.assertEqual(res_safe.stdout, "")

        # Guard mode 'off' fails open even for destructive commands.
        res_off = self.cli(
            "hook", "claude", "pre", "--guard", "off",
            stdin=self._claude_bash("git reset --hard"),
        )
        self.assertEqual(res_off.returncode, 0)

    def test_checkpoint_mode_fails_closed_on_lock_timeout(self) -> None:
        with self.registry.workspace_lock(self.root) as store:
            (store / "pending").mkdir(exist_ok=True)
        original = hooks.TIMEOUT_SECONDS
        hooks.TIMEOUT_SECONDS = 1
        self.addCleanup(setattr, hooks, "TIMEOUT_SECONDS", original)
        payload = self._claude_bash("rm -rf wip")
        with self.registry.workspace_lock(self.root):
            buf_out, buf_err = io.StringIO(), io.StringIO()
            old_out, old_err = sys.stdout, sys.stderr
            sys.stdout, sys.stderr = buf_out, buf_err
            try:
                code = hooks.main(self.registry, "claude", "pre", io.StringIO(payload))
            finally:
                sys.stdout, sys.stderr = old_out, old_err
        self.assertEqual(code, 2)
        self.assertIn("force-checkpoint failed before rm -rf", buf_err.getvalue())

    def test_checkpoint_mode_always_blocks_unrecoverable_root_or_ancestor_deletion(self) -> None:
        for cmd in ("rm -rf .", f"rm -rf {self.root}", "rm -rf ..", "rm -rf /", "rm -rf .git"):
            with self.subTest(cmd=cmd):
                res = self.cli("hook", "claude", "pre", stdin=self._claude_bash(cmd))
                self.assertEqual(res.returncode, 2, (cmd, res.stdout, res.stderr))
                self.assertEqual(json.loads(res.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        pending = self.registry.store_path(self.root) / "pending"
        self.assertFalse(pending.exists() and list(pending.iterdir()))

    def test_denied_forced_checkpoint_on_prune_error_leaves_no_orphan_marker(self) -> None:
        # Record a normal step first so we can verify undo is not poisoned later.
        (self.root / "tracked.txt").write_text("before-step\n")
        self.assertEqual(self.cli("run", "--", "sh", "-c", "printf 'after-step\\n' > tracked.txt").returncode, 0)

        # Force retention.prune_locked to fail via invalid COLDREWIND_MAX_BYTES during a forced checkpoint.
        res = self.cli(
            "hook", "claude", "pre",
            stdin=self._claude_bash("git reset --hard", call_id="prune-fail"),
            extra_env={"COLDREWIND_MAX_BYTES": "invalid"},
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("force-checkpoint failed before git reset --hard", res.stderr)

        # No orphan pending marker may remain, and undo on the existing step must succeed.
        pending = self.registry.store_path(self.root) / "pending"
        self.assertEqual(list(pending.iterdir()), [])
        undo = self.cli("undo")
        self.assertEqual(undo.returncode, 0, undo.stderr)
        self.assertEqual((self.root / "tracked.txt").read_text(), "before-step\n")

    def test_antigravity_native_step_idx_payload_captures_and_blocks(self) -> None:
        # Native Antigravity payload omits toolCall.id and identifies invocation by stepIdx.
        payload_block = {
            "conversationId": "conv-native",
            "workspacePaths": [str(self.root)],
            "cwd": str(self.root),
            "hookEventName": "PreToolUse",
            "stepIdx": 19,
            "toolCall": {"name": "run_command", "args": {"CommandLine": "git reset --hard"}},
        }
        blocked = self.cli(
            "hook", "antigravity", "pre",
            stdin=json.dumps(payload_block),
            extra_env={"COLDREWIND_GUARD": "block"},
        )
        self.assertEqual(blocked.returncode, 0)
        self.assertEqual(json.loads(blocked.stdout)["decision"], "deny")
        self.assertIn("git reset --hard", blocked.stderr)

        # Checkpoint mode captures and pairs PreToolUse + PostToolUse via stepIdx cleanly.
        (self.root / "tracked.txt").write_text("uncommitted ag edit\n")
        pre = self.cli("hook", "antigravity", "pre", stdin=json.dumps(payload_block))
        self.assertEqual((pre.returncode, pre.stderr), (0, ""))
        self.assertEqual(json.loads(pre.stdout), {"decision": "allow"})
        subprocess.run(["git", "reset", "--hard"], cwd=self.root, check=True)
        post = self.cli(
            "hook", "antigravity", "post",
            stdin=json.dumps({**payload_block, "hookEventName": "PostToolUse"}),
        )
        self.assertEqual((post.returncode, post.stderr), (0, ""))
        self.assertEqual(json.loads(post.stdout), {})

        steps = read_steps(self.registry, self.root)
        self.assertEqual(steps[-1].agent, "Antigravity")
        self.assertIsNotNone(steps[-1].pre_snapshot_id)
        self.assertEqual(self.cli("undo").returncode, 0)
        self.assertEqual((self.root / "tracked.txt").read_text(), "uncommitted ag edit\n")

    def test_gemini_dir_path_resolves_workspace_and_relative_rm_targets(self) -> None:
        outside = self.root.parent / "outside-cwd"
        outside.mkdir()
        (self.root / "sub").mkdir()

        # 1. Event cwd is outside registered workspace, but relative dir_path enters registered workspace.
        payload_enter = {
            "session_id": "s-gem",
            "cwd": str(outside),
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "git reset --hard", "dir_path": "../workspace"},
        }
        res_enter = self.cli(
            "hook", "gemini", "pre",
            stdin=json.dumps(payload_enter),
            extra_env={"COLDREWIND_GUARD": "block"},
        )
        self.assertEqual(res_enter.returncode, 2)
        self.assertEqual(json.loads(res_enter.stdout)["decision"], "deny")

        # 2. Event cwd is workspace root, dir_path='sub', 'rm -rf ..' resolves to workspace root -> always-blocked in checkpoint mode.
        payload_root = {
            "session_id": "s-gem",
            "cwd": str(self.root),
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "rm -rf ..", "dir_path": "sub"},
        }
        res_root = self.cli("hook", "gemini", "pre", stdin=json.dumps(payload_root))
        self.assertEqual(res_root.returncode, 2)
        self.assertEqual(json.loads(res_root.stdout)["decision"], "deny")

        # 3. Event cwd is workspace root, dir_path=outside, 'rm -rf temp' targets outside -> NOT blocked in block mode.
        payload_outside = {
            "session_id": "s-gem",
            "cwd": str(self.root),
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "rm -rf temp", "dir_path": str(outside)},
        }
        res_outside = self.cli(
            "hook", "gemini", "pre",
            stdin=json.dumps(payload_outside),
            extra_env={"COLDREWIND_GUARD": "block"},
        )
        self.assertEqual(res_outside.returncode, 0, res_outside.stderr)
        self.assertEqual(json.loads(res_outside.stdout), {"decision": "allow"})

    def test_cross_workspace_dir_path_still_guards_event_cwd_workspace(self) -> None:
        other_ws = self.root.parent / "workspace-b"
        other_ws.mkdir()
        self.registry.register(other_ws)
        (self.root / "precious").mkdir()
        (self.root / "precious" / "file.txt").write_text("keep me\n")

        # Event cwd is workspace A, dir_path is workspace B, command deletes workspace A root -> ALWAYS BLOCKED.
        payload_root = {
            "session_id": "s-gem",
            "cwd": str(self.root),
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": f"rm -r {self.root}", "dir_path": str(other_ws)},
        }
        res_root = self.cli("hook", "gemini", "pre", stdin=json.dumps(payload_root))
        self.assertEqual(res_root.returncode, 2)
        self.assertEqual(json.loads(res_root.stdout)["decision"], "deny")

        # Event cwd is workspace A, dir_path is workspace B, command deletes subdir inside workspace A -> blocked in block mode.
        payload_sub = {
            "session_id": "s-gem",
            "cwd": str(self.root),
            "hook_event_name": "BeforeTool",
            "tool_name": "run_shell_command",
            "tool_input": {"command": "rm -rf ../workspace/precious", "dir_path": str(other_ws)},
        }
        res_sub = self.cli(
            "hook", "gemini", "pre",
            stdin=json.dumps(payload_sub),
            extra_env={"COLDREWIND_GUARD": "block"},
        )
        self.assertEqual(res_sub.returncode, 2)
        self.assertEqual(json.loads(res_sub.stdout)["decision"], "deny")

        # In checkpoint mode, workspace A is checkpointed so undo restores workspace A's deleted subdir!
        pre = self.cli("hook", "gemini", "pre", stdin=json.dumps(payload_sub))
        self.assertEqual((pre.returncode, pre.stderr), (0, ""))
        subprocess.run(["rm", "-rf", str(self.root / "precious")], check=True)
        self.assertFalse((self.root / "precious").exists())
        post = self.cli("hook", "gemini", "post", stdin=json.dumps({**payload_sub, "hook_event_name": "AfterTool"}))
        self.assertEqual((post.returncode, post.stderr), (0, ""))
        self.assertEqual(self.cli("undo").returncode, 0)
        self.assertEqual((self.root / "precious" / "file.txt").read_text(), "keep me\n")

    def test_start_capture_rollback_unlinks_marker_even_if_overlap_cleanup_fails(self) -> None:
        with self.registry.workspace_lock(self.root) as store:
            snap_id = snapshot.take_locked(store, self.root)
            pending = snapshot.pending_directory(store)
            real_write = snapshot._write

            def write_then_fail(directory: Path, path: Path, data: bytes) -> None:
                real_write(directory, path, data)
                raise OSError("simulated fsync failure after marker creation")

            with (
                unittest.mock.patch.object(snapshot, "_write", side_effect=write_then_fail),
                unittest.mock.patch.object(
                    ledger, "discard_denied_overlaps_locked",
                    side_effect=sqlite3.OperationalError("simulated overlap cleanup failure"),
                ),
            ):
                with self.assertRaisesRegex(OSError, "simulated fsync failure"):
                    snapshot.start_capture_locked(store, "a" * 64, snap_id)
            self.assertEqual(list(pending.iterdir()), [])

    def test_block_mode_denies_per_client_contract_without_leaving_pending_markers(self) -> None:
        secret = "ghp_" + "Z" * 36
        cmd = f"git clean -fdx # {secret}"
        cases = [
            ("claude", {"cwd": str(self.root), "session_id": "s", "tool_use_id": "c1", "tool_name": "Bash", "tool_input": {"command": cmd}}, 2),
            ("codex", {"cwd": str(self.root), "session_id": "s", "tool_use_id": "c2", "tool_name": "Bash", "tool_input": {"command": cmd}}, 2),
            ("opencode", {"cwd": str(self.root), "session_id": "s", "tool_use_id": "c3", "tool_name": "bash", "tool_input": {"command": cmd}}, 2),
            ("cursor", {"cwd": str(self.root), "conversation_id": "s", "tool_use_id": "c4", "tool_name": "Shell", "tool_input": {"command": cmd}}, 2),
            ("antigravity", {"cwd": str(self.root), "conversationId": "s", "toolCall": {"id": "c5", "name": "run_command", "args": {"CommandLine": cmd}}}, 0),
            ("gemini", {"cwd": str(self.root), "session_id": "s", "tool_name": "run_shell_command", "tool_input": {"command": cmd}}, 2),
        ]
        for client, payload, expected_code in cases:
            with self.subTest(client=client):
                res = self.cli(
                    "hook", client, "pre",
                    stdin=json.dumps(payload),
                    extra_env={"COLDREWIND_GUARD": "block"},
                )
                self.assertEqual(res.returncode, expected_code, (client, res.stdout, res.stderr))
                self.assertIn("git clean -f", res.stderr)
                self.assertNotIn(secret, res.stdout)
                self.assertNotIn(secret, res.stderr)
                if client == "claude":
                    self.assertEqual(json.loads(res.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
                elif client == "cursor":
                    self.assertEqual(json.loads(res.stdout)["permission"], "deny")
                elif client in ("antigravity", "gemini"):
                    self.assertEqual(json.loads(res.stdout)["decision"], "deny")

        pending = self.registry.store_path(self.root) / "pending"
        self.assertFalse(pending.exists() and list(pending.iterdir()))

        # Safe command is still allowed in block mode.
        safe = json.dumps({
            "cwd": str(self.root), "session_id": "s", "tool_name": "write_file",
            "tool_input": {"path": "tracked.txt"},
        })
        res = self.cli("hook", "gemini", "pre", stdin=safe, extra_env={"COLDREWIND_GUARD": "block"})
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(json.loads(res.stdout), {"decision": "allow"})

    def test_init_with_guard_flag_pins_and_uninstalls_cleanly(self) -> None:
        res = self.cli("init", "--yes", "--guard", "block")
        self.assertEqual(res.returncode, 0, res.stderr)

        cursor_cfg = json.loads((self.home / ".cursor" / "hooks.json").read_text())
        cursor_pre = cursor_cfg["hooks"]["preToolUse"][0]["command"]
        self.assertIn("--guard block", cursor_pre)

        run_blocked = subprocess.run(
            shlex.split(cursor_pre),
            input=json.dumps({
                "cwd": str(self.root), "conversation_id": "c", "tool_use_id": "t1",
                "tool_name": "Shell", "tool_input": {"command": "git restore ."},
            }),
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(run_blocked.returncode, 2)
        self.assertEqual(json.loads(run_blocked.stdout)["permission"], "deny")

        opencode_plugin = (self.home / ".config" / "opencode" / "plugins" / "coldrewind.js").read_text()
        self.assertIn("result.exitCode === 2", opencode_plugin)
        self.assertIn('"block"', opencode_plugin)

        un = self.cli("uninstall")
        self.assertEqual(un.returncode, 0, un.stderr)
        self.assertFalse((self.home / ".config" / "opencode" / "plugins" / "coldrewind.js").exists())
        self.assertEqual(json.loads((self.home / ".cursor" / "hooks.json").read_text()), {"version": 1})
        self.assertEqual(json.loads((self.home / ".gemini" / "config" / "hooks.json").read_text()), {})
        self.assertEqual(json.loads((self.home / ".gemini" / "settings.json").read_text()), {})

    def test_invalid_guard_env_fails_closed_for_destructive_command(self) -> None:
        res = self.cli(
            "hook", "claude", "pre",
            stdin=self._claude_bash("git reset --hard"),
            extra_env={"COLDREWIND_GUARD": "bogus"},
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("COLDREWIND_GUARD must be one of", res.stderr)


if __name__ == "__main__":
    unittest.main()
