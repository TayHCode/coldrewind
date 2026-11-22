import hashlib
import json
import os
import select
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from coldrewind import hooks, restore, retention, snapshot
from coldrewind.config import Registry
from coldrewind.init_cmd import EVENTS
from coldrewind.ledger import read_steps


class TestOverlap(unittest.TestCase):
    def setUp(self):
        base = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.root = base / "workspace"
        self.root.mkdir()
        self.registry = Registry(base / "state" / "coldrewind")
        self.registry.register(self.root)
        self.store = self.registry.store_path(self.root)
        self.env = dict(os.environ, XDG_STATE_HOME=str(base / "state"),
                        PYTHONPATH=str(Path(__file__).resolve().parents[1]))
        self.cli = [sys.executable, "-m", "coldrewind.cli"]

    def writer(self, name):
        process = subprocess.Popen(
            [*self.cli, "run", "--", "sh", "-c",
             'printf "%s" "$1" > "$1"; echo ready; read -r line', "sh", name],
            cwd=self.root, env=self.env, text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        self.addCleanup(self.finish, process)
        self.assertTrue(select.select([process.stdout], [], [], 10)[0])
        self.assertEqual(process.stdout.readline(), "ready\n")
        return process

    def finish(self, process):
        if not process.stdin.closed:
            try:
                process.stdin.write("done\n")
                process.stdin.close()
            except BrokenPipeError:
                pass
        process.wait(timeout=10)
        process.stdout.close()

    def prune(self):
        with patch.object(retention, "MAX_BYTES", 0):
            for i in range(4):
                (self.root / "churn").write_text(str(i))
                snapshot.take(self.registry, self.root)

    def test_both_pre_snapshots_survive_pruning_until_capture_ends(self):
        first = snapshot.take(self.registry, self.root)
        left = self.writer("left")
        second = snapshot.take(self.registry, self.root)
        right = self.writer("right")
        self.prune()
        manifests = [snapshot.read_manifest(self.registry, self.root, idx) for idx in (first, second)]
        self.assertEqual(manifests[0]["files"], {})
        digest = manifests[1]["files"]["left"]["sha256"]
        self.assertEqual((self.store / "blobs" / digest).read_bytes(), b"left")
        self.assertEqual(snapshot.pending_ids(self.store), {first, second})
        self.finish(right)
        self.assertEqual(snapshot.pending_ids(self.store), {first})
        self.finish(left)
        self.assertEqual(snapshot.pending_ids(self.store), set())
        self.assert_refused_pair()

    def test_undo_names_both_steps_and_preserves_edits(self):
        first = self.writer("left")
        second = self.writer("right")
        self.finish(second)
        self.finish(first)
        self.assert_refused_pair()

    def assert_refused_pair(self):
        steps = read_steps(self.registry, self.root)
        self.assertEqual([s.step_id for s in steps], [1, 2])
        with patch.object(restore, "take_locked", side_effect=AssertionError("started restore")):
            with self.assertRaisesRegex(restore.AmbiguousRestore, "step 2 overlaps step 1"):
                restore.undo(self.registry, self.root, 2, force=True)
        for step, peer in ((2, 1), (1, 2)):
            for options in ([], ["--force"]):
                result = subprocess.run([*self.cli, "undo", str(step), *options],
                                        env=self.env, cwd=self.root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"step {step}", result.stderr)
                self.assertIn(f"step {peer}", result.stderr)
                self.assertIn("overlap", result.stderr)
                for name in ("left", "right"):
                    self.assertEqual((self.root / name).read_text(), name)
        self.assertEqual(read_steps(self.registry, self.root), steps)

    def test_hook_overlapping_run(self):
        payload = dict(cwd=str(self.root), tool_name="Write", tool_use_id="abc")
        hooks.handle(self.registry, "claude", "pre", payload)
        (self.root / "left").write_text("left")
        self.finish(self.writer("right"))
        hooks.handle(self.registry, "claude", "post", payload)
        self.assert_refused_pair()

    def test_finished_step_stays_ambiguous_when_its_peer_crashes(self):
        wrapper = self.writer("left")
        self.finish(self.writer("right"))
        for _ in range(2):
            result = subprocess.run([*self.cli, "undo", "1", "--force"], env=self.env,
                                    cwd=self.root, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("step 1 overlaps unfinished capture run.", result.stderr)
            self.assertEqual((self.root / "right").read_text(), "right")
            wrapper.kill()
            wrapper.wait(timeout=10)

    def test_hooks_with_the_same_snapshot_have_independent_pins(self):
        payload = dict(cwd=str(self.root), tool_name="Write", tool_use_id="abc")
        for client in ("claude", "codex"):
            hooks.handle(self.registry, client, "pre", payload)
        (self.root / "left").write_text("left")
        (self.root / "right").write_text("right")
        hooks.handle(self.registry, "codex", "post", payload)
        self.assertEqual(len(snapshot.pending_ids(self.store)), 1)
        hooks.handle(self.registry, "claude", "post", payload)
        self.assert_refused_pair()

    def test_missing_hook_post_reports_marker_and_expiry_and_keeps_overlap(self):
        hook = dict(cwd=str(self.root), tool_name="Write", tool_use_id="denied")
        self.finish(self.writer("before"))
        hooks.handle(self.registry, "claude", "pre", hook)
        marker, = (self.store / "pending").iterdir()
        expires = datetime.fromtimestamp(marker.stat().st_mtime + retention.MAX_AGE_SECONDS, UTC)
        self.finish(self.writer("during"))
        for step in ("1", "2"):
            result = subprocess.run([*self.cli, "undo", step], env=self.env, cwd=self.root,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn(marker.name, result.stderr)
            self.assertIn(expires.isoformat(), result.stderr)
        os.utime(marker, (1, 1))
        self.assertEqual(snapshot.pending_ids(self.store), set())
        with self.assertRaisesRegex(restore.AmbiguousRestore, "overlaps unfinished capture"):
            restore.undo(self.registry, self.root, 2)
        self.assertEqual((self.root / "during").read_bytes(), b"during")
        self.finish(self.writer("later"))
        restore.undo(self.registry, self.root, 3)
        self.assertFalse((self.root / "later").exists())

    def test_session_end_leaves_inflight_calls_protected(self):
        for client in ("claude", "codex"):
            with self.subTest(client=client):
                pre = dict(cwd=str(self.root), session_id="shared", tool_use_id=client, tool_name="Write")
                hooks.handle(self.registry, client, "pre", pre)
                pins = snapshot.pending_markers(self.store)
                phase = EVENTS[client].get("SessionEnd")
                if phase:
                    hooks.handle(self.registry, client, phase, dict(pre, hook_event_name="SessionEnd"))
                self.assertEqual(snapshot.pending_markers(self.store), pins)
        self.finish(self.writer("later"))
        with self.assertRaises(restore.AmbiguousRestore):
            restore.undo(self.registry, self.root, 1, force=True)

    def test_denial_preserves_other_calls_overlapping_the_same_writer(self):
        event = dict(cwd=str(self.root), session_id="s", tool_name="Write")
        first = dict(event, tool_use_id="first")
        second = dict(event, tool_use_id="second")
        hooks.handle(self.registry, "claude", "pre", first)
        marker, = snapshot.pending_markers(self.store)
        hooks.handle(self.registry, "claude", "pre", second)
        self.finish(self.writer("file"))
        hooks.handle(self.registry, "claude", "denied", dict(second, hook_event_name="PermissionDenied"))
        self.assertEqual(set(snapshot.pending_markers(self.store)), {marker})
        with self.assertRaisesRegex(restore.AmbiguousRestore, marker):
            restore.undo(self.registry, self.root, 1, force=True)

    def test_legacy_pin_needs_a_call_id_to_release(self):
        event = dict(cwd=str(self.root), session_id="old", tool_use_id="one", tool_name="Write")
        key = hashlib.sha256(json.dumps(["claude", "old", "one"]).encode()).hexdigest()
        pre = snapshot.take(self.registry, self.root)
        with self.registry.workspace_lock(self.root):
            marker = snapshot.start_capture_locked(self.store, key, pre)
        self.assertIn(marker.name, snapshot.pending_markers(self.store))
        self.finish(self.writer("file"))
        hooks.handle(self.registry, "claude", "denied", dict(event, hook_event_name="PermissionDenied"))
        restore.undo(self.registry, self.root, 1)
        self.assertFalse(marker.exists())

    def test_unconfirmed_release_preserves_the_marker(self):
        event = dict(cwd=str(self.root), session_id="s", tool_use_id="id", tool_name="Write")
        hooks.handle(self.registry, "claude", "pre", event)
        marker, = snapshot.pending_markers(self.store)
        for client, phase, fields in (
            ("claude", "denied", {"hook_event_name": "Stop"}),
            ("claude", "denied", {"hook_event_name": "PermissionDenied", "session_id": None}),
            ("claude", "denied", {"hook_event_name": "PermissionDenied", "tool_use_id": ""}),
            ("codex", "denied", {"hook_event_name": "PermissionDenied"}),
            ("opencode", "denied", {"hook_event_name": "PermissionDenied"}),
            ("claude", "denied", {"hook_event_name": "SessionEnd"}),
        ):
            with self.subTest(client=client, phase=phase, fields=fields), self.assertRaises(ValueError):
                hooks.handle(self.registry, client, phase, {**event, **fields})
        self.assertEqual(set(snapshot.pending_markers(self.store)), {marker})

    def test_hook_can_undo_and_redo_a_step_completed_before_the_hook(self):
        self.finish(self.writer("before"))
        hook = dict(cwd=str(self.root), tool_name="Bash", tool_use_id="undo")
        hooks.handle(self.registry, "claude", "pre", hook)
        result = subprocess.run([*self.cli, "undo", "1"], env=self.env, cwd=self.root,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "before").exists())
        hooks.handle(self.registry, "claude", "post", hook)
        with self.assertRaisesRegex(restore.AmbiguousRestore, "step 3 overlaps step 2"):
            restore.undo(self.registry, self.root, 3)
        hook["tool_use_id"] = "redo"
        hooks.handle(self.registry, "claude", "pre", hook)
        result = subprocess.run([*self.cli, "redo", "2"], env=self.env, cwd=self.root,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "before").read_bytes(), b"before")
        hooks.handle(self.registry, "claude", "post", hook)

    def test_killed_wrapper_releases_pin(self):
        pre = snapshot.take(self.registry, self.root)
        wrapper = self.writer("left")
        self.assertIn(pre, snapshot.pending_ids(self.store))
        wrapper.kill()
        wrapper.wait(timeout=10)
        self.prune()
        self.assertFalse((self.store / "snapshots" / f"{pre}.json").exists())
        self.assertEqual(list((self.store / "pending").iterdir()), [])
