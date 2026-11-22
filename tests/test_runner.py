import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from coldrewind.config import Registry
from coldrewind.ledger import append_step, read_steps
from coldrewind.snapshot import read_manifest


class TestRun(unittest.TestCase):
    def setUp(self) -> None:
        base = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.root = base / "workspace"
        self.root.mkdir()
        state_home = base / "state"
        self.registry = Registry(state_home / "coldrewind")
        self.registry.register(self.root)
        self.env = {
            **os.environ,
            "XDG_STATE_HOME": str(state_home),
            "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        }

    def cli(
        self, *args: str, cwd: Path | None = None, start_new_session: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "coldrewind.cli", "run", *args],
            cwd=cwd or self.root, env=self.env, capture_output=True, text=True, timeout=10,
            start_new_session=start_new_session,
        )

    def test_bash_mutation_appends_to_existing_timeline(self) -> None:
        first = append_step(self.registry, self.root, agent="Codex", command=("edit",))
        command = ("bash", "-c", "printf data > note; printf out; printf err >&2")
        result = self.cli("--", *command)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "out", "err"))
        self.assertEqual((self.root / "note").read_text(), "data")
        previous, step = read_steps(self.registry, self.root)
        self.assertEqual(previous, first)
        self.assertEqual((step.step_id, step.agent, step.command), (2, "run", ("bash", "[REDACTED]")))
        self.assertEqual((step.changed_paths, step.reversibility), (("note",), "partial"))

    def test_shell_payload_is_private_and_env_file_round_trips(self) -> None:
        target = self.root / ".env"
        original = b"COLOR=blue\r\n"
        target.write_bytes(original)
        marker = "mauveplum"
        command = ("/bin/sh", "-c", f"printf 'COLOR={marker}\\n' > .env")
        result = self.cli("--", *command)
        self.assertEqual(result.returncode, 0, result.stderr)
        updated = f"COLOR={marker}\n".encode()
        self.assertEqual(target.read_bytes(), updated)
        database = self.registry.store_path(self.root) / "timeline.sqlite3"

        def cli(*args):
            return subprocess.run(
                [sys.executable, "-m", "coldrewind.cli", *args], cwd=self.root, env=self.env,
                check=True, capture_output=True, text=True, timeout=10,
            ).stdout

        with closing(sqlite3.connect(database)) as db:
            stored, = db.execute("SELECT command FROM steps").fetchone()
            with self.subTest(record="new"):
                self.assertNotIn(marker, stored)
            for version in ("new", "legacy"):
                if version == "legacy":
                    with db:
                        db.execute("UPDATE steps SET command = ?", (json.dumps(command),))
                with self.subTest(record=version, output="log"):
                    self.assertNotIn(marker, cli("log"))
                with self.subTest(record=version, output="json"):
                    timeline = cli("log", "--json")
                    self.assertEqual(len(json.loads(timeline)["steps"]), 1)
                    self.assertNotIn(marker, timeline)
            self.assertEqual(db.execute("SELECT command FROM steps").fetchone(), (json.dumps(command),))
        cli("undo", "1")
        self.assertEqual(target.read_bytes(), original)
        cli("redo")
        self.assertEqual(target.read_bytes(), updated)

    def test_deletion_retains_original_bytes(self) -> None:
        content = b"\x00original\xff"
        target = self.root / "data.bin"
        target.write_bytes(content)
        result = self.cli("--", "rm", "--", target.name)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(target.exists())
        step, = read_steps(self.registry, self.root)
        self.assertEqual(step.changed_paths, ("data.bin",))
        before = read_manifest(self.registry, self.root, step.pre_snapshot_id)
        after = read_manifest(self.registry, self.root, step.post_snapshot_id)
        self.assertNotIn("data.bin", after["files"])
        blob = self.registry.store_path(self.root) / "blobs" / before["files"]["data.bin"]["sha256"]
        self.assertEqual(blob.read_bytes(), content)

    def test_failed_child_records_both_versions_and_returns_its_exit_code(self) -> None:
        (self.root / "note").write_text("before")
        result = self.cli("--", "bash", "-c", "printf after > note; exit 37")
        self.assertEqual(result.returncode, 37, result.stderr)
        step, = read_steps(self.registry, self.root)
        self.assertEqual((step.changed_paths, step.reversibility), (("note",), "partial"))
        before = read_manifest(self.registry, self.root, step.pre_snapshot_id)
        after = read_manifest(self.registry, self.root, step.post_snapshot_id)
        blobs = self.registry.store_path(self.root) / "blobs"
        self.assertEqual((blobs / before["files"]["note"]["sha256"]).read_text(), "before")
        self.assertEqual((blobs / after["files"]["note"]["sha256"]).read_text(), "after")

    def test_stubbed_outbound_write_is_irreversible(self) -> None:
        curl = self.root.parent / "curl"
        curl.write_text('#!/bin/sh\n[ "$*" = "-X POST https://example.invalid" ]\n')
        curl.chmod(0o700)
        result = self.cli("--", str(curl), "-X", "POST", "https://example.invalid")
        self.assertEqual(result.returncode, 0, result.stderr)
        step, = read_steps(self.registry, self.root)
        self.assertEqual(step.reversibility, "irreversible")
        self.assertEqual(step.reason, "Command can mutate external state")
        self.assertEqual(step.changed_paths, ())

    def test_outside_write_with_local_change_is_partial(self) -> None:
        result = self.cli("--", "touch", "../outside", "inside")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root.parent / "outside").is_file())
        step, = read_steps(self.registry, self.root)
        self.assertEqual((step.changed_paths, step.reversibility), (("inside",), "partial"))

    def test_child_uses_original_directory_and_literal_args(self) -> None:
        subdir = self.root / "nested"
        subdir.mkdir()
        name = "a file; touch unexpected"
        result = self.cli("--", "touch", "--", name, cwd=subdir)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(subdir.iterdir()), [subdir / name])
        step, = read_steps(self.registry, self.root)
        self.assertEqual(step.changed_paths, (f"nested/{name}",))

    def test_records_git_index_delta(self) -> None:
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        (self.root / "existing").touch()
        result = self.cli("--", "git", "add", "existing")
        self.assertEqual(result.returncode, 0, result.stderr)
        step, = read_steps(self.registry, self.root)
        self.assertEqual(step.changed_paths, (".git/index",))

    def test_signal_status_is_shell_compatible(self) -> None:
        result = self.cli("--", "sh", "-c", "touch note; kill -TERM $$")
        self.assertEqual(result.returncode, 128 + signal.SIGTERM, result.stderr)
        step, = read_steps(self.registry, self.root)
        self.assertEqual(step.changed_paths, ("note",))

    def test_child_can_finish_cleanup_after_ctrl_c(self) -> None:
        script = """
import os
from pathlib import Path
import signal
import sys
import time

def cleanup(signum, frame):
    time.sleep(0.5)
    Path('cleaned').touch()
    sys.exit(31)

signal.signal(signal.SIGINT, cleanup)
os.killpg(os.getpgrp(), signal.SIGINT)
"""
        result = self.cli("--", sys.executable, "-c", script, start_new_session=True)
        self.assertEqual(result.returncode, 31, result.stderr)
        step, = read_steps(self.registry, self.root)
        self.assertEqual(step.changed_paths, ("cleaned",))

    def test_post_snapshot_failure_records_incomplete_step_and_returns_child_status(self) -> None:
        result = self.cli("--", "sh", "-c", "ln -s missing .git; exit 37")
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn("post-command snapshot failed", result.stderr)
        step, = read_steps(self.registry, self.root)
        self.assertIsNotNone(step.pre_snapshot_id)
        self.assertIsNone(step.post_snapshot_id)
        self.assertEqual(step.reversibility, "irreversible")

    def test_ledger_failure_is_reported_without_replacing_child_status(self) -> None:
        database = self.registry.store_path(self.root) / "timeline.sqlite3"
        database.mkdir(parents=True)
        result = self.cli("--", "sh", "-c", "touch note; exit 37")
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertIn("timeline write failed", result.stderr)
        self.assertTrue((self.root / "note").exists())

    def test_invalid_input_does_not_launch_child(self) -> None:
        for args, cwd in [(("--",), self.root), (("--", "touch", "note"), self.root.parent)]:
            with self.subTest(args=args, cwd=cwd):
                result = self.cli(*args, cwd=cwd)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse((cwd / "note").exists())
        self.assertEqual(read_steps(self.registry, self.root), [])
