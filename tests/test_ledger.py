import multiprocessing
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from coldrewind.config import Registry
from coldrewind.ledger import append_step, read_steps


def append_batch(state: Path, root: Path, agent: str) -> list[int]:
    registry = Registry(state)
    return [
        append_step(
            registry, root, agent=agent, command=(f"tool-{index}", str(index)),
            changed_paths=(f"{agent}/{index}",),
            pre_snapshot_id=f"{agent}:{index}:before",
            post_snapshot_id=f"{agent}:{index}:after",
            capture_complete=True,
        ).step_id
        for index in range(20)
    ]


class TestLedger(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / "repo"
        self.root.mkdir()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        self.registry = Registry(self.base / "state")
        self.registry.register(self.root)
        self.database = self.registry.store_path(self.root) / "timeline.sqlite3"

    def test_order_round_trip_and_workspace_isolation(self) -> None:
        before = set(self.root.rglob("*"))
        self.assertEqual(read_steps(self.registry, self.root), [])
        self.assertFalse(self.database.exists())
        agents = ("Claude Code", "Codex", "OpenCode")
        expected = [
            append_step(
                self.registry, self.root, agent=agent, command=("edit", "line\nbreak"),
                changed_paths=("line\nbreak",),
                pre_snapshot_id="opaque:before", post_snapshot_id="opaque:after",
                capture_complete=True,
            )
            for agent in agents
        ]
        actual = read_steps(Registry(self.registry.state_dir), self.root)
        self.assertEqual(actual, expected)
        self.assertEqual([step.step_id for step in actual], [1, 2, 3])
        self.assertEqual([step.agent for step in actual], list(agents))
        for step in actual:
            self.assertEqual(datetime.fromisoformat(step.timestamp).tzinfo, UTC)
            self.assertEqual(step.command, ("edit", "[REDACTED]"))
            self.assertEqual(step.changed_paths, ("line\nbreak",))
            self.assertEqual(step.pre_snapshot_id, "opaque:before")
            self.assertEqual(step.post_snapshot_id, "opaque:after")
            self.assertEqual(step.reversibility, "reversible")
        other = self.base / "another"
        other.mkdir()
        self.registry.register(other)
        step = append_step(self.registry, other, agent="Codex", command=("edit",))
        self.assertEqual(step.step_id, 1)
        self.assertEqual(read_steps(self.registry, other), [step])
        self.assertTrue(self.database.is_file())
        self.assertEqual(set(self.root.rglob("*")), before)
        self.assertEqual(list(other.iterdir()), [])

    def test_opaque_commands_keep_only_the_tool_name(self) -> None:
        cases = [
            (("env", "COLOR=ceramic", "/bin/sh", "-lc", "printenv COLOR"), ("env", "[REDACTED]")),
            (("sh -c 'echo x' > /tmp/ceramic",), ("[REDACTED]",)),
            (("coldrewind", "undo", "1"), ("coldrewind", "[REDACTED]")),
        ]
        for command, expected in cases:
            with self.subTest(command=command):
                step = append_step(self.registry, self.root, agent="run", command=command)
                self.assertEqual(step.command, expected)

    def test_concurrent_process_appends_preserve_every_record_and_order(self) -> None:
        before = set(self.root.rglob("*"))
        agents = ("Claude Code", "Codex", "OpenCode", "run")
        context = multiprocessing.get_context("spawn")
        ready = context.Barrier(len(agents))
        with ProcessPoolExecutor(
            max_workers=len(agents), mp_context=context,
            initializer=ready.wait, initargs=(15,),
        ) as pool:
            futures = {
                agent: pool.submit(append_batch, self.registry.state_dir, self.root, agent)
                for agent in agents
            }
            ids_by_agent = {agent: future.result(timeout=30) for agent, future in futures.items()}
        steps = read_steps(self.registry, self.root)
        self.assertEqual([step.step_id for step in steps], list(range(1, 81)))
        for agent in agents:
            rows = [step for step in steps if step.agent == agent]
            self.assertEqual([step.step_id for step in rows], ids_by_agent[agent])
            self.assertEqual([step.command for step in rows], [(f"tool-{i}", "[REDACTED]") for i in range(20)])
            self.assertEqual([step.changed_paths for step in rows], [
                (f"{agent}/{i}",) for i in range(20)
            ])
            self.assertEqual([step.pre_snapshot_id for step in rows], [
                f"{agent}:{i}:before" for i in range(20)
            ])
            self.assertEqual([step.post_snapshot_id for step in rows], [
                f"{agent}:{i}:after" for i in range(20)
            ])
        self.assertEqual(set(self.root.rglob("*")), before)

    def test_recovers_from_interrupted_trailing_write(self) -> None:
        first = append_step(self.registry, self.root, agent="Codex", command=("edit",))
        committed_bytes = self.database.read_bytes()
        script = """
import os
import sqlite3
import sys
from pathlib import Path
from coldrewind.config import Registry

registry = Registry(Path(sys.argv[1]))
with registry.workspace_lock(Path(sys.argv[2])) as store:
    db = sqlite3.connect(store / "timeline.sqlite3")
    db.execute("PRAGMA cache_size = 1")
    db.execute("BEGIN IMMEDIATE")
    db.execute(
        "INSERT INTO steps SELECT NULL, timestamp, agent, ?, reversibility, reason, "
        "pre_snapshot_id, post_snapshot_id, changed_paths FROM steps WHERE step_id = 1",
        ("unfinished" * 100_000,),
    )
    os._exit(79)
"""
        child = subprocess.run(
            [sys.executable, "-c", script, str(self.registry.state_dir), str(self.root)],
            cwd=Path(__file__).resolve().parents[1],
            timeout=10,
        )
        self.assertEqual(child.returncode, 79)
        self.assertNotEqual(self.database.read_bytes(), committed_bytes)
        self.assertTrue(self.database.with_suffix(".sqlite3-journal").is_file())
        self.assertEqual(read_steps(self.registry, self.root), [first])
        second = append_step(self.registry, self.root, agent="OpenCode", command=("edit",))
        self.assertEqual(second.step_id, 2)
        self.assertEqual(read_steps(self.registry, self.root), [first, second])

    def test_does_not_reuse_a_pruned_step_id(self) -> None:
        append_step(self.registry, self.root, agent="Codex", command=("edit",))
        second = append_step(self.registry, self.root, agent="Codex", command=("edit",))
        with self.registry.workspace_lock(self.root):
            with closing(sqlite3.connect(self.database)) as connection, connection:
                connection.execute("DELETE FROM steps WHERE step_id = ?", (second.step_id,))
        third = append_step(self.registry, self.root, agent="Codex", command=("edit",))
        self.assertEqual(third.step_id, 3)
        self.assertEqual([step.step_id for step in read_steps(self.registry, self.root)], [1, 3])

    def test_refuses_database_and_sidecar_symlinks(self) -> None:
        for suffix in ("", "-journal", "-wal", "-shm"):
            with self.subTest(suffix=suffix):
                target = self.root / "must-not-create"
                link = self.database.with_name(self.database.name + suffix)
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(target)
                try:
                    with self.assertRaises(ValueError):
                        append_step(self.registry, self.root, agent="Codex", command=("edit",))
                    with self.assertRaises(ValueError):
                        read_steps(self.registry, self.root)
                    self.assertFalse(target.exists())
                finally:
                    link.unlink()

    def test_reversibility_classification(self) -> None:
        outside = str(self.base / "outside")
        (self.root / "escape").symlink_to(self.base, target_is_directory=True)
        risks = [
            (("sudo", "edit"), (), "Privileged command"),
            (("edit",), (outside,), "Write outside the watched workspace"),
            (("edit",), ("escape/outside",), "Write outside the watched workspace"),
            (("curl", "-X", "POST", "https://example.invalid"), (), "Command can mutate external state"),
            (("gh", "pr", "create"), (), "Command can mutate external state"),
            (("git", "push"), (), "Command can mutate external state"),
            (("doas", "edit"), (), "Privileged command"),
            (("run0", "edit"), (), "Privileged command"),
            (("runuser", "-u", "root", "--", "edit"), (), "Privileged command"),
            (("systemd-run", "edit"), (), "Privileged command"),
            (("env", "sudo", "edit"), (), "Command delegates execution"),
            (("bash", "-c", "curl -X POST https://example.invalid"), (), "Command delegates execution"),
            (("sh", "-c", "cd x && git push"), (), "Command delegates execution"),
            (("timeout", "5", "curl"), (), "Command delegates execution"),
            (("nohup", "gh", "pr", "create"), (), "Command delegates execution"),
            (("make", "publish"), (), "Command delegates execution"),
            (("find", ".", "-exec", "sudo", "{}"), (), "Command delegates execution"),
            (("flock", "lock", "git", "push"), (), "Command delegates execution"),
            (("nice", "git", "push"), (), "Command delegates execution"),
            (("setsid", "git", "push"), (), "Command delegates execution"),
            (("stdbuf", "-oL", "git", "push"), (), "Command delegates execution"),
            (("python3.11", "-c", "publish()"), (), "Command delegates execution"),
            (("rsync", "local", "example.invalid:remote"), (), "Command can mutate external state"),
            (("nc", "example.invalid", "1234"), (), "Command can mutate external state"),
            (("docker", "push", "image"), (), "Command can mutate external state"),
            (("npm", "publish"), (), "Command can mutate external state"),
            (("npx", "publish"), (), "Command can mutate external state"),
        ]
        cases = [
            (command, paths + local, expected, reason, "before", "after", True)
            for command, paths, reason in risks
            for local, expected in [((), "irreversible"), (("local.txt",), "partial")]
        ]
        cases.extend([
            (
                ("ls",), (), "irreversible",
                "No observed local change to restore", "before", "after", True,
            ),
            (
                ("edit",), ("local.txt",), "reversible",
                "All changes are local and covered by snapshots", "before", "after", True,
            ),
            (
                ("edit",), ("local.txt",), "partial",
                "Incomplete evidence of reversible local effects", "before", "after", False,
            ),
            (
                ("edit",), ("local.txt",), "partial",
                "Incomplete evidence of reversible local effects", "before", None, True,
            ),
        ])
        for command, paths, expected, reason, pre, post, complete in cases:
            with self.subTest(command=command, paths=paths, pre=pre, post=post, complete=complete):
                step = append_step(
                    self.registry, self.root, agent="Codex", command=command,
                    changed_paths=paths, pre_snapshot_id=pre, post_snapshot_id=post,
                    capture_complete=complete,
                )
                self.assertEqual((step.reversibility, step.reason), (expected, reason))
