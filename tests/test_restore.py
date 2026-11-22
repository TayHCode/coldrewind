import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import textwrap
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coldrewind import restore, snapshot
from coldrewind.config import Registry
from coldrewind.git_state import git_files
from coldrewind.ledger import append_step, read_steps
from test_snapshot import GIT_ENV, git, live_entries


def git_out(root: Path, *args: str, check: bool = True) -> str:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=check, env=GIT_ENV).stdout


def state(root: Path) -> tuple:
    return (
        live_entries(root),
        {name: path.read_bytes() for name, path in git_files(root).items()},
        git_out(root, "for-each-ref", "--format=%(refname) %(objectname)"),
        git_out(root, "symbolic-ref", "HEAD") + git_out(root, "rev-parse", "--verify", "-q", "HEAD", check=False),
        git_out(root, "ls-files", "--stage"),
    )


class RestoreTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name).resolve()
        self.root = base / "repo"
        self.root.mkdir()
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(base)}):
            self.registry = Registry()
        self.registry.register(self.root)

        git(self.root, "init", "-q", "-b", "main")
        (self.root / "notes.txt").write_text("committed\n")
        (self.root / "staged.txt").write_text("committed\n")
        (self.root / "src").mkdir()
        (self.root / "src" / "tool.sh").write_text("#!/bin/sh\n")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "base")
        git(self.root, "branch", "other")
        (self.root / "second.txt").write_text("second commit\n")
        git(self.root, "add", "second.txt")
        git(self.root, "commit", "-q", "-m", "second")

        (self.root / "notes.txt").write_text("uncommitted edit\n")
        (self.root / "untracked.txt").write_text("brand new\n")
        (self.root / "staged.txt").write_text("staged change\n")
        git(self.root, "add", "staged.txt")
        (self.root / "src" / "blob.bin").write_bytes(bytes(range(256)) * 64)
        (self.root / "src" / "tool.sh").chmod(0o750)
        (self.root / "link").symlink_to("notes.txt")
        with sqlite3.connect(self.root / "app.db") as db:
            db.execute("CREATE TABLE t (v TEXT)")
            db.executemany("INSERT INTO t VALUES (?)", [("row",)] * 100)
        db.close()

        self.before = state(self.root)
        self.pre = snapshot.take(self.registry, self.root)
        for entry in self.root.iterdir():
            if entry.name != ".git":
                subprocess.run(["rm", "-rf", str(entry)], check=True)
        git(self.root, "pack-refs", "--all")
        git(self.root, "reset", "-q", "--hard", "HEAD~1")
        self.after = state(self.root)
        self.post = snapshot.take(self.registry, self.root)
        self.step = append_step(
            self.registry, self.root, agent="test", command=("rm", "-rf", "."),
            changed_paths=("notes.txt",), pre_snapshot_id=self.pre,
            post_snapshot_id=self.post, capture_complete=True,
        )

    def test_undo_then_redo_is_exact(self) -> None:
        self.assertNotEqual(self.before, self.after)

        undone = restore.undo(self.registry, self.root, self.step.step_id)
        self.assertEqual(state(self.root), self.before)
        self.assertEqual(snapshot.take(self.registry, self.root), self.pre)
        self.assertEqual(
            git_out(self.root, "diff", "--cached", "--name-only"), "staged.txt\n"
        )
        self.assertIn("refs/heads/other ", self.before[2])
        self.assertNotEqual(self.before[3], self.after[3])
        with sqlite3.connect(self.root / "app.db") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM t").fetchone(), (100,))
        db.close()
        self.assertEqual(undone.command, ("coldrewind", "undo", str(self.step.step_id)))
        self.assertEqual((undone.pre_snapshot_id, undone.post_snapshot_id), (self.post, self.pre))

        restore.redo(self.registry, self.root, undone.step_id)
        self.assertEqual(state(self.root), self.after)
        self.assertEqual(snapshot.take(self.registry, self.root), self.post)

    def cli(self, *args, injection=""):
        inject = self.root.parent / "inject"
        inject.mkdir(exist_ok=True)
        (inject / "sitecustomize.py").write_text(textwrap.dedent(injection))
        env = {**os.environ, "XDG_STATE_HOME": str(self.root.parent),
               "PYTHONPATH": os.pathsep.join((str(inject), str(Path(restore.__file__).resolve().parents[1])))}
        return subprocess.run([sys.executable, "-m", "coldrewind.cli", *args],
                              cwd=self.root, env=env, capture_output=True, text=True, timeout=30)

    def test_next_workspace_access_recovers_interrupted_undo_once(self) -> None:
        result = self.cli("undo", "1", injection="""
            from coldrewind import restore_journal as journal
            import os, signal
            move = journal.exclusive_move
            def stop(src, source, dst, destination):
                move(src, source, dst, destination)
                if source == "new" and destination == "index":
                    os.kill(os.getpid(), signal.SIGKILL)
            journal.exclusive_move = stop
        """)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        self.assertNotEqual(state(self.root), self.after)
        intent = json.loads((self.registry.store_path(self.root) / "restore-intent.json").read_bytes())
        self.assertEqual((intent["safety"], intent["target"]), (self.post, self.pre))
        interrupted = self.cli("log", injection="""
            from coldrewind import restore_journal as journal
            import os, signal
            move = journal.exclusive_move
            def stop(src, source, dst, destination):
                move(src, source, dst, destination)
                if source == "old":
                    os.kill(os.getpid(), signal.SIGKILL)
            journal.exclusive_move = stop
        """)
        self.assertEqual(interrupted.returncode, -signal.SIGKILL, interrupted.stderr)
        for _ in range(2):
            log = self.cli("log", "--json")
            self.assertEqual(log.returncode, 0, log.stderr)
            self.assertEqual([s["step_id"] for s in json.loads(log.stdout)["steps"]], [1])
            self.assertEqual(state(self.root), self.after)
            self.assertEqual(snapshot.take(self.registry, self.root), intent["safety"])

    def test_edit_at_replacement_wins(self) -> None:
        result = self.cli("undo", "1", "--force", injection="""
            from coldrewind import restore_journal as journal
            from pathlib import Path
            move = journal.exclusive_move
            def edit(src, source, dst, destination):
                if source == "new" and destination == "notes.txt":
                    Path("notes.txt").write_text("competing edit")
                move(src, source, dst, destination)
            journal.exclusive_move = edit
        """)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.root / "notes.txt").read_text(), "competing edit")
        self.assertEqual(read_steps(self.registry, self.root), [self.step])
        (self.root / "notes.txt").write_bytes(b"committed\n")
        self.assertEqual(state(self.root), self.after)

    def test_rollback_restores_submodule_gitfile(self) -> None:
        def add_submodule():
            (self.root / "sub").mkdir()
            (self.root / "sub" / ".git").write_text("gitdir: ../.git/modules/sub")

        step = self.record(("edit",), add_submodule)
        result = self.cli("undo", str(step.step_id), injection="""
            from coldrewind import restore
            import os, signal
            replace = restore._replace
            def stop(*args):
                replace(*args)
                if args[2] == "sub/.git":
                    os.kill(os.getpid(), signal.SIGKILL)
            restore._replace = stop
        """)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        for _ in range(2):
            self.assertEqual(snapshot.take(self.registry, self.root), step.post_snapshot_id)
            self.assertEqual(read_steps(self.registry, self.root)[-1], step)

    def test_recovery_preserves_missing_and_replaced_parent_directories(self) -> None:
        paths = [self.root / name / "child" for name in ("deleted", "replaced", "linked")]
        for path in paths:
            path.parent.mkdir()
            path.write_text("before")

        def change():
            for path in paths:
                path.write_text("after")

        step = self.record(("edit",), change)
        stopped = self.cli("undo", str(step.step_id), injection="""
            from coldrewind.restore_journal import Journal
            import os, signal
            Journal.visit = lambda *args, **kwargs: os.kill(os.getpid(), signal.SIGKILL)
        """)
        self.assertEqual(stopped.returncode, -signal.SIGKILL, stopped.stderr)
        removed, replaced, linked = paths
        shutil.rmtree(removed.parent)
        replaced.parent.rename(self.root.parent / "original")
        replaced.parent.mkdir()
        replaced.write_text("new directory")
        linked.parent.rename(self.root.parent / "outside")
        linked.parent.symlink_to(self.root.parent / "outside", target_is_directory=True)
        linked.write_text("outside edit")

        conflict = self.cli("log")
        self.assertEqual(conflict.returncode, 1, conflict.stderr)
        for path in paths:
            self.assertIn(path.relative_to(self.root).as_posix(), conflict.stderr)
        for _ in range(2):
            self.assertEqual(read_steps(self.registry, self.root)[-1], step)
            self.assertFalse(removed.parent.exists())
            self.assertEqual(replaced.read_text(), "new directory")
            self.assertTrue(linked.parent.is_symlink())
            self.assertEqual(linked.read_text(), "outside edit")

    def test_replaced_workspace_reports_the_paused_intent(self) -> None:
        result = self.cli("undo", "1", injection="""
            from coldrewind import restore
            import os, signal
            replace = restore._replace
            def stop(*args):
                replace(*args)
                os.kill(os.getpid(), signal.SIGKILL)
            restore._replace = stop
        """)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        intent_path = self.registry.store_path(self.root) / "restore-intent.json"
        self.root.rename(self.root.with_name("original"))
        self.root.mkdir()
        refused = self.cli("log")
        self.assertEqual(refused.returncode, 2, refused.stderr)
        self.assertIn(str(intent_path), refused.stderr)
        self.assertTrue(intent_path.is_file())
        self.assertEqual(list(self.root.iterdir()), [])
        self.root.rmdir()
        self.root.with_name("original").rename(self.root)
        self.assertEqual(read_steps(self.registry, self.root), [self.step])
        self.assertEqual(state(self.root), self.after)

    def test_two_competing_edits_during_rollback_keep_both_versions(self) -> None:
        result = self.cli("undo", "1", injection="""
            import errno
            from pathlib import Path
            from coldrewind import restore_journal as journal
            move = journal.exclusive_move
            def race(src, source, dst, destination):
                if source == "new" and destination == "staged.txt":
                    raise OSError(errno.EIO, "injected error")
                if source == "notes.txt" and destination == "removed":
                    Path("notes.txt").write_text("earlier edit")
                    move(src, source, dst, destination)
                    Path("notes.txt").write_text("latest edit")
                else:
                    move(src, source, dst, destination)
            journal.exclusive_move = race
        """)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.root / "notes.txt").read_text(), "latest edit")
        saved, = self.root.glob(".coldrewind-saved-*")
        self.assertEqual(saved.read_text(), "earlier edit")
        self.assertIn(str(saved), result.stderr)
        self.assertEqual(read_steps(self.registry, self.root), [self.step])

    def test_committed_restore_survives_kill_before_cleanup(self) -> None:
        result = self.cli("undo", "1", injection="""
            from coldrewind.restore_journal import Journal
            import os, signal
            Journal.finish = lambda self: os.kill(os.getpid(), signal.SIGKILL)
        """)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        for _ in range(2):
            steps = read_steps(self.registry, self.root)
            self.assertEqual([step.step_id for step in steps], [1, 2])
            self.assertEqual((steps[-1].pre_snapshot_id, steps[-1].post_snapshot_id), (self.post, self.pre))
            self.assertEqual(state(self.root), self.before)

    def test_post_step_edit_refuses_then_force_keeps_it_redoable(self) -> None:
        (self.root / "notes.txt").write_text("human edit after the step\n")
        edited = state(self.root)

        with self.assertRaises(restore.Conflict) as caught:
            restore.undo(self.registry, self.root, self.step.step_id)
        self.assertEqual(caught.exception.paths, ["notes.txt"])
        self.assertEqual(state(self.root), edited)
        self.assertEqual(len(read_steps(self.registry, self.root)), 1)

        forced = restore.undo(self.registry, self.root, self.step.step_id, force=True)
        self.assertEqual(state(self.root), self.before)

        restore.redo(self.registry, self.root, forced.step_id)
        self.assertEqual(state(self.root), edited)

    def test_swapped_worktree_is_never_written(self) -> None:
        moved = self.root.with_name("moved")
        real_take = snapshot.take_locked

        def swap_then_take(store: Path, root: Path) -> str:
            self.root.rename(moved)
            self.root.mkdir()
            return real_take(store, root)

        with patch.object(restore, "take_locked", swap_then_take):
            with self.assertRaisesRegex(ValueError, "identity changed"):
                restore.undo(self.registry, self.root, self.step.step_id, force=True)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(state(moved), self.after)
        self.assertEqual(len(read_steps(self.registry, self.root)), 1)

    def test_redo_needs_an_undo_step(self) -> None:
        with self.assertRaisesRegex(ValueError, "undo step"):
            restore.redo(self.registry, self.root, self.step.step_id)

    def test_failed_write_rolls_back_to_current_state(self) -> None:
        real_replace = restore._replace
        calls = []

        def fail_once(*args) -> None:
            calls.append(args)
            if len(calls) == 3:
                raise OSError("disk full")
            real_replace(*args)

        with patch.object(restore, "_replace", fail_once):
            with self.assertRaisesRegex(OSError, "disk full"):
                restore.undo(self.registry, self.root, self.step.step_id)
        self.assertEqual(state(self.root), self.after)
        self.assertEqual(len(read_steps(self.registry, self.root)), 1)

    def test_branch_moved_after_a_checkout_step_is_a_conflict(self) -> None:
        main = git_out(self.root, "rev-parse", "HEAD").strip()
        pre = snapshot.take(self.registry, self.root)
        git(self.root, "checkout", "-q", "-b", "feature")
        post = snapshot.take(self.registry, self.root)
        step = append_step(
            self.registry, self.root, agent="test", command=("git", "checkout", "-b", "feature"),
            pre_snapshot_id=pre, post_snapshot_id=post, capture_complete=True,
        )
        newer = git_out(self.root, "commit-tree", "HEAD^{tree}", "-p", main, "-m", "newer").strip()
        git(self.root, "update-ref", "refs/heads/main", newer, main)
        moved = state(self.root)

        with self.assertRaises(restore.Conflict) as caught:
            restore.undo(self.registry, self.root, step.step_id)
        self.assertIn(".git/refs/heads/main", caught.exception.paths)
        self.assertEqual(state(self.root), moved)

    def test_replaced_worktree_at_the_same_path_is_refused_even_with_force(self) -> None:
        shutil.copytree(self.root, self.root.with_name("copy"), symlinks=True)
        self.root.rename(self.root.with_name("original"))
        self.root.with_name("copy").rename(self.root)
        replaced = state(self.root)

        with self.assertRaisesRegex(ValueError, "not the worktree the step captured"):
            restore.undo(self.registry, self.root, self.step.step_id, force=True)
        self.assertEqual(state(self.root), replaced)
        self.assertEqual(len(read_steps(self.registry, self.root)), 1)

    def record(self, command: tuple[str, ...], change) -> object:
        pre = snapshot.take(self.registry, self.root)
        change()
        post = snapshot.take(self.registry, self.root)
        return append_step(
            self.registry, self.root, agent="test", command=command,
            pre_snapshot_id=pre, post_snapshot_id=post, capture_complete=True,
        )

    def test_rollback_survives_a_file_that_was_a_directory(self) -> None:
        (self.root / "m").mkdir()
        (self.root / "m" / "child").write_text("child\n")

        def change() -> None:
            (self.root / "b.txt").write_text("changed\n")
            shutil.rmtree(self.root / "m")
            (self.root / "m").write_text("now a file\n")
            (self.root / "z").write_text("only after\n")

        (self.root / "b.txt").write_text("original\n")
        step = self.record(("edit",), change)
        after = state(self.root)
        real_replace = restore._replace
        calls = []

        def fail_first(*args) -> None:
            if not args[-1] or args[-1]["type"] != "file":
                return real_replace(*args)
            calls.append(args)
            if len(calls) == 1:
                raise OSError("disk full")
            real_replace(*args)

        with patch.object(restore, "_replace", fail_first):
            with self.assertRaisesRegex(OSError, "disk full"):
                restore.undo(self.registry, self.root, step.step_id)
        self.assertEqual(state(self.root), after)

    def test_ref_renamed_into_a_ref_directory_round_trips(self) -> None:
        for ref in ("refs/heads/topic", "refs/topic"):
            with self.subTest(ref=ref):
                git(self.root, "update-ref", ref, "HEAD")
                before = state(self.root)

                def change() -> None:
                    git(self.root, "update-ref", "-d", ref)
                    git(self.root, "update-ref", f"{ref}/sub", "HEAD")

                step = self.record(("git", "update-ref"), change)
                after = state(self.root)
                undone = restore.undo(self.registry, self.root, step.step_id)
                self.assertEqual(state(self.root), before)
                restore.redo(self.registry, self.root, undone.step_id)
                self.assertEqual(state(self.root), after)
                git(self.root, "update-ref", "-d", f"{ref}/sub")

    def test_rollback_restores_a_ref_that_became_a_ref_directory(self) -> None:
        def change() -> None:
            git(self.root, "update-ref", "refs/topic/sub", "HEAD")

        git(self.root, "update-ref", "refs/topic", "HEAD")
        step = self.record(("git", "update-ref"), lambda: (git(self.root, "update-ref", "-d", "refs/topic"), change()))
        after = state(self.root)
        real_replace = restore._replace

        def fail_on_ref(journal, base, rel, old, new) -> None:
            if rel == "refs/topic" and new and new["type"] == "file":
                real_replace(journal, base, rel, old, new)
                raise OSError("disk full")
            real_replace(journal, base, rel, old, new)

        with patch.object(restore, "_replace", fail_on_ref):
            with self.assertRaisesRegex(OSError, "disk full"):
                restore.undo(self.registry, self.root, step.step_id)
        self.assertEqual(state(self.root), after)

    def test_reinitialized_git_directory_is_refused_even_with_force(self) -> None:
        (self.root / ".git").rename(self.root.with_name("old-git"))
        git(self.root, "init", "-q", "-b", "main")
        replaced = state(self.root)

        with self.assertRaisesRegex(ValueError, "not the worktree the step captured"):
            restore.undo(self.registry, self.root, self.step.step_id, force=True)
        self.assertEqual(state(self.root), replaced)

    def test_linked_worktree_private_refs_belong_to_that_worktree(self) -> None:
        git(self.root, "update-ref", "refs/bisect/main-only", "HEAD")
        linked = self.root.with_name("linked")
        git(self.root, "worktree", "add", "-q", "-b", "wt", str(linked))
        self.registry.register(linked)
        self.assertNotIn("refs/bisect/main-only", git_files(linked))

        pre = snapshot.take(self.registry, linked)
        git(linked, "update-ref", "refs/bisect/good-test", "HEAD")
        post = snapshot.take(self.registry, linked)
        self.assertIn("refs/bisect/good-test", git_files(linked))
        step = append_step(
            self.registry, linked, agent="test", command=("git", "bisect"),
            pre_snapshot_id=pre, post_snapshot_id=post, capture_complete=True,
        )
        restore.undo(self.registry, linked, step.step_id)
        self.assertEqual(git_out(linked, "for-each-ref", "refs/bisect"), "")

        git(self.root, "update-ref", "refs/worktree/topic", "HEAD")
        git(linked, "symbolic-ref", "HEAD", "refs/worktree/topic")
        self.assertNotIn("refs/worktree/topic", git_files(linked))
        git(linked, "update-ref", "refs/worktree/topic", git_out(self.root, "rev-parse", "HEAD").strip())
        gitdir = Path(git_out(linked, "rev-parse", "--absolute-git-dir").strip())
        self.assertEqual(git_files(linked)["refs/worktree/topic"], gitdir / "refs/worktree/topic")
        self.assertIn("refs/bisect/main-only", git_out(self.root, "for-each-ref", "refs/bisect"))
