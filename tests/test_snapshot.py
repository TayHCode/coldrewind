import hashlib
import json
import os
import sqlite3
import statistics
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from coldrewind import snapshot
from coldrewind.config import Registry
from coldrewind.git_state import git_files

GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "fixture",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "fixture",
}


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=GIT_ENV, capture_output=True)


def tree_state(root: Path) -> dict[str, tuple]:
    state = {}
    for path in [root, *root.rglob("*")]:
        st = path.lstat()
        data = path.read_bytes() if path.is_file() and not path.is_symlink() else None
        state[str(path)] = (st.st_mode, st.st_size, st.st_mtime_ns, data)
    return state


def live_entries(root: Path) -> dict[str, tuple]:
    entries = {}
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        bytecode = rel.parent.name == "__pycache__" and rel.suffix == ".pyc"
        if rel.parts[0] == ".git" or (bytecode and path.is_file() and not path.is_symlink()):
            continue
        st = path.lstat()
        if path.is_symlink():
            entries[rel.as_posix()] = ("symlink", os.readlink(path))
        elif path.is_dir():
            entries[rel.as_posix()] = ("dir", st.st_mode & 0o7777)
        elif path.is_file():
            entries[rel.as_posix()] = ("file", st.st_mode & 0o7777, path.read_bytes())
    return entries


def workspace_reads(store_fd) -> int:
    return sum(1 for call in store_fd.call_args_list if call.args[2] is not None)


def materialize(blobs: Path, manifest: dict, target: Path) -> None:
    for rel, entry in sorted(manifest["files"].items()):
        path = target / rel
        if entry["type"] == "dir":
            path.mkdir(parents=True, exist_ok=True)
        elif entry["type"] == "symlink":
            path.symlink_to(entry["target"])
        else:
            path.write_bytes((blobs / entry["sha256"]).read_bytes())
            path.chmod(entry["mode"])
    for rel, entry in manifest["files"].items():
        if entry["type"] == "dir":
            (target / rel).chmod(entry["mode"])


def restored_entries(blobs: Path, manifest: dict) -> dict[str, tuple]:
    entries = {}
    for rel, entry in manifest["files"].items():
        if entry["type"] == "symlink":
            entries[rel] = ("symlink", entry["target"])
        elif entry["type"] == "dir":
            entries[rel] = ("dir", entry["mode"])
        else:
            entries[rel] = ("file", entry["mode"], (blobs / entry["sha256"]).read_bytes())
    return entries


class SnapshotTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        self.registry = Registry(self.base / "state")
        self.registry.register(self.repo)
        self.store = self.registry.store_path(self.repo)
        self.blobs = self.store / "blobs"

    def take(self) -> tuple[str, dict]:
        snapshot_id = snapshot.take(self.registry, self.repo)
        return snapshot_id, snapshot.read_manifest(self.registry, self.repo, snapshot_id)


class TestSnapshot(SnapshotTestCase):
    def plant_fixture(self) -> sqlite3.Connection:
        repo = self.repo
        (repo / "tracked.txt").write_text("committed\n")
        (repo / "stashed.txt").write_text("base\n")
        git(repo, "add", "tracked.txt", "stashed.txt")
        git(repo, "commit", "-q", "-m", "base")
        (repo / "stashed.txt").write_text("stash me\n")
        git(repo, "stash", "push", "-q", "-m", "work")

        (repo / "tracked.txt").write_text("uncommitted edit\n")
        (repo / "staged.txt").write_text("staged only\n")
        git(repo, "add", "staged.txt")
        (repo / "untracked.txt").write_text("brand new\n")
        (repo / ".env").write_text("TOKEN=synthetic-not-a-secret\n")
        (repo / "data.bin").write_bytes(bytes(range(256)) * 64)
        script = repo / "tool.sh"
        script.write_text("#!/bin/sh\necho hi\n")
        script.chmod(0o750)
        private = repo / "private.key"
        private.write_text("synthetic\n")
        private.chmod(0o600)
        (repo / "nested" / "empty").mkdir(parents=True)
        (repo / "nested").chmod(0o700)
        (repo / "link-to-tracked").symlink_to("tracked.txt")
        (repo / "dangling").symlink_to("missing/target")
        (repo / "escape").symlink_to("/etc/passwd")
        (repo / "__pycache__").mkdir()
        (repo / "__pycache__" / "noise.pyc").write_bytes(b"\x00")
        (repo / "__pycache__" / ".env").write_text("HIDDEN=synthetic\n")
        (repo / "__pycache__" / "assets.pyc").mkdir()
        (repo / "__pycache__" / "assets.pyc" / "keep.txt").write_text("keep\n")
        (repo / "__pycache__" / "link.pyc").symlink_to("../tracked.txt")
        os.mkfifo(repo / "pipe")

        db = sqlite3.connect(repo / "local.db")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA wal_autocheckpoint=0")
        db.execute("CREATE TABLE notes (body TEXT)")
        db.executemany("INSERT INTO notes VALUES (?)", [("one",), ("two",), ("three",)])
        db.commit()
        self.addCleanup(db.close)
        return db

    def test_round_trip_is_byte_exact_and_repo_is_untouched(self) -> None:
        self.plant_fixture()
        self.assertGreater((self.repo / "local.db-wal").stat().st_size, 0)
        before = tree_state(self.repo)

        snapshot_id, manifest = self.take()

        self.assertEqual(tree_state(self.repo), before)
        self.assertEqual(restored_entries(self.blobs, manifest), live_entries(self.repo))
        for name in (".env", "untracked.txt", "staged.txt", "data.bin", "local.db", "local.db-wal"):
            self.assertEqual(manifest["files"][name]["type"], "file", name)
        self.assertEqual(manifest["files"]["escape"], {"type": "symlink", "target": "/etc/passwd"})
        self.assertNotIn("pipe", manifest["files"])
        self.assertFalse(any(rel.startswith(".git") for rel in manifest["files"]))
        self.assertNotIn("__pycache__/noise.pyc", manifest["files"])
        self.assertEqual(manifest["files"]["__pycache__/.env"]["type"], "file")
        self.assertEqual(manifest["files"]["__pycache__/assets.pyc"]["type"], "dir")
        self.assertEqual(manifest["files"]["__pycache__/link.pyc"]["type"], "symlink")

        restored = self.base / "restored"
        restored.mkdir()
        materialize(self.blobs, manifest, restored)
        restored_db = sqlite3.connect(restored / "local.db")
        self.addCleanup(restored_db.close)
        rows = [row[0] for row in restored_db.execute("SELECT body FROM notes ORDER BY rowid")]
        self.assertEqual(rows, ["one", "two", "three"])

        self.assertEqual(snapshot.take(self.registry, self.repo), snapshot_id)

    def test_git_state_is_captured_byte_exact(self) -> None:
        self.plant_fixture()
        _, manifest = self.take()

        expected = {"HEAD", "index", "refs/heads/main", "refs/stash", "logs/refs/stash"}
        self.assertTrue(expected <= set(manifest["git"]), manifest["git"])
        git_dir = self.repo / ".git"
        for name, entry in manifest["git"].items():
            live = git_dir / name
            self.assertEqual((self.blobs / entry["sha256"]).read_bytes(), live.read_bytes(), name)
            self.assertEqual(entry["mode"], live.stat().st_mode & 0o7777, name)
        staged = subprocess.run(
            ["git", "-C", str(self.repo), "ls-files", "--stage", "staged.txt"],
            check=True, capture_output=True, text=True, env=GIT_ENV,
        ).stdout
        self.assertIn("staged.txt", staged)

        git(self.repo, "pack-refs", "--all")
        _, packed = self.take()
        self.assertEqual(
            (self.blobs / packed["git"]["packed-refs"]["sha256"]).read_bytes(),
            (git_dir / "packed-refs").read_bytes(),
        )

    def test_split_index_captures_shared_index(self) -> None:
        (self.repo / "a.txt").write_text("a\n")
        git(self.repo, "add", "a.txt")
        git(self.repo, "update-index", "--split-index")
        shared = list((self.repo / ".git").glob("sharedindex.*"))
        self.assertEqual(len(shared), 1)

        _, manifest = self.take()

        entry = manifest["git"][shared[0].name]
        self.assertEqual((self.blobs / entry["sha256"]).read_bytes(), shared[0].read_bytes())

    def test_deleted_binary_stays_in_earlier_snapshot(self) -> None:
        binary = self.repo / "data.bin"
        binary.write_bytes(os.urandom(4096))
        original = binary.read_bytes()
        _, first = self.take()
        binary.unlink()
        _, second = self.take()

        self.assertNotIn("data.bin", second["files"])
        self.assertEqual((self.blobs / first["files"]["data.bin"]["sha256"]).read_bytes(), original)

    def test_digest_is_deterministic_and_tracks_modes(self) -> None:
        (self.repo / "a.txt").write_text("a\n")
        first_id, _ = self.take()
        self.assertEqual(snapshot.take(self.registry, self.repo), first_id)
        manifest_path = self.store / "snapshots" / f"{first_id}.json"
        self.assertEqual(hashlib.sha256(manifest_path.read_bytes()).hexdigest(), first_id)

        (self.repo / "a.txt").chmod(0o640)
        second_id, second = self.take()
        self.assertNotEqual(second_id, first_id)
        self.assertEqual(second["files"]["a.txt"]["mode"], 0o640)

    def test_stat_cache_detects_same_size_edit_with_restored_mtime(self) -> None:
        path = self.repo / "same.txt"
        path.write_text("aaaa\n")
        old = path.stat()
        os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns - 5_000_000_000))
        time.sleep(1.1)
        self.take()
        cached = path.stat()
        path.write_text("bbbb\n")
        os.utime(path, ns=(cached.st_atime_ns, cached.st_mtime_ns))

        _, manifest = self.take()
        sha = manifest["files"]["same.txt"]["sha256"]
        self.assertEqual((self.blobs / sha).read_bytes(), b"bbbb\n")

    def test_malformed_stat_cache_entries_are_rehashed(self) -> None:
        contents = {name: f"{name} body\n".encode() for name in ("a", "b", "c", "d")}
        for name, body in contents.items():
            (self.repo / name).write_bytes(body)
        self.take()
        (self.blobs / ".tmp-poison").write_bytes(b"poison")
        keys = {name: snapshot._key((self.repo / name).lstat()) for name in contents}
        poisoned = {
            "a": [*keys["a"], ".tmp-poison"],
            "b": [*keys["b"], ["unhashable"]],
            "c": keys["c"],
            "d": "not a list",
        }
        (self.store / "stat-cache.json").write_text(json.dumps(poisoned))

        _, manifest = self.take()
        for name, body in contents.items():
            self.assertEqual(manifest["files"][name]["sha256"], hashlib.sha256(body).hexdigest())

    def test_racy_clean_file_is_rehashed_until_outside_the_window(self) -> None:
        path = self.repo / "fresh.txt"
        path.write_text("fresh\n")
        ctime = path.stat().st_ctime_ns

        def reads_at(offset_ns: int) -> int:
            with patch.object(snapshot.time, "time_ns", return_value=ctime + offset_ns):
                self.take()
                with patch.object(snapshot, "_store_fd", wraps=snapshot._store_fd) as store_fd:
                    self.take()
            return workspace_reads(store_fd)

        self.assertEqual(reads_at(snapshot.RACY_WINDOW_NS), 1)
        self.assertEqual(reads_at(snapshot.RACY_WINDOW_NS + 1), 0)

    def test_git_file_vanishing_during_capture_retries(self) -> None:
        real_capture = snapshot._capture_git
        calls = []

        def vanish_once(*args):
            calls.append(1)
            if len(calls) == 1:
                raise FileNotFoundError("sharedindex expired")
            return real_capture(*args)

        with patch.object(snapshot, "_capture_git", side_effect=vanish_once):
            _, manifest = self.take()
        self.assertEqual(len(calls), 2)
        self.assertIn("HEAD", manifest["git"])

    def test_file_created_after_listing_triggers_rescan(self) -> None:
        db = self.repo / "app.db"
        db.write_bytes(b"main")
        real_scan = snapshot._scan
        calls = []

        def scan_then_wal_appears(*args):
            result = real_scan(*args)
            if not calls:
                (self.repo / "app.db-wal").write_bytes(b"committed txn")
            calls.append(1)
            return result

        with patch.object(snapshot, "_scan", side_effect=scan_then_wal_appears):
            _, manifest = self.take()
        self.assertEqual(len(calls), 2)
        wal = manifest["files"]["app.db-wal"]
        self.assertEqual((self.blobs / wal["sha256"]).read_bytes(), b"committed txn")

    def test_same_name_in_other_directory_changed_after_scan_is_rehashed(self) -> None:
        for name in ("first", "second"):
            directory = self.repo / name
            directory.mkdir()
            (directory / "file").write_bytes(b"before")
        target = self.repo / "second" / "file"
        capture_git = snapshot._capture_git

        def edit_after_scan(*args):
            if target.read_bytes() == b"before":
                target.write_bytes(b"edited")
            return capture_git(*args)

        with patch.object(snapshot, "_capture_git", side_effect=edit_after_scan):
            _, manifest = self.take()
        self.assertEqual(restored_entries(self.blobs, manifest), live_entries(self.repo))

    def test_shared_index_appearing_during_capture_triggers_rescan(self) -> None:
        real_capture = snapshot._capture_git
        late = self.repo / ".git" / f"sharedindex.{'a' * 40}"

        def capture_then_shared_index_appears(*args):
            result = real_capture(*args)
            if not late.exists():
                late.write_bytes(b"shared")
            return result

        with patch.object(snapshot, "_capture_git", side_effect=capture_then_shared_index_appears):
            _, manifest = self.take()
        self.assertEqual((self.blobs / manifest["git"][late.name]["sha256"]).read_bytes(), b"shared")

    def test_store_lives_outside_the_repo(self) -> None:
        self.assertFalse(self.store.is_relative_to(self.repo))

    def test_head_ref_traversal_is_refused(self) -> None:
        (self.repo / ".git" / "HEAD").write_text("ref: refs/heads/../../../../outside\n")
        with self.assertRaises(ValueError):
            git_files(self.repo)
        with self.assertRaises(ValueError):
            snapshot.take(self.registry, self.repo)

    def test_linked_worktree_reads_refs_from_common_dir(self) -> None:
        (self.repo / "f.txt").write_text("f\n")
        git(self.repo, "add", "f.txt")
        git(self.repo, "commit", "-q", "-m", "f")
        linked = self.base / "linked"
        git(self.repo, "worktree", "add", "-q", "-b", "side", str(linked))

        found = git_files(linked)

        common = (self.repo / ".git").resolve()
        self.assertEqual(found["refs/heads/side"], common / "refs" / "heads" / "side")
        self.assertEqual(found["HEAD"].parent.parent, common / "worktrees")
        self.registry.register(linked)
        snapshot_id = snapshot.take(self.registry, linked)
        manifest = snapshot.read_manifest(self.registry, linked, snapshot_id)
        store_blobs = self.registry.store_path(linked) / "blobs"
        for name in ("HEAD", "index", "refs/heads/side"):
            self.assertEqual(
                (store_blobs / manifest["git"][name]["sha256"]).read_bytes(),
                found[name].read_bytes(),
                name,
            )
        self.assertEqual(manifest["files"][".git"]["type"], "file")

        backlink = found["HEAD"].parent / "gitdir"
        backlink.write_text(os.path.relpath(linked / ".git", backlink.parent) + "\n")
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.base)
        self.assertEqual(git_files(linked)["refs/heads/side"], found["refs/heads/side"])

    def test_git_dir_redirection_is_refused(self) -> None:
        other = self.base / "other"
        other.mkdir()
        git(other, "init", "-q")
        dot_git = self.repo / ".git"
        moved = self.base / "moved.git"
        dot_git.rename(moved)
        dot_git.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError):
            git_files(self.repo)
        dot_git.unlink()
        dot_git.write_text(f"gitdir: {other / '.git'}\n")
        with self.assertRaises(ValueError):
            git_files(self.repo)

    def test_symlinked_store_directory_is_refused(self) -> None:
        self.store.mkdir(parents=True, exist_ok=True)
        decoy = self.base / "decoy"
        decoy.mkdir()
        (self.store / "blobs").symlink_to(decoy, target_is_directory=True)
        with self.assertRaises(ValueError):
            snapshot.take(self.registry, self.repo)
        self.assertEqual(list(decoy.iterdir()), [])

    def test_workspace_that_keeps_changing_fails_closed(self) -> None:
        (self.repo / "a.txt").write_text("a\n")
        with patch.object(snapshot, "_stat_key", return_value=None):
            with self.assertRaises(RuntimeError):
                snapshot.take(self.registry, self.repo)
        self.assertEqual(list((self.store / "snapshots").iterdir()), [])

    def test_rejects_unknown_snapshot_ids(self) -> None:
        with self.assertRaises(ValueError):
            snapshot.read_manifest(self.registry, self.repo, "../config")


class TestIncrementalBenchmark(SnapshotTestCase):
    FILES = 10_000
    RUNS = 20
    TARGET_MS = 500

    def test_incremental_snapshot_on_10000_files(self) -> None:
        for d in range(100):
            directory = self.repo / f"d{d:03}"
            directory.mkdir()
            for f in range(self.FILES // 100):
                (directory / f"f{f:03}.txt").write_text(f"file {d}/{f}\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "bulk")
        time.sleep(1.1)

        start = time.perf_counter()
        _, baseline = self.take()
        full_ms = (time.perf_counter() - start) * 1000
        regular = [e for e in baseline["files"].values() if e["type"] == "file"]
        self.assertEqual(len(regular), self.FILES)

        samples = []
        for run in range(self.RUNS):
            (self.repo / "d000" / "f000.txt").write_text(f"edit {run}\n")
            start = time.perf_counter()
            snapshot_id = snapshot.take(self.registry, self.repo)
            samples.append((time.perf_counter() - start) * 1000)
            manifest = snapshot.read_manifest(self.registry, self.repo, snapshot_id)
            sha = manifest["files"]["d000/f000.txt"]["sha256"]
            self.assertEqual((self.blobs / sha).read_bytes(), f"edit {run}\n".encode())

        median = statistics.median(samples)
        p95 = statistics.quantiles(samples, n=20, method="inclusive")[18]
        verdict = "meets" if p95 <= self.TARGET_MS else "MISSES"
        print(
            f"\nCRW-T2 benchmark: files={self.FILES} incremental_runs={self.RUNS} "
            f"first_full_ms={full_ms:.1f} incremental_median_ms={median:.1f} "
            f"incremental_p95_ms={p95:.1f} target_ms={self.TARGET_MS} p95_{verdict}_target",
            flush=True,
        )


if __name__ == "__main__":
    unittest.main()
