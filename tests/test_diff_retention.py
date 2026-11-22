import json
import os
import sqlite3
import subprocess
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from coldrewind import hooks, restore, retention, snapshot
from coldrewind.config import Registry
from coldrewind.diff import diff
from coldrewind.ledger import append_step, read_steps
from coldrewind.redact import redact_step, redact_text

OLD_TOKEN = "sk-" + "ORIGINAL" + "s" * 24
NEW_TOKEN = "ghp_" + "R" * 36
DB_PASSWORD = "hunter2-plain-value"
KEY_BODY = "Q" * 40
KEY_LABEL = "OPENSSH " + "PRIVATE KEY"
PRIVATE_KEY = f"-----BEGIN {KEY_LABEL}-----\n{KEY_BODY}\n-----END {KEY_LABEL}-----\n"
OPAQUE = "opaque" + "Value" * 3
SECRETS = (OLD_TOKEN, NEW_TOKEN, DB_PASSWORD, KEY_BODY)


def store_bytes(store: Path) -> int:
    return sum(
        path.stat().st_size
        for directory in (store / "snapshots", store / "blobs")
        for path in directory.iterdir()
    )


def rebuilt_files(registry: Registry, root: Path, snapshot_id: str) -> dict[str, bytes]:
    blobs = registry.store_path(root) / "blobs"
    manifest = snapshot.read_manifest(registry, root, snapshot_id)
    return {
        rel: (blobs / entry["sha256"]).read_bytes()
        for rel, entry in manifest["files"].items()
        if entry["type"] == "file"
    }


def live_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(root).parts
    }


class Workspace(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        self.root = base / "repo"
        self.root.mkdir()
        self.registry = Registry(base / "state")
        self.registry.register(self.root)
        self.store = self.registry.store_path(self.root)


class SecretSafeDiffTest(Workspace):
    def setUp(self) -> None:
        super().setUp()
        self.env = self.root / ".env"
        self.original = (
            f"OPENAI_API_KEY={OLD_TOKEN}\nexport DB_PASSWORD='{DB_PASSWORD}'\nDEBUG=1\n"
        ).encode()
        self.env.write_bytes(self.original)
        (self.root / "id_ed25519").write_text(PRIVATE_KEY)
        self.pre = snapshot.take(self.registry, self.root)
        self.env.write_bytes(self.original.replace(OLD_TOKEN.encode(), NEW_TOKEN.encode()))
        (self.root / "id_ed25519").unlink()
        (self.root / "notes.txt").write_text(f"token = {NEW_TOKEN}\nplain line\n")
        (self.root / "blob.bin").write_bytes(b"\0\x01binary")
        self.post = snapshot.take(self.registry, self.root)
        command = ("bash", "-c", f"echo OPENAI_API_KEY={NEW_TOKEN} > .env")
        append_step(
            self.registry, self.root, agent="test", command=command,
            changed_paths=(".env", "id_ed25519", "notes.txt", "blob.bin"),
            pre_snapshot_id=self.pre, post_snapshot_id=self.post, capture_complete=True,
        )

    def test_undo_source_keeps_exact_secret_bytes(self) -> None:
        files = rebuilt_files(self.registry, self.root, self.pre)
        self.assertEqual(files[".env"], self.original)
        self.assertEqual(files["id_ed25519"], PRIVATE_KEY.encode())

    def test_default_diff_and_log_contain_no_secret_literals(self) -> None:
        result = diff(self.registry, self.root, self.pre, self.post)
        rendered = json.dumps(result)
        log = repr([redact_step(step) for step in read_steps(self.registry, self.root)])
        for secret in SECRETS:
            self.assertNotIn(secret, rendered)
            self.assertNotIn(secret, log)
        self.assertEqual(result["added"], ["blob.bin", "notes.txt"])
        self.assertEqual(result["deleted"], ["id_ed25519"])
        self.assertEqual(result["modified"], [".env"])
        self.assertEqual(result["binary"], ["blob.bin"])
        self.assertIn("+plain line\n", result["patch"])

    def test_paths_multiline_env_flags_and_stash_logs_are_redacted(self) -> None:
        (self.root / f"leak-{NEW_TOKEN}.bin").write_bytes(b"\0")
        (self.root / f"report_{NEW_TOKEN}.txt").write_text("plain\n")
        self.env.write_text(
            f'MULTI="first\n{OLD_TOKEN}-tail\nmore"\nESCAPED="a\\\n{OPAQUE}\nend"\nDEBUG=1\n'
        )
        logs = self.root / ".git" / "logs" / "refs"
        logs.mkdir(parents=True)
        (self.root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (logs / "stash").write_text(f"0 1 T <t> 0 +0000\tWIP: {DB_PASSWORD}\n")
        post = snapshot.take(self.registry, self.root)
        rendered = json.dumps(diff(self.registry, self.root, self.pre, post))
        step = append_step(
            self.registry, self.root, agent="test", command=("tool", "--api-token", NEW_TOKEN),
        )
        shell = append_step(
            self.registry, self.root, agent="test", command=("bash", "-c", f'tool --no-token --password "x\\"{OPAQUE}" --token a\\\n{OPAQUE}'),
        )
        log = repr([redact_step(step), redact_step(shell)])
        for secret in (*SECRETS, OPAQUE):
            self.assertNotIn(secret, rendered)
            self.assertNotIn(secret, log)
        self.assertIn(".git/logs/refs/stash", rendered)

    def test_redacting_a_long_dash_run_is_fast(self) -> None:
        start = time.perf_counter()
        redact_text("-" * 100_000)
        self.assertLess(time.perf_counter() - start, 2)

    def test_show_secrets_is_explicit_opt_in(self) -> None:
        patch_text = diff(self.registry, self.root, self.pre, self.post, show_secrets=True)["patch"]
        for secret in SECRETS:
            self.assertIn(secret, patch_text)

    def test_git_ref_changes_are_reported(self) -> None:
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
        identity = ["-c", "user.name=T", "-c", "user.email=fixture"]
        run = lambda *args: subprocess.run(  # noqa: E731
            ["git", "-C", str(self.root), *identity, *args], check=True, env=env,
            capture_output=True,
        )
        run("init", "-q", "-b", "main")
        run("add", "notes.txt")
        run("commit", "-qm", "one")
        before = snapshot.take(self.registry, self.root)
        run("commit", "-q", "--allow-empty", "-m", "two")
        result = diff(self.registry, self.root, before, snapshot.take(self.registry, self.root))
        self.assertIn(".git/refs/heads/main", result["git"])
        self.assertIn("+++ b/.git/refs/heads/main", result["patch"])


class RetentionTest(Workspace):
    def mutate(self, count: int) -> list[str]:
        data = self.root / "data.bin"
        steps = []
        for index in range(count):
            pre = snapshot.take(self.registry, self.root)
            data.write_bytes(os.urandom(4096) + index.to_bytes(4, "big"))
            post = snapshot.take(self.registry, self.root, keep=frozenset({pre}))
            append_step(
                self.registry, self.root, agent="test", command=("write", str(index)),
                changed_paths=("data.bin",), pre_snapshot_id=pre, post_snapshot_id=post,
                capture_complete=True,
            )
            steps.append(pre)
        return steps

    def test_whole_store_budget_and_abandoned_hook(self):
        self.mutate(14)
        pending = snapshot.pending_directory(self.store)
        abandoned = pending / ("0" * 64)
        abandoned.write_text(read_steps(self.registry, self.root)[0].pre_snapshot_id)
        os.utime(abandoned, (1, 1))
        with patch.object(retention, "MAX_BYTES", 64 * 1024):
            retention.prune(self.registry, self.root)
        measured = sum(p.stat().st_size for p in self.store.rglob("*") if p.is_file())
        self.assertLessEqual(measured, 64 * 1024)
        self.assertFalse(abandoned.exists())

    @patch.object(retention, "TALLY_SLACK", 1)
    def test_protected_overage_keeps_capture_caches(self):
        (self.root / "large").write_bytes(b"x" * 100_000)
        started = (self.root / "large").stat().st_ctime_ns + 2 * snapshot.RACY_WINDOW_NS
        with patch.dict(os.environ, COLDREWIND_MAX_BYTES="65536"), patch("time.time_ns", return_value=started):
            for version in ("first", "second"):
                (self.root / "note").write_text(version)
                snapshot.take(self.registry, self.root)
                self.assertIn("large", json.loads((self.store / "stat-cache.json").read_bytes()))
                self.assertTrue(retention._read_tally(self.store / retention.TALLY))

    def test_age_expiry_reuses_pages_until_store_needs_compaction(self):
        database = self.store / "timeline.sqlite3"
        append_step(self.registry, self.root, agent="test", command=("edit",), changed_paths=("a" * 64000,))
        latest = append_step(self.registry, self.root, agent="test", command=("edit",))
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("UPDATE steps SET timestamp = '2000-01-01' WHERE step_id = 1")
        retention.prune(self.registry, self.root)
        with closing(sqlite3.connect(database)) as db:
            self.assertGreater(db.execute("PRAGMA freelist_count").fetchone()[0], 0)
        with patch.dict(os.environ, COLDREWIND_MAX_BYTES="32768"):
            retention.prune(self.registry, self.root)
        self.assertLess(database.stat().st_size, 32768)
        self.assertEqual(read_steps(self.registry, self.root), [latest])

    def test_byte_pressure_compacts_ledger_and_keeps_latest_and_redo(self):
        for index in range(32):
            append_step(self.registry, self.root, agent="test", command=("edit",),
                        changed_paths=(f"{index}" * 2000,))
        undo_step = append_step(self.registry, self.root, agent="coldrewind",
                                command=("coldrewind", "undo", "32"))
        latest = append_step(self.registry, self.root, agent="test", command=("edit",))
        database = self.store / "timeline.sqlite3"
        with patch.dict(os.environ, COLDREWIND_MAX_BYTES="32768"):
            self.assertGreater(database.stat().st_size, 32768)
            retention.prune(self.registry, self.root)
            self.assertLessEqual(sum(p.stat().st_size for p in self.store.iterdir() if p.is_file()), 32768)
        remaining = read_steps(self.registry, self.root)
        self.assertEqual(remaining[-2:], [undo_step, latest])
        self.assertGreater(remaining[0].step_id, 1)

    def test_expired_overlap_keeps_refusal_until_neither_side_is_needed(self):
        event = dict(cwd=str(self.root), tool_name="Write", tool_use_id="one")
        hooks.handle(self.registry, "claude", "pre", event)
        second = dict(event, tool_use_id="two")
        hooks.handle(self.registry, "codex", "pre", second)
        hooks.handle(self.registry, "codex", "post", second)
        abandoned, = (self.store / "pending").iterdir()
        os.utime(abandoned, (1, 1))
        with patch.dict(os.environ, COLDREWIND_MAX_AGE_SECONDS="0"):
            retention.prune(self.registry, self.root)
            self.assertFalse(abandoned.exists())
            with self.assertRaises(restore.AmbiguousRestore):
                restore.undo(self.registry, self.root, 1, force=True)
            self.mutate(1)
            with closing(sqlite3.connect(self.store / "timeline.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM capture_overlaps").fetchone(), (0,))

    def test_200_mutations_stay_under_byte_cap_and_latest_undo_rebuilds(self) -> None:
        (self.root / ".env").write_text(f"TOKEN={OLD_TOKEN}\n")
        cap = 64 * 1024
        with patch.object(retention, "MAX_BYTES", cap):
            self.mutate(199)
            self.assertLessEqual(store_bytes(self.store), cap)
            expected = live_files(self.root)
            [pre] = self.mutate(1)
            self.assertLessEqual(store_bytes(self.store), cap)
        remaining = list((self.store / "snapshots").glob("*.json"))
        self.assertLess(len(remaining), 20)
        self.assertEqual(rebuilt_files(self.registry, self.root, pre), expected)
        latest = read_steps(self.registry, self.root)[-1]
        self.assertEqual(
            rebuilt_files(self.registry, self.root, latest.post_snapshot_id), live_files(self.root)
        )
        for path in remaining:
            rebuilt_files(self.registry, self.root, path.stem)

    def test_age_cap_prunes_old_snapshots_but_keeps_protected_ones(self) -> None:
        old_pre, = self.mutate(1)
        kept, = self.mutate(1)
        latest_pre, = self.mutate(1)
        stale = time.time() - retention.MAX_AGE_SECONDS - 60
        manifests = (self.store / "snapshots").glob("*.json")
        by_age = sorted(manifests, key=lambda path: path.stat().st_mtime_ns)
        for offset, path in enumerate(by_age):
            os.utime(path, (stale + offset, stale + offset))
        (self.root / "data.bin").write_bytes(b"fresh")
        newest = snapshot.take(self.registry, self.root, keep=frozenset({kept}))
        names = {path.stem for path in (self.store / "snapshots").glob("*.json")}
        latest = read_steps(self.registry, self.root)[-1]
        self.assertEqual(names, {kept, latest_pre, latest.post_snapshot_id, newest})
        self.assertNotIn(old_pre, names)
        for snapshot_id in names:
            rebuilt_files(self.registry, self.root, snapshot_id)

    def test_prune_removes_the_matching_backend_sidecar(self) -> None:
        ids = []
        for version in range(4):
            (self.root / "data").write_text(str(version))
            ids.append(snapshot.take(self.registry, self.root))
        old, legacy, *kept = ids
        snapshots = self.store / "snapshots"
        sidecar = snapshots / f"{old}.backend"
        self.assertTrue(sidecar.is_file())
        (snapshots / f"{legacy}.backend").unlink()
        stale = time.time() - retention.MAX_AGE_SECONDS - 60
        for snapshot_id in (old, legacy):
            os.utime(snapshots / f"{snapshot_id}.json", (stale, stale))

        self.assertEqual(set(retention.prune(self.registry, self.root)), {old, legacy})
        self.assertFalse(sidecar.exists())
        self.assertEqual({path.stem for path in snapshots.glob("*.backend")}, set(kept))
        self.assertEqual({path.stem for path in snapshots.glob("*.json")}, set(kept))

    def test_owner_marker_is_written(self) -> None:
        snapshot.take(self.registry, self.root)
        marker = json.loads((self.store / retention.MARKER).read_text())
        self.assertEqual(marker["schema_version"], 1)
        self.assertEqual(marker["retention"]["owner"], "coldrewind")
        self.assertEqual(marker["retention"]["policy"], "keep")
        self.assertNotIn("expires", marker["retention"])

    def test_capture_that_crosses_the_cap_keeps_the_pending_pre_snapshot(self) -> None:
        with patch.object(retention, "MAX_BYTES", 32 * 1024):
            self.mutate(5)
            (self.root / "data.bin").write_bytes(b"pending step")
            pre = snapshot.take(self.registry, self.root)
            (self.root / "data.bin").write_bytes(os.urandom(64 * 1024))
            snapshot.take(self.registry, self.root)
        rebuilt_files(self.registry, self.root, pre)

    def test_keep_protects_pending_pre_snapshot_across_clock_skew(self) -> None:
        with patch.object(retention, "MAX_BYTES", 32 * 1024):
            older, = self.mutate(1)
            future = time.time() + 3600
            os.utime(self.store / "snapshots" / f"{older}.json", (future, future))
            (self.root / "data.bin").write_bytes(b"pending step")
            pre = snapshot.take(self.registry, self.root)
            (self.root / "data.bin").write_bytes(os.urandom(64 * 1024))
            snapshot.take(self.registry, self.root, keep=frozenset({pre}))
        rebuilt_files(self.registry, self.root, pre)

    def test_fifo_at_marker_path_does_not_block_capture(self) -> None:
        snapshot.take(self.registry, self.root)
        marker = self.store / retention.MARKER
        marker.unlink()
        os.mkfifo(marker)
        snapshot.take(self.registry, self.root)
        self.assertEqual(json.loads(marker.read_text())["retention"]["policy"], "keep")

    def test_round_one_temporary_marker_is_upgraded_to_keep(self) -> None:
        snapshot.take(self.registry, self.root)
        marker = self.store / retention.MARKER
        marker.write_text(json.dumps({"retention": {"policy": "temporary"}}))
        snapshot.take(self.registry, self.root)
        self.assertEqual(json.loads(marker.read_text())["retention"]["policy"], "keep")

    def test_orphan_blobs_are_reclaimed_before_history(self) -> None:
        with patch.object(retention, "MAX_BYTES", 64 * 1024):
            first, _ = self.mutate(2)
            orphan = self.store / "blobs" / ("0" * 64)
            orphan.write_bytes(os.urandom(64 * 1024))
            self.mutate(1)
        self.assertFalse(orphan.exists())
        rebuilt_files(self.registry, self.root, first)

    def assert_tally_matches_recount(self) -> None:
        blobs = self.store / "blobs"
        tally, _ = retention._count_blobs(blobs, retention._read_tally(self.store / retention.TALLY))
        recount = {
            path.name: path.lstat().st_size
            for path in blobs.iterdir()
            if snapshot.is_digest(path.name)
        }
        self.assertEqual({digest: size for digest, (_, size) in tally.items()}, recount)

    @patch.object(retention, "TALLY_SLACK", 1)
    def test_blob_tally_matches_a_full_recount(self) -> None:
        ids = []
        for version in range(4):
            (self.root / "data").write_text(str(version) * 100)
            ids.append(snapshot.take(self.registry, self.root))
        self.assert_tally_matches_recount()

        stale = time.time() - retention.MAX_AGE_SECONDS - 60
        for snapshot_id in ids[:2]:
            os.utime(self.store / "snapshots" / f"{snapshot_id}.json", (stale, stale))
        blobs_before = len(os.listdir(self.store / "blobs"))
        self.assertEqual(set(retention.prune(self.registry, self.root)), set(ids[:2]))
        self.assertLess(len(os.listdir(self.store / "blobs")), blobs_before)
        self.assert_tally_matches_recount()

        tally = self.store / retention.TALLY
        tally.unlink()
        (self.root / "data").write_text("missing")
        snapshot.take(self.registry, self.root)
        self.assert_tally_matches_recount()

        tally.write_text("{not json")
        (self.root / "data").write_text("corrupt")
        snapshot.take(self.registry, self.root)
        self.assert_tally_matches_recount()

        saved = tally.read_bytes()
        with patch.object(retention, "TALLY_SLACK", 2):
            (self.root / "data").write_text("not yet saved")
            snapshot.take(self.registry, self.root)
        self.assertEqual(tally.read_bytes(), saved)
        self.assert_tally_matches_recount()

    @patch.object(retention, "TALLY_SLACK", 1)
    def test_tally_with_unknown_inodes_cannot_hide_bytes_from_the_cap(self) -> None:
        self.mutate(5)
        cap = 8 * 1024
        self.assertGreater(store_bytes(self.store), cap)
        tally = self.store / retention.TALLY
        current = retention._read_tally(tally)
        self.assertTrue(current)
        poisoned = {digest: [ino + 1, 0] for digest, (ino, _) in current.items()}
        tally.write_bytes(retention._encode_tally(poisoned))
        with patch.object(retention, "MAX_BYTES", cap):
            self.assertNotEqual(retention.prune(self.registry, self.root), [])
        self.assert_tally_matches_recount()

    @patch.object(retention, "TALLY_SLACK", 1)
    def test_tally_with_a_corrupt_size_cannot_hide_bytes_from_the_cap(self) -> None:
        self.mutate(5)
        cap = 8 * 1024
        tally = self.store / retention.TALLY
        digest, _, body = tally.read_bytes().partition(b"\n")
        shrunk = {name: [ino, 0] for name, (ino, _) in json.loads(body).items()}
        tally.write_bytes(digest + b"\n" + json.dumps(shrunk).encode())
        with patch.object(retention, "MAX_BYTES", cap):
            self.assertNotEqual(retention.prune(self.registry, self.root), [])
        self.assert_tally_matches_recount()

    @unittest.skipIf(os.geteuid() == 0, "root can read a mode 000 file")
    @patch.object(retention, "TALLY_SLACK", 1)
    def test_unreadable_tally_falls_back_to_a_recount(self) -> None:
        self.mutate(5)
        tally = self.store / retention.TALLY
        tally.chmod(0)
        self.addCleanup(tally.chmod, 0o600)
        with patch.object(retention, "MAX_BYTES", 8 * 1024):
            self.assertNotEqual(retention.prune(self.registry, self.root), [])

    def test_symlinked_blob_store_is_refused(self) -> None:
        snapshot.take(self.registry, self.root)
        outside = self.store.parent / "outside"
        (self.store / "blobs").rename(outside)
        (self.store / "blobs").symlink_to(outside)
        with self.assertRaises(ValueError):
            retention.prune(self.registry, self.root)


if __name__ == "__main__":
    unittest.main()
