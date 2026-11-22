import errno
import io
import os
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from coldrewind import cow, snapshot
from coldrewind.cli import main
from coldrewind.config import Registry
from test_snapshot import SnapshotTestCase, git


def simulate_reflink(source: int, destination: int, target: Path) -> bool:
    while chunk := os.read(source, snapshot.CHUNK):
        os.write(destination, chunk)
    os.lseek(source, 0, os.SEEK_SET)
    return True


class TestCoW(SnapshotTestCase):
    def test_reflink_and_fallback_publish_identical_manifests(self) -> None:
        path = self.repo / "tool"
        path.write_bytes(bytes(range(256)) * 32)
        path.chmod(0o750)
        (self.repo / "link").symlink_to("tool")
        git(self.repo, "add", "tool")
        git(self.repo, "commit", "-q", "-m", "fixture")
        payload = b"workspace edit" * path.stat().st_blksize
        path.write_bytes(payload)

        portable = Registry(self.base / "portable")
        portable.register(self.repo)
        with (
            patch.object(cow.sys, "platform", "linux"),
            patch.object(cow.fcntl, "ioctl", side_effect=OSError(errno.EXDEV, "cross-device")),
        ):
            portable_id = snapshot.take(portable, self.repo)
        with patch.object(cow, "clone", side_effect=simulate_reflink):
            cloned_id, manifest = self.take()

        self.assertEqual(cloned_id, portable_id)
        self.assertEqual(manifest, snapshot.read_manifest(portable, self.repo, portable_id))
        self.assertEqual(snapshot.read_backend(portable, self.repo, portable_id), "portable")
        self.assertEqual(snapshot.read_backend(self.registry, self.repo, cloned_id), "mixed")
        digest = manifest["files"]["tool"]["sha256"]
        path.write_bytes(b"subsequent edit")
        self.assertEqual((self.blobs / digest).read_bytes(), payload)
        self.assertEqual(manifest["files"]["tool"]["mode"], 0o750)
        self.assertEqual(manifest["files"]["link"]["target"], "tool")
        self.assertIn("index", manifest["git"])

        stdout = io.StringIO()
        with (
            patch("coldrewind.cli.Registry", return_value=self.registry),
            patch("coldrewind.cli.Path.cwd", return_value=self.repo),
            redirect_stdout(stdout),
        ):
            self.assertEqual(main(["status"]), 0)
        self.assertEqual(stdout.getvalue(), "Snapshot backend: mixed\n")

    def test_unexpected_clone_failure_surfaces_and_cleans_up(self) -> None:
        path = self.repo / "file"
        path.touch()
        path.write_bytes(b"x" * path.stat().st_blksize)
        with (
            patch.object(cow.sys, "platform", "linux"),
            patch.object(cow.fcntl, "ioctl", side_effect=OSError(errno.EIO, "I/O failure")),
            self.assertRaises(OSError) as failure,
        ):
            self.take()
        self.assertEqual(failure.exception.errno, errno.EIO)
        self.assertEqual(list(self.blobs.iterdir()), [])
        self.assertEqual(list((self.store / "snapshots").iterdir()), [])

    def test_snapshot_without_backend_metadata_reports_portable(self) -> None:
        snapshot_id, _ = self.take()
        (self.store / "snapshots" / f"{snapshot_id}.backend").unlink()
        self.assertEqual(snapshot.read_backend(self.registry, self.repo, snapshot_id), "portable")

    def test_snapshot_with_only_cache_hits_reports_cached(self) -> None:
        repo = self.base / "plain"
        repo.mkdir()
        self.registry.register(repo)
        path = repo / "file"
        path.touch()
        path.write_bytes(b"x" * path.stat().st_blksize)
        later = path.stat().st_ctime_ns + 2 * snapshot.RACY_WINDOW_NS
        with (
            patch.object(snapshot.time, "time_ns", return_value=later),
            patch.object(cow, "clone", side_effect=simulate_reflink),
        ):
            snapshot_id = snapshot.take(self.registry, repo)
            self.assertEqual(snapshot.read_backend(self.registry, repo, snapshot_id), "reflink")
            self.assertEqual(snapshot.take(self.registry, repo), snapshot_id)
        self.assertEqual(snapshot.read_backend(self.registry, repo, snapshot_id), "cached")

    def test_status_follows_capture_when_manifest_is_reused(self) -> None:
        path = self.repo / "file"
        path.write_bytes(b"first")
        first_id, _ = self.take()
        path.write_bytes(b"second")
        second_id, _ = self.take()
        path.write_bytes(b"first")
        reused_id, _ = self.take()
        self.assertEqual(first_id, reused_id)
        self.assertNotEqual(first_id, second_id)
        self.assertEqual(snapshot.latest_backend(self.registry, self.repo), "cached")

    def test_incremental_capture_clones_only_new_content(self) -> None:
        unchanged = self.repo / "unchanged"
        changed = self.repo / "changed"
        unchanged.touch()
        changed.touch()
        unchanged.write_bytes(b"unchanged" * unchanged.stat().st_blksize)
        block_size = changed.stat().st_blksize
        changed.write_bytes(b"a" * block_size)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "fixture")
        cloned_inodes = []

        def record_clone(source: int, destination: int, target: Path) -> bool:
            cloned_inodes.append(os.fstat(source).st_ino)
            return simulate_reflink(source, destination, target)

        with patch.object(cow, "clone", side_effect=record_clone):
            self.take()
            cloned_inodes.clear()
            changed.write_bytes(b"b" * block_size)
            self.take()

        self.assertEqual(cloned_inodes, [changed.stat().st_ino])
