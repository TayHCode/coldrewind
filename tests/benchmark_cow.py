import hashlib
import statistics
import time
from contextlib import nullcontext
from unittest.mock import patch

from coldrewind import cow, snapshot
from coldrewind.config import Registry
from test_snapshot import SnapshotTestCase, git


class TestCoWBenchmark(SnapshotTestCase):
    def test_snapshot_on_10000_files(self) -> None:
        file_count = 10_000
        runs = 20
        target_ms = 150
        for directory_number in range(100):
            directory = self.repo / f"d{directory_number:03}"
            directory.mkdir()
            for file_number in range(file_count // 100):
                (directory / f"f{file_number:03}.txt").write_text(
                    f"file {directory_number}/{file_number}\n"
                )
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "bulk")
        time.sleep(1.1)

        portable = Registry(self.base / "portable")
        portable.register(self.repo)
        stores = {"auto": self.registry, "forced-portable": portable}
        first_id, auto_first_ms = self.measure(self.registry, "mixed")
        portable_id, portable_first_ms = self.measure(portable, "portable", force_portable=True)
        self.assertEqual(first_id, portable_id)
        first = snapshot.read_manifest(self.registry, self.repo, first_id)
        self.assertEqual(sum(entry["type"] == "file" for entry in first["files"].values()), file_count)

        samples = {backend: [] for backend in stores}
        relative = "d000/f000.txt"
        for run in range(runs):
            payload = f"edit {run}\n".encode()
            (self.repo / relative).write_bytes(payload)
            expected = hashlib.sha256(payload).hexdigest()
            order = stores if run % 2 == 0 else reversed(stores)
            ids = {}
            for backend in order:
                registry = stores[backend]
                blobs = registry.store_path(self.repo) / "blobs"
                self.assertFalse((blobs / expected).exists())
                snapshot_id, elapsed_ms = self.measure(
                    registry, "portable", force_portable=backend == "forced-portable"
                )
                samples[backend].append(elapsed_ms)
                ids[backend] = snapshot_id
                manifest = snapshot.read_manifest(registry, self.repo, snapshot_id)
                self.assertEqual(manifest["files"][relative]["sha256"], expected)
                self.assertEqual((blobs / expected).read_bytes(), payload)
            self.assertEqual(ids["auto"], ids["forced-portable"])

        for mode, first_ms in (("auto", auto_first_ms), ("forced-portable", portable_first_ms)):
            timings = samples[mode]
            median = statistics.median(timings)
            p95 = statistics.quantiles(timings, n=20, method="inclusive")[18]
            print(
                f"\nCRW-T3 benchmark: files={file_count} mode={mode} backend=portable "
                f"incremental_runs={runs} "
                f"first_full_ms={first_ms:.1f} incremental_median_ms={median:.1f} "
                f"incremental_p95_ms={p95:.1f} range_ms={min(timings):.1f}-{max(timings):.1f} "
                f"target_ms={target_ms}",
                flush=True,
            )

        payload = bytes(range(256)) * 4096
        (self.repo / relative).write_bytes(payload)
        reflink_id, _ = self.measure(self.registry, "reflink")
        portable_id, _ = self.measure(portable, "portable", force_portable=True)
        self.assertEqual(reflink_id, portable_id)
        manifest = snapshot.read_manifest(self.registry, self.repo, reflink_id)
        digest = manifest["files"][relative]["sha256"]
        self.assertEqual((self.blobs / digest).read_bytes(), payload)

    def measure(
        self, registry: Registry, expected_backend: str, *, force_portable: bool = False
    ) -> tuple[str, float]:
        selection = patch.object(cow, "clone", new=lambda *_: False) if force_portable else nullcontext()
        with selection:
            start = time.perf_counter()
            snapshot_id = snapshot.take(registry, self.repo)
            elapsed_ms = (time.perf_counter() - start) * 1000
        self.assertEqual(snapshot.read_backend(registry, self.repo, snapshot_id), expected_backend)
        return snapshot_id, elapsed_ms
