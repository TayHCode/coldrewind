import sqlite3
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path

from . import retention, snapshot
from .config import Registry
from .ledger import append_step_locked
from .paths import file_lock


def workspace_root(registry: Registry, cwd: Path) -> Path | None:
    return max(
        (root for root in registry.roots() if cwd.is_relative_to(root)),
        key=lambda path: len(path.parts),
        default=None,
    )


def changed_paths_between(before: dict, after: dict) -> tuple[str, ...]:
    paths = []
    for section, prefix in (("files", ""), ("git", ".git/")):
        old, new = before[section], after[section]
        paths.extend(
            prefix + path for path in old.keys() | new.keys() if old.get(path) != new.get(path)
        )
    return tuple(sorted(paths))


def run(registry: Registry, command: tuple[str, ...]) -> int:
    """Capture a command in its registered workspace and return its shell status."""
    root = workspace_root(registry, Path.cwd())
    if root is None:
        raise ValueError("current directory is outside registered workspaces")

    with ExitStack() as capture:
        with snapshot.track_capture_error(registry, root, b"run_before"), registry.workspace_lock(root) as store:
            pre_id = snapshot.take_locked(store, root)
            marker = snapshot.start_capture_locked(store, "run", pre_id)
            capture.enter_context(file_lock(marker))
            retention.maintain_locked(store, keep={pre_id})
            before = snapshot.read_manifest(registry, root, pre_id)
        with subprocess.Popen(command) as child:
            while True:
                try:
                    status = child.wait()
                    break
                except KeyboardInterrupt:
                    continue

        try:
            with registry.workspace_lock(root) as store:
                try:
                    post_id = snapshot.take_locked(store, root)
                    after = snapshot.read_manifest(registry, root, post_id)
                    changed_paths = changed_paths_between(before, after)
                except (OSError, RuntimeError, ValueError) as error:
                    print(f"coldrewind run: post-command snapshot failed: {error}", file=sys.stderr)
                    snapshot.record_capture_error(registry, root, b"run_after")
                    post_id = None
                    changed_paths = ()
                append_step_locked(
                    store, root, agent="run", command=command, capture=marker.name,
                    changed_paths=changed_paths, pre_snapshot_id=pre_id, post_snapshot_id=post_id,
                )
                marker.unlink()
                retention.maintain_locked(store)
        except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
            print(f"coldrewind run: timeline write failed: {error}", file=sys.stderr)
            snapshot.record_capture_error(registry, root, b"run_timeline")
    return 128 - status if status < 0 else status
