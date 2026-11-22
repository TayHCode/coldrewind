import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import __version__, snapshot
from .config import Registry
from .ledger import _check_database_files, _has_overlaps


MAX_BYTES = 500 * 1024 * 1024
MAX_AGE_SECONDS = 7 * 24 * 60 * 60
MARKER = ".cold-artifact.json"
PROTECT_NEWEST = 2
TALLY = "blob-tally.json"
TALLY_SLACK = 1024


@dataclass
class PruneResult:
    pruned: list[str]
    total_bytes: int
    protected_bytes: int | None


def _limit(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    if not value.isascii() or not value.isdecimal():
        raise ValueError(f"{name} must be a nonnegative integer")
    return int(value)


def prune(registry: Registry, root: Path, *, keep: frozenset[str] = frozenset()) -> list[str]:
    with registry.workspace_lock(root) as store:
        return prune_locked(store, keep=keep).pruned


def maintain_locked(store: Path, *, keep: frozenset[str] = frozenset()) -> None:
    try:
        prune_locked(store, keep=keep)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"coldrewind: retention failed: {error}", file=sys.stderr)


def _stored_bytes(directory: Path, known: dict[str, int] | None = None) -> int:
    total = 0
    with os.scandir(directory) as entries:
        for entry in entries:
            if known is not None and entry.name in known:
                total += known[entry.name]
            elif entry.is_dir(follow_symlinks=False):
                total += _stored_bytes(Path(entry.path))
            else:
                total += entry.stat(follow_symlinks=False).st_size
    return total


def prune_locked(store: Path, *, keep: frozenset[str] = frozenset(), report: bool = False) -> PruneResult:
    if (store / "restore-intent.json").exists():
        raise ValueError("cannot prune during restore recovery")
    cap = _limit("COLDREWIND_MAX_BYTES", MAX_BYTES)
    age = _limit("COLDREWIND_MAX_AGE_SECONDS", MAX_AGE_SECONDS)
    now = time.time()
    cutoff = now - min(age, int(now) + 1)
    active = snapshot.pending_markers(store, reap=True)
    keep = keep | set(active.values())
    snapshots, blobs = store / "snapshots", store / "blobs"
    _write_marker(store)
    if any(path.is_symlink() or (path.exists() and not path.is_dir()) for path in (snapshots, blobs)):
        raise ValueError("ColdRewind store directory is not a real directory")
    stats = {}
    backend_sizes = {}
    for path in snapshots.iterdir() if snapshots.exists() else ():
        snapshot_id = path.stem
        if not snapshot.is_digest(snapshot_id):
            continue
        if path.suffix == ".json":
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("snapshot manifest is not a regular file")
            stats[snapshot_id] = info
        elif path.suffix == ".backend":
            backend_sizes[snapshot_id] = path.lstat().st_size
    old_tally = _read_tally(store / TALLY)
    tally, restatted = _count_blobs(blobs, old_tally) if blobs.exists() else ({}, 0)
    _save_tally(store, tally, restatted)
    blob_sizes = {digest: size for digest, (_, size) in tally.items()}
    database = store / "timeline.sqlite3"
    protected_steps = _protected_steps(database)
    protected = set(keep) | {sid for _, *pair in protected_steps for sid in pair if sid}
    oldest_first = sorted(stats, key=lambda key: stats[key].st_mtime_ns)
    protected.update(oldest_first[-PROTECT_NEWEST:])
    step_ids = [row[0] for row in protected_steps]
    _trim_ledger(database, step_ids, active, cutoff=cutoff)
    sizes = {f"{sid}.json": info.st_size for sid, info in stats.items()}
    sizes.update({f"{sid}.backend": size for sid, size in backend_sizes.items()})
    directories = {}
    if snapshots.exists():
        directories["snapshots"] = _stored_bytes(snapshots, sizes)
    if blobs.exists():
        directories["blobs"] = _stored_bytes(blobs, blob_sizes)
    total = _stored_bytes(store, directories)
    if not report and total <= cap and all(st.st_mtime >= cutoff for st in stats.values()):
        return PruneResult([], total, None)

    manifests = {sid: _blob_refs(snapshots / f"{sid}.json") for sid in stats}
    refs = Counter(digest for digests in manifests.values() for digest in digests)
    pinned = protected.intersection(stats)
    pinned_blobs = {digest for sid in pinned for digest in manifests[sid]}
    protected_bytes = sum(stats[sid].st_size + backend_sizes.get(sid, 0) for sid in pinned)
    protected_bytes += sum(blob_sizes.get(digest, 0) for digest in pinned_blobs)
    for sid in backend_sizes.keys() - stats.keys():
        (snapshots / f"{sid}.backend").unlink()
        total -= backend_sizes[sid]
    total -= sum(size for digest, size in blob_sizes.items() if refs[digest] == 0)
    pruned = []
    for sid in oldest_first:
        if sid in protected or (stats[sid].st_mtime >= cutoff and total <= cap):
            continue
        (snapshots / f"{sid}.backend").unlink(missing_ok=True)
        (snapshots / f"{sid}.json").unlink()
        pruned.append(sid)
        total -= stats[sid].st_size + backend_sizes.get(sid, 0)
        for digest in manifests[sid]:
            refs[digest] -= 1
            if refs[digest] == 0:
                total -= blob_sizes.get(digest, 0)

    if snapshots.exists():
        snapshot._fsync_dir(snapshots)
    for digest in blob_sizes:
        if refs[digest] == 0:
            (blobs / digest).unlink()
    if blobs.exists():
        snapshot._fsync_dir(blobs)
    if total > cap:
        empty_tally = _encode_tally({})
        caches = {}
        for path in (store / TALLY, store / "stat-cache.json"):
            if path.is_file() and not path.is_symlink():
                minimum = len(empty_tally) if path.name == TALLY else 0
                caches[path] = max(0, path.stat().st_size - minimum)
        reclaimable = sum(caches.values())
        if total - reclaimable > cap and database.exists():
            before = database.stat().st_size
            _trim_ledger(database, step_ids, active, budget=cap - (total - before - reclaimable))
            total += database.stat().st_size - before
        if total - reclaimable <= cap:
            for path, size in caches.items():
                if total <= cap:
                    break
                if size:
                    if path.name == TALLY:
                        snapshot._write(store, path, empty_tally)
                    else:
                        path.unlink()
                    total -= size
    return PruneResult(pruned, _stored_bytes(store), protected_bytes)


def _count_blobs(
    blobs: Path, old_tally: dict[str, list[int]]
) -> tuple[dict[str, list[int]], int]:
    tally = {}
    restatted = 0
    with os.scandir(blobs) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False) or not snapshot.is_digest(entry.name):
                continue
            known = old_tally.get(entry.name)
            if known is not None and known[0] == entry.inode():
                tally[entry.name] = known
            else:
                tally[entry.name] = [entry.inode(), entry.stat(follow_symlinks=False).st_size]
                restatted += 1
    return tally, restatted


def _read_tally(path: Path) -> dict[str, list[int]]:
    if path.is_symlink() or not path.is_file():
        return {}
    try:
        digest, _, body = path.read_bytes().partition(b"\n")
        if hashlib.sha256(body).hexdigest().encode() != digest:
            return {}
        data = json.loads(body)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        digest: entry
        for digest, entry in data.items()
        if isinstance(entry, list)
        and len(entry) == 2
        and all(type(value) is int and value >= 0 for value in entry)
    }


def _encode_tally(tally: dict[str, list[int]]) -> bytes:
    body = json.dumps(tally, separators=(",", ":")).encode()
    return hashlib.sha256(body).hexdigest().encode() + b"\n" + body


def _save_tally(store: Path, tally: dict[str, list[int]], restatted: int) -> None:
    if restatted >= TALLY_SLACK:
        snapshot._write(store, store / TALLY, _encode_tally(tally))


def _blob_refs(path: Path) -> set[str]:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != path.stem:
        raise ValueError("snapshot manifest does not match its id")
    manifest = json.loads(data)
    entries = [*manifest["files"].values(), *manifest["git"].values()]
    return {entry["sha256"] for entry in entries if "sha256" in entry}


def _protected_steps(database: Path) -> list[tuple]:
    _check_database_files(database)
    if not database.exists():
        return []
    with closing(sqlite3.connect(database.as_uri() + "?mode=rw", uri=True)) as connection:
        if connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'steps'"
        ).fetchone() is None:
            return []
        return connection.execute("""
            SELECT step_id, pre_snapshot_id, post_snapshot_id FROM steps
            WHERE step_id = (SELECT MAX(step_id) FROM steps)
               OR step_id = (SELECT MAX(step_id) FROM steps WHERE agent = 'coldrewind'
                             AND json_extract(command, '$[0]') = 'coldrewind'
                             AND json_extract(command, '$[1]') = 'undo')
        """).fetchall()


def _trim_ledger(database: Path, kept: list[int], active: dict[str, str], *,
                 cutoff: float | None = None, budget: int | None = None) -> None:
    if not database.exists():
        return
    with closing(sqlite3.connect(database)) as connection:
        if budget is not None and connection.execute("PRAGMA freelist_count").fetchone()[0]:
            connection.execute("VACUUM")
            if database.stat().st_size <= budget:
                return
        overlaps = _has_overlaps(connection)
        if overlaps:
            connection.execute("CREATE TEMP TABLE active (capture TEXT PRIMARY KEY)")
            connection.executemany("INSERT INTO active VALUES (?)", ((name,) for name in active))
        while True:
            before = connection.total_changes
            with connection:
                if kept:
                    keep = (kept[0], kept[-1])
                    if cutoff is not None:
                        stamp = datetime.fromtimestamp(cutoff, UTC).isoformat(timespec="microseconds")
                        connection.execute("""
                            DELETE FROM steps WHERE timestamp < ? AND step_id NOT IN (?, ?)
                        """, (stamp, *keep))
                    else:
                        size = database.stat().st_size
                        rows, = connection.execute("SELECT COUNT(*) FROM steps").fetchone()
                        batch = max(1, rows * (size - max(0, budget)) // size)
                        connection.execute("""
                            DELETE FROM steps WHERE step_id IN (
                                SELECT step_id FROM steps WHERE step_id NOT IN (?, ?)
                                ORDER BY step_id LIMIT ?)
                        """, (*keep, batch))
                if overlaps:
                    has_step = "step_id IN (SELECT step_id FROM steps)" if kept else "0"
                    connection.execute(f"""
                        WITH live AS MATERIALIZED (
                            SELECT capture, peer FROM capture_overlaps
                            WHERE {has_step} OR capture IN (SELECT capture FROM active))
                        DELETE FROM capture_overlaps AS o WHERE
                            (o.capture, o.peer) NOT IN (SELECT capture, peer FROM live)
                            AND (o.peer, o.capture) NOT IN (SELECT capture, peer FROM live)
                    """)
            changed = connection.total_changes != before
            if budget is not None and changed:
                connection.execute("VACUUM")
            if budget is None or not changed or database.stat().st_size <= budget:
                break


def _write_marker(store: Path) -> None:
    path = store / MARKER
    try:
        if (
            not path.is_symlink()
            and path.is_file()
            and json.loads(path.read_bytes())["retention"]["policy"] == "keep"
        ):
            return
    except (ValueError, KeyError, TypeError):
        pass
    now = datetime.now(UTC).replace(microsecond=0)
    marker = {
        "schema_version": 1,
        "retention": {
            "owner": "coldrewind",
            "policy": "keep",
        },
        "provenance": {"producer": f"coldrewind {__version__}", "created_at": _utc(now)},
    }
    snapshot._write(store, store / MARKER, json.dumps(marker, sort_keys=True).encode())


def _utc(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
