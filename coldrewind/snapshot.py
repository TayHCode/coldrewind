import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import time
import uuid
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from . import retention
from .config import Registry
from .ledger import record_overlap_locked
from .git_state import git_dirs, git_files
from . import cow

RACY_WINDOW_NS = 1_000_000_000
SCAN_ATTEMPTS = 3
CHUNK = 1 << 20
CAPTURE_ERROR = "last-capture-error"
CAPTURE_ERROR_MESSAGES = {
    b"hook": "Hook capture failed",
    b"run_before": "Pre-command capture failed",
    b"run_after": "Post-command snapshot failed",
    b"run_timeline": "Timeline write failed",
}


DIGEST = re.compile("[0-9a-f]{64}")


def is_digest(value: object) -> bool:
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def take(registry: Registry, root: Path, *, keep: frozenset[str] = frozenset()) -> str:
    root = root.resolve(strict=True)
    with registry.workspace_lock(root) as store:
        snapshot_id = take_locked(store, root)
        retention.prune_locked(store, keep=keep | {snapshot_id})
        return snapshot_id


def read_marker(marker: Path) -> str | None:
    try:
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("pending hook marker is not a regular file")
        if marker.name.startswith("run."):
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                return None
        elif info.st_mtime < time.time() - retention.MAX_AGE_SECONDS:
            return None
        value = os.read(fd, 65).decode("ascii", "replace")
    finally:
        os.close(fd)
    return value if is_digest(value) else None


def pending_directory(store: Path) -> Path:
    pending = store / "pending"
    pending.mkdir(mode=0o700, exist_ok=True)
    if pending.is_symlink() or not pending.is_dir():
        raise ValueError("ColdRewind store directory is not a real directory")
    return pending


HOOK_MARKER = re.compile(r"[0-9a-f]{64}(?:\.[0-9a-f]{32})?")


def describe_marker(store: Path, name: str) -> str:
    if not HOOK_MARKER.fullmatch(name):
        return name
    pending = store / "pending"
    if pending.is_symlink():
        raise ValueError("ColdRewind store directory is not a real directory")
    try:
        info = (pending / name).lstat()
    except FileNotFoundError:
        return f"{name} (hook marker is gone)"
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("pending hook marker is not a regular file")
    expiry = datetime.fromtimestamp(info.st_mtime + retention.MAX_AGE_SECONDS, UTC)
    return f"{name} (hook pin expiry {expiry.isoformat()}, no manual clear command)"


def pending_markers(store: Path, *, reap: bool = False) -> dict[str, str]:
    pending = store / "pending"
    if pending.is_symlink():
        raise ValueError("ColdRewind store directory is not a real directory")
    if not pending.exists():
        return {}
    active = {}
    for marker in pending.iterdir():
        prefix, _, nonce = marker.name.partition(".")
        if not (HOOK_MARKER.fullmatch(marker.name) or
                (prefix == "run" and re.fullmatch("[0-9a-f]{32}", nonce))):
            continue
        try:
            snapshot_id = read_marker(marker)
        except (OSError, ValueError):
            continue
        if snapshot_id is not None:
            active[marker.name] = snapshot_id
        elif reap and (prefix == "run" or marker.lstat().st_mtime < time.time() - retention.MAX_AGE_SECONDS):
            marker.unlink(missing_ok=True)
    return active


def pending_ids(store: Path) -> frozenset[str]:
    return frozenset(pending_markers(store, reap=True).values())


def start_capture_locked(store: Path, key: str, snapshot_id: str) -> Path:
    pending = pending_directory(store)
    marker = pending / f"{key}.{uuid.uuid4().hex}"
    record_overlap_locked(store, marker.name, tuple(pending_markers(store)))
    _write(pending, marker, snapshot_id.encode("ascii"))
    return marker


def take_locked(store: Path, root: Path, *, exclude: str | None = None) -> str:
    blobs = store / "blobs"
    snapshots = store / "snapshots"
    for directory in (blobs, snapshots):
        if not directory.exists():
            directory.mkdir(mode=0o700)
            _fsync_dir(store)
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("ColdRewind store directory is not a real directory")
    cache_path = store / "stat-cache.json"
    old_cache = _read_cache(cache_path)

    for _ in range(SCAN_ATTEMPTS):
        captures: set[str] = set()
        try:
            files, new_cache, keys = _scan(root, blobs, old_cache, captures, exclude)
            git, git_keys = _capture_git(root, blobs, captures)
        except FileNotFoundError:
            continue
        if all(_stat_key(path) == key for path, key in (keys | git_keys).items()) and set(
            git_files(root)
        ) == set(git):
            break
    else:
        raise RuntimeError("workspace kept changing during the snapshot")

    manifest = json.dumps(
        {"version": 1, "identity": _identity(root), "files": files, "git": git},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    snapshot_id = hashlib.sha256(manifest).hexdigest()
    backend = "mixed" if len(captures) > 1 else next(iter(captures), "cached")
    _write(snapshots, snapshots / f"{snapshot_id}.backend", backend.encode("ascii"))

    target = snapshots / f"{snapshot_id}.json"
    if target.exists():
        os.utime(target)
    else:
        _write(snapshots, target, manifest)
    if new_cache != old_cache:
        _write(store, cache_path, json.dumps(new_cache, separators=(",", ":")).encode())
    return snapshot_id


def _scan(
    root: Path, blobs: Path, old_cache: dict[str, list], captures: set[str], exclude: str | None = None
) -> tuple[dict, dict, dict]:
    stored = set(os.listdir(blobs))
    started = time.time_ns()
    files: dict[str, dict] = {}
    new_cache: dict[str, list] = {}
    keys: dict[str, list] = {str(root): _key(os.lstat(root))}
    for dirpath, dirnames, filenames, dirfd in os.fwalk(root, onerror=_raise):
        dirnames[:] = [name for name in dirnames if name != ".git" and not (dirpath == str(root) and name == exclude)]
        prefix = os.path.relpath(dirpath, root).replace(os.sep, "/")
        bytecode = os.path.basename(dirpath) == "__pycache__"
        for name in (*dirnames, *filenames):
            rel = name if prefix == "." else f"{prefix}/{name}"
            st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                files[rel] = {"type": "symlink", "target": os.readlink(name, dir_fd=dirfd)}
            elif stat.S_ISDIR(st.st_mode):
                keys[f"{root}/{rel}"] = _key(st)
                files[rel] = {"type": "dir", "mode": stat.S_IMODE(st.st_mode)}
            elif stat.S_ISREG(st.st_mode):
                if bytecode and name.endswith(".pyc"):
                    continue
                key = _key(st)
                keys[f"{root}/{rel}"] = key
                hit = old_cache.get(rel)
                if hit is not None and hit[:4] == key and hit[4] in stored:
                    digest = hit[4]
                    new_cache[rel] = hit
                else:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
                    digest, stable = _store_fd(blobs, fd, key, captures)
                    if stable and st.st_ctime_ns < started - RACY_WINDOW_NS:
                        new_cache[rel] = [*key, digest]
                files[rel] = {"type": "file", "mode": stat.S_IMODE(st.st_mode), "sha256": digest}
    return files, new_cache, keys


def _capture_git(root: Path, blobs: Path, captures: set[str]) -> tuple[dict, dict]:
    git = {}
    keys = {}
    for name, path in git_files(root).items():
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        st = os.fstat(fd)
        digest, _ = _store_fd(blobs, fd, None, captures)
        git[name] = {"mode": stat.S_IMODE(st.st_mode), "sha256": digest}
        keys[str(path)] = _key(st)
    return git, keys


def _identity(root: Path) -> list[list[int]]:
    return [[st.st_dev, st.st_ino] for st in map(os.stat, (root, *(git_dirs(root) or ())))]


def _key(st: os.stat_result) -> list[int]:
    return [st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_ino]


def _stat_key(path: str) -> list[int] | None:
    try:
        return _key(os.lstat(path))
    except FileNotFoundError:
        return None


def read_manifest(registry: Registry, root: Path, snapshot_id: str) -> dict:
    if not is_digest(snapshot_id):
        raise ValueError("snapshot id must be a SHA-256 hex digest")
    path = registry.store_path(root) / "snapshots" / f"{snapshot_id}.json"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != snapshot_id:
        raise ValueError("snapshot manifest does not match its id")
    return json.loads(data)


def read_backend(registry: Registry, root: Path, snapshot_id: str) -> str:
    if not is_digest(snapshot_id):
        raise ValueError("snapshot id must be a SHA-256 hex digest")
    manifest = registry.store_path(root) / "snapshots" / f"{snapshot_id}.json"
    manifest.stat()
    try:
        backend = manifest.with_suffix(".backend").read_text(encoding="ascii")
    except FileNotFoundError:
        return "portable"
    if backend not in {"portable", "reflink", "mixed", "cached"}:
        raise ValueError("invalid snapshot backend")
    return backend


def latest_capture_error(registry: Registry, root: Path) -> str | None:
    path = registry.store_path(root) / CAPTURE_ERROR
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("capture error record is not a regular file")
        return CAPTURE_ERROR_MESSAGES.get(os.read(fd, 32))
    finally:
        os.close(fd)


def record_capture_error(registry: Registry, root: Path, reason: bytes) -> None:
    try:
        store = registry.store_path(root)
        _write(store, store / CAPTURE_ERROR, reason)
    except (OSError, RuntimeError, ValueError):
        pass


@contextmanager
def track_capture_error(registry: Registry, root: Path, reason: bytes):
    try:
        yield
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        record_capture_error(registry, root, reason)
        raise


def latest_backend(registry: Registry, root: Path) -> str | None:
    if not (registry.store_path(root) / "snapshots").is_dir():
        return None
    with registry.workspace_lock(root) as store:
        snapshots = store / "snapshots"
        recency = {
            path.stem: path.stat().st_mtime_ns
            for path in snapshots.glob("*.backend")
            if is_digest(path.stem)
        }
        latest = max(
            (path for path in snapshots.glob("*.json") if is_digest(path.stem)),
            key=lambda path: recency[path.stem] if path.stem in recency else path.stat().st_mtime_ns,
            default=None,
        )
        return read_backend(registry, root, latest.stem) if latest is not None else None


def _read_cache(path: Path) -> dict[str, list]:
    try:
        data = json.loads(path.read_bytes())
    except (FileNotFoundError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        rel: entry
        for rel, entry in data.items()
        if isinstance(entry, list) and len(entry) == 5 and is_digest(entry[4])
    }


def _store_fd(blobs: Path, fd: int, key: list | None, captures: set[str]) -> tuple[str, bool]:
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("snapshot source is not a regular file")

        can_share_block = before.st_size >= before.st_blksize
        if not can_share_block:
            data = os.pread(fd, before.st_blksize, 0)
            if len(data) == before.st_size:
                digest = hashlib.sha256(data).hexdigest()
                blob = blobs / digest
                if not blob.exists():
                    _write(blobs, blob, data)
                    captures.add("portable")
                return digest, key == _key(os.fstat(fd))
        else:
            with os.fdopen(fd, "rb", closefd=False) as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            if (blobs / digest).exists():
                return digest, key == _key(os.fstat(fd))
            os.lseek(fd, 0, os.SEEK_SET)

        hasher = hashlib.sha256()
        out_fd, temporary = tempfile.mkstemp(dir=blobs, prefix=".tmp-")
        try:
            with ExitStack() as stack:
                out = stack.enter_context(os.fdopen(out_fd, "wb"))
                reflinked = can_share_block and cow.clone(fd, out.fileno(), Path(temporary))
                if reflinked:
                    cloned = stack.enter_context(open(temporary, "rb"))
                    while chunk := cloned.read(CHUNK):
                        hasher.update(chunk)
                else:
                    while chunk := os.read(fd, CHUNK):
                        hasher.update(chunk)
                        out.write(chunk)
                    out.flush()
                digest = hasher.hexdigest()
                blob = blobs / digest
                if not blob.exists():
                    os.fsync(cloned.fileno() if reflinked else out.fileno())
                    os.replace(temporary, blob)
                    _fsync_dir(blobs)
                    captures.add("reflink" if reflinked else "portable")
            after = os.fstat(fd)
        finally:
            Path(temporary).unlink(missing_ok=True)
    finally:
        os.close(fd)
    return digest, key == _key(after)


def _write(directory: Path, path: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
        _fsync_dir(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _raise(error: OSError) -> None:
    raise error


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
