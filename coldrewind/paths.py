import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def workspace_path(root: Path, relative: str | Path) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("workspace path must be relative and contain no '..'")

    root = root.resolve(strict=True)
    candidate = root
    for part in path.parts:
        candidate /= part
        if not candidate.resolve().is_relative_to(root):
            raise ValueError("path escapes the workspace")
    return candidate


def is_ignored(relative: str | Path) -> bool:
    return Path(relative).parts[:2] == (".git", "objects")


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)
