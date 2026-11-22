import json
import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .classify import Reversibility, classify
from .config import Registry
from .redact import command_summary


@dataclass(frozen=True)
class Step:
    step_id: int
    timestamp: str
    agent: str
    command: tuple[str, ...]
    reversibility: Reversibility
    reason: str
    pre_snapshot_id: str | None
    post_snapshot_id: str | None
    changed_paths: tuple[str, ...]


def _check_database_files(database: Path) -> None:
    for suffix in ("", "-journal", "-wal", "-shm"):
        path = database.with_name(database.name + suffix)
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("ledger files must be regular files without links")


def record_overlap_locked(store: Path, capture: str, peers: tuple[str, ...]) -> None:
    if not peers:
        return
    database = store / "timeline.sqlite3"
    _check_database_files(database)
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        _record_overlap(connection, capture, peers)


def _record_overlap(connection, capture: str, peers: tuple[str, ...]) -> None:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS capture_overlaps (
            capture TEXT NOT NULL, peer TEXT NOT NULL, step_id INTEGER,
            PRIMARY KEY (capture, peer)
        )
    """)
    connection.executemany(
        "INSERT OR IGNORE INTO capture_overlaps (capture, peer) VALUES (?, ?)",
        [pair for peer in peers for pair in ((capture, peer), (peer, capture))],
    )


def _has_overlaps(connection: sqlite3.Connection) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_schema WHERE type='table' AND name='capture_overlaps'"
    ).fetchone() is not None


def discard_denied_overlaps_locked(store: Path, capture: str) -> None:
    database = store / "timeline.sqlite3"
    _check_database_files(database)
    if not database.exists():
        return
    with closing(sqlite3.connect(database)) as connection, connection:
        if _has_overlaps(connection):
            connection.execute("""
                DELETE FROM capture_overlaps WHERE (capture = ? OR peer = ?)
                AND NOT EXISTS (SELECT 1 FROM capture_overlaps
                                WHERE capture = ? AND step_id IS NOT NULL)
            """, (capture, capture, capture))


def overlapping_steps_locked(store: Path, step_id: int) -> list[tuple[int | None, str]]:
    database = store / "timeline.sqlite3"
    _check_database_files(database)
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        if not _has_overlaps(connection):
            return []
        rows = connection.execute("""
            SELECT other.step_id, other.capture FROM capture_overlaps AS this
            JOIN capture_overlaps AS other ON this.peer = other.capture AND other.peer = this.capture
            WHERE this.step_id = ? AND this.capture NOT LIKE 'restore.%'
            ORDER BY other.step_id, other.capture
        """, (step_id,))
        return rows.fetchall()


def append_step(registry: Registry, root: Path, **fields) -> Step:
    root = root.resolve(strict=True)
    with registry.workspace_lock(root) as store:
        from .retention import maintain_locked

        step = append_step_locked(store, root, **fields)
        maintain_locked(store)
        return step


def append_step_locked(
    store: Path,
    root: Path,
    *,
    agent: str,
    command: tuple[str, ...],
    changed_paths: tuple[str, ...] = (),
    pre_snapshot_id: str | None = None,
    post_snapshot_id: str | None = None,
    capture_complete: bool = False,
    capture: str | None = None,
    captures_during_restore: tuple[str, ...] = (),
) -> Step:
    """Append an observed step. Set capture_complete only with evidence that
    both snapshots cover all changes and no external effects occurred.
    """
    if not isinstance(agent, str) or not agent:
        raise ValueError("agent must be a nonempty string")
    if not isinstance(command, tuple) or not command or any(
        not isinstance(arg, str) or "\x00" in arg for arg in command
    ) or not command[0]:
        raise ValueError("command must be an argument tuple with a nonempty tool name")
    if not isinstance(changed_paths, tuple) or any(
        not isinstance(path, str) or not path or "\x00" in path for path in changed_paths
    ):
        raise ValueError("changed_paths must be a tuple of nonempty path strings")
    if any(
        value is not None and (not isinstance(value, str) or not value)
        for value in (pre_snapshot_id, post_snapshot_id)
    ):
        raise ValueError("snapshot IDs must be nonempty strings or None")
    if not isinstance(capture_complete, bool):
        raise ValueError("capture_complete must be a boolean")

    database = store / "timeline.sqlite3"
    _check_database_files(database)
    reversibility, reason = classify(
        root,
        command,
        changed_paths,
        pre_snapshot_id=pre_snapshot_id,
        post_snapshot_id=post_snapshot_id,
        capture_complete=capture_complete,
    )
    command = command_summary(agent, command)
    timestamp = datetime.now(UTC).isoformat(timespec="microseconds")
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS steps (
                step_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                agent TEXT NOT NULL,
                command TEXT NOT NULL,
                reversibility TEXT NOT NULL
                    CHECK (reversibility IN ('reversible', 'partial', 'irreversible')),
                reason TEXT NOT NULL,
                pre_snapshot_id TEXT,
                post_snapshot_id TEXT,
                changed_paths TEXT NOT NULL
            )
        """)
        cursor = connection.execute("""
            INSERT INTO steps (
                timestamp, agent, command, reversibility, reason,
                pre_snapshot_id, post_snapshot_id, changed_paths
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, agent, json.dumps(command), reversibility, reason,
            pre_snapshot_id, post_snapshot_id, json.dumps(changed_paths),
        ))
        step_id = cursor.lastrowid
        if captures_during_restore:
            capture = f"restore.{step_id}"
            _record_overlap(connection, capture, captures_during_restore)
        if capture is not None and _has_overlaps(connection):
            connection.execute("UPDATE capture_overlaps SET step_id = ? WHERE capture = ?",
                               (step_id, capture))

    return Step(
        step_id, timestamp, agent, command, reversibility, reason,
        pre_snapshot_id, post_snapshot_id, changed_paths,
    )


def read_steps(registry: Registry, root: Path) -> list[Step]:
    with registry.workspace_lock(root) as store:
        return read_steps_locked(store)


def read_steps_locked(store: Path) -> list[Step]:
    database = store / "timeline.sqlite3"
    _check_database_files(database)
    if not database.exists():
        return []
    with closing(sqlite3.connect(database.as_uri() + "?mode=rw", uri=True)) as connection:
        if connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table' AND name = 'steps'"
        ).fetchone() is None:
            return []
        rows = connection.execute("""
            SELECT step_id, timestamp, agent, command, reversibility, reason,
                   pre_snapshot_id, post_snapshot_id, changed_paths
            FROM steps ORDER BY step_id
        """)
        return [
            Step(
                step_id, timestamp, agent, tuple(json.loads(command)), reversibility,
                reason, pre_snapshot_id, post_snapshot_id, tuple(json.loads(changed_paths)),
            )
            for step_id, timestamp, agent, command, reversibility, reason,
            pre_snapshot_id, post_snapshot_id, changed_paths in rows
        ]
