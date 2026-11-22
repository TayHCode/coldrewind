import hashlib
import json
import signal
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import TextIO

from . import retention, snapshot
from .config import Registry
from .ledger import append_step_locked, discard_denied_overlaps_locked, record_overlap_locked
from .runner import changed_paths_between, workspace_root

AGENTS = {"claude": "Claude Code", "codex": "Codex", "opencode": "OpenCode"}
PHASES = ("pre", "post", "denied")
TIMEOUT_SECONDS = 60


def _command(payload: dict) -> tuple[str, ...]:
    tool = payload.get("tool_name")
    if not isinstance(tool, str) or not tool or "\x00" in tool:
        raise ValueError("hook input needs a tool_name")
    tool_input = payload.get("tool_input")
    if tool.lower() == "bash" and isinstance(tool_input, dict):
        command = tool_input.get("command")
        if isinstance(command, str) and command and "\x00" not in command:
            return ("bash", "-c", command)
    return (tool,)


def handle(registry: Registry, client: str, phase: str, payload: object) -> None:
    if client not in AGENTS or phase not in PHASES:
        raise ValueError("unknown hook client or phase")
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")
    cwd, call_id = payload.get("cwd"), payload.get("tool_use_id")
    if not isinstance(cwd, str) or not Path(cwd).is_absolute():
        raise ValueError("hook input needs an absolute cwd")
    if not isinstance(call_id, str) or not call_id:
        raise ValueError("hook input needs a tool_use_id")
    session_id = payload.get("session_id")
    if phase == "denied" and (
        client != "claude" or payload.get("hook_event_name") != "PermissionDenied"
        or not isinstance(session_id, str) or not session_id.strip() or not call_id.strip()
    ):
        raise ValueError("denial needs a Claude PermissionDenied event with session and call IDs")
    command = _command(payload)
    root = workspace_root(registry, Path(cwd).resolve())
    if root is None:
        return

    key = hashlib.sha256(
        json.dumps([client, session_id, call_id]).encode()
    ).hexdigest()
    with snapshot.track_capture_error(registry, root, b"hook"), registry.workspace_lock(root) as store:
        pending = snapshot.pending_directory(store)
        marker = next(pending.glob(f"{key}.*"), pending / key)
        pre_id = snapshot.read_marker(marker)
        if phase == "denied":
            if pre_id is not None:
                discard_denied_overlaps_locked(store, marker.name)
                marker.unlink()
            return
        if phase == "pre" and pre_id is not None:
            return
        if phase == "pre":
            snapshot_id = snapshot.take_locked(store, root)
            marker.unlink(missing_ok=True)
            snapshot.start_capture_locked(store, key, snapshot_id)
        else:
            if pre_id is None:
                if not marker.exists():
                    marker = pending / f"{key}.{uuid.uuid4().hex}"
                record_overlap_locked(store, marker.name, tuple(snapshot.pending_markers(store)))
            try:
                snapshot_id = snapshot.take_locked(store, root)
                after = snapshot.read_manifest(registry, root, snapshot_id)
                changed = () if pre_id is None else changed_paths_between(
                    snapshot.read_manifest(registry, root, pre_id), after
                )
                append_step_locked(
                    store,
                    root,
                    agent=AGENTS[client],
                    capture=marker.name,
                    command=command,
                    changed_paths=changed,
                    pre_snapshot_id=pre_id,
                    post_snapshot_id=snapshot_id,
                )
            finally:
                marker.unlink(missing_ok=True)
        retention.prune_locked(store, keep={snapshot_id})


class HookTimeout(RuntimeError):
    pass


def _timeout(signum: int, frame: object) -> None:
    raise HookTimeout(f"gave up after {TIMEOUT_SECONDS}s")


def main(registry: Registry, client: str, phase: str, stdin: TextIO) -> int:
    """Record a hook event. Always exit 0 so ColdRewind never blocks the agent."""
    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(TIMEOUT_SECONDS)
    try:
        handle(registry, client, phase, json.loads(stdin.read()))
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        print(f"coldrewind hook: {error}", file=sys.stderr)
    finally:
        signal.alarm(0)
    return 0
