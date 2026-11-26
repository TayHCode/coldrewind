from dataclasses import dataclass
import hashlib
import json
import signal
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import TextIO

from . import guard, retention, snapshot
from .config import Registry
from .ledger import append_step_locked, discard_denied_overlaps_locked, record_overlap_locked
from .runner import changed_paths_between, workspace_root

AGENTS = {
    "claude": "Claude Code",
    "codex": "Codex",
    "opencode": "OpenCode",
    "cursor": "Cursor",
    "antigravity": "Antigravity",
    "gemini": "Gemini CLI",
}
PHASES = ("pre", "post", "denied")
TIMEOUT_SECONDS = 60

_SHELL_TOOLS = {
    "claude": {"bash"},
    "codex": {"bash", "shell", "shell_command", "exec_command"},
    "opencode": {"bash"},
    "cursor": {"shell", "bash", "run_terminal_cmd", "terminal"},
    "antigravity": {"run_command", "bash", "shell"},
    "gemini": {"run_shell_command", "shell", "bash"},
}


@dataclass(frozen=True)
class _HookEvent:
    cwd: Path
    effective_cwd: Path
    session_id: object
    call_id: str
    command: tuple[str, ...]


def _extract_shell_command(client: str, tool_name: str, tool_input: object, payload: dict) -> tuple[str, ...]:
    if tool_name.lower() in _SHELL_TOOLS[client]:
        candidates: list[object] = []
        if isinstance(tool_input, dict):
            if client == "antigravity":
                candidates.extend((tool_input.get("CommandLine"), tool_input.get("command"), tool_input.get("cmd")))
            else:
                candidates.extend((tool_input.get("command"), tool_input.get("cmd")))
        if client == "cursor":
            candidates.append(payload.get("command"))
        for candidate in candidates:
            if isinstance(candidate, str) and candidate and "\x00" not in candidate:
                return ("bash", "-c", candidate)
    return (tool_name,)


def _resolve_tool_cwd(base_cwd: Path, raw_dir: object) -> Path:
    if not isinstance(raw_dir, str) or not raw_dir or "\x00" in raw_dir:
        return base_cwd
    candidate = Path(raw_dir)
    if candidate.is_absolute():
        return candidate
    return base_cwd / candidate


def _first_absolute_path(*values: object) -> Path | None:
    for value in values:
        if isinstance(value, str) and value and Path(value).is_absolute():
            return Path(value)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item and Path(item).is_absolute():
                    return Path(item)
    return None


def _parse_event(client: str, phase: str, payload: object) -> _HookEvent:
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")

    if client == "antigravity":
        cwd = _first_absolute_path(payload.get("cwd"), payload.get("workspacePaths"))
        if cwd is None:
            raise ValueError("hook input needs an absolute cwd")
        session_id = payload.get("conversationId") or payload.get("session_id")
        tool_call = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
        call_id = tool_call.get("id") or payload.get("tool_use_id")
        if not isinstance(call_id, str) or not call_id:
            step_idx = payload.get("stepIdx")
            if isinstance(step_idx, int) and not isinstance(step_idx, bool) and step_idx >= 0:
                call_id = f"step:{step_idx}"
            else:
                raise ValueError("hook input needs a toolCall.id or stepIdx")
        tool_name = tool_call.get("name") or payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name or "\x00" in tool_name:
            raise ValueError("hook input needs a toolCall.name")
        tool_input = tool_call.get("args") if "args" in tool_call else payload.get("tool_input")
        effective_cwd = cwd
        if tool_name.lower() in _SHELL_TOOLS[client] and isinstance(tool_input, dict):
            effective_cwd = _resolve_tool_cwd(cwd, tool_input.get("Cwd") or tool_input.get("cwd"))
        command = _extract_shell_command(client, tool_name, tool_input, payload)
        return _HookEvent(cwd, effective_cwd, session_id, call_id, command)

    if client == "cursor":
        cwd = _first_absolute_path(payload.get("cwd"), payload.get("workspace_roots"))
        if cwd is None:
            raise ValueError("hook input needs an absolute cwd")
        session_id = payload.get("conversation_id") or payload.get("session_id")
        call_id = payload.get("tool_use_id") or payload.get("generation_id")
        if not isinstance(call_id, str) or not call_id:
            raise ValueError("hook input needs a tool_use_id")
        tool_name = payload.get("tool_name")
        if (not isinstance(tool_name, str) or not tool_name) and (
            payload.get("hook_event_name") in ("beforeShellExecution", "afterShellExecution")
            or isinstance(payload.get("command"), str)
        ):
            tool_name = "Shell"
        if not isinstance(tool_name, str) or not tool_name or "\x00" in tool_name:
            raise ValueError("hook input needs a tool_name")
        tool_input = payload.get("tool_input")
        effective_cwd = cwd
        if tool_name.lower() in _SHELL_TOOLS[client] and isinstance(tool_input, dict):
            effective_cwd = _resolve_tool_cwd(cwd, tool_input.get("working_directory") or tool_input.get("cwd"))
        command = _extract_shell_command(client, tool_name, tool_input, payload)
        return _HookEvent(cwd, effective_cwd, session_id, call_id, command)

    if client == "gemini":
        cwd = _first_absolute_path(payload.get("cwd"))
        if cwd is None:
            raise ValueError("hook input needs an absolute cwd")
        session_id = payload.get("session_id")
        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name or "\x00" in tool_name:
            raise ValueError("hook input needs a tool_name")
        tool_input = payload.get("tool_input")
        if tool_input is None and isinstance(payload.get("tool_args"), dict):
            tool_input = payload.get("tool_args")
        effective_cwd = cwd
        if tool_name.lower() in _SHELL_TOOLS[client] and isinstance(tool_input, dict):
            effective_cwd = _resolve_tool_cwd(cwd, tool_input.get("dir_path"))
        call_id = payload.get("tool_use_id") or payload.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            digest = hashlib.sha256(
                json.dumps([tool_name, tool_input], sort_keys=True, default=str).encode()
            ).hexdigest()
            call_id = f"gemini:{digest}"
        command = _extract_shell_command(client, tool_name, tool_input, payload)
        return _HookEvent(cwd, effective_cwd, session_id, call_id, command)

    # Claude Code, Codex, OpenCode
    cwd_raw, call_id = payload.get("cwd"), payload.get("tool_use_id")
    if not isinstance(cwd_raw, str) or not Path(cwd_raw).is_absolute():
        raise ValueError("hook input needs an absolute cwd")
    if not isinstance(call_id, str) or not call_id:
        raise ValueError("hook input needs a tool_use_id")
    session_id = payload.get("session_id")
    if phase == "denied" and (
        client != "claude" or payload.get("hook_event_name") != "PermissionDenied"
        or not isinstance(session_id, str) or not session_id.strip() or not call_id.strip()
    ):
        raise ValueError("denial needs a Claude PermissionDenied event with session and call IDs")
    tool_name = payload.get("tool_name")
    if not isinstance(tool_name, str) or not tool_name or "\x00" in tool_name:
        raise ValueError("hook input needs a tool_name")
    tool_input = payload.get("tool_input")
    base_cwd = Path(cwd_raw)
    effective_cwd = base_cwd
    if tool_name.lower() in _SHELL_TOOLS[client] and isinstance(tool_input, dict):
        effective_cwd = _resolve_tool_cwd(base_cwd, tool_input.get("workdir") or tool_input.get("cwd"))
    command = _extract_shell_command(client, tool_name, tool_input, payload)
    return _HookEvent(base_cwd, effective_cwd, session_id, call_id, command)


def handle(
    registry: Registry,
    client: str,
    phase: str,
    payload: object,
    *,
    guard_mode: str | None = None,
) -> None:
    if client not in AGENTS or phase not in PHASES:
        raise ValueError("unknown hook client or phase")
    if phase == "denied" and client != "claude":
        raise ValueError("denial needs a Claude PermissionDenied event with session and call IDs")

    event = _parse_event(client, phase, payload)
    resolved_effective_cwd = event.effective_cwd.resolve(strict=False)
    resolved_cwd = event.cwd.resolve(strict=False)
    effective_root = workspace_root(registry, resolved_effective_cwd)
    cwd_root = workspace_root(registry, resolved_cwd)
    guard_roots = tuple(dict.fromkeys(r for r in (effective_root, cwd_root) if r is not None))
    if not guard_roots:
        return

    match: guard.GuardMatch | None = None
    match_root: Path | None = None
    for candidate_root in guard_roots:
        candidate = guard.classify_guard(event.command, root=candidate_root, cwd=resolved_effective_cwd)
        if candidate is not None:
            if candidate.always_block:
                match, match_root = candidate, candidate_root
                break
            if match is None:
                match, match_root = candidate, candidate_root

    root = match_root if match_root is not None else guard_roots[0]
    force_checkpoint = False
    if phase == "pre":
        try:
            mode = guard.resolve_mode(guard_mode)
        except ValueError as error:
            if match is not None:
                raise guard.GuardBlocked(match, str(error)) from error
            raise
        if match is not None:
            if mode == "block" or (mode == "checkpoint" and match.always_block):
                raise guard.GuardBlocked(match, f"blocked {match.rule}: {match.reason}")
            force_checkpoint = mode == "checkpoint"

    key = hashlib.sha256(
        json.dumps([client, event.session_id, event.call_id]).encode()
    ).hexdigest()

    try:
        with snapshot.track_capture_error(registry, root, b"hook"), registry.workspace_lock(root) as store:
            pending = snapshot.pending_directory(store)
            marker = next(pending.glob(f"{key}.*"), pending / key)
            pre_id = snapshot.read_marker(marker)
            if phase == "denied":
                if pre_id is not None:
                    discard_denied_overlaps_locked(store, marker.name)
                    marker.unlink()
                return
            if phase == "pre" and pre_id is not None and not force_checkpoint:
                return
            if phase == "pre":
                if force_checkpoint:
                    snapshot_id = snapshot.take_locked(store, root)
                else:
                    min_interval = guard.snapshot_min_interval_seconds()
                    recent = snapshot.recent_snapshot_locked(store, min_interval)
                    snapshot_id = recent if recent is not None else snapshot.take_locked(store, root)
                retention.prune_locked(store, keep={snapshot_id})
                marker.unlink(missing_ok=True)
                snapshot.start_capture_locked(store, key, snapshot_id)
            else:
                if pre_id is None:
                    if not marker.exists():
                        marker = pending / f"{key}.{uuid.uuid4().hex}"
                    record_overlap_locked(store, marker.name, tuple(snapshot.pending_markers(store)))
                try:
                    before = None
                    if pre_id is not None:
                        try:
                            before = snapshot.read_manifest(registry, root, pre_id)
                        except FileNotFoundError:
                            pre_id = None
                    snapshot_id = snapshot.take_locked(store, root)
                    after = snapshot.read_manifest(registry, root, snapshot_id)
                    changed = changed_paths_between(before, after) if before is not None else ()
                    append_step_locked(
                        store,
                        root,
                        agent=AGENTS[client],
                        capture=marker.name,
                        command=event.command,
                        changed_paths=changed,
                        pre_snapshot_id=pre_id,
                        post_snapshot_id=snapshot_id,
                    )
                finally:
                    marker.unlink(missing_ok=True)
                retention.prune_locked(store, keep={snapshot_id})
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        if force_checkpoint and match is not None:
            raise guard.GuardBlocked(
                match,
                f"force-checkpoint failed before {match.rule}: {error}",
            ) from error
        raise


class HookTimeout(RuntimeError):
    pass


def _timeout(signum: int, frame: object) -> None:
    raise HookTimeout(f"gave up after {TIMEOUT_SECONDS}s")


def _emit_allow(client: str, phase: str) -> None:
    if client == "cursor":
        print(json.dumps({"permission": "allow"} if phase == "pre" else {}))
    elif client in ("antigravity", "gemini"):
        print(json.dumps({"decision": "allow"} if phase == "pre" else {}))


def _emit_block(client: str, message: str) -> int:
    print(f"coldrewind guard: {message}", file=sys.stderr)
    if client == "claude":
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }))
        return 2
    if client == "cursor":
        print(json.dumps({
            "permission": "deny",
            "agentMessage": message,
            "user_message": message,
        }))
        return 2
    if client == "gemini":
        print(json.dumps({"decision": "deny", "reason": message}))
        return 2
    if client == "antigravity":
        print(json.dumps({"decision": "deny", "reason": message}))
        return 0
    return 2


def main(
    registry: Registry,
    client: str,
    phase: str,
    stdin: TextIO,
    *,
    guard_mode: str | None = None,
) -> int:
    """Record a hook event. Blocks only when the pre-tool guard denies or fails closed."""
    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(TIMEOUT_SECONDS)
    try:
        handle(registry, client, phase, json.loads(stdin.read()), guard_mode=guard_mode)
    except guard.GuardBlocked as blocked:
        return _emit_block(client, str(blocked))
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
        print(f"coldrewind hook: {error}", file=sys.stderr)
    finally:
        signal.alarm(0)
    _emit_allow(client, phase)
    return 0
