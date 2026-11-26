import json
import os
import shlex
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import coldrewind

from . import guard
from .config import Registry
from .hooks import AGENTS

EVENTS = {
    "claude": {
        "PreToolUse": "pre", "PostToolUse": "post", "PostToolUseFailure": "post",
        "PermissionDenied": "denied",
    },
    "codex": {"PreToolUse": "pre", "PostToolUse": "post"},
    "cursor": {
        "preToolUse": "pre", "postToolUse": "post", "postToolUseFailure": "post",
    },
    "antigravity": {"PreToolUse": "pre", "PostToolUse": "post"},
    "gemini": {"BeforeTool": "pre", "AfterTool": "post"},
}
ANTIGRAVITY_HOOK_KEY = "coldrewind"
HOOK_TIMEOUT_SECONDS = 90
_PLUGIN_LEGACY = """const [python, code] = %s;

export const ColdRewind = async ({ $, directory }) => {
  const send = async (phase, input, args) => {
    const payload = JSON.stringify({
      cwd: directory,
      session_id: input.sessionID,
      tool_use_id: input.callID,
      tool_name: input.tool,
      tool_input: args,
    });
    try {
      await $`${python} -I -c ${code} hook opencode ${phase} < ${new Response(payload)}`.nothrow().quiet();
    } catch {}
  };
  return {
    "tool.execute.before": async (input, output) => send("pre", input, output.args),
    "tool.execute.after": async (input) => send("post", input, input.args),
  };
};
"""
_PLUGIN_DEFAULT = """const [python, code] = %s;

export const ColdRewind = async ({ $, directory }) => {
  const send = async (phase, input, args) => {
    const payload = JSON.stringify({
      cwd: directory,
      session_id: input.sessionID,
      tool_use_id: input.callID,
      tool_name: input.tool,
      tool_input: args,
    });
    let result;
    try {
      result = await $`${python} -I -c ${code} hook opencode ${phase} < ${new Response(payload)}`.nothrow().quiet();
    } catch {
      return;
    }
    if (phase === "pre" && result && result.exitCode === 2) {
      const reason = result.stderr ? result.stderr.toString().trim() : "";
      throw new Error(reason || "Blocked by ColdRewind guard");
    }
  };
  return {
    "tool.execute.before": async (input, output) => send("pre", input, output.args),
    "tool.execute.after": async (input) => send("post", input, input.args),
  };
};
"""
_PLUGIN_GUARDED = """const [python, code, guardMode] = %s;

export const ColdRewind = async ({ $, directory }) => {
  const send = async (phase, input, args) => {
    const payload = JSON.stringify({
      cwd: directory,
      session_id: input.sessionID,
      tool_use_id: input.callID,
      tool_name: input.tool,
      tool_input: args,
    });
    let result;
    try {
      result = await $`${python} -I -c ${code} hook opencode ${phase} --guard ${guardMode} < ${new Response(payload)}`.nothrow().quiet();
    } catch {
      return;
    }
    if (phase === "pre" && result && result.exitCode === 2) {
      const reason = result.stderr ? result.stderr.toString().trim() : "";
      throw new Error(reason || "Blocked by ColdRewind guard");
    }
  };
  return {
    "tool.execute.before": async (input, output) => send("pre", input, output.args),
    "tool.execute.after": async (input) => send("post", input, input.args),
  };
};
"""


def _env_dir(name: str, default: Path) -> Path:
    path = Path(os.environ.get(name, ""))
    return path if path.is_absolute() else default


def config_paths(home: Path) -> dict[str, Path]:
    return {
        "claude": _env_dir("CLAUDE_CONFIG_DIR", home / ".claude") / "settings.json",
        "codex": _env_dir("CODEX_HOME", home / ".codex") / "hooks.json",
        "opencode": _env_dir("XDG_CONFIG_HOME", home / ".config")
        / "opencode" / "plugins" / "coldrewind.js",
        "cursor": _env_dir("CURSOR_CONFIG_DIR", home / ".cursor") / "hooks.json",
        "antigravity": _env_dir("ANTIGRAVITY_CONFIG_DIR", home / ".gemini" / "config")
        / "hooks.json",
        "gemini": _env_dir("GEMINI_CONFIG_DIR", home / ".gemini") / "settings.json",
    }


def _launcher() -> list[str]:
    package_root = str(Path(coldrewind.__file__).resolve().parent.parent)
    code = (
        f"import sys; sys.path.insert(0, {package_root!r}); "
        "from coldrewind.cli import main; sys.exit(main())"
    )
    return [sys.executable, "-I", "-c", code]


def hook_command(client: str, phase: str, guard_mode: str | None = None) -> str:
    argv = [*_launcher(), "hook", client, phase]
    if guard_mode is not None:
        argv.extend(("--guard", guard_mode))
    return shlex.join(argv)


def _our_commands(client: str, phase: str) -> frozenset[str]:
    return frozenset({
        hook_command(client, phase),
        *(hook_command(client, phase, mode) for mode in guard.MODES),
    })


def _is_ours(handler: object, client: str, phase: str) -> bool:
    if not isinstance(handler, dict):
        return False
    commands = _our_commands(client, phase)
    if client == "cursor":
        return handler.get("command") in commands
    return handler.get("type") == "command" and handler.get("command") in commands


def _plugin_text(guard_mode: str | None = None) -> str:
    python, _, _, code = _launcher()
    if guard_mode is None:
        return _PLUGIN_DEFAULT % json.dumps([python, code])
    return _PLUGIN_GUARDED % json.dumps([python, code, guard_mode])


def _our_plugins() -> frozenset[bytes]:
    python, _, _, code = _launcher()
    legacy = (_PLUGIN_LEGACY % json.dumps([python, code])).encode()
    return frozenset({
        legacy,
        _plugin_text().encode(),
        *(_plugin_text(mode).encode() for mode in guard.MODES),
    })


def _read(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path} is not a regular file")
        return file.read()


def _validate_grouped_events(path: Path, container: dict, client: str) -> None:
    for event in EVENTS[client]:
        groups = container.get(event, [])
        if not isinstance(groups, list) or any(
            not isinstance(group, dict) or not isinstance(group.get("hooks", []), list)
            for group in groups
        ):
            raise ValueError(f"{path}: malformed {event} hooks")


def _parse_json(path: Path, raw: bytes | None, client: str) -> dict:
    if raw is None:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    if client == "antigravity":
        entry = data.get(ANTIGRAVITY_HOOK_KEY, {})
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: malformed {ANTIGRAVITY_HOOK_KEY} hooks")
        _validate_grouped_events(path, entry, client)
        return data
    if client == "cursor":
        version = data.get("version")
        if version is not None and (isinstance(version, bool) or not isinstance(version, int)):
            raise ValueError(f"{path}: expected integer 'version'")
        hooks = data.get("hooks", {})
        if not isinstance(hooks, dict):
            raise ValueError(f"{path}: expected a JSON object with an object 'hooks'")
        for event in EVENTS[client]:
            handlers = hooks.get(event, [])
            if not isinstance(handlers, list) or any(not isinstance(h, dict) for h in handlers):
                raise ValueError(f"{path}: malformed {event} hooks")
        return data
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"{path}: expected a JSON object with an object 'hooks'")
    _validate_grouped_events(path, hooks, client)
    return data


def _strip_grouped(container: dict, client: str) -> None:
    for event, phase in EVENTS[client].items():
        if not container.get(event):
            continue
        groups = []
        for group in container[event]:
            handlers = group.get("hooks", [])
            kept = [handler for handler in handlers if not _is_ours(handler, client, phase)]
            if len(kept) == len(handlers):
                groups.append(group)
            elif kept:
                groups.append({**group, "hooks": kept})
        if groups:
            container[event] = groups
        else:
            del container[event]


def _strip(data: dict, client: str) -> dict:
    data = json.loads(json.dumps(data))
    if client == "antigravity":
        entry = data.get(ANTIGRAVITY_HOOK_KEY)
        if not entry:
            return data
        _strip_grouped(entry, client)
        if not entry:
            del data[ANTIGRAVITY_HOOK_KEY]
        return data
    hooks = data.get("hooks")
    if not hooks:
        return data
    if client == "cursor":
        for event, phase in EVENTS[client].items():
            if not hooks.get(event):
                continue
            kept = [handler for handler in hooks[event] if not _is_ours(handler, client, phase)]
            if kept:
                hooks[event] = kept
            else:
                del hooks[event]
    else:
        _strip_grouped(hooks, client)
    if not hooks:
        del data["hooks"]
    return data


def _install_entries(data: dict, client: str, guard_mode: str | None) -> None:
    if client == "cursor":
        data.setdefault("version", 1)
        hooks = data.setdefault("hooks", {})
        for event, phase in EVENTS[client].items():
            hooks.setdefault(event, []).append({
                "command": hook_command(client, phase, guard_mode),
                "timeout": HOOK_TIMEOUT_SECONDS,
            })
        return
    if client == "antigravity":
        entry = data.setdefault(ANTIGRAVITY_HOOK_KEY, {})
        for event, phase in EVENTS[client].items():
            entry.setdefault(event, []).append({
                "matcher": "*",
                "hooks": [{
                    "type": "command",
                    "command": hook_command(client, phase, guard_mode),
                    "timeout": HOOK_TIMEOUT_SECONDS,
                }],
            })
        return
    if client == "gemini":
        hooks = data.setdefault("hooks", {})
        for event, phase in EVENTS[client].items():
            hooks.setdefault(event, []).append({
                "matcher": "*",
                "hooks": [{
                    "name": f"coldrewind-{phase}",
                    "type": "command",
                    "command": hook_command(client, phase, guard_mode),
                    "timeout": HOOK_TIMEOUT_SECONDS * 1000,
                }],
            })
        return
    hooks = data.setdefault("hooks", {})
    for event, phase in EVENTS[client].items():
        hooks.setdefault(event, []).append({"hooks": [{
            "type": "command",
            "command": hook_command(client, phase, guard_mode),
            "timeout": HOOK_TIMEOUT_SECONDS,
        }]})


def _plan_json(
    path: Path, raw: bytes | None, client: str, install: bool, guard_mode: str | None = None
) -> str | None:
    original = _parse_json(path, raw, client)
    data = _strip(original, client)
    if install:
        _install_entries(data, client, guard_mode)
    if data == original:
        return None
    return json.dumps(data, indent=2) + "\n"


def _plan_plugin(
    path: Path, raw: bytes | None, install: bool, guard_mode: str | None = None
) -> str | None:
    wanted = _plugin_text(guard_mode)
    if raw is not None and raw not in _our_plugins():
        raise ValueError(f"{path} exists and is not this ColdRewind's plugin")
    if not install:
        return "" if raw is not None else None
    return None if raw == wanted.encode() else wanted


def _write_new(directory: Path, data: bytes, mode: int) -> Path:
    output = tempfile.NamedTemporaryFile(dir=directory, delete=False)
    temporary = Path(output.name)
    try:
        with output:
            output.write(data)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _check_unchanged(path: Path, raw: bytes | None) -> None:
    if _read(path) != raw:
        raise ValueError(f"{path} changed during ColdRewind setup; it was not written")


def _apply(path: Path, raw: bytes | None, text: str, backup: bool) -> None:
    staged = None
    if text:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        mode = path.stat().st_mode & 0o777 if raw is not None else 0o600
        staged = _write_new(path.parent, text.encode(), mode)
    try:
        _check_unchanged(path, raw)
        if raw is not None and backup:
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
            copy = _write_new(path.parent, raw, 0o600)
            try:
                os.link(copy, path.with_name(f"{path.name}.coldrewind-backup-{stamp}"))
            finally:
                copy.unlink()
        _check_unchanged(path, raw)
        if staged is None:
            path.unlink()
        elif raw is None:
            os.link(staged, path)
        else:
            staged.replace(path)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def _change(
    home: Path, clients: tuple[str, ...], install: bool, *, guard_mode: str | None = None
) -> list[Path]:
    if not clients or any(client not in AGENTS for client in clients):
        raise ValueError(f"clients must be among: {', '.join(AGENTS)}")
    if guard_mode is not None and guard_mode not in guard.MODES:
        raise ValueError(f"guard mode must be among: {', '.join(guard.MODES)}")
    paths = config_paths(home)
    plans = []
    for client in dict.fromkeys(clients):
        if client == "opencode":
            path = paths[client]
            if path.is_symlink():
                raise ValueError(f"{path} is a symlink; ColdRewind manages only its own plugin file")
            raw = _read(path)
            text = _plan_plugin(path, raw, install, guard_mode)
        else:
            path = paths[client].resolve()
            raw = _read(path)
            text = _plan_json(path, raw, client, install, guard_mode)
        if text is not None:
            plans.append((path, raw, text, client != "opencode"))
    for plan in plans:
        _apply(*plan)
    return [path for path, *_ in plans]


def init(
    registry: Registry,
    home: Path,
    cwd: Path,
    clients: tuple[str, ...],
    *,
    guard_mode: str | None = None,
) -> list[Path]:
    """Register cwd as a workspace and install hooks for the selected clients."""
    registry.register(cwd)
    return _change(home, clients, install=True, guard_mode=guard_mode)


def uninstall(home: Path, clients: tuple[str, ...]) -> list[Path]:
    """Remove only ColdRewind hook entries; timelines and repo files stay."""
    return _change(home, clients, install=False)
