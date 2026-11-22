import json
import os
import shlex
import stat
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import coldrewind

from .config import Registry
from .hooks import AGENTS

EVENTS = {
    "claude": {
        "PreToolUse": "pre", "PostToolUse": "post", "PostToolUseFailure": "post",
        "PermissionDenied": "denied",
    },
    "codex": {"PreToolUse": "pre", "PostToolUse": "post"},
}
HOOK_TIMEOUT_SECONDS = 90
_PLUGIN = """const [python, code] = %s;

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


def _env_dir(name: str, default: Path) -> Path:
    path = Path(os.environ.get(name, ""))
    return path if path.is_absolute() else default


def config_paths(home: Path) -> dict[str, Path]:
    return {
        "claude": _env_dir("CLAUDE_CONFIG_DIR", home / ".claude") / "settings.json",
        "codex": _env_dir("CODEX_HOME", home / ".codex") / "hooks.json",
        "opencode": _env_dir("XDG_CONFIG_HOME", home / ".config")
        / "opencode" / "plugins" / "coldrewind.js",
    }


def _launcher() -> list[str]:
    package_root = str(Path(coldrewind.__file__).resolve().parent.parent)
    code = (
        f"import sys; sys.path.insert(0, {package_root!r}); "
        "from coldrewind.cli import main; sys.exit(main())"
    )
    return [sys.executable, "-I", "-c", code]


def hook_command(client: str, phase: str) -> str:
    return shlex.join([*_launcher(), "hook", client, phase])


def _is_ours(handler: object, client: str, phase: str) -> bool:
    return (
        isinstance(handler, dict)
        and handler.get("type") == "command"
        and handler.get("command") == hook_command(client, phase)
    )


def _plugin_text() -> str:
    python, _, _, code = _launcher()
    return _PLUGIN % json.dumps([python, code])


def _read(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as file:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError(f"{path} is not a regular file")
        return file.read()


def _parse_json(path: Path, raw: bytes | None, client: str) -> dict:
    if raw is None:
        return {}
    data = json.loads(raw)
    hooks = data.get("hooks", {}) if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        raise ValueError(f"{path}: expected a JSON object with an object 'hooks'")
    for event in EVENTS[client]:
        groups = hooks.get(event, [])
        if not isinstance(groups, list) or any(
            not isinstance(group, dict) or not isinstance(group.get("hooks", []), list)
            for group in groups
        ):
            raise ValueError(f"{path}: malformed {event} hooks")
    return data


def _strip(data: dict, client: str) -> dict:
    data = json.loads(json.dumps(data))
    hooks = data.get("hooks")
    if not hooks:
        return data
    for event, phase in EVENTS[client].items():
        if not hooks.get(event):
            continue
        groups = []
        for group in hooks[event]:
            handlers = group.get("hooks", [])
            kept = [handler for handler in handlers if not _is_ours(handler, client, phase)]
            if len(kept) == len(handlers):
                groups.append(group)
            elif kept:
                groups.append({**group, "hooks": kept})
        if groups:
            hooks[event] = groups
        else:
            del hooks[event]
    if not hooks:
        del data["hooks"]
    return data


def _plan_json(path: Path, raw: bytes | None, client: str, install: bool) -> str | None:
    original = _parse_json(path, raw, client)
    data = _strip(original, client)
    if install:
        hooks = data.setdefault("hooks", {})
        for event, phase in EVENTS[client].items():
            hooks.setdefault(event, []).append({"hooks": [{
                "type": "command",
                "command": hook_command(client, phase),
                "timeout": HOOK_TIMEOUT_SECONDS,
            }]})
    if data == original:
        return None
    return json.dumps(data, indent=2) + "\n"


def _plan_plugin(path: Path, raw: bytes | None, install: bool) -> str | None:
    wanted = _plugin_text()
    if raw is not None and raw != wanted.encode():
        raise ValueError(f"{path} exists and is not this ColdRewind's plugin")
    if not install:
        return "" if raw is not None else None
    return None if raw is not None else wanted


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


def _change(home: Path, clients: tuple[str, ...], install: bool) -> list[Path]:
    if not clients or any(client not in AGENTS for client in clients):
        raise ValueError(f"clients must be among: {', '.join(AGENTS)}")
    paths = config_paths(home)
    plans = []
    for client in dict.fromkeys(clients):
        if client == "opencode":
            path = paths[client]
            if path.is_symlink():
                raise ValueError(f"{path} is a symlink; ColdRewind manages only its own plugin file")
            raw = _read(path)
            text = _plan_plugin(path, raw, install)
        else:
            path = paths[client].resolve()
            raw = _read(path)
            text = _plan_json(path, raw, client, install)
        if text is not None:
            plans.append((path, raw, text, client != "opencode"))
    for plan in plans:
        _apply(*plan)
    return [path for path, *_ in plans]


def init(registry: Registry, home: Path, cwd: Path, clients: tuple[str, ...]) -> list[Path]:
    """Register cwd as a workspace and install hooks for the selected clients."""
    registry.register(cwd)
    return _change(home, clients, install=True)


def uninstall(home: Path, clients: tuple[str, ...]) -> list[Path]:
    """Remove only ColdRewind hook entries; timelines and repo files stay."""
    return _change(home, clients, install=False)
