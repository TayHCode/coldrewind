import ast
import difflib
import json
import os
import re
import shlex
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import coldrewind

from . import guard
from .config import Registry
from .hooks import AGENTS
from .redact import MASK, redact_text


class MultiClientConfirmationRequired(ValueError):
    pass


@dataclass(frozen=True)
class PlannedChange:
    client: str
    path: Path
    diff: str


_OPENCODE_HEADER_RE = re.compile(
    r"^const \[python, code(, guardMode)?\] = (\[[^\n]+\]);",
)
_SYS_PATH_INSERT_RE = re.compile(
    r"sys\.path\.insert\(0,\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")\)",
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?key|private[_-]?key|token|secret|password|passwd|credential|authorization|auth|bearer)"
)

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


def _launcher_code(package_root: str) -> str:
    return (
        f"import sys; sys.path.insert(0, {package_root!r}); "
        "from coldrewind.cli import main; sys.exit(main())"
    )


def _launcher() -> list[str]:
    package_root = str(Path(coldrewind.__file__).resolve().parent.parent)
    return [sys.executable, "-I", "-c", _launcher_code(package_root)]


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
            not isinstance(group, dict)
            or not isinstance(group.get("hooks", []), list)
            or any(not isinstance(handler, dict) for handler in group.get("hooks", []))
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


def _sanitize_json_value(value: object, *, redact_all: bool = False) -> object:
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            key_str = str(key)
            child_redact = (
                redact_all
                or key_str.lower() == "env"
                or _SENSITIVE_KEY_RE.search(key_str) is not None
            )
            sanitized[key] = _sanitize_json_value(item, redact_all=child_redact)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_json_value(item, redact_all=redact_all) for item in value]
    if isinstance(value, str):
        return MASK if redact_all else redact_text(value)
    return value


def _format_diff(client: str, path: Path, raw: bytes | None, text: str) -> str:
    if client == "opencode":
        old_text = "" if raw is None else redact_text(raw.decode("utf-8"))
        new_text = redact_text(text)
    else:
        if raw is None:
            old_text = ""
        else:
            old_data = _sanitize_json_value(json.loads(raw))
            old_text = json.dumps(old_data, indent=2) + "\n"
        if not text:
            new_text = ""
        else:
            new_data = _sanitize_json_value(json.loads(text))
            new_text = json.dumps(new_data, indent=2) + "\n"
    fromfile = "/dev/null" if raw is None else str(path)
    tofile = "/dev/null" if not text else str(path)
    lines = difflib.unified_diff(
        old_text.splitlines(keepends=True),
        new_text.splitlines(keepends=True),
        fromfile=fromfile,
        tofile=tofile,
        n=1,
    )
    return "".join(line if line.endswith("\n") else line + "\n" for line in lines)


def _plan_changes(
    home: Path, clients: tuple[str, ...], install: bool, *, guard_mode: str | None = None
) -> list[tuple[str, Path, bytes | None, str, bool]]:
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
            plans.append((client, path, raw, text, client != "opencode"))
    return plans


def _change(
    home: Path, clients: tuple[str, ...], install: bool, *, guard_mode: str | None = None
) -> list[Path]:
    plans = _plan_changes(home, clients, install, guard_mode=guard_mode)
    for _, path, raw, text, backup in plans:
        _apply(path, raw, text, backup)
    return [path for _, path, *_ in plans]


def plan_init(
    registry: Registry,
    home: Path,
    cwd: Path,
    clients: tuple[str, ...],
    *,
    guard_mode: str | None = None,
) -> list[PlannedChange]:
    """Preview config changes for init without registering cwd or writing files."""
    registry.validate_root(cwd)
    plans = _plan_changes(home, clients, install=True, guard_mode=guard_mode)
    return [
        PlannedChange(client=client, path=path, diff=_format_diff(client, path, raw, text))
        for client, path, raw, text, _ in plans
    ]


def init(
    registry: Registry,
    home: Path,
    cwd: Path,
    clients: tuple[str, ...],
    *,
    guard_mode: str | None = None,
    yes: bool = False,
) -> list[Path]:
    """Register cwd as a workspace and install hooks for the selected clients."""
    if not clients or any(client not in AGENTS for client in clients):
        raise ValueError(f"clients must be among: {', '.join(AGENTS)}")
    unique_clients = tuple(dict.fromkeys(clients))
    if len(unique_clients) > 1 and not yes:
        raise MultiClientConfirmationRequired(
            f"editing multiple client configs ({', '.join(unique_clients)}) requires --yes; "
            "pass --client <name> for one client or --dry-run to preview"
        )
    registry.validate_root(cwd)
    plans = _plan_changes(home, unique_clients, install=True, guard_mode=guard_mode)
    registry.register(cwd)
    for _, path, raw, text, backup in plans:
        _apply(path, raw, text, backup)
    return [path for _, path, *_ in plans]


def uninstall(home: Path, clients: tuple[str, ...]) -> list[Path]:
    """Remove only ColdRewind hook entries; timelines and repo files stay."""
    return _change(home, clients, install=False)


def _extract_package_root(code: str) -> str | None:
    match = _SYS_PATH_INSERT_RE.search(code)
    if match is None:
        return None
    try:
        value = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError):
        return None
    return value if isinstance(value, str) else None


def _validate_hook_cli_args(
    cli_args: list[str], expected_client: str, expected_phase: str
) -> str | None:
    if not cli_args or cli_args[0] != "hook":
        return f"invalid hook command arguments: {' '.join(cli_args) or '(missing hook subcommand)'}"
    positionals: list[str] = []
    guard_mode: str | None = None
    idx = 1
    while idx < len(cli_args):
        token = cli_args[idx]
        if token == "--guard":
            if idx + 1 >= len(cli_args):
                return "missing value for --guard"
            guard_mode = cli_args[idx + 1]
            idx += 2
        elif token.startswith("--guard="):
            guard_mode = token.split("=", 1)[1]
            idx += 1
        elif token.startswith("-"):
            return f"unrecognized hook option: {token}"
        else:
            positionals.append(token)
            idx += 1
    if guard_mode is not None and guard_mode not in guard.MODES:
        return f"invalid --guard mode {guard_mode!r} (expected one of: {', '.join(guard.MODES)})"
    if len(positionals) != 2:
        return f"expected 'hook {expected_client} {expected_phase}', got: {' '.join(cli_args)}"
    got_client, got_phase = positionals
    if got_client != expected_client:
        return f"hook client mismatch: expected {expected_client!r}, got {got_client!r}"
    if got_phase != expected_phase:
        return f"hook phase mismatch: expected {expected_phase!r}, got {got_phase!r}"
    return None


def _validate_launcher_code(code: str) -> tuple[str | None, str | None]:
    package_root = _extract_package_root(code)
    if package_root is None or code != _launcher_code(package_root):
        return package_root, "malformed ColdRewind launcher code"
    return package_root, None


def _parse_coldrewind_command(
    command: object, client: str, phase: str
) -> tuple[str, str | None, str | None] | None:
    if not isinstance(command, str) or not command.strip():
        return None
    try:
        argv = shlex.split(command)
    except ValueError as error:
        if "coldrewind" in command:
            return "", None, f"malformed hook command shell syntax: {error}"
        return None
    if len(argv) >= 4 and argv[1:3] == ["-I", "-c"] and "coldrewind" in argv[3]:
        package_root, code_error = _validate_launcher_code(argv[3])
        arg_error = _validate_hook_cli_args(argv[4:], client, phase)
        combined = "; ".join(err for err in (code_error, arg_error) if err) or None
        return argv[0], package_root, combined
    if argv and Path(argv[0]).name == "coldrewind":
        arg_error = _validate_hook_cli_args(argv[1:], client, phase)
        return argv[0], None, arg_error
    return None


def _check_hook_target(
    event: str,
    executable: str,
    package_root: str | None,
    *,
    arg_error: str | None = None,
) -> dict:
    resolved: str | None = None
    errors: list[str] = []
    if not executable:
        if arg_error is None:
            errors.append("empty executable path")
    elif os.sep in executable or (os.altsep and os.altsep in executable):
        candidate = Path(executable)
        if not candidate.exists():
            errors.append(f"executable not found: {executable}")
        elif not candidate.is_file():
            errors.append(f"executable is not a file: {executable}")
        elif not os.access(candidate, os.X_OK):
            errors.append(f"path is not executable: {executable}")
        else:
            resolved = str(candidate.resolve())
    else:
        found = shutil.which(executable)
        if found is None:
            errors.append(f"executable not found on PATH: {executable}")
        else:
            resolved = str(Path(found).resolve())

    if not errors and package_root is not None:
        if not (Path(package_root) / "coldrewind" / "cli.py").is_file():
            errors.append(f"coldrewind package not found under {package_root}")

    if arg_error is not None:
        errors.append(arg_error)

    error = "; ".join(errors) if errors else None
    return {
        "event": event,
        "executable": executable,
        "resolved_executable": resolved,
        "package_root": package_root,
        "ok": error is None,
        "error": error,
    }


def _iter_client_handlers(data: dict, client: str) -> list[tuple[str, str, object]]:
    found: list[tuple[str, str, object]] = []
    if client == "cursor":
        hooks_map = data.get("hooks", {})
        for event, phase in EVENTS[client].items():
            for handler in hooks_map.get(event, []):
                if not isinstance(handler, dict):
                    raise ValueError(f"malformed {event} hooks")
                found.append((event, phase, handler.get("command")))
        return found
    container = data.get(ANTIGRAVITY_HOOK_KEY, {}) if client == "antigravity" else data.get("hooks", {})
    for event, phase in EVENTS[client].items():
        for group in container.get(event, []):
            if not isinstance(group, dict):
                raise ValueError(f"malformed {event} hooks")
            for handler in group.get("hooks", []):
                if not isinstance(handler, dict):
                    raise ValueError(f"malformed {event} hooks")
                if handler.get("type") == "command":
                    found.append((event, phase, handler.get("command")))
    return found


def _validate_opencode_plugin(path: Path, text: str) -> tuple[str, str | None]:
    match = _OPENCODE_HEADER_RE.match(text)
    if match is None:
        raise ValueError(f"{path} is not a recognized ColdRewind plugin")
    has_guard = match.group(1) is not None
    values = json.loads(match.group(2))
    expected_len = 3 if has_guard else 2
    if (
        not isinstance(values, list)
        or len(values) != expected_len
        or not all(isinstance(item, str) for item in values)
    ):
        raise ValueError(f"{path} has malformed ColdRewind plugin header")
    python_exec, code = values[0], values[1]
    package_root, code_error = _validate_launcher_code(code)
    if code_error is not None:
        raise ValueError(f"{path} has {code_error}")
    if has_guard:
        if values[2] not in guard.MODES:
            raise ValueError(
                f"{path} has invalid guard mode {values[2]!r} "
                f"(expected one of: {', '.join(guard.MODES)})"
            )
        expected = (_PLUGIN_GUARDED % json.dumps([python_exec, _launcher_code(package_root), values[2]]),)
    else:
        expected = (
            _PLUGIN_DEFAULT % json.dumps([python_exec, _launcher_code(package_root)]),
            _PLUGIN_LEGACY % json.dumps([python_exec, _launcher_code(package_root)]),
        )
    if text not in expected:
        raise ValueError(f"{path} is truncated or modified and does not match a valid ColdRewind plugin")
    return python_exec, package_root


def _check_client(home: Path, client: str) -> dict:
    path = config_paths(home)[client]
    if client == "opencode":
        if path.is_symlink():
            return {
                "client": client,
                "path": str(path),
                "status": "broken",
                "hooks": [],
                "error": f"{path} is a symlink; ColdRewind manages only its own plugin file",
            }
        try:
            raw = _read(path)
        except (OSError, ValueError) as error:
            return {
                "client": client,
                "path": str(path),
                "status": "broken",
                "hooks": [],
                "error": str(error),
            }
        if raw is None:
            return {
                "client": client,
                "path": str(path),
                "status": "not_installed",
                "hooks": [],
                "error": None,
            }
        try:
            python_exec, package_root = _validate_opencode_plugin(path, raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            return {
                "client": client,
                "path": str(path),
                "status": "broken",
                "hooks": [],
                "error": str(error),
            }
        hook_result = _check_hook_target("plugin", python_exec, package_root)
        return {
            "client": client,
            "path": str(path),
            "status": "ok" if hook_result["ok"] else "broken",
            "hooks": [hook_result],
            "error": hook_result["error"],
        }

    if path.is_symlink() and not path.exists():
        return {
            "client": client,
            "path": str(path),
            "status": "broken",
            "hooks": [],
            "error": f"{path} is a broken symlink",
        }
    resolved_path = path.resolve()
    try:
        raw = _read(resolved_path)
    except (OSError, ValueError) as error:
        return {
            "client": client,
            "path": str(resolved_path),
            "status": "broken",
            "hooks": [],
            "error": str(error),
        }
    if raw is None:
        return {
            "client": client,
            "path": str(resolved_path),
            "status": "not_installed",
            "hooks": [],
            "error": None,
        }
    try:
        data = _parse_json(resolved_path, raw, client)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        return {
            "client": client,
            "path": str(resolved_path),
            "status": "broken",
            "hooks": [],
            "error": str(error),
        }
    hook_results = []
    for event, phase, command in _iter_client_handlers(data, client):
        parsed = _parse_coldrewind_command(command, client, phase)
        if parsed is not None:
            executable, package_root, arg_error = parsed
            hook_results.append(_check_hook_target(event, executable, package_root, arg_error=arg_error))
    if not hook_results:
        return {
            "client": client,
            "path": str(resolved_path),
            "status": "not_installed",
            "hooks": [],
            "error": None,
        }
    errors = [item["error"] for item in hook_results if item["error"]]
    seen_events = {item["event"] for item in hook_results}
    missing_events = [event for event in EVENTS[client] if event not in seen_events]
    if missing_events:
        errors.append(f"missing required hook event(s): {', '.join(missing_events)}")
    return {
        "client": client,
        "path": str(resolved_path),
        "status": "ok" if not errors else "broken",
        "hooks": hook_results,
        "error": "; ".join(errors) if errors else None,
    }


def doctor(
    registry: Registry,
    home: Path,
    clients: tuple[str, ...] | None = None,
) -> dict:
    """Verify installed hooks resolve to executable binaries and valid package paths."""
    selected = tuple(dict.fromkeys(AGENTS if clients is None else clients))
    if not selected or any(client not in AGENTS for client in selected):
        raise ValueError(f"clients must be among: {', '.join(AGENTS)}")
    registry_error: str | None = None
    try:
        registered_workspaces = len(registry.roots())
    except (OSError, ValueError) as error:
        registered_workspaces = 0
        registry_error = str(error)
    client_results = [_check_client(home, client) for client in selected]
    ok = registry_error is None and all(entry["status"] != "broken" for entry in client_results)
    return {
        "ok": ok,
        "python": sys.executable,
        "registered_workspaces": registered_workspaces,
        "registry_error": registry_error,
        "clients": client_results,
    }
