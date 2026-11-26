"""Pre-tool guard classifier for destructive and irreversible commands."""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

MODES = ("checkpoint", "block", "off")
DEFAULT_MODE = "checkpoint"

_PRIVILEGED = frozenset({"doas", "pkexec", "run0", "runuser", "su", "sudo", "systemd-run"})
_SHELLS = frozenset({"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh"})
_SIMPLE_WRAPPERS = frozenset({"builtin", "command", "nohup", "time"})
_GIT_VALUE_FLAGS = frozenset({
    "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env",
    "--exec-path",
})
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_SHELL_EXPANSION = re.compile(r"[$`*?\[]")
_SPLIT_FALLBACK = re.compile(r"(?:&&|\|\||[;\n|])")


@dataclass(frozen=True)
class GuardMatch:
    category: str
    rule: str
    reason: str
    always_block: bool = False


class GuardBlocked(RuntimeError):
    def __init__(self, match: GuardMatch, message: str) -> None:
        super().__init__(message)
        self.match = match


def resolve_mode(override: str | None = None) -> str:
    value = os.environ.get("COLDREWIND_GUARD", DEFAULT_MODE) if override is None else override
    if value not in MODES:
        raise ValueError(f"COLDREWIND_GUARD must be one of: {', '.join(MODES)}")
    return value


def snapshot_min_interval_seconds() -> int:
    value = os.environ.get("COLDREWIND_SNAPSHOT_MIN_INTERVAL_SECONDS")
    if value is None:
        return 0
    if not value.isascii() or not value.isdecimal():
        raise ValueError("COLDREWIND_SNAPSHOT_MIN_INTERVAL_SECONDS must be a nonnegative integer")
    return int(value)


def classify_guard(command: tuple[str, ...], *, root: Path, cwd: Path) -> GuardMatch | None:
    """Classify whether a pre-tool command is destructive or irreversible/partial-capture."""
    if not command:
        return None
    root = root.resolve(strict=False)
    cwd = cwd.resolve(strict=False)
    return _check_argv(list(command), root=root, cwd=cwd, depth=0)


def _check_shell_script(script: str, *, root: Path, cwd: Path | None, depth: int) -> GuardMatch | None:
    if depth > 4:
        return None
    segments, raw_segments, unquoted_heredocs = _split_shell(script)
    effective_cwd = cwd
    best: GuardMatch | None = None
    for segment in segments:
        if not segment:
            continue
        if segment[0] == "cd":
            effective_cwd = _apply_cd(segment[1:], effective_cwd)
            continue
        match = _check_argv(segment, root=root, cwd=effective_cwd, depth=depth + 1)
        if match is not None:
            if match.always_block:
                return match
            if best is None:
                best = match
    for sub in _extract_substitutions("\n".join((*raw_segments, *unquoted_heredocs))):
        match = _check_shell_script(sub, root=root, cwd=cwd, depth=depth + 1)
        if match is not None:
            if match.always_block:
                return match
            if best is None:
                best = match
    return best


def _parse_heredoc_delimiter(script: str, start: int) -> tuple[str, bool, bool, int] | None:
    """Parse a heredoc operator starting after '<<'. Returns (delim, strip_tabs, quoted, next_idx)."""
    n = len(script)
    i = start
    strip_tabs = False
    if i < n and script[i] == "-":
        strip_tabs = True
        i += 1
    while i < n and script[i] in (" ", "\t"):
        i += 1
    if i >= n or script[i] in "\n;&|()<>":
        return None
    delim_chars: list[str] = []
    quoted = False
    while i < n and not script[i].isspace() and script[i] not in ";&|()<>":
        ch = script[i]
        if ch == "'":
            quoted = True
            i += 1
            while i < n and script[i] != "'":
                delim_chars.append(script[i])
                i += 1
            if i < n:
                i += 1
        elif ch == '"':
            quoted = True
            i += 1
            while i < n and script[i] != '"':
                if script[i] == "\\" and i + 1 < n:
                    i += 1
                delim_chars.append(script[i])
                i += 1
            if i < n:
                i += 1
        elif ch == "\\" and i + 1 < n:
            quoted = True
            delim_chars.append(script[i + 1])
            i += 2
        else:
            delim_chars.append(ch)
            i += 1
    delim = "".join(delim_chars)
    if not delim:
        return None
    return delim, strip_tabs, quoted, i


def _split_shell_raw(script: str) -> tuple[list[str], list[str]]:
    """Split a shell script on unquoted command separators (including newlines),
    consuming heredoc body lines as data. Returns (raw_segments, unquoted_heredoc_bodies).
    """
    raw_segments: list[str] = []
    unquoted_heredocs: list[str] = []
    pending_heredocs: list[tuple[str, bool, bool]] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(script)

    def flush() -> None:
        text = "".join(buf).strip()
        if text:
            raw_segments.append(text)
        buf.clear()

    def consume_heredocs(pos: int) -> int:
        for delim, strip_tabs, quoted in pending_heredocs:
            body_lines: list[str] = []
            while pos < n:
                nl = script.find("\n", pos)
                if nl == -1:
                    line = script[pos:]
                    pos = n
                else:
                    line = script[pos:nl]
                    pos = nl + 1
                check = line.rstrip("\r")
                if strip_tabs:
                    check = check.lstrip("\t")
                if check == delim:
                    break
                body_lines.append(line)
            if not quoted and body_lines:
                unquoted_heredocs.append("\n".join(body_lines))
        pending_heredocs.clear()
        return pos

    while i < n:
        ch = script[i]
        if in_single:
            buf.append(ch)
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                if script[i + 1] == "\n":
                    i += 2
                    continue
                buf.append(ch)
                buf.append(script[i + 1])
                i += 2
                continue
            buf.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        # Outside quotes
        if ch == "\\" and i + 1 < n:
            if script[i + 1] == "\n":
                i += 2
                continue
            buf.append(ch)
            buf.append(script[i + 1])
            i += 2
            continue
        if ch == "'":
            in_single = True
            buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            buf.append(ch)
            i += 1
            continue
        if ch == "#" and (not buf or buf[-1].isspace()):
            while i < n and script[i] != "\n":
                i += 1
            continue
        if ch == "<" and i + 2 < n and script[i : i + 3] == "<<<":
            buf.append("<<<")
            i += 3
            continue
        if ch == "<" and i + 1 < n and script[i + 1] == "<":
            parsed = _parse_heredoc_delimiter(script, i + 2)
            if parsed is not None:
                delim, strip_tabs, quoted, next_idx = parsed
                pending_heredocs.append((delim, strip_tabs, quoted))
                buf.append(script[i:next_idx])
                i = next_idx
                continue
        if ch == "\n":
            flush()
            i += 1
            if pending_heredocs:
                i = consume_heredocs(i)
            continue
        if ch in ";&|()":
            flush()
            if i + 1 < n and script[i : i + 2] in ("&&", "||", "|&"):
                i += 2
            else:
                i += 1
            continue
        buf.append(ch)
        i += 1

    flush()
    return raw_segments, unquoted_heredocs


def _split_shell(script: str) -> tuple[list[list[str]], list[str], list[str]]:
    raw_segments, unquoted_heredocs = _split_shell_raw(script)
    segments: list[list[str]] = []
    for raw in raw_segments:
        try:
            tokens = shlex.split(raw, posix=True)
        except ValueError:
            for chunk in _SPLIT_FALLBACK.split(raw):
                parts = chunk.strip().split()
                if parts:
                    segments.append(parts)
            continue
        if tokens:
            segments.append(tokens)
    return segments, raw_segments, unquoted_heredocs


def _extract_substitutions(script: str) -> list[str]:
    """Extract unquoted or double-quoted $(...) and `...` command substitutions."""
    found: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(script)
    while i < n:
        ch = script[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch == "'" and not in_double:
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = not in_double
            i += 1
            continue
        if ch == "$" and i + 1 < n and script[i + 1] == "(":
            depth = 1
            j = i + 2
            sub_single = False
            sub_double = False
            while j < n and depth > 0:
                c = script[j]
                if sub_single:
                    if c == "'":
                        sub_single = False
                elif c == "\\" and j + 1 < n:
                    j += 1
                elif c == "'" and not sub_double:
                    sub_single = True
                elif c == '"':
                    sub_double = not sub_double
                elif not sub_double:
                    if c == "(":
                        depth += 1
                    elif c == ")":
                        depth -= 1
                j += 1
            if depth == 0:
                body = script[i + 2 : j - 1].strip()
                if body:
                    found.append(body)
                i = j
                continue
        if ch == "`":
            j = i + 1
            while j < n:
                if script[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if script[j] == "`":
                    break
                j += 1
            if j < n and script[j] == "`":
                body = script[i + 1 : j].strip()
                if body:
                    found.append(body)
                i = j + 1
                continue
        i += 1
    return found


def _apply_cd(args: list[str], cwd: Path | None) -> Path | None:
    target = None
    for arg in args:
        if arg == "--":
            continue
        if arg.startswith("-"):
            continue
        target = arg
        break
    if target is None:
        return Path.home().resolve(strict=False)
    if target == "-" or _SHELL_EXPANSION.search(target):
        return None
    path = Path(os.path.expanduser(target))
    if path.is_absolute():
        return path.resolve(strict=False)
    if cwd is None:
        return None
    return (cwd / path).resolve(strict=False)


def _strip_wrappers(tokens: list[str]) -> list[str]:
    idx = 0
    while idx < len(tokens):
        token = tokens[idx]
        if _ENV_ASSIGNMENT.match(token):
            idx += 1
            continue
        name = Path(token).name
        if name in _SIMPLE_WRAPPERS:
            idx += 1
            while idx < len(tokens) and tokens[idx].startswith("-"):
                idx += 1
            continue
        if name == "env":
            idx += 1
            while idx < len(tokens):
                arg = tokens[idx]
                if arg in ("-u", "-C", "--unset", "--chdir"):
                    idx += 2
                elif arg.startswith("-") or _ENV_ASSIGNMENT.match(arg):
                    idx += 1
                else:
                    break
            continue
        if name == "nice":
            idx += 1
            if idx < len(tokens) and tokens[idx] in ("-n", "--adjustment"):
                idx += 2
            elif idx < len(tokens) and tokens[idx].startswith("-"):
                idx += 1
            continue
        if name == "timeout":
            idx += 1
            while idx < len(tokens) and tokens[idx].startswith("-"):
                if tokens[idx] in ("-k", "-s", "--kill-after", "--signal"):
                    idx += 2
                else:
                    idx += 1
            if idx < len(tokens):
                idx += 1  # duration argument
            continue
        break
    return tokens[idx:]


def _check_argv(tokens: list[str], *, root: Path, cwd: Path | None, depth: int) -> GuardMatch | None:
    tokens = _strip_wrappers(tokens)
    if not tokens:
        return None
    executable = Path(tokens[0]).name
    args = tokens[1:]

    if executable in _PRIVILEGED:
        return GuardMatch(
            "irreversible",
            executable,
            "Privileged command can mutate state outside safe capture",
        )

    if executable in _SHELLS:
        script = _shell_c_argument(args)
        if script is not None:
            return _check_shell_script(script, root=root, cwd=cwd, depth=depth + 1)
        return None

    if executable == "git":
        return _check_git(args)
    if executable == "rm":
        return _check_rm(args, root=root, cwd=cwd)
    if executable == "find":
        return _check_find(args)
    return None


def _shell_c_argument(args: list[str]) -> str | None:
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg == "--":
            return None
        if arg == "-c" or (arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]):
            return args[idx + 1] if idx + 1 < len(args) else None
        if arg.startswith("-"):
            idx += 1
            continue
        return None
    return None


def _check_git(args: list[str]) -> GuardMatch | None:
    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg in _GIT_VALUE_FLAGS:
            idx += 2
            continue
        if arg.startswith("-"):
            idx += 1
            continue
        break
    if idx >= len(args):
        return None
    subcmd = args[idx]
    subargs = args[idx + 1:]

    if subcmd == "reset":
        for arg in subargs:
            if arg == "--":
                break
            if arg == "--hard":
                return GuardMatch("destructive", "git reset --hard", "Discards uncommitted working tree and index changes")
            if arg == "--merge":
                return GuardMatch("destructive", "git reset --merge", "Discards uncommitted working tree changes")
        return None

    if subcmd == "clean":
        dry_run = False
        force = False
        for arg in subargs:
            if arg == "--":
                break
            if arg in ("-n", "--dry-run"):
                dry_run = True
            elif arg == "--force":
                force = True
            elif arg.startswith("-") and not arg.startswith("--"):
                flags = arg[1:]
                if "n" in flags:
                    dry_run = True
                if "f" in flags:
                    force = True
        if force and not dry_run:
            return GuardMatch("destructive", "git clean -f", "Permanently removes untracked workspace files")
        return None

    if subcmd == "checkout":
        has_dash_dash = "--" in subargs
        has_force = False
        positional: list[str] = []
        skip_next = False
        for arg in subargs:
            if skip_next:
                skip_next = False
                continue
            if arg == "--":
                break
            if arg in ("-b", "-B", "--orphan", "--conflict", "--pathspec-from-file"):
                skip_next = True
                continue
            if arg in ("-f", "--force"):
                has_force = True
            elif arg.startswith("-") and not arg.startswith("--"):
                if "f" in arg[1:]:
                    has_force = True
            else:
                positional.append(arg)
        if has_dash_dash:
            return GuardMatch("destructive", "git checkout --", "Overwrites uncommitted working tree files")
        if has_force:
            return GuardMatch("destructive", "git checkout --force", "Discards local working tree modifications")
        if "." in positional:
            return GuardMatch("destructive", "git checkout .", "Overwrites uncommitted working tree files")
        return None

    if subcmd == "restore":
        staged = False
        worktree = False
        for arg in subargs:
            if arg == "--":
                break
            if arg in ("-S", "--staged"):
                staged = True
            elif arg in ("-W", "--worktree"):
                worktree = True
            elif arg.startswith("-") and not arg.startswith("--"):
                flags = arg[1:]
                if "S" in flags:
                    staged = True
                if "W" in flags:
                    worktree = True
        if worktree or not staged:
            return GuardMatch("destructive", "git restore", "Discards uncommitted working tree changes")
        return None

    if subcmd == "stash":
        for arg in subargs:
            if arg.startswith("-"):
                continue
            if arg in ("drop", "clear"):
                return GuardMatch("destructive", f"git stash {arg}", "Permanently removes stashed changes")
            break
        return None

    if subcmd in ("push", "send-email"):
        return GuardMatch("irreversible", f"git {subcmd}", "Mutates remote Git state outside local snapshots")

    return None


def _check_rm(args: list[str], *, root: Path, cwd: Path | None) -> GuardMatch | None:
    recursive = False
    force = False
    targets: list[str] = []
    options_done = False
    for arg in args:
        if options_done:
            targets.append(arg)
            continue
        if arg == "--":
            options_done = True
            continue
        if arg == "--recursive":
            recursive = True
        elif arg == "--force":
            force = True
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            flags = arg[1:]
            if "r" in flags or "R" in flags:
                recursive = True
            if "f" in flags:
                force = True
        else:
            targets.append(arg)
    if not recursive or not targets:
        return None

    rule = "rm -rf" if force else "rm -r"
    git_dir = root / ".git"
    workspace_match: GuardMatch | None = None
    for target in targets:
        impact = _classify_rm_target(target, root=root, git_dir=git_dir, cwd=cwd)
        if impact == "unrecoverable":
            return GuardMatch(
                "unrecoverable",
                rule,
                "Deletes the workspace root, an ancestor directory, or .git, which cannot be undone",
                always_block=True,
            )
        if impact == "workspace" and workspace_match is None:
            workspace_match = GuardMatch(
                "destructive",
                rule,
                "Recursively deletes files inside the workspace",
            )
    return workspace_match


def _classify_rm_target(target: str, *, root: Path, git_dir: Path, cwd: Path | None) -> str | None:
    if not target:
        return None
    if _SHELL_EXPANSION.search(target):
        return "workspace"
    expanded = Path(os.path.expanduser(target))
    if expanded.is_absolute():
        resolved = expanded.resolve(strict=False)
    elif cwd is None:
        return "workspace"
    else:
        resolved = (cwd / expanded).resolve(strict=False)
    if root.is_relative_to(resolved) or resolved.is_relative_to(git_dir) or git_dir.is_relative_to(resolved):
        return "unrecoverable"
    if resolved.is_relative_to(root):
        return "workspace"
    return None


def _check_find(args: list[str]) -> GuardMatch | None:
    if "-delete" in args:
        return GuardMatch("destructive", "find -delete", "Deletes matched files directly")
    return None
