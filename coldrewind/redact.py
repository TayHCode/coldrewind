from __future__ import annotations

import re
from dataclasses import replace
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ledger import Step

MASK = "[REDACTED]"

_PRIVATE_KEY = re.compile(
    "-----BEGIN ([A-Z0-9 ]*)PRIVATE" r" KEY-----.*?(?:-----END \1PRIVATE" r" KEY-----|\Z)", re.DOTALL
)
_TOKENS = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"sk-[A-Za-z0-9_-]{16,}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|glpat-[A-Za-z0-9_-]{20,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{35}"
    r")"
)
_ASSIGNMENT = re.compile(
    r"(?i)((?:api[_-]?key|access[_-]?key|token|secret|password|passwd)[A-Za-z0-9_-]*"
    r"[\"']?\s*[:=]\s*)(\"[^\"\n]*\"|'[^'\n]*'|[^\s,;\"']+)"
)
_ENV_LINE = re.compile(
    r"(?m)^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*=)"
    r"(?:\s*\"(?:[^\"\\]|\\[\s\S])*\"?|\s*'[^']*'?|[^\n]*)"
)
_AUTH_HEADER = re.compile(
    r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?\s*(?:bearer|basic)[ \t]+)([^\s,;\"']+)"
)
_FLAG = r"--?[A-Za-z0-9_-]*(?:token|secret|password|passwd|api[_-]?key|access[_-]?key)[A-Za-z0-9_-]*"
_FLAG_VALUE = re.compile(rf"(?i)((?<![A-Za-z0-9_-]){_FLAG}[ \t]+)(?:\\\n|[^\n])+")


def is_env_file(path: str) -> bool:
    return PurePosixPath(path).name.startswith(".env")


def redact_text(text: str) -> str:
    text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    text = _TOKENS.sub(MASK, text)
    text = _AUTH_HEADER.sub(lambda match: match.group(1) + MASK, text)
    text = _FLAG_VALUE.sub(lambda match: match.group(1) + MASK, text)
    return _ASSIGNMENT.sub(lambda match: match.group(1) + MASK, text)


def redact_file(path: str, text: str) -> str:
    if is_env_file(path):
        text = _ENV_LINE.sub(lambda match: match.group(1) + MASK, text)
    return redact_text(text)


def command_summary(agent: str, command: tuple[str, ...]) -> tuple[str, ...]:
    if (
        agent == "coldrewind" and len(command) == 3 and command[0] == "coldrewind"
        and command[1] in ("undo", "redo") and re.fullmatch(r"[0-9]+", command[2])
    ):
        return command
    tool = PurePosixPath(command[0]).name
    if not tool or not re.fullmatch(r"[A-Za-z0-9_./+-]+", command[0]) or redact_text(tool) != tool:
        tool = MASK
    return (tool, MASK) if len(command) > 1 else (tool,)


def redact_step(step: Step) -> Step:
    return replace(
        step,
        command=command_summary(step.agent, step.command),
        changed_paths=tuple(redact_text(path) for path in step.changed_paths),
        reason=redact_text(step.reason),
    )
