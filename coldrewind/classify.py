from pathlib import Path
from typing import Literal

from .paths import is_ignored, workspace_path

Reversibility = Literal["reversible", "partial", "irreversible"]

_PRIVILEGED = {"doas", "pkexec", "run0", "runuser", "su", "sudo", "systemd-run"}
_COMMAND_WRAPPERS = {
    "ash", "bash", "csh", "dash", "env", "eval", "exec", "fish", "flock", "ksh",
    "make", "nice", "nohup", "python", "python3", "setsid", "sh", "stdbuf", "tcsh",
    "time", "timeout", "xargs", "zsh",
}
_EXTERNAL_COMMANDS = {
    "curl", "docker", "gh", "nc", "netcat", "npm", "npx", "rsync", "scp", "sftp", "ssh", "wget",
}


def classify(
    root: Path,
    command: tuple[str, ...],
    changed_paths: tuple[str, ...],
    *,
    pre_snapshot_id: str | None,
    post_snapshot_id: str | None,
    capture_complete: bool = False,
) -> tuple[Reversibility, str]:
    """Classify observed effects. Complete capture requires evidence of local-only
    execution and snapshot coverage of every change, beyond the presence of IDs.
    """
    root = root.resolve(strict=True)
    local_changes = False
    outside_changes = False
    ignored_changes = False
    for name in changed_paths:
        path = Path(name)
        try:
            relative = path.relative_to(root) if path.is_absolute() else path
            workspace_path(root, relative)
        except (ValueError, OSError, RuntimeError):
            outside_changes = True
        else:
            local_changes = True
            ignored_changes |= is_ignored(relative)

    executable = Path(command[0]).name
    if executable in _PRIVILEGED:
        reason = "Privileged command"
    elif (
        executable in _COMMAND_WRAPPERS
        or executable.startswith("python3.")
        or (executable == "find" and {"-exec", "-execdir", "-ok", "-okdir"}.intersection(command[1:]))
    ):
        reason = "Command delegates execution"
    elif executable in _EXTERNAL_COMMANDS or (
        executable == "git" and any(arg in {"push", "send-email"} for arg in command[1:])
    ):
        reason = "Command can mutate external state"
    elif outside_changes:
        reason = "Write outside the watched workspace"
    elif ignored_changes:
        reason = "Write to an excluded path"
    elif not (capture_complete is True and pre_snapshot_id and post_snapshot_id):
        reason = "Incomplete evidence of reversible local effects"
    elif not local_changes:
        return "irreversible", "No observed local change to restore"
    else:
        return "reversible", "All changes are local and covered by snapshots"

    return ("partial" if local_changes else "irreversible"), reason
