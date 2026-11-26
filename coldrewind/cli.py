"""Command-line entry point for ColdRewind."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path

from coldrewind import __version__, guard, hooks, init_cmd, restore, retention, snapshot
from coldrewind.config import Registry
from coldrewind.diff import diff
from coldrewind.ledger import read_steps
from coldrewind.redact import redact_step, redact_text
from coldrewind.runner import run, workspace_root


JSON_COMMANDS = (
    ("init", "Watch this workspace and install agent hooks"),
    ("uninstall", "Remove ColdRewind agent hooks"),
    ("status", "Show the backend of the latest stored snapshot"),
    ("log", "Show recorded steps"),
    ("diff", "Show what changed in a step"),
    ("undo", "Restore the workspace to before a step"),
    ("redo", "Restore the workspace to before an undo"),
    ("prune", "Apply workspace store retention"),
)


class NothingToRestore(ValueError):
    pass


class UnregisteredWorkspace(ValueError):
    pass


class UsageError(ValueError):
    pass


class JSONArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def build_parser(*, json_errors: bool = False) -> argparse.ArgumentParser:
    parser_type = JSONArgumentParser if json_errors else argparse.ArgumentParser
    parser = parser_type(
        prog="coldrewind",
        description="Local-first rewind button for AI agents.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    commands = parser.add_subparsers(dest="subcommand")
    run_parser = commands.add_parser("run", help="Capture a command in a watched workspace")
    run_parser.add_argument("command", nargs=argparse.REMAINDER, metavar="-- <cmd>")
    hook_parser = commands.add_parser("hook", help="Record one agent hook event from stdin")
    hook_parser.add_argument("client", choices=tuple(hooks.AGENTS))
    hook_parser.add_argument("phase", choices=hooks.PHASES)
    hook_parser.add_argument(
        "--guard", choices=guard.MODES, default=None,
        help="destructive/irreversible command guard mode (default: COLDREWIND_GUARD or checkpoint)",
    )

    for name, help_text in JSON_COMMANDS:
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--json", action="store_true", help="Emit versioned JSON")
        if name in ("init", "uninstall"):
            command.add_argument(
                "--client", action="append", choices=tuple(hooks.AGENTS), dest="clients",
                help="client to change (repeatable; default: all)",
            )
        if name == "init":
            command.add_argument(
                "--guard", choices=guard.MODES, default=None,
                help="pin guard mode in installed hooks (checkpoint, block, or off)",
            )
        if name in ("diff", "undo", "redo"):
            command.add_argument("step", type=int, nargs=None if name == "diff" else "?")
        if name in ("undo", "redo"):
            command.add_argument("--force", action="store_true", help="Allow intervening changes")
        if name == "diff":
            command.add_argument("--show-secrets", action="store_true", help="Show unredacted changes")
    return parser


def _print(args: argparse.Namespace, payload: dict, lines: list[str]) -> None:
    if args.json:
        print(json.dumps({"schema_version": 1, **payload}))
    else:
        for line in lines:
            print(line)


def _workspace_command(args: argparse.Namespace, registry: Registry, root: Path) -> None:
    name = args.subcommand
    if name == "status":
        backend = snapshot.latest_backend(registry, root)
        capture_error = snapshot.latest_capture_error(registry, root)
        lines = [f"Snapshot backend: {backend}" if backend else "No snapshots"]
        if capture_error:
            lines.append(f"Last capture error: {capture_error}")
        _print(args, {"backend": backend, "last_capture_error": capture_error}, lines)
        return
    if name == "prune":
        with registry.workspace_lock(root) as store:
            result = retention.prune_locked(store, report=True)
        _print(args, asdict(result), [f"Pruned {len(result.pruned)} snapshot(s)",
                                     f"{result.total_bytes} bytes total, {result.protected_bytes} protected snapshot bytes"])
        return
    if name == "log":
        steps = [redact_step(step) for step in read_steps(registry, root)]
        _print(args, {"steps": [asdict(step) for step in steps]}, [
            f"{step.step_id} {step.timestamp} {step.agent} {step.reversibility} {' '.join(step.command)}"
            for step in steps
        ])
        return

    if name == "diff":
        step = next((step for step in read_steps(registry, root) if step.step_id == args.step), None)
        if step is None:
            raise ValueError(f"no step {args.step}")
        if not (step.pre_snapshot_id and step.post_snapshot_id):
            raise ValueError("step has no snapshots to compare")
        try:
            changes = diff(
                registry, root, step.pre_snapshot_id, step.post_snapshot_id,
                show_secrets=args.show_secrets,
            )
        except FileNotFoundError:
            raise restore.PrunedSnapshots("step snapshot data is no longer available") from None
        if args.json:
            _print(args, changes, [])
        else:
            sys.stdout.write(changes["patch"])
            for kind in ("added", "deleted", "modified", "binary", "git"):
                for path in changes[kind]:
                    print(f"{kind}: {path}")
        return

    step_id = args.step
    if step_id is None:
        steps = read_steps(registry, root)
        if name == "redo":
            steps = [
                step for step in steps
                if step.agent == "coldrewind" and step.command[:2] == ("coldrewind", "undo")
            ]
        if not steps:
            raise NothingToRestore("no undo to redo" if name == "redo" else "no step to undo")
        step_id = steps[-1].step_id
    rewind = restore.undo if name == "undo" else restore.redo
    step = redact_step(rewind(registry, root, step_id, force=args.force))
    _print(args, {"step": asdict(step)}, [f"{name} recorded as step {step.step_id}"])


def _error(name: str, reason: str, message: str, code: int, *, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"schema_version": 1, "reason": reason, "message": redact_text(message)}))
    else:
        print(f"coldrewind {name}: {message}", file=sys.stderr)
    return code


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    options = argv[:argv.index("--")] if "--" in argv else argv
    json_errors = bool(options and options[0] in dict(JSON_COMMANDS) and any(
        token.split("=", 1)[0] in ("--j", "--js", "--jso", "--json")
        for token in options[1:]
    ))
    parser = build_parser(json_errors=json_errors)
    try:
        args = parser.parse_args(argv)
    except UsageError as error:
        return _error(argv[0], "usage", str(error), 2, as_json=json_errors)
    name = args.subcommand
    if name is None:
        parser.print_help()
        return 0
    if name == "run" and (len(args.command) < 2 or args.command[0] != "--" or not args.command[1]):
        parser.error("expected coldrewind run -- <cmd>")

    try:
        registry = Registry()
        if name == "run":
            return run(registry, tuple(args.command[1:]))
        if name == "hook":
            return hooks.main(registry, args.client, args.phase, sys.stdin, guard_mode=args.guard)
        cwd = Path.cwd()
        if name in ("init", "uninstall"):
            clients = tuple(args.clients or hooks.AGENTS)
            changed = (
                init_cmd.init(registry, Path.home(), cwd, clients, guard_mode=args.guard)
                if name == "init" else init_cmd.uninstall(Path.home(), clients)
            )
            _print(args, {"updated": [str(path) for path in changed]}, [f"updated {path}" for path in changed])
        else:
            root = workspace_root(registry, cwd)
            if root is None:
                raise UnregisteredWorkspace("current directory is outside registered workspaces")
            _workspace_command(args, registry, root)
    except (NothingToRestore, restore.Conflict, restore.PrunedSnapshots, restore.AmbiguousRestore) as error:
        reason = {
            NothingToRestore: "nothing_to_restore",
            restore.Conflict: "conflict",
            restore.PrunedSnapshots: "pruned_snapshots",
            restore.AmbiguousRestore: "ambiguous_restore",
        }[type(error)]
        return _error(
            name, reason, redact_text(str(error)), 0 if name == "hook" else 1,
            as_json=getattr(args, "json", False),
        )
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
        reason = "unregistered_workspace" if isinstance(error, UnregisteredWorkspace) else "local_error"
        return _error(name, reason, str(error), 0 if name == "hook" else 2,
                      as_json=getattr(args, "json", False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
