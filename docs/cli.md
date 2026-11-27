# CLI contracts

The inspection and restore commands use the nearest registered workspace that contains the current directory.

| Command | Success output with `--json` |
|---|---|
| `init [--client CLIENT] [--guard MODE] [--dry-run] [--yes]` | [Updated hook configuration paths](schemas/cli-v1.schema.json#init). Registers the current directory. Multi-client edits require `--yes`; `--dry-run` previews planned files and diffs without writing. |
| `uninstall [--client CLIENT]` | [Updated hook configuration paths](schemas/cli-v1.schema.json#uninstall). Removes user-level hooks for the selected clients and keeps the registry and timeline. |
| `doctor [--client CLIENT]` | [Hook resolution and environment check](schemas/cli-v1.schema.json#doctor). Verifies installed hooks resolve to an executable binary and package path. Exits `1` if any installed hook or the registry is broken. |
| `status` | [Backend of the latest snapshot](schemas/cli-v1.schema.json#status), and the last recorded capture error for this workspace. Each field can be `null`. Capture errors are summaries and remain visible after subsequent successful captures. |
| `log` | [Redacted steps](schemas/cli-v1.schema.json#log) in ascending step ID order. |
| `diff STEP [--show-secrets]` | [Changed paths and unified patch](schemas/cli-v1.schema.json#diff) between the step's two snapshots. |
| `undo [STEP] [--force]` | [Recorded restore step](schemas/cli-v1.schema.json#undo). Defaults to the latest step. |
| `redo [UNDO_STEP] [--force]` | [Recorded restore step](schemas/cli-v1.schema.json#redo). Defaults to the latest undo. |
| `prune` | [IDs of removed snapshots and workspace store sizes](schemas/cli-v1.schema.json#prune). |

See [Client hooks and uninstall](../README.md#client-hooks-and-uninstall) for the default client selection, config paths, and hook ownership rules.

Successful JSON responses contain one object with `schema_version: 1` on stdout. With `--json`, a refusal or error also writes one [error object](schemas/cli-v1.schema.json#error) on stdout. Its `reason` is a stable code and `message` is for display. In plain mode, stderr explains the failure. The [outbox schema](schemas/cli-v1.schema.json#outbox) is reserved for Phase 2.

| Code | Meaning |
|---|---|
| `0` | The command succeeded. |
| `1` | `conflict` for intervening changes, `ambiguous_restore` for overlapping captures, `pruned_snapshots` for unavailable snapshot data, `nothing_to_restore` when no step was given and there is no eligible step, or a failed `doctor` check. |
| `2` | `usage` for invalid arguments, `unregistered_workspace` where registration is required, or `local_error` for a local failure such as an unknown step ID or an incomplete step. |

`--force` allows a restore to overwrite intervening changes. A restore still needs both step snapshots. If either manifest is gone, `undo` and `redo` exit `1` before taking a safety snapshot or changing the workspace.

Each workspace store shares one retention budget across snapshots, the SQLite ledger, caches, markers and other files. Set `COLDREWIND_MAX_BYTES` and `COLDREWIND_MAX_AGE_SECONDS` in the environment of the CLI and hook processes to override 500 MiB and seven days. Both accept nonnegative integers. The same age applies to ledger rows and snapshots. Under byte pressure, prune can drop rebuildable caches, older snapshots and older ledger rows. Step IDs stay stable.

After pruning, `total_bytes` counts the logical sizes of all non-directory entries under the workspace store, including SQLite and symlinks themselves. `protected_bytes` counts the manifests, backend sidecars and distinct blobs for active capture pins, the two newest snapshots, the latest step and the latest undo. The latest step, the latest undo and overlap evidence needed by surviving steps or active captures are retained. Protected content and required metadata can exceed a small byte budget. Hook pins keep their existing seven-day lifetime independently of the configured history age.

ColdRewind pins each active capture's pre-snapshot during pruning. Undo refuses a step that overlapped another capture, including with `--force`, because its snapshots can contain both writers' changes. The refusal names the overlapping steps. A capture that never recorded a step is identified by its capture ID. Use `coldrewind diff STEP` to inspect the changes before editing the workspace yourself.

An agent can invoke undo or redo from a hooked command for a step that finished before the hook started. The restore journal records the exact change. The enclosing hook step overlaps that restore and cannot itself be undone.

A pre event without a post pins its snapshot for seven days unless ColdRewind receives a confirmed release. Undo and redo refusals name the overlapping capture and its UTC pin expiry. After expiry, new captures can proceed. Previously recorded overlaps still refuse undo, including with `--force`. Run `coldrewind init --client claude` after upgrading to install the denial handler.

- **Claude Code.** Auto mode emits `PermissionDenied` with the session and tool-use IDs. ColdRewind removes that call’s pin and overlap records because the tool never ran. Manual permission denials do not emit this event. `SessionEnd` also fires on `/clear` and interactive `/resume`. This event cannot confirm that a particular call never ran. [Claude Code hook reference](https://code.claude.com/docs/en/hooks#permissiondenied)
- **Codex.** No documented hook confirms that a particular pending call will never run. `SessionEnd` reports the end of the main thread, while subagent hooks can carry the same session ID. `PermissionRequest` precedes the decision, `Interrupt` reports a turn interruption, and `Stop` can continue a turn. None confirms denial of an individual call. [Codex hook reference](https://developers.openai.com/codex/hooks)
- **OpenCode.** The v1 plugin has no confirmed release signal for an orphaned pre hook. An interrupted call may still reach `tool.execute.after` after its tool part reports an error. Session deletion does not establish that all tools have stopped. These pins retain the seven-day expiry. [OpenCode tool execution](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/session/tools.ts#L102-L129), [interruption cleanup](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/session/processor.ts#L585-L608), [session deletion](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/session/session.ts#L606-L625)

Undo and redo save a recovery intent before changing files. After interruption, the next command that locks the workspace rolls back an unfinished restore. If the ledger already contains its committed step, recovery keeps the completed restore. Both paths can be restarted. A competing save at replacement keeps its contents and causes a conflict, including with `--force`. Filesystem changes use exclusive rename on Linux and macOS. A filesystem that cannot perform the move refuses the restore.

If two saves collide during rollback, the latest save stays at its path. The conflict message names any additional saved version. If the workspace identity or ledger changed, recovery pauses and prints the intent file path. To resume, restore the original workspace and ledger, then run `coldrewind log`. To retire an intent for a workspace you deliberately replaced, first stop workspace writers. Preserve the workspace and state directory, including the `.coldrewind-<nonce>` directories in the workspace, Git directories and store. After verifying the replacement files and ledger, rename the reported `restore-intent.json` to `restore-intent.archived.json` in its store and run `coldrewind log`.

`run -- COMMAND [ARG ...]` forwards the child's streams. It returns the child's exit code, or `128 + signal number` if a signal killed it. Errors before launch exit `2`. Capture errors after launch go to stderr and preserve the child's status.

`hook CLIENT PHASE [--guard MODE]` reads one JSON event on stdin for `claude`, `codex`, `opencode`, `cursor`, `antigravity`, or `gemini`. For non-guarded commands it exits `0` even if processing fails, reporting the failure on stderr so it does not block the agent. For destructive or irreversible/partial-capture commands during `pre`, the guard defaults to `checkpoint` (force-checkpoint immediately, bypassing `COLDREWIND_SNAPSHOT_MIN_INTERVAL_SECONDS`, fail closed if checkpointing fails, and always deny unrecoverable recursive deletions of the workspace root, an ancestor directory, or `.git`), supports `block` (deny before execution), and supports `off` (fail-open). Override via `COLDREWIND_GUARD` or `--guard`. Blocked calls emit each client's native deny response (`permissionDecision: "deny"` + exit `2` for Claude Code, exit `2` for Codex/OpenCode, `permission: "deny"` + exit `2` for Cursor, `decision: "deny"` + exit `2` for Gemini CLI, `decision: "deny"` + exit `0` for Antigravity). Invalid CLI arguments exit `2`. The `run` and `hook` interfaces use their own stream contracts.

## Verify the installed CLI

Build a wheel, then run the installed CLI tests. Wheel preparation can fetch the build backend. The test installs the resulting wheel offline in a fresh virtual environment and blocks Python socket operations in the installed CLI.

```sh
python3 -m pip wheel --no-deps --wheel-dir .scratch/wheels .
COLDREWIND_WHEEL="$(pwd)/.scratch/wheels/coldrewind-0.1.0-py3-none-any.whl" \
  python3 -m unittest discover -s tests/installed -v
```
