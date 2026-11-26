# ColdRewind

ColdRewind checkpoints local files and Git state around a command. Use its
Claude Code, Codex, OpenCode, Cursor, Antigravity, or Gemini CLI hooks, or run
a command with `coldrewind run --`.
Inspect the changes, undo a captured step, and redo it when needed.

- Zero third-party runtime dependencies (Python 3.11+ standard library)
- Zero cloud services, zero outbound network calls, zero persistent daemon
- Restores what Git misses: uncommitted edits, untracked files, staged index state, binaries, permissions, symlinks, local SQLite files, and Git refs

## Install and capture your first change

From a local ColdRewind checkout, run the following with uv and Python 3.11 or
newer. uv installs the CLI in its own environment. Keep that environment outside
the workspace you want to watch.

```sh
uv tool install .
coldrewind --version
```

If your shell cannot find `coldrewind`, run `uv tool update-shell`, then open
a new shell.

For an unattended install from the checkout, activate a fresh Python 3.11+
virtual environment outside the watched workspace and run these commands.

```sh
python -m pip install .
coldrewind --version
```

In the workspace you want to watch, register it and install the hooks for one
client. This example uses Claude Code.

```sh
coldrewind init --client claude
```

Start a new Claude Code session in that workspace and ask it to make a small file
edit. Run `coldrewind log` in the workspace to find the step ID, then run
`coldrewind diff STEP` with that ID to see the captured change.

## Client hooks and uninstall

`init` registers the current directory and installs user-level hooks for the
selected clients. The hooks apply across all registered workspaces for those
clients. Both `init` and `uninstall` select all six clients by default.
Repeat `--client` to select more than one. Pass `--guard checkpoint|block|off`
to `init` to pin a pre-tool guard mode in the installed hooks.

| Client | Default path | Entries installed by `init` and removed by `uninstall` |
| --- | --- | --- |
| Claude Code (`claude`) | `~/.claude/settings.json` | One command handler each under `hooks.PreToolUse`, `hooks.PostToolUse`, `hooks.PostToolUseFailure`, and `hooks.PermissionDenied`. |
| Codex (`codex`) | `~/.codex/hooks.json` | One command handler each under `hooks.PreToolUse` and `hooks.PostToolUse`. |
| OpenCode (`opencode`) | `~/.config/opencode/plugins/coldrewind.js` | One plugin file that registers `tool.execute.before` and `tool.execute.after`. |
| Cursor (`cursor`) | `~/.cursor/hooks.json` | One command entry each under `hooks.preToolUse`, `hooks.postToolUse`, and `hooks.postToolUseFailure` (with `version: 1`). |
| Antigravity (`antigravity`) | `~/.gemini/config/hooks.json` | One named `coldrewind` hook spec with `PreToolUse` and `PostToolUse` matcher groups (`*`). |
| Gemini CLI (`gemini`) | `~/.gemini/settings.json` | One matcher group (`*`) each under `hooks.BeforeTool` and `hooks.AfterTool` with millisecond timeouts. |

When set to absolute paths, `CLAUDE_CONFIG_DIR` replaces `~/.claude`,
`CODEX_HOME` replaces `~/.codex`, `XDG_CONFIG_HOME` replaces `~/.config`,
`CURSOR_CONFIG_DIR` replaces `~/.cursor`, `ANTIGRAVITY_CONFIG_DIR` replaces
`~/.gemini/config`, and `GEMINI_CONFIG_DIR` replaces `~/.gemini`.

JSON-configured clients keep other settings and handlers. ColdRewind matches its
command handlers by the exact command for the current installation. Before
changing an existing JSON file, it saves a sibling copy named
`<filename>.coldrewind-backup-<UTC timestamp>`. For OpenCode, ColdRewind
removes the plugin only if its contents match what the current installation
generates. It refuses to replace or remove a different file at that path.

## Destructive command guard

Pre-tool hooks classify destructive workspace commands (`git reset --hard`,
`git reset --merge`, `git clean -f*`, `git checkout --`, `git checkout .`,
`git checkout -f`, `git restore` on the worktree, `git stash drop/clear`,
`rm -rf` targeting the workspace, `find -delete`) and irreversible/partial-capture
commands (privileged wrappers like `sudo`, `git push`, `git send-email`):

- `checkpoint` (default): force-checkpoints immediately before execution
  (bypassing `COLDREWIND_SNAPSHOT_MIN_INTERVAL_SECONDS` throttling) and **fails
  closed** (blocks the tool) if the force-checkpoint fails. Unrecoverable
  recursive deletions of the workspace root, an ancestor directory, or `.git`
  are always denied because they cannot be undone.
- `block`: blocks classified commands before execution without leaving pending
  markers behind.
- `off`: disables guard blocking and falls back to fail-open capture.

Configure via `COLDREWIND_GUARD=checkpoint|block|off` or `--guard` on `init` / `hook`.

From any directory, remove Claude Code's hooks with the following command.

```sh
coldrewind uninstall --client claude
```

Uninstall keeps the installed CLI, config backups, workspace registry, snapshots,
and timeline. ColdRewind stores the registry, snapshots, and timeline under
`~/.local/state/coldrewind` by default, or `$XDG_STATE_HOME/coldrewind` when
`XDG_STATE_HOME` is absolute. Running `init` again enables hooks for the selected
client across previously registered workspaces.

To remove the CLI as well, first remove every client hook you installed, then run
`uv tool uninstall coldrewind`. The hooks refer to the installation that created
them, so remove them before moving or removing that installation.

## Limitations

Use a local Linux or macOS filesystem that supports advisory locks, symlinks,
and exclusive rename. Btrfs, XFS with reflink enabled, and APFS can clone file
data when the snapshot store and workspace support it. ColdRewind copies bytes
when cloning is unavailable, including on ext4. Restore refuses a filesystem
that cannot safely replace a file. Network filesystems and Windows are untested.

Undo restores recorded workspace files, the Git index, and refs whose objects
still exist. It cannot reverse a network request, a remote push, or writes
outside the workspace. Concurrent edits can cause a conflict. A snapshot of a
live database is a file copy and may require application-level recovery.

## Documentation

- [CLI commands and exit codes](docs/cli.md)
- [Contribution and test instructions](CONTRIBUTING.md)
- [Security reporting](SECURITY.md)

## License

MIT. See [LICENSE](LICENSE).
