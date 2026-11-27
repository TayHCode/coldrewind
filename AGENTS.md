# ColdRewind (Agent Guide)

Local-first rewind button for AI coding agents. No telemetry. Zero network calls.

## Install & Verify
- Install: `uv tool install .` (or `python -m pip install .` in a venv outside the watched workspace).
- Verify install & hooks: `coldrewind --version` and `coldrewind doctor --json`.
- Verify workspace state (inside a registered workspace): `coldrewind status --json`.

## First Commands
- Preview hook config diffs safely: `coldrewind init --dry-run --json`
- Enable for one client: `coldrewind init --client claude --json` (`claude`, `codex`, `opencode`, `cursor`, `antigravity`, `gemini`)
- Inspect and restore: `coldrewind log --json`, `coldrewind diff <step> --json`, `coldrewind undo [step] --json`

## Safety Rules
- Never pass `--yes` (multi-client `init`), `--force` (`undo`/`redo`), or `--apply` without explicit user approval. Prefer `--dry-run` or a single `--client <name>`.

## Exit Codes
- `0`: Success (`doctor`: all installed hooks resolve, or none installed yet).
- `1`: Failed check or refusal (`doctor` broken hook/registry, `conflict`, `ambiguous_restore`, `pruned_snapshots`, `nothing_to_restore`).
- `2`: Usage error (including multi-client `init` without `--yes`), `unregistered_workspace`, or `local_error`.
