import json
import os
import re
import stat
from contextlib import ExitStack, contextmanager
from pathlib import Path

from . import retention
from .config import Registry
from .git_state import git_dirs, is_private
from .ledger import Step, append_step_locked, overlapping_steps_locked, read_steps_locked
from .restore_journal import Conflict, DIR_FLAGS, INTENT, Journal, directory, identity, info
from .snapshot import describe_marker, pending_markers, read_manifest, take_locked


class AmbiguousRestore(ValueError):
    pass


class PrunedSnapshots(ValueError):
    pass


def undo(registry: Registry, root: Path, step_id: int, *, force: bool = False) -> Step:
    return _rewind(registry, root, step_id, force, "undo")


def redo(registry: Registry, root: Path, undo_step_id: int, *, force: bool = False) -> Step:
    return _rewind(registry, root, undo_step_id, force, "redo")


def _rewind(registry: Registry, root: Path, step_id: int, force: bool, verb: str) -> Step:
    root = root.resolve(strict=True)
    with registry.workspace_lock(root) as store:
        steps = read_steps_locked(store)
        step = next((step for step in steps if step.step_id == step_id), None)
        if step is None:
            raise ValueError(f"no step {step_id}")
        if verb == "redo" and (step.agent != "coldrewind" or step.command[:2] != ("coldrewind", "undo")):
            raise ValueError("redo needs an undo step")
        peers = overlapping_steps_locked(store, step.step_id)
        if peers:
            names = [f"step {peer}" if peer is not None else
                     f"unfinished capture {describe_marker(store, name)}" for peer, name in peers]
            raise AmbiguousRestore(f"step {step.step_id} overlaps " + ", ".join(names))
        if not (step.pre_snapshot_id and step.post_snapshot_id):
            raise ValueError("step has no snapshots to restore")
        try:
            target = read_manifest(registry, root, step.pre_snapshot_id)
            post = read_manifest(registry, root, step.post_snapshot_id)
        except FileNotFoundError:
            raise PrunedSnapshots("step snapshots are no longer available and may have been pruned") from None
        if _blobs(target) - set(os.listdir(store / "blobs")):
            raise ValueError("snapshot blobs are missing")
        with _bases(root) as bases:
            safety_id = take_locked(store, root)
            opened = [identity(fd) for fd in bases]
            if [list(key) for _, key in _identity(root)] != opened:
                raise ValueError("workspace identity changed; refusing to write")
            if any(m.get("identity") != opened for m in (post, target)):
                raise ValueError("workspace is not the worktree the step captured; refusing to write")
            safety = read_manifest(registry, root, safety_id)
            active = tuple(pending_markers(store))
            if safety_id != step.post_snapshot_id and not force:
                conflict = Conflict(_changed(safety, post))
                if active:
                    markers = ", ".join(describe_marker(store, name) for name in active)
                    raise AmbiguousRestore(f"{conflict}. Pending capture: {markers}")
                raise conflict
            if safety["files"].get(".git") != target["files"].get(".git"):
                raise Conflict([".git"])
            journal = Journal.begin(store, bases, safety_id, step.pre_snapshot_id, steps[-1].step_id)
            try:
                _apply(journal, safety, target)
                excluded = journal.name if "0" in journal.intent["staging"] else None
                observed = take_locked(store, root, exclude=excluded)
                if observed != step.pre_snapshot_id:
                    raise Conflict(_changed(read_manifest(registry, root, observed), target))
                journal.visit(rollback=False)
                result = append_step_locked(
                    store, root, agent="coldrewind", command=("coldrewind", verb, str(step.step_id)),
                    changed_paths=tuple(_changed(safety, target)), pre_snapshot_id=safety_id,
                    post_snapshot_id=step.pre_snapshot_id, capture_complete=True,
                    captures_during_restore=active,
                )
            except BaseException:
                recover_locked(store, root)
                raise
            journal.finish()
            retention.maintain_locked(store)
            return result


@contextmanager
def _bases(root):
    with ExitStack() as stack:
        bases = []
        for path, key in _identity(root):
            fd = os.open(path, DIR_FLAGS)
            stack.callback(os.close, fd)
            if _key(os.fstat(fd)) != key:
                raise ValueError("workspace identity changed; refusing to write")
            bases.append(fd)
        yield bases


def recover_locked(store, root):
    intent = json.loads((store / INTENT).read_bytes())
    if not re.fullmatch("[a-f0-9]{32}", intent["nonce"]):
        raise ValueError("invalid restore journal nonce")
    with _bases(root) as bases:
        if [identity(fd) for fd in bases] != intent["identity"]:
            raise ValueError(f"workspace identity changed; recovery paused at {store / INTENT}. See docs/cli.md.")
        journal = Journal(store, bases, intent)
        if intent.get("finished"):
            journal.clean()
            return
        steps = read_steps_locked(store)
        latest = steps[-1] if steps else None
        conflicts = []
        if latest and latest.step_id == intent["previous_step"]:
            conflicts = journal.visit(rollback=True)
        elif not latest or (latest.agent, latest.pre_snapshot_id, latest.post_snapshot_id) != (
            "coldrewind", intent["safety"], intent["target"]
        ):
            raise ValueError(f"restore journal and ledger disagree; recovery paused at {store / INTENT}. See docs/cli.md.")
        locations = [path for path, _ in _identity(root)]
        conflicts.extend(str(locations[base] / name) for name, base in intent.get("saved", {}).items())
        journal.finish()
        if conflicts:
            raise Conflict(conflicts)


def _key(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def _identity(root: Path) -> list[tuple[Path, tuple[int, int]]]:
    if root.resolve(strict=True) != root:
        raise ValueError("workspace path changed; refusing to write")
    return [(path, _key(os.stat(path))) for path in (root, *(git_dirs(root) or ()))]


def _changed(a: dict, b: dict) -> list[str]:
    files = [p for p in a["files"].keys() | b["files"].keys() if a["files"].get(p) != b["files"].get(p)]
    git = [f".git/{n}" for n in a["git"].keys() | b["git"].keys() if a["git"].get(n) != b["git"].get(n)]
    return sorted(files + git)


def _blobs(manifest: dict) -> set[str]:
    entries = [*manifest["files"].values(), *manifest["git"].values()]
    return {entry["sha256"] for entry in entries if "sha256" in entry}


def _apply(journal, current, target):
    _apply_tree(journal, 0, current["files"], target["files"])
    if len(journal.bases) == 1:
        return
    for private, base in ((True, 1), (False, 2)):
        old, new = [
            {name: {"type": "file", **entry} for name, entry in manifest["git"].items()
             if is_private(name) == private}
            for manifest in (current, target)
        ]
        _apply_tree(journal, base, old, new, git=True)


def _apply_tree(journal, base, current, target, git=False):
    root = journal.bases[base]
    if git:
        # Git snapshots list files only. Keep existing ref directories unless
        # their name must become a file.
        files = set(target)
        needed = {str(p) for rel in files for p in Path(rel).parents if p != Path(".")}
        parents = {str(p) for rel in current for p in Path(rel).parents if p != Path(".")}
        for rel in needed | parents | files:
            with ExitStack() as stack:
                try:
                    st = info(_parent(stack, root, rel), rel.split("/")[-1])
                except (NotADirectoryError, FileNotFoundError):
                    st = None
            if st and stat.S_ISDIR(st.st_mode):
                if rel in current:
                    raise Conflict([f".git/{rel}"])
                current[rel] = {"type": "dir", "mode": stat.S_IMODE(st.st_mode)}
                if rel not in files and not any(str(p) in files for p in Path(rel).parents):
                    target[rel] = current[rel]
            if rel in needed and rel not in target:
                target[rel] = {"type": "dir", "mode": 0o755}
    removed = set()
    for rel in sorted(current, key=lambda p: p.split("/"), reverse=True):
        old, new = current[rel], target.get(rel)
        if new is None or (old["type"] == "dir") != (new["type"] == "dir"):
            _replace(journal, base, rel, old, None)
            removed.add(rel)
    modes = []
    for rel in sorted(target, key=lambda p: p.split("/")):
        new = target[rel]
        old = None if rel in removed else current.get(rel)
        if new == old:
            continue
        if new["type"] == "dir":
            writable = old or {"type": "dir", "mode": 0o700}
            if old is None:
                _replace(journal, base, rel, None, writable)
            if new != writable:
                modes.append((rel, writable, new))
        else:
            _replace(journal, base, rel, old, new)
    for rel, old, new in reversed(modes):
        _replace(journal, base, rel, old, new)


def _parent(stack, root, rel):
    fd = root
    for part in rel.split("/")[:-1]:
        fd = stack.enter_context(directory(fd, part))
    return fd


def _replace(journal, base, rel, old, new):
    with ExitStack() as stack:
        parent = _parent(stack, journal.bases[base], rel)
        journal.change(base, parent, rel, old, new)
