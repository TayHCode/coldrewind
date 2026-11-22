import difflib
from pathlib import Path

from .config import Registry
from .redact import redact_file, redact_text
from .snapshot import read_manifest


def diff(
    registry: Registry, root: Path, old_id: str, new_id: str, *, show_secrets: bool = False
) -> dict:
    with registry.workspace_lock(root) as store:
        blobs = store / "blobs"
        old = read_manifest(registry, root, old_id)
        new = read_manifest(registry, root, new_id)
        result = {"added": [], "deleted": [], "modified": [], "binary": [], "git": [], "patch": ""}
        patch: list[str] = []
        sections = (
            ("", old["files"], new["files"], result),
            (".git/", old["git"], new["git"], None),
        )
        for prefix, before, after, lists in sections:
            for rel in sorted(before.keys() | after.keys()):
                a, b = before.get(rel), after.get(rel)
                if a == b:
                    continue
                name = prefix + rel
                shown = name if show_secrets else redact_text(name)
                if lists is None:
                    result["git"].append(shown)
                else:
                    kind = "added" if a is None else "deleted" if b is None else "modified"
                    result[kind].append(shown)
                if not show_secrets and name.startswith(".git/logs/"):
                    continue
                texts = [_text(blobs, entry) for entry in (a, b)]
                if any(text is False for text in texts):
                    result["binary"].append(shown)
                    continue
                if not show_secrets:
                    texts = [redact_file(name, text) for text in texts]
                patch.extend(difflib.unified_diff(
                    texts[0].splitlines(keepends=True),
                    texts[1].splitlines(keepends=True),
                    "/dev/null" if a is None else f"a/{shown}",
                    "/dev/null" if b is None else f"b/{shown}",
                ))
        result["patch"] = "".join(line if line.endswith("\n") else line + "\n" for line in patch)
        return result


def _text(blobs: Path, entry: dict | None) -> str | bool:
    if entry is None or "sha256" not in entry:
        return ""
    data = (blobs / entry["sha256"]).read_bytes()
    if b"\0" in data:
        return False
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return False
