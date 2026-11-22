from pathlib import Path

from .paths import workspace_path

COMMON_FILES = ("packed-refs", "refs/stash", "logs/refs/stash")
PRIVATE_REFS = ("refs/bisect/", "refs/rewritten/", "refs/worktree/")


def is_private(name: str) -> bool:
    return name in ("HEAD", "index") or name.startswith(("sharedindex.", *PRIVATE_REFS))


def _read(base: Path, name: str) -> str:
    return workspace_path(base, name).read_text(encoding="utf-8").strip()


def git_dirs(root: Path) -> tuple[Path, Path] | None:
    dot_git = root / ".git"
    if dot_git.is_symlink():
        raise ValueError(".git must not be a symlink")
    if dot_git.is_dir():
        return dot_git, dot_git
    if not dot_git.is_file():
        return None

    text = dot_git.read_text(encoding="utf-8").strip()
    if not text.startswith("gitdir: "):
        raise ValueError(".git file has no gitdir line")
    gitdir = (root / text.removeprefix("gitdir: ")).resolve(strict=True)
    common = gitdir.parent.parent
    if (
        gitdir.parent.name != "worktrees"
        or (gitdir / _read(gitdir, "commondir")).resolve() != common
        or (gitdir / _read(gitdir, "gitdir")).resolve() != dot_git
    ):
        raise ValueError(".git file is not a linked worktree of its common Git directory")
    return gitdir, common


def git_files(root: Path) -> dict[str, Path]:
    dirs = git_dirs(root)
    if dirs is None:
        return {}
    gitdir, common = dirs
    wanted = {"HEAD": gitdir, "index": gitdir}
    wanted.update({path.name: gitdir for path in gitdir.glob("sharedindex.*")})
    wanted.update({name: common for name in COMMON_FILES})

    if workspace_path(gitdir, "HEAD").is_file():
        head = _read(gitdir, "HEAD")
        if head.startswith("ref: "):
            ref = head.removeprefix("ref: ")
            if not ref.startswith("refs/"):
                raise ValueError("HEAD names a ref outside refs/")
            wanted[ref] = gitdir if is_private(ref) else common

    for base in dict.fromkeys((gitdir, common)):
        refs = workspace_path(base, "refs")
        for path in refs.rglob("*") if refs.is_dir() else ():
            name = path.relative_to(base).as_posix()
            if gitdir != common and (base == gitdir) != is_private(name):
                continue
            if not path.name.endswith(".lock") and not path.is_symlink() and path.is_file():
                wanted[name] = base

    found = {}
    for name, base in wanted.items():
        path = workspace_path(base, name)
        if path.is_file():
            found[name] = path
    return found
