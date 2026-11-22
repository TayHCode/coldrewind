import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .paths import file_lock


class Registry:
    def __init__(self, state_dir: Path | None = None) -> None:
        if state_dir is None:
            state_home = Path(os.environ.get("XDG_STATE_HOME", ""))
            if not state_home.is_absolute():
                state_home = Path.home() / ".local" / "state"
            state_dir = state_home / "coldrewind"
        self.state_dir = state_dir.resolve()
        self.config_path = self.state_dir / "config.json"

    def _state_path(self, path: Path) -> Path:
        if path.resolve() != path:
            raise ValueError("ColdRewind state path contains a symlink")
        return path

    def _check_root(self, root: Path) -> None:
        if (
            not root.is_absolute()
            or self.state_dir.is_relative_to(root)
            or root.is_relative_to(self.state_dir)
        ):
            raise ValueError("watched roots and ColdRewind state must be disjoint")

    def roots(self) -> tuple[Path, ...]:
        try:
            data = json.loads(self._state_path(self.config_path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return ()
        if not isinstance(data, list) or any(
            not isinstance(root, str) or not Path(root).is_absolute() for root in data
        ):
            raise ValueError("registry must contain a list of absolute watched roots")
        roots = tuple(Path(root) for root in data)
        for root in roots:
            self._check_root(root.resolve())
        return roots

    def register(self, root: Path) -> Path:
        root = root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("watched root must be a directory")
        self._check_root(root)
        self.roots()
        self._state_path(self.state_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
        with file_lock(self.state_dir / "registry.lock"):
            roots = self.roots()
            if root not in roots:
                self._save((*roots, root))
        return root

    def _save(self, roots: tuple[Path, ...]) -> None:
        config_path = self._state_path(self.config_path)
        output = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.state_dir, delete=False
        )
        temporary = Path(output.name)
        try:
            with output:
                json.dump([str(root) for root in roots], output)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(config_path)
        finally:
            temporary.unlink(missing_ok=True)

    def store_path(self, root: Path) -> Path:
        root = root.resolve(strict=True)
        if root not in self.roots():
            raise ValueError("workspace is not registered")
        workspace_id = hashlib.sha256(os.fsencode(root)).hexdigest()
        return self._state_path(self.state_dir / "workspaces" / workspace_id)

    @contextmanager
    def workspace_lock(self, root: Path) -> Iterator[Path]:
        store = self.store_path(root)
        store.mkdir(mode=0o700, parents=True, exist_ok=True)
        with file_lock(store / "workspace.lock"):
            if (store / "restore-intent.json").exists():
                from .restore import recover_locked
                recover_locked(store, root.resolve(strict=True))
            yield store
