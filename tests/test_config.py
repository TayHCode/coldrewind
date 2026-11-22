import os
import select
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from coldrewind.config import Registry
from coldrewind.paths import is_ignored, workspace_path


class TestConfig(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.state = self.base / "state"
        self.registry = Registry(self.state)

    def test_registration_round_trip_creates_no_files_in_repo(self) -> None:
        (self.repo / ".env").write_text("TOKEN=synthetic\n")
        (self.repo / "untracked.bin").write_bytes(b"\x00")
        before = set(self.repo.rglob("*"))
        other = self.base / "other"
        other.mkdir()
        alias = self.base / "alias"
        alias.symlink_to(self.repo, target_is_directory=True)

        self.assertEqual(self.registry.register(self.repo), self.repo)
        self.assertEqual(self.registry.register(alias), self.repo)
        self.registry.register(other)

        reloaded = Registry(self.state)
        self.assertEqual(reloaded.roots(), (self.repo, other))
        with reloaded.workspace_lock(self.repo) as store:
            self.assertTrue(store.is_relative_to(self.state))
            self.assertEqual(store, self.registry.store_path(alias))
            self.assertNotEqual(store, reloaded.store_path(other))
            self.assertTrue((store / "workspace.lock").is_file())
        self.assertEqual(set(self.repo.rglob("*")), before)

    def test_default_location_is_local_state_home(self) -> None:
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(self.state)}):
            registry = Registry()
        registry.register(self.repo)
        self.assertEqual(Registry(self.state / "coldrewind").roots(), (self.repo,))

    def test_failed_replacement_preserves_config_and_cleans_temp_file(self) -> None:
        self.registry.register(self.repo)
        other = self.base / "other"
        other.mkdir()
        before = set(self.state.iterdir())

        with patch.object(Path, "replace", side_effect=OSError("replace failed")):
            with self.assertRaisesRegex(OSError, "replace failed"):
                self.registry.register(other)

        self.assertEqual(Registry(self.state).roots(), (self.repo,))
        self.assertEqual(set(self.state.iterdir()), before)

    def test_state_inside_watched_root_is_refused_before_writing(self) -> None:
        for state in (self.repo, self.repo / "state"):
            with self.subTest(state=state):
                with self.assertRaises(ValueError):
                    Registry(state).register(self.repo)
        self.assertEqual({path.name for path in self.repo.iterdir()}, {".git"})

    def test_symlinked_store_is_refused_before_writing(self) -> None:
        self.registry.register(self.repo)
        store = self.registry.store_path(self.repo)
        store.parent.mkdir()
        store.symlink_to(self.repo, target_is_directory=True)

        with self.assertRaises(ValueError), self.registry.workspace_lock(self.repo):
            self.fail("lock accepted a store that points into the watched repo")
        self.assertEqual({path.name for path in self.repo.iterdir()}, {".git"})

    def test_path_refuses_traversal_and_escaping_symlinks(self) -> None:
        outside = self.base / "repo-other"
        outside.mkdir()
        (self.repo / "escape").symlink_to(outside, target_is_directory=True)
        (self.repo / "dangling").symlink_to(outside / "missing")
        (self.repo / "safe").symlink_to(".git", target_is_directory=True)

        for path in (outside, "../repo-other", ".git/../file", "escape/file", "dangling"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                workspace_path(self.repo, path)
        self.assertEqual(workspace_path(self.repo, "safe/HEAD"), self.repo / "safe/HEAD")
        self.assertEqual(workspace_path(self.repo, "new"), self.repo / "new")

    def test_default_exclusion_preserves_user_files_and_separate_git_metadata(self) -> None:
        for path in (".env", "untracked.bin", ".git/HEAD", ".git/index", ".git/refs/stash"):
            with self.subTest(path=path):
                self.assertFalse(is_ignored(path))
        self.assertTrue(is_ignored(".git/objects"))
        self.assertTrue(is_ignored(".git/objects/pack/index"))

    def test_workspace_lock_serializes_processes(self) -> None:
        self.registry.register(self.repo)
        code = """
import sys
from pathlib import Path
from coldrewind.config import Registry

registry = Registry(Path(sys.argv[1]))
sys.stdin.readline()
print("ready", flush=True)
with registry.workspace_lock(Path(sys.argv[2])):
    print("acquired", flush=True)
"""
        with subprocess.Popen(
            [sys.executable, "-u", "-c", code, str(self.state), str(self.repo)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0,
        ) as child:
            try:
                with self.registry.workspace_lock(self.repo):
                    child.stdin.write(b"go\n")
                    child.stdin.flush()
                    self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                    self.assertEqual(child.stdout.readline(), b"ready\n")
                    self.assertFalse(select.select([child.stdout], [], [], 0.2)[0])
                output, _ = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 0)
                self.assertEqual(output, b"acquired\n")
            finally:
                if child.poll() is None:
                    child.kill()
