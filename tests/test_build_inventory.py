import tomllib
import unittest
from pathlib import Path


class BuildInventory(unittest.TestCase):
    def test_release_build_uses_locked_packages(self):
        root = Path(__file__).resolve().parents[1]
        with (root / "pylock.toml").open("rb") as stream:
            packages = tomllib.load(stream)["packages"]
        with (root / "pyproject.toml").open("rb") as stream:
            requires = tomllib.load(stream)["build-system"]["requires"]
        pins = {f"{package['name']}=={package['version']}" for package in packages}
        self.assertTrue(pins)
        self.assertTrue(set(requires) <= pins, (requires, pins))
