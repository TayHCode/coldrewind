import io
import unittest
from contextlib import redirect_stdout

from coldrewind import __version__
from coldrewind.cli import main


class TestSmoke(unittest.TestCase):
    def test_version_defined(self) -> None:
        self.assertEqual(__version__, "0.1.0")

    def test_cli_help_exits_zero(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main([])
        self.assertEqual(code, 0)
        self.assertIn("coldrewind", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
