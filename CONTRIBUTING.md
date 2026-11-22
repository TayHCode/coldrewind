# Contributing

Use Python 3.11 or newer and Git. From a checkout in an activated virtual
environment, run both suites.

```sh
python -m unittest discover -s tests -v
python -m unittest discover -s tests/installed -v
```

The second command builds the wheel, installs it in a fresh environment, and
exercises the installed CLI in disposable workspaces. Set `COLDREWIND_WHEEL` to
an existing wheel path to test that artifact.

When updating setuptools, update the build-system pin and regenerate
`pylock.toml` with the same version. The release scan uses that lock to check
the build dependency. Include the commands and results with your pull request.
