import hashlib
import json
import os
import shlex
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
from contextlib import closing
import venv
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]
SCHEMAS = json.loads((PROJECT / "docs/schemas/cli-v1.schema.json").read_text())["$defs"]
VERSION = tomllib.loads((PROJECT / "pyproject.toml").read_text())["project"]["version"]
TYPES = {"object": dict, "array": list, "string": str, "integer": int, "null": type(None)}
BLOCK_SOCKETS = """
import os
import sys

def forbid(event, args):
    if event.startswith("socket."):
        with open(os.environ["COLDREWIND_SOCKET_LOG"], "a") as log:
            log.write(event + "\\n")
        raise PermissionError("sockets blocked by CLI test")

sys.addaudithook(forbid)
"""


def fingerprint(root):
    entries = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if relative.startswith(".git/") and not (
            relative in (".git/HEAD", ".git/index", ".git/packed-refs") or relative.startswith(".git/refs/")
        ):
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            data = os.fsencode(os.readlink(path))
        elif stat.S_ISDIR(mode):
            data = b""
        else:
            data = path.read_bytes()
        entries[relative] = [mode, hashlib.sha256(data).hexdigest()]
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()


class InstalledCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.install = Path(cls.enterClassContext(tempfile.TemporaryDirectory())).resolve()
        if "COLDREWIND_WHEEL" in os.environ:
            wheel = Path(os.environ["COLDREWIND_WHEEL"]).resolve(strict=True)
        else:
            subprocess.run(
                [sys.executable, "-m", "pip", "wheel", "--no-deps",
                 "--wheel-dir", str(cls.install), str(PROJECT)],
                check=True, cwd=cls.install,
            )
            wheel, = cls.install.glob("coldrewind-*.whl")
        if wheel.suffix != ".whl":
            raise ValueError("COLDREWIND_WHEEL must point to a built wheel")
        venv.create(cls.install, with_pip=True)
        cls.python = cls.install / "bin/python"
        cls.executable = cls.install / "bin/coldrewind"
        subprocess.run(
            [cls.python, "-Im", "pip", "--isolated", "install", "--no-index",
             "--no-deps", "--disable-pip-version-check", wheel],
            check=True, cwd=cls.install,
        )
        site = Path(subprocess.check_output(
            [cls.python, "-Ic", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            text=True, cwd=cls.install,
        ).strip())
        (site / "_block_cli_sockets.py").write_text(BLOCK_SOCKETS)
        (site / "_block_cli_sockets.pth").write_text("import _block_cli_sockets\n")

    def setUp(self):
        base = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.root = base / "workspace"
        self.home = base / "home"
        self.home.mkdir()
        self.root.mkdir()
        self.attempts = base / "socket-attempts"
        self.attempts.touch()
        self.env = {
            "HOME": str(self.home),
            "PATH": os.environ["PATH"],
            "GIT_CONFIG_NOSYSTEM": "1",
            "COLDREWIND_SOCKET_LOG": str(self.attempts),
        }
        self.launch(["git", "init", "-q"]).check_returncode()

    def tearDown(self):
        self.assertEqual(self.attempts.read_text(), "", "unexpected socket operation")

    def launch(self, argv, *, stdin=None, cwd=None):
        return subprocess.run(
            argv, cwd=cwd or self.root, env=self.env, input=stdin,
            text=True, capture_output=True, timeout=20,
        )

    def cli(self, *args, code=0, stdin=None, cwd=None):
        result = self.launch([self.executable, *args], stdin=stdin, cwd=cwd)
        self.assertEqual(result.returncode, code, (args, result.stdout, result.stderr))
        return result

    def test_installed_recovery_journey(self):
        root, home = self.root, self.home
        secret_before = "ghp_" + "A" * 36
        secret_after = "ghp_" + "B" * 36

        def invoke(argv, *, stdin=None, code=0):
            result = self.launch(argv, stdin=stdin)
            for secret in (secret_before, secret_after):
                if secret in result.stdout or secret in result.stderr:
                    self.fail("synthetic token exposed in command output")
            self.assertEqual(result.returncode, code, result.stderr)
            self.assertEqual(result.stderr, "")
            return result.stdout

        def crw(*args, code=0):
            return json.loads(invoke([self.executable, *args, "--json"], code=code))

        def git(*args):
            invoke(["git", *args])

        git("symbolic-ref", "HEAD", "refs/heads/main")
        git("config", "user.name", "Lab Fixture")
        git("config", "user.email", "fixture")
        note = root / "note"
        note.write_text("first commit\n")
        git("add", "note")
        git("commit", "-qm", "first")
        note.write_text("second commit\n")
        binary = root / "asset.bin"
        binary.write_bytes(bytes(range(256)))
        git("add", "note", "asset.bin")
        git("commit", "-qm", "second")
        note.write_text("staged edit\n")
        git("add", "note")
        note.write_text("unstaged edit\n")
        (root / "scratch.txt").write_bytes(b"untracked\n")
        (root / "link").symlink_to("note")
        with closing(sqlite3.connect(root / "local.db")) as db:
            db.execute("CREATE TABLE items (value TEXT)")
            db.execute("INSERT INTO items VALUES ('before')")
            db.commit()
        (root / ".env").write_text(f"LAB_TOKEN={secret_before}\n")

        claude = home / ".claude/settings.json"
        codex = home / ".codex/hooks.json"
        other = home / ".config/opencode/plugins/other.js"
        configs = {
            claude: {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "true"}]}]}},
            codex: {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": "true"}]}]}},
        }
        for path, data in configs.items():
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(data, indent=2) + "\n")
        other.parent.mkdir(parents=True)
        other.write_bytes(b"export const Other = async () => ({})\n")
        original_configs = {path: path.read_bytes() for path in (*configs, other)}
        plugin = other.with_name("coldrewind.js")

        crw("init")
        self.assertTrue(plugin.is_file())
        crw("status")
        states = [fingerprint(root)]

        def simulate(client, command, call_id):
            event = json.dumps({"cwd": str(root), "tool_use_id": call_id, "session_id": "lab",
                                "tool_name": "Bash", "tool_input": {"command": command}})
            for phase, name in (("pre", "PreToolUse"), ("post", "PostToolUse")):
                if client == "opencode":
                    handler = [self.executable, "hook", client, phase]
                else:
                    config = claude if client == "claude" else codex
                    hook = json.loads(config.read_text())["hooks"][name][-1]["hooks"][0]
                    handler = shlex.split(hook["command"])
                invoke(handler, stdin=event)
                if phase == "pre":
                    invoke(["bash", "-c", command])
            states.append(fingerprint(root))

        hook_damage = (
            "git reset --hard -q HEAD~1 && "
            "rm -f scratch.txt && printf 'hook overwrite\\n' > note && "
            "printf 'broken sqlite\\n' > local.db && "
            'printf "HOOK_TOKEN=%s\\n" "$(cat ../synthetic-value)" > .env'
        )
        (root.parent / "synthetic-value").write_text(secret_after)
        simulate("claude", hook_damage, "call-1")
        self.assertFalse(binary.exists())
        self.assertFalse((root / "scratch.txt").exists())
        simulate("codex", "echo codex >> note", "call-2")
        simulate("opencode", "echo opencode >> note", "call-3")
        wrapper_damage = (
            "rm -f local.db link && printf 'wrapper overwrite\\n' > note && "
            "git checkout --detach -q && git add note && "
            'printf "RUN_TOKEN=%s\\n" "$(cat ../synthetic-value)" > .env'
        )
        invoke([self.executable, "run", "--", "bash", "-c", wrapper_damage])
        self.assertFalse((root / "local.db").exists())
        self.assertFalse((root / "link").is_symlink())
        states.append(fingerprint(root))
        self.assertEqual(len(set(states)), 5)

        steps = crw("log")["steps"]
        self.assertEqual([s["agent"] for s in steps], ["Claude Code", "Codex", "OpenCode", "run"])
        ids = [str(step["step_id"]) for step in steps]
        for step_id, deleted in ((ids[0], "scratch.txt"), (ids[-1], "local.db")):
            changes = crw("diff", step_id)
            self.assertIn(".env", changes["modified"])
            self.assertIn("[REDACTED]", changes["patch"])
            self.assertIn("note", changes["modified"])
            self.assertIn(deleted, changes["deleted"])
            self.assertTrue({".git/HEAD", ".git/index", ".git/refs/heads/main"} & set(changes["git"]))

        undo_ids = []
        for step_id, expected in reversed(list(zip(ids, states[:-1], strict=True))):
            undo_ids.append(str(crw("undo", step_id)["step"]["step_id"]))
            self.assertEqual(fingerprint(root), expected, f"undo {step_id}")
        for undo_id, expected in zip(reversed(undo_ids), states[1:], strict=True):
            crw("redo", undo_id)
            self.assertEqual(fingerprint(root), expected, f"redo {undo_id}")

        note.write_text("later edit")
        later = fingerprint(root)
        self.assertEqual(crw("undo", ids[-1], code=1)["reason"], "conflict")
        self.assertEqual(fingerprint(root), later)
        crw("undo", "--force", ids[-1])
        self.assertEqual(fingerprint(root), states[-2])
        crw("redo")
        self.assertEqual(fingerprint(root), later)

        store = self.store
        oldest_id = steps[0]["pre_snapshot_id"]
        oldest = store / "snapshots" / (oldest_id + ".json")
        age = time.time() - 8 * 86400
        os.utime(oldest, (age, age))
        self.assertIn(oldest_id, crw("prune")["pruned"])
        self.assertFalse(oldest.exists())
        stored = fingerprint(store)
        self.assertEqual(crw("undo", "--force", ids[0], code=1)["reason"], "pruned_snapshots")
        self.assertEqual(fingerprint(root), later)
        self.assertEqual(fingerprint(store), stored)

        crw("uninstall")
        self.assertFalse(plugin.exists())
        for path, original in original_configs.items():
            self.assertEqual(path.read_bytes(), original)
        self.assertEqual(fingerprint(root), later)

    def as_json(self, name, *args, cwd=None):
        result = self.cli(name, "--json", *args, cwd=cwd)
        self.assertEqual(result.stderr, "")
        data = json.loads(result.stdout)
        self.assertIs(type(data["schema_version"]), int)
        self.assertEqual(data["schema_version"], 1)
        self.assert_schema(data, SCHEMAS[name])
        return data

    def assert_error(self, result, reason, message):
        self.assertEqual(result.stderr, "")
        data = json.loads(result.stdout)
        self.assert_schema(data, SCHEMAS["error"])
        self.assertEqual(data["reason"], reason)
        self.assertIn(message, data["message"])

    def assert_schema(self, value, schema):
        if "$ref" in schema:
            self.assert_schema(value, SCHEMAS[schema["$ref"].removeprefix("#/$defs/")])
        if "type" in schema:
            types = schema["type"]
            if isinstance(types, str):
                types = [types]
            self.assertIn(type(value), [TYPES[kind] for kind in types])
        if "const" in schema:
            self.assertEqual(value, schema["const"])
        if "enum" in schema:
            self.assertIn(value, schema["enum"])
        if "minimum" in schema:
            self.assertGreaterEqual(value, schema["minimum"])
        if "properties" in schema:
            self.assertEqual(set(value), set(schema["required"]))
            for key, member in schema["properties"].items():
                with self.subTest(field=key):
                    self.assert_schema(value[key], member)
        if "items" in schema:
            for member in value:
                self.assert_schema(member, schema["items"])

    def write_step(self, text):
        self.cli("run", "--", "sh", "-c", 'printf "%s\\n" "$1" > note', "sh", text)

    @property
    def store(self):
        state = self.home / ".local/state/coldrewind/workspaces"
        [store] = state.iterdir()
        return store

    def age_manifests(self):
        now = time.time() - 8 * 24 * 60 * 60
        for offset, path in enumerate(sorted(
            (self.store / "snapshots").glob("*.json"), key=lambda path: path.stat().st_mtime_ns
        )):
            os.utime(path, (now + offset, now + offset))

    def test_denial_releases_only_the_matching_pending_call(self):
        self.cli("init", "--client", "claude")
        config = json.loads((self.home / ".claude/settings.json").read_text())["hooks"]
        payload = dict(session_id="session-a", tool_use_id="call-a", tool_name="Write",
                       cwd=str(self.root))

        def fire(event, **fields):
            handler = config[event][0]["hooks"][0]["command"]
            data = {**payload, "hook_event_name": event, **fields}
            result = self.launch(shlex.split(handler), stdin=json.dumps(data))
            self.assertEqual((result.returncode, result.stderr), (0, ""))

        fire("PreToolUse")
        marker, = (self.store / "pending").iterdir()
        self.write_step("independent edit")
        refusal = self.cli("undo", "1", code=1)
        self.assertIn(marker.name, refusal.stderr)
        self.assertIn("hook pin expiry", refusal.stderr)
        self.assertEqual((self.root / "note").read_text(), "independent edit\n")
        fire("PermissionDenied", session_id="session-b")
        fire("PermissionDenied", tool_use_id="call-b")
        self.assertIn(marker.name, self.cli("undo", "1", "--force", code=1).stderr)
        self.assert_error(
            self.cli("undo", "1", "--force", "--json", code=1), "ambiguous_restore", marker.name,
        )
        fire("PermissionDenied")
        fire("PermissionDenied")
        self.assertFalse(marker.exists())
        self.cli("undo", "1")
        self.assertFalse((self.root / "note").exists())

    def test_socket_guard_detects_even_a_caught_attempt(self):
        probe = self.launch([
            self.python, "-Ic", """
import coldrewind
import socket
import sys
from pathlib import Path

assert Path(coldrewind.__file__).is_relative_to(sys.prefix)
try:
    socket.socket()
except PermissionError as error:
    assert str(error) == "sockets blocked by CLI test"
else:
    raise AssertionError("socket creation was allowed")
""",
        ])
        self.assertEqual(probe.returncode, 0, probe.stderr)
        attempts = self.attempts.read_text()
        self.attempts.write_text("")
        self.assertEqual(attempts, "socket.__new__\n")

    def test_installed_lifecycle(self):
        self.assertEqual(self.cli("--version").stdout, f"coldrewind {VERSION}\n")
        updated = self.as_json("init")["updated"]
        self.assertEqual(len(updated), 6)
        self.assertTrue(all(Path(path).is_file() for path in updated))
        status = self.as_json("status")
        self.assertIsNone(status["backend"])
        self.assertIsNone(status["last_capture_error"])
        self.assertEqual(self.as_json("log")["steps"], [])
        note = self.root / "note"
        note.write_text("before\n")
        self.write_step("after")
        self.assertIsNotNone(self.as_json("status")["backend"])
        self.assertEqual(self.as_json("diff", "1")["modified"], ["note"])
        self.assertIn("-before\n+after\n", self.cli("diff", "1").stdout)
        self.assertEqual(self.as_json("undo")["step"]["command"], ["coldrewind", "undo", "1"])
        self.assertEqual(note.read_text(), "before\n")
        self.assertEqual(self.as_json("redo")["step"]["command"], ["coldrewind", "redo", "2"])
        self.assertEqual(note.read_text(), "after\n")

        event = json.dumps({"cwd": str(self.root), "tool_use_id": "edit1", "tool_name": "Edit"})
        config = json.loads((self.home / ".claude/settings.json").read_text())
        for phase in ("PreToolUse", "PostToolUse"):
            command = config["hooks"][phase][0]["hooks"][0]["command"]
            result = self.launch(shlex.split(command), stdin=event)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
            if phase == "PreToolUse":
                note.write_text("hooked\n")

        steps = self.as_json("log")["steps"]
        self.assertEqual([step["agent"] for step in steps], ["run", "coldrewind", "coldrewind", "Claude Code"])
        self.assertEqual(steps[-1]["changed_paths"], ["note"])
        self.assertEqual(self.as_json("prune")["pruned"], [])
        self.assertEqual(self.as_json("uninstall")["updated"], updated)
        self.assertEqual(self.as_json("uninstall")["updated"], [])
        self.assertEqual(self.as_json("log")["steps"], steps)

    def test_status_reports_a_fail_open_capture_error_for_its_workspace(self):
        self.as_json("init", "--client", "claude")
        self.write_step("one")
        pending = self.store / "pending"
        pending.rmdir()
        pending.symlink_to(self.home, target_is_directory=True)
        event = json.dumps({"cwd": str(self.root), "tool_use_id": "edit", "tool_name": "Edit"})
        result = self.cli("hook", "claude", "pre", stdin=event)
        self.assertEqual(result.stdout, "")
        self.assertIn("ColdRewind store directory is not a real directory", result.stderr)
        status = self.as_json("status")
        self.assertIsNotNone(status["backend"])
        self.assertEqual(status["last_capture_error"], "Hook capture failed")

        other = self.root.parent / "other"
        other.mkdir()
        self.as_json("init", "--client", "claude", cwd=other)
        self.assertIsNone(self.as_json("status", cwd=other)["last_capture_error"])

    def test_exit_codes(self):
        result = self.cli("status", "--json", code=2)
        self.assert_error(result, "unregistered_workspace", "outside registered workspaces")
        self.assertEqual(
            self.cli("status", code=2).stderr,
            "coldrewind status: current directory is outside registered workspaces\n",
        )
        self.cli("run", "--", "true", code=2)
        self.as_json("init", "--client", "claude")
        for verb in ("undo", "redo"):
            result = self.cli(verb, "--json", code=1)
            self.assert_error(result, "nothing_to_restore", f"to {verb}")
        for verb in ("diff", "undo"):
            result = self.cli(verb, "999", "--json", code=2)
            self.assert_error(result, "local_error", "no step 999")
        self.assert_error(self.cli("diff", "--json", code=2), "usage", "required")
        self.assert_error(self.cli("undo", "bad", "--json", code=2), "usage", "invalid int")
        self.cli("diff", code=2)
        result = self.cli("run", "--", "sh", "-c", "printf child; printf error >&2; exit 37", code=37)
        self.assertEqual((result.stdout, result.stderr), ("child", "error"))
        self.cli("run", "--", "sh", "-c", "kill -TERM $$", code=128 + signal.SIGTERM)
        self.cli("run", "true", code=2)
        result = self.cli("hook", "codex", "pre", stdin="{")
        self.assertEqual(result.stdout, "")
        self.assertIn("coldrewind hook:", result.stderr)
        self.cli("hook", "codex", "invalid", code=2)

        self.write_step("one")
        note = self.root / "note"
        note.write_text("human\n")
        result = self.cli("undo", "--json", code=1)
        self.assert_error(result, "conflict", "workspace changed")
        self.assertEqual(note.read_text(), "human\n")
        self.as_json("undo", "--force")
        self.assertFalse(note.exists())
        self.as_json("redo")
        self.assertEqual(note.read_text(), "human\n")

        event = json.dumps({"cwd": str(self.root), "tool_use_id": "no-pre", "tool_name": "Edit"})
        self.cli("hook", "codex", "post", stdin=event)
        step = self.as_json("log")["steps"][-1]
        self.assertIsNone(step["pre_snapshot_id"])
        for verb in ("diff", "undo"):
            result = self.cli(verb, "--json", str(step["step_id"]), code=2)
            self.assert_error(result, "local_error", "step has no snapshots")

    def test_pruned_undo_refuses_without_writes(self):
        self.as_json("init")
        for text in ("one", "two", "three"):
            self.write_step(text)
        first = self.as_json("log")["steps"][0]
        self.age_manifests()
        self.assertIn(first["pre_snapshot_id"], self.as_json("prune")["pruned"])
        self.assert_pruned_without_writes("1")

        last = self.as_json("log")["steps"][-1]
        (self.store / "snapshots" / f'{last["post_snapshot_id"]}.json').unlink()
        self.assert_pruned_without_writes(str(last["step_id"]))

    def assert_pruned_without_writes(self, step_id):
        def files():
            return {
                path: (path.stat().st_mtime_ns, path.read_bytes())
                for directory in (self.root, self.store)
                for path in directory.rglob("*") if path.is_file()
            }

        before = files()
        result = self.cli("undo", "--json", "--force", step_id, code=1)
        self.assert_error(
            result, "pruned_snapshots", "step snapshots are no longer available and may have been pruned",
        )
        self.assertEqual(
            self.cli("undo", "--force", step_id, code=1).stderr,
            "coldrewind undo: step snapshots are no longer available and may have been pruned\n",
        )
        self.assertEqual(files(), before)

    def test_whole_store_retention(self):
        self.as_json("init")
        cap = 64 * 1024
        self.env.update(COLDREWIND_MAX_BYTES=str(cap), COLDREWIND_MAX_AGE_SECONDS="60")
        for index in range(20):
            self.write_step(str(index) + "x" * 4096)
            measured = sum(path.stat().st_size for path in self.store.rglob("*") if path.is_file())
            self.assertLessEqual(measured, cap)
        rows = self.as_json("log")["steps"]
        latest = rows[-1]
        self.assertEqual(latest["step_id"], 20)
        database = self.store / "timeline.sqlite3"
        with closing(sqlite3.connect(database)) as db, db:
            db.execute("UPDATE steps SET timestamp = '2000-01-01T00:00:00+00:00' WHERE step_id < 19")
        self.age_manifests()
        pending = self.store / "pending"
        current = pending / ("1" * 64)
        abandoned = pending / ("0" * 64)
        for marker in (current, abandoned):
            marker.write_text(latest["pre_snapshot_id"])
        os.utime(abandoned, (1, 1))
        report = self.as_json("prune")
        measured = sum(path.stat().st_size for path in self.store.rglob("*") if path.is_file())
        self.assertEqual(report["total_bytes"], measured)
        self.assertLessEqual(measured, cap)
        protected = set()
        for key in ("pre_snapshot_id", "post_snapshot_id"):
            sid = latest[key]
            manifest = self.store / "snapshots" / f"{sid}.json"
            protected.update((manifest, manifest.with_suffix(".backend")))
            doc = json.loads(manifest.read_bytes())
            for entry in (*doc["files"].values(), *doc["git"].values()):
                if "sha256" in entry:
                    protected.add(self.store / "blobs" / entry["sha256"])
        pinned = sum(path.stat().st_size for path in protected)
        self.assertEqual(report["protected_bytes"], pinned)
        self.assertEqual([s["step_id"] for s in self.as_json("log")["steps"]], [19, 20])
        self.assertEqual(list(pending.iterdir()), [current])
        self.assertEqual(self.as_json("prune"), {**report, "pruned": []})
        print(f"20 CLI mutations, cap={cap}, age=60s, measured/reported={measured}/{report['total_bytes']}, "
              f"protected measured/reported={pinned}/{report['protected_bytes']}, steps=19,20, "
              "active markers=1, expired markers=0")

    def test_redo_survives_retention_after_later_steps(self):
        self.as_json("init")
        self.write_step("one")
        self.write_step("two")
        undone = self.as_json("undo")["step"]
        for text in ("three", "four", "five"):
            self.write_step(text)
        self.age_manifests()
        self.assertTrue(self.as_json("prune")["pruned"])
        for key in ("pre_snapshot_id", "post_snapshot_id"):
            self.assertTrue((self.store / "snapshots" / f"{undone[key]}.json").is_file())
        self.cli("redo", "--json", code=1)
        self.as_json("redo", "--force")
        self.assertEqual((self.root / "note").read_text(), "two\n")

    def test_installed_guard_and_new_clients_end_to_end(self):
        self.launch(["git", "config", "user.name", "Lab Fixture"]).check_returncode()
        self.launch(["git", "config", "user.email", "fixture"]).check_returncode()
        note = self.root / "note.txt"
        note.write_text("committed\n")
        self.launch(["git", "add", "note.txt"]).check_returncode()
        self.launch(["git", "commit", "-qm", "base"]).check_returncode()

        self.as_json("init", "--client", "cursor", "--client", "antigravity", "--client", "gemini")
        # Baseline snapshot, then edit uncommitted work under an aggressive throttle.
        self.write_step("baseline")
        note.write_text("precious uncommitted\n")
        (self.root / "untracked.txt").write_text("do not lose\n")
        self.env["COLDREWIND_SNAPSHOT_MIN_INTERVAL_SECONDS"] = "3600"

        cursor_cfg = json.loads((self.home / ".cursor/hooks.json").read_text())
        cursor_pre = shlex.split(cursor_cfg["hooks"]["preToolUse"][0]["command"])
        cursor_post = shlex.split(cursor_cfg["hooks"]["postToolUse"][0]["command"])
        event = json.dumps({
            "cwd": str(self.root), "conversation_id": "conv", "tool_use_id": "wipe-1",
            "tool_name": "Shell", "tool_input": {"command": "git reset --hard && git clean -fdx"},
        })
        pre = self.launch(cursor_pre, stdin=event)
        self.assertEqual((pre.returncode, pre.stderr), (0, ""))
        self.assertEqual(json.loads(pre.stdout), {"permission": "allow"})

        self.launch(["bash", "-c", "git reset --hard && git clean -fdx"]).check_returncode()
        self.assertEqual(note.read_text(), "committed\n")
        self.assertFalse((self.root / "untracked.txt").exists())

        post = self.launch(cursor_post, stdin=event)
        self.assertEqual((post.returncode, post.stderr), (0, ""))

        self.as_json("undo")
        self.assertEqual(note.read_text(), "precious uncommitted\n")
        self.assertEqual((self.root / "untracked.txt").read_text(), "do not lose\n")

        # Strict block mode denies via Antigravity (exit 0 + decision=deny) and Gemini CLI (exit 2 + decision=deny).
        self.env["COLDREWIND_GUARD"] = "block"
        ag_cfg = json.loads((self.home / ".gemini/config/hooks.json").read_text())
        ag_pre = shlex.split(ag_cfg["coldrewind"]["PreToolUse"][0]["hooks"][0]["command"])
        ag_res = self.launch(ag_pre, stdin=json.dumps({
            "cwd": str(self.root), "conversationId": "c-ag",
            "toolCall": {"id": "t1", "name": "run_command", "args": {"CommandLine": "rm -rf ."}},
        }))
        self.assertEqual(ag_res.returncode, 0)
        self.assertEqual(json.loads(ag_res.stdout)["decision"], "deny")

        gem_cfg = json.loads((self.home / ".gemini/settings.json").read_text())
        gem_pre = shlex.split(gem_cfg["hooks"]["BeforeTool"][0]["hooks"][0]["command"])
        gem_res = self.launch(gem_pre, stdin=json.dumps({
            "cwd": str(self.root), "session_id": "s-gem",
            "tool_name": "run_shell_command", "tool_input": {"command": "git checkout -- ."},
        }))
        self.assertEqual(gem_res.returncode, 2)
        self.assertEqual(json.loads(gem_res.stdout)["decision"], "deny")

        self.as_json("uninstall", "--client", "cursor", "--client", "antigravity", "--client", "gemini")
