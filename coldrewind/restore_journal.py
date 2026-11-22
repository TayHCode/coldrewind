"""Write-ahead undo records for filesystem changes made under the workspace lock."""

import ctypes
import errno
import hashlib
import json
import os
import secrets
import shutil
import stat
import sys
from contextlib import ExitStack, contextmanager

from . import snapshot

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
INTENT = "restore-intent.json"


class Conflict(Exception):
    def __init__(self, paths: list[str]) -> None:
        self.paths = paths
        super().__init__("workspace changed after the step: " + ", ".join(paths))


@contextmanager
def directory(parent, name):
    fd = os.open(name, DIR_FLAGS, dir_fd=parent)
    try:
        yield fd
    finally:
        os.close(fd)


def exclusive_move(src, source, dst, destination):
    # POSIX rename can overwrite a concurrent save, even after a fresh lstat.
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = getattr(libc, "renameatx_np", None)
        flag = 4  # RENAME_EXCL
    else:
        rename = getattr(libc, "renameat2", None)
        flag = 1  # RENAME_NOREPLACE
    if rename is None:
        raise OSError(errno.ENOTSUP, "filesystem requires exclusive rename support")
    if rename(src, os.fsencode(source), dst, os.fsencode(destination), flag):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)
    os.fsync(src)
    os.fsync(dst)


def info(parent, name):
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def matches(parent, name, entry):
    st = info(parent, name)
    if st is None or entry is None:
        return (st is None) == (entry is None)
    kind = entry["type"]
    if kind == "symlink":
        return stat.S_ISLNK(st.st_mode) and os.readlink(name, dir_fd=parent) == entry["target"]
    if stat.S_IMODE(st.st_mode) != entry["mode"]:
        return False
    if kind == "dir":
        return stat.S_ISDIR(st.st_mode)
    if not stat.S_ISREG(st.st_mode):
        return False
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(fd, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest() == entry["sha256"]


def identity(fd):
    st = os.fstat(fd)
    return [st.st_dev, st.st_ino]


class Journal:
    def __init__(self, store, bases, intent):
        self.store = store
        self.bases = bases
        self.intent = intent
        self.name = ".coldrewind-" + intent["nonce"]
        self.records = store / self.name
        self.count = 0

    @classmethod
    def begin(cls, store, bases, safety, target, previous_step):
        intent = dict(nonce=secrets.token_hex(16), safety=safety, target=target,
                      identity=[identity(fd) for fd in bases], previous_step=previous_step, staging={})
        journal = cls(store, bases, intent)
        if journal.records.exists() or any(info(fd, journal.name) for fd in bases):
            raise ValueError("restore staging path exists")
        snapshot._write(store, store / INTENT, json.dumps(intent).encode())
        journal.records.mkdir(mode=0o700)
        snapshot._fsync_dir(store)
        return journal

    def change(self, base, parent, rel, before, after):
        name = rel.split("/")[-1]
        if not matches(parent, name, before):
            raise Conflict([rel])
        base = self.intent["identity"].index(identity(self.bases[base]))
        if str(base) not in self.intent["staging"]:
            root = self.bases[base]
            self.intent["staging"][str(base)] = None
            self.save()
            try:
                os.mkdir(self.name, 0o700, dir_fd=root)
            except FileExistsError:
                del self.intent["staging"][str(base)]
                self.save()
                raise
            os.fsync(root)
            with directory(root, self.name) as fd:
                self.intent["staging"][str(base)] = identity(fd)
            self.save()
        self.count += 1
        with self.staging(base) as staging:
            number = str(self.count)
            os.mkdir(number, 0o700, dir_fd=staging)
            os.fsync(staging)
            with directory(staging, number) as slot:
                mode_change = before and after and before["type"] == after["type"] == "dir"
                if after and not mode_change:
                    self.prepare(slot, after)
                record = dict(base=base, path=rel, parent=identity(parent), before=before, after=after)
                if mode_change:
                    with directory(parent, name) as fd:
                        record["directory"] = identity(fd)
                        self.record(number, record)
                        if stat.S_IMODE(os.fstat(fd).st_mode) != before["mode"]:
                            raise Conflict([rel])
                        os.fchmod(fd, after["mode"])
                        os.fsync(fd)
                    return
                if after:
                    record["installed"] = info(slot, "new").st_ino
                self.record(number, record)
                if before:
                    try:
                        exclusive_move(parent, name, slot, "old")
                    except FileNotFoundError:
                        raise Conflict([rel]) from None
                    if not self.original_matches(slot, record):
                        raise Conflict([rel])
                if after:
                    try:
                        exclusive_move(slot, "new", parent, name)
                    except FileExistsError:
                        raise Conflict([rel]) from None

    def save(self):
        snapshot._write(self.store, self.store / INTENT, json.dumps(self.intent).encode())

    def record(self, number, record):
        snapshot._write(self.records, self.records / number, json.dumps(record).encode())

    @contextmanager
    def staging(self, base):
        with directory(self.bases[base], self.name) as fd:
            if identity(fd) != self.intent["staging"][str(base)]:
                raise ValueError("restore staging directory changed")
            yield fd

    def prepare(self, slot, entry):
        if entry["type"] == "symlink":
            os.symlink(entry["target"], "new", dir_fd=slot)
        elif entry["type"] == "dir":
            os.mkdir("new", 0o700, dir_fd=slot)
            with directory(slot, "new") as fd:
                os.fchmod(fd, entry["mode"])
                os.fsync(fd)
        else:
            fd = os.open("new", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=slot)
            with os.fdopen(fd, "wb") as out, (self.store / "blobs" / entry["sha256"]).open("rb") as source:
                shutil.copyfileobj(source, out)
                out.flush()
                os.fchmod(fd, entry["mode"])
                os.fsync(fd)

    @staticmethod
    def original_matches(slot, record):
        before = record["before"]
        if not matches(slot, "old", before):
            return False
        if before["type"] == "dir":
            with directory(slot, "old") as fd:
                children = os.listdir(fd)
                return not children or (record["path"].split("/")[-1] == "__pycache__" and
                                        all(n.endswith(".pyc") and stat.S_ISREG(info(fd, n).st_mode)
                                            for n in children))
        return True

    def visit(self, rollback):
        preserved = self.intent.setdefault("preserved", [])
        conflicts = [rel for _, rel in preserved]
        if not self.records.exists():
            if self.intent["staging"]:
                raise ValueError("restore records are missing")
            return conflicts
        paths = sorted((p for p in self.records.iterdir() if p.name.isdecimal()),
                       key=lambda path: int(path.name), reverse=True)
        for path in paths:
            record = json.loads(path.read_bytes())
            base = record["base"]
            record["number"] = path.name
            with self.staging(base) as staging, directory(staging, path.name) as slot:
                if rollback:
                    rel = record["path"]
                    if any(base == index and (rel == edited or rel.startswith(edited + "/"))
                           for index, edited in preserved):
                        self.keep_edited_original(slot, record)
                    elif not self.reverse(self.bases[base], slot, record):
                        preserved.append([base, rel])
                        conflicts.append(rel)
                        self.save()
                    path.unlink()
                    snapshot._fsync_dir(self.records)
                elif info(slot, "old") and not self.original_matches(slot, record):
                    raise Conflict([record["path"]])
        return conflicts

    def keep_edit(self, slot, source, record):
        base = record["base"]
        name = f".coldrewind-saved-{self.intent['nonce']}-{record['number']}-{source}"
        self.intent.setdefault("saved", {})[name] = base
        self.save()
        exclusive_move(slot, source, self.bases[base], name)

    def keep_edited_original(self, slot, record):
        if info(slot, "old") and not self.original_matches(slot, record):
            self.keep_edit(slot, "old", record)

    def reverse(self, root, slot, record):
        parts = record["path"].split("/")
        if any(p in ("", ".", "..") for p in parts) or ".git" in parts[:-1]:
            raise ValueError("invalid restore journal path")
        with ExitStack() as stack:
            parent = root
            try:
                for part in parts[:-1]:
                    parent = stack.enter_context(directory(parent, part))
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
                    raise
                parent = None
            if parent is None or identity(parent) != record["parent"]:
                if info(slot, "removed"):
                    self.keep_edit(slot, "removed", record)
                self.keep_edited_original(slot, record)
                return False
            name, after = parts[-1], record["after"]
            if "directory" in record:
                if matches(parent, name, record["before"]):
                    return True
                if not matches(parent, name, after):
                    return False
                with directory(parent, name) as fd:
                    if identity(fd) != record["directory"]:
                        return False
                    os.fchmod(fd, record["before"]["mode"])
                    os.fsync(fd)
                return True
            if after and not info(slot, "new") and not info(slot, "removed"):
                live = info(parent, name)
                if live is None or live.st_ino != record["installed"] or not matches(parent, name, after):
                    self.keep_edited_original(slot, record)
                    return False
                exclusive_move(parent, name, slot, "removed")
            if info(slot, "removed"):
                edited = info(slot, "removed").st_ino != record["installed"] or not matches(slot, "removed", after)
                if after["type"] == "dir" and not edited:
                    with directory(slot, "removed") as fd:
                        edited = bool(os.listdir(fd))
                if edited:
                    try:
                        exclusive_move(slot, "removed", parent, name)
                    except FileExistsError:
                        self.keep_edit(slot, "removed", record)
                    self.keep_edited_original(slot, record)
                    return False
            if info(slot, "old"):
                try:
                    exclusive_move(slot, "old", parent, name)
                except FileExistsError:
                    self.keep_edited_original(slot, record)
                    return False
            return True

    def finish(self):
        self.intent["finished"] = True
        self.save()
        self.clean()

    def clean(self):
        for index in self.intent["staging"]:
            base = int(index)
            root = self.bases[base]
            if info(root, self.name):
                if self.intent["staging"][index] is not None:
                    with self.staging(base) as staging:
                        for number in os.listdir(staging):
                            if not number.isdecimal():
                                raise ValueError("unexpected file in restore staging directory")
                            shutil.rmtree(number, dir_fd=staging)
                os.rmdir(self.name, dir_fd=root)
                os.fsync(root)
        if self.records.exists():
            shutil.rmtree(self.records)
        (self.store / INTENT).unlink()
        snapshot._fsync_dir(self.store)
