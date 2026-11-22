import errno
import fcntl
import os
import stat
import sys
import tempfile
from pathlib import Path

FICLONE = 0x40049409
CLONE_NOOWNERCOPY = 0x0002
UNSUPPORTED = {errno.EINVAL, errno.ENOSYS, errno.ENOTSUP, errno.ENOTTY, errno.EXDEV}

if sys.platform == "darwin":
    import ctypes

    _fclonefileat = ctypes.CDLL(None, use_errno=True).fclonefileat
    _fclonefileat.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32)
    _fclonefileat.restype = ctypes.c_int


def _clone_apfs(source: int, target: Path) -> None:
    flags = os.fstat(source).st_flags
    if flags & (stat.UF_IMMUTABLE | stat.UF_APPEND | stat.SF_IMMUTABLE | stat.SF_APPEND):
        raise OSError(errno.ENOTSUP, "source flags would prevent blob cleanup")
    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".tmp-") as staging:
        directory = os.open(staging, os.O_RDONLY | os.O_DIRECTORY)
        try:
            if _fclonefileat(source, directory, b"blob", CLONE_NOOWNERCOPY):
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            clone = Path(staging) / "blob"
            clone.chmod(0o600)
            clone.replace(target)
        finally:
            os.close(directory)


def clone(source: int, destination: int, target: Path) -> bool:
    try:
        if sys.platform == "linux":
            fcntl.ioctl(destination, FICLONE, source)
            return True
        if sys.platform == "darwin":
            _clone_apfs(source, target)
            return True
    except OSError as error:
        if error.errno not in UNSUPPORTED:
            raise
    return False
