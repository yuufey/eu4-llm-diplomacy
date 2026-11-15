"""Cross-owner collection lock for one SQLite database."""

from __future__ import annotations

import errno
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path


_BUSY_ERRNOS = {
    errno.EACCES,
    errno.EAGAIN,
    getattr(errno, "EDEADLK", -1),
}


def _is_lock_busy(error: OSError) -> bool:
    return error.errno in _BUSY_ERRNOS or getattr(error, "winerror", None) == 33


class CollectionLock:
    """Serialize source collection for a database across threads and processes.

    Each instance is reentrant for its owning thread. File-backed databases
    also use a persistent adjacent lock file so separate instances and
    processes coordinate through the operating system.
    """

    _registry_guard = threading.Lock()
    _process_locks: dict[str, threading.Lock] = {}

    def __init__(self, database: os.PathLike[str] | str):
        self._thread_lock = threading.RLock()
        self._local = threading.local()
        self._memory_database = os.fspath(database) == ":memory:"

        if self._memory_database:
            self._lock_path: Path | None = None
            self._process_lock = None
            return

        database_path = Path(database).expanduser().resolve()
        self._lock_path = database_path.with_name(
            database_path.name + ".collection.lock"
        )
        registry_key = os.path.normcase(str(self._lock_path))
        with self._registry_guard:
            self._process_lock = self._process_locks.setdefault(
                registry_key, threading.Lock()
            )

    @contextmanager
    def acquire(self, blocking: bool = True):
        """Acquire the lock and yield whether acquisition succeeded."""

        if not isinstance(blocking, bool):
            raise TypeError("blocking must be a bool")

        if not self._thread_lock.acquire(blocking):
            yield False
            return

        depth = getattr(self._local, "depth", 0)
        if depth:
            self._local.depth = depth + 1
            try:
                yield True
            finally:
                self._local.depth = depth
                self._thread_lock.release()
            return

        process_lock_acquired = False
        lock_file = None
        os_lock_acquired = False
        try:
            if self._lock_path is not None:
                assert self._process_lock is not None
                process_lock_acquired = self._process_lock.acquire(blocking)
                if not process_lock_acquired:
                    yield False
                    return

                # a+b creates the file without truncating an existing lock.
                lock_file = open(self._lock_path, "a+b")
                if os.fstat(lock_file.fileno()).st_size == 0:
                    lock_file.seek(0, os.SEEK_END)
                    lock_file.write(b"\0")
                    lock_file.flush()

                os_lock_acquired = self._acquire_file_lock(lock_file, blocking)
                if not os_lock_acquired:
                    yield False
                    return

            self._local.depth = 1
            try:
                yield True
            finally:
                del self._local.depth
        finally:
            try:
                if lock_file is not None:
                    try:
                        if os_lock_acquired:
                            self._release_file_lock(lock_file)
                    finally:
                        lock_file.close()
            finally:
                try:
                    if process_lock_acquired:
                        assert self._process_lock is not None
                        self._process_lock.release()
                finally:
                    self._thread_lock.release()

    @staticmethod
    def _acquire_file_lock(lock_file, blocking: bool) -> bool:
        if os.name == "nt":
            import msvcrt

            while True:
                try:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                    return True
                except OSError as error:
                    if not _is_lock_busy(error):
                        raise
                    if not blocking:
                        return False
                    time.sleep(0.02)

        import fcntl

        flags = fcntl.LOCK_EX
        if not blocking:
            flags |= fcntl.LOCK_NB
        try:
            fcntl.flock(lock_file.fileno(), flags)
            return True
        except OSError as error:
            if not _is_lock_busy(error):
                raise
            if not blocking:
                return False
            raise

    @staticmethod
    def _release_file_lock(lock_file) -> None:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            return

        import fcntl

        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
