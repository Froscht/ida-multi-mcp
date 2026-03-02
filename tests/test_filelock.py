"""Tests for filelock.py — Cross-platform file locking."""

import os

import pytest

from ida_multi_mcp.filelock import FileLock, FileLockTimeout


class TestFileLock:
    def test_context_manager_acquire_release(self, tmp_path):
        lock_path = str(tmp_path / "test.lock")
        lock = FileLock(lock_path)
        with lock:
            assert lock._fd is not None
        assert lock._fd is None

    def test_creates_parent_dirs_and_lock_file(self, tmp_path):
        lock_path = str(tmp_path / "sub" / "dir" / "test.lock")
        with FileLock(lock_path):
            assert os.path.exists(lock_path)

    def test_timeout_raises(self, tmp_path):
        lock_path = str(tmp_path / "contended.lock")
        # Hold the lock from a separate fd
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)
        try:
            import sys
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            with pytest.raises(FileLockTimeout):
                FileLock(lock_path, timeout=0.1).acquire()
        finally:
            if sys.platform == "win32":
                try:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_release_without_acquire_is_noop(self, tmp_path):
        lock = FileLock(str(tmp_path / "noop.lock"))
        lock.release()  # Should not raise

    def test_reacquire_after_release(self, tmp_path):
        lock_path = str(tmp_path / "reacquire.lock")
        lock = FileLock(lock_path)
        lock.acquire()
        lock.release()
        lock.acquire()
        assert lock._fd is not None
        lock.release()
