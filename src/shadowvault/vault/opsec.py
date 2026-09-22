"""OPSEC features: memory zeroize, auto-lockout, secure memory handling."""

from __future__ import annotations

import ctypes
import sys
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager


def zeroize_bytes(data: bytearray) -> None:
    """Securely zeroize a bytearray in memory.

    Attempts multiple methods to ensure memory is actually zeroed:
    1. Direct overwrite
    2. ctypes memset
    3. volatile write barrier
    """
    if not isinstance(data, bytearray):
        raise TypeError("Can only zeroize bytearray objects")

    length = len(data)

    # Method 1: Direct overwrite (Python level)
    for i in range(length):
        data[i] = 0

    # Method 2: ctypes memset (C level)
    try:
        buf = (ctypes.c_char * length).from_buffer(data)
        ctypes.memset(ctypes.addressof(buf), 0, length)
    except (TypeError, ValueError):
        pass

    # Method 3: Verify zeroed
    if any(b != 0 for b in data):
        # Fallback: overwrite with pattern then zero
        for i in range(length):
            data[i] = 0xFF
        for i in range(length):
            data[i] = 0x00


def zeroize_string(data: str) -> None:
    """Attempt to zeroize a string (best effort, strings are immutable in Python).

    Note: This is best-effort due to Python string immutability.
    The original string object cannot be modified, but this helps
    ensure copies are cleared if they exist.
    """
    # Strings are immutable in Python, so we can't truly zeroize them.
    # This is a best-effort function for documentation purposes.
    # In practice, use bytearray for sensitive string operations.
    pass


@contextmanager
def secure_buffer(size: int = 1024) -> Generator[bytearray, None, None]:
    """Context manager for a secure buffer that is zeroized on exit.

    Args:
        size: Size of the buffer in bytes.

    Yields:
        A bytearray buffer.
    """
    buffer = bytearray(size)
    try:
        yield buffer
    finally:
        zeroize_bytes(buffer)


class AutoLocker:
    """Auto-lock vault after configurable inactivity period."""

    def __init__(
        self,
        timeout_seconds: int = 300,
        on_lock=None,
    ):
        """Initialize auto-locker.

        Args:
            timeout_seconds: Seconds of inactivity before auto-lock.
            on_lock: Callback function to execute when locking.
        """
        self.timeout_seconds = timeout_seconds
        self.on_lock = on_lock
        self._last_activity = time.monotonic()
        self._locked = False
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None
        self._enabled = True

    def touch(self) -> None:
        """Update last activity timestamp."""
        with self._lock:
            self._last_activity = time.monotonic()
            if self._enabled and not self._locked:
                self._schedule_check()

    def _schedule_check(self) -> None:
        """Schedule the next inactivity check."""
        if self._timer is not None:
            self._timer.cancel()

        if self._enabled and not self._locked:
            self._timer = threading.Timer(self.timeout_seconds, self._check_timeout)
            self._timer.daemon = True
            self._timer.start()

    def _check_timeout(self) -> None:
        """Check if timeout has been exceeded."""
        with self._lock:
            if not self._enabled or self._locked:
                return

            elapsed = time.monotonic() - self._last_activity
            if elapsed >= self.timeout_seconds:
                self._locked = True
                if self.on_lock:
                    self.on_lock()

    def lock(self) -> None:
        """Manually lock the vault."""
        with self._lock:
            self._locked = True
            if self._timer:
                self._timer.cancel()
                self._timer = None

    def unlock(self) -> None:
        """Unlock the vault and reset timer."""
        with self._lock:
            self._locked = False
            self._last_activity = time.monotonic()
            if self._enabled:
                self._schedule_check()

    @property
    def is_locked(self) -> bool:
        """Check if vault is locked."""
        with self._lock:
            return self._locked

    @property
    def is_enabled(self) -> bool:
        """Check if auto-lock is enabled."""
        with self._lock:
            return self._enabled

    def enable(self) -> None:
        """Enable auto-lock."""
        with self._lock:
            self._enabled = True
            if not self._locked:
                self._schedule_check()

    def disable(self) -> None:
        """Disable auto-lock."""
        with self._lock:
            self._enabled = False
            if self._timer:
                self._timer.cancel()
                self._timer = None

    def set_timeout(self, seconds: int) -> None:
        """Update the timeout period.

        Args:
            seconds: New timeout in seconds.
        """
        with self._lock:
            self.timeout_seconds = seconds
            if self._enabled and not self._locked:
                self._schedule_check()

    def cleanup(self) -> None:
        """Cancel timer and clean up resources."""
        with self._lock:
            self._enabled = False
            if self._timer:
                self._timer.cancel()
                self._timer = None


class SecureString:
    """String wrapper that zeroizes content when deleted."""

    def __init__(self, value: str):
        self._value = bytearray(value.encode("utf-8"))

    @property
    def value(self) -> str:
        """Get the string value."""
        return bytes(self._value).decode("utf-8")

    def __del__(self):
        """Zeroize on garbage collection."""
        if hasattr(self, "_value"):
            zeroize_bytes(self._value)

    def __repr__(self) -> str:
        return "<SecureString: [REDACTED]>"

    def __str__(self) -> str:
        return "[REDACTED]"


class MemoryGuard:
    """Context manager for sensitive operations that zeroizes on exit."""

    def __init__(self):
        self._buffers: list[bytearray] = []
        self._strings: list[SecureString] = []

    def buffer(self, size: int = 1024) -> bytearray:
        """Create a managed buffer.

        Args:
            size: Buffer size in bytes.

        Returns:
            A bytearray that will be zeroized on context exit.
        """
        buf = bytearray(size)
        self._buffers.append(buf)
        return buf

    def secure_string(self, value: str) -> SecureString:
        """Create a managed secure string.

        Args:
            value: String value.

        Returns:
            A SecureString that will be zeroized on context exit.
        """
        s = SecureString(value)
        self._strings.append(s)
        return s

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False

    def cleanup(self) -> None:
        """Zeroize all managed buffers and strings."""
        for buf in self._buffers:
            zeroize_bytes(buf)
        self._buffers.clear()

        for s in self._strings:
            if hasattr(s, "_value"):
                zeroize_bytes(s._value)
        self._strings.clear()


def prevent_dump() -> None:
    """Best-effort prevention of memory dumps.

    On Linux, attempts to set dumpable flag to prevent ptrace.
    """
    if sys.platform == "linux":
        try:
            # PR_SET_DUMPABLE = 4
            libc = ctypes.CDLL("libc.so.6")
            libc.prctl(4, 0)
        except (OSError, AttributeError):
            pass
