"""Shared capacity accounting for interactive network terminal sessions."""

from __future__ import annotations

import asyncio


class InteractiveSessionLimiter:
    """A non-blocking ceiling shared by SSH and Telnet WebSocket bridges."""

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("interactive session limit must be positive")
        self.limit = limit
        self._active = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> int:
        return self._active

    async def try_acquire(self) -> bool:
        async with self._lock:
            if self._active >= self.limit:
                return False
            self._active += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            if self._active <= 0:
                raise RuntimeError("interactive session capacity released twice")
            self._active -= 1
