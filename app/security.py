from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque


class RateLimiter:
    """Simple in-memory sliding-window limiter (single process)."""

    def __init__(self, limit_per_minute: int) -> None:
        self.limit = max(1, limit_per_minute)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._last_cleanup = time.monotonic()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        window_start = now - 60.0
        hits = self._hits[key]
        while hits and hits[0] < window_start:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)

        if now - self._last_cleanup > 300:
            self._cleanup(now)
            self._last_cleanup = now
        return True

    def _cleanup(self, now: float) -> None:
        window_start = now - 60.0
        stale = [key for key, hits in self._hits.items() if not hits or hits[-1] < window_start]
        for key in stale:
            self._hits.pop(key, None)


def token_matches(expected: str, provided: str) -> bool:
    return hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))
