import threading
import time
from collections import defaultdict, deque

from fastapi import Request

LOCALHOST = {"127.0.0.1", "::1", None}


class RateLimiter:
    """In-memory sliding window. Correct only with a single worker process."""

    def __init__(self, limit: int, window_seconds: int = 3600):
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, now: float | None = None) -> int | None:
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.limit:
                return max(1, int(self.window - (now - q[0])) + 1)
            q.append(now)
            return None


def client_ip(request: Request) -> str:
    peer = request.client.host if request.client else None
    if peer in LOCALHOST and (real := request.headers.get("x-real-ip")):
        return real
    return peer or "unknown"
