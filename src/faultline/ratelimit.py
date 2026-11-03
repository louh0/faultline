from __future__ import annotations

import threading
import time
from typing import Callable


class TokenBucketLimiter:
    def __init__(
        self,
        rate_per_sec: float,
        burst: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be positive")
        self.rate_per_sec = float(rate_per_sec)
        self.capacity = float(burst if burst is not None and burst > 0 else max(1.0, rate_per_sec))
        self._tokens = self.capacity
        self._clock = clock
        self._sleeper = sleeper
        self._last_refill = self._clock()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> float:
        if tokens <= 0:
            return 0.0
        waited = 0.0
        while True:
            with self._lock:
                now = self._clock()
                elapsed = max(0.0, now - self._last_refill)
                self._last_refill = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_sec)
                # 1e-9 epsilon avoids sub-ULP sleep loops when deficit / rate < ulp(now)
                if self._tokens + 1e-9 >= tokens:
                    self._tokens = max(0.0, self._tokens - tokens)
                    return waited
                deficit = tokens - self._tokens
                sleep_seconds = deficit / self.rate_per_sec

            self._sleeper(sleep_seconds)
            waited += sleep_seconds
