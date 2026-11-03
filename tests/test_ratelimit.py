from __future__ import annotations

import pytest

from faultline.ratelimit import TokenBucketLimiter


def test_token_bucket_rate_limiter_waits_when_depleted() -> None:
    fake_now = [100.0]
    slept: list[float] = []

    def clock() -> float:
        return fake_now[0]

    def sleeper(seconds: float) -> None:
        slept.append(round(seconds, 4))
        fake_now[0] += seconds

    limiter = TokenBucketLimiter(rate_per_sec=10.0, burst=2, clock=clock, sleeper=sleeper)

    assert limiter.acquire(1.0) == 0.0
    assert limiter.acquire(1.0) == 0.0
    assert slept == []

    waited = limiter.acquire(1.0)
    assert round(waited, 4) == 0.1
    assert slept == [0.1]


def test_token_bucket_rejects_non_positive_rate() -> None:
    with pytest.raises(ValueError, match="rate_per_sec must be positive"):
        TokenBucketLimiter(rate_per_sec=0)
