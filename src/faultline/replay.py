from __future__ import annotations

import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin

from faultline.differ import ContractDiffer, DiffConfig
from faultline.models import (
    ExchangeComparison,
    HttpExchange,
    LatencyStats,
    RecordedRequest,
    RecordedResponse,
    ReplayReport,
)
from faultline.ratelimit import TokenBucketLimiter

HOP_BY_HOP_HEADERS: frozenset[str] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)

TransportCallable = Callable[[RecordedRequest, str, float], RecordedResponse]


def default_http_transport(
    request: RecordedRequest, target_base_url: str, timeout_sec: float
) -> RecordedResponse:
    base = target_base_url.rstrip("/")
    path = request.path if request.path.startswith("/") else f"/{request.path}"
    full_url = urljoin(f"{base}/", path.lstrip("/"))

    outbound_headers: dict[str, str] = {}
    for k, v in request.headers.items():
        if k.lower() not in HOP_BY_HOP_HEADERS and not v.startswith("<"):
            outbound_headers[k] = v
    outbound_headers["X-Faultline-Replay"] = "1"

    body_bytes = request.body.encode("utf-8") if request.body else None
    req_obj = urllib.request.Request(
        url=full_url,
        data=body_bytes,
        headers=outbound_headers,
        method=request.method.upper(),
    )

    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req_obj, timeout=timeout_sec) as resp:
            raw_bytes = resp.read()
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            resp_headers = {str(k): str(v) for k, v in resp.headers.items()}
            return RecordedResponse(
                status_code=int(resp.status),
                headers=resp_headers,
                body=raw_bytes.decode("utf-8", errors="replace"),
                latency_ms=round(elapsed_ms, 3),
            )
    except urllib.error.HTTPError as http_err:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        err_bytes = http_err.read() if http_err.fp else b""
        resp_headers = (
            {str(k): str(v) for k, v in http_err.headers.items()} if http_err.headers else {}
        )
        return RecordedResponse(
            status_code=int(http_err.code),
            headers=resp_headers,
            body=err_bytes.decode("utf-8", errors="replace"),
            latency_ms=round(elapsed_ms, 3),
        )


@dataclass(frozen=True)
class ReplayOptions:
    target_url: str
    concurrency: int = 4
    rate_limit_rps: float | None = None
    timeout_sec: float = 10.0
    extra_headers: dict[str, str] = field(default_factory=dict)
    diff_config: DiffConfig = field(default_factory=DiffConfig)


class ReplayEngine:
    def __init__(
        self,
        options: ReplayOptions,
        transport: TransportCallable | None = None,
    ) -> None:
        self.options = options
        self.transport = transport or default_http_transport
        self.differ = ContractDiffer(options.diff_config)
        self.limiter: TokenBucketLimiter | None = (
            TokenBucketLimiter(options.rate_limit_rps)
            if options.rate_limit_rps and options.rate_limit_rps > 0
            else None
        )

    def _replay_one(self, exchange: HttpExchange) -> ExchangeComparison:
        if self.limiter is not None:
            self.limiter.acquire(1.0)

        merged_headers = dict(exchange.request.headers)
        merged_headers.update(self.options.extra_headers)
        effective_request = RecordedRequest(
            method=exchange.request.method,
            path=exchange.request.path,
            headers=merged_headers,
            body=exchange.request.body,
            query_params=exchange.request.query_params,
        )

        try:
            candidate_resp = self.transport(
                effective_request,
                self.options.target_url,
                self.options.timeout_sec,
            )
            return self.differ.compare_exchange(exchange, candidate_resp)
        except Exception as exc:
            return self.differ.compare_exchange(
                exchange,
                candidate=None,
                transport_error=f"{type(exc).__name__}: {exc}",
            )

    def run(self, exchanges: list[HttpExchange], session_name: str = "default") -> ReplayReport:
        workers = max(1, int(self.options.concurrency))
        if workers == 1 or len(exchanges) <= 1:
            comparisons = [self._replay_one(ex) for ex in exchanges]
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                comparisons = list(pool.map(self._replay_one, exchanges))

        baseline_samples = [c.baseline_latency_ms for c in comparisons]
        candidate_samples = [
            c.candidate_latency_ms for c in comparisons if c.transport_error is None
        ]

        breaking_count = sum(1 for c in comparisons if c.has_breaking_changes)
        warning_count = sum(
            1 for c in comparisons if (not c.has_breaking_changes and c.has_warnings)
        )
        passed_count = sum(1 for c in comparisons if not c.has_breaking_changes)

        return ReplayReport(
            session=session_name,
            target_url=self.options.target_url,
            total_exchanges=len(comparisons),
            passed_count=passed_count,
            breaking_count=breaking_count,
            warning_count=warning_count,
            baseline_latency=LatencyStats.from_samples(baseline_samples),
            candidate_latency=LatencyStats.from_samples(candidate_samples),
            comparisons=comparisons,
        )
