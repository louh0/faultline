from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import parse_qsl, urlsplit

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NUMERIC_SEGMENT_RE = re.compile(r"^\d+$")
_HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


class Severity(str, Enum):
    BREAKING = "breaking"
    WARNING = "warning"
    INFO = "info"


class DiffKind(str, Enum):
    STATUS_MISMATCH = "status_mismatch"
    HEADER_MISSING = "header_missing"
    HEADER_MISMATCH = "header_mismatch"
    FIELD_REMOVED = "field_removed"
    FIELD_ADDED = "field_added"
    TYPE_CHANGED = "type_changed"
    NULLABILITY_CHANGED = "nullability_changed"
    ARRAY_ITEM_DRIFT = "array_item_drift"
    VALUE_MISMATCH = "value_mismatch"
    BODY_TEXT_MISMATCH = "body_text_mismatch"
    LATENCY_REGRESSION = "latency_regression"
    TRANSPORT_ERROR = "transport_error"


def normalize_path_template(raw_path: str) -> str:
    """Replace numeric IDs, UUIDs, and hex tokens in URL paths with placeholders."""
    parsed = urlsplit(raw_path)
    segments = [seg for seg in parsed.path.split("/") if seg]
    normalized: list[str] = []
    for seg in segments:
        if _UUID_RE.match(seg):
            normalized.append(":uuid")
        elif _NUMERIC_SEGMENT_RE.match(seg):
            normalized.append(":id")
        elif _HEX_TOKEN_RE.match(seg):
            normalized.append(":token")
        else:
            normalized.append(seg)
    base = "/" + "/".join(normalized)
    if parsed.query:
        query_keys = sorted({k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)})
        if query_keys:
            base = f"{base}?{'&'.join(query_keys)}"
    return base


def _extract_json_skeleton(value: Any) -> Any:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        if not value:
            return ["empty"]
        # cap at 16 items so huge pagination arrays don't tank hashing
        seen: dict[str, Any] = {}
        for item in value[:16]:
            skel = _extract_json_skeleton(item)
            key = json.dumps(skel, sort_keys=True)
            seen[key] = skel
        return [seen[k] for k in sorted(seen)]
    if isinstance(value, dict):
        return {str(k): _extract_json_skeleton(v) for k, v in sorted(value.items())}
    return "unknown"


@dataclass(frozen=True)
class RecordedRequest:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    query_params: dict[str, str] = field(default_factory=dict)

    def header(self, name: str, default: str | None = None) -> str | None:
        target = name.lower()
        for k, v in self.headers.items():
            if k.lower() == target:
                return v
        return default

    def json_body(self) -> Any:
        if not self.body or not self.body.strip():
            raise ValueError("Empty request body")
        return json.loads(self.body)

    def try_json_body(self) -> tuple[bool, Any]:
        if not self.body or not self.body.strip():
            return False, None
        try:
            return True, json.loads(self.body)
        except (ValueError, TypeError):
            return False, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "headers": dict(self.headers),
            "body": self.body,
            "query_params": dict(self.query_params),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RecordedRequest:
        return cls(
            method=str(data["method"]).upper(),
            path=str(data["path"]),
            headers={str(k): str(v) for k, v in data.get("headers", {}).items()},
            body=str(data.get("body", "")),
            query_params={str(k): str(v) for k, v in data.get("query_params", {}).items()},
        )


@dataclass(frozen=True)
class RecordedResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    latency_ms: float = 0.0

    def header(self, name: str, default: str | None = None) -> str | None:
        target = name.lower()
        for k, v in self.headers.items():
            if k.lower() == target:
                return v
        return default

    def try_json_body(self) -> tuple[bool, Any]:
        if not self.body or not self.body.strip():
            return False, None
        try:
            return True, json.loads(self.body)
        except (ValueError, TypeError):
            return False, None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "body": self.body,
            "latency_ms": round(self.latency_ms, 3),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RecordedResponse:
        return cls(
            status_code=int(data["status_code"]),
            headers={str(k): str(v) for k, v in data.get("headers", {}).items()},
            body=str(data.get("body", "")),
            latency_ms=float(data.get("latency_ms", 0.0)),
        )


def compute_structural_fingerprint(
    request: RecordedRequest, response: RecordedResponse
) -> str:
    """Hash method + normalized route + status + JSON type skeleton."""
    _, req_json = request.try_json_body()
    _, resp_json = response.try_json_body()
    envelope = {
        "method": request.method.upper(),
        "route": normalize_path_template(request.path),
        "status": response.status_code,
        "req_shape": _extract_json_skeleton(req_json) if req_json is not None else bool(request.body),
        "resp_shape": _extract_json_skeleton(resp_json) if resp_json is not None else bool(response.body),
    }
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class HttpExchange:
    exchange_id: str
    session: str
    captured_at: str
    request: RecordedRequest
    response: RecordedResponse
    fingerprint: str = ""
    tags: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.fingerprint:
            fp = compute_structural_fingerprint(self.request, self.response)
            object.__setattr__(self, "fingerprint", fp)

    @property
    def route_template(self) -> str:
        return normalize_path_template(self.request.path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exchange_id": self.exchange_id,
            "session": self.session,
            "captured_at": self.captured_at,
            "fingerprint": self.fingerprint,
            "tags": dict(self.tags),
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HttpExchange:
        req = RecordedRequest.from_dict(data["request"])
        resp = RecordedResponse.from_dict(data["response"])
        return cls(
            exchange_id=str(data["exchange_id"]),
            session=str(data.get("session", "default")),
            captured_at=str(data.get("captured_at", "")),
            request=req,
            response=resp,
            fingerprint=str(data.get("fingerprint", "")),
            tags={str(k): str(v) for k, v in data.get("tags", {}).items()},
        )


@dataclass(frozen=True)
class CaptureSessionSummary:
    session: str
    exchange_count: int
    unique_fingerprints: int
    first_captured_at: str
    last_captured_at: str
    avg_latency_ms: float
    error_count: int


@dataclass(frozen=True)
class ContractViolation:
    kind: DiffKind
    severity: Severity
    path: str
    message: str
    expected: Any = None
    actual: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "severity": self.severity.value,
            "path": self.path,
            "message": self.message,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass(frozen=True)
class ExchangeComparison:
    exchange_id: str
    method: str
    path: str
    baseline_status: int
    candidate_status: int | None
    baseline_latency_ms: float
    candidate_latency_ms: float
    violations: list[ContractViolation] = field(default_factory=list)
    transport_error: str | None = None

    @property
    def has_breaking_changes(self) -> bool:
        return any(v.severity == Severity.BREAKING for v in self.violations)

    @property
    def has_warnings(self) -> bool:
        return any(v.severity == Severity.WARNING for v in self.violations)

    @property
    def latency_delta_ms(self) -> float:
        return round(self.candidate_latency_ms - self.baseline_latency_ms, 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exchange_id": self.exchange_id,
            "method": self.method,
            "path": self.path,
            "baseline_status": self.baseline_status,
            "candidate_status": self.candidate_status,
            "baseline_latency_ms": round(self.baseline_latency_ms, 3),
            "candidate_latency_ms": round(self.candidate_latency_ms, 3),
            "latency_delta_ms": self.latency_delta_ms,
            "has_breaking_changes": self.has_breaking_changes,
            "transport_error": self.transport_error,
            "violations": [v.to_dict() for v in self.violations],
        }


@dataclass(frozen=True)
class LatencyStats:
    count: int
    min_ms: float
    p50_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float

    @classmethod
    def from_samples(cls, samples: list[float]) -> LatencyStats:
        if not samples:
            return cls(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        ordered = sorted(samples)
        n = len(ordered)

        def _pct(p: float) -> float:
            if n == 1:
                return round(ordered[0], 3)
            rank = (p / 100.0) * (n - 1)
            low = math.floor(rank)
            high = math.ceil(rank)
            weight = rank - low
            val = ordered[low] * (1.0 - weight) + ordered[high] * weight
            return round(val, 3)

        return cls(
            count=n,
            min_ms=round(ordered[0], 3),
            p50_ms=_pct(50.0),
            p90_ms=_pct(90.0),
            p95_ms=_pct(95.0),
            p99_ms=_pct(99.0),
            max_ms=round(ordered[-1], 3),
            mean_ms=round(sum(ordered) / n, 3),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "min_ms": self.min_ms,
            "p50_ms": self.p50_ms,
            "p90_ms": self.p90_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "max_ms": self.max_ms,
            "mean_ms": self.mean_ms,
        }


@dataclass(frozen=True)
class ReplayReport:
    session: str
    target_url: str
    total_exchanges: int
    passed_count: int
    breaking_count: int
    warning_count: int
    baseline_latency: LatencyStats
    candidate_latency: LatencyStats
    comparisons: list[ExchangeComparison] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.breaking_count == 0

    @property
    def p95_regression_ms(self) -> float:
        return round(self.candidate_latency.p95_ms - self.baseline_latency.p95_ms, 3)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session": self.session,
            "target_url": self.target_url,
            "passed": self.passed,
            "total_exchanges": self.total_exchanges,
            "passed_count": self.passed_count,
            "breaking_count": self.breaking_count,
            "warning_count": self.warning_count,
            "p95_regression_ms": self.p95_regression_ms,
            "baseline_latency": self.baseline_latency.to_dict(),
            "candidate_latency": self.candidate_latency.to_dict(),
            "comparisons": [c.to_dict() for c in self.comparisons],
        }
