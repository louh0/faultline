from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any

from faultline.models import (
    ContractViolation,
    DiffKind,
    ExchangeComparison,
    HttpExchange,
    RecordedResponse,
    Severity,
)

DEFAULT_VOLATILE_PATHS: frozenset[str] = frozenset(
    {
        "$.request_id",
        "$.trace_id",
        "$.correlation_id",
        "$.timestamp",
        "$.server_time",
        "$.meta.request_id",
        "$.meta.trace_id",
        "$.meta.timestamp",
        "$.meta.duration_ms",
    }
)

DEFAULT_REQUIRED_HEADERS: frozenset[str] = frozenset({"content-type"})


def _json_type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _normalize_content_type(raw: str | None) -> str:
    if not raw:
        return ""
    return raw.split(";", 1)[0].strip().lower()


@dataclass(frozen=True)
class DiffConfig:
    ignore_paths: frozenset[str] = field(default_factory=lambda: DEFAULT_VOLATILE_PATHS)
    required_headers: frozenset[str] = field(default_factory=lambda: DEFAULT_REQUIRED_HEADERS)
    fail_on_added_fields: bool = False
    allow_int_to_float_widening: bool = True
    strict_scalar_values: bool = False
    max_latency_regression_ms: float | None = None
    max_array_items_inspected: int = 32

    def is_ignored(self, json_path: str) -> bool:
        for pattern in self.ignore_paths:
            if json_path == pattern or fnmatch.fnmatchcase(json_path, pattern):
                return True
        return False


class ContractDiffer:
    def __init__(self, config: DiffConfig | None = None) -> None:
        self.config = config or DiffConfig()

    def compare_exchange(
        self,
        exchange: HttpExchange,
        candidate: RecordedResponse | None,
        transport_error: str | None = None,
    ) -> ExchangeComparison:
        baseline = exchange.response
        if transport_error is not None or candidate is None:
            violation = ContractViolation(
                kind=DiffKind.TRANSPORT_ERROR,
                severity=Severity.BREAKING,
                path="$http",
                message=f"Transport failure during replay: {transport_error or 'no response'}",
                expected=baseline.status_code,
                actual=None,
            )
            return ExchangeComparison(
                exchange_id=exchange.exchange_id,
                method=exchange.request.method,
                path=exchange.request.path,
                baseline_status=baseline.status_code,
                candidate_status=None,
                baseline_latency_ms=baseline.latency_ms,
                candidate_latency_ms=0.0,
                violations=[violation],
                transport_error=transport_error or "no response",
            )

        violations = self.diff_responses(baseline, candidate)
        return ExchangeComparison(
            exchange_id=exchange.exchange_id,
            method=exchange.request.method,
            path=exchange.request.path,
            baseline_status=baseline.status_code,
            candidate_status=candidate.status_code,
            baseline_latency_ms=baseline.latency_ms,
            candidate_latency_ms=candidate.latency_ms,
            violations=violations,
        )

    def diff_responses(
        self, baseline: RecordedResponse, candidate: RecordedResponse
    ) -> list[ContractViolation]:
        violations: list[ContractViolation] = []

        if baseline.status_code != candidate.status_code:
            base_class = baseline.status_code // 100
            cand_class = candidate.status_code // 100
            severity = Severity.BREAKING if base_class != cand_class else Severity.WARNING
            if cand_class == 5 or base_class == 2:
                severity = Severity.BREAKING
            violations.append(
                ContractViolation(
                    kind=DiffKind.STATUS_MISMATCH,
                    severity=severity,
                    path="$http.status",
                    message=(
                        f"HTTP status changed from {baseline.status_code} to {candidate.status_code}"
                    ),
                    expected=baseline.status_code,
                    actual=candidate.status_code,
                )
            )

        for hdr in sorted(self.config.required_headers):
            base_val = baseline.header(hdr)
            cand_val = candidate.header(hdr)
            if base_val is not None and cand_val is None:
                violations.append(
                    ContractViolation(
                        kind=DiffKind.HEADER_MISSING,
                        severity=Severity.BREAKING,
                        path=f"$http.headers.{hdr}",
                        message=f"Required response header '{hdr}' is missing",
                        expected=base_val,
                        actual=None,
                    )
                )
            elif base_val is not None and cand_val is not None:
                if hdr.lower() == "content-type":
                    base_ct = _normalize_content_type(base_val)
                    cand_ct = _normalize_content_type(cand_val)
                    if base_ct != cand_ct:
                        violations.append(
                            ContractViolation(
                                kind=DiffKind.HEADER_MISMATCH,
                                severity=Severity.BREAKING,
                                path="$http.headers.content-type",
                                message=f"Content-Type changed from '{base_ct}' to '{cand_ct}'",
                                expected=base_ct,
                                actual=cand_ct,
                            )
                        )
                elif base_val != cand_val:
                    violations.append(
                        ContractViolation(
                            kind=DiffKind.HEADER_MISMATCH,
                            severity=Severity.WARNING,
                            path=f"$http.headers.{hdr}",
                            message=f"Header '{hdr}' value changed",
                            expected=base_val,
                            actual=cand_val,
                        )
                    )

        base_is_json, base_json = baseline.try_json_body()
        cand_is_json, cand_json = candidate.try_json_body()

        if base_is_json and not cand_is_json:
            violations.append(
                ContractViolation(
                    kind=DiffKind.TYPE_CHANGED,
                    severity=Severity.BREAKING,
                    path="$",
                    message="Baseline body was valid JSON, but candidate body is not valid JSON",
                    expected="json",
                    actual="non-json",
                )
            )
        elif base_is_json and cand_is_json:
            self._diff_json_nodes(base_json, cand_json, "$", violations)
        elif (
            baseline.body.strip() != candidate.body.strip()
            and not self.config.is_ignored("$")
        ):
            violations.append(
                ContractViolation(
                    kind=DiffKind.BODY_TEXT_MISMATCH,
                    severity=Severity.WARNING,
                    path="$body",
                    message="Non-JSON response body text differs from baseline",
                    expected=baseline.body[:120],
                    actual=candidate.body[:120],
                )
            )

        if self.config.max_latency_regression_ms is not None:
            delta = candidate.latency_ms - baseline.latency_ms
            if delta > self.config.max_latency_regression_ms:
                violations.append(
                    ContractViolation(
                        kind=DiffKind.LATENCY_REGRESSION,
                        severity=Severity.WARNING,
                        path="$http.latency_ms",
                        message=(
                            f"Latency increased by +{delta:.1f}ms "
                            f"(budget: +{self.config.max_latency_regression_ms:.1f}ms)"
                        ),
                        expected=round(baseline.latency_ms, 2),
                        actual=round(candidate.latency_ms, 2),
                    )
                )

        return violations

    def _diff_json_nodes(
        self,
        expected: Any,
        actual: Any,
        path: str,
        violations: list[ContractViolation],
    ) -> None:
        if self.config.is_ignored(path):
            return

        exp_type = _json_type_name(expected)
        act_type = _json_type_name(actual)

        if exp_type != "null" and act_type == "null":
            violations.append(
                ContractViolation(
                    kind=DiffKind.NULLABILITY_CHANGED,
                    severity=Severity.BREAKING,
                    path=path,
                    message=f"Field '{path}' became null (expected {exp_type})",
                    expected=exp_type,
                    actual="null",
                )
            )
            return

        if exp_type == "null" and act_type != "null":
            violations.append(
                ContractViolation(
                    kind=DiffKind.NULLABILITY_CHANGED,
                    severity=Severity.INFO,
                    path=path,
                    message=f"Previously null field '{path}' resolved to {act_type}",
                    expected="null",
                    actual=act_type,
                )
            )
            return

        if exp_type != act_type:
            if (
                self.config.allow_int_to_float_widening
                and exp_type in ("integer", "number")
                and act_type in ("integer", "number")
            ):
                pass
            else:
                violations.append(
                    ContractViolation(
                        kind=DiffKind.TYPE_CHANGED,
                        severity=Severity.BREAKING,
                        path=path,
                        message=f"Type mismatch at '{path}': expected {exp_type}, got {act_type}",
                        expected=exp_type,
                        actual=act_type,
                    )
                )
                return

        if exp_type == "object" and isinstance(expected, dict) and isinstance(actual, dict):
            exp_keys = set(expected.keys())
            act_keys = set(actual.keys())

            for missing_key in sorted(exp_keys - act_keys):
                child_path = f"{path}.{missing_key}"
                if self.config.is_ignored(child_path):
                    continue
                violations.append(
                    ContractViolation(
                        kind=DiffKind.FIELD_REMOVED,
                        severity=Severity.BREAKING,
                        path=child_path,
                        message=f"Required field '{child_path}' was removed from response",
                        expected=_json_type_name(expected[missing_key]),
                        actual=None,
                    )
                )

            for added_key in sorted(act_keys - exp_keys):
                child_path = f"{path}.{added_key}"
                if self.config.is_ignored(child_path):
                    continue
                severity = (
                    Severity.BREAKING if self.config.fail_on_added_fields else Severity.INFO
                )
                violations.append(
                    ContractViolation(
                        kind=DiffKind.FIELD_ADDED,
                        severity=severity,
                        path=child_path,
                        message=f"New field '{child_path}' added to response ({_json_type_name(actual[added_key])})",
                        expected=None,
                        actual=_json_type_name(actual[added_key]),
                    )
                )

            for shared_key in sorted(exp_keys & act_keys):
                self._diff_json_nodes(
                    expected[shared_key],
                    actual[shared_key],
                    f"{path}.{shared_key}",
                    violations,
                )
            return

        if exp_type == "array" and isinstance(expected, list) and isinstance(actual, list):
            if not expected or not actual:
                return
            baseline_sample = expected[0]
            limit = min(len(actual), self.config.max_array_items_inspected)
            for idx in range(limit):
                self._diff_json_nodes(
                    baseline_sample,
                    actual[idx],
                    f"{path}[{idx}]",
                    violations,
                )
            return

        if self.config.strict_scalar_values and expected != actual:
            violations.append(
                ContractViolation(
                    kind=DiffKind.VALUE_MISMATCH,
                    severity=Severity.WARNING,
                    path=path,
                    message=f"Scalar value changed at '{path}'",
                    expected=expected,
                    actual=actual,
                )
            )
