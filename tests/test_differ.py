from __future__ import annotations

from faultline.differ import ContractDiffer, DiffConfig
from faultline.models import DiffKind, HttpExchange, RecordedRequest, RecordedResponse, Severity


def test_differ_ignores_default_volatile_paths() -> None:
    differ = ContractDiffer()
    baseline = RecordedResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"request_id": "req_1", "meta": {"timestamp": "2026-10-01"}, "data": {"ok": true}}',
    )
    candidate = RecordedResponse(
        status_code=200,
        headers={"Content-Type": "application/json; charset=utf-8"},
        body='{"request_id": "req_2", "meta": {"timestamp": "2026-10-29"}, "data": {"ok": true}}',
    )
    violations = differ.diff_responses(baseline, candidate)
    assert violations == []


def test_differ_detects_removed_field_and_type_change_as_breaking() -> None:
    differ = ContractDiffer()
    baseline = RecordedResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"customer": {"id": 100, "tier": "gold", "balance": 500}}',
    )
    candidate = RecordedResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"customer": {"id": "100", "balance": 500, "new_flag": true}}',
    )
    violations = differ.diff_responses(baseline, candidate)
    by_path = {v.path: v for v in violations}

    assert "$.customer.tier" in by_path
    assert by_path["$.customer.tier"].kind == DiffKind.FIELD_REMOVED
    assert by_path["$.customer.tier"].severity == Severity.BREAKING

    assert "$.customer.id" in by_path
    assert by_path["$.customer.id"].kind == DiffKind.TYPE_CHANGED
    assert by_path["$.customer.id"].severity == Severity.BREAKING

    assert "$.customer.new_flag" in by_path
    assert by_path["$.customer.new_flag"].kind == DiffKind.FIELD_ADDED
    assert by_path["$.customer.new_flag"].severity == Severity.INFO


def test_differ_detects_nullability_regression() -> None:
    differ = ContractDiffer()
    baseline = RecordedResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"invoice": {"download_url": "https://cdn.example.com/inv.pdf"}}',
    )
    candidate = RecordedResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"invoice": {"download_url": null}}',
    )
    violations = differ.diff_responses(baseline, candidate)
    assert len(violations) == 1
    assert violations[0].kind == DiffKind.NULLABILITY_CHANGED
    assert violations[0].severity == Severity.BREAKING
    assert violations[0].path == "$.invoice.download_url"


def test_differ_status_mismatch_and_latency_budget() -> None:
    differ = ContractDiffer(DiffConfig(max_latency_regression_ms=50.0))
    baseline = RecordedResponse(
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"ok": true}',
        latency_ms=15.0,
    )
    candidate = RecordedResponse(
        status_code=500,
        headers={"Content-Type": "application/json"},
        body='{"ok": false}',
        latency_ms=95.0,
    )
    violations = differ.diff_responses(baseline, candidate)
    kinds = {v.kind for v in violations}
    assert DiffKind.STATUS_MISMATCH in kinds
    assert DiffKind.LATENCY_REGRESSION in kinds


def test_compare_exchange_records_transport_error() -> None:
    differ = ContractDiffer()
    ex = HttpExchange(
        exchange_id="ex_err",
        session="s1",
        captured_at="2026-10-25T00:00:00Z",
        request=RecordedRequest(method="GET", path="/v1/ping"),
        response=RecordedResponse(status_code=200, body='{"pong": true}'),
    )
    comp = differ.compare_exchange(ex, candidate=None, transport_error="Connection refused")
    assert comp.has_breaking_changes
    assert comp.violations[0].kind == DiffKind.TRANSPORT_ERROR
