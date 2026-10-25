from __future__ import annotations

from faultline.models import (
    HttpExchange,
    LatencyStats,
    RecordedRequest,
    RecordedResponse,
    compute_structural_fingerprint,
    normalize_path_template,
)


def test_normalize_path_template_ids_and_uuids() -> None:
    raw = "/v1/accounts/98412/webhooks/b7c91e02-41d2-4e89-9a10-3301c88e102a?limit=10&cursor=abc"
    assert normalize_path_template(raw) == "/v1/accounts/:id/webhooks/:uuid?cursor&limit"


def test_normalize_path_template_hex_tokens() -> None:
    raw = "/v2/sessions/a9f401bc883100ef99123456/events"
    assert normalize_path_template(raw) == "/v2/sessions/:token/events"


def test_structural_fingerprint_ignores_scalar_values() -> None:
    req1 = RecordedRequest(
        method="POST",
        path="/v1/orders/101",
        body='{"amount": 2500, "currency": "USD", "items": [{"sku": "A1", "qty": 1}]}',
    )
    resp1 = RecordedResponse(
        status_code=201,
        body='{"order_id": "ord_1", "status": "created", "total": 2500}',
    )

    req2 = RecordedRequest(
        method="POST",
        path="/v1/orders/99999",
        body='{"currency": "EUR", "amount": 900, "items": [{"qty": 5, "sku": "B9"}]}',
    )
    resp2 = RecordedResponse(
        status_code=201,
        body='{"total": 900, "order_id": "ord_99", "status": "pending"}',
    )

    assert compute_structural_fingerprint(req1, resp1) == compute_structural_fingerprint(
        req2, resp2
    )


def test_structural_fingerprint_changes_when_field_removed() -> None:
    req = RecordedRequest(method="GET", path="/v1/users/42")
    resp_a = RecordedResponse(status_code=200, body='{"id": 42, "email": "dev@kern.io"}')
    resp_b = RecordedResponse(status_code=200, body='{"id": 42}')

    assert compute_structural_fingerprint(req, resp_a) != compute_structural_fingerprint(
        req, resp_b
    )


def test_case_insensitive_header_lookup() -> None:
    req = RecordedRequest(
        method="GET",
        path="/health",
        headers={"X-Correlation-ID": "req-777", "Content-Type": "application/json"},
    )
    assert req.header("x-correlation-id") == "req-777"
    assert req.header("CONTENT-TYPE") == "application/json"
    assert req.header("missing", "fallback") == "fallback"


def test_exchange_dict_roundtrip() -> None:
    ex = HttpExchange(
        exchange_id="ex_001",
        session="billing",
        captured_at="2026-10-21T12:00:00Z",
        request=RecordedRequest(method="POST", path="/v1/refunds", body='{"id": 1}'),
        response=RecordedResponse(status_code=200, body='{"ok": true}', latency_ms=14.2),
        tags={"env": "staging"},
    )
    rehydrated = HttpExchange.from_dict(ex.to_dict())
    assert rehydrated == ex
    assert len(rehydrated.fingerprint) == 16


def test_latency_stats_percentiles() -> None:
    samples = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
    stats = LatencyStats.from_samples(samples)
    assert stats.count == 10
    assert stats.min_ms == 10.0
    assert stats.p50_ms == 55.0
    assert stats.p90_ms == 91.0
    assert stats.max_ms == 100.0
    assert stats.mean_ms == 55.0


def test_latency_stats_empty_and_single() -> None:
    empty = LatencyStats.from_samples([])
    assert empty.count == 0
    assert empty.p95_ms == 0.0

    single = LatencyStats.from_samples([42.5])
    assert single.count == 1
    assert single.p50_ms == 42.5
    assert single.p99_ms == 42.5
