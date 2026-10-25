from __future__ import annotations

from pathlib import Path

from faultline.models import HttpExchange, RecordedRequest, RecordedResponse
from faultline.storage import (
    ExchangeStore,
    export_har,
    export_jsonl,
    import_har,
    import_jsonl,
)


def _sample_exchange(
    exchange_id: str,
    session: str = "payments",
    path: str = "/v1/charges/100",
    status: int = 200,
    body: str = '{"id": "ch_1", "amount": 500}',
) -> HttpExchange:
    return HttpExchange(
        exchange_id=exchange_id,
        session=session,
        captured_at=f"2026-10-28T10:00:0{exchange_id[-1]}Z",
        request=RecordedRequest(
            method="POST",
            path=path,
            headers={"Content-Type": "application/json"},
            body='{"amount": 500}',
        ),
        response=RecordedResponse(
            status_code=status,
            headers={"Content-Type": "application/json"},
            body=body,
            latency_ms=12.4,
        ),
    )


def test_sqlite_store_save_query_and_deduplicate(tmp_path: Path) -> None:
    store = ExchangeStore(tmp_path / "test.db")
    try:
        ex1 = _sample_exchange("ex_001", path="/v1/charges/100")
        ex2 = _sample_exchange("ex_002", path="/v1/charges/200")
        ex3 = _sample_exchange(
            "ex_003",
            path="/v1/charges/300",
            status=500,
            body='{"error": "internal_error"}',
        )
        store.save_many([ex1, ex2, ex3])

        all_exchanges = store.list_exchanges(session="payments")
        assert len(all_exchanges) == 3

        deduped = store.list_exchanges(session="payments", deduplicate_fingerprints=True)
        assert len(deduped) == 2

        fetched = store.get_exchange("ex_002")
        assert fetched is not None
        assert fetched.request.path == "/v1/charges/200"

        summaries = store.list_sessions()
        assert len(summaries) == 1
        assert summaries[0].session == "payments"
        assert summaries[0].exchange_count == 3
        assert summaries[0].unique_fingerprints == 2
        assert summaries[0].error_count == 1

        deleted = store.delete_session("payments")
        assert deleted == 3
        assert store.list_sessions() == []
    finally:
        store.close()


def test_jsonl_export_and_import_roundtrip(tmp_path: Path) -> None:
    exchanges = [
        _sample_exchange("ex_101", session="webhooks"),
        _sample_exchange("ex_102", session="webhooks", path="/v1/charges/999"),
    ]
    jsonl_file = tmp_path / "fixtures" / "webhooks.jsonl"
    written = export_jsonl(exchanges, jsonl_file)
    assert written == 2

    loaded = import_jsonl(jsonl_file, override_session="webhooks-restored")
    assert len(loaded) == 2
    assert loaded[0].session == "webhooks-restored"
    assert loaded[0].fingerprint == exchanges[0].fingerprint


def test_har_export_and_import_roundtrip(tmp_path: Path) -> None:
    exchanges = [_sample_exchange("ex_201", session="har-demo")]
    har_file = tmp_path / "capture.har"
    assert export_har(exchanges, har_file) == 1

    imported = import_har(har_file, session="from-har")
    assert len(imported) == 1
    assert imported[0].session == "from-har"
    assert imported[0].request.method == "POST"
    assert imported[0].response.status_code == 200
