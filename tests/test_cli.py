from __future__ import annotations

import json
from pathlib import Path

import pytest

from faultline.cli import main
from faultline.models import HttpExchange, RecordedRequest, RecordedResponse
from faultline.storage import ExchangeStore, export_jsonl


def _seed_exchange(
    exchange_id: str,
    session: str,
    resp_body: str,
    status_code: int = 200,
) -> HttpExchange:
    return HttpExchange(
        exchange_id=exchange_id,
        session=session,
        captured_at="2026-10-30T15:00:00Z",
        request=RecordedRequest(
            method="GET",
            path="/v1/accounts/42",
            headers={"Accept": "application/json"},
        ),
        response=RecordedResponse(
            status_code=status_code,
            headers={"Content-Type": "application/json"},
            body=resp_body,
            latency_ms=8.5,
        ),
    )


def test_cli_import_sessions_inspect_and_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db_path = str(tmp_path / "cli.db")
    fixture_path = tmp_path / "seed.jsonl"
    export_jsonl(
        [_seed_exchange("ex_seed_1", "core-api", '{"id": 42, "plan": "pro"}')],
        fixture_path,
    )

    rc = main(["--db", db_path, "import", "--input", str(fixture_path)])
    assert rc == 0
    capsys.readouterr()

    rc = main(["--db", db_path, "sessions"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "core-api" in out

    rc = main(["--db", db_path, "inspect", "ex_seed"])
    assert rc == 0
    inspect_doc = json.loads(capsys.readouterr().out)
    assert inspect_doc["route_template"] == "/v1/accounts/:id"
    assert inspect_doc["inferred_response_schema"]["properties"]["plan"]["type"] == "string"

    rc = main(["--db", db_path, "schema", "--session", "core-api"])
    assert rc == 0
    schema_doc = json.loads(capsys.readouterr().out)
    assert schema_doc["required"] == ["id", "plan"]


def test_cli_offline_diff_returns_nonzero_on_breaking_drift(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db_path = str(tmp_path / "diff.db")
    store = ExchangeStore(db_path)
    store.save_exchange(_seed_exchange("ex_base", "v1-session", '{"id": 42, "plan": "pro"}'))
    store.save_exchange(_seed_exchange("ex_cand", "v2-session", '{"id": 42}'))
    store.close()

    rc = main(
        [
            "--db",
            db_path,
            "diff",
            "--baseline",
            "v1-session",
            "--candidate",
            "v2-session",
            "--format",
            "json",
        ]
    )
    assert rc == 2
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is False
    assert report["breaking_count"] == 1
