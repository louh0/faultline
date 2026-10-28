from __future__ import annotations

import json

from faultline.models import HttpExchange, RecordedRequest, RecordedResponse
from faultline.redaction import RedactionPolicy, Redactor


def test_redacts_sensitive_headers_preserving_scheme() -> None:
    redactor = Redactor()
    headers = {
        "Authorization": "Bearer sk_live_9988776655",
        "X-Api-Key": "internal-key-912",
        "Content-Type": "application/json",
    }
    sanitized = redactor.redact_headers(headers)
    assert sanitized["Authorization"].startswith("Bearer <TOKEN:")
    assert "sk_live_9988776655" not in sanitized["Authorization"]
    assert sanitized["X-Api-Key"].startswith("<HEADER:")
    assert sanitized["Content-Type"] == "application/json"


def test_deterministic_redaction_preserves_correlation() -> None:
    redactor = Redactor(RedactionPolicy(salt="s1"))
    h1 = redactor.redact_headers({"Authorization": "Bearer tok_abc"})
    h2 = redactor.redact_headers({"Authorization": "Bearer tok_abc"})
    h3 = redactor.redact_headers({"Authorization": "Bearer tok_xyz"})
    assert h1["Authorization"] == h2["Authorization"]
    assert h1["Authorization"] != h3["Authorization"]


def test_redacts_nested_json_keys_emails_jwts_and_cards() -> None:
    redactor = Redactor()
    payload = {
        "user": {
            "email": "m.weber@acme-pay.de",
            "password": "hunter2_prod_password!",
        },
        "payment": {
            "card_number": "4111 1111 1111 4242",
            "billing_note": "4532-0151-1283-0366",
        },
        "session_jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    }
    raw_body = json.dumps(payload)
    sanitized = json.loads(redactor.redact_body(raw_body))

    assert sanitized["user"]["email"].endswith("@acme-pay.de")
    assert not sanitized["user"]["email"].startswith("m.weber")
    assert sanitized["user"]["password"].startswith("<SECRET:")
    assert sanitized["payment"]["card_number"].startswith("<SECRET:")
    assert sanitized["payment"]["billing_note"] == "****-****-****-0366"
    assert sanitized["session_jwt"].startswith("<JWT:")


def test_disabled_redaction_policy_leaves_exchange_untouched() -> None:
    redactor = Redactor(RedactionPolicy(enabled=False))
    ex = HttpExchange(
        exchange_id="ex1",
        session="s1",
        captured_at="2026-10-20T00:00:00Z",
        request=RecordedRequest(
            method="POST",
            path="/login",
            headers={"Authorization": "Bearer raw-token"},
            body='{"password": "plain"}',
        ),
        response=RecordedResponse(status_code=200, body='{"ok": true}'),
    )
    out = redactor.redact_exchange(ex)
    assert out.request.headers["Authorization"] == "Bearer raw-token"
    assert out.request.body == '{"password": "plain"}'
