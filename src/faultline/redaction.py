from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from faultline.models import HttpExchange, RecordedRequest, RecordedResponse

DEFAULT_SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "stripe-signature",
        "x-hub-signature-256",
        "x-webhook-secret",
    }
)

DEFAULT_SENSITIVE_JSON_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "client_secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "id_token",
        "private_key",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
    }
)

_BEARER_RE = re.compile(r"^(Bearer|Basic|Token)\s+(.+)$", re.IGNORECASE)
_JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_CARD_DIGITS_RE = re.compile(r"^(?:\d[ -]*?){13,19}$")


def _deterministic_token(raw_value: str, salt: str, prefix: str = "REDACTED") -> str:
    # Hash with local salt so repeated requests from the same caller still share
    # the same token placeholder in captured dumps without storing the raw secret.
    digest = hashlib.sha256(f"{salt}:{raw_value}".encode()).hexdigest()[:10]
    return f"<{prefix}:{digest}>"


@dataclass(frozen=True)
class RedactionPolicy:
    enabled: bool = True
    salt: str = "faultline-local-salt"
    sensitive_headers: frozenset[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_HEADERS)
    sensitive_json_keys: frozenset[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_JSON_KEYS)
    scrub_emails: bool = True
    scrub_jwts: bool = True
    scrub_card_numbers: bool = True


class Redactor:
    def __init__(self, policy: RedactionPolicy | None = None) -> None:
        self.policy = policy or RedactionPolicy()

    def redact_headers(self, headers: dict[str, str]) -> dict[str, str]:
        if not self.policy.enabled:
            return dict(headers)
        sanitized: dict[str, str] = {}
        for key, value in headers.items():
            lower_key = key.lower()
            if lower_key in self.policy.sensitive_headers:
                match = _BEARER_RE.match(value.strip())
                if match:
                    scheme, token = match.group(1), match.group(2)
                    sanitized[key] = (
                        f"{scheme} {_deterministic_token(token, self.policy.salt, 'TOKEN')}"
                    )
                else:
                    sanitized[key] = _deterministic_token(value, self.policy.salt, "HEADER")
            else:
                sanitized[key] = value
        return sanitized

    def _redact_scalar(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        if self.policy.scrub_jwts and _JWT_RE.match(stripped):
            return _deterministic_token(stripped, self.policy.salt, "JWT")
        if self.policy.scrub_emails and _EMAIL_RE.match(stripped):
            _, domain = stripped.rsplit("@", 1)
            digest = hashlib.sha256(f"{self.policy.salt}:{stripped}".encode()).hexdigest()[:8]
            return f"redacted-{digest}@{domain}"
        if self.policy.scrub_card_numbers and _CARD_DIGITS_RE.match(stripped):
            digits = "".join(ch for ch in stripped if ch.isdigit())
            if 13 <= len(digits) <= 19:
                return f"****-****-****-{digits[-4:]}"
        return value

    def redact_json_value(self, value: Any, parent_key: str | None = None) -> Any:
        if not self.policy.enabled:
            return value
        if parent_key and parent_key.lower() in self.policy.sensitive_json_keys:
            if value is None:
                return None
            return _deterministic_token(str(value), self.policy.salt, "SECRET")

        if isinstance(value, dict):
            return {
                str(k): self.redact_json_value(v, parent_key=str(k)) for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.redact_json_value(item, parent_key=parent_key) for item in value]
        return self._redact_scalar(value)

    def redact_body(self, body: str) -> str:
        if not self.policy.enabled or not body or not body.strip():
            return body
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError):
            return body
        sanitized = self.redact_json_value(parsed)
        return json.dumps(sanitized, separators=(",", ":"), sort_keys=False)

    def redact_request(self, request: RecordedRequest) -> RecordedRequest:
        if not self.policy.enabled:
            return request
        sanitized_query: dict[str, str] = {}
        for k, v in request.query_params.items():
            if k.lower() in self.policy.sensitive_json_keys:
                sanitized_query[k] = _deterministic_token(v, self.policy.salt, "QUERY")
            else:
                sanitized_query[k] = v
        return RecordedRequest(
            method=request.method,
            path=request.path,
            headers=self.redact_headers(request.headers),
            body=self.redact_body(request.body),
            query_params=sanitized_query,
        )

    def redact_response(self, response: RecordedResponse) -> RecordedResponse:
        if not self.policy.enabled:
            return response
        return RecordedResponse(
            status_code=response.status_code,
            headers=self.redact_headers(response.headers),
            body=self.redact_body(response.body),
            latency_ms=response.latency_ms,
        )

    def redact_exchange(self, exchange: HttpExchange) -> HttpExchange:
        if not self.policy.enabled:
            return exchange
        req = self.redact_request(exchange.request)
        resp = self.redact_response(exchange.response)
        return HttpExchange(
            exchange_id=exchange.exchange_id,
            session=exchange.session,
            captured_at=exchange.captured_at,
            request=req,
            response=resp,
            tags=dict(exchange.tags),
        )
