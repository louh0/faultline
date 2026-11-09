# faultline

Local HTTP/webhook capture proxy, replay runner, and structural API contract differ.

I built `faultline` after getting burned a few times by backend serializer refactors (mostly Pydantic v1 -> v2 and SQLAlchemy response mappings) where unit tests passed against mocked fixtures, but staging webhooks broke because a nested integer turned into a string or an optional field started returning `null`. Tools like GoReplay require `libpcap` / root access, and full contract testing frameworks require maintaining separate consumer/provider specs.

`faultline` sits in front of a local or staging service as a reverse proxy, records HTTP request/response pairs into a local SQLite database (WAL mode), scrubs auth headers and PII before writing to disk, and replays captured sessions against a candidate build to flag breaking schema drift or latency regressions.

## Install

Requires Python 3.9+. No third-party runtime dependencies (uses stdlib `sqlite3`, `http.server`, `urllib`, `concurrent.futures`).

```bash
git clone https://github.com/louh0/faultline.git
cd faultline
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick example

Two sample fixture files (`payments_v1_baseline.jsonl` and `payments_v2_candidate.jsonl`) are checked into `fixtures/` to test offline diffing without spinning up a server:

```bash
faultline diff \
  --baseline fixtures/payments_v1_baseline.jsonl \
  --candidate fixtures/payments_v2_candidate.jsonl
```

Output:
```text
Faultline Contract Report :: session=fixtures/payments_v1_baseline.jsonl
==========================================================================
Target   : offline://fixtures/payments_v2_candidate.jsonl
Verdict  : FAIL (breaking contract drift)
Exchanges: 3 total | 2 passed | 1 breaking | 0 warnings
Latency  : p50/p95 baseline 18.40ms / 21.73ms -> candidate 19.10ms / 20.36ms (p95 delta: -1.37ms)
--------------------------------------------------------------------------
[PASS ] ex_8f91a02c1001  POST   /v1/charges                        201->201  (18.4ms -> 19.1ms)
        - [INFO] field_added at $.settlement_tier: New field '$.settlement_tier' added to response (string)
[BREAK] ex_8f91a02c1002  GET    /v1/customers/48102/balance        200->200  (9.2ms -> 14.8ms)
        - [BREAKING] field_removed at $.pending_cents: Required field '$.pending_cents' was removed from response
        - [BREAKING] type_changed at $.customer_id: Type mismatch at '$.customer_id': expected integer, got string
        - [BREAKING] nullability_changed at $.overdraft_protection: Field '$.overdraft_protection' became null (expected boolean)
[PASS ] ex_8f91a02c1003  POST   /v1/refunds                        200->200  (22.1ms -> 20.5ms)
```

## Usage

### 1. Record live traffic
Run the recording reverse proxy on port `9090` forwarding to your local service on port `8000`:

```bash
faultline record \
  --listen 127.0.0.1:9090 \
  --upstream http://127.0.0.1:8000 \
  --session billing-v1
```

By default, exchanges are stored in `.faultline/traffic.db` (override with `--db`).

### 2. Inspect sessions and infer schemas
```bash
# summary of all recorded sessions
faultline sessions

# list exchanges in a session (use --dedupe to collapse identical payload shapes)
faultline sessions --session billing-v1 --dedupe

# inspect a single exchange by ID prefix
faultline inspect ex_8f91a0

# generate a merged Draft 2020-12 JSON Schema across responses in a session
faultline schema --session billing-v1 --path-prefix /v1/charges
```

### 3. Replay against a candidate build
```bash
faultline replay \
  --session billing-v1 \
  --target http://127.0.0.1:8001 \
  --concurrency 8 \
  --rate-limit 50 \
  --max-latency-regression-ms 25.0 \
  --dedupe
```

`faultline replay` and `faultline diff` exit with `0` if no breaking contract violations are found, `1` on usage/storage errors, and `2` when breaking drift is detected. Pass `--format json` or `--format markdown` for CI output.

### 4. Export / import fixtures
Sessions can be exported to newline-delimited JSON (`.jsonl`) or HTTP Archive (`.har` 1.2) files so regression fixtures can be committed to git:

```bash
faultline export --session billing-v1 --output fixtures/billing.jsonl
faultline import --input fixtures/billing.jsonl --session billing-restored
```

## Design notes

- **Structural fingerprinting (`models.py`)**: Replaying 5,000 identical webhook deliveries wastes time. When an exchange is recorded, dynamic URL segments (numeric IDs, UUIDs, 16+ char hex tokens) are normalized into placeholders (`/v1/customers/:id/balance`) and JSON bodies are reduced to recursive type skeletons. Hashing `(method, route_template, status, req_skeleton, resp_skeleton)` produces a 16-char fingerprint used by `--dedupe`.
- **Correlation-preserving redaction (`redaction.py`)**: Masking every `Authorization` header or secret field with a static `"REDACTED"` string makes it impossible to tell if two requests in a session came from the same caller. `Redactor` hashes sensitive headers (`Authorization`, `Cookie`, `X-Api-Key`, `Stripe-Signature`), JSON secret keys, JWTs, and emails with a local salt (`Bearer <TOKEN:84d91a0c11>`, `redacted-7f01a9c2@acme.io`) so correlation is preserved without writing raw secrets to SQLite.
- **Diff rules (`differ.py`)**: Adding a new field to a JSON response is logged as `INFO` (unless `--fail-on-added` is passed), whereas status class changes (`2xx -> 4xx/5xx`), missing fields (`field_removed`), incompatible type changes (`integer -> string`), and non-null fields becoming `null` (`nullability_changed`) are flagged as `BREAKING`. Dynamic metadata paths (`$.request_id`, `$.trace_id`, `$.timestamp`, `$.meta.request_id`, etc.) are ignored by default and can be extended via `--ignore-path`.
- **Rate limiting & concurrency (`ratelimit.py`, `replay.py`)**: Replay uses a bounded `ThreadPoolExecutor` gated by a monotonic clock token-bucket limiter so replaying a large capture session doesn't accidentally overwhelm a local or staging server.

## Running tests

```bash
make check
# or directly:
pytest
mypy src tests
ruff check src tests
```

## TODO
- [ ] `faultline openapi`: synthesize OpenAPI 3.1 specs from captured sessions grouped by `(method, route_template)`
- [ ] Chaos / fault injection flags on `faultline record` (`--chaos-latency-ms`, `--chaos-error-rate`) for testing client retries
- [ ] Stateful parameter correlation across chained requests (extract ID from `POST` response and substitute into subsequent `GET` paths)
- [ ] Optional HMAC header re-signing (`Stripe-Signature`, `X-Hub-Signature-256`) during replay

## License

MIT
