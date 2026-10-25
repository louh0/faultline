from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from faultline.models import (
    CaptureSessionSummary,
    HttpExchange,
    RecordedRequest,
    RecordedResponse,
)

SCHEMA_VERSION = 2

_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exchanges (
    exchange_id TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    route_template TEXT NOT NULL,
    request_headers TEXT NOT NULL,
    request_body TEXT NOT NULL,
    query_params TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_headers TEXT NOT NULL,
    response_body TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    fingerprint TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_exchanges_session ON exchanges(session, captured_at);
CREATE INDEX IF NOT EXISTS idx_exchanges_fingerprint ON exchanges(session, fingerprint);
CREATE INDEX IF NOT EXISTS idx_exchanges_status ON exchanges(session, status_code);
"""


class ExchangeStore:
    def __init__(self, db_path: str | Path = ".faultline/traffic.db") -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._persistent_conn: sqlite3.Connection | None = None
        if self.db_path == ":memory:":
            self._persistent_conn = self._create_connection()
        self._init_schema()

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _conn(self) -> sqlite3.Connection:
        if self._persistent_conn is not None:
            return self._persistent_conn
        return self._create_connection()

    def _init_schema(self) -> None:
        conn = self._conn()
        try:
            with conn:
                conn.executescript(_DDL)
                cur = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM schema_migrations WHERE version = ?",
                    (SCHEMA_VERSION,),
                )
                row = cur.fetchone()
                if row and int(row["cnt"]) == 0:
                    now = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                        (SCHEMA_VERSION, now),
                    )
        finally:
            if self._persistent_conn is None:
                conn.close()

    def close(self) -> None:
        if self._persistent_conn is not None:
            self._persistent_conn.close()
            self._persistent_conn = None

    def save_exchange(self, exchange: HttpExchange) -> None:
        conn = self._conn()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO exchanges (
                        exchange_id, session, captured_at, method, path, route_template,
                        request_headers, request_body, query_params,
                        status_code, response_headers, response_body,
                        latency_ms, fingerprint, tags
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        exchange.exchange_id,
                        exchange.session,
                        exchange.captured_at,
                        exchange.request.method,
                        exchange.request.path,
                        exchange.route_template,
                        json.dumps(exchange.request.headers, sort_keys=True),
                        exchange.request.body,
                        json.dumps(exchange.request.query_params, sort_keys=True),
                        exchange.response.status_code,
                        json.dumps(exchange.response.headers, sort_keys=True),
                        exchange.response.body,
                        exchange.response.latency_ms,
                        exchange.fingerprint,
                        json.dumps(exchange.tags, sort_keys=True),
                    ),
                )
        finally:
            if self._persistent_conn is None:
                conn.close()

    def save_many(self, exchanges: list[HttpExchange]) -> int:
        if not exchanges:
            return 0
        conn = self._conn()
        try:
            with conn:
                conn.executemany(
                    """
                    INSERT OR REPLACE INTO exchanges (
                        exchange_id, session, captured_at, method, path, route_template,
                        request_headers, request_body, query_params,
                        status_code, response_headers, response_body,
                        latency_ms, fingerprint, tags
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            ex.exchange_id,
                            ex.session,
                            ex.captured_at,
                            ex.request.method,
                            ex.request.path,
                            ex.route_template,
                            json.dumps(ex.request.headers, sort_keys=True),
                            ex.request.body,
                            json.dumps(ex.request.query_params, sort_keys=True),
                            ex.response.status_code,
                            json.dumps(ex.response.headers, sort_keys=True),
                            ex.response.body,
                            ex.response.latency_ms,
                            ex.fingerprint,
                            json.dumps(ex.tags, sort_keys=True),
                        )
                        for ex in exchanges
                    ],
                )
            return len(exchanges)
        finally:
            if self._persistent_conn is None:
                conn.close()

    @staticmethod
    def _row_to_exchange(row: sqlite3.Row) -> HttpExchange:
        req = RecordedRequest(
            method=str(row["method"]),
            path=str(row["path"]),
            headers=json.loads(str(row["request_headers"])),
            body=str(row["request_body"]),
            query_params=json.loads(str(row["query_params"])),
        )
        resp = RecordedResponse(
            status_code=int(row["status_code"]),
            headers=json.loads(str(row["response_headers"])),
            body=str(row["response_body"]),
            latency_ms=float(row["latency_ms"]),
        )
        return HttpExchange(
            exchange_id=str(row["exchange_id"]),
            session=str(row["session"]),
            captured_at=str(row["captured_at"]),
            request=req,
            response=resp,
            fingerprint=str(row["fingerprint"]),
            tags=json.loads(str(row["tags"])),
        )

    def get_exchange(self, exchange_id: str) -> HttpExchange | None:
        conn = self._conn()
        try:
            cur = conn.execute(
                "SELECT * FROM exchanges WHERE exchange_id = ? OR exchange_id LIKE ?",
                (exchange_id, f"{exchange_id}%"),
            )
            row = cur.fetchone()
            return self._row_to_exchange(row) if row else None
        finally:
            if self._persistent_conn is None:
                conn.close()

    def list_exchanges(
        self,
        session: str | None = None,
        method: str | None = None,
        path_prefix: str | None = None,
        status_code: int | None = None,
        deduplicate_fingerprints: bool = False,
        limit: int | None = None,
    ) -> list[HttpExchange]:
        clauses: list[str] = []
        params: list[Any] = []
        if session:
            clauses.append("session = ?")
            params.append(session)
        if method:
            clauses.append("method = ?")
            params.append(method.upper())
        if path_prefix:
            clauses.append("path LIKE ?")
            params.append(f"{path_prefix}%")
        if status_code is not None:
            clauses.append("status_code = ?")
            params.append(status_code)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM exchanges {where_sql} ORDER BY captured_at ASC, exchange_id ASC"
        if limit is not None and not deduplicate_fingerprints:
            sql += f" LIMIT {int(limit)}"

        conn = self._conn()
        try:
            cur = conn.execute(sql, params)
            exchanges = [self._row_to_exchange(r) for r in cur.fetchall()]
        finally:
            if self._persistent_conn is None:
                conn.close()

        if deduplicate_fingerprints:
            seen: set[str] = set()
            deduped: list[HttpExchange] = []
            for ex in exchanges:
                if ex.fingerprint not in seen:
                    seen.add(ex.fingerprint)
                    deduped.append(ex)
            exchanges = deduped
            if limit is not None:
                exchanges = exchanges[:limit]

        return exchanges

    def list_sessions(self) -> list[CaptureSessionSummary]:
        conn = self._conn()
        try:
            cur = conn.execute(
                """
                SELECT
                    session,
                    COUNT(*) AS exchange_count,
                    COUNT(DISTINCT fingerprint) AS unique_fingerprints,
                    MIN(captured_at) AS first_captured_at,
                    MAX(captured_at) AS last_captured_at,
                    AVG(latency_ms) AS avg_latency_ms,
                    SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS error_count
                FROM exchanges
                GROUP BY session
                ORDER BY last_captured_at DESC
                """
            )
            summaries: list[CaptureSessionSummary] = []
            for row in cur.fetchall():
                summaries.append(
                    CaptureSessionSummary(
                        session=str(row["session"]),
                        exchange_count=int(row["exchange_count"]),
                        unique_fingerprints=int(row["unique_fingerprints"]),
                        first_captured_at=str(row["first_captured_at"]),
                        last_captured_at=str(row["last_captured_at"]),
                        avg_latency_ms=round(float(row["avg_latency_ms"] or 0.0), 2),
                        error_count=int(row["error_count"] or 0),
                    )
                )
            return summaries
        finally:
            if self._persistent_conn is None:
                conn.close()

    def delete_session(self, session: str) -> int:
        conn = self._conn()
        try:
            with conn:
                cur = conn.execute("DELETE FROM exchanges WHERE session = ?", (session,))
                return int(cur.rowcount)
        finally:
            if self._persistent_conn is None:
                conn.close()


def export_jsonl(exchanges: list[HttpExchange], output_path: str | Path) -> int:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for ex in exchanges:
            fh.write(json.dumps(ex.to_dict(), sort_keys=True) + "\n")
    return len(exchanges)


def import_jsonl(input_path: str | Path, override_session: str | None = None) -> list[HttpExchange]:
    path = Path(input_path)
    exchanges: list[HttpExchange] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped:
                continue
            raw = json.loads(stripped)
            if override_session:
                raw["session"] = override_session
            exchanges.append(HttpExchange.from_dict(raw))
    return exchanges


def export_har(exchanges: list[HttpExchange], output_path: str | Path) -> int:
    entries: list[dict[str, Any]] = []
    for ex in exchanges:
        entries.append(
            {
                "startedDateTime": ex.captured_at,
                "time": ex.response.latency_ms,
                "request": {
                    "method": ex.request.method,
                    "url": f"http://localhost{ex.request.path}",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": k, "value": v} for k, v in ex.request.headers.items()
                    ],
                    "queryString": [
                        {"name": k, "value": v} for k, v in ex.request.query_params.items()
                    ],
                    "postData": {
                        "mimeType": ex.request.header("content-type", "application/json")
                        or "application/json",
                        "text": ex.request.body,
                    }
                    if ex.request.body
                    else {},
                },
                "response": {
                    "status": ex.response.status_code,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [
                        {"name": k, "value": v} for k, v in ex.response.headers.items()
                    ],
                    "content": {
                        "size": len(ex.response.body.encode("utf-8")),
                        "mimeType": ex.response.header("content-type", "application/json")
                        or "application/json",
                        "text": ex.response.body,
                    },
                },
                "timings": {"send": 0, "wait": ex.response.latency_ms, "receive": 0},
            }
        )
    har_doc = {
        "log": {
            "version": "1.2",
            "creator": {"name": "faultline", "version": "0.4.2"},
            "entries": entries,
        }
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(har_doc, indent=2), encoding="utf-8")
    return len(entries)


def import_har(input_path: str | Path, session: str = "imported-har") -> list[HttpExchange]:
    raw = json.loads(Path(input_path).read_text(encoding="utf-8"))
    entries = raw.get("log", {}).get("entries", [])
    exchanges: list[HttpExchange] = []
    for entry in entries:
        req_raw = entry.get("request", {})
        resp_raw = entry.get("response", {})
        parsed_url = urlsplit(str(req_raw.get("url", "/")))
        full_path = parsed_url.path or "/"
        if parsed_url.query:
            full_path = f"{full_path}?{parsed_url.query}"
        req_headers = {
            str(h["name"]): str(h["value"]) for h in req_raw.get("headers", []) if "name" in h
        }
        resp_headers = {
            str(h["name"]): str(h["value"]) for h in resp_raw.get("headers", []) if "name" in h
        }
        query_params = dict(parse_qsl(parsed_url.query, keep_blank_values=True))
        post_data = req_raw.get("postData") or {}
        req = RecordedRequest(
            method=str(req_raw.get("method", "GET")).upper(),
            path=full_path,
            headers=req_headers,
            body=str(post_data.get("text", "")),
            query_params=query_params,
        )
        content = resp_raw.get("content") or {}
        resp = RecordedResponse(
            status_code=int(resp_raw.get("status", 200)),
            headers=resp_headers,
            body=str(content.get("text", "")),
            latency_ms=float(entry.get("time", 0.0)),
        )
        exchanges.append(
            HttpExchange(
                exchange_id=uuid.uuid4().hex[:12],
                session=session,
                captured_at=str(
                    entry.get("startedDateTime") or datetime.now(timezone.utc).isoformat()
                ),
                request=req,
                response=resp,
            )
        )
    return exchanges
