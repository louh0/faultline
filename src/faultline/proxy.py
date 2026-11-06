from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import parse_qsl, urlsplit

from faultline.models import HttpExchange, RecordedRequest, RecordedResponse
from faultline.redaction import Redactor
from faultline.replay import HOP_BY_HOP_HEADERS, TransportCallable, default_http_transport
from faultline.storage import ExchangeStore


class RecordingReverseProxy:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        upstream_url: str,
        session: str,
        store: ExchangeStore,
        redactor: Redactor | None = None,
        timeout_sec: float = 15.0,
        transport: TransportCallable | None = None,
        on_capture: Callable[[HttpExchange], None] | None = None,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_url = upstream_url.rstrip("/")
        self.session = session
        self.store = store
        self.redactor = redactor or Redactor()
        self.timeout_sec = timeout_sec
        self.transport = transport or default_http_transport
        self.on_capture = on_capture
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def bound_port(self) -> int:
        if self._httpd is not None:
            return int(self._httpd.server_port)
        return self.listen_port

    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        proxy = self

        class _ProxyHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def _handle_any_method(self) -> None:
                content_len = int(self.headers.get("Content-Length", "0") or "0")
                raw_body = self.rfile.read(content_len) if content_len > 0 else b""
                body_text = raw_body.decode("utf-8", errors="replace")

                parsed_url = urlsplit(self.path)
                query_params = dict(parse_qsl(parsed_url.query, keep_blank_values=True))
                req_headers = {str(k): str(v) for k, v in self.headers.items()}

                live_req = RecordedRequest(
                    method=self.command.upper(),
                    path=self.path,
                    headers=req_headers,
                    body=body_text,
                    query_params=query_params,
                )

                try:
                    live_resp = proxy.transport(live_req, proxy.upstream_url, proxy.timeout_sec)
                except Exception as exc:
                    err_payload = f'{{"error":"bad_gateway","detail":"{exc}"}}'
                    live_resp = RecordedResponse(
                        status_code=502,
                        headers={"Content-Type": "application/json"},
                        body=err_payload,
                        latency_ms=0.0,
                    )

                # Persist before writing the response back so callers querying
                # the store immediately after response completion see the record.
                raw_exchange = HttpExchange(
                    exchange_id=uuid.uuid4().hex[:12],
                    session=proxy.session,
                    captured_at=datetime.now(timezone.utc).isoformat(),
                    request=live_req,
                    response=live_resp,
                )
                sanitized = proxy.redactor.redact_exchange(raw_exchange)
                proxy.store.save_exchange(sanitized)
                if proxy.on_capture is not None:
                    proxy.on_capture(sanitized)

                resp_bytes = live_resp.body.encode("utf-8")
                self.send_response(live_resp.status_code)
                for hk, hv in live_resp.headers.items():
                    if hk.lower() not in HOP_BY_HOP_HEADERS:
                        self.send_header(hk, hv)
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command.upper() != "HEAD":
                    self.wfile.write(resp_bytes)
                self.wfile.flush()

            def do_GET(self) -> None:
                self._handle_any_method()

            def do_POST(self) -> None:
                self._handle_any_method()

            def do_PUT(self) -> None:
                self._handle_any_method()

            def do_PATCH(self) -> None:
                self._handle_any_method()

            def do_DELETE(self) -> None:
                self._handle_any_method()

            def do_HEAD(self) -> None:
                self._handle_any_method()

            def do_OPTIONS(self) -> None:
                self._handle_any_method()

        return _ProxyHandler

    def start_background(self) -> str:
        handler_cls = self._build_handler()
        self._httpd = ThreadingHTTPServer((self.listen_host, self.listen_port), handler_cls)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name=f"faultline-proxy-{self.session}",
            daemon=True,
        )
        self._thread.start()
        return f"http://{self.listen_host}:{self.bound_port}"

    def serve_forever(self) -> None:
        handler_cls = self._build_handler()
        self._httpd = ThreadingHTTPServer((self.listen_host, self.listen_port), handler_cls)
        try:
            self._httpd.serve_forever()
        finally:
            self._httpd.server_close()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            self._thread = None
