from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from faultline.proxy import RecordingReverseProxy
from faultline.replay import ReplayEngine, ReplayOptions
from faultline.storage import ExchangeStore


class _MockUpstreamServer:
    def __init__(self, mode: str = "v1") -> None:
        self.mode = mode
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> str:
        parent = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                _ = self.rfile.read(length) if length > 0 else b""
                if parent.mode == "v1":
                    payload = {
                        "id": "evt_100",
                        "status": "succeeded",
                        "amount_cents": 4900,
                        "request_id": "req_v1_dynamic",
                    }
                    code = 200
                else:
                    payload = {
                        "id": "evt_100",
                        "status": 1,
                        "request_id": "req_v2_dynamic",
                    }
                    code = 200

                raw = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self._httpd.server_port}"

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def test_end_to_end_proxy_capture_and_shadow_replay(tmp_path: Path) -> None:
    store = ExchangeStore(tmp_path / "e2e.db")
    upstream_v1 = _MockUpstreamServer(mode="v1")
    upstream_v2 = _MockUpstreamServer(mode="v2")

    v1_url = upstream_v1.start()
    v2_url = upstream_v2.start()
    proxy = RecordingReverseProxy(
        listen_host="127.0.0.1",
        listen_port=0,
        upstream_url=v1_url,
        session="stripe-webhooks",
        store=store,
    )
    proxy_url = proxy.start_background()

    try:
        req = urllib.request.Request(
            url=f"{proxy_url}/v1/webhooks/stripe",
            data=b'{"event": "charge.succeeded", "secret": "whsec_999"}',
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer sk_live_secret123",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            assert resp.status == 200
            body = json.loads(resp.read().decode("utf-8"))
            assert body["amount_cents"] == 4900

        captured = store.list_exchanges(session="stripe-webhooks")
        assert len(captured) == 1
        assert "sk_live_secret123" not in captured[0].request.headers["Authorization"]
        assert "whsec_999" not in captured[0].request.body

        engine_v1 = ReplayEngine(ReplayOptions(target_url=v1_url, concurrency=2))
        report_v1 = engine_v1.run(captured, session_name="stripe-webhooks")
        assert report_v1.passed
        assert report_v1.breaking_count == 0

        engine_v2 = ReplayEngine(ReplayOptions(target_url=v2_url, concurrency=2))
        report_v2 = engine_v2.run(captured, session_name="stripe-webhooks")
        assert not report_v2.passed
        assert report_v2.breaking_count == 1
        violation_paths = {v.path for v in report_v2.comparisons[0].violations}
        assert "$.amount_cents" in violation_paths
        assert "$.status" in violation_paths
    finally:
        proxy.stop()
        upstream_v1.stop()
        upstream_v2.stop()
        store.close()
