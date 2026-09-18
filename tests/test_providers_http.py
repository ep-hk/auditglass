"""The connectors over real HTTP, against a stub that speaks the real wire format.

Parsing is covered in ``test_providers_parse.py``. What this file covers is everything
between a planner's request and that parse: template rendering, PolicyGuard mediation,
URL and query-string construction, the constrained client, and the run loop's handling
of what comes back.

The stub records every request it receives, so the assertions are about what actually
went out on the wire — the LogQL string, the nanosecond bounds, the limit — rather
than about what the code intended to send.

What this cannot prove is that a real Loki accepts the LogQL these templates generate.
That needs a real Loki, and lives in ``tests/integration/``.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlparse

import pytest

from auditglass.build import assemble
from auditglass.config import Config
from auditglass.trigger.payload import incident_from_payload

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "query-templates"

LOG_LINES = [
    "timed out acquiring connection from pool after 5000ms",
    "connection pool exhausted: 50/50 in use, 31 waiters",
    '{"message":"upstream timeout calling payments","trace_id":"tr-0051a01",'
    '"client_ip":"203.0.113.47"}',
]


class _Stub(BaseHTTPRequestHandler):
    """Answers like Loki or Prometheus, and records what it was asked."""

    received: ClassVar[list[dict[str, Any]]] = []

    def log_message(self, *args):  # silence the default stderr spam
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        type(self).received.append(
            {"method": "GET", "path": parsed.path, "params": params}
        )

        if parsed.path.startswith("/loki/"):
            body = self._loki(params)
        elif parsed.path.startswith("/api/v1/"):
            body = self._prometheus(params)
        else:
            self.send_error(404)
            return

        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        """Recorded and refused: nothing in this tool should ever POST to a backend."""
        parsed = urlparse(self.path)
        type(self).received.append({"method": "POST", "path": parsed.path, "params": {}})
        self.send_error(405)

    @staticmethod
    def _loki(params: dict[str, str]) -> dict[str, Any]:
        query = params.get("query", "")
        service = "orders" if '"orders"' in query else "payments"
        level = "error" if 'level="error"' in query else "warn"
        start_ns = int(params.get("start", "1773453000000000000"))
        return {
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [
                    {
                        "stream": {"app": service, "level": level},
                        "values": [
                            [str(start_ns + i * 1_000_000_000), line]
                            for i, line in enumerate(LOG_LINES)
                        ],
                    }
                ],
            },
        }

    @staticmethod
    def _prometheus(params: dict[str, str]) -> dict[str, Any]:
        query = params.get("query", "")
        name = query.split("{", 1)[0] or "unknown"
        service = "orders" if 'service="orders"' in query else "payments"
        start = int(float(params.get("start", "1773453000")))
        # Saturated pool for orders, degraded latency for payments — the shape the
        # rulebook reasoner is built to recognise.
        series = {
            "connection_pool_active": [8, 50, 50],
            "connection_pool_max": [50, 50, 50],
            "request_latency_p99": [42, 900, 1307],
            "error_rate": [0.002, 0.31, 0.38],
        }.get(name, [1, 1, 1])
        return {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {"__name__": name, "service": service},
                        "values": [[start + i * 60, str(v)] for i, v in enumerate(series)],
                    }
                ],
            },
        }


@pytest.fixture
def stub():
    _Stub.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], _Stub
    finally:
        server.shutdown()
        server.server_close()


def _config(tmp_path: Path, port: int, backends: tuple[str, ...]) -> Config:
    endpoints, providers, templates = [], [], []
    if "loki" in backends:
        endpoints.append(
            {
                "name": "loki", "backend": "loki", "scheme": "http",
                "host": "127.0.0.1", "port": port, "methods": ["GET"],
                "paths": ["/loki/api/v1/query_range", "/loki/api/v1/query"],
            }
        )
        providers.append({"backend": "loki", "kind": "loki", "endpoint": "loki"})
        templates.append(TEMPLATES / "loki.yaml")
    if "prometheus" in backends:
        endpoints.append(
            {
                "name": "prom", "backend": "prometheus", "scheme": "http",
                "host": "127.0.0.1", "port": port, "methods": ["GET"],
                "paths": ["/api/v1/query", "/api/v1/query_range"],
            }
        )
        providers.append({"backend": "prometheus", "kind": "prometheus", "endpoint": "prom"})
        templates.append(TEMPLATES / "prometheus.yaml")

    return Config.model_validate(
        {
            "scope": {
                "services": ["api-gateway", "orders", "payments", "inventory-db"],
                "topology": {"orders": ["payments", "inventory-db"]},
            },
            "policy": {"endpoints": endpoints, "rate_limit_per_second": 0},
            "providers": providers,
            "template_files": templates,
            "audit": {"run_root": tmp_path / "runs"},
            "redaction": {
                "field_policy": {
                    "logs": {
                        "allow": ["timestamp", "service", "level", "message",
                                  "client_ip", "trace_id"],
                        "free_text": ["message"],
                        "pseudonymise": {"client_ip": "IP"},
                    },
                    "metrics": {"allow": ["timestamp", "service", "metric", "value"]},
                }
            },
        }
    )


ALERT = {
    "incident_id": "INC-HTTP",
    "service": "orders",
    "window": {"start": "2026-03-14T02:10:00Z", "end": "2026-03-14T02:30:00Z"},
}


# --------------------------------------------------------------------------- #


def test_loki_request_goes_out_correctly_formed(stub, tmp_path):
    port, recorder = stub
    config = _config(tmp_path, port, ("loki",))
    assembled = assemble(config)
    try:
        assembled.run.execute(incident_from_payload(ALERT, config, source="test"))
    finally:
        assembled.close()

    logs = [r for r in recorder.received if r["path"].startswith("/loki/")]
    assert logs, "no request reached the Loki stub"
    first = logs[0]

    assert first["method"] == "GET"
    assert first["path"] == "/loki/api/v1/query_range"
    # The LogQL the shipped template actually produces.
    assert first["params"]["query"] == '{app="orders"} | json | level="error"'
    # Bounds are nanoseconds, and they match the incident window.
    assert first["params"]["start"] == "1773454200000000000"
    assert first["params"]["end"] == "1773455400000000000"
    assert first["params"]["limit"] == "200"
    assert first["params"]["direction"] == "backward"


def test_prometheus_request_goes_out_correctly_formed(stub, tmp_path):
    port, recorder = stub
    config = _config(tmp_path, port, ("loki", "prometheus"))
    assembled = assemble(config)
    try:
        assembled.run.execute(incident_from_payload(ALERT, config, source="test"))
    finally:
        assembled.close()

    metrics = [r for r in recorder.received if r["path"].startswith("/api/v1/")]
    assert metrics, "the run never reached the metrics stage"
    first = metrics[0]

    assert first["path"] == "/api/v1/query_range"
    assert first["params"]["query"].startswith("connection_pool_")
    assert 'service="orders"' in first["params"]["query"]
    # Prometheus takes seconds, not nanoseconds.
    assert first["params"]["start"] == "1773454200"
    assert first["params"]["end"] == "1773455400"
    assert first["params"]["step"] == "60"


def test_nothing_is_ever_posted_to_a_backend(stub, tmp_path):
    port, recorder = stub
    config = _config(tmp_path, port, ("loki", "prometheus"))
    assembled = assemble(config)
    try:
        assembled.run.execute(incident_from_payload(ALERT, config, source="test"))
    finally:
        assembled.close()

    assert [r for r in recorder.received if r["method"] != "GET"] == []


def test_full_run_over_http_reaches_the_causal_finding(stub, tmp_path):
    """The demo's conclusion, but arrived at over the wire instead of from a fixture."""
    port, _ = stub
    config = _config(tmp_path, port, ("loki", "prometheus"))
    assembled = assemble(config)
    try:
        diagnosis = assembled.run.execute(incident_from_payload(ALERT, config, source="test"))
    finally:
        assembled.close()

    statements = " ".join(f.statement for f in diagnosis.findings).lower()
    assert "pool" in statements
    assert "payments" in statements
    assert diagnosis.rounds_used > 1

    report = (assembled.sink.run_dir / "report.md").read_text(encoding="utf-8")
    assert "## Findings" in report


def test_redaction_applies_to_records_fetched_over_http(stub, tmp_path):
    port, _ = stub
    config = _config(tmp_path, port, ("loki",))
    assembled = assemble(config)
    try:
        assembled.run.execute(incident_from_payload(ALERT, config, source="test"))
    finally:
        assembled.close()

    evidence = assembled.sink._evidence
    assert evidence
    blob = json.dumps([e.to_dict() for e in evidence])
    assert "203.0.113.47" not in blob
    assert "IP_" in blob


def test_backend_returning_an_error_envelope_becomes_a_gap_not_a_silence(tmp_path):
    """A failed query must never read as 'nothing matched'."""

    class ErrorStub(_Stub):
        @staticmethod
        def _loki(params):
            return {"status": "error", "errorType": "bad_data", "error": "parse error"}

    ErrorStub.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ErrorStub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        config = _config(tmp_path, server.server_address[1], ("loki",))
        assembled = assemble(config)
        try:
            diagnosis = assembled.run.execute(
                incident_from_payload(ALERT, config, source="test")
            )
        finally:
            assembled.close()
    finally:
        server.shutdown()
        server.server_close()

    assert diagnosis.gaps, "the failed query vanished instead of becoming a gap"
    assert any("parse error" in g.reason for g in diagnosis.gaps)
    report = (assembled.sink.run_dir / "report.md").read_text(encoding="utf-8")
    assert "## Evidence gaps" in report


def test_policy_still_refuses_an_undeclared_path_over_real_http(stub, tmp_path):
    """The guard sits in front of the wire, not beside it."""
    from auditglass.errors import PolicyViolation
    from auditglass.models import OutboundRequest

    port, recorder = stub
    config = _config(tmp_path, port, ("loki",))
    assembled = assemble(config)
    try:
        with pytest.raises(PolicyViolation):
            assembled.client.send(
                OutboundRequest(
                    method="GET", scheme="http", host="127.0.0.1", port=port,
                    path="/loki/api/v1/push", backend="loki",
                )
            )
    finally:
        assembled.close()

    assert [r for r in recorder.received if "push" in r["path"]] == []
