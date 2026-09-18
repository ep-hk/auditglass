"""The one thing no stub can establish: that real servers accept these queries.

Everything else about the connectors is covered without a backend —
``test_providers_parse.py`` for response handling, ``test_providers_http.py`` for
request construction and policy mediation over real HTTP. What remains is whether a
real Loki parses the LogQL these templates generate, and whether a real Prometheus
parses the PromQL. Only Loki and Prometheus can answer that.

Skipped unless ``AUDITGLASS_LIVE=1``, so the ordinary suite still needs nothing::

    docker compose -f demo/docker-compose.yml up -d
    sleep 90                       # let a usable time range accumulate
    AUDITGLASS_LIVE=1 pytest tests/integration -v
    docker compose -f demo/docker-compose.yml down -v

The assertion that matters is not "findings were produced" — a run produces a report
even when everything failed, by design. It is that **no evidence gap names a query
error**. A gap saying "parse error at line 1" is a broken template, and it is exactly
the failure the offline tests cannot see.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta
from pathlib import Path

import pytest

from auditglass.build import assemble
from auditglass.config import load_config
from auditglass.errors import PolicyViolation
from auditglass.models import OutboundRequest, TimeWindow, utcnow
from auditglass.trigger.payload import incident_from_payload

pytestmark = pytest.mark.skipif(
    os.environ.get("AUDITGLASS_LIVE") != "1",
    reason="live backends not running; set AUDITGLASS_LIVE=1 with demo/docker-compose.yml up",
)

CONFIG = Path(__file__).resolve().parents[2] / "config" / "demo-live.yaml"
LOKI = os.environ.get("LOKI_URL", "http://127.0.0.1:3100")
PROM = os.environ.get("PROM_URL", "http://127.0.0.1:9090")


def _get(url: str, timeout: int = 5):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def _wait_for_data(timeout: int = 180) -> None:
    """Block until both backends actually hold samples for the incident window."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            logs = _get(
                f"{LOKI}/loki/api/v1/query_range?query="
                + urllib.parse.quote('{app="orders"}')
                + f"&start={int((time.time() - 300) * 1e9)}&end={int(time.time() * 1e9)}&limit=5"
            )
            metrics = _get(f"{PROM}/api/v1/query?query=connection_pool_active")
            have_logs = bool(logs.get("data", {}).get("result"))
            have_metrics = bool(metrics.get("data", {}).get("result"))
            if have_logs and have_metrics:
                # Give Prometheus a couple more scrapes so a range query has shape.
                time.sleep(15)
                return
            last = f"logs={have_logs} metrics={have_metrics}"
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(5)
    pytest.fail(f"backends never produced data within {timeout}s ({last})")


@pytest.fixture(scope="module")
def live():
    _wait_for_data()


@pytest.fixture
def config(tmp_path):
    cfg = load_config(CONFIG)
    cfg.audit.run_root = tmp_path / "runs"
    return cfg


def _recent_incident(config, minutes: int = 5):
    end = utcnow()
    window = TimeWindow(end - timedelta(minutes=minutes), end)
    return incident_from_payload(
        {"incident_id": "INC-LIVE", "service": "orders", "window": window.to_dict()},
        config,
        source="integration-test",
    )


# --------------------------------------------------------------------------- #


def test_real_loki_accepts_the_generated_logql(live, config):
    assembled = assemble(config)
    try:
        diagnosis = assembled.run.execute(_recent_incident(config))
    finally:
        assembled.close()

    query_failures = [
        g for g in diagnosis.gaps if "unavailable" in g.reason or "error response" in g.reason
    ]
    assert not query_failures, f"a backend rejected a generated query: {query_failures}"

    logs = [e for e in assembled.sink._evidence if e.kind == "logs"]
    assert logs, "no log evidence came back from a live Loki"
    assert any(e.records for e in logs)


def test_real_prometheus_accepts_the_generated_promql(live, config):
    assembled = assemble(config)
    try:
        diagnosis = assembled.run.execute(_recent_incident(config))
    finally:
        assembled.close()

    metrics = [e for e in assembled.sink._evidence if e.kind == "metrics"]
    assert metrics, "the run never reached the metrics stage against live Prometheus"
    assert any(e.records for e in metrics), "Prometheus returned no samples"
    assert not [g for g in diagnosis.gaps if "error response" in g.reason]


def test_records_come_back_in_the_shape_the_field_policy_expects(live, config):
    """A connector can parse without producing the fields the rest of the tool needs."""
    assembled = assemble(config)
    try:
        assembled.run.execute(_recent_incident(config))
    finally:
        assembled.close()

    for evidence in assembled.sink._evidence:
        for record in evidence.records[:20]:
            assert "timestamp" in record
            assert "service" in record
            if evidence.kind == "logs":
                assert "message" in record
            else:
                assert "metric" in record and "value" in record


def test_pseudonymisation_applied_to_live_records(live, config):
    assembled = assemble(config)
    try:
        assembled.run.execute(_recent_incident(config))
    finally:
        assembled.close()

    blob = json.dumps([e.to_dict() for e in assembled.sink._evidence])
    for raw in ("203.0.113.47", "203.0.113.19", "198.51.100.8", "192.0.2.144"):
        assert raw not in blob, f"{raw} reached the evidence unredacted"


def test_injected_line_is_marked_when_present(live, config):
    """The seeder plants one once the incident has ramped; tolerate it not being there yet."""
    assembled = assemble(config)
    try:
        assembled.run.execute(_recent_incident(config))
    finally:
        assembled.close()

    blob = json.dumps([e.to_dict() for e in assembled.sink._evidence])
    if "Ignore all previous" in blob:
        assert any(e.injection_suspected for e in assembled.sink._evidence)


def test_the_write_endpoint_is_refused_against_a_real_loki(live, config):
    """The seeder pushes through this path. This tool must not be able to."""
    assembled = assemble(config)
    try:
        with pytest.raises(PolicyViolation):
            assembled.client.send(
                OutboundRequest(
                    method="POST", scheme="http", host="127.0.0.1", port=3100,
                    path="/loki/api/v1/push", backend="loki",
                    body={"streams": []},
                )
            )
    finally:
        assembled.close()

    # And confirm the path really is live, so the refusal means something.
    request = urllib.request.Request(
        f"{LOKI}/loki/api/v1/push",
        data=json.dumps({"streams": []}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status < 500, "the write path should exist and accept requests"


def test_report_is_produced_from_live_evidence(live, config):
    assembled = assemble(config)
    try:
        assembled.run.execute(_recent_incident(config))
    finally:
        assembled.close()

    report = (assembled.sink.run_dir / "report.md").read_text(encoding="utf-8")
    assert "## Findings" in report
    assert "## Evidence" in report
    manifest = json.loads((assembled.sink.run_dir / "manifest.json").read_text())
    assert manifest["status"] == "complete"
