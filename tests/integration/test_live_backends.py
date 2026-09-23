"""The one thing no stub can establish: that real servers accept these queries.

Everything else about the connectors is covered without a backend —
``test_providers_parse.py`` for response handling, ``test_providers_http.py`` for
request construction and policy mediation over real HTTP. What remains is whether a
real Loki parses the LogQL these templates generate, whether a real Prometheus parses
the PromQL, and whether the whole diagnosis still reaches its conclusion when the
evidence comes from real servers rather than a fixture.

Skipped unless ``AUDITGLASS_LIVE=1``, so the ordinary suite still needs nothing::

    docker compose -f demo/docker-compose.yml up -d --wait
    AUDITGLASS_LIVE=1 pytest tests/integration -v
    docker compose -f demo/docker-compose.yml down -v

Three lessons are built into this file, all learned from running it.

**Wait for the incident, not for data.** The seeder spends a healthy period before
the incident starts. The first version waited only for *any* log line to exist, so it
ran during the healthy period, asked for ``level="error"``, and got a correct but
empty answer. The wait now blocks until the connection pool is actually saturated,
which is the last thing to happen.

**The diagnosis needs a baseline, and a baseline needs history.** Prometheus is
sampled at a 60s step. A stack that has been up for a minute gives one point per
series, and one point cannot show a rise — so the run correctly reported the pool
saturation but not the latency behind it, and a loose assertion still passed. The
seeder now stays healthy for longer than one step, the wait checks that a healthy
sample really is one step back, and the causal assertion names the exact findings.

**No assertion may pass on an empty list.** A shape check that iterates over zero
records passes while proving nothing. Every test here first asserts there is
something to check.
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
from auditglass.models import Confidence, OutboundRequest, TimeWindow, utcnow
from auditglass.trigger.payload import incident_from_payload

pytestmark = pytest.mark.skipif(
    os.environ.get("AUDITGLASS_LIVE") != "1",
    reason="live backends not running; set AUDITGLASS_LIVE=1 with demo/docker-compose.yml up",
)

CONFIG = Path(__file__).resolve().parents[2] / "config" / "demo-live.yaml"
LOKI = os.environ.get("LOKI_URL", "http://127.0.0.1:3100")
PROM = os.environ.get("PROM_URL", "http://127.0.0.1:9090")
SEEDER_IPS = ("203.0.113.47", "203.0.113.19", "198.51.100.8", "192.0.2.144")

#: The pool ceiling is 50. The rulebook calls it saturated at 95%.
SATURATED = 48.0
#: The default step of ``metrics.by_service_metric``.
STEP_SECONDS = 60
#: Payments p99 is 42ms while healthy and 1307ms at the peak.
HEALTHY_LATENCY_BELOW = 100.0


def _get(url: str, timeout: int = 5):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def _instant(query: str, at: float | None = None) -> float | None:
    url = f"{PROM}/api/v1/query?query={urllib.parse.quote(query)}"
    if at is not None:
        url += f"&time={at:.3f}"
    result = _get(url).get("data", {}).get("result") or []
    return float(result[0]["value"][1]) if result else None


def _pool_active() -> float | None:
    return _instant("connection_pool_active")


def _error_lines(seconds: int = 300) -> int:
    now = time.time()
    query = urllib.parse.quote('{app="orders", level="error"}')
    body = _get(
        f"{LOKI}/loki/api/v1/query_range?query={query}"
        f"&start={int((now - seconds) * 1e9)}&end={int(now * 1e9)}&limit=1000"
    )
    return sum(len(s.get("values", [])) for s in body.get("data", {}).get("result", []))


def _wait_for_incident(timeout: int = 240) -> None:
    """Block until the incident has fully developed on both backends."""
    deadline = time.time() + timeout
    last = "no response yet"
    while time.time() < deadline:
        try:
            pool = _pool_active()
            errors = _error_lines()
            last = f"pool={pool} error_lines={errors}"
            if pool is not None and pool >= SATURATED and errors >= 5:
                # Two more scrapes so the saturated plateau is in the range too.
                time.sleep(12)
                _require_baseline()
                return
        except (urllib.error.URLError, OSError, ValueError, KeyError, IndexError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        time.sleep(3)
    pytest.fail(f"incident never developed within {timeout}s ({last})")


def _require_baseline() -> None:
    """Fail clearly if the harness, rather than the tool, would sink the diagnosis.

    The range query the run makes samples every ``STEP_SECONDS`` back from now. If
    the sample one step back is not yet healthy-looking, the run can see only the
    peak, and its silence about latency would be a property of this stack's short
    history, not of the connectors.
    """
    one_step_back = time.time() - STEP_SECONDS
    value = _instant('request_latency_p99{service="payments"}', at=one_step_back)
    if value is None or value >= HEALTHY_LATENCY_BELOW:
        pytest.fail(
            f"no healthy payments latency sample {STEP_SECONDS}s back (got {value}); "
            "the seeder's healthy period is shorter than one query step, so the run "
            "could not see a baseline. Check HEALTHY_SECONDS in demo/docker-compose.yml."
        )


@pytest.fixture(scope="module")
def live_run(tmp_path_factory):
    """One diagnosis against the live stack, shared by every assertion below.

    Sharing it means every test is looking at the same run, which is how a reader of
    the report would see it, and keeps the job to one diagnosis rather than seven.
    """
    _wait_for_incident()

    config = load_config(CONFIG)
    config.audit.run_root = tmp_path_factory.mktemp("runs")

    end = utcnow()
    window = TimeWindow(end - timedelta(minutes=5), end)
    incident = incident_from_payload(
        {"incident_id": "INC-LIVE", "service": "orders", "window": window.to_dict()},
        config,
        source="integration-test",
    )

    assembled = assemble(config)
    try:
        diagnosis = assembled.run.execute(incident)
    finally:
        assembled.close()
    return assembled, diagnosis


def _evidence(live_run, kind: str):
    assembled, _ = live_run
    items = [e for e in assembled.sink._evidence if e.kind == kind]
    records = [r for e in items for r in e.records]
    return items, records


# --------------------------------------------------------------------------- #
# The questions only real servers can answer
# --------------------------------------------------------------------------- #


def test_no_generated_query_was_rejected(live_run):
    """The core claim. A rejected template would surface as a gap naming the error."""
    _, diagnosis = live_run
    rejected = [
        g
        for g in diagnosis.gaps
        if "error response" in g.reason or "unavailable" in g.reason or "rejected" in g.reason
    ]
    assert not rejected, f"a live backend rejected a generated query: {rejected}"


def test_real_loki_returned_log_records(live_run):
    items, records = _evidence(live_run, "logs")
    assert items, "no log query reached Loki"
    assert records, "Loki answered every log query with nothing"
    assert any(r.get("level") == "error" for r in records)


def test_real_prometheus_returned_samples(live_run):
    items, records = _evidence(live_run, "metrics")
    assert items, "the run never reached the metrics stage"
    assert records, "Prometheus answered every metrics query with nothing"
    names = {r.get("metric") for r in records}
    assert "connection_pool_active" in names, names
    latency = [
        r
        for r in records
        if r.get("metric") == "request_latency_p99" and r.get("service") == "payments"
    ]
    assert len(latency) >= 2, f"a range query should return a series, got {latency}"


def test_live_run_reaches_the_causal_finding(live_run):
    """The demo's conclusion, arrived at from real servers.

    If this passes, the multi-round investigation works end to end against real
    backends: the error logs led to the pool metrics, the saturated pool led to the
    downstreams, and the downstream latency was found and tied back.

    Each finding is matched by its own wording. An earlier version checked only that
    "pool" and "payments" appeared somewhere among the findings, and passed on
    "payments logged 24 error(s)" while the latency and causal findings were absent.
    """
    _, diagnosis = live_run
    statements = [
        f.statement for f in diagnosis.findings if f.confidence is Confidence.SUPPORTED
    ]

    def found(fragment: str) -> bool:
        return any(fragment in s for s in statements)

    assert found("connection pool reached"), statements
    assert found("payments p99 latency rose from"), statements
    assert found("latency degradation in payments held orders's connections open"), statements
    assert diagnosis.rounds_used >= 3, diagnosis.rounds_used


# --------------------------------------------------------------------------- #
# Properties that must hold on real data, each checked against something real
# --------------------------------------------------------------------------- #


def test_records_have_the_fields_the_rest_of_the_tool_needs(live_run):
    _, logs = _evidence(live_run, "logs")
    _, metrics = _evidence(live_run, "metrics")
    assert logs and metrics, "nothing to check the shape of"
    for record in logs:
        assert {"timestamp", "service", "message"} <= set(record), record
    for record in metrics:
        assert {"timestamp", "service", "metric", "value"} <= set(record), record


def test_addresses_from_real_loki_are_pseudonymised(live_run):
    assembled, _ = live_run
    _, logs = _evidence(live_run, "logs")
    with_ip = [r for r in logs if r.get("client_ip")]
    assert with_ip, "no record carried a client_ip, so redaction was never exercised"
    assert all(str(r["client_ip"]).startswith("IP_") for r in with_ip)

    blob = json.dumps([e.to_dict() for e in assembled.sink._evidence])
    for raw in SEEDER_IPS:
        assert raw not in blob, f"{raw} reached the evidence unredacted"


def test_injected_line_from_real_loki_is_marked(live_run):
    """The seeder plants an instruction-bearing line once the incident is underway."""
    assembled, _ = live_run
    _, logs = _evidence(live_run, "logs")
    assert any("Ignore all previous" in str(r.get("message")) for r in logs), (
        "the injected line never came back, so the marker was not exercised"
    )
    assert any(e.injection_suspected for e in assembled.sink._evidence)


def test_report_is_written_from_live_evidence(live_run):
    assembled, _ = live_run
    report = (assembled.sink.run_dir / "report.md").read_text(encoding="utf-8")
    assert "## Findings" in report
    assert "payments" in report
    manifest = json.loads((assembled.sink.run_dir / "manifest.json").read_text())
    assert manifest["status"] == "complete"


# --------------------------------------------------------------------------- #
# The asymmetry the whole project is about
# --------------------------------------------------------------------------- #


def test_the_write_endpoint_is_refused_against_a_real_loki(live_run):
    """The seeder pushes through this path. This tool must not be able to."""
    config = load_config(CONFIG)
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

    # Confirm the path really is live, so the refusal above means something.
    request = urllib.request.Request(
        f"{LOKI}/loki/api/v1/push",
        data=json.dumps({"streams": []}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status < 500, "the write path should exist and accept requests"
