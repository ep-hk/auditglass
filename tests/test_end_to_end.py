"""Whole-pipeline behaviour, run the way the CLI runs it."""

from __future__ import annotations

import json

import pytest

from auditglass.build import assemble
from auditglass.models import Confidence, Termination
from auditglass.trigger.payload import incident_from_payload


def _run(config, alert, **kwargs):
    incident = incident_from_payload(alert, config, source="test")
    assembled = assemble(config, **kwargs)
    try:
        diagnosis = assembled.run.execute(incident)
    finally:
        assembled.close()
    return assembled, diagnosis


def test_demo_run_produces_a_complete_run_directory(config, alert):
    assembled, diagnosis = _run(config, alert)
    run_dir = assembled.sink.run_dir

    for name in ("manifest.json", "queries.jsonl", "evidence.jsonl", "report.md", "report.json"):
        assert (run_dir / name).is_file(), f"missing {name}"

    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["status"] == "complete"
    for key in ("config_hash", "template_fingerprint", "planner", "reasoner", "budget"):
        assert manifest.get(key), f"manifest is missing {key}"
    assert manifest["config_hash"].startswith("sha256:")
    assert diagnosis.termination is Termination.SUFFICIENT


def test_every_supported_finding_cites_real_evidence(config, alert):
    assembled, diagnosis = _run(config, alert)
    known = {e.evidence_id for e in assembled.sink._evidence}
    supported = [f for f in diagnosis.findings if f.confidence is Confidence.SUPPORTED]
    assert supported
    for finding in supported:
        assert finding.evidence_ids
        assert set(finding.evidence_ids) <= known, finding


def test_the_incident_needs_more_than_one_round(config, alert):
    """If a single query solved it, the premise of the tool would be false."""
    config.budget.max_rounds = 1
    _, one_round = _run(config, alert)
    assert one_round.termination is Termination.BUDGET_EXHAUSTED

    statements = " ".join(f.statement for f in one_round.findings).lower()
    assert "payments" not in statements, (
        "one round should not be able to name the downstream cause"
    )

    config.budget.max_rounds = 4
    _, full = _run(config, alert)
    full_statements = " ".join(f.statement for f in full.findings).lower()
    assert "payments" in full_statements
    assert "pool" in full_statements
    assert full.rounds_used > 1


def test_a_report_is_produced_even_when_the_budget_runs_out(config, alert):
    config.budget.max_queries = 1
    assembled, diagnosis = _run(config, alert)
    assert diagnosis.termination is Termination.BUDGET_EXHAUSTED
    assert (assembled.sink.run_dir / "report.md").is_file()
    assert any("budget" in g.reason for g in diagnosis.gaps)


def test_backend_failure_becomes_a_gap_not_a_crash(config, alert):
    assembled, diagnosis = _run(config, alert, simulate_outage={"metrics"})
    assert diagnosis.gaps
    assert any("unavailable" in g.reason for g in diagnosis.gaps)

    report = (assembled.sink.run_dir / "report.md").read_text(encoding="utf-8")
    assert "## Evidence gaps" in report
    assert "metrics.by_service_metric" in report
    # It still says what it did manage to establish.
    assert any(f.confidence is Confidence.SUPPORTED for f in diagnosis.findings)


def test_queries_record_template_and_parameters_not_just_a_string(config, alert):
    assembled, _ = _run(config, alert)
    lines = (assembled.sink.run_dir / "queries.jsonl").read_text().splitlines()
    assert lines
    for line in lines:
        query = json.loads(line)
        assert query["template_id"]
        assert "params" in query
        assert query["statement"]


def test_evidence_hash_is_over_the_raw_response(config, alert):
    assembled, _ = _run(config, alert)
    for evidence in assembled.sink._evidence:
        assert evidence.response_hash.startswith("sha256:")


def test_reverse_map_can_be_switched_off(config, alert):
    config.redaction.write_reverse_map = False
    assembled, _ = _run(config, alert)
    assert not (assembled.sink.run_dir / "reverse-map.json").exists()


def test_reverse_map_is_written_restricted(config, alert):
    import stat

    assembled, _ = _run(config, alert)
    path = assembled.sink.run_dir / "reverse-map.json"
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_purge_removes_only_expired_runs(config, alert, tmp_path):
    import os
    import time

    from auditglass.audit.sink import purge

    assembled, _ = _run(config, alert)
    run_dir = assembled.sink.run_dir
    assert purge(config.audit.run_root, retention_days=30) == []

    old = time.time() - 60 * 60 * 24 * 90
    os.utime(run_dir, (old, old))
    removed = purge(config.audit.run_root, retention_days=30, dry_run=True)
    assert removed == [run_dir.name]
    assert run_dir.exists(), "dry run must not delete"

    assert purge(config.audit.run_root, retention_days=30) == [run_dir.name]
    assert not run_dir.exists()


@pytest.mark.parametrize("service", ["orders", "payments"])
def test_runs_are_reproducible_in_what_they_query(config, alert, service):
    """Same input, same queries. Only the pseudonym salt differs between runs."""
    alert = {**alert, "service": service}
    first, _ = _run(config, alert)
    second, _ = _run(config, alert)

    def queries(assembled):
        return [
            (json.loads(line)["template_id"], json.loads(line)["statement"])
            for line in (assembled.sink.run_dir / "queries.jsonl").read_text().splitlines()
        ]

    assert queries(first) == queries(second)
