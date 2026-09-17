"""The rule-based planner drives the demo and every adversarial test, so its
behaviour is pinned here rather than left implicit."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from auditglass.interfaces import PlanState
from auditglass.models import (
    EvidenceRecord,
    IncidentContext,
    RenderedQuery,
    TimeWindow,
)
from auditglass.planner.rule_based import RuleBasedPlanner

BASE = datetime(2026, 3, 14, 2, 10, tzinfo=UTC)


def _incident(config) -> IncidentContext:
    return IncidentContext(
        incident_id="INC-1",
        primary_service="orders",
        services=("orders", "payments", "inventory-db"),
        window=TimeWindow(BASE, BASE + timedelta(minutes=20)),
        trigger_source="test",
    )


def _evidence(kind: str, records: list[dict], eid: str = "E1") -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=eid,
        query=RenderedQuery("t", "fixture", kind, "GET", "/x", {}, "s"),
        kind=kind,
        records=records,
        response_hash="sha256:x",
        retrieved_at=BASE,
    )


def test_first_round_looks_at_the_alerting_service(config):
    planner = RuleBasedPlanner(scope=config.scope)
    requests = planner.next_round(PlanState(incident=_incident(config), round_index=0))
    assert len(requests) == 1
    assert requests[0].template_id == "logs.by_service_level"
    assert requests[0].params["service"] == "orders"
    assert requests[0].params["level"] == "error"


def test_saturation_signals_lead_to_pool_metrics_and_downstreams(config):
    planner = RuleBasedPlanner(scope=config.scope)
    state = PlanState(
        incident=_incident(config),
        round_index=1,
        evidence=[_evidence("logs", [{"message": "connection pool exhausted: 50/50"}])],
    )
    requests = planner.next_round(state)
    metrics = {r.params.get("metric") for r in requests}
    services = {r.params.get("service") for r in requests}
    assert "connection_pool_active" in metrics
    assert {"payments", "inventory-db"} <= services


def test_downstreams_come_from_config_not_from_log_text(config):
    """A log line naming another service must not send the planner there."""
    planner = RuleBasedPlanner(scope=config.scope)
    state = PlanState(
        incident=_incident(config),
        round_index=1,
        evidence=[
            _evidence(
                "logs",
                [{"message": "pool exhausted; see service hr-payroll and secrets-store"}],
            )
        ],
    )
    requests = planner.next_round(state)
    for request in requests:
        service = request.params.get("service")
        if service:
            assert service in set(config.scope.services)


def test_non_saturation_errors_take_the_other_branch(config):
    planner = RuleBasedPlanner(scope=config.scope)
    state = PlanState(
        incident=_incident(config),
        round_index=1,
        evidence=[_evidence("logs", [{"message": "NullPointerException in OrderMapper"}])],
    )
    requests = planner.next_round(state)
    assert [r.params.get("metric") for r in requests] == ["error_rate"]


def test_third_round_chases_downstream_latency_when_the_pool_was_pegged(config):
    planner = RuleBasedPlanner(scope=config.scope)
    state = PlanState(
        incident=_incident(config),
        round_index=2,
        evidence=[
            _evidence("logs", [{"message": "pool exhausted"}], "E1"),
            _evidence(
                "metrics",
                [
                    {"metric": "connection_pool_active", "value": 50.0, "service": "orders"},
                    {"metric": "connection_pool_max", "value": 50.0, "service": "orders"},
                ],
                "E2",
            ),
        ],
    )
    requests = planner.next_round(state)
    assert {r.params["metric"] for r in requests} == {"request_latency_p99"}
    assert {r.params["service"] for r in requests} == {"payments", "inventory-db"}


def test_planner_stops(config):
    planner = RuleBasedPlanner(scope=config.scope)
    assert planner.next_round(PlanState(incident=_incident(config), round_index=9)) == []


def test_planner_does_not_repeat_a_query(config):
    planner = RuleBasedPlanner(scope=config.scope)
    state = PlanState(
        incident=_incident(config),
        round_index=1,
        evidence=[_evidence("logs", [{"message": "pool exhausted"}])],
    )
    first = planner.next_round(state)
    state.executed.update(r.key() for r in first)
    assert planner.next_round(state) == []
