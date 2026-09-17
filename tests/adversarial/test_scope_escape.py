"""Scope is fixed by configuration and cannot be widened by anything at runtime.

Threat T5: the agent must not become a route to data the requester is not entitled
to. In v0.1 this is enforced at the deployment level rather than per-requester — see
the threat model for what that does and does not cover — so these tests pin the part
that *is* enforced: no input can extend the service set the deployment declares.
"""

from __future__ import annotations

import pytest

from auditglass.config import ScopeConfig
from auditglass.errors import ConfigError
from auditglass.trigger.payload import incident_from_payload

pytestmark = pytest.mark.adversarial


def test_alert_cannot_name_a_service_outside_scope(config):
    with pytest.raises(ConfigError, match=r"not in scope\.services"):
        incident_from_payload({"service": "hr-payroll"}, config)


def test_alert_cannot_smuggle_extra_services(config):
    with pytest.raises(ConfigError, match=r"outside this deployment's scope"):
        incident_from_payload(
            {"service": "orders", "services": ["orders", "hr-payroll"]}, config
        )


def test_incident_scope_is_the_configured_intersection(config):
    incident = incident_from_payload({"service": "orders"}, config)
    assert set(incident.services) <= set(config.scope.services)
    # Downstreams come from the topology, which is configuration.
    assert "payments" in incident.services
    assert "hr-payroll" not in incident.services


def test_topology_cannot_reference_unknown_services():
    with pytest.raises(ValueError, match=r"not in scope\.services"):
        ScopeConfig(services=["orders"], topology={"orders": ["payroll"]})


def test_topology_key_must_be_in_scope():
    with pytest.raises(ValueError, match=r"not in scope\.services"):
        ScopeConfig(services=["orders"], topology={"payroll": ["orders"]})


def test_planner_only_sees_configured_downstreams(config):
    from auditglass.planner.rule_based import RuleBasedPlanner

    planner = RuleBasedPlanner(scope=config.scope)
    assert planner.scope.downstreams("orders") == ["payments", "inventory-db"]
    assert planner.scope.downstreams("hr-payroll") == []


def test_window_cannot_drift_far_from_the_incident(config, alert):
    """A planner may narrow the window; it may not wander off to another day."""
    from datetime import timedelta

    from auditglass.errors import ParamValidationError
    from auditglass.models import TimeWindow
    from auditglass.policy.templates import RenderContext, TemplateRegistry

    incident = incident_from_payload(alert, config, source="test")
    registry = TemplateRegistry.load(list(config.template_files))
    context = RenderContext(
        scope=config.scope_dict(),
        incident_window=incident.window,
        max_lookback_seconds=3600,
    )
    drifted = TimeWindow(
        incident.window.start - timedelta(hours=10), incident.window.end
    )
    with pytest.raises(ParamValidationError):
        registry.get("logs.by_service_level").render(
            {"service": "orders", "level": "error", "window": drifted.to_dict()}, context
        )
