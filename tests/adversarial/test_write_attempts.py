"""Write attempts must be refused before anything leaves the process.

These run with a guard that would happily talk to the demo endpoint, so a refusal
here is the policy working rather than the absence of a route. This is the suite a
security reviewer should run first, and it is designed to be readable by someone who
has never seen the codebase.

See ``docs/readonly-guarantee.md`` for what each layer does and does not promise.
"""

from __future__ import annotations

import pytest

from auditglass.models import OutboundRequest

pytestmark = pytest.mark.adversarial

ALLOWED_HOST = {"scheme": "http", "host": "fixture.invalid", "port": 9999}


def _request(**overrides) -> OutboundRequest:
    base = {**ALLOWED_HOST, "method": "GET", "path": "/logs", "backend": "fixture"}
    base.update(overrides)
    return OutboundRequest(**base)


# --------------------------------------------------------------------------- #
# Methods
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH", "HEAD", "OPTIONS", "TRACE"])
def test_write_methods_are_refused(guard, method):
    decision = guard.authorize(_request(method=method))
    assert not decision.allowed
    assert decision.rule == "method-unsupported"


def test_post_refused_on_a_get_only_endpoint(guard):
    decision = guard.authorize(_request(method="POST"))
    assert not decision.allowed
    assert decision.rule == "method-not-allowlisted"


# --------------------------------------------------------------------------- #
# Destinations
# --------------------------------------------------------------------------- #


def test_undeclared_host_is_refused(guard):
    decision = guard.authorize(_request(host="logs.internal.example"))
    assert not decision.allowed
    assert decision.rule == "host-not-allowlisted"


def test_undeclared_path_is_refused(guard):
    """A read endpoint and a write endpoint frequently sit on the same host."""
    for path in ["/_bulk", "/loki/api/v1/push", "/api/v1/admin/tsdb/delete_series", "/logs/../admin"]:
        decision = guard.authorize(_request(path=path))
        assert not decision.allowed, path
        assert decision.rule == "path-not-allowlisted"


def test_port_is_part_of_the_identity(guard):
    decision = guard.authorize(_request(port=9998))
    assert not decision.allowed
    assert decision.rule == "host-not-allowlisted"


def test_scheme_downgrade_is_refused(guard):
    decision = guard.authorize(_request(scheme="https"))
    assert not decision.allowed


def test_backend_mismatch_is_refused(guard):
    decision = guard.authorize(_request(backend="prometheus"))
    assert not decision.allowed
    assert decision.rule == "backend-mismatch"


# --------------------------------------------------------------------------- #
# Statement provenance — the check that does the real work
# --------------------------------------------------------------------------- #


def test_statement_without_a_template_is_refused(guard):
    decision = guard.authorize(_request(statement="service=orders level=error"))
    assert not decision.allowed
    assert decision.rule == "statement-without-template"


def test_tampered_statement_is_refused(guard, registry, context, window_params):
    """The canonical attack: render legitimately, then alter the statement."""
    rendered = registry.get("logs.by_service_level").render(
        {"service": "orders", "level": "error", "window": window_params}, context
    )
    decision = guard.authorize(
        _request(
            template_id=rendered.template_id,
            params=rendered.params,
            statement=rendered.statement + " | collect index=exfil",
        )
    )
    assert not decision.allowed
    assert decision.rule in {"statement-mismatch", "forbidden-substring"}


def test_unknown_template_is_refused(guard):
    decision = guard.authorize(
        _request(template_id="logs.arbitrary", statement="anything", params={})
    )
    assert not decision.allowed
    assert decision.rule == "unknown-template"


def test_params_not_matching_template_are_refused(guard, registry, context, window_params):
    rendered = registry.get("logs.by_service_level").render(
        {"service": "orders", "level": "error", "window": window_params}, context
    )
    decision = guard.authorize(
        _request(
            template_id=rendered.template_id,
            params={**rendered.params, "service": "payments"},
            statement=rendered.statement,
        )
    )
    assert not decision.allowed
    assert decision.rule == "statement-mismatch"


def test_route_swap_is_refused(guard, registry, context, window_params):
    """Right statement, wrong path — the template declares where it may go."""
    rendered = registry.get("logs.by_service_level").render(
        {"service": "orders", "level": "error", "window": window_params}, context
    )
    decision = guard.authorize(
        _request(
            path="/metrics",
            template_id=rendered.template_id,
            params=rendered.params,
            statement=rendered.statement,
        )
    )
    assert not decision.allowed
    assert decision.rule == "route-mismatch"


def test_a_legitimate_query_is_allowed(guard, registry, context, window_params):
    """The suite would pass trivially if everything were denied."""
    rendered = registry.get("logs.by_service_level").render(
        {"service": "orders", "level": "error", "window": window_params}, context
    )
    decision = guard.authorize(
        _request(
            template_id=rendered.template_id,
            params=rendered.params,
            statement=rendered.statement,
        )
    )
    assert decision.allowed, decision.reason


# --------------------------------------------------------------------------- #
# Denials reach the audit trail
# --------------------------------------------------------------------------- #


def test_every_denial_is_audited(config, registry, context):
    from auditglass.policy.guard import PolicyGuard

    recorded: list[tuple] = []
    audited_guard = PolicyGuard(
        config.policy, registry, context, on_denial=lambda r, d: recorded.append((r, d))
    )
    audited_guard.authorize(_request(method="DELETE"))
    audited_guard.authorize(_request(host="elsewhere.example"))
    audited_guard.authorize(_request(path="/_bulk"))

    assert len(recorded) == 3
    for request, decision in recorded:
        assert not decision.allowed
        assert decision.reason
        assert decision.rule
        assert "url" in request.describe()
