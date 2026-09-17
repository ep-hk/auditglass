"""The template engine is where the read-only property becomes tractable, so these
tests are about what it *refuses* at least as much as what it renders."""

from __future__ import annotations

from datetime import timedelta

import pytest

from auditglass.errors import ParamValidationError, TemplateError
from auditglass.models import TimeWindow
from auditglass.policy.templates import RenderContext, TemplateRegistry


def test_renders_deterministically(registry, context, window_params):
    template = registry.get("logs.by_service_level")
    first = template.render(
        {"service": "orders", "level": "error", "window": window_params}, context
    )
    second = template.render(
        {"service": "orders", "level": "error", "window": window_params}, context
    )
    assert first.statement == second.statement == "service=orders level=error"


def test_enum_confined_to_configured_services(registry, context, window_params):
    template = registry.get("logs.by_service_level")
    with pytest.raises(ParamValidationError, match="not in the permitted set"):
        template.render(
            {"service": "hr-payroll", "level": "error", "window": window_params}, context
        )


def test_unknown_parameter_rejected(registry, context, window_params):
    template = registry.get("logs.by_service_level")
    with pytest.raises(ParamValidationError, match="does not accept parameter"):
        template.render(
            {
                "service": "orders",
                "level": "error",
                "window": window_params,
                "index": "secrets-*",
            },
            context,
        )


def test_window_must_intersect_incident(registry, context, incident_window):
    template = registry.get("logs.by_service_level")
    far_away = TimeWindow(
        incident_window.start - timedelta(days=30),
        incident_window.start - timedelta(days=30) + timedelta(minutes=5),
    )
    with pytest.raises(ParamValidationError, match="does not intersect"):
        template.render(
            {"service": "orders", "level": "error", "window": far_away.to_dict()}, context
        )


def test_window_cannot_exceed_template_maximum(registry, context, incident_window):
    template = registry.get("logs.by_service_level")
    huge = TimeWindow(incident_window.start, incident_window.start + timedelta(hours=12))
    with pytest.raises(ParamValidationError, match="exceeds the template maximum"):
        template.render(
            {"service": "orders", "level": "error", "window": huge.to_dict()}, context
        )


def test_int_bounds_enforced(registry, context, window_params):
    template = registry.get("logs.by_service_level")
    with pytest.raises(ParamValidationError, match="outside the permitted range"):
        template.render(
            {
                "service": "orders",
                "level": "error",
                "window": window_params,
                "limit": 10_000_000,
            },
            context,
        )


def test_ref_must_have_been_observed(registry, context, window_params):
    template = registry.get("logs.by_trace")
    with pytest.raises(ParamValidationError, match="was not observed"):
        template.render({"trace_id": "tr-deadbeef", "window": window_params}, context)

    context.observe("trace_id", "tr-0051a01")
    rendered = template.render({"trace_id": "tr-0051a01", "window": window_params}, context)
    assert rendered.statement == "trace_id=tr-0051a01"


def test_ref_rejects_structure_bearing_characters(registry, context, window_params):
    """A trace id comes from a log line, and log lines are attacker-influenced."""
    template = registry.get("logs.by_trace")
    for hostile in ['tr-1" or app="payroll', "tr-1\n| collect", "tr-1}{app='x'"]:
        context.observed.setdefault("trace_id", set()).add(hostile)
        with pytest.raises(ParamValidationError, match="not permitted in a reference"):
            template.render({"trace_id": hostile, "window": window_params}, context)


def test_observe_ignores_values_outside_the_charset(context):
    context.observe("trace_id", 'abc" or 1=1')
    assert "trace_id" not in context.observed or not context.observed["trace_id"]


def test_free_text_parameter_type_does_not_exist(tmp_path):
    """The absence of a free-text type is the security property, so pin it."""
    path = tmp_path / "bad.yaml"
    path.write_text(
        "backend: fixture\n"
        "templates:\n"
        "  - id: bad.free\n"
        "    kind: logs\n"
        "    params:\n"
        "      q: {type: string}\n"
        "    statement: 'q={q}'\n",
        encoding="utf-8",
    )
    with pytest.raises(TemplateError, match="unknown type"):
        TemplateRegistry().load_file(path)


def test_placeholder_without_parameter_fails_at_load(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        "backend: fixture\n"
        "templates:\n"
        "  - id: bad.placeholder\n"
        "    kind: logs\n"
        "    params:\n"
        "      service: {type: enum, values: [a]}\n"
        "    statement: 'service={service} index={index}'\n",
        encoding="utf-8",
    )
    with pytest.raises(TemplateError, match="not a declared parameter"):
        TemplateRegistry().load_file(path)


def test_unsupported_method_rejected_at_load(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text(
        "backend: fixture\n"
        "templates:\n"
        "  - id: bad.method\n"
        "    kind: logs\n"
        "    method: DELETE\n"
        "    params: {}\n"
        "    statement: 'x'\n",
        encoding="utf-8",
    )
    with pytest.raises(TemplateError, match="only GET and POST"):
        TemplateRegistry().load_file(path)


def test_catalogue_is_stable(registry):
    assert registry.fingerprint() == registry.fingerprint()
    ids = {entry["id"] for entry in registry.catalogue()}
    assert "logs.by_service_level" in ids


def test_enum_source_resolves_from_scope(registry):
    catalogue = {e["id"]: e for e in registry.catalogue()}
    spec = catalogue["logs.by_service_level"]["params"]["service"]
    assert spec["type"] == "enum"


def test_render_context_scope_isolation(config):
    ctx = RenderContext(scope=config.scope_dict())
    assert ctx.resolve_source("scope.services") == list(config.scope.services)
    with pytest.raises(TemplateError):
        ctx.resolve_source("scope.secrets")
