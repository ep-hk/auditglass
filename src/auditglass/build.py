"""Wiring.

One place that turns a :class:`Config` into a runnable :class:`DiagnosticRun`, so
that the CLI and the tests construct the system identically. If a test passes because
it wired the components differently from the CLI, it is not testing the thing users run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .audit.sink import LocalRunDirectory
from .config import Config
from .errors import ConfigError
from .interfaces import Planner, Reasoner
from .policy.guard import PolicyGuard
from .policy.http import ConstrainedHTTPClient
from .policy.templates import RenderContext, TemplateRegistry
from .providers.fixture import FixtureProvider
from .providers.loki import LokiProvider
from .providers.prometheus import PrometheusProvider
from .redact.redactor import DeterministicRedactor, make_salt
from .run import DiagnosticRun


@dataclass
class Assembled:
    config: Config
    registry: TemplateRegistry
    guard: PolicyGuard
    client: ConstrainedHTTPClient | None
    sink: LocalRunDirectory
    run: DiagnosticRun

    def close(self) -> None:
        if self.client is not None:
            self.client.close()


def assemble(
    config: Config,
    *,
    simulate_outage: set[str] | None = None,
    credential_env: dict[str, str] | None = None,
) -> Assembled:
    registry = TemplateRegistry.load(list(config.template_files))
    if not len(registry):
        raise ConfigError(
            "no query templates were loaded; a planner cannot ask for anything",
            locator="template_files",
        )

    sink = LocalRunDirectory(config.audit.run_root)

    # The guard's render context is refreshed per run with the incident window; this
    # one exists so that denials outside a run still have somewhere to resolve.
    guard_context = RenderContext(scope=config.scope_dict())
    guard = PolicyGuard(
        config.policy,
        registry,
        guard_context,
        on_denial=lambda request, decision: sink.record_denial(request, decision),
    )

    needs_http = any(p.kind != "fixture" for p in config.providers) or (
        config.reasoner.kind == "openai_compat"
    )
    client = (
        ConstrainedHTTPClient(
            guard,
            timeout_seconds=config.policy.timeout_seconds(),
            rate_limit_per_second=config.policy.rate_limit_per_second,
            credential_env=credential_env or {},
        )
        if needs_http
        else None
    )

    providers: dict[str, Any] = {}
    for spec in config.providers:
        if spec.kind == "fixture":
            providers[spec.backend] = FixtureProvider(
                spec.fixture_path,  # type: ignore[arg-type]
                max_records=config.budget.max_records,
                fail_backends=simulate_outage,
                guard=guard,
                endpoint=config.endpoint(spec.endpoint) if spec.endpoint else None,
            )
            continue
        assert client is not None
        endpoint = config.endpoint(spec.endpoint)  # type: ignore[arg-type]
        cls = {"loki": LokiProvider, "prometheus": PrometheusProvider}[spec.kind]
        providers[spec.backend] = cls(client, endpoint, max_records=config.budget.max_records)

    redactor = DeterministicRedactor(config.redaction, make_salt(config.redaction))
    planner = _planner(config, registry, client)
    reasoner = _reasoner(config, client)

    run = DiagnosticRun(
        config=config,
        registry=registry,
        planner=planner,
        providers=providers,
        redactor=redactor,
        reasoner=reasoner,
        sink=sink,
        guard=guard,
    )
    return Assembled(config, registry, guard, client, sink, run)


def _planner(config: Config, registry: TemplateRegistry, client) -> Planner:
    if config.planner.kind == "rule_based":
        from .planner.rule_based import RuleBasedPlanner

        return RuleBasedPlanner(scope=config.scope)

    from .planner.llm import LLMPlanner

    if client is None or config.reasoner.kind != "openai_compat":
        raise ConfigError(
            "planner.kind=llm requires reasoner.kind=openai_compat with a model endpoint",
            locator="planner.kind",
        )
    return LLMPlanner(config.reasoner, client, _model_endpoint(config), registry)


def _reasoner(config: Config, client) -> Reasoner:
    if config.reasoner.kind == "rulebook":
        from .reason.rulebook import RulebookReasoner

        return RulebookReasoner()

    from .reason.openai_compat import OpenAICompatReasoner

    assert client is not None
    return OpenAICompatReasoner(config.reasoner, client, _model_endpoint(config))


def _model_endpoint(config: Config):
    for endpoint in config.policy.endpoints:
        if endpoint.backend == "model":
            return endpoint
    raise ConfigError(
        "reasoner.kind=openai_compat requires an endpoint with backend: model in "
        "policy.endpoints, so that the model host is allowlisted like any other",
        locator="policy.endpoints",
    )
