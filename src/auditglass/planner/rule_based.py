"""A planner that needs no language model.

This exists for three reasons, in order of importance:

1. **The quickstart must not require an API key.** ``auditglass demo`` runs the whole
   pipeline — policy, templates, providers, redaction, audit, report — with this
   planner, so a reviewer can see a real run directory within a minute of cloning.
2. **The test suite must be deterministic.** Every adversarial test runs against this
   planner, so a failure means the control failed, not that a model sampled badly.
3. **It is a reference for what a planner is allowed to do.** It sees only redacted
   evidence and the frozen scope, and it can only return template ids with typed
   parameters — exactly the same surface a model-driven planner gets.

The investigation it encodes is the ordinary one: start at the service that alerted,
notice what the errors look like, follow saturation upstream to its cause.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..config import ScopeConfig
from ..interfaces import PlanState
from ..models import EvidenceRecord, QueryRequest

SATURATION_SIGNALS = (
    "pool",
    "exhausted",
    "timeout",
    "timed out",
    "connection refused",
    "no available connection",
    "acquire",
    "saturat",
)

LATENCY_SIGNALS = ("slow", "latency", "deadline", "p99", "degraded")


@dataclass
class RuleBasedPlanner:
    scope: ScopeConfig
    name: str = "rule_based"

    logs_template: str = "logs.by_service_level"
    metrics_template: str = "metrics.by_service_metric"

    def next_round(self, state: PlanState) -> list[QueryRequest]:
        window = state.incident.window.to_dict()
        primary = state.incident.primary_service

        if state.round_index == 0:
            return [
                QueryRequest(
                    self.logs_template,
                    {"service": primary, "level": "error", "window": window, "limit": 200},
                )
            ]

        messages = _messages(state.evidence)

        if state.round_index == 1:
            requests: list[QueryRequest] = []
            if _any_signal(messages, SATURATION_SIGNALS):
                # The errors look like resource starvation rather than a bug, so ask
                # what the resource was doing, and look at what this service depends
                # on. Downstreams come from configuration, never from the log text.
                for metric in ("connection_pool_active", "connection_pool_max"):
                    requests.append(
                        QueryRequest(
                            self.metrics_template,
                            {"service": primary, "metric": metric, "window": window},
                        )
                    )
                for downstream in self.scope.downstreams(primary):
                    requests.append(
                        QueryRequest(
                            self.logs_template,
                            {
                                "service": downstream,
                                "level": "error",
                                "window": window,
                                "limit": 100,
                            },
                        )
                    )
            else:
                requests.append(
                    QueryRequest(
                        self.metrics_template,
                        {"service": primary, "metric": "error_rate", "window": window},
                    )
                )
            return [r for r in requests if not state.already_ran(r)]

        if state.round_index == 2:
            requests = []
            saturated = _pool_saturated(state.evidence)
            if saturated or _any_signal(messages, LATENCY_SIGNALS):
                for downstream in self.scope.downstreams(primary):
                    requests.append(
                        QueryRequest(
                            self.metrics_template,
                            {
                                "service": downstream,
                                "metric": "request_latency_p99",
                                "window": window,
                            },
                        )
                    )
            return [r for r in requests if not state.already_ran(r)]

        return []


# --------------------------------------------------------------------------- #


def _messages(evidence: list[EvidenceRecord]) -> list[str]:
    out: list[str] = []
    for item in evidence:
        if item.kind != "logs":
            continue
        for record in item.records:
            value = record.get("message")
            if isinstance(value, str):
                out.append(value.casefold())
    return out


def _any_signal(messages: list[str], signals: tuple[str, ...]) -> bool:
    return any(signal in message for message in messages for signal in signals)


def _pool_saturated(evidence: list[EvidenceRecord], threshold: float = 0.95) -> bool:
    active = _series(evidence, "connection_pool_active")
    limit = _series(evidence, "connection_pool_max")
    if not active or not limit:
        return False
    ceiling = max(limit)
    return ceiling > 0 and (max(active) / ceiling) >= threshold


def _series(evidence: list[EvidenceRecord], metric: str) -> list[float]:
    values: list[float] = []
    for item in evidence:
        if item.kind != "metrics":
            continue
        for record in item.records:
            if record.get("metric") == metric:
                value: Any = record.get("value")
                if isinstance(value, (int, float)):
                    values.append(float(value))
    return values
