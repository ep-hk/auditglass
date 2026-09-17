"""Core domain types.

These are deliberately plain and immutable where possible. Everything that crosses
a trust boundary is represented here so that the boundary crossing is visible in
the type signature rather than buried in a dict.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Time
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TimeWindow:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.start.tzinfo is None or self.end.tzinfo is None:
            raise ValueError("TimeWindow bounds must be timezone-aware")
        if self.end <= self.start:
            raise ValueError("TimeWindow end must be after start")

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    def intersects(self, other: TimeWindow) -> bool:
        return self.start < other.end and other.start < self.end

    def contains(self, other: TimeWindow) -> bool:
        return self.start <= other.start and other.end <= self.end

    def to_dict(self) -> dict[str, str]:
        return {"start": self.start.isoformat(), "end": self.end.isoformat()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> TimeWindow:
        return cls(_parse_dt(d["start"]), _parse_dt(d["end"]))


def _parse_dt(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Incident
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IncidentContext:
    """What the agent was asked to look at.

    ``services`` is the frozen scope for the run. It is derived from configuration
    intersected with the trigger, never from model output, and it cannot be widened
    once the run has started.
    """

    incident_id: str
    primary_service: str
    services: tuple[str, ...]
    window: TimeWindow
    trigger_source: str
    alert: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "primary_service": self.primary_service,
            "services": list(self.services),
            "window": self.window.to_dict(),
            "trigger_source": self.trigger_source,
            # The alert payload is untrusted input; it is recorded verbatim for
            # audit but never interpolated into a query.
            "alert": self.alert,
        }


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class QueryRequest:
    """What a Planner asks for. Never a query string."""

    template_id: str
    params: dict[str, Any]

    def key(self) -> str:
        return f"{self.template_id}:{json.dumps(self.params, sort_keys=True, default=str)}"


@dataclass(frozen=True)
class RenderedQuery:
    """The result of rendering a template with validated parameters.

    ``statement`` is produced by the template engine from typed parameters. It is
    never assembled from model output, and PolicyGuard re-derives it independently
    before any request leaves the process.
    """

    template_id: str
    backend: str
    kind: str
    method: str
    path: str
    params: dict[str, Any]
    statement: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "backend": self.backend,
            "kind": self.kind,
            "method": self.method,
            "path": self.path,
            "params": _jsonable(self.params),
            "statement": self.statement,
        }


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


@dataclass
class EvidenceRecord:
    evidence_id: str
    query: RenderedQuery
    kind: str
    records: list[dict[str, Any]]
    response_hash: str
    retrieved_at: datetime
    truncated: bool = False
    injection_suspected: bool = False
    injection_markers: list[str] = field(default_factory=list)

    def to_dict(self, include_records: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "query": self.query.to_dict(),
            "response_hash": self.response_hash,
            "retrieved_at": self.retrieved_at.isoformat(),
            "record_count": len(self.records),
            "truncated": self.truncated,
            "injection_suspected": self.injection_suspected,
            "injection_markers": self.injection_markers,
        }
        if include_records:
            d["records"] = self.records
        return d


@dataclass
class EvidenceGap:
    """Something the agent tried to retrieve and could not.

    Gaps are first-class output. A report that silently omits what it could not see
    is worse than no report, because the reader cannot tell the difference between
    "no signal" and "did not look".
    """

    template_id: str
    params: dict[str, Any]
    reason: str
    occurred_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "params": _jsonable(self.params),
            "reason": self.reason,
            "occurred_at": self.occurred_at.isoformat(),
        }


# --------------------------------------------------------------------------- #
# Findings and report
# --------------------------------------------------------------------------- #


class Confidence(StrEnum):
    SUPPORTED = "supported"
    SPECULATIVE = "speculative"


@dataclass
class Finding:
    statement: str
    evidence_ids: list[str]
    confidence: Confidence = Confidence.SUPPORTED

    def __post_init__(self) -> None:
        # A conclusion with no evidence is speculation, and is labelled as such
        # regardless of how it was produced.
        if not self.evidence_ids:
            self.confidence = Confidence.SPECULATIVE

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "evidence_ids": list(self.evidence_ids),
            "confidence": self.confidence.value,
        }


class Termination(StrEnum):
    SUFFICIENT = "evidence_sufficient"
    BUDGET_EXHAUSTED = "budget_exhausted"
    NO_NEW_EVIDENCE = "no_new_evidence"
    PLAN_COMPLETE = "plan_complete"
    ABORTED = "aborted"


@dataclass
class Diagnosis:
    incident: IncidentContext
    findings: list[Finding]
    gaps: list[EvidenceGap]
    termination: Termination
    rounds_used: int
    summary: str = ""

    @property
    def coverage(self) -> str:
        total = len(self.findings) + len(self.gaps)
        if total == 0:
            return "no evidence retrieved"
        return f"{len(self.gaps)} gap(s) across {self.rounds_used} round(s)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident": self.incident.to_dict(),
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "gaps": [g.to_dict() for g in self.gaps],
            "termination": self.termination.value,
            "rounds_used": self.rounds_used,
            "coverage": self.coverage,
        }


# --------------------------------------------------------------------------- #
# Budget
# --------------------------------------------------------------------------- #


@dataclass
class Budget:
    max_queries: int = 12
    max_records: int = 5000
    max_rounds: int = 4
    max_tokens: int | None = None
    max_cost_usd: float | None = None


@dataclass
class BudgetLedger:
    budget: Budget
    queries: int = 0
    records: int = 0
    rounds: int = 0
    tokens: int = 0
    cost_usd: float = 0.0

    def exhausted(self) -> str | None:
        b = self.budget
        if self.queries >= b.max_queries:
            return f"query budget exhausted ({self.queries}/{b.max_queries})"
        if self.records >= b.max_records:
            return f"record budget exhausted ({self.records}/{b.max_records})"
        if self.rounds >= b.max_rounds:
            return f"round budget exhausted ({self.rounds}/{b.max_rounds})"
        if b.max_tokens is not None and self.tokens >= b.max_tokens:
            return f"token budget exhausted ({self.tokens}/{b.max_tokens})"
        if b.max_cost_usd is not None and self.cost_usd >= b.max_cost_usd:
            return f"cost budget exhausted ({self.cost_usd:.4f}/{b.max_cost_usd})"
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "limits": {
                "max_queries": self.budget.max_queries,
                "max_records": self.budget.max_records,
                "max_rounds": self.budget.max_rounds,
                "max_tokens": self.budget.max_tokens,
                "max_cost_usd": self.budget.max_cost_usd,
            },
            "consumed": {
                "queries": self.queries,
                "records": self.records,
                "rounds": self.rounds,
                "tokens": self.tokens,
                "cost_usd": round(self.cost_usd, 6),
            },
        }


# --------------------------------------------------------------------------- #
# Outbound request / policy decision
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class OutboundRequest:
    method: str
    scheme: str
    host: str
    port: int
    path: str
    query_params: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | None = None
    backend: str = ""
    template_id: str = ""
    statement: str = ""
    # Carried so PolicyGuard can independently re-render the statement from the
    # template and compare, rather than trusting the statement it was handed.
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def url(self) -> str:
        default = {"http": 80, "https": 443}.get(self.scheme)
        netloc = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}"

    def describe(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "query_params": dict(self.query_params),
            "backend": self.backend,
            "template_id": self.template_id,
            "statement": self.statement,
            "has_body": self.body is not None,
        }


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: str = ""

    @classmethod
    def allow(cls, rule: str) -> Decision:
        return cls(True, "allowed", rule)

    @classmethod
    def deny(cls, reason: str, rule: str = "default-deny") -> Decision:
        return cls(False, reason, rule)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, TimeWindow):
        return obj.to_dict()
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    return obj


def stable_hash(payload: Any) -> str:
    """SHA-256 over a canonical JSON encoding. Used for response and config hashes."""
    blob = json.dumps(_jsonable(payload), sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()
