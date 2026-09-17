"""The seven replaceable abstractions.

Every one of these is a Protocol so that a third party can supply an implementation
without modifying this package. The split between Planner and Reasoner is
deliberate: the security-relevant decisions (what to query, within what scope,
against what budget) live in the Planner and can be tested — and run — without a
language model at all.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .models import (
    Decision,
    Diagnosis,
    EvidenceGap,
    EvidenceRecord,
    Finding,
    IncidentContext,
    OutboundRequest,
    QueryRequest,
    RenderedQuery,
)


@dataclass
class PlanState:
    """Everything a Planner may consider when deciding the next round.

    Note what is absent: there is no way to reach configuration, the network, or
    the raw alert text from here beyond what the incident context carries. A
    Planner sees redacted evidence only.
    """

    incident: IncidentContext
    round_index: int
    evidence: list[EvidenceRecord] = field(default_factory=list)
    gaps: list[EvidenceGap] = field(default_factory=list)
    executed: set[str] = field(default_factory=set)

    def evidence_of_kind(self, kind: str) -> list[EvidenceRecord]:
        return [e for e in self.evidence if e.kind == kind]

    def already_ran(self, request: QueryRequest) -> bool:
        return request.key() in self.executed


@dataclass
class RedactionHit:
    """Where a rule fired. Deliberately does not carry the original value."""

    rule: str
    field_name: str
    record_index: int
    start: int
    end: int
    token: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "field": self.field_name,
            "record_index": self.record_index,
            "span": [self.start, self.end],
            "token": self.token,
        }


@dataclass
class RedactionResult:
    records: list[dict[str, Any]]
    hits: list[RedactionHit]
    injection_suspected: bool = False
    injection_markers: list[str] = field(default_factory=list)
    dropped_fields: set[str] = field(default_factory=set)


@runtime_checkable
class Trigger(Protocol):
    """Turns an external signal into a scoped incident context."""

    name: str

    def incidents(self) -> Iterable[IncidentContext]: ...


@runtime_checkable
class Planner(Protocol):
    """Decides what to retrieve next. Returns an empty list to finish."""

    name: str

    def next_round(self, state: PlanState) -> list[QueryRequest]: ...


@runtime_checkable
class Guard(Protocol):
    """Mediates every outbound request. Default deny."""

    def authorize(self, request: OutboundRequest) -> Decision: ...


@runtime_checkable
class EvidenceProvider(Protocol):
    """Executes a rendered query against one backend."""

    backend: str

    def fetch(self, query: RenderedQuery) -> tuple[list[dict[str, Any]], bool]:
        """Return (records, truncated)."""
        ...


@runtime_checkable
class Redactor(Protocol):
    """Pseudonymises records before they reach a Reasoner."""

    def process(self, records: list[dict[str, Any]], kind: str) -> RedactionResult: ...


@runtime_checkable
class Reasoner(Protocol):
    """Produces findings from redacted evidence. Every finding cites evidence."""

    name: str

    def diagnose(
        self,
        incident: IncidentContext,
        evidence: list[EvidenceRecord],
        gaps: list[EvidenceGap],
    ) -> tuple[list[Finding], str]:
        """Return (findings, summary)."""
        ...


@runtime_checkable
class AuditSink(Protocol):
    """Records everything the run did, as it happens."""

    def open_run(self, incident: IncidentContext, manifest: dict[str, Any]) -> str: ...
    def record_query(self, query: RenderedQuery) -> None: ...
    def record_denial(self, request: OutboundRequest, decision: Decision) -> None: ...
    def record_evidence(self, evidence: EvidenceRecord) -> None: ...
    def record_redactions(self, evidence_id: str, hits: list[RedactionHit]) -> None: ...
    def record_gap(self, gap: EvidenceGap) -> None: ...
    def close_run(self, diagnosis: Diagnosis, manifest: dict[str, Any]) -> None: ...
