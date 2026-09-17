"""The diagnostic run loop.

Order of operations per query, and why each step is where it is:

1. **Render** from template + parameters. A parameter the template rejects — a service
   outside scope, a window that does not intersect the incident, a reference to a
   value never observed — ends here, as a recorded gap rather than a request.
2. **Dispatch** through the constrained client, which asks PolicyGuard first.
3. **Hash the raw response** before anything touches it, so the audit trail attests
   to what the backend actually returned.
4. **Redact**, before the records reach a planner or a reasoner. A redaction failure
   aborts the run; it never degrades to passing data through.
5. **Observe** values from the *redacted* records, so that later ``ref`` parameters
   can only point at things a planner legitimately saw.

Termination is always explicit and always recorded: evidence sufficient, budget
exhausted, no new evidence, or plan complete. A report is produced in every case,
including when the run ends early — a partial report that says what it could not see
is more useful during an incident than no report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .errors import ParamValidationError, PolicyViolation, ProviderError, ReasonerError
from .interfaces import Planner, PlanState, Reasoner
from .models import (
    BudgetLedger,
    Diagnosis,
    EvidenceGap,
    EvidenceRecord,
    IncidentContext,
    QueryRequest,
    Termination,
    stable_hash,
    utcnow,
)
from .policy.templates import RenderContext, TemplateRegistry
from .redact.redactor import DeterministicRedactor

#: Fields whose values are remembered so that ``ref`` parameters have something to
#: point at. Kept small on purpose: a planner should be able to follow a trace, not
#: to accumulate a corpus.
OBSERVABLE_FIELDS = ("trace_id", "span_id", "request_id", "host", "pod")


@dataclass
class DiagnosticRun:
    config: Config
    registry: TemplateRegistry
    planner: Planner
    providers: dict[str, Any]
    redactor: DeterministicRedactor
    reasoner: Reasoner
    sink: Any
    guard: Any = None
    manifest: dict[str, Any] = field(default_factory=dict)

    def execute(self, incident: IncidentContext) -> Diagnosis:
        ledger = BudgetLedger(self.config.budget.to_budget())
        context = RenderContext(
            scope=self.config.scope_dict(),
            incident_window=incident.window,
            max_lookback_seconds=max(86_400, int(incident.window.duration.total_seconds() * 4)),
        )
        # The guard verifies by re-rendering, so it must hold the same context this
        # run renders against — the incident window included.
        if self.guard is not None:
            self.guard.bind_context(context)
        state = PlanState(incident=incident, round_index=0)
        base_manifest = self._manifest(incident, ledger)
        self.sink.open_run(incident, base_manifest)

        counter = 0
        termination = Termination.PLAN_COMPLETE
        barren_rounds = 0

        while True:
            exhausted = ledger.exhausted()
            if exhausted:
                termination = Termination.BUDGET_EXHAUSTED
                self.sink.record_gap(
                    EvidenceGap("<budget>", {}, exhausted, utcnow())
                )
                state.gaps.append(EvidenceGap("<budget>", {}, exhausted, utcnow()))
                break

            try:
                requests = self.planner.next_round(state)
            except ReasonerError as exc:
                termination = Termination.ABORTED
                gap = EvidenceGap("<planner>", {}, f"planner failed: {exc}", utcnow())
                state.gaps.append(gap)
                self.sink.record_gap(gap)
                break

            if not requests:
                termination = (
                    Termination.SUFFICIENT if state.evidence else Termination.PLAN_COMPLETE
                )
                break

            gained = 0
            for request in requests:
                if ledger.exhausted():
                    break
                counter += 1
                outcome = self._run_one(request, context, state, ledger, counter)
                if outcome:
                    gained += 1
                state.executed.add(request.key())

            state.round_index += 1
            ledger.rounds += 1

            barren_rounds = barren_rounds + 1 if gained == 0 else 0
            if barren_rounds >= 2:
                termination = Termination.NO_NEW_EVIDENCE
                break

        findings, summary = self._reason(incident, state)
        diagnosis = Diagnosis(
            incident=incident,
            findings=findings,
            gaps=state.gaps,
            termination=termination,
            rounds_used=state.round_index,
            summary=summary,
        )

        final = self._manifest(incident, ledger)
        if self.config.redaction.write_reverse_map and hasattr(self.sink, "record_reverse_map"):
            self.sink.record_reverse_map(self.redactor.pseudonymiser.reverse)
        self._persist_prompts()
        self.sink.close_run(diagnosis, final)
        return diagnosis

    # ------------------------------------------------------------------ #

    def _run_one(
        self,
        request: QueryRequest,
        context: RenderContext,
        state: PlanState,
        ledger: BudgetLedger,
        counter: int,
    ) -> bool:
        try:
            template = self.registry.get(request.template_id)
            rendered = template.render(request.params, context)
        except ParamValidationError as exc:
            # The expected outcome when something tries to reach outside scope. It is
            # a recorded gap, not a crash, and the run carries on.
            self._gap(state, request.template_id, request.params, f"rejected: {exc}")
            return False

        provider = self.providers.get(rendered.backend)
        if provider is None:
            self._gap(
                state,
                request.template_id,
                request.params,
                f"no provider configured for backend {rendered.backend!r}",
            )
            return False

        self.sink.record_query(rendered)
        ledger.queries += 1

        try:
            raw_records, truncated = provider.fetch(rendered)
        except PolicyViolation as exc:
            self._gap(state, request.template_id, request.params, f"denied by policy: {exc}")
            return False
        except ProviderError as exc:
            self._gap(state, request.template_id, request.params, f"backend unavailable: {exc}")
            return False

        response_hash = stable_hash(raw_records)
        result = self.redactor.process(raw_records, rendered.kind)

        evidence = EvidenceRecord(
            evidence_id=f"E{counter}",
            query=rendered,
            kind=rendered.kind,
            records=result.records,
            response_hash=response_hash,
            retrieved_at=utcnow(),
            truncated=truncated,
            injection_suspected=result.injection_suspected,
            injection_markers=result.injection_markers,
        )
        self.sink.record_evidence(evidence)
        self.sink.record_redactions(evidence.evidence_id, result.hits)
        state.evidence.append(evidence)
        ledger.records += len(result.records)

        for record in result.records:
            for name in OBSERVABLE_FIELDS:
                if name in record:
                    context.observe(name, record[name])

        return bool(result.records)

    def _gap(self, state: PlanState, template_id: str, params: dict, reason: str) -> None:
        gap = EvidenceGap(template_id, params, reason, utcnow())
        state.gaps.append(gap)
        self.sink.record_gap(gap)

    def _reason(self, incident: IncidentContext, state: PlanState):
        try:
            return self.reasoner.diagnose(incident, state.evidence, state.gaps)
        except ReasonerError as exc:
            from .models import Confidence, Finding

            return (
                [
                    Finding(
                        f"The reasoner did not produce a usable diagnosis ({exc}). The "
                        f"evidence below was still retrieved and is recorded in full.",
                        [],
                        Confidence.SPECULATIVE,
                    )
                ],
                "Reasoning step failed; evidence is intact.",
            )

    def _persist_prompts(self) -> None:
        if not self.config.audit.write_prompts or not hasattr(self.sink, "record_prompt"):
            return
        for label, holder, attr in (
            ("reasoner", self.reasoner, "last_prompt"),
            ("reasoner-response", self.reasoner, "last_response"),
            ("planner-transcript", self.planner, "transcript"),
        ):
            payload = getattr(holder, attr, None)
            if payload:
                self.sink.record_prompt(label, payload)

    def _manifest(self, incident: IncidentContext, ledger: BudgetLedger) -> dict[str, Any]:
        return {
            "tool": "auditglass",
            "tool_version": _version(),
            "started_at": self.manifest.get("started_at") or utcnow().isoformat(),
            "incident": incident.to_dict(),
            "trigger_source": incident.trigger_source,
            "config_path": str(self.config.source_path or ""),
            "config_hash": self.config.config_hash(),
            "template_fingerprint": self.registry.fingerprint(),
            "template_count": len(self.registry),
            "policy_endpoints": [e.name for e in self.config.policy.endpoints],
            "planner": getattr(self.planner, "name", type(self.planner).__name__),
            "reasoner": getattr(self.reasoner, "name", type(self.reasoner).__name__),
            "model": self.config.reasoner.model,
            "redaction": {
                "salt_scope": self.config.redaction.salt_scope,
                "strict_fields": self.config.redaction.strict_fields,
                "rules": list(self.config.redaction.rules),
                "reverse_map_written": self.config.redaction.write_reverse_map,
            },
            "budget": ledger.to_dict(),
            **{k: v for k, v in self.manifest.items() if k != "started_at"},
        }


def _version() -> str:
    from . import __version__

    return __version__
