"""A reasoner that needs no language model.

It states only what the evidence supports, cites the evidence id behind every
sentence, and labels anything it cannot support as speculation. That constraint is
the same one imposed on the model-backed reasoner — the difference is that here it
is arithmetic rather than instruction-following, which makes it a useful control
when testing whether a report is being steered by its inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..models import Confidence, EvidenceGap, EvidenceRecord, Finding, IncidentContext


@dataclass
class RulebookReasoner:
    name: str = "rulebook"
    saturation_threshold: float = 0.95
    latency_multiple: float = 2.0

    def diagnose(
        self,
        incident: IncidentContext,
        evidence: list[EvidenceRecord],
        gaps: list[EvidenceGap],
    ) -> tuple[list[Finding], str]:
        findings: list[Finding] = []
        primary = incident.primary_service

        error_counts = _errors_by_service(evidence)
        primary_errors = error_counts.get(primary, (0, []))
        if primary_errors[0]:
            findings.append(
                Finding(
                    f"{primary} logged {primary_errors[0]} error(s) during the incident "
                    f"window.",
                    primary_errors[1],
                )
            )

        saturation = _saturation(evidence)
        if saturation is not None:
            ratio, ids = saturation
            if ratio >= self.saturation_threshold:
                findings.append(
                    Finding(
                        f"{primary}'s connection pool reached {ratio:.0%} of its "
                        f"configured maximum, so requests were waiting on a connection "
                        f"rather than on work.",
                        ids,
                    )
                )
            else:
                findings.append(
                    Finding(
                        f"{primary}'s connection pool peaked at {ratio:.0%} of its "
                        f"maximum, which does not indicate saturation.",
                        ids,
                    )
                )

        latency = _latency_elevation(evidence, primary)
        for service, (baseline, peak, ids) in latency.items():
            if baseline > 0 and peak / baseline >= self.latency_multiple:
                findings.append(
                    Finding(
                        f"{service} p99 latency rose from {baseline:.0f}ms to "
                        f"{peak:.0f}ms within the window ({peak / baseline:.1f}x).",
                        ids,
                    )
                )

        causal = _causal_chain(primary, saturation, latency, self.saturation_threshold,
                               self.latency_multiple)
        if causal:
            statement, ids = causal
            findings.append(Finding(statement, ids))

        for service, (count, ids) in error_counts.items():
            if service != primary and count:
                findings.append(
                    Finding(f"{service} logged {count} error(s) in the same window.", ids)
                )

        marked = [e.evidence_id for e in evidence if e.injection_suspected]
        if marked:
            findings.append(
                Finding(
                    "One or more evidence blocks contain instruction-like content and "
                    "are marked below. Treat their narrative content as untrusted; the "
                    "surrounding measurements are unaffected.",
                    marked,
                )
            )

        if not findings:
            findings.append(
                Finding(
                    "No supporting evidence was retrieved for this window. The gaps "
                    "listed below explain what could not be examined.",
                    [],
                    Confidence.SPECULATIVE,
                )
            )

        return findings, _summary(primary, findings, gaps)


# --------------------------------------------------------------------------- #


def _errors_by_service(evidence: list[EvidenceRecord]) -> dict[str, tuple[int, list[str]]]:
    out: dict[str, tuple[int, list[str]]] = {}
    for item in evidence:
        if item.kind != "logs":
            continue
        for record in item.records:
            if str(record.get("level", "")).casefold() != "error":
                continue
            service = str(record.get("service") or "unknown")
            count, ids = out.get(service, (0, []))
            if item.evidence_id not in ids:
                ids = [*ids, item.evidence_id]
            out[service] = (count + 1, ids)
    return out


def _metric_points(evidence: list[EvidenceRecord], metric: str, service: str | None = None):
    points: list[tuple[str, float]] = []
    ids: list[str] = []
    for item in evidence:
        if item.kind != "metrics":
            continue
        for record in item.records:
            if record.get("metric") != metric:
                continue
            if service is not None and str(record.get("service")) != service:
                continue
            value = record.get("value")
            if isinstance(value, (int, float)):
                points.append((str(record.get("timestamp", "")), float(value)))
                if item.evidence_id not in ids:
                    ids.append(item.evidence_id)
    points.sort(key=lambda p: p[0])
    return points, ids


def _saturation(evidence: list[EvidenceRecord]) -> tuple[float, list[str]] | None:
    active, active_ids = _metric_points(evidence, "connection_pool_active")
    limit, limit_ids = _metric_points(evidence, "connection_pool_max")
    if not active or not limit:
        return None
    ceiling = max(v for _, v in limit)
    if ceiling <= 0:
        return None
    peak = max(v for _, v in active)
    return peak / ceiling, sorted(set(active_ids + limit_ids))


def _latency_elevation(
    evidence: list[EvidenceRecord], exclude: str
) -> dict[str, tuple[float, float, list[str]]]:
    services: set[str] = set()
    for item in evidence:
        if item.kind != "metrics":
            continue
        for record in item.records:
            if record.get("metric") == "request_latency_p99":
                services.add(str(record.get("service")))
    out: dict[str, tuple[float, float, list[str]]] = {}
    for service in sorted(services - {exclude, "None", ""}):
        points, ids = _metric_points(evidence, "request_latency_p99", service)
        if len(points) < 2:
            continue
        values = [v for _, v in points]
        head = values[: max(1, len(values) // 4)]
        baseline = sum(head) / len(head)
        out[service] = (baseline, max(values), ids)
    return out


def _causal_chain(
    primary: str,
    saturation: tuple[float, list[str]] | None,
    latency: dict[str, tuple[float, float, list[str]]],
    saturation_threshold: float,
    latency_multiple: float,
) -> tuple[str, list[str]] | None:
    if saturation is None or saturation[0] < saturation_threshold:
        return None
    culprits = [
        (service, data)
        for service, data in latency.items()
        if data[0] > 0 and data[1] / data[0] >= latency_multiple
    ]
    if not culprits:
        return None
    service, (_, _, ids) = max(culprits, key=lambda kv: kv[1][1] / max(kv[1][0], 1e-9))
    return (
        f"The most consistent reading of the evidence is that latency degradation in "
        f"{service} held {primary}'s connections open long enough to exhaust its pool, "
        f"which then surfaced upstream as timeouts. This is a correlation in time "
        f"across the cited evidence, not a proven cause.",
        sorted(set(ids + saturation[1])),
    )


def _summary(primary: str, findings: list[Finding], gaps: list[EvidenceGap]) -> str:
    supported = sum(1 for f in findings if f.confidence == Confidence.SUPPORTED)
    text = (
        f"{supported} supported finding(s) for {primary} from the evidence retrieved."
    )
    if gaps:
        text += f" {len(gaps)} piece(s) of evidence could not be retrieved; see Evidence gaps."
    return text


def estimate_tokens(payload: Any) -> int:
    """Rough token estimate used for budget accounting when no model is called."""
    return max(1, len(str(payload)) // 4)
