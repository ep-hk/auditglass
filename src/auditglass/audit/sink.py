"""Run directories.

Records are written *as the run proceeds*, not assembled at the end. That detail is
the difference between an audit trail and a summary: a run that aborts — because
redaction failed, or a budget was hit, or the process was killed — still leaves
behind exactly what it had done up to that point.

Layout::

    runs/<run_id>/
      manifest.json        configuration, policy, template set, model, budget
      queries.jsonl        every query dispatched, template + params + statement
      denials.jsonl        every request PolicyGuard refused, with cause
      evidence.jsonl       evidence metadata, one line per block
      evidence/<id>.json   the redacted records themselves
      redactions.jsonl     which rule fired where — never the original value
      gaps.jsonl           what could not be retrieved, and why
      prompts/             model input and output, when a model was used
      reverse-map.json     token -> original, local only, optional
      report.md            the human-readable report
      report.json          the machine-readable equivalent

``reverse-map.json`` is the only file that contains original values. It never leaves
the run directory, and ``redaction.write_reverse_map: false`` stops it being written
at all.
"""

from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..interfaces import RedactionHit
from ..models import (
    Decision,
    Diagnosis,
    EvidenceGap,
    EvidenceRecord,
    OutboundRequest,
    RenderedQuery,
    utcnow,
)
from .report import render_markdown


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")


class LocalRunDirectory:
    """Filesystem audit sink. The reference implementation of the protocol."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.run_dir: Path | None = None
        self.run_id: str = ""
        self._evidence: list[EvidenceRecord] = []
        #: Denials that happened before a run opened — a policy check, or a client
        #: used directly. They are buffered rather than dropped, and never allowed to
        #: raise: an audit hook that can crash the thing it audits is worse than no
        #: hook, and PolicyGuard calls this from inside its refusal path.
        self._pending_denials: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ #

    def open_run(self, incident, manifest: dict[str, Any]) -> str:
        stamp = utcnow().strftime("%Y%m%dT%H%M%SZ")
        safe_incident = "".join(
            c for c in incident.incident_id if c.isalnum() or c in "-_"
        )[:40] or "incident"
        self.run_id = f"{stamp}-{safe_incident}"
        self.run_dir = self.root / self.run_id
        (self.run_dir / "evidence").mkdir(parents=True, exist_ok=True)
        (self.run_dir / "prompts").mkdir(parents=True, exist_ok=True)
        # Written immediately so an aborted run still has provenance.
        self._write_manifest({**manifest, "run_id": self.run_id, "status": "running"})
        for entry in self._pending_denials:
            _append_jsonl(self._path("denials.jsonl"), entry)
        self._pending_denials.clear()
        return self.run_id

    def _write_manifest(self, manifest: dict[str, Any]) -> None:
        assert self.run_dir is not None
        (self.run_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )

    def _path(self, name: str) -> Path:
        assert self.run_dir is not None, "open_run must be called first"
        return self.run_dir / name

    # ------------------------------------------------------------------ #

    def record_query(self, query: RenderedQuery) -> None:
        _append_jsonl(self._path("queries.jsonl"), {"at": utcnow(), **query.to_dict()})

    def record_denial(self, request: OutboundRequest, decision: Decision) -> None:
        entry = {
            "at": utcnow(),
            "request": request.describe(),
            "rule": decision.rule,
            "reason": decision.reason,
        }
        if self.run_dir is None:
            self._pending_denials.append(entry)
            return
        _append_jsonl(self._path("denials.jsonl"), entry)

    def record_evidence(self, evidence: EvidenceRecord) -> None:
        self._evidence.append(evidence)
        _append_jsonl(self._path("evidence.jsonl"), evidence.to_dict(include_records=False))
        (self._path("evidence") / f"{evidence.evidence_id}.json").write_text(
            json.dumps(evidence.to_dict(), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    def record_redactions(self, evidence_id: str, hits: list[RedactionHit]) -> None:
        for hit in hits:
            _append_jsonl(
                self._path("redactions.jsonl"), {"evidence_id": evidence_id, **hit.to_dict()}
            )

    def record_gap(self, gap: EvidenceGap) -> None:
        _append_jsonl(self._path("gaps.jsonl"), gap.to_dict())

    def record_prompt(self, label: str, payload: Any) -> None:
        safe = "".join(c for c in label if c.isalnum() or c in "-_") or "prompt"
        (self._path("prompts") / f"{safe}.json").write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )

    def record_reverse_map(self, mapping: dict[str, str]) -> None:
        if not mapping:
            return
        path = self._path("reverse-map.json")
        path.write_text(
            json.dumps(mapping, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        os.chmod(path, 0o600)

    # ------------------------------------------------------------------ #

    def close_run(self, diagnosis: Diagnosis, manifest: dict[str, Any]) -> None:
        final = {**manifest, "run_id": self.run_id, "status": "complete",
                 "finished_at": utcnow().isoformat()}
        self._write_manifest(final)
        self._path("report.md").write_text(
            render_markdown(diagnosis, self._evidence, final), encoding="utf-8"
        )
        self._path("report.json").write_text(
            json.dumps(diagnosis.to_dict(), indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )

    def abort_run(self, reason: str, manifest: dict[str, Any]) -> None:
        self._write_manifest(
            {**manifest, "run_id": self.run_id, "status": "aborted", "abort_reason": reason,
             "finished_at": utcnow().isoformat()}
        )


# --------------------------------------------------------------------------- #


def purge(root: Path, retention_days: int, dry_run: bool = False) -> list[str]:
    """Delete run directories older than the retention period.

    Run directories accumulate production-derived data. Set retention before the
    first production run, not after — on day one the directory is empty and it is
    easy to forget it will not stay that way.
    """
    root = Path(root)
    if not root.is_dir():
        return []
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    removed: list[str] = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        modified = datetime.fromtimestamp(child.stat().st_mtime, tz=UTC)
        if modified < cutoff:
            removed.append(child.name)
            if not dry_run:
                shutil.rmtree(child)
    return removed
