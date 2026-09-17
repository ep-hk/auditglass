"""Fixture-backed provider.

Reads synthetic evidence from a JSON file instead of a live backend. This is what
makes the quickstart work in well under five minutes with no backend, no credentials
and no API key, and it is what the whole test suite runs against.

It is also the honest way to ship a demo: every record in ``demo/fixtures/`` is
synthetic and was written for this repository. No production system anywhere is
described by it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..errors import PolicyViolation, ProviderError
from ..models import RenderedQuery, TimeWindow, _parse_dt
from .base import build_request


class FixtureProvider:
    backend = "fixture"

    def __init__(
        self,
        path: Path,
        max_records: int = 5000,
        fail_backends: set[str] | None = None,
        guard=None,
        endpoint=None,
    ):
        self._path = Path(path)
        self._max_records = max_records
        #: Used by tests and by the demo's ``--simulate-outage`` flag to exercise the
        #: partial-evidence path, which is otherwise hard to reach deliberately.
        self._fail_kinds = fail_backends or set()
        # The fixture never touches the network, but it still goes through
        # PolicyGuard. Otherwise the demo — the thing most people will actually run —
        # would skip the control the project is mostly about.
        self._guard = guard
        self._endpoint = endpoint
        if not self._path.is_file():
            raise ProviderError(f"fixture file not found: {self._path}")
        try:
            self._data = json.loads(self._path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProviderError(f"fixture file is not valid JSON: {exc}") from exc

    # ------------------------------------------------------------------ #

    def fetch(self, query: RenderedQuery) -> tuple[list[dict[str, Any]], bool]:
        if self._guard is not None and self._endpoint is not None:
            decision = self._guard.authorize(build_request(query, self._endpoint))
            if not decision.allowed:
                raise PolicyViolation(decision.reason, decision.rule)

        if query.kind in self._fail_kinds:
            raise ProviderError(
                f"simulated backend outage for {query.kind!r} evidence"
            )

        pool = list(self._data.get(query.kind, []))
        params = query.params

        window: TimeWindow | None = params.get("window")
        if window is not None:
            pool = [r for r in pool if _in_window(r, window)]

        for key in ("service", "level", "metric"):
            wanted = params.get(key)
            if wanted is not None:
                pool = [r for r in pool if str(r.get(key)) == str(wanted)]

        trace = params.get("trace_id")
        if trace is not None:
            pool = [r for r in pool if str(r.get("trace_id")) == str(trace)]

        pool.sort(key=lambda r: str(r.get("timestamp", "")))
        limit = int(params.get("limit", self._max_records))
        truncated = len(pool) > limit
        return pool[:limit], truncated


def _in_window(record: dict[str, Any], window: TimeWindow) -> bool:
    raw = record.get("timestamp")
    if raw is None:
        return True
    try:
        ts = _parse_dt(raw)
    except (ValueError, TypeError):
        return True
    return window.start <= ts <= window.end
