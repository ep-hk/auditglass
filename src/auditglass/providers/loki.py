"""Grafana Loki connector.

LogQL is read-only by grammar — there is no write verb to guard against — which is
part of why Loki is a first-class backend here rather than a later addition. The
interesting work is normalising streams into flat records the field policy can act on.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .base import HTTPBackedProvider, ensure_success


class LokiProvider(HTTPBackedProvider):
    backend = "loki"

    def parse(self, body: Any) -> list[dict[str, Any]]:
        data = ensure_success(body, "Loki")
        records: list[dict[str, Any]] = []
        for stream in data.get("result", []):
            labels = dict(stream.get("stream") or {})
            for entry in stream.get("values") or []:
                if len(entry) < 2:
                    continue
                ts_ns, line = entry[0], entry[1]
                record: dict[str, Any] = {
                    "timestamp": _from_ns(ts_ns),
                    "service": labels.get("app") or labels.get("service") or "",
                    "level": labels.get("level") or labels.get("severity") or "",
                    "message": line,
                }
                # Loki lines are frequently JSON. Lift recognised keys so the field
                # policy can act on them individually rather than treating the whole
                # line as free text.
                lifted = _maybe_json(line)
                if lifted:
                    for key in ("host", "client_ip", "trace_id", "error", "level", "service"):
                        if key in lifted and not record.get(key):
                            record[key] = lifted[key]
                    if "message" in lifted:
                        record["message"] = lifted["message"]
                for key, value in labels.items():
                    record.setdefault(key, value)
                records.append(record)
        records.sort(key=lambda r: str(r.get("timestamp", "")))
        return records


def _from_ns(value: Any) -> str:
    try:
        seconds = int(value) / 1_000_000_000
    except (TypeError, ValueError):
        return str(value)
    return datetime.fromtimestamp(seconds, tz=UTC).isoformat()


def _maybe_json(line: str) -> dict[str, Any] | None:
    text = (line or "").strip()
    if not text.startswith("{"):
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None
