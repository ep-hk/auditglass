"""Prometheus connector.

PromQL, like LogQL, has no write form. The remote-write endpoint is a separate path
and is simply never declared in ``policy.endpoints``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .base import HTTPBackedProvider


class PrometheusProvider(HTTPBackedProvider):
    backend = "prometheus"

    def parse(self, body: Any) -> list[dict[str, Any]]:
        data = (body or {}).get("data") or {}
        result_type = data.get("resultType")
        records: list[dict[str, Any]] = []

        for series in data.get("result", []):
            labels = dict(series.get("metric") or {})
            name = labels.get("__name__", "")
            service = labels.get("service") or labels.get("job") or labels.get("app") or ""

            if result_type == "matrix":
                points = series.get("values") or []
            elif result_type == "vector":
                points = [series.get("value")] if series.get("value") else []
            else:
                points = []

            for point in points:
                if not point or len(point) < 2:
                    continue
                records.append(
                    {
                        "timestamp": _from_unix(point[0]),
                        "service": service,
                        "metric": name,
                        "value": _as_float(point[1]),
                        **{
                            k: v
                            for k, v in labels.items()
                            if k not in {"__name__", "service", "job", "app"}
                        },
                    }
                )
        records.sort(key=lambda r: (str(r.get("metric", "")), str(r.get("timestamp", ""))))
        return records


def _from_unix(value: Any) -> str:
    try:
        return datetime.fromtimestamp(float(value), tz=UTC).isoformat()
    except (TypeError, ValueError):
        return str(value)


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
