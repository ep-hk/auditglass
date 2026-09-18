"""Prometheus connector.

PromQL, like LogQL, has no write form. The remote-write endpoint is a separate path
and is simply never declared in ``policy.endpoints``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ..errors import ProviderError
from .base import HTTPBackedProvider, ensure_success

#: Shapes this connector knows how to read. ``scalar`` and ``string`` are valid
#: Prometheus result types but carry no series, so a template producing one is a
#: template bug — raised rather than silently returning no records.
READABLE_RESULT_TYPES = frozenset({"matrix", "vector"})


class PrometheusProvider(HTTPBackedProvider):
    backend = "prometheus"

    def parse(self, body: Any) -> list[dict[str, Any]]:
        data = ensure_success(body, "Prometheus")
        result_type = data.get("resultType")
        if data and result_type is not None and result_type not in READABLE_RESULT_TYPES:
            raise ProviderError(
                f"Prometheus returned resultType {result_type!r}, which carries no time "
                f"series; this connector reads {sorted(READABLE_RESULT_TYPES)}"
            )
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


def _as_float(value: Any) -> float:
    """Prometheus sends sample values as strings, including NaN, +Inf and -Inf.

    A value that will not parse means the response is not the shape we think it is,
    so it is raised rather than turned into None — a None would flow into the reasoner
    as a missing measurement and quietly weaken a conclusion.
    """
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ProviderError(
            f"Prometheus sample value {value!r} is not a number"
        ) from exc
