"""Triggers.

There is deliberately no HTTP server here. Running one would mean authentication,
TLS, a deployment story and a new listening port — all of which a security reviewer
must assess — to gain something a file already provides. An organisation that wants
webhook delivery can point its existing ingress at ``--alert-payload``.

The important property of this module: **the alert cannot widen scope.** Whatever a
payload claims, the resulting scope is the intersection of the payload with
``scope.services`` from configuration. An alert naming a service the deployment does
not cover is rejected, not quietly honoured.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import timedelta
from pathlib import Path
from typing import Any

from ..config import Config
from ..errors import ConfigError
from ..models import IncidentContext, TimeWindow, _parse_dt, utcnow


def _window_from(payload: dict[str, Any], config: Config) -> TimeWindow:
    if payload.get("window"):
        return TimeWindow.from_dict(payload["window"])
    if payload.get("start") and payload.get("end"):
        return TimeWindow(_parse_dt(payload["start"]), _parse_dt(payload["end"]))
    end = _parse_dt(payload["at"]) if payload.get("at") else utcnow()
    return TimeWindow(end - timedelta(seconds=config.default_window_seconds()), end)


def incident_from_payload(
    payload: dict[str, Any], config: Config, source: str = "payload"
) -> IncidentContext:
    primary = payload.get("service") or payload.get("primary_service")
    if not primary:
        raise ConfigError("alert payload must name a 'service'")
    if primary not in config.scope.services:
        raise ConfigError(
            f"alert names service {primary!r}, which is not in scope.services for this "
            f"deployment ({sorted(config.scope.services)}). Scope comes from "
            f"configuration; an alert cannot extend it."
        )

    requested = payload.get("services") or []
    unknown = set(requested) - set(config.scope.services)
    if unknown:
        raise ConfigError(
            f"alert names service(s) outside this deployment's scope: {sorted(unknown)}"
        )

    services = [primary]
    services += [s for s in requested if s not in services]
    services += [s for s in config.scope.downstreams(primary) if s not in services]

    return IncidentContext(
        incident_id=str(payload.get("incident_id") or payload.get("id") or f"inc-{primary}"),
        primary_service=primary,
        services=tuple(services),
        window=_window_from(payload, config),
        trigger_source=source,
        alert=payload,
    )


class FilePayloadTrigger:
    """Reads one alert payload from a JSON file (or ``-`` for stdin)."""

    name = "file"

    def __init__(self, path: str | Path, config: Config) -> None:
        self._path = path
        self._config = config

    def incidents(self) -> Iterable[IncidentContext]:
        import sys

        if str(self._path) == "-":
            raw = sys.stdin.read()
        else:
            raw = Path(self._path).read_text(encoding="utf-8")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"alert payload is not valid JSON: {exc}") from exc
        yield incident_from_payload(payload, self._config, source=f"file:{self._path}")


class CLITrigger:
    """Manual invocation: a service name and a time window."""

    name = "cli"

    def __init__(
        self,
        config: Config,
        service: str,
        window: TimeWindow | None = None,
        incident_id: str | None = None,
    ) -> None:
        self._config = config
        self._service = service
        self._window = window
        self._incident_id = incident_id

    def incidents(self) -> Iterable[IncidentContext]:
        payload: dict[str, Any] = {"service": self._service}
        if self._incident_id:
            payload["incident_id"] = self._incident_id
        if self._window:
            payload["window"] = self._window.to_dict()
        yield incident_from_payload(payload, self._config, source="cli")
