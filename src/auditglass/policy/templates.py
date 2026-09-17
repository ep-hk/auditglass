"""Parameterised query templates.

This module is the reason the read-only property is tractable.

A planner — rule-based or model-driven — never emits a query string. It emits a
template id and a set of typed parameters. Rendering happens here, in code, from a
fixed template set loaded from configuration. The consequences:

* A query the template set does not describe cannot be expressed at all. There is
  no parameter type that accepts free text, so "also read the payroll index" is not
  a thing a planner can say.
* Validating what reaches a backend becomes a positive check rather than a denylist:
  PolicyGuard re-renders the statement from the same template and parameters and
  compares it byte for byte.
* The audit trail records ``(template_id, params)``, which a reviewer can read,
  rather than a backend-specific query language they may not know.

Parameter types are intentionally few: ``enum``, ``timerange``, ``int``, ``bool``
and ``ref``. ``ref`` accepts only a value that was actually observed in evidence
already retrieved during this run, under a strict character class — so a planner
can narrow an investigation using a trace id it genuinely saw, but cannot invent
identifiers.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..config import parse_duration
from ..errors import ParamValidationError, TemplateError
from ..models import RenderedQuery, TimeWindow

PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)\}")

#: Values supplied as ``ref`` parameters must match this. Evidence content is
#: attacker-influenced, so anything that could alter a query's structure — quotes,
#: braces, pipes, backslashes, whitespace, control characters — is not eligible.
REF_CHARSET = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


# --------------------------------------------------------------------------- #
# Escaping
# --------------------------------------------------------------------------- #


def _escape_quoted(value: str) -> str:
    """Escape a value destined for a double-quoted string in LogQL/PromQL."""
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ParamValidationError("control characters are not permitted in query values")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_plain(value: str) -> str:
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ParamValidationError("control characters are not permitted in query values")
    return value


ESCAPERS = {
    "loki": _escape_quoted,
    "prometheus": _escape_quoted,
    "elastic": _escape_quoted,
    "fixture": _escape_plain,
}


def escaper_for(backend: str):
    return ESCAPERS.get(backend, _escape_quoted)


# --------------------------------------------------------------------------- #
# Render context
# --------------------------------------------------------------------------- #


@dataclass
class RenderContext:
    """Everything a template may resolve against.

    ``observed`` is built from evidence already retrieved in this run and is what
    makes ``ref`` parameters safe: a planner may only reference values the run has
    actually seen.
    """

    scope: dict[str, Any] = field(default_factory=dict)
    incident_window: TimeWindow | None = None
    observed: dict[str, set[str]] = field(default_factory=dict)
    max_lookback_seconds: int = 86_400

    def resolve_source(self, dotted: str) -> list[str]:
        node: Any = self.scope
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                raise TemplateError(f"enum source {dotted!r} does not resolve")
            node = node[part]
        if not isinstance(node, list):
            raise TemplateError(f"enum source {dotted!r} must resolve to a list")
        return [str(v) for v in node]

    def observe(self, field_name: str, value: Any) -> None:
        if value is None:
            return
        text = str(value)
        if REF_CHARSET.match(text):
            self.observed.setdefault(field_name, set()).add(text)


# --------------------------------------------------------------------------- #
# Parameter specifications
# --------------------------------------------------------------------------- #


@dataclass
class ParamSpec:
    name: str
    required: bool = True
    default: Any = None

    def validate(self, value: Any, ctx: RenderContext) -> Any:  # pragma: no cover
        raise NotImplementedError

    def substitutions(self, value: Any, backend: str) -> dict[str, str]:
        esc = escaper_for(backend)
        return {self.name: esc(str(value))}


@dataclass
class EnumParam(ParamSpec):
    values: list[str] | None = None
    source: str | None = None

    def allowed(self, ctx: RenderContext) -> list[str]:
        if self.source:
            return ctx.resolve_source(self.source)
        return list(self.values or [])

    def validate(self, value: Any, ctx: RenderContext) -> Any:
        allowed = self.allowed(ctx)
        text = str(value)
        if text not in allowed:
            raise ParamValidationError(
                f"{self.name}={text!r} is not in the permitted set; "
                f"allowed values are {sorted(allowed)}"
            )
        return text


@dataclass
class RefParam(ParamSpec):
    from_field: str = ""

    def validate(self, value: Any, ctx: RenderContext) -> Any:
        text = str(value)
        if not REF_CHARSET.match(text):
            raise ParamValidationError(
                f"{self.name}={text!r} contains characters not permitted in a reference"
            )
        seen = ctx.observed.get(self.from_field, set())
        if text not in seen:
            raise ParamValidationError(
                f"{self.name}={text!r} was not observed in evidence retrieved during "
                f"this run (field {self.from_field!r}); references may only point at "
                f"values the run has actually seen"
            )
        return text


@dataclass
class IntParam(ParamSpec):
    minimum: int = 0
    maximum: int = 10_000

    def validate(self, value: Any, ctx: RenderContext) -> Any:
        try:
            n = int(value)
        except (TypeError, ValueError) as exc:
            raise ParamValidationError(f"{self.name} must be an integer") from exc
        if n < self.minimum or n > self.maximum:
            raise ParamValidationError(
                f"{self.name}={n} is outside the permitted range "
                f"[{self.minimum}, {self.maximum}]"
            )
        return n


@dataclass
class BoolParam(ParamSpec):
    def validate(self, value: Any, ctx: RenderContext) -> Any:
        if isinstance(value, bool):
            return value
        if str(value).lower() in {"true", "false"}:
            return str(value).lower() == "true"
        raise ParamValidationError(f"{self.name} must be a boolean")


@dataclass
class TimeRangeParam(ParamSpec):
    max_seconds: int = 21_600
    must_intersect_incident: bool = True

    def validate(self, value: Any, ctx: RenderContext) -> Any:
        if isinstance(value, TimeWindow):
            window = value
        elif isinstance(value, dict) and {"start", "end"} <= set(value):
            window = TimeWindow.from_dict(value)
        else:
            raise ParamValidationError(
                f"{self.name} must be a time window with 'start' and 'end'"
            )

        if window.duration.total_seconds() > self.max_seconds:
            raise ParamValidationError(
                f"{self.name} spans {int(window.duration.total_seconds())}s which exceeds "
                f"the template maximum of {self.max_seconds}s"
            )
        if self.must_intersect_incident:
            if ctx.incident_window is None:
                raise ParamValidationError(
                    f"{self.name} must intersect the incident window, but no incident "
                    f"window is set on the render context"
                )
            if not window.intersects(ctx.incident_window):
                raise ParamValidationError(
                    f"{self.name} does not intersect the incident window; a run may "
                    f"narrow its time range but never move outside it"
                )
        if ctx.incident_window is not None:
            drift = abs((ctx.incident_window.start - window.start).total_seconds())
            if drift > ctx.max_lookback_seconds:
                raise ParamValidationError(
                    f"{self.name} starts {int(drift)}s from the incident window, beyond "
                    f"the configured maximum lookback of {ctx.max_lookback_seconds}s"
                )
        return window

    def substitutions(self, value: Any, backend: str) -> dict[str, str]:
        w: TimeWindow = value
        return {
            self.name: f"{w.start.isoformat()}/{w.end.isoformat()}",
            f"{self.name}.start_iso": w.start.isoformat(),
            f"{self.name}.end_iso": w.end.isoformat(),
            f"{self.name}.start_unix": str(int(w.start.timestamp())),
            f"{self.name}.end_unix": str(int(w.end.timestamp())),
            f"{self.name}.start_ns": str(int(w.start.timestamp() * 1_000_000_000)),
            f"{self.name}.end_ns": str(int(w.end.timestamp() * 1_000_000_000)),
            f"{self.name}.duration_s": str(int(w.duration.total_seconds())),
        }


_PARAM_TYPES = {
    "enum": EnumParam,
    "ref": RefParam,
    "int": IntParam,
    "bool": BoolParam,
    "timerange": TimeRangeParam,
}


def _build_param(name: str, spec: dict[str, Any], template_id: str) -> ParamSpec:
    if not isinstance(spec, dict) or "type" not in spec:
        raise TemplateError(f"parameter {name!r} needs a 'type'", locator=template_id)
    kind = spec["type"]
    if kind not in _PARAM_TYPES:
        raise TemplateError(
            f"parameter {name!r} has unknown type {kind!r}; permitted types are "
            f"{sorted(_PARAM_TYPES)}. Free-text parameters are deliberately absent.",
            locator=template_id,
        )
    required = bool(spec.get("required", "default" not in spec))
    default = spec.get("default")

    if kind == "enum":
        if not spec.get("values") and not spec.get("source"):
            raise TemplateError(
                f"enum parameter {name!r} needs 'values' or 'source'", locator=template_id
            )
        return EnumParam(
            name=name,
            required=required,
            default=default,
            values=spec.get("values"),
            source=spec.get("source"),
        )
    if kind == "ref":
        if not spec.get("from"):
            raise TemplateError(
                f"ref parameter {name!r} needs 'from' naming the evidence field it "
                f"may reference",
                locator=template_id,
            )
        return RefParam(
            name=name, required=required, default=default, from_field=spec["from"]
        )
    if kind == "int":
        return IntParam(
            name=name,
            required=required,
            default=default,
            minimum=int(spec.get("min", 0)),
            maximum=int(spec.get("max", 10_000)),
        )
    if kind == "bool":
        return BoolParam(name=name, required=required, default=default)
    return TimeRangeParam(
        name=name,
        required=required,
        default=default,
        max_seconds=parse_duration(spec.get("max", "6h")),
        must_intersect_incident=spec.get("must_intersect", "incident") == "incident",
    )


# --------------------------------------------------------------------------- #
# Templates
# --------------------------------------------------------------------------- #


@dataclass
class QueryTemplate:
    id: str
    backend: str
    kind: str
    method: str
    path: str
    params: dict[str, ParamSpec]
    statement_spec: str
    query_param_specs: dict[str, str] = field(default_factory=dict)
    description: str = ""

    def _resolve(self, spec: str, subs: dict[str, str], where: str) -> str:
        def repl(m: re.Match[str]) -> str:
            key = m.group(1)
            if key not in subs:
                raise TemplateError(
                    f"placeholder {{{key}}} in {where} does not match any declared "
                    f"parameter of template {self.id!r}",
                    locator=self.id,
                )
            return subs[key]

        return PLACEHOLDER.sub(repl, spec)

    def validate_params(self, raw: dict[str, Any], ctx: RenderContext) -> dict[str, Any]:
        unknown = set(raw) - set(self.params)
        if unknown:
            raise ParamValidationError(
                f"template {self.id!r} does not accept parameter(s) {sorted(unknown)}"
            )
        resolved: dict[str, Any] = {}
        for name, spec in self.params.items():
            if name in raw and raw[name] is not None:
                resolved[name] = spec.validate(raw[name], ctx)
            elif spec.default is not None:
                resolved[name] = spec.validate(spec.default, ctx)
            elif spec.required:
                raise ParamValidationError(
                    f"template {self.id!r} requires parameter {name!r}"
                )
        return resolved

    def render(self, raw: dict[str, Any], ctx: RenderContext) -> RenderedQuery:
        resolved = self.validate_params(raw, ctx)
        subs: dict[str, str] = {}
        for name, value in resolved.items():
            subs.update(self.params[name].substitutions(value, self.backend))

        statement = self._resolve(self.statement_spec, subs, "statement")
        subs["statement"] = statement
        qp = {
            key: self._resolve(spec, subs, f"query_params.{key}")
            for key, spec in self.query_param_specs.items()
        }
        rendered = RenderedQuery(
            template_id=self.id,
            backend=self.backend,
            kind=self.kind,
            method=self.method,
            path=self.path,
            params=resolved,
            statement=statement,
        )
        # Query params travel with the rendered query but are not part of its
        # identity, so they are attached rather than being a constructor field.
        object.__setattr__(rendered, "_query_params", qp)
        return rendered


def query_params_of(rendered: RenderedQuery) -> dict[str, str]:
    return dict(getattr(rendered, "_query_params", {}) or {})


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #


class TemplateRegistry:
    def __init__(self) -> None:
        self._templates: dict[str, QueryTemplate] = {}

    def __len__(self) -> int:
        return len(self._templates)

    def __iter__(self) -> Iterator[QueryTemplate]:
        return iter(self._templates.values())

    def __contains__(self, template_id: object) -> bool:
        return template_id in self._templates

    def get(self, template_id: str) -> QueryTemplate:
        try:
            return self._templates[template_id]
        except KeyError:
            raise ParamValidationError(
                f"no such template {template_id!r}; available templates are "
                f"{sorted(self._templates)}"
            ) from None

    def for_backend(self, backend: str) -> list[QueryTemplate]:
        return [t for t in self._templates.values() if t.backend == backend]

    def add(self, template: QueryTemplate) -> None:
        if template.id in self._templates:
            raise TemplateError(f"duplicate template id {template.id!r}", locator=template.id)
        self._templates[template.id] = template

    def catalogue(self) -> list[dict[str, Any]]:
        """A description of the template set, suitable for showing a planner."""
        out = []
        for t in sorted(self._templates.values(), key=lambda x: x.id):
            params = {}
            for name, spec in t.params.items():
                entry: dict[str, Any] = {"type": type(spec).__name__.replace("Param", "").lower()}
                if isinstance(spec, EnumParam):
                    entry["values"] = spec.values or f"<from {spec.source}>"
                elif isinstance(spec, IntParam):
                    entry["range"] = [spec.minimum, spec.maximum]
                elif isinstance(spec, TimeRangeParam):
                    entry["max_seconds"] = spec.max_seconds
                elif isinstance(spec, RefParam):
                    entry["from"] = spec.from_field
                entry["required"] = spec.required
                params[name] = entry
            out.append(
                {
                    "id": t.id,
                    "backend": t.backend,
                    "kind": t.kind,
                    "description": t.description,
                    "params": params,
                }
            )
        return out

    def fingerprint(self) -> str:
        from ..models import stable_hash

        return stable_hash(self.catalogue())

    @classmethod
    def load(cls, paths: list[Path]) -> TemplateRegistry:
        reg = cls()
        for path in paths:
            reg.load_file(Path(path))
        return reg

    def load_file(self, path: Path) -> None:
        if not path.is_file():
            raise TemplateError(f"template file not found: {path}")
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise TemplateError(f"could not parse template file: {exc}", locator=str(path)) from exc
        backend = doc.get("backend")
        if not backend:
            raise TemplateError("template file needs a top-level 'backend'", locator=str(path))
        for raw in doc.get("templates", []):
            self.add(self._build(raw, backend, str(path)))

    @staticmethod
    def _build(raw: dict[str, Any], backend: str, locator: str) -> QueryTemplate:
        for required in ("id", "kind", "statement"):
            if required not in raw:
                raise TemplateError(f"template is missing {required!r}", locator=locator)
        method = str(raw.get("method", "GET")).upper()
        if method not in {"GET", "POST"}:
            raise TemplateError(
                f"template {raw['id']!r} declares method {method!r}; only GET and POST "
                f"are supported",
                locator=locator,
            )
        params = {
            name: _build_param(name, spec, raw["id"])
            for name, spec in (raw.get("params") or {}).items()
        }
        template = QueryTemplate(
            id=raw["id"],
            backend=backend,
            kind=raw["kind"],
            method=method,
            path=raw.get("path", "/"),
            params=params,
            statement_spec=raw["statement"],
            query_param_specs=dict(raw.get("query_params") or {}),
            description=raw.get("description", ""),
        )
        # Fail at load time, not at incident time, if a placeholder cannot resolve.
        known = {"statement"}
        for name, spec in params.items():
            known.add(name)
            if isinstance(spec, TimeRangeParam):
                known.update(
                    f"{name}.{suffix}"
                    for suffix in (
                        "start_iso",
                        "end_iso",
                        "start_unix",
                        "end_unix",
                        "start_ns",
                        "end_ns",
                        "duration_s",
                    )
                )
        for spec_text, where in [(template.statement_spec, "statement")] + [
            (v, f"query_params.{k}") for k, v in template.query_param_specs.items()
        ]:
            for m in PLACEHOLDER.finditer(spec_text):
                if m.group(1) not in known:
                    raise TemplateError(
                        f"template {template.id!r} references {{{m.group(1)}}} in {where}, "
                        f"which is not a declared parameter",
                        locator=locator,
                    )
        return template
