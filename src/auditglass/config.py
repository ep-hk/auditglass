"""Declarative configuration.

Configuration is the read-only boundary. Everything that decides what the agent may
reach lives here, in a file intended for version control, and the hash of the
effective configuration is recorded in every run manifest so that a change is
visible in the artefacts of every subsequent run.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .errors import ConfigError
from .models import Budget, stable_hash

_DURATION = re.compile(r"^(\d+)([smhd])$")
_MULT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(text: str) -> int:
    """Parse ``30s`` / ``15m`` / ``6h`` / ``7d`` into seconds."""
    m = _DURATION.match(str(text).strip())
    if not m:
        raise ConfigError(f"invalid duration {text!r}; expected forms like 15m, 6h, 7d")
    return int(m.group(1)) * _MULT[m.group(2)]


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #


HttpMethod = Literal["GET", "POST"]


def _default_methods() -> list[HttpMethod]:
    # A named, annotated factory rather than a lambda: mypy 2 infers a lambda's
    # return as list[str], which does not satisfy list[Literal[...]].
    return ["GET"]


class EndpointPolicy(Base):
    """One allowed destination. Anything not described here is denied."""

    name: str
    backend: str
    scheme: Literal["http", "https"] = "https"
    host: str
    port: int | None = None
    paths: list[str] = Field(default_factory=list)
    methods: list[HttpMethod] = Field(default_factory=_default_methods)

    @field_validator("paths")
    @classmethod
    def _paths_absolute(cls, v: list[str]) -> list[str]:
        for p in v:
            if not p.startswith("/"):
                raise ValueError(f"path {p!r} must start with '/'")
            if "*" in p:
                raise ValueError(
                    f"path {p!r} must be exact; wildcards are not accepted because "
                    "they make the allowlist hard to reason about"
                )
        return v

    def effective_port(self) -> int:
        return self.port if self.port is not None else (443 if self.scheme == "https" else 80)


class PolicyConfig(Base):
    endpoints: list[EndpointPolicy] = Field(default_factory=list)
    # Defence in depth only. The primary control is that PolicyGuard re-derives the
    # statement from the template and compares it byte-for-byte; this list exists to
    # catch a template that was itself authored badly.
    forbidden_substrings: list[str] = Field(
        default_factory=lambda: [
            "| collect",
            "| outputlookup",
            "| sendalert",
            "| script",
            "| rest",
            "_bulk",
            "_delete_by_query",
            "_update_by_query",
            "delete ",
            "drop ",
            "insert ",
            "update ",
        ]
    )
    request_timeout: str = "20s"
    rate_limit_per_second: float = 4.0

    def timeout_seconds(self) -> float:
        return float(parse_duration(self.request_timeout))


# --------------------------------------------------------------------------- #


class ScopeConfig(Base):
    """The frozen scope for a run.

    ``services`` is the complete set of service names any template parameter may
    take. ``topology`` declares which downstream services may be examined when
    investigating a given service. Both come from configuration; neither can be
    extended by a planner, a model, or anything read from a backend.
    """

    services: list[str] = Field(min_length=1)
    topology: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _topology_within_services(self) -> ScopeConfig:
        known = set(self.services)
        for svc, downstreams in self.topology.items():
            if svc not in known:
                raise ValueError(f"topology key {svc!r} is not in scope.services")
            unknown = set(downstreams) - known
            if unknown:
                raise ValueError(
                    f"topology for {svc!r} names services not in scope.services: {sorted(unknown)}"
                )
        return self

    def downstreams(self, service: str) -> list[str]:
        return list(self.topology.get(service, []))


# --------------------------------------------------------------------------- #


class CustomRule(Base):
    name: str
    pattern: str
    token_prefix: str

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
        return v


class FieldPolicy(Base):
    """Which fields of a record may be considered at all.

    This is a positive control: fields not listed never reach the reasoner. It is
    stronger than scanning every field for patterns, because it does not depend on
    recognising sensitive content.
    """

    allow: list[str] = Field(default_factory=list)
    #: Fields whose contents are unstructured and therefore pattern-scanned and
    #: checked for injected instructions.
    free_text: list[str] = Field(default_factory=list)
    #: Fields whose entire value is replaced by a stable token, keyed by the token
    #: prefix to use. Preferred over pattern-scanning wherever the field is known to
    #: hold one identifier, because it does not depend on recognising the format.
    pseudonymise: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _subsets_of_allow(self) -> FieldPolicy:
        allowed = set(self.allow)
        unknown = set(self.free_text) - allowed
        if unknown:
            raise ValueError(f"free_text fields must also be in allow: {sorted(unknown)}")
        unknown = set(self.pseudonymise) - allowed
        if unknown:
            raise ValueError(f"pseudonymise fields must also be in allow: {sorted(unknown)}")
        overlap = set(self.free_text) & set(self.pseudonymise)
        if overlap:
            raise ValueError(
                f"fields cannot be both free_text and pseudonymise: {sorted(overlap)}"
            )
        return self


class RedactionConfig(Base):
    salt_scope: Literal["run", "deployment"] = "run"
    deployment_salt_env: str = "AUDITGLASS_SALT"
    strict_fields: bool = False
    write_reverse_map: bool = True
    rules: list[str] = Field(
        default_factory=lambda: [
            "secret_token",
            "email",
            "ipv4",
            "ipv6",
            "card_number",
            "account_number",
            "phone",
        ]
    )
    custom_rules: list[CustomRule] = Field(default_factory=list)
    field_policy: dict[str, FieldPolicy] = Field(default_factory=dict)
    mark_injection: bool = True


# --------------------------------------------------------------------------- #


class BudgetConfig(Base):
    max_queries: int = 12
    max_records: int = 5000
    max_rounds: int = 4
    max_tokens: int | None = 120_000
    max_cost_usd: float | None = 1.00

    def to_budget(self) -> Budget:
        return Budget(
            max_queries=self.max_queries,
            max_records=self.max_records,
            max_rounds=self.max_rounds,
            max_tokens=self.max_tokens,
            max_cost_usd=self.max_cost_usd,
        )


class AuditConfig(Base):
    run_root: Path = Path("./runs")
    retention_days: int = 30
    write_prompts: bool = True


class ReasonerConfig(Base):
    kind: Literal["rulebook", "openai_compat"] = "rulebook"
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    temperature: float = 0.0
    max_output_tokens: int = 2000
    price_per_1k_input_usd: float | None = None
    price_per_1k_output_usd: float | None = None

    @model_validator(mode="after")
    def _needs_endpoint(self) -> ReasonerConfig:
        if self.kind == "openai_compat" and not (self.base_url and self.model):
            raise ValueError("reasoner.kind=openai_compat requires base_url and model")
        return self


class PlannerConfig(Base):
    kind: Literal["rule_based", "llm"] = "rule_based"


class ProviderConfig(Base):
    backend: str
    kind: Literal["fixture", "loki", "prometheus"]
    fixture_path: Path | None = None
    endpoint: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> ProviderConfig:
        if self.kind == "fixture" and self.fixture_path is None:
            raise ValueError("fixture provider requires fixture_path")
        if self.kind != "fixture" and not self.endpoint:
            raise ValueError(f"{self.kind} provider requires an endpoint name")
        return self

    # A fixture provider may declare an endpoint even though it makes no request, so
    # that the demo still exercises PolicyGuard end to end.


# --------------------------------------------------------------------------- #


class Config(Base):
    version: int = 1
    default_window: str = "1h"
    scope: ScopeConfig
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    reasoner: ReasonerConfig = Field(default_factory=ReasonerConfig)
    planner: PlannerConfig = Field(default_factory=PlannerConfig)
    providers: list[ProviderConfig] = Field(default_factory=list)
    template_files: list[Path] = Field(default_factory=list)

    # Populated at load time; not part of the file.
    source_path: Path | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def _endpoints_resolve(self) -> Config:
        names = {e.name for e in self.policy.endpoints}
        for p in self.providers:
            if p.endpoint and p.endpoint not in names:
                raise ValueError(
                    f"provider {p.backend!r} references endpoint {p.endpoint!r} "
                    f"which is not declared in policy.endpoints"
                )
        return self

    def default_window_seconds(self) -> int:
        return parse_duration(self.default_window)

    def endpoint(self, name: str) -> EndpointPolicy:
        for e in self.policy.endpoints:
            if e.name == name:
                return e
        raise ConfigError(f"no endpoint named {name!r}", locator="policy.endpoints")

    def provider_for(self, backend: str) -> ProviderConfig:
        for p in self.providers:
            if p.backend == backend:
                return p
        raise ConfigError(f"no provider configured for backend {backend!r}", locator="providers")

    def config_hash(self) -> str:
        return stable_hash(self.model_dump(mode="json"))

    def scope_dict(self) -> dict[str, Any]:
        """Values that enum parameters may resolve against."""
        return {"scope": {"services": list(self.scope.services)}}


def _resolve(base: Path, value: Any) -> Any:
    p = Path(value)
    return p if p.is_absolute() else (base / p)


def load_config(path: str | Path) -> Config:
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"could not parse YAML: {exc}", locator=str(path)) from exc
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping", locator=str(path))

    base = path.parent
    # Paths in the file are relative to the file, not to the working directory.
    if "template_files" in raw:
        raw["template_files"] = [_resolve(base, v) for v in raw["template_files"]]
    for prov in raw.get("providers", []):
        if isinstance(prov, dict) and prov.get("fixture_path"):
            prov["fixture_path"] = _resolve(base, prov["fixture_path"])
    if isinstance(raw.get("audit"), dict) and raw["audit"].get("run_root"):
        raw["audit"]["run_root"] = _resolve(base, raw["audit"]["run_root"])

    try:
        cfg = Config.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError
        raise ConfigError(f"invalid configuration: {exc}", locator=str(path)) from exc
    cfg.source_path = path
    return cfg
