# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is [semantic](https://semver.org/); pre-1.0, minor versions may break.

## [Unreleased]

### Planned for v0.1.0

- Elastic connector
- Webhook and polling triggers
- Pluggable audit sinks (S3, SIEM, syslog)
- Fixture replay for regression testing

### Not planned, ever

- Remediation of any kind. Write capability would void the compliance argument the
  project exists to make.

## [0.1.0.dev0] — 2026-09-17

First working version. The architecture and the controls are in place; the connector
set is small.

### Added

**Read-only enforcement**
- `PolicyGuard`: default-deny egress mediation on host, exact path, method and backend.
- Parameterised query templates with typed parameters — `enum`, `timerange`, `int`,
  `bool`, `ref` — and deliberately no free-text type, so a planner selects and fills
  rather than writing a query.
- Statement verification by re-rendering: the guard independently renders from the
  template and parameters and requires a byte-for-byte match, making validation a
  positive check rather than a denylist.
- `ref` parameters accept only values observed in evidence already retrieved during the
  run, under a strict character class.
- Scope frozen at run start from configuration; alert payloads cannot widen it.
- A single constrained HTTP client that never follows redirects, with a CI test that
  fails the build if any other module imports a network primitive.

**Evidence**
- Loki and Prometheus connectors.
- Fixture provider, so the quickstart and the whole test suite need no backend.
- Multi-round gathering with query, record, round, token and monetary budgets.
- Evidence gaps as first-class output: a backend that fails becomes a recorded gap and
  a section in the report, not a crash and not a silent omission.

**Data handling**
- Deterministic pseudonymisation preserving correlation: the same value yields the same
  token throughout a run.
- Field-level allowlisting as the primary control, with pattern rules secondary.
- Twelve built-in rules plus custom regex rules; configurable salt scope.
- Injection marking on retrieved evidence.
- Redaction failure aborts the run rather than degrading.

**Planning and reasoning**
- Rule-based planner and rulebook reasoner, both deterministic and requiring no model —
  the quickstart needs no API key and no model download.
- LLM planner and OpenAI-compatible reasoner, covering hosted providers, vLLM and
  Ollama through one adapter.
- Every finding cites the evidence ids it rests on; uncited conclusions are labelled
  speculation. Citations to evidence ids that do not exist are dropped.

**Audit**
- Run directories written as the run proceeds, so an aborted run still leaves a record.
- Manifest recording configuration hash, policy, template-set fingerprint, model
  identity and budget consumption.
- Markdown report with evidence neutralised: control characters and ANSI sequences
  removed, fences defused, image syntax broken.
- Configurable retention and `auditglass purge`.
- A complete sample run directory committed at `examples/run-sample/`.

**Documentation**
- `docs/readonly-guarantee.md`, `docs/threat-model.md` (13 threats, 7 residual risks),
  `docs/quickstart.md`, `docs/writing-a-connector.md`, `docs/requirements.md`,
  `SECURITY.md`.

### Known limitations

Documented rather than hidden; see `docs/threat-model.md` § 8.

- No per-requester authorisation. Scope is per-deployment, not per-user.
- Audit records are neither signed nor append-only.
- Pattern-based redaction has recall below 100%, particularly on encoded, obfuscated
  and non-Latin content. Measured against `tests/corpus/pii_corpus.json`.
- Injected content can influence a report's narrative even though it cannot influence
  what is queried.
- Splunk is not supported. See `docs/writing-a-connector.md` for why, and for the
  specification.
