# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning is [semantic](https://semver.org/); pre-1.0, minor versions may break.

## [Unreleased]

### Fixed

Four defects, all found by writing the connector tests that should have existed from
the start. The Loki and Prometheus connectors had shipped with **no test touching
them at all**, while the README described them as working.

- **A backend error response read as "nothing matched".** Both Loki and Prometheus can
  answer HTTP 200 with `{"status": "error", ...}`; `parse()` returned an empty record
  list for that, so a failed query became "no errors found" in the report. For a tool
  whose value rests on being honest about what it could not see, this was the worst
  available failure mode. Error envelopes now raise and become recorded evidence gaps.
- **Two backends could not share a host and port.** PolicyGuard matched the first
  endpoint at a destination and then rejected the path against it, so an observability
  gateway fronting Loki at `/loki/*` and Prometheus at `/api/v1/*` on one host — a
  normal deployment — permanently denied the second backend, blaming the wrong
  endpoint in the message. Endpoints are now selected by destination *and* path.
- **An unreadable Prometheus response was silent.** A `scalar` result type, or a sample
  value that would not parse, produced empty or `None` rather than an error.
- **The audit hook could crash its caller.** A PolicyGuard denial outside an open run
  raised `AssertionError` from the sink. Denials are now buffered and flushed when the
  run opens.

CI had failed on every run since the first push, and that went unnoticed. The
consequences were worse than a red badge:

- **The test suite never ran in CI.** The type-check step failed under mypy 2 — a
  lambda default for a `list[Literal[...]]` field, and a dead URL helper — and every
  step after it was skipped. The typing is fixed and the dead helper removed.
- **`pip install git+https://...` — the README's install command — did not work.** The
  wheel config listed the bundled demo directory twice, which hatchling refuses to
  build. An editable install never builds a wheel, so nothing local showed it. The
  duplicate is gone and the `build` job installs the built wheel and runs the demo.
- **The no-egress job could not start.** GitHub's Ubuntu 24.04 runners forbid
  unprivileged user namespaces, so `unshare -rn` failed before the pipeline ran. It now
  uses `sudo unshare -n`, and still proves the namespace has no route out first.
- **The live-backend tests ran before the incident and asserted over empty lists.**
  They waited for any data, ran during the seeder's healthy period, and several
  passed while checking nothing. They now wait until the incident has developed,
  every check first asserts it has something to check, and the causal assertion
  names each finding it expects. Run against real Loki 3.3.2 and Prometheus 3.1.0,
  that stricter version then found one more thing: with only a minute of history, a
  60-second query step leaves one sample per series, so the run could not see latency
  rise. The loose assertion had passed anyway. The seeder now stays healthy for longer
  than one step, and the test fails with an explanation if that ever stops holding.

### Added

- `tests/test_providers_parse.py` — response handling against the real wire formats,
  including nanosecond string timestamps, `NaN`/`+Inf`, metrics with no `__name__`
  after a function, error envelopes and malformed points.
- `tests/test_providers_http.py` — the connectors over real HTTP against a stub that
  speaks the real formats, asserting what actually goes out on the wire.
- `demo/docker-compose.yml` and `demo/seed/` — real Loki and real Prometheus with a
  seeder playing the incident into them live.
- `tests/integration/` and `config/demo-live.yaml` — the check that only real servers
  can answer, run in CI by the `live-backends` job.

### Changed

- README now separates what has been exercised from what has merely been written, and
  points at git install rather than PyPI until the package is published. The Loki and
  Prometheus connectors move from "not yet run against a live server" to "exercised
  against small synthetic ones", with the limits of that stated.

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
