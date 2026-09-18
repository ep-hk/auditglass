# Auditglass

**Incident forensics for engineers who don't have production access.**

In organisations that enforce Segregation of Duties — banks, insurers, health systems,
government, listed companies — application engineers are not permitted to read
production. So an incident goes like this: the alert fires, the engineer is woken, the
engineer cannot see the logs, the engineer asks the ops team for them, the ops team
returns them, the engineer reads them and realises they need something else, and the
whole loop runs again. Every round trip happens while the incident is still going.

Gathering evidence is a read-only activity. `auditglass` performs the multi-round
version of it under a policy that can be reviewed, leaves an audit trail that can be
replayed, and **never changes anything** — it contains no write-path code, and never
will.

It is not an AIOps platform, not alert triage, and it does not remediate. See
[§ When not to use this](#when-not-to-use-this).

---

## What it produces

```
  6 supported finding(s) for orders from the evidence retrieved.

  · orders logged 27 error(s) during the incident window.  [E1]
  · orders's connection pool reached 100% of its configured maximum, so requests
    were waiting on a connection rather than on work.  [E2, E3]
  · payments p99 latency rose from 42ms to 1307ms within the window (31.2x).  [E6]
  · The most consistent reading of the evidence is that latency degradation in
    payments held orders's connections open long enough to exhaust its pool, which
    then surfaced upstream as timeouts. This is a correlation in time across the
    cited evidence, not a proven cause.  [E2, E3, E6]
  · payments logged 4 error(s) in the same window.  [E4]
  · One or more evidence blocks contain instruction-like content and are marked
    below. Treat their narrative content as untrusted.  [E1]

  terminated: evidence_sufficient after 3 round(s)
```

Every conclusion cites the evidence it rests on, so it can be checked rather than
believed. A conclusion with no citation is labelled speculation.

**[Read a complete run directory →](examples/run-sample/)** — committed to this repo, so
you can assess the audit trail without installing anything. That is the recommended
starting point for a security or compliance reviewer.

---

## Quickstart

No backend, no credentials, no API key, no model download:

```bash
pip install auditglass
auditglass demo
```

That runs a synthetic incident end to end and writes a run directory. The incident is
deliberately not solvable in one query — round one sees timeouts and cannot say why —
so the demo shows the thing the tool is actually for. Try `auditglass demo
--max-rounds 1` to watch it fail, and `--simulate-outage` to see how it reports what
it could not see.

**Before pointing it at anything real, read
[`docs/quickstart.md`](docs/quickstart.md) § 1 and create read-only service accounts.**
That is the first step for a reason; see below.

---

## How the read-only property works

The tool does **not** claim its own code is what keeps your systems safe. It claims
that write operations are independently blocked at several layers, and it states what
happens when each one fails.

| Layer | Control | Owner | If this layer fails |
|---|---|---|---|
| **L1** | Read-only service account, enforced by your backend's RBAC | **You** | Nothing. This is the only strong guarantee |
| **L2** | Egress mediation: host/path/method allowlist plus templated query construction | auditglass | Falls back to L1 |
| **L3** | No write-path code exists; all backend access goes through one constrained client, asserted in CI | auditglass | Falls back to L1 and L2 |
| **L4** | Process-level network egress allowlist | **You** | Optional hardening |

If you give this tool a credential that can write, you have moved the entire property
onto application code written by a stranger. Don't.

Full detail, including what each layer does *not* promise:
**[`docs/readonly-guarantee.md`](docs/readonly-guarantee.md)**.

### Why a method allowlist is not enough

Reads on real observability backends routinely use POST and share endpoints with
writes. Splunk's search endpoint is POST, and an SPL pipeline can carry
side-effecting commands — `collect`, `outputlookup`, `sendalert` — inside the request
body. Elasticsearch `_search` is POST, and so are `_bulk` and `_delete_by_query`. A
verb allowlist sees none of this.

### Why there is no keyword denylist either

Query languages are large, extensible, and support macros and string construction. A
denylist of dangerous keywords loses to the first person who finds a synonym.

So instead: **a planner never writes a query.** It selects a template and fills typed
parameters, and the rendering happens in code.

```yaml
- id: logs.by_service_level
  params:
    service: { type: enum, source: scope.services }   # not free text
    level:   { type: enum, values: [error, warn, info] }
    window:  { type: timerange, max: 6h, must_intersect: incident }
    limit:   { type: int, max: 5000 }
  statement: '{app="{service}"} | json | level="{level}"'
```

There is no parameter type that accepts free text. PolicyGuard then re-renders the
statement from the same template and parameters and requires a byte-for-byte match, so
validation is a positive check rather than a search for bad substrings.

`auditglass templates --config your.yaml` prints the complete set of things a
deployment can ask a backend.

---

## Prompt injection

The agent reads production logs. Production logs contain attacker-controlled strings —
form fields, headers, usernames, upstream payloads. If the agent's next query were
derived from that content, one HTTP request would buy an attacker a cross-privilege
data extraction, performed by a tool the organisation itself approved.

Wrapping retrieved data in "untrusted" delimiters does not prevent this and is not
relied upon here. The defence is structural: injected text can at most cause a
*different legitimate template with different in-range parameters* to run — visible in
the audit trail, and not a boundary crossing.

The demo fixture contains a real injection payload so you can watch this work. See
[`docs/threat-model.md`](docs/threat-model.md) T2, and
`tests/adversarial/test_injection.py`.

---

## What happens to sensitive data

Masking would destroy the tool's value: replace every address with `***` and "three
hundred errors, all from one host" — often the only useful conclusion available — stops
being visible. So values are pseudonymised instead, with stable tokens:

```
203.0.113.47   ->  IP_a37f2b1c
acct-88413920  ->  ACCT_5d9e0417
```

The same input yields the same token throughout a run, so correlation survives while
the original stays inside your network. Structured records additionally go through a
field allowlist — fields you have not listed never reach a model at all.

**This is data minimisation, not a guarantee.** Pattern rules have recall below 100%,
especially in free text, stack traces, encoded payloads and non-Latin scripts. Measured
recall against the corpus in `tests/corpus/` is **100% on easy and medium cases and 0%
on the cases labelled hard** — the hard cases are in the corpus precisely so this number
stays honest. If your requirement is that production data must not leave, the answer is
a local model endpoint, which is a `base_url` change:

```yaml
reasoner:
  kind: openai_compat
  base_url: http://vllm.internal:8000/v1   # or Ollama
```

CI runs the full pipeline in a container with no outbound network to keep that claim true.

---

## When not to use this

| Situation | Do this instead |
|---|---|
| Your engineers could just be given production read access | Give them read access. It is simpler and faster |
| Your backends have no read-only API | This tool cannot work |
| You cannot accept an LLM in incident handling at all | The rule-based planner and reasoner need no model, but if you want no automation here, this is not for you |
| You want automatic remediation | Never, by design. Write capability would void the entire compliance argument |
| You need alert aggregation or noise reduction | Use a mature product; that is not this |

---

## Status

**v0.1.0.dev0 — early.** The architecture and the controls are in place and tested;
the connector set is small. Working today: CLI and alert-payload triggers, PolicyGuard,
the template layer, Loki and Prometheus connectors, pseudonymising redaction,
rule-based and LLM planners, rulebook and OpenAI-compatible reasoners, the full audit
trail and report.

Not yet: webhook and polling triggers, Elastic and Splunk connectors, pluggable audit
sinks, fixture replay, per-requester authorisation. See
[`docs/requirements.md`](docs/requirements.md) for the full scope and
[`CHANGELOG.md`](CHANGELOG.md).

A Splunk connector specification is written up in
[`docs/writing-a-connector.md`](docs/writing-a-connector.md) and community
implementations are very welcome — a connector written by someone with a real Splunk
estate will be better than one written without.

---

## Verifying the claims

Nothing above should be taken on trust. All of this runs without a production system:

```bash
git clone https://github.com/ep-hk/auditglass && cd auditglass
pip install -e ".[dev]"
pytest tests/adversarial -v     # write attempts, injection, scope escape
pytest tests/ci -v              # no module but one may speak HTTP
pytest -v                       # everything
```

`docs/threat-model.md` § 10 maps each claim to the test that checks it.

---

## Documentation

| | |
|---|---|
| [`docs/quickstart.md`](docs/quickstart.md) | Getting to a first real run, starting with read-only credentials |
| [`docs/readonly-guarantee.md`](docs/readonly-guarantee.md) | The layered model in detail, and its limits |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, boundaries, thirteen threats, residual risk |
| [`docs/writing-a-connector.md`](docs/writing-a-connector.md) | Adding a backend |
| [`docs/requirements.md`](docs/requirements.md) | Full requirements specification |
| [`SECURITY.md`](SECURITY.md) | Reporting a vulnerability |

---

## Licence and provenance

Apache 2.0 — the patent grant tends to matter for enterprise legal review. See
[`LICENSE`](LICENSE).

All examples, fixtures and test corpora in this repository are synthetic and were
written for this project. They describe no real system and contain no real person's
data. Addresses use RFC 5737 documentation ranges and domains use RFC 2606 reserved
names.

Contributions are welcome under the DCO — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
