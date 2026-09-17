# The read-only guarantee

This document exists to be read by someone whose job is to say no.

The short version: **auditglass does not claim that its own code is what keeps your
production systems safe.** It claims that write operations are independently blocked at
several layers, that it can show you each one, and that it will tell you what happens
when any of them fails. A tool that asked you to trust a single application-level guard
written by a stranger would not deserve deployment, and this one does not ask that.

---

## The layers

| Layer | Control | Owner | If this layer fails |
|---|---|---|---|
| **L1** | Read-only service account, enforced by the backend's own RBAC | **Deploying organisation** | Nothing — this is the only strong guarantee. Its failure means L2 and L3 are all that remain |
| **L2** | Egress mediation: host / path / method allowlist, plus templated query construction | auditglass | Falls back to L1 |
| **L3** | Structural: no write-path code exists; all backend access goes through one constrained client, asserted in CI | auditglass | Falls back to L1 and L2 |
| **L4** | Process-level network egress allowlist — the container can reach only declared endpoints | **Deploying organisation** | Optional hardening |

Two of the four are yours. That is not an evasion; it is where the strong guarantee
actually lives. An application cannot make a credential less powerful than it is.

---

## L1 — the credential

**This is the control that matters.** Issue the agent a service account that has no
write permission in the backend, and every other layer becomes defence in depth. Skip
it, and the read-only property of your production estate rests entirely on this
project's bug count.

Configuration examples for each supported backend are in
[`quickstart.md`](quickstart.md) § 1, and that section is first in the document for
the same reason it is first here.

A question worth asking your backend team, because the answer is often "no": *can this
token, today, write to that system?* Many observability deployments hand out a single
token that reads and writes, and nobody notices until someone asks.

---

## L2 — egress mediation

Every outbound request passes through `PolicyGuard` before it is dispatched, and the
default is deny. The checks run in this order, and the ordering is deliberate: the
destination is settled before anything about the query is considered, so an unknown
host is refused without the query being examined at all.

1. Is the method one this tool emits at all? (`GET`, `POST` — nothing else exists.)
2. Is `scheme://host:port` a declared endpoint?
3. Is the exact path declared on that endpoint? (No wildcards. A path is exact or it is
   not allowed.)
4. Is the method permitted *on that endpoint*?
5. Does the backend match the endpoint's declared backend?
6. **Does the statement match what its template renders for these parameters?**
7. A denylist scan for obviously dangerous constructs — defence in depth only.

Every denial is written to `denials.jsonl` in the run directory with its cause.

### Why a method allowlist is not enough

The intuition that "reads are GET" is wrong on real observability backends:

- Splunk's `search/jobs` is POST. An SPL pipeline can carry `| collect`,
  `| outputlookup`, `| sendalert`, `| script` or `| rest` — all side-effecting, all
  inside the request **body**, where a verb allowlist cannot see them.
- Elasticsearch `_search` is POST. So are `_bulk`, `_delete_by_query` and
  `_update_by_query`.
- Prometheus remote-write and Loki's `/push` are POST to paths that live on the same
  host as the read API.

Step 3 handles the last of those — the write path is simply never declared. Steps 6
handles the first two.

### Why there is no keyword denylist

Rejecting statements that contain dangerous keywords is the obvious design and it does
not work. Query languages are large and extensible; SPL alone has hundreds of commands
and gains more each release. Macros, `eval` string construction, case variation, URL
encoding and comment insertion all defeat substring matching. Every bypass found is a
security incident, and the list is never finished.

A denylist is present in the configuration (`policy.forbidden_substrings`) and it is
explicitly **not** what makes the guard sound. It exists to catch a badly authored
template early and loudly.

### What actually makes it sound: the model never writes a query

A planner emits `{template_id, params}`. Rendering happens in code, from a template set
loaded at startup.

```yaml
- id: logs.by_service_level
  params:
    service: { type: enum, source: scope.services }
    level:   { type: enum, values: [error, warn, info] }
    window:  { type: timerange, max: 6h, must_intersect: incident }
    limit:   { type: int, max: 5000 }
  statement: '{app="{service}"} | json | level="{level}"'
```

The parameter types are `enum`, `timerange`, `int`, `bool` and `ref`. **There is no
free-text type.** That absence is the security property, and there is a test that fails
if one is ever added.

- `enum` values come from the template or from `scope.services` in configuration.
  "Query the payroll index" is not a sentence this system can express.
- `timerange` has a maximum span and must intersect the incident window. A run can
  narrow its view; it cannot wander to another day.
- `ref` accepts only a value already observed in evidence retrieved during this run,
  under a strict character class — so a planner can follow a trace id it genuinely saw,
  but cannot invent one, and cannot smuggle a quote or a pipe through it.

Because statements are generated from a fixed template set, step 6 can be a **positive
check**: the guard re-renders from the template and the validated parameters and
requires an exact match. A statement altered anywhere between rendering and dispatch
fails, regardless of what it was altered to.

### Scope is frozen

The set of reachable services is fixed before the first query and cannot be widened. It
comes from `scope.services`, intersected with the trigger. An alert payload naming a
service the deployment does not cover is rejected outright, not quietly honoured. The
downstream services a planner may follow come from `scope.topology` — configuration —
never from something read in a log line.

---

## L3 — no write path exists

`src/auditglass/policy/http.py` is the only module in the package permitted to import
an HTTP client, a socket, or a subprocess primitive.
`tests/ci/test_no_unmediated_http.py` walks the source tree with the AST and fails the
build if anything else does.

This is a structural test rather than a behavioural one, and the difference matters.
Behavioural tests show that the paths you thought of are guarded. This shows there are
no other paths.

Two further controls live in that module:

- **Redirects are never followed.** A 302 from an allowlisted host to somewhere else
  would otherwise carry credentials past a guard that had already said yes.
- **Credentials are attached there and nowhere else**, read from the environment at
  call time, so they cannot reach a log line, an audit record or a report by riding
  inside a request object.

---

## L4 — network policy

Optional, and worth doing. The agent needs to reach exactly the endpoints in
`policy.endpoints` and nothing else. Expressing that as a container network policy or
egress firewall rule gives you a control that holds even if this entire package is
compromised.

With a local model endpoint and an egress policy that permits no external destinations,
no evidence can leave the organisation regardless of configuration error. That
combination is the only configuration that *guarantees* it; redaction is data
minimisation, not a guarantee.

---

## What this does not cover

Stated plainly, because a document like this is worth nothing if it only lists
strengths.

- **A write-capable credential.** If you supply one, L1 is gone and the property rests
  on this project's code. The tool cannot detect or prevent that choice.
- **Misuse by an authorised user.** v0.1 has no per-requester authorisation: scope is
  per-deployment, not per-user. An engineer permitted to trigger the agent can trigger
  it for any service in the deployment's scope. Mitigate by running one instance per
  ownership boundary with a matching scope, and restricting run-directory access. See
  threat T5.
- **Host-level compromise.** An adversary who can read the agent's memory or filesystem
  has the credential, whatever it can do.
- **A compromised backend.** The tool assumes backends return data faithfully.
- **Audit tampering.** Run directories are ordinary files in v0.1: not signed, not
  append-only. Where that matters, write to a SIEM or WORM store.

---

## Checking all of this yourself

```bash
pip install -e ".[dev]"
pytest tests/adversarial -v    # write attempts, injection, scope escape
pytest tests/ci -v             # the structural check
```

`tests/adversarial/test_write_attempts.py` is written to be readable by someone who has
never seen the codebase. It includes a test asserting that a *legitimate* query is
allowed, because a suite that denied everything would pass while proving nothing.

[`docs/threat-model.md`](threat-model.md) § 10 maps every claim in this document to the
test that checks it.
