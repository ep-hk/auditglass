# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, using GitHub's
[private vulnerability reporting](https://github.com/ep-hk/auditglass/security/advisories/new)
on this repository. **Do not open a public issue for a suspected vulnerability.**

Expect an acknowledgement within 5 working days and an assessment within 15. This is
currently a small project maintained outside working hours; if you have not heard back
in 10 days, please chase, because it means a message went astray rather than that the
report was dismissed.

If a fix is warranted, the intention is to release it within 30 days of confirmation
and to credit you in the advisory unless you prefer otherwise.

## Scope

This project holds credentials to production observability infrastructure and moves a
processed subset of production data across a boundary that exists deliberately. The
following are in scope and especially welcome:

- **Any path by which a state-changing request could reach a backend.** This is the
  most serious class of finding in this project.
- **Any way injected content in retrieved evidence can cause a query outside the
  declared scope** — a service not in `scope.services`, a window outside the incident,
  a dataset not named in the template set.
- **Any evidence content that survives report rendering in a form that acts on the
  reader's client** — an image that fetches, a link that misleads, an escape sequence
  that rewrites a terminal.
- **Any systematic redaction bypass.** A single missed pattern is a bug report, not a
  vulnerability; a class of values that never matches is a vulnerability.
- Credential leakage into logs, audit records, reports or error messages.
- Any way to make the tool exceed its configured budgets or scope.

## Out of scope

- **A deployment that supplies a write-capable credential.** The tool cannot detect or
  prevent that choice; see [`docs/readonly-guarantee.md`](docs/readonly-guarantee.md).
- The security of the observability backends themselves.
- Host-level compromise of the machine running the agent.
- Denial of service against a backend achieved by configuring budgets and rate limits
  higher than that backend can take.
- Recall gaps in pattern-based redaction, which are a known and documented limitation.
  The cases in `tests/corpus/pii_corpus.json` labelled `hard` are expected to fail.

## Known limitations

These are documented rather than fixed, and are stated here so a report does not have
to be filed to discover them. Full detail in
[`docs/threat-model.md`](docs/threat-model.md) § 8.

- **No per-requester authorisation** in v0.1. Scope is per-deployment, not per-user.
  Run one instance per ownership boundary.
- **Audit records are not signed or append-only** in v0.1. Where that matters, write to
  a SIEM or WORM store.
- **Injected content can still influence a report's narrative**, even though it cannot
  influence what is queried. Evidence citations and injection markers help; they do not
  eliminate it.
- **Pseudonymisation is data minimisation, not a guarantee.** The configuration that
  guarantees data does not leave is a local model endpoint plus a network policy.

## Supported versions

Pre-1.0: only the latest release receives fixes.

## Disclosure

Coordinated disclosure, please. If a finding affects a downstream connector or a
backend vendor, we will work with you on timing.
