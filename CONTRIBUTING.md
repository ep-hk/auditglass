# Contributing

Contributions are welcome. The most useful ones are connectors for backends the author
cannot test against, and adversarial tests that break a control this project claims to
have.

## Getting set up

```bash
git clone https://github.com/ep-hk/auditglass && cd auditglass
pip install -e ".[dev]"
pytest              # 180+ tests, no backend required
ruff check .
mypy src/auditglass
```

Every test runs against synthetic fixtures. **You never need access to a real
production system to work on this project, and you should not use one.**

## Sign your commits (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
rather than a CLA. Add a sign-off line to each commit:

```bash
git commit -s -m "Add Elastic connector"
```

which appends `Signed-off-by: Your Name <your@email>`. That is the whole process — no
paperwork, no assignment of copyright.

## Things that will get a change sent back

These are not style preferences; each one is load-bearing for a claim the project
makes.

**Importing an HTTP client outside `policy/http.py`.** There is a CI test for this. If
it fails on your change, the fix is to go through `ConstrainedHTTPClient` so that
`PolicyGuard` sees the request — not to add your module to the allowlist.

**Adding a free-text query parameter type.** The absence of one is the security
property that makes injection defence structural rather than aspirational. There is a
test asserting it stays absent.

**Constructing a query string outside the template engine.** If your backend needs
something templates cannot express, the template engine is what should change.

**Adding anything that writes.** This project will never remediate, restart, scale,
roll back or change configuration. A pull request adding write capability will be
declined regardless of how it is guarded, because the entire compliance argument rests
on the capability not existing.

**A new output format that does not neutralise evidence.** Evidence is
attacker-influenced. Every renderer has to remove control characters, defuse fences and
break image syntax. See `audit/report.py` and threat T8.

**Real data of any kind.** Fixtures must be synthetic. Use RFC 5737 addresses
(`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`) and RFC 2606 domains
(`example.com`, `.invalid`, `.test`).

## Adding a connector

See [`docs/writing-a-connector.md`](docs/writing-a-connector.md). Open an issue first
so the template set can be agreed — that is the part that needs review; the Python
around it is small.

## Adding a redaction rule

Add it to `BUILTIN` in `redact/rules.py`, put it in the right position in `ORDER`, and
add cases to `tests/corpus/pii_corpus.json` with a `difficulty` label. If your rule
cannot catch a case, add it as `hard` rather than leaving it out — the published recall
figure is only worth something if the corpus includes what we miss.

Watch for over-matching. A rule that eats epoch-millis timestamps or request ids makes
reports useless; `test_non_luhn_digit_runs_are_not_treated_as_cards` exists because of
exactly that failure mode.

## Tests

New behaviour needs a test. Security-relevant behaviour needs an adversarial one — a
test that asserts the control holds when something actively tries to break it, marked
`@pytest.mark.adversarial`.

A note on writing those: `tests/adversarial/test_write_attempts.py` includes a test
asserting that a *legitimate* query is allowed. A suite that denied everything would
pass while proving nothing. Please keep that kind of control in your own additions.

## Documentation

If your change moves a trust boundary, adds a backend, or adds an output format, say so
in the pull request and update `docs/threat-model.md`. It has a review-history table at
the bottom.

If you change what a control actually does, check that the prose still matches. The
docs in this repository make specific claims, and a claim that has drifted from the
code is worse than no claim.

## Commit messages

Explain why, not what — the diff already says what. If a change exists because of a
specific failure mode, name it.

## Code of conduct

Be straightforward and courteous. Disagreement about technical substance is welcome and
is most of the value; contempt is not.
