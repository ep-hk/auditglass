# Quickstart

## 0. See it work first

No backend, no credentials, no API key:

```bash
pip install auditglass
auditglass demo
```

This runs a synthetic incident end to end and writes a run directory. Open the
`report.md` it names.

Two variations worth a minute each:

```bash
auditglass demo --max-rounds 1      # one query: sees timeouts, cannot say why
auditglass demo --simulate-outage   # a backend is down: reports its evidence gaps
```

The first is the point of the tool in one command. The second is the behaviour that
matters most during a real incident, when the backends are often degraded because of
the incident.

---

## 1. Create read-only credentials

**Do this before anything else.** It is the only control in the stack that is a strong
guarantee — see [`readonly-guarantee.md`](readonly-guarantee.md). Everything the tool
does itself is defence in depth behind it.

The question to put to whoever owns your observability estate is blunt: *can the token
you are about to give me write to that system today?* The answer is often yes, because
many deployments issue one token for everything.

### Grafana Loki

Loki has no built-in user model; access is normally mediated by a gateway or by Grafana.
Whichever sits in front of it, the agent's credential must reach `query` and
`query_range` and must not reach `push`.

With `nginx` as the gateway:

```nginx
location ~ ^/loki/api/v1/(query|query_range)$ {
    proxy_pass http://loki-read:3100;
}
location / {
    return 403;   # /loki/api/v1/push included
}
```

With Grafana Enterprise Logs or a multi-tenant setup, issue a token scoped to
`logs:read` for the relevant tenant only.

### Prometheus

Prometheus has no authentication of its own. Put it behind a proxy that permits only
`/api/v1/query` and `/api/v1/query_range`, and denies `/api/v1/admin/*` — in particular
`/api/v1/admin/tsdb/delete_series` — and the remote-write receiver.

If you run Thanos or Mimir, use their query frontends with a read-only tenant token.

### Elasticsearch (connector not yet shipped)

Create a role with `read` and `view_index_metadata` on the specific indices, and no
cluster privileges:

```json
{
  "cluster": [],
  "indices": [
    { "names": ["logs-app-*"], "privileges": ["read", "view_index_metadata"] }
  ]
}
```

### Verify before you continue

Try to write with the credential you just made, and confirm it fails. A control you
have not tested is a belief.

```bash
# Should return 403 / 405, never 204.
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $AUDITGLASS_LOKI_TOKEN" \
  -X POST https://loki.observability.internal:3100/loki/api/v1/push -d '{}'
```

---

## 2. Write a configuration

Start from [`config/example.yaml`](../config/example.yaml), which is commented
throughout. The parts that need your attention:

```yaml
scope:
  services: [api-gateway, orders, payments, inventory-db]
  topology:
    orders: [payments, inventory-db]
```

`scope.services` is the complete set of service names any query may name — nothing
outside it is reachable, whatever an alert payload or a model asks for. `topology`
tells the planner where to look next when a service's problems appear to originate
downstream. Both are configuration on purpose: a service named in a log line never
becomes somewhere the agent goes.

```yaml
policy:
  endpoints:
    - name: loki
      backend: loki
      scheme: https
      host: loki.observability.internal
      port: 3100
      methods: [GET]
      paths:
        - /loki/api/v1/query_range
        - /loki/api/v1/query
```

Paths are exact; wildcards are rejected at load time. Note what is *not* listed —
`/loki/api/v1/push` — and that its absence is itself a control.

Check what you wrote:

```bash
auditglass policy    --config your-config.yaml   # the complete egress allowlist
auditglass templates --config your-config.yaml   # everything a planner could ask for
```

The second command prints the complete set of queries this deployment can make. If
something is in that list that should not be, remove the template.

---

## 3. Set the field policy

This is the part people skip and later regret.

```yaml
redaction:
  field_policy:
    logs:
      allow: [timestamp, service, level, host, client_ip, trace_id, message]
      free_text: [message]
      pseudonymise:
        client_ip: IP
```

`allow` is a positive control: a field not listed never reaches a planner or a
reasoner. This is stronger than pattern-scanning, because it does not depend on
recognising sensitive content.

`free_text` fields are pattern-scanned and checked for injected instructions.
`pseudonymise` fields have their whole value replaced by a stable token — preferred
wherever a field holds exactly one identifier.

Once you know your log schema, turn on:

```yaml
redaction:
  strict_fields: true
```

This aborts a run when a field appears that no policy covers, turning a silent drop
into a loud failure. Redaction never degrades to passing data through.

**Decide the salt scope deliberately.** `run` (default) gives a fresh salt per run:
tokens cannot be correlated between runs, which is better for privacy and rules out
cross-incident analysis. `deployment` reads a salt from `$AUDITGLASS_SALT` and enables
cross-run correlation — at the cost that if the salt leaks, low-entropy values like
IPv4 addresses become brute-forceable from their tokens.

---

## 4. Set retention

```yaml
audit:
  run_root: /var/lib/auditglass/runs
  retention_days: 30
```

Run directories accumulate production-derived data. On day one the directory is empty
and it is easy to forget it will not stay that way. Set this before the first
production run, and schedule the purge:

```bash
auditglass purge --config your-config.yaml --dry-run
auditglass purge --config your-config.yaml
```

---

## 5. Run it

Manually, first, for a window you already understand:

```bash
auditglass run --config your-config.yaml --service orders --since 45m
```

Or from an alert payload — a file, or stdin:

```bash
cat alert.json | auditglass run --config your-config.yaml --alert-payload -
```

A minimal payload:

```json
{
  "incident_id": "INC-4471",
  "service": "orders",
  "window": {"start": "2026-03-14T02:10:00Z", "end": "2026-03-14T02:30:00Z"}
}
```

There is deliberately no webhook server. Running one would mean authentication, TLS, a
deployment story and a new listening port for your security team to assess, in order to
do something your existing ingress can already do by writing a file or piping to stdin.

---

## 6. Add a model, if you want one

Everything above works with no model at all: the rule-based planner and the rulebook
reasoner are deterministic and need no network. That is the right place to start,
because it makes the audit trail trivially reviewable and the behaviour reproducible.

When you do add a model, the adapter speaks the OpenAI chat-completions shape, so a
hosted provider, vLLM and Ollama are all a `base_url`:

```yaml
policy:
  endpoints:
    - name: model
      backend: model
      scheme: http
      host: vllm.internal
      port: 8000
      methods: [POST]
      paths: [/v1/chat/completions]

reasoner:
  kind: openai_compat
  base_url: http://vllm.internal:8000/v1
  model: Qwen/Qwen2.5-14B-Instruct
  api_key_env: AUDITGLASS_MODEL_TOKEN
  temperature: 0.0
  price_per_1k_input_usd: 0.0
  price_per_1k_output_usd: 0.0
```

The model endpoint is allowlisted like any other destination.

**If your requirement is that production data must not leave the organisation, a local
endpoint plus a network policy that permits no external egress is the answer.**
Redaction is data minimisation; it is not a guarantee. Pair it with:

```yaml
budget:
  max_tokens: 120000
  max_cost_usd: 1.00
```

because token ceilings and money ceilings are not the same thing across models, and
finance approval usually wants the second number.

To let the model choose queries as well as explain them:

```yaml
planner:
  kind: llm
```

It still cannot write a query — it selects a template and fills typed parameters, and
everything after that is the same validation path the rule-based planner goes through.

---

## Troubleshooting

**`no query templates were loaded`** — `template_files` paths are resolved relative to
the configuration file, not the working directory.

**Every query becomes an evidence gap saying "rejected"** — the parameters are failing
template validation. The gap text names the reason. The common cause is a service not
in `scope.services`, or a window that does not intersect the incident.

**`denied by policy` in `denials.jsonl`** — read the `rule` field. `host-not-allowlisted`
and `path-not-allowlisted` mean a missing endpoint declaration; `statement-mismatch`
means something altered a query after rendering and should be investigated rather than
worked around.

**`redaction.salt_scope is 'deployment' but $AUDITGLASS_SALT is not set`** — set it, or
switch to `salt_scope: run`.

**The report is thin and there are gaps** — run with `--simulate-outage` off and check
the backends answered. A run that could not see something says so rather than
inventing a conclusion; that is the intended behaviour.
