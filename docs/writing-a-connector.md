# Writing a connector

A connector's job is small on purpose: turn a already-rendered query into one outbound
request, and normalise the response into flat records. It does **not** build query
strings — that has happened in the template engine — and it does not talk to the
network directly.

If you find yourself needing to do either, something has gone wrong; open an issue
rather than working around it, because both are load-bearing for the read-only property.

---

## The three pieces

### 1. A template file

This is the interesting part, and it is where most of the design work is. The template
file defines the complete set of queries your backend will ever be asked for. There is
no free-text parameter type, so if a query is not expressible as a template with typed
parameters, this tool cannot make it.

```yaml
backend: mybackend

templates:
  - id: logs.by_service_level
    kind: logs                    # logs | metrics  (traces and changes reserved)
    description: Log lines for one service at one severity.
    method: GET                   # GET or POST; nothing else exists
    path: /api/v1/search          # exact, and must be declared in policy.endpoints
    params:
      service:
        type: enum
        source: scope.services    # resolved from configuration at render time
      level:
        type: enum
        values: [error, warn, info]
      window:
        type: timerange
        max: 6h
        must_intersect: incident
      limit:
        type: int
        min: 1
        max: 5000
        default: 500
    statement: 'service:"{service}" AND level:"{level}"'
    query_params:
      q: '{statement}'
      from: '{window.start_iso}'
      to: '{window.end_iso}'
      size: '{limit}'
```

**Parameter types.** `enum`, `timerange`, `int`, `bool`, `ref`. That is the complete
list and it is deliberately short.

| Type | Accepts | Notes |
|---|---|---|
| `enum` | one of `values`, or of the list at `source` | `source: scope.services` draws from configuration |
| `timerange` | `{start, end}` | `max` caps the span; `must_intersect: incident` forbids leaving the incident window |
| `int` | an integer in `[min, max]` | |
| `bool` | true / false | |
| `ref` | a value observed in evidence already retrieved **this run** | `from:` names the field; a strict character class applies |

**Placeholders.** `{name}` for any parameter. Time ranges additionally expose
`{w.start_iso}`, `{w.end_iso}`, `{w.start_unix}`, `{w.end_unix}`, `{w.start_ns}`,
`{w.end_ns}` and `{w.duration_s}`. Inside `query_params`, `{statement}` is the rendered
statement. A placeholder that does not resolve fails at **load** time, not at incident
time.

**Escaping** is applied automatically per backend when a value is substituted into a
statement. Register yours in `ESCAPERS` in `policy/templates.py` if quoting differs
from the LogQL/PromQL convention of a double-quoted string with backslash escapes.

### 2. A provider class

```python
from auditglass.providers.base import HTTPBackedProvider


class MyBackendProvider(HTTPBackedProvider):
    backend = "mybackend"

    def parse(self, body):
        """Normalise the response into flat records.

        For kind: logs   -> timestamp, service, level, message, plus what you have
        For kind: metrics -> timestamp, service, metric, value

        Field names matter: they are what the field policy in a deployment's
        configuration names, and what the rulebook reasoner looks for.
        """
        return [
            {
                "timestamp": hit["@timestamp"],
                "service": hit["service"]["name"],
                "level": hit["log"]["level"],
                "message": hit["message"],
                "host": hit.get("host", {}).get("name"),
                "trace_id": hit.get("trace", {}).get("id"),
            }
            for hit in body.get("hits", {}).get("hits", [])
        ]
```

`HTTPBackedProvider.fetch` handles building the request, passing it through
`PolicyGuard` via the constrained client, and truncating to the record budget. You only
write `parse`.

### 3. Registration

Add it to the `cls` mapping in `build.py`, and to the `kind` literal in
`ProviderConfig` in `config.py`. Both are one line.

---

## Rules

**Never import an HTTP client.** `tests/ci/test_no_unmediated_http.py` walks the source
tree and fails the build if any module but `policy/http.py` imports `httpx`, `requests`,
`urllib.request`, `socket`, `subprocess` or similar. If that test fails on your
connector, the fix is to go through `ConstrainedHTTPClient`, not to add yourself to the
allowlist.

**Never construct a query string.** If your backend needs something the template engine
cannot express, the template engine is what should change.

**Never declare a write path.** Do not add `/push`, `_bulk`, or a remote-write endpoint
to your example configuration, even commented out. The absence of those paths from
`policy.endpoints` is one of the layers.

**Normalise field names to the common vocabulary** — `timestamp`, `service`, `level`,
`message`, `host`, `trace_id`, `metric`, `value` — so that a deployment's field policy
and the rulebook reasoner work without per-backend special cases.

**If you add a renderer or an output format**, re-read `audit/report.py`. Evidence is
attacker-influenced, and every new output path has to neutralise it again: control
characters and ANSI sequences removed, fences defused, image syntax broken. See threat
T8.

---

## Testing without a backend

Tests must run with no real system, which means an HTTP mock. Everything in
`tests/` does this already; follow the pattern.

```python
def test_parse_normalises_records():
    provider = MyBackendProvider(client=None, endpoint=None)
    records = provider.parse({"hits": {"hits": [ ... ]}})
    assert records[0]["service"] == "orders"
```

And add your backend to the adversarial suite if it has a write path worth asserting
against — a test that your write endpoint is refused is worth more than a test that
your read endpoint works.

---

## A connector we would particularly like: Splunk

Splunk is the backend most of the target audience actually runs, and it is **not**
shipped here for a reason worth stating plainly: the author does not have a Splunk
estate to develop against, and building a connector from knowledge of a specific
employer's deployment would be a confidentiality problem regardless of whether any
text was copied. A connector written by someone with a real Splunk estate and the right
to work on it will be better than one written without.

The specification, if you want to write it:

**Endpoints.** `POST /services/search/jobs` to create a job, `GET
/services/search/jobs/{sid}/results` to collect it. Both must be declared in
`policy.endpoints`; nothing else should be.

**The hard part is the template set.** SPL is a large language and most of it must not
be reachable. A conservative starting set:

```yaml
backend: splunk

templates:
  - id: logs.by_index_source_level
    kind: logs
    method: POST
    path: /services/search/jobs
    params:
      index:
        type: enum
        values: [app_logs, platform_logs]   # never source: anything user-controlled
      service:
        type: enum
        source: scope.services
      level:
        type: enum
        values: [ERROR, WARN, INFO]
      window:
        type: timerange
        max: 6h
        must_intersect: incident
      limit:
        type: int
        max: 5000
        default: 500
    statement: >-
      search index={index} sourcetype={service} log_level={level}
      | head {limit}
    query_params:
      search: '{statement}'
      earliest_time: '{window.start_iso}'
      latest_time: '{window.end_iso}'
      output_mode: json
      exec_mode: blocking
```

**Things to get right**, in rough order of how badly they go wrong:

1. `index` must be an `enum` with explicit values. Never `source:` anything a planner
   or an alert can influence. This is the single most important line in the file.
2. The statement must not be able to grow a pipeline segment. Because rendering happens
   in code from typed parameters and `PolicyGuard` re-renders and compares byte for
   byte, the danger is not runtime injection — it is a *template* that is itself too
   permissive. Keep them narrow and specific.
3. Job polling needs a bounded number of `GET` requests against the results endpoint,
   respecting the query budget. `exec_mode: blocking` avoids this at the cost of a long
   request; prefer it if your timeouts allow.
4. Splunk returns results in several shapes depending on `output_mode` and the search
   type. Normalise to the common field vocabulary above.
5. The read-only Splunk role you document in your example configuration should have
   `search` and nothing else — in particular not `edit_search_server`,
   `run_collect`, or `run_script`, which are what make `| collect` and `| script` work.

Open an issue before starting and we can agree on the template set first — that is the
part that needs review, and the Python around it is an afternoon.
