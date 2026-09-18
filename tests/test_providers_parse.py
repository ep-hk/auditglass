"""Response parsing, against the wire formats the real backends actually return.

These payloads are transcribed from the documented response shapes of Loki's
``query_range`` and Prometheus's ``query`` / ``query_range`` endpoints, including the
awkward parts: nanosecond string timestamps, values as strings, ``NaN`` and ``+Inf``,
metric names absent after a function like ``rate()``, and error envelopes returned
with a 200.

This file exists because the connectors were originally written from knowledge of the
API shape and shipped with no test touching them at all. That was a real defect: the
README claimed they worked. Parsing is the half of a connector that can be tested
without a server, so it is tested exhaustively here, and `tests/integration/` covers
the half that cannot.
"""

from __future__ import annotations

import contextlib
import math

import pytest

from auditglass.errors import ProviderError
from auditglass.providers.loki import LokiProvider
from auditglass.providers.prometheus import PrometheusProvider


@pytest.fixture
def loki() -> LokiProvider:
    return LokiProvider.__new__(LokiProvider)  # parse() needs no client


@pytest.fixture
def prom() -> PrometheusProvider:
    return PrometheusProvider.__new__(PrometheusProvider)


# --------------------------------------------------------------------------- #
# Loki
# --------------------------------------------------------------------------- #


LOKI_STREAMS = {
    "status": "success",
    "data": {
        "resultType": "streams",
        "result": [
            {
                "stream": {"app": "orders", "level": "error", "pod": "orders-7d9f4b-2xk"},
                "values": [
                    ["1773453000000000000", "timed out acquiring connection from pool"],
                    [
                        "1773453001500000000",
                        '{"message":"pool exhausted","trace_id":"tr-0051a01",'
                        '"client_ip":"203.0.113.47","host":"orders-7d9f4b-9wq"}',
                    ],
                ],
            },
            {
                "stream": {"app": "payments", "level": "warn"},
                "values": [["1773453002000000000", "settlement retry 3"]],
            },
        ],
        "stats": {"summary": {"totalLinesProcessed": 3}},
    },
}


def test_loki_parses_streams(loki):
    records = loki.parse(LOKI_STREAMS)
    assert len(records) == 3
    assert {r["service"] for r in records} == {"orders", "payments"}
    assert {r["level"] for r in records} == {"error", "warn"}


def test_loki_converts_nanosecond_timestamps(loki):
    records = loki.parse(LOKI_STREAMS)
    assert records[0]["timestamp"].startswith("2026-03-14T")
    assert records[0]["timestamp"].endswith("+00:00")


def test_loki_lifts_fields_out_of_json_lines(loki):
    """Loki lines are frequently JSON; the field policy acts on fields, not on a blob."""
    records = loki.parse(LOKI_STREAMS)
    lifted = next(r for r in records if r.get("trace_id"))
    assert lifted["trace_id"] == "tr-0051a01"
    assert lifted["client_ip"] == "203.0.113.47"
    assert lifted["message"] == "pool exhausted"
    # A field inside the line must not silently overwrite the stream label.
    assert lifted["service"] == "orders"


def test_loki_keeps_plain_lines_intact(loki):
    records = loki.parse(LOKI_STREAMS)
    plain = records[0]
    assert plain["message"] == "timed out acquiring connection from pool"


def test_loki_carries_stream_labels_through(loki):
    records = loki.parse(LOKI_STREAMS)
    assert records[0]["pod"] == "orders-7d9f4b-2xk"


def test_loki_accepts_severity_and_service_label_variants(loki):
    body = {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"service": "billing", "severity": "error"},
                    "values": [["1773453000000000000", "x"]],
                }
            ],
        },
    }
    record = loki.parse(body)[0]
    assert record["service"] == "billing"
    assert record["level"] == "error"


def test_loki_empty_result_is_not_an_error(loki):
    """No matching logs is a legitimate answer, not a failure."""
    assert loki.parse({"status": "success", "data": {"resultType": "streams", "result": []}}) == []


def test_loki_error_envelope_raises(loki):
    """Loki can answer 200 with an error body; returning [] would look like 'no logs'."""
    with pytest.raises(ProviderError, match="parse error"):
        loki.parse({"status": "error", "errorType": "bad_data", "error": "parse error at line 1"})


def test_loki_tolerates_malformed_entries(loki):
    body = {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {"app": "orders"},
                    "values": [["1773453000000000000"], [], ["1773453001000000000", "ok"]],
                }
            ],
        },
    }
    records = loki.parse(body)
    assert [r["message"] for r in records] == ["ok"]


def test_loki_non_dict_json_line_stays_a_message(loki):
    body = {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {"stream": {"app": "orders"}, "values": [["1773453000000000000", "[1,2,3]"]]}
            ],
        },
    }
    assert loki.parse(body)[0]["message"] == "[1,2,3]"


def test_loki_output_is_time_ordered(loki):
    records = loki.parse(LOKI_STREAMS)
    assert [r["timestamp"] for r in records] == sorted(r["timestamp"] for r in records)


# --------------------------------------------------------------------------- #
# Prometheus
# --------------------------------------------------------------------------- #


PROM_MATRIX = {
    "status": "success",
    "data": {
        "resultType": "matrix",
        "result": [
            {
                "metric": {
                    "__name__": "connection_pool_active",
                    "service": "orders",
                    "instance": "10.0.0.4:9090",
                },
                "values": [[1773453000, "42"], [1773453060, "50"]],
            },
            {
                "metric": {"__name__": "connection_pool_active", "service": "payments"},
                "values": [[1773453000, "3"]],
            },
        ],
    },
}

PROM_VECTOR = {
    "status": "success",
    "data": {
        "resultType": "vector",
        "result": [
            {
                "metric": {"__name__": "error_rate", "job": "orders"},
                "value": [1773453060, "0.37"],
            }
        ],
    },
}


def test_prometheus_parses_matrix(prom):
    records = prom.parse(PROM_MATRIX)
    assert len(records) == 3
    assert all(r["metric"] == "connection_pool_active" for r in records)
    assert {r["service"] for r in records} == {"orders", "payments"}


def test_prometheus_values_become_floats(prom):
    records = prom.parse(PROM_MATRIX)
    assert records[0]["value"] == 42.0
    assert isinstance(records[0]["value"], float)


def test_prometheus_converts_unix_timestamps(prom):
    records = prom.parse(PROM_MATRIX)
    assert records[0]["timestamp"].startswith("2026-03-14T")


def test_prometheus_parses_vector(prom):
    records = prom.parse(PROM_VECTOR)
    assert len(records) == 1
    assert records[0]["metric"] == "error_rate"
    assert records[0]["service"] == "orders"  # falls back to the job label
    assert records[0]["value"] == 0.37


def test_prometheus_keeps_extra_labels(prom):
    records = prom.parse(PROM_MATRIX)
    with_instance = next(r for r in records if "instance" in r)
    assert with_instance["instance"] == "10.0.0.4:9090"


def test_prometheus_handles_nan_and_inf(prom):
    """Prometheus serialises these as strings; they must not crash or become 0."""
    body = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"__name__": "ratio", "service": "orders"},
                    "values": [[1773453000, "NaN"], [1773453060, "+Inf"], [1773453120, "-Inf"]],
                }
            ],
        },
    }
    values = [r["value"] for r in prom.parse(body)]
    assert math.isnan(values[0])
    assert values[1] == math.inf
    assert values[2] == -math.inf


def test_prometheus_metric_without_a_name(prom):
    """A function such as rate() returns series with no __name__."""
    body = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {"metric": {"service": "orders"}, "values": [[1773453000, "1"]]}
            ],
        },
    }
    record = prom.parse(body)[0]
    assert record["service"] == "orders"
    assert record["metric"] == ""


def test_prometheus_empty_result_is_not_an_error(prom):
    assert prom.parse({"status": "success", "data": {"resultType": "matrix", "result": []}}) == []


def test_prometheus_error_envelope_raises(prom):
    with pytest.raises(ProviderError, match="invalid parameter"):
        prom.parse(
            {
                "status": "error",
                "errorType": "bad_data",
                "error": 'invalid parameter "query": unknown function',
            }
        )


def test_prometheus_unsupported_result_type_raises(prom):
    """Returning [] for a shape we cannot read would masquerade as 'no data'."""
    with pytest.raises(ProviderError, match="scalar"):
        prom.parse(
            {"status": "success", "data": {"resultType": "scalar", "result": [1773453000, "1"]}}
        )


def test_prometheus_tolerates_malformed_points(prom):
    body = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {
                    "metric": {"__name__": "m", "service": "orders"},
                    "values": [[1773453000], [], [1773453060, "2"]],
                }
            ],
        },
    }
    assert [r["value"] for r in prom.parse(body)] == [2.0]


def test_prometheus_unparseable_value_raises(prom):
    """A value that is not a number means the response is not what we think it is."""
    body = {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {"metric": {"__name__": "m"}, "values": [[1773453000, "not-a-number"]]}
            ],
        },
    }
    with pytest.raises(ProviderError, match="not-a-number"):
        prom.parse(body)


# --------------------------------------------------------------------------- #
# Shapes neither backend should produce, but a proxy might
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("body", [None, {}, {"data": None}, {"data": {}}, "not json at all"])
def test_providers_survive_junk_bodies(loki, prom, body):
    """Either parse it as empty or refuse it explicitly. Never raise something else."""
    for provider in (loki, prom):
        with contextlib.suppress(ProviderError):
            assert provider.parse(body) == []
