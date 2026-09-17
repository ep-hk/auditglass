"""Redaction: correlation must survive, originals must not, and the published recall
figure must be measured rather than asserted."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditglass.config import FieldPolicy, RedactionConfig
from auditglass.errors import RedactionFailure
from auditglass.redact.redactor import DeterministicRedactor, Pseudonymiser

CORPUS = Path(__file__).parent / "corpus" / "pii_corpus.json"

#: The floor the README figure must not silently drop below. Raise it when the rules
#: improve; never lower it to make a build pass.
MIN_RECALL_NON_HARD = 0.95


def _redactor(**overrides) -> DeterministicRedactor:
    config = RedactionConfig(
        field_policy={
            "logs": FieldPolicy(
                allow=["timestamp", "service", "level", "host", "client_ip", "message"],
                free_text=["message"],
                pseudonymise={"client_ip": "IP"},
            )
        },
        rules=[
            "private_key", "jwt", "secret_token", "bearer_token", "aws_key", "email",
            "nz_bank_account", "card_number", "account_number", "ipv4", "ipv6", "phone",
        ],
        **overrides,
    )
    return DeterministicRedactor(config, b"fixed-test-salt")


# --------------------------------------------------------------------------- #
# The property that makes diagnosis possible at all
# --------------------------------------------------------------------------- #


def test_same_value_yields_the_same_token():
    redactor = _redactor()
    records = [
        {"message": "from 203.0.113.47", "client_ip": "203.0.113.47"},
        {"message": "again from 203.0.113.47", "client_ip": "203.0.113.47"},
        {"message": "different 198.51.100.8", "client_ip": "198.51.100.8"},
    ]
    result = redactor.process(records, "logs")
    assert result.records[0]["client_ip"] == result.records[1]["client_ip"]
    assert result.records[0]["client_ip"] != result.records[2]["client_ip"]
    # "three hundred errors, all from one host" must remain visible.
    assert result.records[0]["message"] != result.records[2]["message"]


def test_tokens_are_normalised_across_formatting():
    p = Pseudonymiser(b"salt")
    assert p.token("CARD", "4539 5787 6362 1486") == p.token("CARD", "4539578763621486")
    assert p.token("EMAIL", "Mei.Tan@Example.org") == p.token("EMAIL", "mei.tan@example.org")


def test_different_salts_give_different_tokens():
    assert Pseudonymiser(b"a").token("IP", "203.0.113.47") != Pseudonymiser(b"b").token(
        "IP", "203.0.113.47"
    )


def test_original_values_never_appear_in_hits():
    redactor = _redactor()
    result = redactor.process(
        [{"message": "card 4539578763621486 for rangi.walker@example.com"}], "logs"
    )
    blob = json.dumps([h.to_dict() for h in result.hits])
    assert "4539578763621486" not in blob
    assert "rangi.walker@example.com" not in blob
    assert result.hits


def test_originals_are_gone_from_the_records():
    redactor = _redactor()
    result = redactor.process(
        [{"message": "card 4539578763621486 for rangi.walker@example.com"}], "logs"
    )
    text = result.records[0]["message"]
    assert "4539578763621486" not in text
    assert "rangi.walker@example.com" not in text
    assert "CARD_" in text and "EMAIL_" in text


# --------------------------------------------------------------------------- #
# Field policy is the positive control
# --------------------------------------------------------------------------- #


def test_fields_outside_the_policy_never_reach_the_reasoner():
    redactor = _redactor()
    result = redactor.process(
        [{"message": "ok", "internal_customer_note": "do not disclose"}], "logs"
    )
    assert "internal_customer_note" not in result.records[0]
    assert "internal_customer_note" in result.dropped_fields


def test_strict_fields_aborts_rather_than_dropping():
    redactor = _redactor(strict_fields=True)
    with pytest.raises(RedactionFailure, match="not covered by the field policy"):
        redactor.process([{"message": "ok", "surprise": "x"}], "logs")


def test_strict_fields_aborts_on_an_undeclared_kind():
    redactor = _redactor(strict_fields=True)
    with pytest.raises(RedactionFailure, match="no field policy"):
        redactor.process([{"anything": 1}], "traces")


def test_unknown_rule_name_fails_loudly():
    with pytest.raises(RedactionFailure, match="unknown redaction rule"):
        DeterministicRedactor(RedactionConfig(rules=["not_a_rule"]), b"salt")


def test_deployment_salt_requires_the_environment_variable(monkeypatch):
    from auditglass.redact.redactor import make_salt

    monkeypatch.delenv("AUDITGLASS_SALT", raising=False)
    with pytest.raises(RedactionFailure, match="is not set"):
        make_salt(RedactionConfig(salt_scope="deployment"))

    monkeypatch.setenv("AUDITGLASS_SALT", "shared-salt")
    assert make_salt(RedactionConfig(salt_scope="deployment")) == b"shared-salt"


# --------------------------------------------------------------------------- #
# Overlap handling
# --------------------------------------------------------------------------- #


def test_secrets_win_over_looser_rules():
    redactor = _redactor()
    text = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abcdefghijklmnop"
    result = redactor.process([{"message": text}], "logs")
    assert "eyJhbGciOiJIUzI1NiJ9" not in result.records[0]["message"]
    assert "SECRET_" in result.records[0]["message"]


def test_non_luhn_digit_runs_are_not_treated_as_cards():
    """Otherwise every epoch-millis timestamp becomes a redacted 'card'."""
    redactor = _redactor()
    result = redactor.process([{"message": "seq 1742000000000 processed"}], "logs")
    assert "1742000000000" in result.records[0]["message"]


# --------------------------------------------------------------------------- #
# Measured recall
# --------------------------------------------------------------------------- #


def _recall() -> tuple[float, float, list[dict]]:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    redactor = _redactor()
    hit, total, hard_hit, hard_total = 0, 0, 0, 0
    misses: list[dict] = []
    for case in corpus["cases"]:
        result = redactor.process([{"message": case["text"]}], "logs")
        fired = {h.rule for h in result.hits}
        for rule in case["expect"]:
            found = rule in fired or (
                rule in {"bearer_token", "jwt", "secret_token"}
                and fired & {"bearer_token", "jwt", "secret_token"}
            )
            if case["difficulty"] == "hard":
                hard_total += 1
                hard_hit += bool(found)
            else:
                total += 1
                hit += bool(found)
                if not found:
                    misses.append({"text": case["text"], "missed": rule})
    return (hit / total if total else 0.0), (
        hard_hit / hard_total if hard_total else 0.0
    ), misses


def test_recall_on_the_labelled_corpus():
    recall, hard_recall, misses = _recall()
    assert recall >= MIN_RECALL_NON_HARD, (
        f"recall {recall:.0%} is below the {MIN_RECALL_NON_HARD:.0%} floor; misses: {misses}"
    )
    # Recorded, not asserted: the hard cases are expected to fail and exist so the
    # published number stays honest.
    print(f"\nrecall (easy+medium): {recall:.1%}   hard cases: {hard_recall:.1%}")


def test_recall_figure_is_reported_for_the_readme(capsys):
    recall, hard_recall, _ = _recall()
    assert 0.0 <= hard_recall <= 1.0
    assert recall <= 1.0
