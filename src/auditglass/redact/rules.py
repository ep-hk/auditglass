"""Built-in detection rules.

Ordering matters: rules run in the order listed, and an earlier match consumes the
span, so ``card_number`` is placed before ``account_number`` to stop the looser rule
from claiming a card.

These rules are pattern-based and therefore have recall below 100%. That is stated
plainly in the README and the threat model, and it is why the field policy — a
positive control that never lets an unlisted field through at all — is the primary
mechanism and these rules are the secondary one.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    prefix: str
    #: Optional confirmation step for patterns that are cheap to match and easy to
    #: over-match, such as anything that looks like a run of digits.
    confirm: Callable[[str], bool] | None = None


def _valid_ipv4(text: str) -> bool:
    parts = text.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _luhn(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


BUILTIN: dict[str, Rule] = {
    # Secrets first: if a credential has leaked into a log line, nothing else about
    # that line matters as much.
    "secret_token": Rule(
        "secret_token",
        re.compile(
            r"\b(?:sk|pk|rk|ghp|gho|ghs|ghu|ghr|xoxb|xoxa|xoxp|xoxr|xoxs)[-_]"
            r"[A-Za-z0-9_\-]{16,}\b"
        ),
        "SECRET",
    ),
    "bearer_token": Rule(
        "bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/\-]{20,}={0,2}"),
        "SECRET",
    ),
    "aws_key": Rule("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "SECRET"),
    "private_key": Rule(
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "SECRET",
    ),
    "email": Rule(
        "email",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "EMAIL",
    ),
    "ipv4": Rule(
        "ipv4",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "IP",
        confirm=_valid_ipv4,
    ),
    "ipv6": Rule(
        "ipv6",
        re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"),
        "IP6",
    ),
    "card_number": Rule(
        "card_number",
        # Anchored on digits at both ends: a trailing ``[ -]?`` would otherwise eat
        # the space after the number and glue the token to the next word.
        re.compile(r"\b\d(?:[ \-]?\d){12,18}\b"),
        "CARD",
        confirm=_luhn,
    ),
    "account_number": Rule(
        "account_number",
        re.compile(
            r"(?i)\b(?:acct|account|acc|customer|cust|iban|member)[-_:# ]{0,2}"
            r"[A-Z0-9]{6,24}\b"
        ),
        "ACCT",
    ),
    "nz_bank_account": Rule(
        "nz_bank_account",
        re.compile(r"\b\d{2}-\d{4}-\d{7}-\d{2,3}\b"),
        "BANKACCT",
    ),
    "phone": Rule(
        "phone",
        re.compile(r"(?<![\w.])\+\d{1,3}[\s\-]?(?:\(?\d{1,4}\)?[\s\-]?){2,5}\d{2,4}(?![\w.])"),
        "PHONE",
    ),
    "jwt": Rule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
        "SECRET",
    ),
}

#: The order rules are applied in. Rules not listed here still work if named
#: explicitly in configuration; this only fixes precedence for the common set.
ORDER = [
    "private_key",
    "jwt",
    "secret_token",
    "bearer_token",
    "aws_key",
    "email",
    "nz_bank_account",
    "card_number",
    "account_number",
    "ipv4",
    "ipv6",
    "phone",
]


def resolve(names: list[str], custom: list[Rule] | None = None) -> list[Rule]:
    """Return the requested rules in a deterministic precedence order."""
    unknown = [n for n in names if n not in BUILTIN]
    if unknown:
        raise KeyError(f"unknown redaction rule(s): {sorted(unknown)}")
    wanted = set(names)
    ordered = [BUILTIN[n] for n in ORDER if n in wanted]
    ordered += [BUILTIN[n] for n in sorted(wanted) if n not in set(ORDER)]
    return ordered + list(custom or [])
