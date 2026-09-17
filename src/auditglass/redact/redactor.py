"""Deterministic pseudonymisation.

Masking destroys the thing diagnosis depends on. If every address becomes ``***``,
then "three hundred errors, all from one upstream host" — frequently the only useful
conclusion available — stops being visible. So values are not masked; they are
replaced by stable tokens:

    203.0.113.47   ->  IP_a37f2b1c
    acct-88413920  ->  ACCT_5d9e0417

The same input yields the same token everywhere in a run, so correlation survives
intact while the original value stays inside the organisation. Tokens are
``PREFIX_HMAC(salt, normalised_value)[:8]``.

Salt scope is a real trade-off and is configuration, not a default to ignore:

``run`` (default)
    A fresh salt per run. Tokens cannot be correlated between runs, which is better
    for privacy and rules out cross-incident pattern analysis.

``deployment``
    A salt held in an environment variable. Cross-run correlation works. If that
    salt ever leaks, low-entropy values — IPv4 addresses, short account numbers —
    become brute-forceable from their tokens.

Pseudonymisation is data minimisation, not a guarantee. The only configuration that
guarantees production data does not leave the organisation is a local model endpoint.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from typing import Any

from ..config import RedactionConfig
from ..errors import RedactionFailure
from ..interfaces import RedactionHit, RedactionResult
from . import injection
from .rules import Rule, resolve


def make_salt(config: RedactionConfig) -> bytes:
    if config.salt_scope == "deployment":
        raw = os.environ.get(config.deployment_salt_env)
        if not raw:
            raise RedactionFailure(
                f"redaction.salt_scope is 'deployment' but ${config.deployment_salt_env} "
                f"is not set. Set it, or switch to salt_scope: run."
            )
        return raw.encode("utf-8")
    return os.urandom(32)


class Pseudonymiser:
    def __init__(self, salt: bytes, keep_reverse: bool = True) -> None:
        self._salt = salt
        self._keep_reverse = keep_reverse
        self.reverse: dict[str, str] = {}

    @staticmethod
    def _normalise(value: str) -> str:
        return re.sub(r"[\s\-]+", "", value).casefold()

    def token(self, prefix: str, value: str) -> str:
        digest = hmac.new(
            self._salt, self._normalise(value).encode("utf-8"), hashlib.sha256
        ).hexdigest()[:8]
        token = f"{prefix}_{digest}"
        if self._keep_reverse:
            self.reverse.setdefault(token, value)
        return token


@dataclass
class _Match:
    start: int
    end: int
    rule: str
    prefix: str


@dataclass
class DeterministicRedactor:
    config: RedactionConfig
    salt: bytes
    _rules: list[Rule] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        custom = [
            Rule(c.name, re.compile(c.pattern), c.token_prefix) for c in self.config.custom_rules
        ]
        try:
            self._rules = resolve(list(self.config.rules), custom)
        except KeyError as exc:
            raise RedactionFailure(str(exc)) from exc
        self.pseudonymiser = Pseudonymiser(self.salt, self.config.write_reverse_map)

    # ------------------------------------------------------------------ #

    def process(self, records: list[dict[str, Any]], kind: str) -> RedactionResult:
        policy = self.config.field_policy.get(kind)
        if policy is None:
            if self.config.strict_fields:
                raise RedactionFailure(
                    f"no field policy declared for evidence kind {kind!r} and "
                    f"redaction.strict_fields is true"
                )
            allow, free_text, pseudo = None, None, {}
        else:
            allow = set(policy.allow)
            free_text = set(policy.free_text)
            pseudo = dict(policy.pseudonymise)

        out: list[dict[str, Any]] = []
        hits: list[RedactionHit] = []
        dropped: set[str] = set()

        for index, record in enumerate(records):
            clean: dict[str, Any] = {}
            for key, value in record.items():
                if allow is not None and key not in allow:
                    if self.config.strict_fields:
                        raise RedactionFailure(
                            f"field {key!r} on evidence kind {kind!r} is not covered by "
                            f"the field policy and redaction.strict_fields is true"
                        )
                    dropped.add(key)
                    continue

                if key in pseudo:
                    if value is not None:
                        token = self.pseudonymiser.token(pseudo[key], str(value))
                        hits.append(
                            RedactionHit(
                                rule=f"field:{key}",
                                field_name=key,
                                record_index=index,
                                start=0,
                                end=len(str(value)),
                                token=token,
                            )
                        )
                        clean[key] = token
                    else:
                        clean[key] = None
                    continue

                scan = free_text is None or key in free_text
                if scan and isinstance(value, str):
                    replaced, field_hits = self._scrub(value, key, index)
                    clean[key] = replaced
                    hits.extend(field_hits)
                else:
                    clean[key] = value
            out.append(clean)

        markers: list[str] = []
        if self.config.mark_injection:
            scan_fields = sorted(free_text) if free_text else _string_fields(records)
            markers = injection.scan_records(records, scan_fields)

        return RedactionResult(
            records=out,
            hits=hits,
            injection_suspected=bool(markers),
            injection_markers=markers,
            dropped_fields=dropped,
        )

    # ------------------------------------------------------------------ #

    def _scrub(self, text: str, field_name: str, index: int) -> tuple[str, list[RedactionHit]]:
        matches: list[_Match] = []
        for rule in self._rules:
            for found in rule.pattern.finditer(text):
                if rule.confirm is not None and not rule.confirm(found.group(0)):
                    continue
                matches.append(_Match(found.start(), found.end(), rule.name, rule.prefix))

        # Overlap policy: at a given position the longest match wins, so
        # "Bearer eyJ…" is claimed whole rather than leaving "Bearer " exposed.
        # Equal-length ties go to whichever rule comes first in rules.ORDER, because
        # the sort is stable and rules are applied in that order above.
        matches.sort(key=lambda candidate: (candidate.start, -(candidate.end - candidate.start)))
        chosen: list[_Match] = []
        cursor = -1
        for candidate in matches:
            if candidate.start >= cursor:
                chosen.append(candidate)
                cursor = candidate.end

        if not chosen:
            return text, []

        pieces: list[str] = []
        hits: list[RedactionHit] = []
        last = 0
        for span in chosen:
            original = text[span.start : span.end]
            token = self.pseudonymiser.token(span.prefix, original)
            pieces.append(text[last : span.start])
            pieces.append(token)
            last = span.end
            hits.append(
                RedactionHit(
                    rule=span.rule,
                    field_name=field_name,
                    record_index=index,
                    start=span.start,
                    end=span.end,
                    token=token,
                )
            )
        pieces.append(text[last:])
        return "".join(pieces), hits


def _string_fields(records: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for record in records:
        for key, value in record.items():
            if isinstance(value, str) and key not in names:
                names.append(key)
    return names
