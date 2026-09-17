"""Detection of instruction-like content in retrieved evidence.

This marks, it does not filter.

Filtering injected content would be a denylist, and would fail the same way every
denylist fails. The actual defence against injection in this tool is architectural:
a planner selects a template and fills typed parameters, so no amount of persuasive
text in a log line can produce a query the template set does not describe. See
``docs/threat-model.md`` T2.

What marking is for: a human reading the report deserves to know that a piece of
evidence was trying to talk to the machine, and an auditor deserves to see it in the
trail. A marked evidence block is a signal, not a verdict.
"""

from __future__ import annotations

import re

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("override-instruction", re.compile(r"(?i)\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:previous|prior|earlier|above|all)\b[^.\n]{0,40}\b(?:instruction|prompt|rule|direction)")),
    ("role-marker", re.compile(r"(?im)^\s*(?:system|assistant|user|developer)\s*:")),
    ("chat-template", re.compile(r"<\|(?:im_start|im_end|system|assistant|user|endoftext)\|>")),
    ("new-instructions", re.compile(r"(?i)\b(?:new|updated|revised)\s+(?:instruction|directive|task)s?\b")),
    ("identity-reassignment", re.compile(r"(?i)\byou\s+are\s+(?:now\s+)?(?:a|an|the)\b")),
    ("tool-directive", re.compile(r"(?i)\b(?:now\s+)?(?:query|fetch|retrieve|read|dump|export)\b[^.\n]{0,30}\b(?:index|table|bucket|database|collection|secret|credential|payroll|salary)\b")),
    ("exfil-directive", re.compile(r"(?i)\b(?:include|append|attach|send|post)\b[^.\n]{0,40}\b(?:full|entire|all|raw)\b[^.\n]{0,20}\b(?:document|record|row|content|response)")),
    ("markdown-image", re.compile(r"!\[[^\]]*\]\(\s*[a-z]+:", re.IGNORECASE)),
    ("diagnosis-assertion", re.compile(r"(?i)\b(?:no action required|known transient|safe to ignore|已确认无需处理)\b")),
    ("ansi-escape", re.compile(r"\x1b\[[0-9;]*[A-Za-z]")),
]


def detect(text: str) -> list[str]:
    """Return the names of any injection patterns present in ``text``."""
    if not text:
        return []
    return [name for name, pattern in PATTERNS if pattern.search(text)]


def scan_records(records: list[dict], fields: list[str]) -> list[str]:
    """Scan the named fields across a set of records, returning distinct markers."""
    found: list[str] = []
    for record in records:
        for name in fields:
            value = record.get(name)
            if isinstance(value, str):
                for marker in detect(value):
                    if marker not in found:
                        found.append(marker)
    return found
