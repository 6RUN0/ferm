"""Unit tests for :mod:`pyferm.streams`."""

from __future__ import annotations

import io

import pytest

from pyferm.streams import argv_to_latin1, reconfigure_latin1


def test_argv_to_latin1_reinterprets_argv_bytes_one_per_char() -> None:
    # argv reaches ferm already decoded by the interpreter (filesystem
    # encoding + surrogateescape); argv_to_latin1 reverses that decode so a
    # value above U+00FF survives as its raw bytes -- one latin-1 char each,
    # the same model the config file follows -- instead of one high codepoint
    # that would overflow save.encode("latin-1") downstream.
    result = argv_to_latin1("€")  # euro, utf-8 bytes b"\xe2\x82\xac"
    assert result == "\xe2\x82\xac"
    assert "€" not in result


def test_reconfigure_latin1_switches_text_stream() -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    reconfigure_latin1(stream)
    stream.write("\xff")
    stream.flush()
    # one byte per char: utf-8 would have produced b"\xc3\xbf"
    assert stream.buffer.getvalue() == b"\xff"


def test_reconfigure_latin1_backslashreplace_above_byte_range() -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    reconfigure_latin1(stream, errors="backslashreplace")
    stream.write("\u20ac")
    stream.flush()
    # chars above U+00FF (localized strerror) must not crash the stream
    assert stream.buffer.getvalue() == b"\\u20ac"


def test_reconfigure_latin1_default_errors_is_strict() -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    reconfigure_latin1(stream)  # default errors must be "strict"
    # strict refuses a char above the byte range with UnicodeEncodeError; any
    # other (mutated) handler name would instead raise LookupError at encode.
    with pytest.raises(UnicodeEncodeError):
        stream.write("€")


def test_reconfigure_latin1_skips_detached_wrapper() -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    stream.detach()
    reconfigure_latin1(stream)  # must not raise


def test_reconfigure_latin1_leaves_plain_stringio_untouched() -> None:
    stream = io.StringIO()
    reconfigure_latin1(stream)  # no reconfigure attr -> silently skipped
    stream.write("x")
    assert stream.getvalue() == "x"
