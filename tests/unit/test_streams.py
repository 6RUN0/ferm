"""Unit tests for :mod:`pyferm.streams`."""

from __future__ import annotations

import io

from pyferm.streams import reconfigure_latin1


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


def test_reconfigure_latin1_skips_detached_wrapper() -> None:
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    stream.detach()
    reconfigure_latin1(stream)  # must not raise


def test_reconfigure_latin1_leaves_plain_stringio_untouched() -> None:
    stream = io.StringIO()
    reconfigure_latin1(stream)  # no reconfigure attr -> silently skipped
    stream.write("x")
    assert stream.getvalue() == "x"
