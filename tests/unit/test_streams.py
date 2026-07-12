"""Unit tests for :mod:`pyferm.streams`."""

from __future__ import annotations

import io
import sys

import pytest

from pyferm.streams import (
    BYTE_ENCODING,
    HUMAN_STREAM_ERRORS,
    argv_to_latin1,
    reconfigure_latin1,
    reconfigure_std_streams,
)


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


class _RecordingStream:
    """A stream double that records every ``reconfigure`` invocation."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def reconfigure(self, *, encoding: str, errors: str) -> None:
        """Record the (encoding, errors) pair the caller requested."""
        self.calls.append((encoding, errors))


def test_reconfigure_std_streams_configures_both_human_tolerant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # reconfigure_std_streams must switch BOTH sys.stdout and sys.stderr to the
    # latin-1 byte model with the human-tolerant error handler -- dropping
    # either stream (a None argument), or the errors= keyword (falling back to
    # "strict"), would either miss a stream or crash it on a localized
    # strerror.  A recording double proves each stream is touched exactly once
    # with the full (encoding, errors) pair.
    out = _RecordingStream()
    err = _RecordingStream()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    reconfigure_std_streams()
    assert out.calls == [(BYTE_ENCODING, HUMAN_STREAM_ERRORS)]
    assert err.calls == [(BYTE_ENCODING, HUMAN_STREAM_ERRORS)]
