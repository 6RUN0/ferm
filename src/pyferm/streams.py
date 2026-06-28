"""
Stream encoding helpers for the latin-1 byte model.

Every byte boundary of ferm is latin-1 (the Perl byte model): a bijective
byte<->char mapping keeps config bytes
intact down to the kernel and keeps ``@substr``/``length``/``re.ASCII``
counting bytes exactly as the oracle does.  Human-facing streams
additionally get ``errors="backslashreplace"``: the only source of chars
above U+00FF is a localized OS ``strerror``, and failing while printing
an error message is unacceptable.
"""

from __future__ import annotations

import os
from typing import Final

#: The encoding of every ferm byte boundary: a bijective byte<->char map
#: (see the module docstring) that keeps config bytes intact down to the
#: kernel and lets ``@substr``/``length``/``re.ASCII`` count bytes exactly.
BYTE_ENCODING: Final[str] = "latin-1"

#: Error handler for human-facing streams (stdout/stderr).  Their only
#: source of chars above U+00FF is a localized OS ``strerror``; escaping it
#: keeps an error message from crashing the very stream printing it.
HUMAN_STREAM_ERRORS: Final[str] = "backslashreplace"


def argv_to_latin1(value: str) -> str:
    """
    Re-read an ``argv`` string as its raw bytes under the latin-1 model.

    ``sys.argv`` is the one ferm input boundary the interpreter decodes
    before user code runs (filesystem encoding plus ``surrogateescape``);
    every other boundary reads raw bytes as latin-1.  ``os.fsencode``
    reverses exactly that decoding, recovering the bytes the user typed,
    which latin-1 then maps one byte per char -- the same model the config
    file, backticks and zonefiles already follow.  Without it a ``--def``
    value above U+00FF reaches ``iptables-restore``'s
    ``save.encode("latin-1")`` and raises ``UnicodeEncodeError`` (while the
    ``--lines`` path silently backslash-escapes it) instead of flowing
    through as bytes, as the Perl oracle's raw-byte ``@ARGV`` does.
    """
    return os.fsencode(value).decode(BYTE_ENCODING)


def reconfigure_latin1(stream: object, errors: str = "strict") -> None:
    """
    Switch ``stream`` to latin-1 if it supports reconfiguration.

    Streams without ``reconfigure`` (test doubles like ``StringIO``) or
    that reject it (detached/closed wrappers raise ``ValueError``) are
    left untouched: the policy matters on the real OS-backed std streams,
    which always support it.  Call it before the first read/write:
    reconfiguring the encoding afterwards raises (and is swallowed as)
    ``ValueError``.
    """
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is None:
        return
    try:
        reconfigure(encoding=BYTE_ENCODING, errors=errors)
    except ValueError:
        return
