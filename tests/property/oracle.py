"""Coprocess bridge to pure functions of the frozen Perl oracle.

``oracle_driver.pl`` extracts subs (``tokenize_string``,
``shell_escape``, import-ferm's ``tokenize``) verbatim from the frozen
sources and serves them over a NUL-delimited pipe protocol; one
persistent process per oracle function keeps the per-example cost at a
pipe round-trip.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

_HERE = Path(__file__).resolve()
REPO_ROOT = _HERE.parents[2]
ORACLE_SOURCE = REPO_ROOT / "reference" / "src" / "ferm"
IMPORT_SOURCE = REPO_ROOT / "reference" / "src" / "import-ferm"
_DRIVER = _HERE.parent / "oracle_driver.pl"

#: Record separator of the pipe protocol; payloads must not contain it.
_RECORD_SEP = b"\0"
#: Token-list separator in token replies; the test strategies exclude
#: codepoints 0 and 1 from inputs so neither separator can be forged by
#: a generated example.
_TOKEN_SEP = "\x01"


class OracleProcess:
    """One persistent driver process serving a single oracle function."""

    def __init__(self, function: str, source: Path = ORACLE_SOURCE) -> None:
        self._proc = subprocess.Popen(  # fixed argv, no shell
            ["perl", str(_DRIVER), str(source), function],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def query(self, record: str) -> str:
        """Send one record and return the oracle's reply.

        Latin-1 is a bijective byte-to-char mapping, so the oracle lexes
        the very same bytes the port sees (the byte model, section 3).
        """
        stdin = self._proc.stdin
        stdout = self._proc.stdout
        assert stdin is not None
        assert stdout is not None
        stdin.write(record.encode("latin-1") + _RECORD_SEP)
        stdin.flush()
        reply = bytearray()
        while (byte := stdout.read(1)) != _RECORD_SEP:
            if not byte:
                raise RuntimeError(
                    f"oracle driver exited (status {self._proc.poll()})"
                )
            reply.extend(byte)
        return reply.decode("latin-1")

    def query_fields(self, *fields: str) -> str:
        """Send one multi-field record (fields joined by ``\\x01``)."""
        return self.query(_TOKEN_SEP.join(fields))

    def tokenize(self, line: str) -> list[str]:
        """Send ``line`` and parse the reply as a token list."""
        reply = self.query(line)
        # The driver prefixes the token count: import-ferm's lexer can
        # emit an empty token (`""` in a save file), so a bare join
        # could not distinguish no tokens from one empty token.
        count_field, *tokens = reply.split(_TOKEN_SEP)
        if len(tokens) != int(count_field):
            raise RuntimeError(
                f"malformed token reply: {count_field} != {len(tokens)}"
            )
        return tokens

    def close(self) -> None:
        """Shut the driver down (EOF on stdin ends its read loop)."""
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None
        self._proc.stdin.close()
        self._proc.wait(timeout=10)
        self._proc.stdout.close()
