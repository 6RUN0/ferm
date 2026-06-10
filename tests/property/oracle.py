"""Coprocess bridge to pure functions of the frozen Perl oracle.

``oracle_driver.pl`` extracts ``tokenize_string`` and ``shell_escape``
verbatim from ``reference/src/ferm`` and serves them over a
NUL-delimited pipe protocol; one persistent process per oracle function
keeps the per-example cost at a pipe round-trip.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

_HERE = Path(__file__).resolve()
REPO_ROOT = _HERE.parents[2]
ORACLE_SOURCE = REPO_ROOT / "reference" / "src" / "ferm"
_DRIVER = _HERE.parent / "oracle_driver.pl"

#: Record separator of the pipe protocol; payloads must not contain it.
_RECORD_SEP = b"\0"
#: Token-list separator in ``tokenize`` replies; the test strategies
#: exclude codepoints 0 and 1 from inputs so neither separator can be
#: forged by a generated example.
_TOKEN_SEP = "\x01"


class OracleProcess:
    """One persistent driver process serving a single oracle function."""

    def __init__(self, function: str) -> None:
        self._proc = subprocess.Popen(  # fixed argv, no shell
            ["perl", str(_DRIVER), str(ORACLE_SOURCE), function],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

    def query(self, record: str) -> str:
        """Send one record and return the oracle's reply."""
        stdin = self._proc.stdin
        stdout = self._proc.stdout
        assert stdin is not None and stdout is not None
        stdin.write(record.encode("ascii") + _RECORD_SEP)
        stdin.flush()
        reply = bytearray()
        while (byte := stdout.read(1)) != _RECORD_SEP:
            if not byte:
                raise RuntimeError(
                    f"oracle driver exited (status {self._proc.poll()})"
                )
            reply.extend(byte)
        return reply.decode("ascii")

    def tokenize(self, line: str) -> list[str]:
        """Tokenize ``line`` via the oracle's ``tokenize_string``."""
        reply = self.query(line)
        # No empty tokens exist (the shortest is a one-character
        # special), so an empty reply means an empty token list.
        return reply.split(_TOKEN_SEP) if reply else []

    def close(self) -> None:
        """Shut the driver down (EOF on stdin ends its read loop)."""
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None
        self._proc.stdin.close()
        self._proc.wait(timeout=10)
        self._proc.stdout.close()
