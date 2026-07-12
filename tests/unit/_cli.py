"""Shared subprocess runner for driving pyferm's console entry point."""

from __future__ import annotations

import subprocess
import sys


def run_pyferm(
    src: str, *extra_flags: str
) -> subprocess.CompletedProcess[str]:
    """
    Run pyferm on *src* via the hermetic ``--test --noexec --lines`` path.

    Feeds *src* on stdin to ``python -m pyferm`` with any *extra_flags*
    (e.g. ``"--nft"``) appended.  Never raises on a non-zero exit: a child
    :class:`FermError` does not cross the process boundary, so callers assert
    on ``returncode`` plus a ``stderr`` substring instead of ``pytest.raises``.
    """
    return subprocess.run(  # fixed argv, no shell
        [
            sys.executable,
            "-m",
            "pyferm",
            "--test",
            "--noexec",
            "--lines",
            *extra_flags,
            "-",
        ],
        input=src,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def run_pyferm_bytes(
    *args: str, stdin: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    """
    Run ``python -m pyferm *args`` in binary mode for byte round-trip tests.

    Unlike :func:`run_pyferm`, stdout/stderr are captured as raw bytes and
    *args* is passed verbatim (no ``--noexec --lines``), so latin-1 / high-byte
    fidelity can be asserted on the wire.
    """
    return subprocess.run(  # fixed argv, no shell
        [sys.executable, "-m", "pyferm", *args],
        input=stdin,
        capture_output=True,
        check=False,
    )
