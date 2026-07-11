"""Golden tests for the nft delta-apply emitter (apply path).

Each case drives::

    python -m pyferm --nft --test --noexec --lines
        [--test-mock-previous=<fam>=<save>] ... <ferm>

and diffs stdout (the emitted delta script) against a checked-in .result.
Delta output is deterministic (sorted), so no sort.pl is applied.

This validates the emitted TEXT only.  Whether a real kernel accepts the
delta (delete/flush of present objects, refcount ordering) is proven by the
opt-in live e2e suite, not here -- a delete-bearing .result references
objects absent from an empty netns and is intentionally never applied here.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from .runner import mock_previous_args

# This module drives the pyferm CLI as ``python -m pyferm`` (the source
# module), not the packaged binary, so it cannot run in the binary
# verify-golden venv, which is deliberately pyferm-free. Skip there; the
# normal test run installs pyferm and exercises it.
pytest.importorskip("pyferm")

_HERE = Path(__file__).resolve().parent
_DELTA_DIR = _HERE / "delta_nft"
_CASES = sorted(_DELTA_DIR.glob("*.ferm"))


def _run_delta(ferm_file: Path) -> str:
    cmd = [
        sys.executable,
        "-m",
        "pyferm",
        "--nft",
        "--test",
        "--noexec",
        "--lines",
        *mock_previous_args(ferm_file),
        str(ferm_file),
    ]
    proc = subprocess.run(
        cmd, capture_output=True, encoding="utf-8", check=False
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.mark.parametrize("ferm_file", _CASES, ids=[p.stem for p in _CASES])
def test_delta_nft_golden(ferm_file: Path) -> None:
    expected = ferm_file.with_suffix(".result").read_text(encoding="utf-8")
    assert _run_delta(ferm_file) == expected
