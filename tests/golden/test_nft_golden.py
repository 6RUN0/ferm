"""Golden text harness for the nft backend (design section 10, layer 1).

Pure string comparison of ``--nft --noexec --lines`` output against a
checked-in, manually-verified ``.nft`` expectation -- no kernel, no caps,
runs in preflight (design section 10).

Each ``nft/<name>.ferm`` input is paired with a ``nft/<name>.nft``
expectation that was generated, cross-checked against the reference
``iptables-translate``/``ip6tables-translate`` for every match/verdict,
read line by line, and only then committed.  The positive parametrization
skips any ``.ferm`` whose ``.nft`` sibling is absent so a negative case
(an input that deliberately exits non-zero and carries no ``.nft``) cannot
break the parametrized suite.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).parent
_CASES = sorted(
    ferm
    for ferm in (_HERE / "nft").glob("*.ferm")
    if ferm.with_suffix(".nft").exists()
)
assert _CASES, f"No golden .ferm/.nft pairs found under {_HERE / 'nft'}"


def _run_nft(ferm_file: Path) -> str:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyferm",
            "--nft",
            "--test",
            "--noexec",
            "--lines",
            str(ferm_file),
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.mark.parametrize("ferm_file", _CASES, ids=lambda p: p.stem)
def test_nft_golden(ferm_file: Path) -> None:
    expected = ferm_file.with_suffix(".nft").read_text(encoding="utf-8")
    assert _run_nft(ferm_file) == expected


def test_nft_uncovered_module_errors() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyferm",
            "--nft",
            "--test",
            "--noexec",
            "--lines",
            str(_HERE / "nft" / "uncovered.ferm"),
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 1
    assert "not yet supported by nft backend" in proc.stderr


def test_nft_port_nat_without_transport_errors() -> None:
    # finding C1: a port-bearing NAT mapping with no preceding transport
    # match exits non-zero at translate time (nft would reject the applied
    # script), rather than emitting a script that fails at apply.
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyferm",
            "--nft",
            "--test",
            "--noexec",
            "--lines",
            str(_HERE / "nft" / "nat_port_no_proto.ferm"),
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 1
    assert "needs a tcp/udp protocol match" in proc.stderr
