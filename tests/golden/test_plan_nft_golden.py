"""Port-only golden tests for ``ferm --plan --nft``.

Each case drives::

    python -m pyferm --plan --plan-format <fmt> --nft --test
        [--test-mock-previous=<fam>=<mock>] ... <ferm>

over a ``.ferm`` input and a hand-written ``nft list table`` mock, and
diffs stdout against a checked-in ``.result``.  Plan output is
deterministic (sorted), so no sort.pl canonicalization is applied.

Mock-file naming convention (per fixture stem):

- ``<stem>.save``    -- ip family mock (nft family ``ip``)
- ``<stem>.save6``   -- ip6 family mock (nft family ``ip6``)
- ``<stem>.savearp`` -- arp family mock (nft family ``arp``)
- ``<stem>.saveeb``  -- eb family mock (nft family ``bridge``)

A fixture that targets only one family carries only the relevant mock
sibling.  The harness auto-detects which mocks are present and passes each
as a separate ``--test-mock-previous=<fam>=<file>`` flag.

Cases that run with ``--plan-format=diff`` instead of ``structured``
are listed in ``_DIFF_FORMAT_STEMS``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# This module drives the pyferm CLI as ``python -m pyferm`` (the source
# module), not the packaged binary, so it cannot run in the binary
# verify-golden venv, which is deliberately pyferm-free. Skip there; the
# normal test run installs pyferm and exercises it.
pytest.importorskip("pyferm")

_HERE = Path(__file__).resolve().parent
_PLAN_NFT_DIR = _HERE / "plan_nft"
_CASES = sorted(_PLAN_NFT_DIR.glob("*.ferm"))

# Map from mock-file suffix to ferm family token.
_MOCK_SUFFIXES: list[tuple[str, str]] = [
    (".save", "ip"),
    (".save6", "ip6"),
    (".savearp", "arp"),
    (".saveeb", "eb"),
]

# Cases that run with --plan-format=diff instead of structured.
_DIFF_FORMAT_STEMS = frozenset({"diff_format"})


def _run_plan_nft(ferm_file: Path, fmt: str) -> tuple[int, str]:
    """Run ``--plan --nft`` over one fixture, return ``(exit_code, stdout)``.

    Detects which mock siblings are present and passes each as a
    ``--test-mock-previous=<fam>=<path>`` argument.
    """
    cmd = [
        sys.executable,
        "-m",
        "pyferm",
        "--plan",
        "--plan-format",
        fmt,
        "--nft",
        "--test",
    ]
    for suffix, ferm_family in _MOCK_SUFFIXES:
        mock = ferm_file.with_suffix(suffix)
        if mock.exists():
            cmd.append(f"--test-mock-previous={ferm_family}={mock}")
    cmd.append(str(ferm_file))
    proc = subprocess.run(  # fixed argv, no shell
        cmd, capture_output=True, encoding="utf-8", check=False
    )
    return proc.returncode, proc.stdout


@pytest.mark.parametrize("ferm_file", _CASES, ids=[p.stem for p in _CASES])
def test_plan_nft_golden(ferm_file: Path) -> None:
    """Each fixture stdout and exit code must match its checked-in .result."""
    fmt = "diff" if ferm_file.stem in _DIFF_FORMAT_STEMS else "structured"
    expected = ferm_file.with_suffix(".result").read_text(encoding="utf-8")
    expected_code = 0 if "No changes" in expected else 2
    code, generated = _run_plan_nft(ferm_file, fmt)
    assert generated == expected
    assert code == expected_code


def test_canon_ip_golden_is_clean_no_changes() -> None:
    """ip canon: named priority + ct-state + reject + burst -> no diff."""
    canon = _PLAN_NFT_DIR / "canon_ip.ferm"
    code, out = _run_plan_nft(canon, "structured")
    assert code == 0, out
    assert "No changes" in out


def test_canon_eb_golden_is_clean_no_changes() -> None:
    """bridge canon: dstnat=-300 named priority -> no diff."""
    canon = _PLAN_NFT_DIR / "canon_eb.ferm"
    code, out = _run_plan_nft(canon, "structured")
    assert code == 0, out
    assert "No changes" in out


def test_plan_nft_diff_format_emits_unified_markers() -> None:
    """``--plan-format=diff`` emits unified-diff markers and ``:chain``."""
    case = _PLAN_NFT_DIR / "diff_format.ferm"
    code, out = _run_plan_nft(case, "diff")
    assert code == 2, out
    assert "@@" in out
    assert ":INPUT" in out


def test_plan_noflush_nft_is_rejected() -> None:
    """``--plan --noflush --nft`` exits 1 and mentions noflush in stderr."""
    # Use any valid .ferm fixture; the error fires before the config is parsed.
    case = _PLAN_NFT_DIR / "canon_ip.ferm"
    mock = _PLAN_NFT_DIR / "canon_ip.save"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyferm",
            "--plan",
            "--noflush",
            "--nft",
            "--test",
            f"--test-mock-previous=ip={mock}",
            str(case),
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 1
    assert "noflush" in proc.stderr.lower()
