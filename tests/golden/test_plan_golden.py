"""Port-only golden tests for ``ferm --plan`` (no Perl oracle exists).

Each case drives ``python -m pyferm --plan --test --test-mock-previous=ip=...``
over a ``.ferm`` input and a hand-written short-form ``.save`` mock, and diffs
stdout against a checked-in ``.result``.  Plan output is deterministic
(sorted), so no sort.pl canonicalization is applied.

The ``--noflush`` variant and the dual-stack (ip6) variant share one helper:
``_run_plan`` adds ``--noflush`` on request and a second
``--test-mock-previous=ip6=...`` whenever a ``.save6`` sibling exists.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_PLAN_DIR = _HERE / "plan"
_CASES = sorted(_PLAN_DIR.glob("*.ferm"))

# Cases that must run with --noflush to exercise the survives/flushed split.
_NOFLUSH_STEMS = frozenset({"noflush"})


def _run_plan(
    ferm_file: Path, fmt: str, *, noflush: bool = False
) -> tuple[int, str]:
    """Run ``--plan`` over one fixture, returning ``(exit_code, stdout)``.

    Passes an ``ip`` mock from the ``.save`` sibling and, when a ``.save6``
    sibling exists, a second ``ip6`` mock so dual-stack cases render both
    family sections.  ``noflush`` adds ``--noflush`` for the survives/flushed
    cases.
    """
    mock = ferm_file.with_suffix(".save")
    cmd = [
        sys.executable,
        "-m",
        "pyferm",
        "--plan",
        "--plan-format",
        fmt,
        "--test",
        f"--test-mock-previous=ip={mock}",
    ]
    mock6 = ferm_file.with_suffix(".save6")
    if mock6.exists():
        cmd.append(f"--test-mock-previous=ip6={mock6}")
    if noflush:
        cmd.append("--noflush")
    cmd.append(str(ferm_file))
    proc = subprocess.run(  # fixed argv, no shell
        cmd, capture_output=True, encoding="utf-8", check=False
    )
    return proc.returncode, proc.stdout


@pytest.mark.parametrize("ferm_file", _CASES, ids=[p.stem for p in _CASES])
def test_plan_golden(ferm_file: Path) -> None:
    expected = ferm_file.with_suffix(".result").read_text(encoding="utf-8")
    _code, generated = _run_plan(
        ferm_file, "structured", noflush=ferm_file.stem in _NOFLUSH_STEMS
    )
    assert generated == expected


def test_canon_golden_is_clean_no_changes() -> None:
    """The canonicalization acceptance test: equivalent config diffs empty."""
    canon = _PLAN_DIR / "canon.ferm"
    code, out = _run_plan(canon, "structured")
    assert code == 0, out
    assert "No changes" in out


def test_plan_diff_format_emits_unified_markers() -> None:
    """``--plan-format=diff`` renders unified-diff markers for a change."""
    case = _PLAN_DIR / "policy.ferm"
    code, out = _run_plan(case, "diff")
    assert code == 2, out
    assert "@@" in out
    assert "+++" in out
