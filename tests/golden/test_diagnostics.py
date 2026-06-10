"""Diagnostics parity over ``reference/test/{negative,params,warning}``.

Upstream ``make check`` never runs these directories; here they pin the
port's diagnostics.  stderr must match the checked-in ``.stderr``
expectation (captured from the Perl oracle, eyeballed) byte for byte,
and the exit status must agree in verdict.  Verdict only: the oracle's
failure *code* is whatever errno ``die`` happens to leak (observed 25,
ENOTTY, under a pipe), not a contract, so failure cases assert non-zero
rather than a specific value -- the port's deliberate ``exit 1`` passes.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from .runner import REFERENCE_TEST, diagnostics_case
from .test_golden import _assert_golden, _ids

if TYPE_CHECKING:
    from .runner import FermTarget

#: Checked-in stderr expectations, mirroring the reference layout
#: (``expected/<category>/<input name>.stderr``).
_EXPECTED = Path(__file__).parent / "expected"


def _cases(category: str) -> list[Path]:
    # negative/params inputs carry no .ferm suffix; take every file.
    return sorted(p for p in (REFERENCE_TEST / category).iterdir())


_FAILURE = [*_cases("negative"), *_cases("params")]
_WARNING = _cases("warning")


def _expected_stderr(ferm_file: Path) -> str:
    rel = ferm_file.relative_to(REFERENCE_TEST)
    return (_EXPECTED / rel.parent / f"{ferm_file.name}.stderr").read_text()


@pytest.mark.parametrize("ferm_file", _FAILURE, ids=_ids(_FAILURE))
def test_failure_diagnostics(
    ferm_file: Path, golden_target: FermTarget
) -> None:
    code, stderr = diagnostics_case(golden_target, ferm_file)
    _assert_golden(_expected_stderr(ferm_file), stderr, ferm_file)
    assert code != 0, f"{ferm_file.name}: expected a failing exit status"


@pytest.mark.parametrize("ferm_file", _WARNING, ids=_ids(_WARNING))
def test_warning_diagnostics(
    ferm_file: Path, golden_target: FermTarget
) -> None:
    code, stderr = diagnostics_case(golden_target, ferm_file)
    _assert_golden(_expected_stderr(ferm_file), stderr, ferm_file)
    assert code == 0, f"{ferm_file.name}: warnings must not fail the run"
