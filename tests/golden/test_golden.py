"""Golden-file tests, parametrized over ``reference/test/**/*.ferm``.

Each test reproduces one Makefile pipeline (see :mod:`runner`) and diffs
the generated output against the checked-in ``.result``.  Pointed at the
Perl oracle (the default ``perl`` target) the suite must reproduce
``make check``: everything green except the ``resolve/*`` cases when
``Net::DNS::Resolver::Mock`` is absent, which are xfailed rather than
left red so the harness itself reports green.
"""

from __future__ import annotations

import difflib
from pathlib import Path

import pytest

from .runner import (
    REFERENCE_TEST,
    FermTarget,
    arptables_case,
    ebtables_case,
    generic_case,
    import_case,
    preserve_case,
)

# Categories that share the generic slow/noflush pipeline.  import-ferm
# round-trips the same set (FERM_SCRIPTS minus arptables/ebtables).
_GENERIC_CATEGORIES = (
    "modules",
    "targets",
    "protocols",
    "misc",
    "glob",
    "ipv6",
    "resolve",
)


def _scripts(category: str) -> list[Path]:
    return sorted((REFERENCE_TEST / category).glob("*.ferm"))


def _ids(paths: list[Path]) -> list[str]:
    return [str(p.relative_to(REFERENCE_TEST)) for p in paths]


_GENERIC = [p for cat in _GENERIC_CATEGORIES for p in _scripts(cat)]
_ARP = _scripts("arptables")
_EB = _scripts("ebtables")
_PRESERVE = _scripts("preserve")


def _maybe_xfail_resolve(
    ferm_file: Path,
    target: FermTarget,
    request: pytest.FixtureRequest,
) -> None:
    """xfail resolve cases on Perl when its mock resolver is unavailable.

    Mirrors ``make check`` on a machine lacking
    ``Net::DNS::Resolver::Mock`` without leaving the suite red.  Scoped
    strictly to that condition so real Python-port failures still surface.
    """
    if "resolve" not in ferm_file.parts or target.name != "perl":
        return
    if not request.getfixturevalue("perl_has_resolver_mock"):
        pytest.xfail("Net::DNS::Resolver::Mock not installed (Perl oracle)")


def _assert_golden(expected: str, generated: str, ferm_file: Path) -> None:
    if expected == generated:
        return
    diff = "".join(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            generated.splitlines(keepends=True),
            fromfile=f"{ferm_file.name} (expected)",
            tofile=f"{ferm_file.name} (generated)",
        )
    )
    pytest.fail(f"golden mismatch for {ferm_file}:\n{diff}", pytrace=False)


@pytest.mark.parametrize("ferm_file", _GENERIC, ids=_ids(_GENERIC))
def test_generic(
    ferm_file: Path,
    golden_target: FermTarget,
    request: pytest.FixtureRequest,
) -> None:
    _maybe_xfail_resolve(ferm_file, golden_target, request)
    expected, generated = generic_case(golden_target, ferm_file)
    _assert_golden(expected, generated, ferm_file)


@pytest.mark.parametrize("ferm_file", _ARP, ids=_ids(_ARP))
def test_arptables(ferm_file: Path, golden_target: FermTarget) -> None:
    expected, generated = arptables_case(golden_target, ferm_file)
    _assert_golden(expected, generated, ferm_file)


@pytest.mark.parametrize("ferm_file", _EB, ids=_ids(_EB))
def test_ebtables(ferm_file: Path, golden_target: FermTarget) -> None:
    expected, generated = ebtables_case(golden_target, ferm_file)
    _assert_golden(expected, generated, ferm_file)


@pytest.mark.parametrize("ferm_file", _GENERIC, ids=_ids(_GENERIC))
def test_import_roundtrip(
    ferm_file: Path,
    golden_target: FermTarget,
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> None:
    _maybe_xfail_resolve(ferm_file, golden_target, request)
    save, save2 = import_case(golden_target, ferm_file, tmp_path)
    _assert_golden(save, save2, ferm_file)


@pytest.mark.parametrize("ferm_file", _PRESERVE, ids=_ids(_PRESERVE))
def test_preserve(
    ferm_file: Path,
    golden_target: FermTarget,
    mock_preserve_save2: Path,
) -> None:
    expected, generated = preserve_case(
        golden_target, ferm_file, mock_preserve_save2
    )
    _assert_golden(expected, generated, ferm_file)
