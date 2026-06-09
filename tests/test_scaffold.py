"""Scaffold tests: prove the package imports and the layout is intact.

These are placeholders so ``nox -s tests`` is green on the empty skeleton;
they are replaced/augmented by the golden-file harness as the port lands.
"""

from __future__ import annotations

from pathlib import Path


def test_package_imports() -> None:
    import pyferm

    assert pyferm.__version__


def test_reference_oracle_present(reference_root: Path) -> None:
    assert (reference_root / "src" / "ferm").is_file()
    assert (reference_root / "Makefile").is_file()


def test_cli_entry_points_are_stubs() -> None:
    from pyferm import cli, import_ferm

    for entry in (cli.main, import_ferm.main):
        try:
            entry([])
        except NotImplementedError:
            continue
        raise AssertionError(f"{entry} should be a scaffold stub")
