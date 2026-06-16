"""Invoke the ferm-under-test and replicate the Makefile pipelines.

Each ``*_case`` helper reproduces one Makefile rule from
``reference/Makefile`` exactly - including the deliberate SED/sort
asymmetry between the generated and the checked-in (expected) side - and
returns ``(expected, generated)`` for the test to diff.

The only external process is ferm itself, selected via :class:`FermTarget`
so the same harness validates against the Perl oracle first and the
Python port later (``FERM_GOLDEN_TARGET=perl|python``).
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .normalize import eb_arp_sed, ebtables_tempfile_rename, result_sed
from .sortpl import sort_output

_HERE = Path(__file__).resolve()
REPO_ROOT = _HERE.parents[2]
REFERENCE_ROOT = REPO_ROOT / "reference"
REFERENCE_TEST = REFERENCE_ROOT / "test"

# Force a deterministic locale: ferm's @include directory walk and the
# localtime banner both depend on collation/formatting that must not vary
# with the developer's environment.
_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}


@dataclass(frozen=True)
class FermTarget:
    """A ferm implementation under test (its ``ferm``/``import-ferm``)."""

    name: str
    ferm: tuple[str, ...]
    import_ferm: tuple[str, ...]


def build_target(name: str, reference_root: Path) -> FermTarget:
    """Construct the command prefixes for the named target."""
    if name == "perl":
        src = reference_root / "src"
        return FermTarget(
            name="perl",
            ferm=("perl", str(src / "ferm")),
            import_ferm=("perl", str(src / "import-ferm")),
        )
    if name == "python":
        # Console scripts installed into the uv-managed venv that pytest
        # already runs under; refined when the Python port can emit.
        return FermTarget(
            name="python",
            ferm=(sys.executable, "-m", "pyferm"),
            import_ferm=(sys.executable, "-m", "pyferm.import_ferm"),
        )
    if name == "binary":
        raw = os.environ.get("FERM_BINARY")
        if not raw:
            raise ValueError(
                "binary target requires FERM_BINARY=<path to ferm in *.dist/>"
            )
        binary = Path(raw)
        # The packaged dist ships ``ferm`` and an in-dist symlink
        # ``import-ferm`` -> ``ferm`` alongside it; the dispatcher routes by
        # the invoked basename, so both prefixes are the same binary under a
        # different name.
        return FermTarget(
            name="binary",
            ferm=(str(binary),),
            import_ferm=(str(binary.with_name("import-ferm")),),
        )
    raise ValueError(f"unknown ferm target: {name!r}")


class FermInvocationError(RuntimeError):
    """ferm exited non-zero; carries stderr for a readable test failure."""

    def __init__(self, cmd: list[str], returncode: int, stderr: str) -> None:
        super().__init__(f"{cmd!r} exited {returncode}\n{stderr}".rstrip())
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr


def _run(prefix: tuple[str, ...], args: list[str]) -> str:
    cmd = [*prefix, *args]
    # Run from the reference tree (like ``make -C reference``): @glob and
    # @include resolve relative to the cwd, and ferm echoes those relative
    # paths into the rules, so the cwd is part of the golden contract.
    proc = subprocess.run(  # fixed argv, no shell
        cmd,
        capture_output=True,
        encoding="utf-8",
        check=False,
        env=_ENV,
        cwd=REFERENCE_ROOT,
    )
    if proc.returncode != 0:
        raise FermInvocationError(cmd, proc.returncode, proc.stderr)
    return proc.stdout


def _rel(path: Path) -> str:
    """A ferm input path expressed relative to the reference tree cwd."""
    return str(path.relative_to(REFERENCE_ROOT))


def _result_of(ferm_file: Path) -> str:
    return ferm_file.with_suffix(".result").read_text(encoding="utf-8")


# --- per-category pipelines (one Makefile rule each) -----------------


def generic_case(target: FermTarget, ferm_file: Path) -> tuple[str, str]:
    """modules/targets/protocols/misc/glob/ipv6/resolve (slow, noflush)."""
    raw = _run(target.ferm, ["--test", "--slow", "--noflush", _rel(ferm_file)])
    generated = result_sed(sort_output(raw))
    expected = sort_output(_result_of(ferm_file))
    return expected, generated


def arptables_case(target: FermTarget, ferm_file: Path) -> tuple[str, str]:
    """arptables: slow, EB_ARP_RESULT_SED, no sort.pl on generated side."""
    raw = _run(target.ferm, ["--test", "--slow", _rel(ferm_file)])
    generated = eb_arp_sed(raw)
    expected = sort_output(_result_of(ferm_file))
    return expected, generated


def ebtables_case(target: FermTarget, ferm_file: Path) -> tuple[str, str]:
    """ebtables: slow, tempfile-rename then EB_ARP_RESULT_SED."""
    raw = _run(target.ferm, ["--test", "--slow", _rel(ferm_file)])
    generated = eb_arp_sed(ebtables_tempfile_rename(raw))
    expected = sort_output(_result_of(ferm_file))
    return expected, generated


def import_case(
    target: FermTarget, ferm_file: Path, tmp: Path
) -> tuple[str, str]:
    """Round-trip: SAVE == SAVE2 through import-ferm (check-import)."""
    save = sort_output(_run(target.ferm, ["--test", _rel(ferm_file)]))
    save_file = tmp / "round.SAVE"
    save_file.write_text(save, encoding="utf-8")

    import_out = _run(target.import_ferm, [str(save_file)])
    import_file = tmp / "round.IMPORT"
    import_file.write_text(import_out, encoding="utf-8")

    save2 = sort_output(
        _run(target.ferm, ["--test", "--fast", str(import_file)])
    )
    return save, save2


def preserve_case(
    target: FermTarget, ferm_file: Path, mock_save2: Path
) -> tuple[str, str]:
    """@preserve against a mocked previous ruleset (check-preserve)."""
    raw = _run(
        target.ferm,
        ["--test", f"--test-mock-previous=ip={mock_save2}", _rel(ferm_file)],
    )
    generated = result_sed(sort_output(raw))
    expected = result_sed(_result_of(ferm_file))
    return expected, generated


def diagnostics_case(target: FermTarget, ferm_file: Path) -> tuple[int, str]:
    """negative/params/warning: return ``(exit code, stderr)``, no raise.

    Unlike :func:`_run`, a non-zero exit is the expected outcome here,
    so the verdict is returned for the test to assert on.
    """
    cmd = [*target.ferm, "--test", "--slow", "--noflush", _rel(ferm_file)]
    proc = subprocess.run(  # fixed argv, no shell
        cmd,
        capture_output=True,
        encoding="utf-8",
        check=False,
        env=_ENV,
        cwd=REFERENCE_ROOT,
    )
    return proc.returncode, proc.stderr


def build_mock_preserve_save2(
    target: FermTarget, reference_root: Path, tmp: Path
) -> Path:
    """Build test/mock/preserve.SAVE2 via the SAVE->IMPORT->SAVE2 chain."""
    mock_ferm = reference_root / "test" / "mock" / "preserve.ferm"
    save = sort_output(_run(target.ferm, ["--test", _rel(mock_ferm)]))
    save_file = tmp / "preserve.SAVE"
    save_file.write_text(save, encoding="utf-8")

    import_out = _run(target.import_ferm, [str(save_file)])
    import_file = tmp / "preserve.IMPORT"
    import_file.write_text(import_out, encoding="utf-8")

    save2 = sort_output(
        _run(target.ferm, ["--test", "--fast", str(import_file)])
    )
    save2_file = tmp / "preserve.SAVE2"
    save2_file.write_text(save2, encoding="utf-8")
    return save2_file
