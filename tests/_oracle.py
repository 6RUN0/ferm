"""
Shared oracle/port subprocess seam for the differential suites.

The corpus, packaged-config, synthetic-module and grammar-fuzzer suites all
shell out to the frozen Perl oracle (``reference/src/ferm``) and the Python
port (``python -m pyferm``) under a forced ``C`` locale, then diff the two.
This module holds the pieces they share -- the locale-pinned environment, the
two command prefixes, a thin compile wrapper, and the three-way parity
assertion -- so the differential contract lives in one place.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parent

# Force a deterministic locale: ferm's @include directory walk and the
# localtime banner both depend on collation/formatting that must not vary
# with the developer's environment.
ORACLE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

#: Command prefix invoking the Python port as a module.
PORT_FERM: tuple[str, ...] = (sys.executable, "-m", "pyferm")


def oracle_ferm(repo_root: Path) -> tuple[str, ...]:
    """Command prefix invoking the frozen Perl oracle ``ferm``."""
    return ("perl", str(repo_root / "reference" / "src" / "ferm"))


def compile_config(
    prefix: tuple[str, ...],
    args: Sequence[str],
    cwd: Path = REPO_ROOT,
) -> tuple[bool, str, str]:
    """Run a ferm ``prefix`` over ``args``; return ``(ok, stdout, stderr)``."""
    proc = subprocess.run(  # fixed argv, no shell
        [*prefix, *args],
        capture_output=True,
        encoding="utf-8",
        check=False,
        env=ORACLE_ENV,
        cwd=cwd,
    )
    return proc.returncode == 0, proc.stdout, proc.stderr


def _identity(text: str) -> str:
    return text


def assert_oracle_parity(
    port: tuple[bool, str, str],
    oracle: tuple[bool, str, str],
    canonicalize: Callable[[str], str],
    *,
    normalize_stderr: Callable[[str], str] = _identity,
) -> None:
    """
    Assert port and oracle agree on verdict, stderr and canonical stdout.

    ``normalize_stderr`` selects the stderr contract and must be passed
    explicitly to loosen it: the default identity is the byte-for-byte
    contract (corpus, synthetic modules), while the grammar fuzzer folds
    both internal-crash renderings to a common marker first. The two
    contracts are deliberately distinct and must never be merged into one.
    """
    assert port[0] == oracle[0], f"exit verdict differs\n{port[2]}{oracle[2]}"
    assert normalize_stderr(port[2]) == normalize_stderr(oracle[2]), (
        "stderr differs"
    )
    assert canonicalize(port[1]) == canonicalize(oracle[1])
