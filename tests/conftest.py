"""Shared pytest fixtures.

The golden-file harness (mock resolver reading the reference zonefile,
paths into ``reference/test``) is added as the port grows; this scaffold
only exposes the repository and reference roots.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from hypothesis import settings

# Match only the sweep's copy root (<repo>/mutants/tests/conftest.py), not any
# ancestor directory that merely happens to be named "mutants" -- a checkout
# under such a path must keep the stock recursion limit.
_UNDER_MUTMUT = Path(__file__).resolve().parents[1].name == "mutants"

# Under a mutmut sweep the suite runs from the <repo>/mutants copy, where the
# trampoline wraps every call in extra frames.  Legal deep-nesting inputs that
# exercise the depth guards (MAX_BLOCK_DEPTH / MAX_VALUE_DEPTH = 100) then blow
# the interpreter's default recursion limit before the product's own guard can
# fire, crashing even the unmutated baseline.  Raise the limit so the guard is
# what trips; a real runaway recursion still hits RecursionError (the limit is
# only lifted, not removed) and the input depth stays bounded at 100.  Normal
# runs keep the stock limit so genuine recursion regressions are still caught.
if _UNDER_MUTMUT:
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 1000) * 5)


def pytest_configure(config: pytest.Config) -> None:
    """Give each mutmut worker process a private pytest tmp base.

    mutmut 3.6 runs mutants across concurrent worker processes that all share
    pytest's default ``/tmp/pytest-of-<user>`` base.  Their numbered-dir
    retention GC (``cleanup_numbered_dir`` -> ``rm_rf``) then races -- one
    worker removes a ``garbage-*`` dir another is still writing, raising
    ``PytestWarning: (rm_rf) ... Directory not empty`` -- which the strict
    ``filterwarnings = error`` escalates into a spurious mutant kill.  A
    per-process ``basetemp`` drops the shared base (and the cross-process GC)
    entirely; pytest wipes an explicit basetemp at session start, so it is
    reused cleanly within a worker and never accumulates.  Only under a sweep
    and only when the caller has not already pinned ``--basetemp``.
    """
    if _UNDER_MUTMUT and not config.option.basetemp:
        base = Path(tempfile.gettempdir()) / f"ferm-mut-{os.getpid()}"
        config.option.basetemp = base
        # A sweep churns through worker PIDs, so remove our own private base at
        # session end (it is unshared -- no rm_rf race) to keep /tmp bounded.
        config.add_cleanup(lambda: shutil.rmtree(base, ignore_errors=True))


# Differential property tests cost a pipe round-trip to a Perl
# coprocess per example, so wall-clock deadlines only add flakiness.
# "thorough" is the fuzz session's profile (nox -s fuzz); select it
# with --hypothesis-profile=thorough.  print_blob makes a CI
# counterexample reproducible locally (paste the printed
# @reproduce_failure decorator) without shipping the example database.
settings.register_profile("default", deadline=None, print_blob=True)
settings.register_profile(
    "thorough", deadline=None, max_examples=2500, print_blob=True
)
settings.load_profile("default")

REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCE_ROOT = REPO_ROOT / "reference"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Absolute path to the repository root."""
    return REPO_ROOT


@pytest.fixture(scope="session")
def reference_root() -> Path:
    """Absolute path to the Perl oracle tree (``reference/``)."""
    return REFERENCE_ROOT


@pytest.fixture(scope="session")
def perl_has_resolver_mock() -> bool:
    """Whether Perl can load Net::DNS::Resolver::Mock on this machine."""
    if shutil.which("perl") is None:
        return False
    proc = subprocess.run(  # fixed argv, no shell
        ["perl", "-MNet::DNS::Resolver::Mock", "-e1"],
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0
