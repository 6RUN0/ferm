"""Shared pytest fixtures.

The golden-file harness (mock resolver reading the reference zonefile,
paths into ``reference/test``) is added as the port grows; this scaffold
only exposes the repository and reference roots.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from hypothesis import settings

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
