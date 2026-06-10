"""Shared pytest fixtures.

The golden-file harness (mock resolver reading the reference zonefile,
paths into ``reference/test``) is added as the port grows; this scaffold
only exposes the repository and reference roots.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import settings

# Differential property tests cost a pipe round-trip to a Perl
# coprocess per example, so wall-clock deadlines only add flakiness.
# "thorough" is the fuzz session's profile (nox -s fuzz); select it
# with --hypothesis-profile=thorough.
settings.register_profile("default", deadline=None)
settings.register_profile("thorough", deadline=None, max_examples=2500)
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
