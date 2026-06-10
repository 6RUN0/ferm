"""Fixtures for the golden-file harness.

Selects the ferm implementation under test and builds the shared
preserve mock once per session.  ``reference_root`` and
``perl_has_resolver_mock`` are inherited from the parent
``tests/conftest.py``.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest

from .runner import FermTarget, build_mock_preserve_save2, build_target

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(scope="session")
def golden_target(reference_root: Path) -> FermTarget:
    """The ferm under test; ``FERM_GOLDEN_TARGET`` env, default ``perl``."""
    name = os.environ.get("FERM_GOLDEN_TARGET", "perl")
    return build_target(name, reference_root)


@pytest.fixture(scope="session")
def mock_preserve_save2(
    golden_target: FermTarget,
    reference_root: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> Path:
    """Build the mocked previous ruleset shared by all preserve tests."""
    tmp = tmp_path_factory.mktemp("preserve-mock")
    return build_mock_preserve_save2(golden_target, reference_root, tmp)
