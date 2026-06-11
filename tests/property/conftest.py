"""Property-suite guard: every test here drives the Perl oracle.

CI's ubuntu runners ship perl in the base image, which makes the
dependency easy to take for granted; on a host without perl the
coprocess spawn would die with a bare ``FileNotFoundError`` deep
inside a fixture.  Skip the whole suite explicitly instead.
"""

from __future__ import annotations

import shutil

import pytest


@pytest.fixture(autouse=True, scope="session")
def _require_perl() -> None:
    """Skip the differential suite when the oracle cannot run."""
    if shutil.which("perl") is None:
        pytest.skip("perl not on PATH; the differential oracle needs it")
