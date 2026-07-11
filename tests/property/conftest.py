"""
Property-suite guard for tests that drive the Perl oracle.

CI's ubuntu runners ship perl in the base image, which makes the
dependency easy to take for granted; on a host without perl the
coprocess spawn would die with a bare ``FileNotFoundError`` deep
inside a fixture.  Modules that shell out to the oracle declare
``pytestmark = pytest.mark.usefixtures("require_perl")`` so only they
skip -- the oracle-free property tests keep running without perl.
"""

from __future__ import annotations

import shutil

import pytest


@pytest.fixture(scope="session")
def require_perl() -> None:
    """Skip oracle-driven tests when the Perl oracle cannot run."""
    if shutil.which("perl") is None:
        pytest.skip("perl not on PATH; the differential oracle needs it")
