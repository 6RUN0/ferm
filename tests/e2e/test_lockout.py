"""
Containerized e2e proof of the ``--interactive`` anti-lockout rollback.

The pty unit experiment proved only the timeout mechanism (the SIGALRM
handler must raise, PEP 475); this test proves the whole safety net:
real kernel netfilter, real iptables-restore, rules that genuinely cut
a connection, an admin who physically cannot answer the prompt, and a
rollback that restores both the ruleset and connectivity.

Netfilter is a namespaced subsystem of the shared kernel, so a
container with ``CAP_NET_ADMIN`` exercises exactly the code a bare
host would -- and the throwaway network namespace is what makes the
lockout safe to provoke.  The host kernel here has no legacy x_tables
modules, so the container uses the nft-backed iptables binaries and
ferm runs with ``--nolegacy`` (a sanctioned deviation gets real-world
exercise as a bonus).

Opt-in: ``nox -s lockout`` (or ``FERM_LOCKOUT_E2E=1`` by hand); skipped
otherwise, and whenever docker is unavailable.  The scenario itself
lives in ``lockout/driver.py``, which runs inside the container.
"""

import os
import shutil
from pathlib import Path

import pytest

from tests.e2e.conftest import build_and_run_driver

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LOCKOUT_DIR = Path(__file__).parent / "lockout"
_IMAGE = "ferm-lockout-e2e"

pytestmark = [
    pytest.mark.lockout,
    pytest.mark.skipif(
        os.environ.get("FERM_LOCKOUT_E2E") != "1",
        reason="opt-in e2e: run via `nox -s lockout`",
    ),
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="docker is not installed",
    ),
    # The first image build downloads a base image and apt packages,
    # which the global 60s budget cannot absorb.
    pytest.mark.timeout(900),
]


def test_interactive_timeout_rolls_back_a_real_lockout() -> None:
    build_and_run_driver(
        _IMAGE,
        _LOCKOUT_DIR,
        run_args=[
            "--cap-add=NET_ADMIN",
            "-v",
            f"{_REPO_ROOT}/src:/work/src:ro",
            "-v",
            f"{_LOCKOUT_DIR}/driver.py:/work/driver.py:ro",
            "-e",
            "PYTHONPATH=/work/src",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            _IMAGE,
            "python3",
            "/work/driver.py",
        ],
        pass_marker="LOCKOUT-E2E-PASS",
    )
