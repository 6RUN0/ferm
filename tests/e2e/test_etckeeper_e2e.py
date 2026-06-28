"""
Containerized e2e proof of the etckeeper integration against real tooling.

This is the semantic layer the host integration test
(``tests/integration/test_etckeeper_git.py``) and the mocked unit tests
cannot reach: it runs the *real* ``etckeeper`` binary -- including its global
``/etc/etckeeper/commit.d`` metadata hooks, which need a real ``/etc`` and
root -- over a real git-managed ``/etc`` and a real nftables kernel.

It drives the full operator loop end to end (see ``etckeeper/driver.py`` for
the scenario): turn ``/etc`` into an etckeeper repo, apply a config and prove
the apply auto-committed a semantic message and the kernel holds the rule,
apply a changed config, then ``ferm rollback --to`` the first revision and
prove ``/etc/ferm`` and the live ruleset both return to the earlier state and
the revert is recorded as a new commit.

Netfilter is a namespaced subsystem of the shared kernel, so a container with
``CAP_NET_ADMIN`` exercises exactly the code a bare host would -- and the
throwaway namespace keeps it safe.

Opt-in: ``nox -s etckeeper_e2e`` (or ``FERM_ETCKEEPER_E2E=1`` by hand);
skipped otherwise, and whenever docker is unavailable.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ETCKEEPER_DIR = Path(__file__).parent / "etckeeper"
_IMAGE = "ferm-etckeeper-e2e"

pytestmark = [
    pytest.mark.etckeeper_e2e,
    pytest.mark.skipif(
        os.environ.get("FERM_ETCKEEPER_E2E") != "1",
        reason="opt-in e2e: run via `nox -s etckeeper_e2e`",
    ),
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="docker is not installed",
    ),
    # The first image build downloads a base image and apt packages,
    # which the global 60s budget cannot absorb.
    pytest.mark.timeout(900),
]


def test_apply_commit_rollback_round_trip() -> None:
    build = subprocess.run(
        ["docker", "build", "-q", "-t", _IMAGE, str(_ETCKEEPER_DIR)],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert build.returncode == 0, f"docker build failed:\n{build.stderr}"

    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--cap-add=NET_ADMIN",
            "-v",
            f"{_REPO_ROOT}/src:/work/src:ro",
            "-v",
            f"{_ETCKEEPER_DIR}/driver.py:/work/driver.py:ro",
            "-e",
            "PYTHONPATH=/work/src",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            _IMAGE,
            "python3",
            "/work/driver.py",
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    verdict = f"driver verdict:\n{run.stdout}\n{run.stderr}"
    assert run.returncode == 0, verdict
    assert "ETCKEEPER-E2E-PASS" in run.stdout, verdict
