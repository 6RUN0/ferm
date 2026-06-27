"""
Containerized e2e proof of ferm/docker coexistence against a real engine.

Where ``test_nft_e2e.py`` hand-plants a foreign table to *simulate*
docker, this runs a genuine docker 29 engine (docker-in-docker, native
nftables backend) and proves the operational promise directly:

* ferm owns only ``table ip ferm`` and never ``flush ruleset``, so the
  real ``docker-bridges`` tables a live engine creates survive a ferm
  apply -- and a ferm *reload* -- byte-for-byte untouched (the pain that
  otherwise forces a full ``docker restart`` after every rule edit);
* docker's forward base chain sits on ``priority filter`` (0), the same
  slot as ferm's default forward chain -- the empirical basis for the
  base-chain priority knob (deterministic ordering needs ferm ``< 0``).

Docker-in-docker needs a privileged container; the inner engine's rules
live in the throwaway container's own network namespace, so the host
firewall is never touched.

Opt-in: ``nox -s docker_coexistence_e2e`` (or
``FERM_DOCKER_COEXIST_E2E=1`` by hand); skipped otherwise, and whenever
docker is unavailable.  The scenario lives in ``docker_coexist/driver.py``,
which runs inside the container.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_COEXIST_DIR = Path(__file__).parent / "docker_coexist"
_IMAGE = "ferm-docker-coexist-e2e"

pytestmark = [
    pytest.mark.docker_coexist_e2e,
    pytest.mark.skipif(
        os.environ.get("FERM_DOCKER_COEXIST_E2E") != "1",
        reason="opt-in e2e: run via `nox -s docker_coexistence_e2e`",
    ),
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="docker is not installed",
    ),
    # The first image build pulls the dind base and apk packages, and the
    # inner engine takes seconds to boot -- the global 60s budget cannot
    # absorb it.
    pytest.mark.timeout(900),
]


def test_ferm_reload_does_not_clobber_real_docker() -> None:
    build = subprocess.run(
        ["docker", "build", "-q", "-t", _IMAGE, str(_COEXIST_DIR)],
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
            # docker-in-docker requires a privileged container; the inner
            # engine's netfilter state stays in the container's netns.
            "--privileged",
            "-v",
            f"{_REPO_ROOT}/src:/work/src:ro",
            "-v",
            f"{_COEXIST_DIR}/driver.py:/work/driver.py:ro",
            "-e",
            "PYTHONPATH=/work/src",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint",
            "python3",
            _IMAGE,
            "/work/driver.py",
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    verdict = f"driver verdict:\n{run.stdout}\n{run.stderr}"
    assert run.returncode == 0, verdict
    assert "DOCKER-COEXIST-PASS" in run.stdout, verdict
