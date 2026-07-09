"""
Containerized pin of the nft readback canon the QoS/addrtype slice
relies on.

The nft backend emits the exact spelling ``nft list ruleset`` prints
back -- the readback canon -- so ``--plan``/delta-apply converge.  The
canon for the match-set/addrtype/QoS vocabulary (fib type names and
their RTN list order, the 64-codepoint dscp name map, the ``meta
priority`` normalisation) was captured from a live kernel; this suite
re-derives it inside a throwaway container network namespace and fails
if the kernel or a newer nft ever spells those rules differently.
Netfilter is a namespaced subsystem of the shared kernel, so a container
with ``CAP_NET_ADMIN`` exercises exactly the code a bare host would.

Opt-in: ``nox -s nft_readback_e2e`` (or ``FERM_NFT_READBACK_E2E=1`` by
hand); skipped otherwise, and whenever docker is unavailable.  The
scenario itself lives in ``readback/driver.py``, which runs inside the
container.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_READBACK_DIR = Path(__file__).parent / "readback"
_IMAGE = "ferm-nft-readback-e2e"

pytestmark = [
    pytest.mark.nft_readback_e2e,
    pytest.mark.skipif(
        os.environ.get("FERM_NFT_READBACK_E2E") != "1",
        reason="opt-in e2e: run via `nox -s nft_readback_e2e`",
    ),
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="docker is not installed",
    ),
    # The first image build downloads a base image and apk packages,
    # which the global 60s budget cannot absorb.
    pytest.mark.timeout(900),
]


def test_nft_readback_canon() -> None:
    build = subprocess.run(
        ["docker", "build", "-q", "-t", _IMAGE, str(_READBACK_DIR)],
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
            f"{_READBACK_DIR}/driver.py:/work/driver.py:ro",
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
    assert "NFT-READBACK-PASS" in run.stdout, verdict
