"""
Containerized e2e proof of the ``--nft`` backend against a real kernel.

This is the semantic/kernel-validation layer for the native nftables
backend.  It proves three things the text golden harness cannot:

* the rendered ``--nft`` save file is accepted by a real netfilter --
  ``nft -c -f -`` checks it against netlink (needs ``CAP_NET_ADMIN``),
  and a real apply lands rules the kernel actually holds;
* the own-table coexistence invariant (design section 6): ferm owns
  only ``table ip ferm`` and never ``flush ruleset``, so a foreign
  table planted before the apply (docker/fail2ban style) survives it
  untouched;
* the DROP-policy shift witness (design sections 6 / 10.3): both base
  chains sit on the input hook, the foreign one at a numerically lower
  priority than ferm's, which is documented expected behavior, not a
  regression.

Netfilter is a namespaced subsystem of the shared kernel, so a
container with ``CAP_NET_ADMIN`` exercises exactly the code a bare host
would -- and the throwaway network namespace keeps it safe.

Opt-in: ``nox -s nft_e2e`` (or ``FERM_NFT_E2E=1`` by hand); skipped
otherwise, and whenever docker is unavailable.  The scenario itself
lives in ``nft/driver.py``, which runs inside the container.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_NFT_DIR = Path(__file__).parent / "nft"
_IMAGE = "ferm-nft-e2e"

pytestmark = [
    pytest.mark.nft_e2e,
    pytest.mark.skipif(
        os.environ.get("FERM_NFT_E2E") != "1",
        reason="opt-in e2e: run via `nox -s nft_e2e`",
    ),
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="docker is not installed",
    ),
    # The first image build downloads a base image and apt packages,
    # which the global 60s budget cannot absorb.
    pytest.mark.timeout(900),
]


def test_nft_round_trip_and_coexistence() -> None:
    build = subprocess.run(
        ["docker", "build", "-q", "-t", _IMAGE, str(_NFT_DIR)],
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
            f"{_NFT_DIR}/driver.py:/work/driver.py:ro",
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
    assert "NFT-E2E-PASS" in run.stdout, verdict
