"""
Opt-in real-nft proof that ``--plan --nft`` pre-validates with ``nft -c``.

Runs ``ferm --plan --nft`` in real mode (NOT ``--test``) inside a rootless
network namespace (``unshare -rn``, no docker) and asserts:

* an ``arp`` chain carrying a ``tcp`` match -- which nft rejects with
  "conflicting protocols" -- aborts the plan with exit 1 and surfaces nft's
  own diagnostic, instead of advertising an un-appliable change as actionable;
* a valid arp rule still produces a normal plan (exit 2).

The text golden harness runs under ``--test`` (a fake nft), so it cannot
exercise the gate; this is the only layer that proves the real ``nft -c``
validation fires.

Opt-in: ``nox -s nft_e2e`` (or ``FERM_NFT_E2E=1`` by hand); skipped when nft
or unshare are unavailable, or rootless user namespaces are disabled.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SRC = _REPO_ROOT / "src"
_OPT_IN = os.environ.get("FERM_NFT_E2E") == "1"


def _rootless_netns_works() -> bool:
    """Probe whether ``unshare -rn`` can make a rootless network namespace."""
    if shutil.which("unshare") is None:
        return False
    try:
        probe = subprocess.run(
            ["unshare", "-rn", "true"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


# Short-circuit on `_OPT_IN` so the probe subprocess never runs during an
# ordinary (non-opt-in) collection.
_NETNS_OK = _OPT_IN and _rootless_netns_works()

pytestmark = [
    pytest.mark.nft_e2e,
    pytest.mark.skipif(
        not _OPT_IN, reason="opt-in e2e: run via `nox -s nft_e2e`"
    ),
    pytest.mark.skipif(
        shutil.which("nft") is None, reason="nft not installed"
    ),
    pytest.mark.skipif(
        not _NETNS_OK, reason="rootless network namespace unavailable"
    ),
    pytest.mark.timeout(60),
]


def _run_plan(config: str) -> subprocess.CompletedProcess[str]:
    """Run real ``ferm --plan --nft`` on *config* inside a fresh netns."""
    return subprocess.run(
        [
            "unshare",
            "-rn",
            sys.executable,
            "-m",
            "pyferm",
            "--plan",
            "--nft",
            "-",
        ],
        input=config,
        capture_output=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONPATH": str(_SRC)},
        check=False,
    )


def test_plan_nft_rejects_unappliable_arp_tcp() -> None:
    proc = _run_plan(
        "domain arp table filter chain INPUT {\n"
        "    policy ACCEPT;\n"
        "    proto tcp dport 22 ACCEPT;\n"
        "}\n"
    )
    assert proc.returncode == 1, (
        f"expected exit 1, got {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    )
    assert "conflicting protocols" in proc.stderr, proc.stderr


def test_plan_nft_accepts_valid_arp_rule() -> None:
    proc = _run_plan(
        "domain arp table filter chain INPUT {\n"
        "    policy ACCEPT;\n"
        "    ACCEPT;\n"
        "}\n"
    )
    assert proc.returncode == 2, (
        f"expected exit 2 (changes), got {proc.returncode}\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
    assert "family arp" in proc.stdout, proc.stdout
