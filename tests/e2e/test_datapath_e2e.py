"""
Containerized data-plane e2e: real traffic through ferm-installed rules.

Where ``test_nft_e2e.py`` proves the *control plane* (rules land in the
kernel), this proves the *data plane*: an allowed packet passes and a
blocked one is cut, for BOTH ferm backends on the same config (parity).

A single container builds a three-netns topology (client/fw/backend on
veth), applies each scenario config inside ``fw`` per backend, and probes
from ``client`` with ``nmap --reason`` (the response-packet class
distinguishes ACCEPT / DROP / REJECT-reset / REJECT-default) plus
``ncat`` for the stateful echo.

Parity caveat: in bookworm ``iptables`` IS ``iptables-nft``, so both
backends ultimately reach the same nft kernel engine.  This proves "both
ferm backends yield the same datapath on one config", not "two
independent kernel engines agree".  Real legacy xtables is backlog.

Opt-in: ``nox -s datapath_e2e`` (or ``FERM_DATAPATH_E2E=1`` by hand);
skipped otherwise, when docker is absent, and when the driver reports
``DATAPATH-E2E-SKIP:`` (e.g. no conntrack on the host kernel).  The
scenario lives in ``datapath/`` and runs inside the container.

The base image is selectable via ``FERM_DATAPATH_BASE`` (passed to the
Dockerfile's ``BASE`` build ARG); ``FERM_DATAPATH_TAG`` namespaces the
built image so distros don't clobber each other.  See the
``datapath_e2e_matrix`` nox session for the wired distro matrix.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DATAPATH_DIR = Path(__file__).parent / "datapath"
# The image tag is namespaced per distro so a matrix run never clobbers
# another distro's image; the base is the Dockerfile's BASE build ARG.
_TAG = os.environ.get("FERM_DATAPATH_TAG", "default")
_IMAGE = f"ferm-datapath-e2e-{_TAG}"
_BASE = os.environ.get("FERM_DATAPATH_BASE")

pytestmark = [
    pytest.mark.datapath_e2e,
    pytest.mark.skipif(
        os.environ.get("FERM_DATAPATH_E2E") != "1",
        reason="opt-in e2e: run via `nox -s datapath_e2e`",
    ),
    pytest.mark.skipif(
        shutil.which("docker") is None,
        reason="docker is not installed",
    ),
    # First build downloads a base image and apt packages; the global
    # 60s budget cannot absorb it.
    pytest.mark.timeout(900),
]


def test_datapath_through_ferm_rules() -> None:
    build_cmd = ["docker", "build", "-q", "-t", _IMAGE]
    if _BASE:
        build_cmd += ["--build-arg", f"BASE={_BASE}"]
    build_cmd.append(str(_DATAPATH_DIR))
    build = subprocess.run(
        build_cmd,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert build.returncode == 0, f"docker build failed:\n{build.stderr}"

    run_cmd = [
        "docker",
        "run",
        "--rm",
        # NET_ADMIN writes netfilter rules; SYS_ADMIN is the broader
        # grant the driver needs for two things NET_ADMIN cannot do
        # (empirically established 2026-06-15): `ip netns add`
        # (mount --make-shared /run/netns) and `mount -o remount,rw
        # /proc/sys` to lift docker's read-only OCI mount so the fw
        # sysctls can be written.  Narrower than --privileged.
        "--cap-add=NET_ADMIN",
        "--cap-add=SYS_ADMIN",
        "-v",
        f"{_REPO_ROOT}/src:/work/src:ro",
        "-v",
        f"{_DATAPATH_DIR}:/work/datapath:ro",
        "-e",
        "PYTHONPATH=/work/src",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
    ]

    # When the host points FERM_BINARY at an unpacked dist tree, mount it
    # and run the full datapath against the PACKAGED binary instead of the
    # in-tree module (opt-in: proves find_tool + the binary on real
    # traffic).  Absent the var, the run stays on `python3 -m pyferm`.
    host_binary = os.environ.get("FERM_BINARY")
    if host_binary:
        binary_path = Path(host_binary).resolve()
        dist_root = binary_path.parent.parent  # holds the *.dist/ dir
        in_container = (
            f"/work-dist/{binary_path.parent.name}/{binary_path.name}"
        )
        run_cmd += [
            "-v",
            f"{dist_root}:/work-dist:ro",
            "-e",
            f"FERM_BINARY={in_container}",
        ]

    run_cmd += [
        _IMAGE,
        "python3",
        "/work/datapath/driver.py",
    ]
    run = subprocess.run(
        run_cmd,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    verdict = f"driver verdict:\nSTDOUT:\n{run.stdout}\nSTDERR:\n{run.stderr}"

    # SKIP must be checked BEFORE the PASS assertion, else a legitimate
    # capability skip reads as a hard failure.
    if "DATAPATH-E2E-SKIP:" in run.stdout:
        reason = run.stdout.split("DATAPATH-E2E-SKIP:", 1)[1].splitlines()[0]
        pytest.skip(f"driver skipped: {reason}")

    assert run.returncode == 0, verdict
    assert "DATAPATH-E2E-PASS" in run.stdout, verdict
