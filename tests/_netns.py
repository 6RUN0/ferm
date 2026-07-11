"""Shared probe for rootless network-namespace availability (opt-in e2e)."""

from __future__ import annotations

import shutil
import subprocess


def rootless_netns_works() -> bool:
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
