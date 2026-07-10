"""
Real-packet calibration of the recent token-bucket vs xt_recent.

The nft backend approximates xt_recent's sliding window as a token bucket:
every update-rule of a name emits the identical calibrated element spec
``{ key timeout S limit rate over R burst B packets }`` with
``R = T*H/S`` (integer-reduced) and ``B = T*H - 1``, ``T`` the number of
update-rules touching the name.  This suite is the executable evidence
that the calibration matches real xt_recent (the 2026-07-10 pin): it drives
ICMP echo-request through the emitted nft form inside a rootless netns and
checks the first DROP lands in the jitter window ``[H-1, H+1]``.

Both corpus structures are covered: chain-maze (a check rule first, a bare
``set`` second) and stuart-ha-server (a bare ``set`` first, a check rule
second) -- the uniform element spec is what makes the set-first order safe.

Opt-in and kept out of ``uv run nox``/``preflight``: it is time-dependent
(token refill), so it is evidence, not a regression gate.  Run it by hand
with ``FERM_RECENT_CAL_E2E=1`` (needs ``unshare -rn``, ``nft`` and
``ping``).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

pytestmark = [
    pytest.mark.recent_calibration_e2e,
    pytest.mark.skipif(
        os.environ.get("FERM_RECENT_CAL_E2E") != "1",
        reason="opt-in e2e: set FERM_RECENT_CAL_E2E=1",
    ),
    pytest.mark.skipif(
        shutil.which("unshare") is None
        or shutil.which("nft") is None
        or shutil.which("ping") is None,
        reason="needs unshare, nft and ping",
    ),
    pytest.mark.timeout(120),
]

# Each scenario: the emitted uniform element spec, the two update rules in
# corpus order, the hitcount H, and how many probes to send (H + slack).
_MAZE_SPEC = "{ ip saddr timeout 1m limit rate over 8/minute burst 7 packets }"
_STUART_SPEC = (
    "{ ip saddr timeout 5m limit rate over 192/hour burst 15 packets }"
)
_SCENARIOS = {
    # chain-maze: check rule FIRST (drop), bare set SECOND (no verdict).
    "maze": (
        f"icmp type echo-request update @r {_MAZE_SPEC} drop\n"
        f"    icmp type echo-request update @r {_MAZE_SPEC}\n",
        4,
        8,
    ),
    # stuart-ha-server: bare set FIRST (no verdict), check rule SECOND (drop).
    "stuart": (
        f"icmp type echo-request update @r {_STUART_SPEC}\n"
        f"    icmp type echo-request update @r {_STUART_SPEC} drop\n",
        8,
        12,
    ),
}


def _ruleset(rules: str) -> str:
    return (
        "table ip cal {\n"
        "  set r { type ipv4_addr; size 65535; flags dynamic,timeout; }\n"
        "  chain inp {\n"
        "    type filter hook input priority 0; policy accept;\n"
        f"    {rules}"
        "  }\n"
        "}\n"
    )


def _first_drop(scenario: str) -> int | None:
    rules, _hitcount, probes = _SCENARIOS[scenario]
    # ping reports OK when the echo returns, DROP when the input hook cuts it;
    # send them back-to-back so token refill stays negligible.
    prober = "".join(
        "if ping -q -c 1 -W 0.3 127.0.0.1 >/dev/null 2>&1; "
        f'then echo "pkt {i} OK"; else echo "pkt {i} DROP"; fi\n'
        for i in range(1, probes + 1)
    )
    inner = (
        f"ip link set lo up\nnft -f - <<'EOF'\n{_ruleset(rules)}EOF\n{prober}"
    )
    proc = subprocess.run(
        ["unshare", "-rn", "sh", "-c", inner],
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=90,
    )
    assert proc.returncode == 0, proc.stderr
    for line in proc.stdout.splitlines():
        match = re.match(r"pkt (\d+) DROP", line)
        if match:
            return int(match.group(1))
    return None


@pytest.mark.parametrize("scenario", ["maze", "stuart"])
def test_recent_first_drop_within_jitter_window(scenario: str) -> None:
    hitcount = _SCENARIOS[scenario][1]
    first_drop = _first_drop(scenario)
    assert first_drop is not None, f"{scenario}: no packet was dropped"
    assert hitcount - 1 <= first_drop <= hitcount + 1, (
        f"{scenario}: first drop at packet {first_drop}, "
        f"outside [{hitcount - 1}, {hitcount + 1}]"
    )
