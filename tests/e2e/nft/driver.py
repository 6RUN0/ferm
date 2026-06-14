"""
Scenario for the nft backend e2e -- runs INSIDE the container.

The container has ``CAP_NET_ADMIN`` and a throwaway network namespace,
so the rules this applies touch a real kernel netfilter without any
risk to the host.  The five logical steps:

1. render the ferm config with ``--nft --test --noexec --lines``;
2. ``nft -c -f -`` -- a SEMANTIC check against netlink (needs
   CAP_NET_ADMIN, which is exactly why this lives in the container and
   not in preflight);
3. real apply via ``python3 -m pyferm --nft basic.ferm``;
4. ``nft list table ip ferm`` proves the kernel really accepted it;
5. the own-table coexistence invariant (added in Task 19).

Prints ``NFT-E2E-PASS`` only after every check has passed.  Stdlib
only: it runs under the container's system ``python3`` with
``PYTHONPATH=/work/src`` and imports nothing from the test deps.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BASIC = """\
domain ip table filter chain INPUT {
    policy DROP;
    proto tcp dport 22 ACCEPT;
}
"""


def _sh(
    *cmd: str, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def main() -> int:
    Path("basic.ferm").write_text(BASIC, encoding="utf-8")

    # Step 1: render the save file without touching the kernel.
    script = _sh(
        "python3", "-m", "pyferm", "--nft", "--test", "--noexec",
        "--lines", "basic.ferm",
    )
    if script.returncode != 0:
        print(f"render failed: {script.stderr}", file=sys.stderr)
        return 1

    # Step 2: semantic validation of the rendered ruleset against netlink.
    check = _sh("nft", "-c", "-f", "-", input_text=script.stdout)
    if check.returncode != 0:
        print(f"nft -c rejected: {check.stderr}", file=sys.stderr)
        return 1

    # Step 3: real apply -- no --nolegacy needed, the nft tool name does
    # not match the legacy regex.
    apply_ = _sh("python3", "-m", "pyferm", "--nft", "basic.ferm")
    if apply_.returncode != 0:
        print(f"apply failed: {apply_.stderr}", file=sys.stderr)
        return 1

    # Step 4: prove the kernel really holds the rule.
    listed = _sh("nft", "list", "table", "ip", "ferm")
    if "tcp dport 22 accept" not in listed.stdout:
        print(f"rule not in kernel:\n{listed.stdout}", file=sys.stderr)
        return 1

    # Step 5: own-table coexistence invariant -- added in Task 19.

    print("NFT-E2E-PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
