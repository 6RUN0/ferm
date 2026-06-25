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
5. the own-table coexistence invariant plus the DROP-policy shift
   witness: a foreign table planted before the apply survives it
   untouched, and both base chains sit on the input hook with foreign's
   priority numerically lower than ferm's.

Prints ``NFT-E2E-PASS`` only after every check has passed.  Stdlib
only: it runs under the container's system ``python3`` with
``PYTHONPATH=/work/src`` and imports nothing from the test deps.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

BASIC = """\
domain ip table filter chain INPUT {
    policy DROP;
    proto tcp dport 22 ACCEPT;
}
"""

#: nft renders the standard filter-hook priorities by their named
#: aliases; resolve them to the integers netfilter uses so the shift
#: witness can compare them numerically.
_PRIORITY_ALIASES = {
    "raw": -300,
    "mangle": -150,
    "dstnat": -100,
    "filter": 0,
    "security": 50,
    "srcnat": 100,
}

#: Matches the base-chain spec line, e.g.
#: ``type filter hook input priority filter;`` or
#: ``... priority -100;``.
_HOOK_RE = re.compile(
    r"type\s+\w+\s+hook\s+(?P<hook>\w+)\s+priority\s+(?P<priority>[\w-]+)\s*;"
)


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


def _input_hook_priority(listing: str) -> int | None:
    """
    Return the numeric priority of the input-hook base chain in a
    ``nft list table`` listing, resolving named aliases, or ``None`` if
    the table has no base chain on the input hook.
    """
    for match in _HOOK_RE.finditer(listing):
        if match.group("hook") != "input":
            continue
        token = match.group("priority")
        if token in _PRIORITY_ALIASES:
            return _PRIORITY_ALIASES[token]
        try:
            return int(token)
        except ValueError:
            return None
    return None


def main() -> int:
    Path("basic.ferm").write_text(BASIC, encoding="utf-8")

    # Plant a foreign table (docker/fail2ban style) BEFORE applying
    # ferm, so we can prove ferm's own-table model leaves it untouched.
    # Its base chain sits at priority -100, ahead of ferm's INPUT.
    for cmd in (
        ("nft", "add", "table", "ip", "foreign"),
        (
            "nft",
            "add",
            "chain",
            "ip",
            "foreign",
            "INPUT",
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "-100",
            ";",
            "}",
        ),
        (
            "nft",
            "add",
            "rule",
            "ip",
            "foreign",
            "INPUT",
            "tcp",
            "dport",
            "12345",
            "accept",
        ),
    ):
        planted = _sh(*cmd)
        if planted.returncode != 0:
            print(f"foreign setup failed: {planted.stderr}", file=sys.stderr)
            return 1

    # Step 1: render the save file without touching the kernel.
    script = _sh(
        "python3",
        "-m",
        "pyferm",
        "--nft",
        "--test",
        "--noexec",
        "--lines",
        "basic.ferm",
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
    ferm_listed = _sh("nft", "list", "table", "ip", "ferm")
    if "tcp dport 22 accept" not in ferm_listed.stdout:
        print(f"rule not in kernel:\n{ferm_listed.stdout}", file=sys.stderr)
        return 1

    # Step 5a: own-table coexistence invariant --
    # ferm owns only `table ip ferm` and never `flush ruleset`, so the
    # foreign table must survive the apply untouched.
    foreign_listed = _sh("nft", "list", "table", "ip", "foreign")
    if "tcp dport 12345 accept" not in foreign_listed.stdout:
        print(
            "CRITICAL: foreign table lost its rule after ferm apply -- "
            f"the own-table invariant is broken:\n{foreign_listed.stdout}",
            file=sys.stderr,
        )
        return 1

    # Step 5b: DROP-policy shift witness.
    # Both tables carry an input-hook base chain; the foreign chain at
    # priority -100 sees packets BEFORE ferm's INPUT at priority 0.
    # This is documented expected behavior, not a regression vs
    # iptables, so assert the ordering positively.
    foreign_priority = _input_hook_priority(foreign_listed.stdout)
    ferm_priority = _input_hook_priority(ferm_listed.stdout)
    if foreign_priority is None or ferm_priority is None:
        print(
            "shift witness: an input-hook base chain is missing "
            f"(foreign={foreign_priority}, ferm={ferm_priority})\n"
            f"foreign:\n{foreign_listed.stdout}\nferm:\n{ferm_listed.stdout}",
            file=sys.stderr,
        )
        return 1
    if not foreign_priority < ferm_priority:
        print(
            "shift witness: foreign priority is not ahead of ferm's "
            f"(foreign={foreign_priority}, ferm={ferm_priority})",
            file=sys.stderr,
        )
        return 1

    print("NFT-E2E-PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
