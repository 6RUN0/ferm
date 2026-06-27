"""
Scenario for the docker-coexistence e2e -- runs INSIDE the dind container.

The container is docker-in-docker: a real docker 29 engine with the
native nftables firewall backend.  Unlike ``nft/driver.py`` -- which
hand-plants a foreign table to *stand in* for docker -- this proves the
own-table coexistence invariant against the genuine ``docker-bridges``
tables a live engine creates, and it pins down the empirical fact that
motivates the base-chain priority knob: docker's forward base chain sits
on ``priority filter`` (0), the same slot as ferm's default forward
chain.

The logical steps:

1. start the inner ``dockerd --firewall-backend=nftables`` and wait for it;
2. ``docker network create`` so the engine materializes its
   ``ip``/``ip6 docker-bridges`` tables with a forward base chain;
3. snapshot those tables;
4. apply a ferm ``--nft`` config (its own ``table ip ferm``) -- and then
   apply it a SECOND time to model ``ferm reload``;
5. assert the docker tables are byte-for-byte unchanged after both
   applies (ferm never ``flush ruleset``, so a reload cannot clobber
   docker -- the original operational pain this proves away);
6. assert ferm's own table really landed in the kernel;
7. witness the priorities: docker's forward chain is at ``filter`` (0),
   equal to ferm's default forward chain -- which is why deterministic
   ordering needs the priority knob;
8. apply the priority knob (``priority -1``) and prove ferm's forward chain
   moves ahead of docker's while docker's tables stay put;
9. re-apply the same priority config and assert ferm's table is unchanged --
   the kernel's offset display (``filter - 1``) canonicalizes back to -1, so
   an unchanged reload triggers no spurious rebuild (no counter reset).

Prints ``DOCKER-COEXIST-PASS`` only after every check has passed.
Stdlib only: runs under the container's system ``python3`` with
``PYTHONPATH=/work/src``.
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

#: ferm config: a forward base chain in ``table ip filter`` -> renders to
#: ``table ip ferm`` with a forward hook at the default priority 0, the
#: same slot docker's forward chain occupies.
FERM_CONFIG = """\
domain ip table filter chain FORWARD {
    policy ACCEPT;
    saddr 10.99.0.0/16 DROP;
}
"""

#: Same chain with the base-chain priority knob: -1 puts ferm's forward
#: chain ahead of docker's (which sits at priority filter = 0).
FERM_CONFIG_PRIO = """\
domain ip table filter chain FORWARD priority -1 {
    policy ACCEPT;
    saddr 10.99.0.0/16 DROP;
}
"""

#: nft prints filter-hook priorities by their named aliases; resolve them
#: to the integers netfilter uses so the witness can compare numerically.
_PRIORITY_ALIASES = {
    "raw": -300,
    "mangle": -150,
    "dstnat": -100,
    "filter": 0,
    "security": 50,
    "srcnat": 100,
}

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


def _hook_priority(listing: str, hook: str) -> int | None:
    """Numeric priority of the named-hook base chain, or ``None``."""
    for match in _HOOK_RE.finditer(listing):
        if match.group("hook") != hook:
            continue
        token = match.group("priority")
        if token in _PRIORITY_ALIASES:
            return _PRIORITY_ALIASES[token]
        try:
            return int(token)
        except ValueError:
            return None
    return None


def _start_dockerd() -> subprocess.Popen[bytes] | None:
    """Start the inner dockerd with the nft backend; wait until ready."""
    log = Path("/work/dockerd.log").open("wb")  # noqa: SIM115
    proc = subprocess.Popen(
        ["dockerd-entrypoint.sh", "--firewall-backend=nftables"],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    for _ in range(60):
        if proc.poll() is not None:
            return None  # dockerd died on startup
        if _sh("docker", "info").returncode == 0:
            return proc
        time.sleep(1)
    return None


def _docker_tables(family: str) -> str:
    """Listing of ``table <family> docker-bridges`` (empty if absent)."""
    listed = _sh("nft", "list", "table", family, "docker-bridges")
    return listed.stdout if listed.returncode == 0 else ""


def main() -> int:
    dockerd = _start_dockerd()
    if dockerd is None:
        log = Path("/work/dockerd.log")
        tail = log.read_text(encoding="utf-8")[-2000:] if log.exists() else ""
        print(f"inner dockerd never became ready:\n{tail}", file=sys.stderr)
        return 1

    backend = _sh("docker", "info", "--format", "{{.FirewallBackend.Driver}}")
    if backend.stdout.strip() != "nftables":
        print(
            f"inner docker not on nft backend: {backend.stdout!r}",
            file=sys.stderr,
        )
        return 1

    # Step 2: make the engine materialize its docker-bridges tables.
    created = _sh("docker", "network", "create", "probe")
    if created.returncode != 0:
        print(
            f"docker network create failed: {created.stderr}",
            file=sys.stderr,
        )
        return 1

    # Step 3: snapshot docker's tables BEFORE ferm touches anything.
    before_v4 = _docker_tables("ip")
    before_v6 = _docker_tables("ip6")
    # Non-vacuity guard: the whole test is meaningless if docker did not
    # actually create its forward chain.
    if "hook forward" not in before_v4:
        print(
            f"docker did not create an ip forward chain:\n{before_v4}",
            file=sys.stderr,
        )
        return 1

    docker_forward = _hook_priority(before_v4, "forward")
    if docker_forward != 0:
        print(
            f"unexpected docker forward priority: {docker_forward} "
            "(expected 0 / `filter`)",
            file=sys.stderr,
        )
        return 1

    Path("forward.ferm").write_text(FERM_CONFIG, encoding="utf-8")

    # Step 4: apply ferm twice -- the second apply models `ferm reload`.
    for label in ("apply", "reload"):
        applied = _sh("python3", "-m", "pyferm", "--nft", "forward.ferm")
        if applied.returncode != 0:
            print(f"ferm {label} failed: {applied.stderr}", file=sys.stderr)
            return 1

        # Step 5: docker's tables must survive each apply untouched.
        after_v4 = _docker_tables("ip")
        after_v6 = _docker_tables("ip6")
        if after_v4 != before_v4 or after_v6 != before_v6:
            print(
                f"CRITICAL: docker-bridges changed after ferm {label} -- "
                "the own-table coexistence invariant is broken",
                file=sys.stderr,
            )
            return 1

    # Step 6: prove ferm's own table really landed.
    ferm_listed = _sh("nft", "list", "table", "ip", "ferm")
    if "ip saddr 10.99.0.0/16 drop" not in ferm_listed.stdout:
        print(
            f"ferm rule not in kernel:\n{ferm_listed.stdout}",
            file=sys.stderr,
        )
        return 1

    # Step 7: witness the equal-priority collision that motivates the knob.
    ferm_forward = _hook_priority(ferm_listed.stdout, "forward")
    if ferm_forward != 0:
        print(
            f"unexpected ferm forward priority: {ferm_forward}",
            file=sys.stderr,
        )
        return 1

    print(
        "witness: docker forward priority=0 (filter) == ferm forward "
        "priority=0 -- deterministic ordering needs the priority knob"
    )

    # Step 8: apply the priority knob -- move ferm's forward chain ahead of
    # docker's (to priority -1) and prove it lands while docker stays put.
    Path("forward_prio.ferm").write_text(FERM_CONFIG_PRIO, encoding="utf-8")
    knob = _sh("python3", "-m", "pyferm", "--nft", "forward_prio.ferm")
    if knob.returncode != 0:
        print(f"priority-knob apply failed: {knob.stderr}", file=sys.stderr)
        return 1

    # nft displays -1 as the offset 'filter - 1' (filter = 0).  Either form
    # is acceptable evidence the override landed.
    ferm_prio = _sh("nft", "list", "table", "ip", "ferm").stdout
    moved = "priority filter - 1" in ferm_prio or "priority -1" in ferm_prio
    if not moved:
        print(
            f"priority knob did not move ferm forward to -1:\n{ferm_prio}",
            file=sys.stderr,
        )
        return 1
    if _docker_tables("ip") != before_v4 or _docker_tables("ip6") != before_v6:
        print(
            "CRITICAL: docker-bridges changed after the priority-knob apply",
            file=sys.stderr,
        )
        return 1

    print(
        "knob: ferm forward moved to priority -1 (ahead of docker's 0); "
        "docker-bridges untouched"
    )

    # Step 9: re-apply the SAME priority config (models another `ferm reload`).
    # The kernel displays -1 as the offset 'filter - 1'; the delta must
    # canonicalize that back to -1 and produce NO change, so ferm's own table
    # is byte-for-byte identical -- proving the offset form does not trigger a
    # spurious chain rebuild (which would reset the chain's counters).
    reknob = _sh("python3", "-m", "pyferm", "--nft", "forward_prio.ferm")
    if reknob.returncode != 0:
        print(f"priority-knob reload failed: {reknob.stderr}", file=sys.stderr)
        return 1
    ferm_prio_reload = _sh("nft", "list", "table", "ip", "ferm").stdout
    if ferm_prio_reload != ferm_prio:
        print(
            "CRITICAL: ferm table changed on an unchanged priority reload -- "
            f"spurious rebuild (counters reset):\n{ferm_prio_reload}",
            file=sys.stderr,
        )
        return 1

    print(
        "idempotent: re-applying priority -1 left ferm's table unchanged "
        "(offset-form 'filter - 1' canonicalizes back to -1; no rebuild)"
    )
    print("DOCKER-COEXIST-PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
