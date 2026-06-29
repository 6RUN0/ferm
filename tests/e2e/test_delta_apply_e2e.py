"""Opt-in live proof that delta-apply preserves counters and set state.

Requires a real ``nft`` and rootless netns.  NOT in the default suite --
gated behind ``nox -s delta_apply_e2e``.  Each test does ALL its nft work
inside ONE fresh ``unshare -rn`` (per the nft conformance harness): a netns
isolates only the network, so the kernel ruleset never touches the host, yet
the tmp config file stays visible.  Both ``python -m pyferm`` and ``nft`` run
inside that one shell so the snapshot/apply/list sequence shares a ruleset.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def _rootless_netns_works() -> bool:
    """Probe whether ``unshare -rn`` can make a rootless network namespace."""
    if shutil.which("nft") is None or shutil.which("unshare") is None:
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


pytestmark = pytest.mark.skipif(
    os.environ.get("FERM_E2E") != "1" or not _rootless_netns_works(),
    reason="requires nft + rootless userns and FERM_E2E=1"
    " (run via nox -s delta_apply_e2e)",
)

# Minimal config: one rule so the handle-stability tests have something to
# grep for.
_CONFIG = """\
domain ip table filter chain INPUT {
    policy ACCEPT;
    proto tcp dport 80 ACCEPT;
}
"""

# Config with a named set: proves the set object is not destroyed+recreated on
# an empty delta (the set handle must remain stable).
_CONFIG_SET = """\
@set $trusted = (10.0.0.1 10.0.0.2);
domain ip table filter chain INPUT {
    policy ACCEPT;
    proto tcp saddr $trusted ACCEPT;
    proto tcp dport 80 ACCEPT;
}
"""


def _run_in_netns(script: str) -> subprocess.CompletedProcess[str]:
    """Run *script* in a fresh rootless network namespace (bash, fail-fast)."""
    return subprocess.run(
        ["unshare", "-rn", "bash", "-euo", "pipefail", "-c", script],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def test_empty_delta_leaves_rule_handles_unchanged(tmp_path: Path) -> None:
    """An empty delta (unchanged config) does not touch kernel rules.

    pyferm skips ``nft -f`` entirely when ``build_nft_delta`` returns ``""``,
    so rule handles are the same before and after the second apply.  A changed
    handle would mean the rule was flushed and re-added, which resets its
    packet/byte counters.
    """
    ferm_file = tmp_path / "c.ferm"
    ferm_file.write_text(_CONFIG, encoding="utf-8")
    py = sys.executable
    proc = _run_in_netns(
        f"{py} -m pyferm --nft --no-etckeeper {ferm_file}\n"
        "handle1=$(nft --handle list chain ip ferm INPUT"
        " | grep 'dport 80' | grep -oP 'handle \\K[0-9]+')\n"
        '[ -n "$handle1" ] || { echo "handle1 capture failed" >&2; exit 1; }\n'
        f"{py} -m pyferm --nft --no-etckeeper {ferm_file}\n"
        "handle2=$(nft --handle list chain ip ferm INPUT"
        " | grep 'dport 80' | grep -oP 'handle \\K[0-9]+')\n"
        '[ -n "$handle2" ] || { echo "handle2 capture failed" >&2; exit 1; }\n'
        'echo "handle1=$handle1 handle2=$handle2"\n'
        '[ "$handle1" = "$handle2" ]\n'
    )
    assert proc.returncode == 0, proc.stderr
    assert re.search(r"handle1=[0-9]+", proc.stdout), (
        "handle was not captured (grep returned empty)"
    )


def test_full_reload_rebuilds_the_table(tmp_path: Path) -> None:
    """``--full-reload`` tears the whole table down and rebuilds it.

    The full reload emits ``delete table`` + ``add table``, so every object is
    replaced (rule counters are lost).  A rule's handle NUMBER can coincide
    after the rebuild because nft restarts handle numbering for the fresh
    table, so the reliable observable is an out-of-band object injected before
    the
    reload: a user chain ``sentinel`` the config never declares must NOT
    survive.  (``flush table`` would have kept its empty declaration alive, so
    this also guards the leftover-chain fix for non-base chains.)
    """
    ferm_file = tmp_path / "c.ferm"
    ferm_file.write_text(_CONFIG, encoding="utf-8")
    py = sys.executable
    proc = _run_in_netns(
        f"{py} -m pyferm --nft --no-etckeeper {ferm_file}\n"
        # Inject a chain the config does not own.
        "nft add chain ip ferm sentinel\n"
        "nft list chain ip ferm sentinel >/dev/null 2>&1"
        ' || { echo "sentinel not created" >&2; exit 1; }\n'
        f"{py} -m pyferm --nft --no-etckeeper --full-reload {ferm_file}\n"
        "nft list table ip ferm\n"
        # Rebuilt from scratch: the out-of-band chain is gone, config stays.
        "! nft list chain ip ferm sentinel >/dev/null 2>&1\n"
    )
    assert proc.returncode == 0, proc.stderr
    assert "chain sentinel" not in proc.stdout
    assert "dport 80" in proc.stdout  # the config's own rule was re-added


# Two base chains; the FORWARD one (hook forward, policy drop) is dropped in
# the follow-up config to prove a full reload removes it for real.
_CONFIG_TWO_BASE_CHAINS = """\
domain ip table filter {
    chain INPUT {
        policy ACCEPT;
        proto tcp dport 80 ACCEPT;
    }
    chain FORWARD {
        policy DROP;
        proto tcp dport 443 ACCEPT;
    }
}
"""


def test_full_reload_removes_dropped_base_chain(tmp_path: Path) -> None:
    """A base chain removed from config must NOT survive a full reload.

    ``flush table`` empties chains of rules but keeps their declarations, so a
    removed base chain with ``policy drop`` would stay bound to its hook and
    keep dropping all hooked traffic -- a silent lockout the operator believes
    they removed.  The whole-table replace (``delete table; add table``) drops
    the chain for real, matching what ``--plan`` reports.
    """
    full = tmp_path / "full.ferm"
    full.write_text(_CONFIG_TWO_BASE_CHAINS, encoding="utf-8")
    reduced = tmp_path / "reduced.ferm"
    reduced.write_text(_CONFIG, encoding="utf-8")  # INPUT only, no FORWARD
    py = sys.executable
    proc = _run_in_netns(
        f"{py} -m pyferm --nft --no-etckeeper {full}\n"
        # FORWARD base chain must exist after the first apply.
        "nft list chain ip ferm FORWARD >/dev/null 2>&1"
        ' || { echo "FORWARD not created" >&2; exit 1; }\n'
        f"{py} -m pyferm --nft --no-etckeeper --full-reload {reduced}\n"
        "nft list table ip ferm\n"
        # FORWARD must be gone (not merely emptied).
        "! nft list chain ip ferm FORWARD >/dev/null 2>&1\n"
    )
    assert proc.returncode == 0, proc.stderr
    assert "chain FORWARD" not in proc.stdout
    assert "chain INPUT" in proc.stdout  # the surviving chain is still there


def test_delta_preserves_named_set_handle(tmp_path: Path) -> None:
    """A config with a named set produces an empty delta on the second apply.

    ``build_nft_delta`` must parse the set correctly and return ``""`` when
    nothing changed -- proving the set diff path does not falsely trigger a
    full reload or gratuitous churn.  The observable: rule handles are
    unchanged after the second apply (pyferm skipped ``nft -f`` entirely,
    so nothing in the table was touched, including the named set).

    The observable is the dport 80 rule handle: an empty delta skips ``nft -f``
    entirely, so the handle is identical across the two applies.  (Full-reload
    rebuild is covered by :func:`test_full_reload_rebuilds_the_table`; its
    handle would not be a reliable discriminator here because a whole-table
    replace restarts nft handle numbering.)
    """
    ferm_file = tmp_path / "c.ferm"
    ferm_file.write_text(_CONFIG_SET, encoding="utf-8")
    py = sys.executable
    # Use the dport 80 rule handle as the stability probe -- it is present in
    # both _CONFIG and _CONFIG_SET and always gets a non-zero kernel handle.
    proc = _run_in_netns(
        f"{py} -m pyferm --nft --no-etckeeper {ferm_file}\n"
        "rh1=$(nft --handle list chain ip ferm INPUT"
        " | grep 'dport 80' | grep -oP 'handle \\K[0-9]+')\n"
        '[ -n "$rh1" ]'
        ' || { echo "rh1 capture failed" >&2; exit 1; }\n'
        # Second apply: same config, set unchanged -> empty delta.
        f"{py} -m pyferm --nft --no-etckeeper {ferm_file}\n"
        "rh2=$(nft --handle list chain ip ferm INPUT"
        " | grep 'dport 80' | grep -oP 'handle \\K[0-9]+')\n"
        '[ -n "$rh2" ]'
        ' || { echo "rh2 capture failed" >&2; exit 1; }\n'
        'echo "rh1=$rh1 rh2=$rh2"\n'
        # Unchanged: empty delta left the table untouched.
        '[ "$rh1" = "$rh2" ]\n'
    )
    assert proc.returncode == 0, proc.stderr
    assert re.search(r"rh1=[0-9]+", proc.stdout), (
        "rule handle was not captured (grep returned empty)"
    )


def test_nft_delete_of_absent_object_fails_closed(tmp_path: Path) -> None:
    """Back the fail-closed safety claim empirically.

    A delta that adds a rule AND deletes an object removed out-of-band must
    abort the WHOLE transaction (no partial apply): the added rule must not
    survive when the delete fails.  This is the kernel guarantee the delta's
    atomicity rests on.
    """
    setup = tmp_path / "setup.nft"
    setup.write_text(
        "add table ip ferm\n"
        "add chain ip ferm INPUT"
        " { type filter hook input priority 0; policy accept; }\n"
        "add rule ip ferm INPUT tcp dport 22 accept\n",
        encoding="utf-8",
    )
    stale = tmp_path / "stale.nft"
    stale.write_text(
        "add table ip ferm\n"
        "add rule ip ferm INPUT tcp dport 80 accept\n"
        "delete chain ip ferm nonexistent\n",
        encoding="utf-8",
    )
    proc = _run_in_netns(
        f"nft -f {setup}\n"
        f"if nft -f {stale};"
        " then echo DELTA_APPLIED; else echo DELTA_ABORTED; fi\n"
        f"nft list table ip ferm\n"
    )
    assert proc.returncode == 0, proc.stderr  # the if-guard keeps script rc 0
    assert "DELTA_ABORTED" in proc.stdout  # delete of absent object aborted it
    assert "dport 80" not in proc.stdout  # atomic: the add rolled back too
