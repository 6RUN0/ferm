"""
In-container driver for the etckeeper integration e2e.

Runs as root inside the throwaway container started by
``tests/e2e/test_etckeeper_e2e.py``.  It proves the full
apply -> commit -> rollback -> re-apply loop against the *real* etckeeper
binary (with its global ``/etc/etckeeper/commit.d`` metadata hooks, which the
host integration test cannot run) and a real nftables kernel:

1. turn ``/etc`` into a git-backed etckeeper repository and commit a baseline;
2. apply a ferm config (state A: accept tcp/22) with the native ``--nft``
   backend and prove the apply auto-committed a semantic message and the
   kernel holds the rule;
3. apply a changed config (state B: accept tcp/8080) and prove the new rule
   replaced the old one and produced a second commit;
4. ``ferm rollback --list`` shows the config's history;
5. ``ferm rollback --to <A>`` reverts ``/etc/ferm`` to state A, re-applies it
   (kernel back to tcp/22, not tcp/8080), and records a "rolled back" commit.

Stdlib-only and standalone on purpose: the container has only a Python
interpreter, nftables, git and etckeeper -- no project dependencies.  ferm is
bind-mounted and run via ``python3 -m pyferm`` (``PYTHONPATH=/work/src``).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import NoReturn

_CONFIG = Path("/etc/ferm/ferm.conf")

#: State A and B differ in a single, greppable rule so the kernel assertions
#: do not depend on counter values or rule ordering.
_CONFIG_A = """\
table filter {
    chain INPUT {
        policy ACCEPT;
        proto tcp dport 22 ACCEPT;
    }
}
"""
_CONFIG_B = """\
table filter {
    chain INPUT {
        policy ACCEPT;
        proto tcp dport 8080 ACCEPT;
    }
}
"""


def _fail(
    message: str, completed: subprocess.CompletedProcess[str]
) -> NoReturn:
    """Abort the driver, dumping the offending command's output."""
    sys.stdout.write(f"ETCKEEPER-E2E-FAIL: {message}\n")
    sys.stdout.write(f"argv: {completed.args}\n")
    sys.stdout.write(f"rc={completed.returncode}\n")
    sys.stdout.write(f"stdout:\n{completed.stdout}\n")
    sys.stdout.write(f"stderr:\n{completed.stderr}\n")
    sys.exit(1)


def _run(
    argv: list[str], *, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a command capturing text output (no shell)."""
    return subprocess.run(
        argv,
        input=stdin,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def _ferm(
    *args: str, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Invoke the bind-mounted ferm via ``python3 -m pyferm``."""
    return _run(["python3", "-m", "pyferm", *args], stdin=stdin)


def _etckeeper_vcs(*args: str) -> str:
    """Return stdout of an ``etckeeper vcs`` read; fail the driver on error."""
    completed = _run(["etckeeper", "vcs", *args])
    if completed.returncode != 0:
        _fail("etckeeper vcs read failed", completed)
    return completed.stdout


def _nft_ruleset() -> str:
    """Return the live nft ruleset text."""
    completed = _run(["nft", "list", "ruleset"])
    if completed.returncode != 0:
        _fail("nft list ruleset failed", completed)
    return completed.stdout


def _init_repo() -> None:
    """Make ``/etc`` a git-backed etckeeper repo with a baseline commit."""
    for key, value in (
        ("user.email", "ferm-e2e@example.invalid"),
        ("user.name", "ferm e2e"),
    ):
        _run(["git", "config", "--global", key, value])
    _run(["git", "config", "--global", "--add", "safe.directory", "/etc"])

    init = _run(["etckeeper", "init"])
    if init.returncode != 0:
        _fail("etckeeper init failed", init)
    baseline = _run(["etckeeper", "commit", "baseline /etc"])
    if baseline.returncode != 0:
        _fail("etckeeper baseline commit failed", baseline)


def _apply(config_text: str, expect_port: str, drop_port: str) -> None:
    """Write ``config_text``, apply it under ``--nft``, assert the kernel."""
    _CONFIG.parent.mkdir(parents=True, exist_ok=True)
    _CONFIG.write_text(config_text, encoding="utf-8")
    applied = _ferm("--nft", str(_CONFIG))
    if applied.returncode != 0:
        _fail(f"ferm apply (port {expect_port}) failed", applied)
    ruleset = _nft_ruleset()
    if f"dport {expect_port}" not in ruleset:
        sys.stdout.write(ruleset)
        _fail(f"kernel missing dport {expect_port} after apply", applied)
    if f"dport {drop_port}" in ruleset:
        sys.stdout.write(ruleset)
        _fail(f"kernel still has dport {drop_port} after apply", applied)


def main() -> int:
    """Drive the apply/commit/rollback/re-apply loop; print the verdict."""
    _init_repo()

    # State A: a committed apply the kernel holds.
    _apply(_CONFIG_A, expect_port="22", drop_port="8080")
    log_a = _etckeeper_vcs("log", "--oneline", "--", "ferm")
    if "ferm: applied" not in log_a:
        _fail(
            "no semantic apply commit recorded",
            subprocess.CompletedProcess(["log"], 0, log_a, ""),
        )
    rev_a = _etckeeper_vcs(
        "log", "--format=%H", "-n", "1", "--", "ferm"
    ).strip()

    # State B: a second committed apply that replaced the rule.
    _apply(_CONFIG_B, expect_port="8080", drop_port="22")

    # rollback --list shows the config history (read-only).
    listing = _ferm("rollback", "--list")
    if listing.returncode != 0 or "ferm: applied" not in listing.stdout:
        _fail("rollback --list did not show history", listing)

    # rollback --to A reverts /etc/ferm and re-applies (kernel back to 22).
    rolled = _ferm("rollback", "--to", rev_a, "--nft")
    if rolled.returncode != 0:
        _fail("rollback --to failed", rolled)
    if _CONFIG.read_text(encoding="utf-8") != _CONFIG_A:
        _fail("config not reverted to state A", rolled)
    ruleset = _nft_ruleset()
    if "dport 22" not in ruleset or "dport 8080" in ruleset:
        sys.stdout.write(ruleset)
        _fail("kernel not re-applied to state A after rollback", rolled)
    log_after = _etckeeper_vcs("log", "--oneline", "--", "ferm")
    if "rolled back to" not in log_after:
        _fail(
            "rollback re-apply not recorded as a commit",
            subprocess.CompletedProcess(["log"], 0, log_after, ""),
        )

    sys.stdout.write("ETCKEEPER-E2E-PASS\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
