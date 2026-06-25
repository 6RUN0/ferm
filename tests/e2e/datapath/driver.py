"""
Datapath e2e driver -- runs INSIDE the container (root, NET_ADMIN+SYS_ADMIN).

Builds the client/fw/backend netns fixture once, then for every scenario
and backend: tears rules down (asserting an empty ruleset), applies the
ferm config in ``fw`` for real (no ``--test``), and probes the data plane
from ``client`` with ``nmap --reason`` / ``ncat``.  Both ferm backends
run the same config (parity).

Marker protocol (contract with pytest):
  * ``DATAPATH-E2E-PASS``  -- every scenario x backend was green;
  * ``DATAPATH-E2E-SKIP:<reason>`` + exit 0 -- a capability is missing
    (e.g. no conntrack); printed BEFORE any scenario runs;
  * any FAIL -> non-zero exit, no PASS marker, diagnostics on stderr.

Stdlib only; imports its siblings (oracle/scenarios/netns) because the
whole ``datapath/`` directory is bind-mounted and on ``sys.path[0]``.
"""

from __future__ import annotations

import os
import pty
import re
import select
import subprocess
import sys
import time
from pathlib import Path

import netns
import scenarios
from oracle import Probe, parse_reason, run_nmap_probe

_ESTAB_NONCE = "DATAPATH-ESTAB-OK"


def _ferm_cmd(prefix: list[str]) -> list[str]:
    """
    Build the ferm invocation for ``prefix``.

    With ``FERM_BINARY`` set the packaged binary is invoked directly (the
    gate that proves the shipped artifact); otherwise the in-tree module is
    run via ``python3 -m pyferm``.
    """
    binary = os.environ.get("FERM_BINARY")
    if binary:
        return [*prefix, binary]
    return [*prefix, "python3", "-m", "pyferm"]


def _apply_config(
    cfg_path: str, backend: str
) -> subprocess.CompletedProcess[str]:
    cmd = _ferm_cmd(["ip", "netns", "exec", "fw"])
    if backend == "nft":
        cmd.append("--nft")
    else:
        # The default backend's find_tool prefers *-legacy binaries,
        # which exist in bookworm-slim but have no kernel xtables here;
        # --nolegacy forces the working iptables-nft path.
        cmd.append("--nolegacy")
    cmd.append(cfg_path)
    return subprocess.run(
        cmd, capture_output=True, encoding="utf-8", check=False
    )


def _probe_reason(probe: Probe) -> tuple[str | None, str, str]:
    """
    Return ``(reason, raw_xml, stderr)``.

    The raw XML + stderr are kept so a FAIL can attach them: without the
    XML a ``got None`` is ambiguous between "nmap reported a different
    reason", "nmap timed out", and "nmap errored" -- so the raw
    ``nmap -oX`` is kept in diagnostics for exactly this reason.
    """
    nmap_xml, stderr = run_nmap_probe(probe)
    return parse_reason(nmap_xml, probe.port, probe.proto), nmap_xml, stderr


def _run_established_check(check: dict) -> bool:
    proc = subprocess.run(
        [
            "ip",
            "netns",
            "exec",
            check["from_netns"],
            "ncat",
            "-w",
            str(check["timeout_s"]),
            check["to_addr"],
            str(check["port"]),
        ],
        input=_ESTAB_NONCE + "\n",
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    return proc.returncode == 0 and _ESTAB_NONCE in proc.stdout


def _run_control(
    scenario: dict, backend: str, listeners: netns.Listeners
) -> list[str]:
    """Stop a listener, assert the control reason, restart it."""
    control = scenario["control"]
    fails: list[str] = []
    # terminate()+wait(): socket gone synchronously
    listeners.stop(control["stop_listener"])
    time.sleep(0.5)  # let the kernel finish tearing the socket down
    probe: Probe = control["probe"]
    got, raw_xml, raw_err = _probe_reason(probe)
    if got != probe.expected_reason:
        fails.append(
            f"[{scenario['name']}][{backend}] control"
            f" {probe.proto}/{probe.port} "
            f"expected {probe.expected_reason} got {got}\n"
            f"--- raw nmap -oX ---\n{raw_xml}\n"
            f"--- nmap stderr ---\n{raw_err}"
        )
    listeners.start(control["stop_listener"])
    # Re-assert the restarted listener is bound before any later scenario
    # can depend on it -- no fixed sleep, no hidden ordering contract.
    listeners.assert_live([control["stop_listener"]])
    return fails


def _run_scenario(
    scenario: dict, backend: str, listeners: netns.Listeners
) -> list[str]:
    name = scenario["name"]
    fails: list[str] = []

    netns.teardown_rules()
    empty, residue = netns.ruleset_empty()
    if not empty:
        fails.append(
            f"[{name}][{backend}] teardown left ruleset non-empty:\n{residue}"
        )

    cfg_path = f"/tmp/{name}.ferm"
    Path(cfg_path).write_text(scenario["config"], encoding="utf-8")
    applied = _apply_config(cfg_path, backend)
    if applied.returncode != 0:
        fails.append(f"[{name}][{backend}] apply failed: {applied.stderr}")
        netns.dump_diagnostics(f"{name}/{backend}")
        return fails  # nothing to probe against a failed apply

    if scenario["type"] == "stateful" and not _run_established_check(
        scenario["established_check"]
    ):
        fails.append(f"[{name}][{backend}] established_check failed")
        netns.dump_diagnostics(f"{name}/{backend}")

    for probe in scenario["probes"]:
        got, raw_xml, raw_err = _probe_reason(probe)
        if got != probe.expected_reason:
            fails.append(
                f"[{name}][{backend}] {probe.proto}/{probe.port} "
                f"expected {probe.expected_reason} got {got}\n"
                f"--- raw nmap -oX ---\n{raw_xml}\n"
                f"--- nmap stderr ---\n{raw_err}"
            )
            netns.dump_diagnostics(f"{name}/{backend}")

    if scenario.get("control"):
        fails += _run_control(scenario, backend, listeners)

    return fails


# The interactive scenario (selected via DATAPATH_SCENARIO=interactive) is
# the only path that enters signal.alarm + the function-local `import
# termios`. It runs the binary under --interactive with a short --timeout
# and never confirms, so the timeout fires and ferm rolls back. The marker
# is emitted by THIS driver, never by the binary: a silent
# --include-module=termios no-op would surface as a ModuleNotFoundError on
# stderr here instead of failing on the most dangerous (lockout) path.

_INTERACTIVE_CONFIG = """\
table filter {
    chain INPUT policy DROP;
}
"""

_INTERACTIVE_TIMEOUT = 5
_PROMPT = b"Please type 'yes' to confirm:"
_ROLLED_BACK = b"Firewall rules rolled back."
_MISSING_MODULE_RE = re.compile(
    rb"ModuleNotFoundError|No module named '(?:termios|signal)'"
)


def _read_until(
    master: int, needle: bytes, buf: bytearray, deadline: float
) -> bool:
    """Drain the pty master until ``needle`` shows up or time runs out."""
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.5)
        if not ready:
            continue
        try:
            chunk = os.read(master, 4096)
        except OSError:
            # EIO: the child closed its pty side (it exited).
            break
        if not chunk:
            break
        buf.extend(chunk)
        if needle in buf:
            return True
    return needle in buf


def _run_interactive() -> int:
    """
    Exercise --interactive confirm/timeout against the binary; print the
    marker only when the timeout+rollback path ran with no missing module.
    """
    config = Path("/tmp/interactive.ferm")
    config.write_text(_INTERACTIVE_CONFIG, encoding="utf-8")

    # A pty stands in for the locked-out admin's tty: ferm prompts and the
    # prompt is never answered, so --timeout has to drive the rollback.
    master, slave = pty.openpty()
    cmd = _ferm_cmd([])
    cmd += [
        "--interactive",
        "--timeout",
        str(_INTERACTIVE_TIMEOUT),
        "--nolegacy",
        str(config),
    ]
    ferm = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    output = bytearray()

    try:
        if not _read_until(master, _PROMPT, output, time.monotonic() + 30):
            print(
                f"FAIL no confirmation prompt; ferm said: {bytes(output)!r}",
                file=sys.stderr,
            )
            return 1
        if not _read_until(
            master, _ROLLED_BACK, output, time.monotonic() + 30
        ):
            print(
                f"FAIL no rollback message; ferm said: {bytes(output)!r}",
                file=sys.stderr,
            )
            return 1
        status = ferm.wait(timeout=30)
    finally:
        if ferm.poll() is None:
            ferm.kill()
        os.close(master)

    if _MISSING_MODULE_RE.search(output):
        print(
            f"FAIL include-flag no-op -- missing module: {bytes(output)!r}",
            file=sys.stderr,
        )
        return 1
    if status != 1:
        print(
            f"FAIL ferm exited {status}, expected 1 (rollback path)",
            file=sys.stderr,
        )
        return 1

    print("INTERACTIVE-ROLLBACK-OK")
    return 0


def main() -> int:
    if os.environ.get("DATAPATH_SCENARIO") == "interactive":
        return _run_interactive()

    if not netns.conntrack_available():
        print("DATAPATH-E2E-SKIP:conntrack")
        return 0

    netns.remount_proc_sys()
    netns.build_topology()
    netns.set_sysctls()

    listeners = netns.Listeners()
    listeners.start_all()

    failures: list[str] = []
    try:
        # assert_live polls with retries, so no fixed startup sleep is
        # needed -- it waits for each listener to actually bind.
        listeners.assert_live()
        for scenario in scenarios.SCENARIOS:
            for backend in scenario["backends"]:
                failures += _run_scenario(scenario, backend, listeners)
    finally:
        listeners.stop_all()
        netns.destroy_topology()

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        return 1

    print("DATAPATH-E2E-PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
