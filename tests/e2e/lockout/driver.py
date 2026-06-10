"""
In-container driver for the ``--interactive`` lockout e2e test.

Runs as root inside the throwaway container started by
``tests/e2e/test_lockout.py`` (see there for the scenario rationale).
It proves the anti-lockout safety net end to end against a real kernel:

1. seed a recognizable baseline ruleset and snapshot it;
2. establish a TCP connection over loopback and prove it works;
3. run ``ferm --interactive`` with a config that sets ``INPUT`` policy
   ``DROP`` and never answer the confirmation prompt (a locked-out
   admin cannot type -- their SSH session hangs without dying, exactly
   like a pty nobody writes to);
4. assert the connection froze, ferm rolled back after ``--timeout``
   seconds and exited 1, the kernel ruleset is byte-identical to the
   baseline, and the frozen connection came back to life through TCP
   retransmission.

Stdlib-only and standalone on purpose: the container has no project
dependencies, just a Python interpreter and iptables.
"""

from __future__ import annotations

import os
import pty
import re
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import NoReturn

#: Plain (alternatives-resolved, nft-backed) binaries: the test host
#: kernel has no legacy x_tables modules, which is also why ferm runs
#: with ``--nolegacy`` below.
IPTABLES_SAVE = "iptables-save"
IPTABLES_RESTORE = "iptables-restore"

ECHO_PORT = 12747

#: A rule that survives only if rollback truly restores the previous
#: ruleset (ferm's DROP config flushes it away).  192.0.2.1 is TEST-NET.
MARKER_RULE = "-A INPUT -s 192.0.2.1/32 -j ACCEPT"

BASELINE = f"""\
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
{MARKER_RULE}
COMMIT
"""

#: ``INPUT`` policy ``DROP`` with no exceptions cuts every inbound
#: packet, loopback included -- the lockout.
LOCKOUT_CONFIG = """\
table filter {
    chain INPUT policy DROP;
}
"""

FERM_TIMEOUT = 5
PROMPT = b"Please type 'yes' to confirm:"
ROLLED_BACK = b"Firewall rules rolled back."

_COUNTERS_RE = re.compile(r"\[\d+:\d+\]")


def _fail(message: str) -> NoReturn:
    print(f"LOCKOUT-E2E-FAIL: {message}", flush=True)
    raise SystemExit(1)


def _step(message: str) -> None:
    print(f"lockout-e2e: {message}", flush=True)


def _snapshot() -> list[str]:
    """Kernel ruleset canonicalized: no comment lines, zeroed counters."""
    save = subprocess.run(
        [IPTABLES_SAVE], capture_output=True, text=True, check=True
    )
    return [
        _COUNTERS_RE.sub("[0:0]", line)
        for line in save.stdout.splitlines()
        if not line.startswith("#")
    ]


def _serve_echo(listener: socket.socket) -> None:
    conn, _addr = listener.accept()
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(data)


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
            # EIO: the child closed its side of the pty (it exited).
            break
        if not chunk:
            break
        buf.extend(chunk)
        if needle in buf:
            return True
    return needle in buf


def main() -> int:
    _step("seeding the baseline ruleset")
    subprocess.run([IPTABLES_RESTORE], input=BASELINE.encode(), check=True)
    before = _snapshot()
    if MARKER_RULE not in before:
        _fail(f"marker rule missing from the baseline snapshot: {before}")

    _step("establishing a loopback TCP connection")
    listener = socket.create_server(("127.0.0.1", ECHO_PORT))
    threading.Thread(target=_serve_echo, args=(listener,), daemon=True).start()
    client = socket.create_connection(("127.0.0.1", ECHO_PORT), timeout=5)
    client.sendall(b"ping-1")
    if client.recv(4096) != b"ping-1":
        _fail("echo roundtrip failed before ferm ran")

    config = Path("/tmp/lockout.ferm")
    config.write_text(LOCKOUT_CONFIG, encoding="utf-8")

    _step("running ferm --interactive under a pty, never confirming")
    master, slave = pty.openpty()
    ferm = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "pyferm",
            "--interactive",
            "--timeout",
            str(FERM_TIMEOUT),
            "--nolegacy",
            str(config),
        ],
        stdin=slave,
        stdout=slave,
        stderr=slave,
    )
    os.close(slave)
    output = bytearray()

    try:
        if not _read_until(master, PROMPT, output, time.monotonic() + 30):
            _fail(f"no confirmation prompt; ferm said: {bytes(output)!r}")

        _step("rules applied; verifying the connection is frozen")
        client.settimeout(1.5)
        client.sendall(b"ping-2")
        try:
            leaked = client.recv(4096)
        except TimeoutError:
            pass
        else:
            _fail(f"INPUT DROP did not cut the connection: {leaked!r}")

        _step("waiting for the timeout rollback")
        if not _read_until(master, ROLLED_BACK, output, time.monotonic() + 30):
            _fail(f"no rollback message; ferm said: {bytes(output)!r}")
        status = ferm.wait(timeout=30)
        if status != 1:
            _fail(f"ferm exited {status}, expected 1 (rollback path)")
    finally:
        if ferm.poll() is None:
            ferm.kill()
        os.close(master)

    after = _snapshot()
    if after != before:
        _fail(
            "ruleset not restored;"
            f" before={before!r} after={after!r} ferm={bytes(output)!r}"
        )

    _step("verifying the frozen connection comes back to life")
    client.settimeout(30)
    try:
        revived = client.recv(4096)
    except TimeoutError:
        _fail("connection did not revive after the rollback")
    if revived != b"ping-2":
        _fail(f"unexpected data after revival: {revived!r}")

    print("LOCKOUT-E2E-PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
