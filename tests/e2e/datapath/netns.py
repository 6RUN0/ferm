"""
Container-side network fixture for the datapath e2e.

Builds the client/fw/backend topology, sets the fw sysctls, owns the
listener lifecycle, and tears rules down between backends.  Everything
here needs root + ``CAP_SYS_ADMIN`` inside the container, so it is
exercised only by the full container run, never on the host.

Empirically established (2026-06-15): ``ip netns add`` needs SYS_ADMIN;
sysctl writes need ``/proc/sys`` remounted rw (docker mounts it ro);
rp_filter defaults to 2 (loose) on fresh interfaces and must be forced
to 0; v6 ND traverses the nft input hook; ``nft flush ruleset`` last is a
safe canonical teardown.
"""

from __future__ import annotations

import subprocess
import sys
import time

# fw-side interface names (also referenced by the NAT masquerade rule).
_VETH_FW_CLIENT = "v_fw_cl"
_VETH_FW_BACKEND = "v_fw_be"

#: A small UDP echo responder; ncat's UDP mode is unreliable for this.
ECHO_PY = """
import socket, sys
fam = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
addr, port = sys.argv[2], int(sys.argv[3])
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind((addr, port))
while True:
    data, peer = s.recvfrom(65535)
    s.sendto(data, peer)
"""

#: Listeners started once at setup and kept alive across both backends
#: (between backends the ruleset is flushed, the listeners are not).
LISTENER_SPECS = [
    {
        "name": "fw-tcp22-v4",
        "netns": "fw",
        "kind": "tcp",
        "family": 4,
        "addr": "10.0.0.1",
        "port": 22,
    },
    {
        "name": "fw-tcp22-v6",
        "netns": "fw",
        "kind": "tcp",
        "family": 6,
        "addr": "fd00:0::1",
        "port": 22,
    },
    {
        "name": "fw-udp53-v4",
        "netns": "fw",
        "kind": "udp-echo",
        "family": 4,
        "addr": "10.0.0.1",
        "port": 53,
    },
    {
        "name": "fw-udp53-v6",
        "netns": "fw",
        "kind": "udp-echo",
        "family": 6,
        "addr": "fd00:0::1",
        "port": 53,
    },
    {
        "name": "be-tcp80-v4",
        "netns": "backend",
        "kind": "tcp",
        "family": 4,
        "addr": "10.0.1.2",
        "port": 80,
    },
    {
        "name": "be-tcp9000-v4",
        "netns": "backend",
        "kind": "tcp-echo",
        "family": 4,
        "addr": "10.0.1.2",
        "port": 9000,
    },
]


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


def _must(*cmd: str) -> None:
    """Run a setup command; abort the whole driver if it fails."""
    proc = _sh(*cmd)
    if proc.returncode != 0:
        raise RuntimeError(
            f"setup command failed: {' '.join(cmd)}\n{proc.stderr}"
        )


def remount_proc_sys() -> None:
    """Make /proc/sys writable (docker mounts it ro; needs SYS_ADMIN)."""
    _must("mount", "-o", "remount,rw", "/proc/sys")


def build_topology() -> None:
    """Create client/fw/backend netns, veth links, addresses, routes."""
    for ns in ("client", "fw", "backend"):
        _must("ip", "netns", "add", ns)

    # client <-> fw
    _must(
        "ip", "link", "add", "v_cl_fw",
        "type", "veth", "peer", "name", _VETH_FW_CLIENT,
    )
    _must("ip", "link", "set", "v_cl_fw", "netns", "client")
    _must("ip", "link", "set", _VETH_FW_CLIENT, "netns", "fw")
    # fw <-> backend
    _must(
        "ip", "link", "add", _VETH_FW_BACKEND,
        "type", "veth", "peer", "name", "v_be_fw",
    )
    _must("ip", "link", "set", _VETH_FW_BACKEND, "netns", "fw")
    _must("ip", "link", "set", "v_be_fw", "netns", "backend")

    # addresses + up
    _addr("client", "v_cl_fw", "10.0.0.2/24", "fd00:0::2/64")
    _addr("fw", _VETH_FW_CLIENT, "10.0.0.1/24", "fd00:0::1/64")
    _addr("fw", _VETH_FW_BACKEND, "10.0.1.1/24", "fd00:1::1/64")
    _addr("backend", "v_be_fw", "10.0.1.2/24", "fd00:1::2/64")
    for ns in ("client", "fw", "backend"):
        _must("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")

    # cross-subnet routes (harmless; NAT path does not require them)
    _must(
        "ip", "netns", "exec", "client",
        "ip", "route", "add", "10.0.1.0/24", "via", "10.0.0.1",
    )
    _must(
        "ip", "netns", "exec", "client",
        "ip", "-6", "route", "add", "fd00:1::/64", "via", "fd00:0::1",
    )
    _must(
        "ip", "netns", "exec", "backend",
        "ip", "route", "add", "10.0.0.0/24", "via", "10.0.1.1",
    )
    _must(
        "ip", "netns", "exec", "backend",
        "ip", "-6", "route", "add", "fd00:0::/64", "via", "fd00:1::1",
    )


def _addr(ns: str, iface: str, v4: str, v6: str) -> None:
    _must("ip", "netns", "exec", ns, "ip", "addr", "add", v4, "dev", iface)
    _must(
        "ip", "netns", "exec", ns,
        "ip", "-6", "addr", "add", v6, "dev", iface, "nodad",
    )
    _must("ip", "netns", "exec", ns, "ip", "link", "set", iface, "up")


def set_sysctls() -> None:
    """Set fw sysctls; hard-fail (named) on any EPERM/EACCES."""
    sysctls = {
        "net.ipv4.ip_forward": "1",
        "net.ipv6.conf.all.forwarding": "1",
        "net.ipv4.conf.all.rp_filter": "0",
        "net.ipv4.conf.default.rp_filter": "0",
        f"net.ipv4.conf.{_VETH_FW_CLIENT}.rp_filter": "0",
        f"net.ipv4.conf.{_VETH_FW_BACKEND}.rp_filter": "0",
        "net.ipv4.icmp_ratelimit": "0",
        "net.ipv6.icmp.ratelimit": "0",
    }
    for key, value in sysctls.items():
        proc = _sh(
            "ip", "netns", "exec", "fw", "sysctl", "-w", f"{key}={value}"
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"sysctl write denied for {key}={value} "
                f"(need `mount -o remount,rw /proc/sys` + SYS_ADMIN):"
                f" {proc.stderr}"
            )


class Listeners:
    """Owns the listener subprocesses; supports per-name stop/start."""

    def __init__(self) -> None:
        self._procs: dict[str, subprocess.Popen[bytes]] = {}

    @staticmethod
    def _spawn(spec: dict) -> subprocess.Popen[bytes]:
        base = ["ip", "netns", "exec", spec["netns"]]
        if spec["kind"] == "udp-echo":
            cmd = [
                *base,
                "python3", "-c", ECHO_PY,
                str(spec["family"]), spec["addr"], str(spec["port"]),
            ]
        else:
            ncat = ["ncat"]
            if spec["family"] == 6:
                ncat.append("-6")
            ncat += ["--keep-open", "--listen"]
            if spec["kind"] == "tcp-echo":
                ncat += ["--exec", "/bin/cat"]
            ncat += [spec["addr"], str(spec["port"])]
            cmd = [*base, *ncat]
        return subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    def start_all(self) -> None:
        for spec in LISTENER_SPECS:
            self._procs[spec["name"]] = self._spawn(spec)

    def stop(self, name: str) -> None:
        proc = self._procs.pop(name, None)
        if proc is not None:
            proc.terminate()
            proc.wait(timeout=5)

    def start(self, name: str) -> None:
        spec = next(s for s in LISTENER_SPECS if s["name"] == name)
        self._procs[name] = self._spawn(spec)

    def stop_all(self) -> None:
        for name in list(self._procs):
            self.stop(name)

    @staticmethod
    def assert_live(names: list[str] | None = None) -> None:
        """
        Raise if any (named) listener is not actually bound.

        Polls with retries instead of trusting a fixed sleep: process
        spawn + bind is not instantaneous, and a fixed ``time.sleep`` is
        the classic flaky-startup source.  Liveness is the oracle's
        precondition (a dead listener turns a REJECT ``reset`` into a
        kernel ``reset`` from a closed port), so this must be solid.
        """
        specs = [
            spec
            for spec in LISTENER_SPECS
            if names is None or spec["name"] in names
        ]
        for spec in specs:
            flag = "-unlH" if "udp" in spec["kind"] else "-tnlH"
            for _ in range(10):  # up to ~2s per listener
                out = _sh(
                    "ip", "netns", "exec", spec["netns"], "ss", flag
                ).stdout
                if f":{spec['port']}" in out:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError(
                    f"listener {spec['name']} not live:\n{out}"
                )


def teardown_rules() -> None:
    """Best-effort rule reset between backends; nft flush ruleset LAST."""
    for tool in ("iptables", "ip6tables"):
        for args in (
            ("-F",),
            ("-X",),
            ("-t", "nat", "-F"),
            ("-t", "nat", "-X"),
        ):
            _sh("ip", "netns", "exec", "fw", tool, *args)
    # Drop stale conntrack: an ESTABLISHED entry from a prior scenario
    # would let through traffic the next scenario expects cut as NEW.
    # Run inside fw's netns -- conntrack is per-network-namespace, so this
    # flushes only fw's table, NOT the host-global one (closing the spec's
    # "conntrack -F is global" residual worry).
    _sh("ip", "netns", "exec", "fw", "conntrack", "-F")
    _sh("ip", "netns", "exec", "fw", "nft", "flush", "ruleset")


def ruleset_empty() -> tuple[bool, str]:
    """
    Assert the fw ruleset is fully empty via ``nft list ruleset`` only.

    In bookworm ``iptables`` is ``iptables-nft``; checking ``iptables -S``
    separately is wrong (``iptables-nft -F`` materializes empty base
    tables into the nft ruleset).  After ``nft flush ruleset`` the
    ruleset is wholly empty, so any residue is a real teardown failure.
    """
    out = _sh(
        "ip", "netns", "exec", "fw", "nft", "list", "ruleset"
    ).stdout
    stripped = out.strip()
    return (stripped == "", stripped)


def destroy_topology() -> None:
    """Delete all three netns (best-effort; errors ignored)."""
    for ns in ("client", "fw", "backend"):
        _sh("ip", "netns", "del", ns)


def conntrack_available() -> bool:
    """
    Lower-bound conntrack detection: does a ``ct state`` rule compile?

    ``nft -c`` proves the expression is accepted by netlink, not that the
    module is loaded (nft autoloads on first packet).  If conntrack is
    truly absent the scenario apply fails loudly (FAIL), not silently.
    """
    ruleset = (
        "table ip ctprobe { chain c "
        "{ type filter hook input priority 0; "
        "ct state established accept } }\n"
    )
    return _sh("nft", "-c", "-f", "-", input_text=ruleset).returncode == 0


def dump_diagnostics(label: str) -> None:
    """Print fw/listener state to stderr on any FAIL."""
    print(f"--- diagnostics for {label} ---", file=sys.stderr)
    for cmd in (
        ("ip", "netns", "exec", "fw", "nft", "list", "ruleset"),
        ("ip", "netns", "exec", "fw", "iptables-save"),
        ("ip", "netns", "exec", "fw", "ip6tables-save"),
        ("ip", "netns", "exec", "fw", "conntrack", "-L"),
    ):
        out = _sh(*cmd)
        print(
            f"$ {' '.join(cmd)}\n{out.stdout}{out.stderr}", file=sys.stderr
        )
    for ns in ("client", "fw", "backend"):
        out = _sh("ip", "netns", "exec", ns, "ss", "-tunlH")
        print(f"$ ss in {ns}\n{out.stdout}", file=sys.stderr)
