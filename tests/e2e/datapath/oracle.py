"""
nmap ``--reason`` oracle: classify a probed port by its response packet.

Runs inside the container, but ``parse_reason`` is pure and unit-tested
on the host against captured XML.  nmap's ``<state reason="...">``
attribute names the response-packet class (``syn-ack`` / ``reset`` /
``port-unreach`` / ``no-response`` / ``udp-response``), which
distinguishes ferm's ACCEPT / DROP / REJECT-reset / REJECT-default
verdicts -- a distinction the coarse open/filtered/closed *state*
collapses (default REJECT sends ICMP port-unreachable, which ``-sS``
reports as ``filtered``, the same word DROP earns).

We parse ``nmap -oX -`` (XML on stdout), never grepable/normal output:
the ``reason`` attribute is stable since nmap 5.x, whereas stdout text is
brittle to version/locale/terminal width.

XML safety: the input is our OWN ``nmap`` output, generated locally in
the container -- a trusted producer, not external/attacker data -- so the
stdlib parser's XXE/entity-expansion exposure does not apply.  Using
stdlib ``ElementTree`` also keeps this driver dependency-free, matching
the stdlib-only constraint of the container (cf. ``nft/driver.py``); a
``defusedxml`` dependency would buy nothing against a producer we control.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from typing import NamedTuple


class Probe(NamedTuple):
    """A single stateless probe and its expected response class."""

    proto: str  # "tcp" | "udp"
    src_netns: str  # netns the probe originates from, e.g. "client"
    dst_addr: str  # target address, e.g. "10.0.0.1" or "fd00:0::1"
    port: int
    family: int  # 4 | 6
    expected_reason: str  # one of the reason tokens above
    max_retries: int  # nmap --max-retries (UDP-ACCEPT needs 2; see risks)


def parse_reason(nmap_xml: str, portid: int, proto: str) -> str | None:
    """
    Return the ``reason`` of ``<port portid=… protocol=…><state>`` or None.

    ``None`` means nmap reported no such port element (host treated down,
    or the scan produced no port block) -- the caller turns that into a
    structural FAIL with the raw XML attached.
    """
    try:
        root = ET.fromstring(nmap_xml)
    except ET.ParseError:
        return None
    for port in root.iter("port"):
        if port.get("protocol") == proto and port.get("portid") == str(portid):
            state = port.find("state")
            if state is None:
                return None
            return state.get("reason")
    return None


def run_nmap_probe(probe: Probe) -> tuple[str, str]:
    """
    Run one nmap probe from ``probe.src_netns`` and return (xml, stderr).

    Per-probe timeouts are mandatory: nmap's default ~20s/probe would
    blow the 900s budget on every ``no-response`` (DROP) probe.
    """
    scan_flag = "-sU" if probe.proto == "udp" else "-sS"
    cmd = ["ip", "netns", "exec", probe.src_netns, "nmap"]
    if probe.family == 6:
        cmd.append("-6")
    cmd += [
        scan_flag,
        "-Pn",
        "-oX",
        "-",
        "--reason",
        "--max-retries",
        str(probe.max_retries),
        "--max-rtt-timeout",
        "1500ms",
        "--host-timeout",
        "3000ms",
        "-p",
        str(probe.port),
        probe.dst_addr,
    ]
    proc = subprocess.run(
        cmd, capture_output=True, encoding="utf-8", check=False
    )
    return proc.stdout, proc.stderr
