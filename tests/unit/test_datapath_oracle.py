"""Host unit tests for the nmap XML reason parser (no docker, no kernel)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The datapath driver package is not importable as ``pyferm``; add its
# directory to the path so the pure parser can be tested on the host.
_DATAPATH_DIR = Path(__file__).resolve().parents[1] / "e2e" / "datapath"
sys.path.insert(0, str(_DATAPATH_DIR))

import oracle  # noqa: E402


def _xml(proto: str, portid: int, state: str, reason: str) -> str:
    return (
        '<?xml version="1.0"?>\n'
        "<nmaprun><host>"
        '<address addr="10.0.0.1" addrtype="ipv4"/>'
        "<ports>"
        f'<port protocol="{proto}" portid="{portid}">'
        f'<state state="{state}" reason="{reason}" reason_ttl="64"/>'
        "</port>"
        "</ports></host></nmaprun>"
    )


@pytest.mark.parametrize(
    ("proto", "portid", "state", "reason"),
    [
        ("tcp", 22, "open", "syn-ack"),
        ("tcp", 23, "closed", "reset"),
        ("tcp", 24, "filtered", "port-unreach"),
        ("tcp", 80, "filtered", "no-response"),
        ("udp", 53, "open", "udp-response"),
    ],
)
def test_parse_reason_returns_state_reason(
    proto: str, portid: int, state: str, reason: str
) -> None:
    xml = _xml(proto, portid, state, reason)
    assert oracle.parse_reason(xml, portid, proto) == reason


def test_parse_reason_missing_port_is_none() -> None:
    # Host-down / no port block: nmap emits no matching <port>.
    xml = '<?xml version="1.0"?>\n<nmaprun><host></host></nmaprun>'
    assert oracle.parse_reason(xml, 22, "tcp") is None


def test_parse_reason_wrong_proto_is_none() -> None:
    # A tcp/22 block must not satisfy a udp/22 query.
    xml = _xml("tcp", 22, "open", "syn-ack")
    assert oracle.parse_reason(xml, 22, "udp") is None


def test_parse_reason_malformed_xml_is_none() -> None:
    assert oracle.parse_reason("<not-xml", 22, "tcp") is None
