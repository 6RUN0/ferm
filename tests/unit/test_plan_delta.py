"""Unit tests for the nft delta-apply emitter and its preconditions."""

from __future__ import annotations

from pyferm.plan import ParsedSet, parse_nft_script


def test_parsed_set_defaults() -> None:
    ps = ParsedSet("hosts")
    assert ps.type_ is None
    assert ps.flags == ()


def test_parse_nft_script_reads_set_type_and_flags() -> None:
    script = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add set ip ferm hosts { type ipv4_addr; flags interval; }\n"
        "add element ip ferm hosts { 10.0.0.0/24 }\n"
    )
    tables = parse_nft_script(script)
    s = tables["ferm"].sets["hosts"]
    assert s.type_ == "ipv4_addr"
    assert s.flags == ("interval",)
    assert s.elements == ["10.0.0.0/24"]


def test_parse_nft_script_set_without_flags() -> None:
    script = (
        "add table ip ferm\n"
        "add set ip ferm ports { type inet_service; }\n"
        "add element ip ferm ports { 22, 80 }\n"
    )
    s = parse_nft_script(script)["ferm"].sets["ports"]
    assert s.type_ == "inet_service"
    assert s.flags == ()
