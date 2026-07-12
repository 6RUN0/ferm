"""
Unit-pin the iptables-nft differential's dump normalizer.

The live differential (:mod:`tests.e2e.test_iptables_nft_diff`) needs a
rootless netns and the nft-backed iptables tools, so its normalizer --
the one component that could silently hide a real translation bug by
folding too much -- is exercised here in isolation, with no kernel
required.  The load-bearing property is the negative one: surface
conventions collapse, but a genuine semantic difference (``dport`` vs
``sport``) must survive.
"""

from __future__ import annotations

from tests.e2e.iptables_nft.normalize import canonicalize_rule, parse_dump


def test_inline_counter_is_stripped() -> None:
    assert (
        canonicalize_rule("tcp dport 22 counter packets 7 bytes 420 accept")
        == "tcp dport 22 accept"
    )


def test_hex_width_is_normalized() -> None:
    assert canonicalize_rule("meta mark 0x00000010 accept") == (
        "meta mark 0x10 accept"
    )
    assert canonicalize_rule("meta mark 0x0 accept") == "meta mark 0x0 accept"


def test_redundant_l4_dispatch_is_dropped() -> None:
    # ``tcp dport`` already carries the protocol dependency, so a leading
    # ``ip protocol tcp`` iptables-nft prints is pure redundancy the port
    # never emits.
    assert canonicalize_rule("ip protocol tcp tcp dport 22 accept") == (
        "tcp dport 22 accept"
    )
    assert canonicalize_rule("ip protocol icmp icmp type echo-request x") == (
        "icmp type echo-request x"
    )


def test_l4_dispatch_spellings_converge() -> None:
    # A bare protocol match with no payload keeps the dispatch, folded to
    # the port's canonical ``meta l4proto`` spelling.
    canon = canonicalize_rule("meta l4proto tcp accept")
    assert canonicalize_rule("ip protocol tcp accept") == canon
    assert canonicalize_rule("ip6 nexthdr tcp accept") == canon


def test_ipv6_icmp_name_is_canonical() -> None:
    assert canonicalize_rule(
        "ip6 nexthdr ipv6-icmp icmpv6 type nd-router x"
    ) == ("icmpv6 type nd-router x")


def test_default_limit_burst_is_folded() -> None:
    assert canonicalize_rule("limit rate 5/minute burst 5 packets accept") == (
        "limit rate 5/minute accept"
    )


def test_anon_set_order_is_normalized() -> None:
    assert canonicalize_rule("tcp dport { 443, 22, 80 } accept") == (
        "tcp dport { 22, 80, 443 } accept"
    )


def test_ct_state_order_is_normalized() -> None:
    assert canonicalize_rule("ct state related,established accept") == (
        "ct state established,related accept"
    )


def test_sport_and_dport_never_fold() -> None:
    # The whole point of the differential: a direction mistranslation must
    # not be normalized away.
    assert canonicalize_rule("tcp dport 22 accept") != (
        canonicalize_rule("tcp sport 22 accept")
    )


def test_saddr_and_daddr_never_fold() -> None:
    assert canonicalize_rule("ip saddr 10.0.0.1 accept") != (
        canonicalize_rule("ip daddr 10.0.0.1 accept")
    )


_DUMP_REFERENCE = """\
# Warning: table ip filter is managed by iptables-nft, do not touch!
table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\ttcp dport 22 counter packets 0 bytes 0 accept
\t}
\tchain FORWARD {
\t\ttype filter hook forward priority filter; policy accept;
\t}
}
table ip nat {
\tchain PREROUTING {
\t\ttype nat hook prerouting priority dstnat; policy accept;
\t\ttcp dport 80 counter packets 0 bytes 0 dnat to 10.0.0.1
\t}
}
"""

_DUMP_PORT = """\
table ip ferm {
\tchain INPUT {
\t\ttype filter hook input priority 0; policy drop;
\t\ttcp dport 22 accept
\t}
\tchain nat_PREROUTING {
\t\ttype nat hook prerouting priority -100; policy accept;
\t\ttcp dport 80 dnat to 10.0.0.1
\t}
}
"""


def test_parse_dump_keys_by_table_concept() -> None:
    # The port packs both concepts into table ``ferm`` and prefixes the
    # nat chain; iptables-nft uses one table per concept with bare chains.
    # Both must reduce to the same ``(family, concept, chain)`` keys so
    # the two sides line up.
    reference = parse_dump(_DUMP_REFERENCE)
    port = parse_dump(_DUMP_PORT)
    assert set(reference) == {
        ("ip", "filter", "INPUT"),
        ("ip", "filter", "FORWARD"),
        ("ip", "nat", "PREROUTING"),
    }
    assert port[("ip", "filter", "INPUT")] == ["tcp dport 22 accept"]
    assert port[("ip", "nat", "PREROUTING")] == [
        "tcp dport 80 dnat to 10.0.0.1"
    ]


def test_parse_dump_agrees_across_translators() -> None:
    reference = parse_dump(_DUMP_REFERENCE)
    port = parse_dump(_DUMP_PORT)
    for key in (("ip", "filter", "INPUT"), ("ip", "nat", "PREROUTING")):
        assert reference[key] == port[key]


def test_parse_dump_drops_base_chain_decl_and_comments() -> None:
    port = parse_dump(_DUMP_PORT)
    # The FORWARD chain is base-decl only on the reference side; on the
    # port side it is absent entirely -- neither yields a phantom rule.
    assert all(
        "type " not in rule and "hook " not in rule
        for rules in port.values()
        for rule in rules
    )
