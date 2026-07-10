# tests/unit/test_backend_nft.py
from __future__ import annotations

import socket
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from pyferm.backend.nft import (
    NftBaseChain,
    NftMatch,
    NftRegularChain,
    NftRule,
    NftStatement,
    NftTable,
    NftVerdict,
    render_comment,
    serialize_table,
)
from pyferm.errors import FermError
from pyferm.scope import OptionKind
from pyferm.values import SetRef, Value


def test_model_constructors_hold_fields() -> None:
    table = NftTable(family="ip", name="ferm")
    assert (table.family, table.name) == ("ip", "ferm")

    base = NftBaseChain(
        name="INPUT",
        type="filter",
        hook="input",
        priority=0,
        policy="drop",
    )
    assert base.hook == "input"
    assert base.policy == "drop"

    user = NftRegularChain(name="mychain")
    assert user.name == "mychain"

    rule = NftRule(statements=[], comment=None)
    assert rule.statements == []


def test_statement_to_text_dispatches_by_type() -> None:
    assert NftMatch("ip saddr 10.0.0.1").to_text() == "ip saddr 10.0.0.1"
    assert NftVerdict("accept").to_text() == "accept"
    # A statement is an abstract base; subclasses own to_text.
    assert issubclass(NftMatch, NftStatement)
    assert issubclass(NftVerdict, NftStatement)


def test_nftmatch_renders_singleton_as_expr() -> None:
    m = NftMatch("tcp dport 22", set_key="tcp dport", element="22")
    assert m.to_text() == "tcp dport 22"


def test_nftmatch_renders_collapsed_set_sorted() -> None:
    m = NftMatch(
        "tcp dport 22",
        set_key="tcp dport",
        elements=["443", "22", "80"],
    )
    assert m.to_text() == "tcp dport { 22, 80, 443 }"


def test_nftmatch_collapsed_set_dedups_repeated_element() -> None:
    # A non-adjacent repeated operand can merge into the same run twice; the
    # rendered anonymous set must not carry a duplicate member.
    m = NftMatch(
        "tcp dport 22",
        set_key="tcp dport",
        elements=["22", "80", "22"],
    )
    assert m.to_text() == "tcp dport { 22, 80 }"


def test_nftmatch_non_eligible_renders_expr() -> None:
    m = NftMatch("ct state new")
    assert m.to_text() == "ct state new"


def test_serialize_table_emits_atomic_transaction() -> None:
    table = NftTable(family="ip", name="ferm")
    chains: list[NftBaseChain | NftRegularChain] = [
        NftBaseChain("INPUT", "filter", "input", 0, policy="drop"),
        NftRegularChain("mychain"),
    ]
    rules = {
        "INPUT": [
            NftRule(
                [
                    NftMatch("ct state established,related"),
                    NftVerdict("accept"),
                ]
            ),
            NftRule([NftVerdict("jump mychain")]),
        ],
        "mychain": [NftRule([NftVerdict("drop")], comment="hi")],
    }
    out = serialize_table(table, chains, rules, {}, noflush=False)
    assert out == (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add chain ip ferm INPUT "
        "{ type filter hook input priority 0; policy drop; }\n"
        "add chain ip ferm mychain\n"
        "add rule ip ferm INPUT ct state established,related accept\n"
        "add rule ip ferm INPUT jump mychain\n"
        'add rule ip ferm mychain drop comment "hi"\n'
    )


def test_serialize_table_noflush_omits_flush() -> None:
    table = NftTable(family="ip", name="ferm")
    chains: list[NftBaseChain | NftRegularChain] = [NftRegularChain("c")]
    out = serialize_table(table, chains, {"c": []}, {}, noflush=True)
    assert "flush table" not in out
    assert out.startswith("add table ip ferm\nadd chain ip ferm c\n")


def test_render_comment_rejects_over_limit() -> None:
    assert render_comment("ok") == 'comment "ok"'
    assert render_comment("two words") == 'comment "two words"'
    with pytest.raises(FermError, match="exceeds nft limit"):
        render_comment("x" * 129)


# ---------------------------------------------------------------------------
# Family.nft_name + map_base_chain
# ---------------------------------------------------------------------------
from pyferm.backend.nft import map_base_chain  # noqa: E402
from pyferm.domains import Family  # noqa: E402


def test_family_nft_name_maps_1to1() -> None:
    assert Family.IP.nft_name == "ip"
    assert Family.IP6.nft_name == "ip6"
    assert Family.ARP.nft_name == "arp"
    assert Family.EB.nft_name == "bridge"


def test_map_base_chain_known_pairs() -> None:
    spec = map_base_chain(Family.IP, "filter", "INPUT")
    assert spec == ("filter", "input", 0)
    assert map_base_chain(Family.IP, "nat", "POSTROUTING") == (
        "nat",
        "postrouting",
        100,
    )
    assert map_base_chain(Family.IP, "mangle", "OUTPUT") == (
        "route",
        "output",
        -150,
    )


def test_map_base_chain_unmappable_is_error() -> None:
    with pytest.raises(FermError, match="not yet supported"):
        map_base_chain(Family.EB, "broute", "BROUTING")
    with pytest.raises(FermError, match="not yet supported"):
        map_base_chain(Family.ARP, "nat", "PREROUTING")


# ---------------------------------------------------------------------------
# build_chains + nft_chain_name
# ---------------------------------------------------------------------------
from pyferm.backend.nft import build_chains  # noqa: E402
from pyferm.domains import ChainInfo, TableInfo  # noqa: E402


def test_build_chains_splits_builtin_and_user() -> None:
    table = TableInfo(
        chains={
            "INPUT": ChainInfo(policy="DROP"),
            "mychain": ChainInfo(),
        }
    )
    chains = build_chains(Family.IP, "filter", table)
    by_name = {c.name: c for c in chains}
    assert isinstance(by_name["INPUT"], NftBaseChain)
    assert by_name["INPUT"].policy == "drop"
    assert by_name["INPUT"].hook == "input"
    assert by_name["INPUT"].type == "filter"
    assert isinstance(by_name["mychain"], NftRegularChain)


def test_build_chains_sorted_for_determinism() -> None:
    table = TableInfo(chains={"zeta": ChainInfo(), "alpha": ChainInfo()})
    names = [c.name for c in build_chains(Family.IP, "filter", table)]
    assert names == ["alpha", "zeta"]


def test_nft_chain_name_disambiguates_non_filter() -> None:
    from pyferm.backend.nft import nft_chain_name

    assert nft_chain_name("filter", "INPUT") == "INPUT"
    assert nft_chain_name("mangle", "INPUT") == "mangle_INPUT"
    # mangle/INPUT becomes a distinct base chain, not a collision with filter.
    table = TableInfo(chains={"INPUT": ChainInfo()})
    chain = build_chains(Family.IP, "mangle", table)[0]
    # mangle/OUTPUT -> route hook (the most error-prone mapping).
    table_out = TableInfo(chains={"OUTPUT": ChainInfo()})
    chain_out = build_chains(Family.IP, "mangle", table_out)[0]
    assert isinstance(chain_out, NftBaseChain)
    assert chain_out.type == "route"

    assert chain.name == "mangle_INPUT"
    assert isinstance(chain, NftBaseChain)
    assert (chain.hook, chain.priority) == ("input", -150)


def test_nft_chain_name_accepts_dashes() -> None:
    # nft's bare-word grammar allows an interior dash (verified against
    # nft v1.1.6: `add chain ip t fail2ban-ssh` and `jump fail2ban-ssh`
    # both apply); fail2ban-style names are common in the wild corpus.
    from pyferm.backend.nft import nft_chain_name

    assert nft_chain_name("filter", "fail2ban-ssh") == "fail2ban-ssh"
    assert nft_chain_name("nat", "pre-routing-x") == "nat_pre-routing-x"
    # whitespace/metacharacters (and a leading dash, which nft would
    # parse as an option) still refuse
    for bad in ("has space", "semi;colon", "-leading", "1leading"):
        with pytest.raises(FermError, match="not a valid nft identifier"):
            nft_chain_name("filter", bad)


# ---------------------------------------------------------------------------
# unwrap_value + first_scalar
# ---------------------------------------------------------------------------
from pyferm.backend.nft import first_scalar, unwrap_value  # noqa: E402
from pyferm.values import Multi, Negated  # noqa: E402


def test_unwrap_value_plain_and_negated() -> None:
    assert unwrap_value("22") == ("22", False)
    assert unwrap_value(Negated("22")) == ("22", True)


def test_unwrap_value_multi_negation_is_error() -> None:
    with pytest.raises(
        FermError, match=r"^multi-value match cannot be negated in nft$"
    ):
        unwrap_value(Negated(["22", "80"]))


def test_unwrap_value_multi_cannot_be_single_match() -> None:
    with pytest.raises(
        FermError,
        match=r"^multi-value cannot be expressed as a single nft match$",
    ):
        unwrap_value(Multi(values=["22", "80"]))


def test_unwrap_value_unsupported_shape_is_error() -> None:
    with pytest.raises(
        FermError, match=r"^unsupported value shape for nft backend$"
    ):
        unwrap_value(None)


def test_unwrap_value_negated_list_collapses_to_scalar() -> None:
    # A negated single-element list still has an nft equivalent: the `> 1`
    # guard does not fire and the value collapses to its sole scalar; an
    # empty negated list collapses to the empty scalar.  Both keep negation.
    assert unwrap_value(Negated(["22"])) == ("22", True)
    assert unwrap_value(Negated([])) == ("", True)


def test_first_scalar_extracts_from_multi() -> None:
    assert first_scalar(Multi(values=["1.2.3.4"])) == "1.2.3.4"
    assert first_scalar("5.6.7.8") == "5.6.7.8"


def test_first_scalar_bad_multi_is_error() -> None:
    with pytest.raises(
        FermError, match=r"^unsupported value shape for nft backend$"
    ):
        first_scalar(Multi(values=[None]))


def test_first_scalar_unsupported_shape_is_error() -> None:
    with pytest.raises(
        FermError, match=r"^unsupported value shape for nft backend$"
    ):
        first_scalar(None)


# ---------------------------------------------------------------------------
# translate_match
# ---------------------------------------------------------------------------
from pyferm.backend.nft import translate_match  # noqa: E402
from pyferm.rules import RenderedOption  # noqa: E402


def _opt(
    name: str,
    value: Value,
    kind: OptionKind = OptionKind.OPTION,
    module: str | None = None,
) -> RenderedOption:
    return RenderedOption(name=name, value=value, kind=kind, module=module)


def test_translate_match_addresses_and_ifaces() -> None:
    assert (
        translate_match(Family.IP, _opt("source", "10.0.0.1"), None)
        == "ip saddr 10.0.0.1"
    )
    assert (
        translate_match(Family.IP6, _opt("destination", "fe80::1"), None)
        == "ip6 daddr fe80::1"
    )
    assert (
        translate_match(Family.IP, _opt("in-interface", "eth0"), None)
        == 'iifname "eth0"'
    )
    assert (
        translate_match(Family.IP, _opt("out-interface", "eth1"), None)
        == 'oifname "eth1"'
    )


def test_translate_match_ports_use_rule_protocol() -> None:
    assert (
        translate_match(Family.IP, _opt("dport", "22"), "tcp")
        == "tcp dport 22"
    )
    assert (
        translate_match(Family.IP, _opt("sport", "53"), "udp")
        == "udp sport 53"
    )


def test_translate_match_port_without_protocol_errors() -> None:
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        translate_match(Family.IP, _opt("dport", "22"), None)


def _host_resolves_services() -> bool:
    """Whether the host /etc/services (netbase) can resolve names."""
    try:
        socket.getservbyname("ssh")
    except OSError:
        return False
    return True


@pytest.mark.skipif(
    not _host_resolves_services(),
    reason="host /etc/services cannot resolve service names",
)
def test_translate_match_service_names_resolve_to_numbers() -> None:
    # nft resolves a service name at parse time and the kernel readback
    # prints the number, so a named port emitted verbatim leaves --plan
    # diffing forever; resolve through the same /etc/services database.
    assert (
        translate_match(Family.IP, _opt("dport", "ssh"), "tcp")
        == "tcp dport 22"
    )
    assert (
        translate_match(Family.IP, _opt("sport", "domain"), "udp")
        == "udp sport 53"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("destination-ports", "http,https", module="multiport"),
            "tcp",
        )
        == "tcp dport { 80, 443 }"
    )
    with pytest.raises(
        FermError, match=r"^unknown service name 'frobnicate-svc'"
    ):
        translate_match(Family.IP, _opt("dport", "frobnicate-svc"), "tcp")


def test_translate_match_negation() -> None:
    assert (
        translate_match(Family.IP, _opt("source", Negated("10.0.0.1")), None)
        == "ip saddr != 10.0.0.1"
    )
    assert (
        translate_match(Family.IP, _opt("dport", Negated("23")), "tcp")
        == "tcp dport != 23"
    )


def test_translate_match_state_and_limit() -> None:
    assert (
        translate_match(
            Family.IP,
            _opt("state", "ESTABLISHED,RELATED", module="state"),
            None,
        )
        == "ct state established,related"
    )
    assert (
        translate_match(
            Family.IP, _opt("limit", "3/second", module="limit"), None
        )
        == "limit rate 3/second"
    )


@pytest.mark.parametrize(
    ("scalar", "expected"),
    [
        # xt_limit accepts any unit prefix, case-insensitively, and nft
        # wants the full spelling (upstream reference: iptables-translate)
        ("10/min", "limit rate 10/minute"),
        ("10/m", "limit rate 10/minute"),
        ("3/sec", "limit rate 3/second"),
        ("1/h", "limit rate 1/hour"),
        ("2/DAY", "limit rate 2/day"),
        # a bare number is per-second in xt_limit
        ("5", "limit rate 5/second"),
    ],
)
def test_translate_match_limit_rate_normalization(
    scalar: str, expected: str
) -> None:
    assert (
        translate_match(Family.IP, _opt("limit", scalar, module="limit"), None)
        == expected
    )


def test_translate_match_limit_bad_unit_is_error() -> None:
    with pytest.raises(FermError, match=r"^invalid rate '5/fortnight'"):
        translate_match(
            Family.IP, _opt("limit", "5/fortnight", module="limit"), None
        )


def test_translate_match_uncovered_is_error() -> None:
    with pytest.raises(FermError, match="not yet supported"):
        translate_match(Family.IP, _opt("totally-unknown", "x"), None)


@pytest.mark.parametrize(
    ("domain", "scalar", "expected"),
    [
        # ip: nft reuses the iptables top-level type names verbatim
        (Family.IP, "echo-request", "icmp type echo-request"),
        (Family.IP, "echo-reply", "icmp type echo-reply"),
        (
            Family.IP,
            "destination-unreachable",
            "icmp type destination-unreachable",
        ),
        (Family.IP, "time-exceeded", "icmp type time-exceeded"),
        (Family.IP, "router-advertisement", "icmp type router-advertisement"),
        # ip aliases (iptables spellings)
        (Family.IP, "ping", "icmp type echo-request"),
        (Family.IP, "pong", "icmp type echo-reply"),
        (Family.IP, "ttl-exceeded", "icmp type time-exceeded"),
        # ip6: the shared names keep their spelling...
        (Family.IP6, "echo-request", "icmpv6 type echo-request"),
        (Family.IP6, "packet-too-big", "icmpv6 type packet-too-big"),
        # ...while the ND family is respelled to nft's nd-* vocabulary
        (Family.IP6, "router-solicitation", "icmpv6 type nd-router-solicit"),
        (Family.IP6, "router-advertisement", "icmpv6 type nd-router-advert"),
        (
            Family.IP6,
            "neighbour-solicitation",
            "icmpv6 type nd-neighbor-solicit",
        ),
        (
            Family.IP6,
            "neighbor-advertisement",
            "icmpv6 type nd-neighbor-advert",
        ),
        (Family.IP6, "redirect", "icmpv6 type nd-redirect"),
        # numeric operands respell to the kernel-readback name (else the
        # applied rule reads back differently and --plan never converges);
        # a number nft knows no name for stays numeric
        (Family.IP, "8", "icmp type echo-request"),
        (Family.IP, "15", "icmp type info-request"),
        (Family.IP, "42", "icmp type 42"),
        (Family.IP, "3/1", "icmp type destination-unreachable icmp code 1"),
        (Family.IP6, "128", "icmpv6 type echo-request"),
        (Family.IP6, "143", "icmpv6 type mld2-listener-report"),
        (Family.IP6, "100", "icmpv6 type 100"),
        (
            Family.IP6,
            "1/4",
            "icmpv6 type destination-unreachable icmpv6 code 4",
        ),
    ],
)
def test_translate_match_icmp_type(
    domain: Family, scalar: str, expected: str
) -> None:
    assert (
        translate_match(
            domain, _opt("icmp-type", scalar, module="icmp"), "icmp"
        )
        == expected
    )


def test_translate_match_icmp_type_negation() -> None:
    assert (
        translate_match(
            Family.IP, _opt("icmp-type", Negated("echo-request")), "icmp"
        )
        == "icmp type != echo-request"
    )
    assert (
        translate_match(Family.IP6, _opt("icmp-type", Negated("128")), "icmp")
        == "icmpv6 type != echo-request"
    )
    # !(type==3 && code==1) has no infix nft equivalent -- refuse, never
    # emit the wrong De Morgan reading `type != 3 code != 1`.
    with pytest.raises(
        FermError, match=r"^negated icmp type/code match cannot be"
    ):
        translate_match(Family.IP, _opt("icmp-type", Negated("3/1")), "icmp")


def test_translate_match_icmp_type_unknown_or_invalid_is_error() -> None:
    # an iptables subtype name (type 3 + code) is not translated yet
    with pytest.raises(
        FermError,
        match=r"^icmp-type 'network-unreachable' not yet supported",
    ):
        translate_match(
            Family.IP, _opt("icmp-type", "network-unreachable"), "icmp"
        )
    # ip-only name in the ip6 family
    with pytest.raises(
        FermError, match=r"^icmp-type 'source-quench' not yet supported"
    ):
        translate_match(Family.IP6, _opt("icmp-type", "source-quench"), "icmp")
    # a type is one octet
    with pytest.raises(FermError, match=r"^invalid icmp type '300'"):
        translate_match(Family.IP, _opt("icmp-type", "300"), "icmp")
    with pytest.raises(FermError, match=r"^invalid icmp type '3/999'"):
        translate_match(Family.IP, _opt("icmp-type", "3/999"), "icmp")


from pyferm.values import Params, PreNegated  # noqa: E402


@pytest.mark.parametrize(
    ("mask", "comp", "expected"),
    [
        # the kernel readback prints the BITWISE form, not the
        # iptables-translate slash form
        ("SYN,RST", "SYN", "tcp flags & (syn | rst) == syn"),
        # input order does not matter: flags sort into header bit order
        ("ACK,SYN", "SYN", "tcp flags & (syn | ack) == syn"),
        # a single-flag mask is unparenthesized in the readback
        ("SYN", "SYN", "tcp flags & syn == syn"),
        # a multi-flag comparison prints WITHOUT parentheses
        (
            "ALL",
            "SYN,ACK",
            "tcp flags & (fin | syn | rst | psh | ack | urg) == syn | ack",
        ),
        # comp NONE reads back as the flag-absence form
        ("FIN,SYN", "NONE", "tcp flags ! fin,syn"),
    ],
)
def test_translate_match_tcp_flags(
    mask: str, comp: str, expected: str
) -> None:
    value = Params(values=[mask, comp])
    assert (
        translate_match(
            Family.IP, _opt("tcp-flags", value, module="tcp"), "tcp"
        )
        == expected
    )


def test_translate_match_tcp_flags_negation_and_errors() -> None:
    negated = PreNegated(Params(values=["SYN,RST", "SYN"]))
    assert (
        translate_match(
            Family.IP, _opt("tcp-flags", negated, module="tcp"), "tcp"
        )
        == "tcp flags & (syn | rst) != syn"
    )
    with pytest.raises(FermError, match=r"^unknown tcp flag 'BOGUS'"):
        translate_match(
            Family.IP,
            _opt(
                "tcp-flags", Params(values=["SYN,BOGUS", "SYN"]), module="tcp"
            ),
            "tcp",
        )
    # !(flags & mask == 0) would need `!= 0x0`, which the readback
    # respells; refuse rather than mistranslate
    with pytest.raises(FermError, match=r"^negated tcp-flags NONE"):
        translate_match(
            Family.IP,
            _opt(
                "tcp-flags",
                PreNegated(Params(values=["SYN", "NONE"])),
                module="tcp",
            ),
            "tcp",
        )


def test_translate_match_syn() -> None:
    # --syn is --tcp-flags FIN,SYN,RST,ACK SYN; the option carries no
    # argument (value None)
    assert (
        translate_match(Family.IP, _opt("syn", None, module="tcp"), "tcp")
        == "tcp flags & (fin | syn | rst | ack) == syn"
    )
    assert (
        translate_match(
            Family.IP, _opt("syn", PreNegated(None), module="tcp"), "tcp"
        )
        == "tcp flags & (fin | syn | rst | ack) != syn"
    )


def test_translate_match_owner() -> None:
    assert (
        translate_match(
            Family.IP, _opt("uid-owner", "1000", module="owner"), None
        )
        == "meta skuid 1000"
    )
    # a uid range passes through (readback keeps the dash form)
    assert (
        translate_match(
            Family.IP, _opt("uid-owner", "1000-2000", module="owner"), None
        )
        == "meta skuid 1000-2000"
    )
    # a user name resolves to the number the readback prints
    assert (
        translate_match(
            Family.IP, _opt("uid-owner", "root", module="owner"), None
        )
        == "meta skuid 0"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("uid-owner", PreNegated("1000"), module="owner"),
            None,
        )
        == "meta skuid != 1000"
    )
    assert (
        translate_match(
            Family.IP, _opt("gid-owner", "100", module="owner"), None
        )
        == "meta skgid 100"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("gid-owner", PreNegated("100"), module="owner"),
            None,
        )
        == "meta skgid != 100"
    )
    with pytest.raises(FermError, match=r"^unknown user 'nosuchuser-xyz'"):
        translate_match(
            Family.IP,
            _opt("uid-owner", "nosuchuser-xyz", module="owner"),
            None,
        )
    with pytest.raises(FermError, match=r"^unknown group 'nosuchgroup-xyz'"):
        translate_match(
            Family.IP,
            _opt("gid-owner", "nosuchgroup-xyz", module="owner"),
            None,
        )


def test_translate_match_length() -> None:
    assert (
        translate_match(
            Family.IP, _opt("length", "512", module="length"), None
        )
        == "meta length 512"
    )
    # the iptables colon range becomes nft's dash range
    assert (
        translate_match(
            Family.IP, _opt("length", "100:200", module="length"), None
        )
        == "meta length 100-200"
    )
    assert (
        translate_match(
            Family.IP, _opt("length", PreNegated("512"), module="length"), None
        )
        == "meta length != 512"
    )
    with pytest.raises(FermError, match=r"^invalid length 'abc'"):
        translate_match(
            Family.IP, _opt("length", "abc", module="length"), None
        )


def test_translate_match_arp_opcode() -> None:
    # numeric opcodes respell to the kernel-readback operation name; a
    # number nft knows no name for stays numeric
    assert (
        translate_match(Family.ARP, _opt("opcode", "1"), None)
        == "arp operation request"
    )
    assert (
        translate_match(Family.ARP, _opt("opcode", "2"), None)
        == "arp operation reply"
    )
    assert (
        translate_match(Family.ARP, _opt("opcode", "10"), None)
        == "arp operation nak"
    )
    assert (
        translate_match(Family.ARP, _opt("opcode", "5"), None)
        == "arp operation 5"
    )
    with pytest.raises(FermError, match=r"^invalid arp opcode 'bogus'"):
        translate_match(Family.ARP, _opt("opcode", "bogus"), None)


def test_translate_match_ttl() -> None:
    assert (
        translate_match(Family.IP, _opt("ttl-eq", "64", module="ttl"), None)
        == "ip ttl 64"
    )
    # the readback spells the comparators as > and <, not gt/lt
    assert (
        translate_match(Family.IP, _opt("ttl-gt", "64", module="ttl"), None)
        == "ip ttl > 64"
    )
    assert (
        translate_match(Family.IP, _opt("ttl-lt", "64", module="ttl"), None)
        == "ip ttl < 64"
    )
    with pytest.raises(FermError, match=r"^invalid ttl 'abc'"):
        translate_match(Family.IP, _opt("ttl-eq", "abc", module="ttl"), None)
    # ip6 has no ttl header field (xt_ttl is ip-only; hl is its ip6 twin)
    with pytest.raises(FermError, match=r"^option 'ttl-eq' not yet"):
        translate_match(Family.IP6, _opt("ttl-eq", "64", module="ttl"), None)


def test_translate_match_mac_source() -> None:
    # the readback lowercases MAC operands
    assert (
        translate_match(
            Family.IP,
            _opt("mac-source", "AA:BB:CC:DD:EE:FF", module="mac"),
            None,
        )
        == "ether saddr aa:bb:cc:dd:ee:ff"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("mac-source", Negated("aa:bb:cc:00:11:22"), module="mac"),
            None,
        )
        == "ether saddr != aa:bb:cc:00:11:22"
    )
    with pytest.raises(FermError, match=r"^invalid mac 'nota-mac'"):
        translate_match(
            Family.IP, _opt("mac-source", "nota-mac", module="mac"), None
        )


def test_translate_match_arp_macs() -> None:
    # the arp family spells MAC selectors arp saddr/daddr ether, unlike
    # mod mac's ether saddr in the ip families
    assert (
        translate_match(
            Family.ARP, _opt("source-mac", "AA:BB:CC:DD:EE:FF"), None
        )
        == "arp saddr ether aa:bb:cc:dd:ee:ff"
    )
    assert (
        translate_match(
            Family.ARP,
            _opt("destination-mac", Negated("aa:bb:cc:dd:ee:00")),
            None,
        )
        == "arp daddr ether != aa:bb:cc:dd:ee:00"
    )


def test_translate_match_full_mask_mark_is_plain() -> None:
    # (mark & 0xffffffff) == value IS the plain equality; a partial mask
    # spells the infix bitwise form instead
    assert (
        translate_match(
            Family.IP, _opt("mark", "2/0xffffffff", module="mark"), None
        )
        == "meta mark 0x00000002"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("mark", "0xffffffff/4294967295", module="connmark"),
            None,
        )
        == "ct mark 0xffffffff"
    )
    assert (
        translate_match(Family.IP, _opt("mark", "2/0xff", module="mark"), None)
        == "meta mark & 0x000000ff == 0x00000002"
    )


def test_translate_match_value_shape_error_names_the_option() -> None:
    # the bare unwrap_value message left corpus refusals anonymous
    # ("unsupported value shape..."); the option name makes the gap
    # actionable
    with pytest.raises(
        FermError, match=r"^option 'ctstate': multi-value cannot"
    ):
        translate_match(
            Family.IP,
            _opt(
                "ctstate", Params(values=["NEW", "SNAT"]), module="conntrack"
            ),
            None,
        )


def test_build_verdict_connmark() -> None:
    save = {"save-mark": _opt("save-mark", None, module="CONNMARK")}
    assert (
        build_verdict(Family.IP, "mangle", "jump", "CONNMARK", save).to_text()
        == "ct mark set meta mark"
    )
    restore = {"restore-mark": _opt("restore-mark", None, module="CONNMARK")}
    assert (
        build_verdict(
            Family.IP, "mangle", "jump", "CONNMARK", restore
        ).to_text()
        == "meta mark set ct mark"
    )
    setmark = {"set-mark": _opt("set-mark", "2", module="CONNMARK")}
    assert (
        build_verdict(
            Family.IP, "mangle", "jump", "CONNMARK", setmark
        ).to_text()
        == "ct mark set 0x00000002"
    )
    # save/restore with a mask moves bits between two masked registers,
    # which nft cannot express; refuse rather than drop it
    masked = {
        "save-mark": _opt("save-mark", None, module="CONNMARK"),
        "nfmask": _opt("nfmask", "0xff", module="CONNMARK"),
    }
    with pytest.raises(FermError, match=r"mixes two masked registers"):
        build_verdict(Family.IP, "mangle", "jump", "CONNMARK", masked)
    with pytest.raises(FermError, match=r"^CONNMARK target not yet supported"):
        build_verdict(Family.IP, "mangle", "jump", "CONNMARK", {})


def test_translate_match_mark_and_connmark() -> None:
    # the kernel readback respells a mark as 8-digit hex; emitting any
    # other spelling would leave --plan diffing forever
    assert (
        translate_match(Family.IP, _opt("mark", "2", module="mark"), None)
        == "meta mark 0x00000002"
    )
    assert (
        translate_match(Family.IP, _opt("mark", "0x10", module="mark"), None)
        == "meta mark 0x00000010"
    )
    assert (
        translate_match(
            Family.IP, _opt("mark", Negated("3"), module="mark"), None
        )
        == "meta mark != 0x00000003"
    )
    # mod connmark spells its option `mark` too; the module tells the
    # ct mark selector apart from the packet-mark one
    assert (
        translate_match(Family.IP, _opt("mark", "2", module="connmark"), None)
        == "ct mark 0x00000002"
    )
    # a partial mask spells the infix bitwise form (readback canon:
    # 8-digit hex on both operands, `!=` under negation)
    assert (
        translate_match(
            Family.IP, _opt("mark", "2/0xff", module="connmark"), None
        )
        == "ct mark & 0x000000ff == 0x00000002"
    )
    assert (
        translate_match(
            Family.IP, _opt("mark", Negated("0x1/0x3"), module="mark"), None
        )
        == "meta mark & 0x00000003 != 0x00000001"
    )
    with pytest.raises(FermError, match=r"^invalid mark 'banana'"):
        translate_match(Family.IP, _opt("mark", "banana", module="mark"), None)
    with pytest.raises(FermError, match=r"^invalid mark 'banana/0xff'"):
        translate_match(
            Family.IP, _opt("mark", "banana/0xff", module="mark"), None
        )
    with pytest.raises(FermError, match=r"^invalid mark '0x1ffffffff/0xff'"):
        translate_match(
            Family.IP, _opt("mark", "0x1ffffffff/0xff", module="mark"), None
        )


def test_build_verdict_tcpmss() -> None:
    clamp = {
        "clamp-mss-to-pmtu": _opt("clamp-mss-to-pmtu", None, module="TCPMSS")
    }
    assert (
        build_verdict(Family.IP, "mangle", "jump", "TCPMSS", clamp).to_text()
        == "tcp option maxseg size set rt mtu"
    )
    setmss = {"set-mss": _opt("set-mss", "1400", module="TCPMSS")}
    assert (
        build_verdict(Family.IP, "mangle", "jump", "TCPMSS", setmss).to_text()
        == "tcp option maxseg size set 1400"
    )
    with pytest.raises(FermError, match=r"^TCPMSS target not yet supported"):
        build_verdict(Family.IP, "mangle", "jump", "TCPMSS", {})
    with pytest.raises(FermError, match=r"^invalid set-mss 'abc'"):
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "TCPMSS",
            {"set-mss": _opt("set-mss", "abc", module="TCPMSS")},
        )


def test_build_verdict_tee_notrack_trace() -> None:
    tee = {"gateway": _opt("gateway", "10.0.0.2", module="TEE")}
    assert (
        build_verdict(Family.IP, "mangle", "jump", "TEE", tee).to_text()
        == "dup to 10.0.0.2"
    )
    with pytest.raises(FermError, match=r"^TEE target not yet supported"):
        build_verdict(Family.IP, "mangle", "jump", "TEE", {})
    assert (
        build_verdict(Family.IP, "raw", "jump", "NOTRACK", {}).to_text()
        == "notrack"
    )
    assert (
        build_verdict(Family.IP, "raw", "jump", "TRACE", {}).to_text()
        == "meta nftrace set 1"
    )


def test_build_verdict_mark_target() -> None:
    comp = {"set-mark": _opt("set-mark", "2", module="MARK")}
    assert (
        build_verdict(Family.IP, "mangle", "jump", "MARK", comp).to_text()
        == "meta mark set 0x00000002"
    )
    # --set-xmark with a full mask (or none: the xt default) clears the
    # old bits first, so the xor writes the value verbatim
    for scalar in ("0xffffffff/0xffffffff", "0x2/0xffffffff", "0x2"):
        xmark = {"set-xmark": _opt("set-xmark", scalar, module="MARK")}
        expected = f"meta mark set 0x{int(scalar.partition('/')[0], 0):08x}"
        assert (
            build_verdict(Family.IP, "mangle", "jump", "MARK", xmark).to_text()
            == expected
        )
    # a partial mask now folds to the readback and/or canon (batch 7):
    # A = ~mask | value, so the AND operand already carries the value bits
    xmark = {"set-xmark": _opt("set-xmark", "0x2/0xff", module="MARK")}
    assert (
        build_verdict(Family.IP, "mangle", "jump", "MARK", xmark).to_text()
        == "meta mark set meta mark & 0xffffff02 | 0x00000002"
    )
    # both spellings at once cannot be ordered; refuse
    both = {
        "set-mark": _opt("set-mark", "2", module="MARK"),
        "set-xmark": _opt("set-xmark", "3", module="MARK"),
    }
    with pytest.raises(FermError, match=r"^MARK target not yet supported"):
        build_verdict(Family.IP, "mangle", "jump", "MARK", both)
    with pytest.raises(FermError, match=r"^MARK target not yet supported"):
        build_verdict(Family.IP, "mangle", "jump", "MARK", {})


def test_translate_match_ctstate_reuses_ct_state() -> None:
    # mod conntrack ctstate is the same nft `ct state` expression the
    # state module already translates to.
    assert (
        translate_match(
            Family.IP,
            _opt("ctstate", "ESTABLISHED,RELATED", module="conntrack"),
            None,
        )
        == "ct state established,related"
    )
    # SNAT/DNAT are ct STATUS bits; alone they translate, but a list
    # mixing them with real states is one OR across both registers,
    # which no single nft rule can spell
    assert (
        translate_match(
            Family.IP, _opt("ctstate", "DNAT", module="conntrack"), None
        )
        == "ct status dnat"
    )
    with pytest.raises(FermError, match=r"mixing connection states"):
        translate_match(
            Family.IP, _opt("ctstate", "NEW,SNAT", module="conntrack"), None
        )
    with pytest.raises(FermError, match=r"^unknown ct state 'banana'"):
        translate_match(
            Family.IP, _opt("ctstate", "NEW,BANANA", module="conntrack"), None
        )


@pytest.mark.parametrize(
    ("name", "scalar", "protocol", "expected"),
    [
        (
            "destination-ports",
            "80,443,8000:8080",
            "tcp",
            "tcp dport { 80, 443, 8000-8080 }",
        ),
        ("destination-ports", "80", "tcp", "tcp dport 80"),
        ("source-ports", "53,123", "udp", "udp sport { 53, 123 }"),
    ],
)
def test_translate_match_multiport(
    name: str, scalar: str, protocol: str, expected: str
) -> None:
    assert (
        translate_match(
            Family.IP, _opt(name, scalar, module="multiport"), protocol
        )
        == expected
    )


def test_translate_match_multiport_negation_and_errors() -> None:
    assert (
        translate_match(
            Family.IP,
            _opt("destination-ports", Negated("80,443"), module="multiport"),
            "tcp",
        )
        == "tcp dport != { 80, 443 }"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("source-ports", Negated("53,123"), module="multiport"),
            "udp",
        )
        == "udp sport != { 53, 123 }"
    )
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        translate_match(Family.IP, _opt("destination-ports", "80,443"), None)
    # a service NAME is a legitimate port operand (nft: `tcp dport ssh`),
    # so the invalid member must be metacharacter-shaped
    with pytest.raises(FermError, match=r"^invalid port"):
        translate_match(
            Family.IP, _opt("destination-ports", "80,bad;port"), "tcp"
        )
    # `ports` matches source OR destination; there is no single nft
    # match for that disjunction
    with pytest.raises(FermError, match=r"^option 'ports' not yet"):
        translate_match(Family.IP, _opt("ports", "80"), "tcp")


def test_match_parts_icmp_type_is_not_set_eligible() -> None:
    # Bare-word elements have no canonical rank in sort_set_elements
    # (unparsable stays in input order), so a folded { echo-request,
    # echo-reply } set could not converge under --plan; keep the match
    # out of the collapse pass until the canon learns that rank.
    from pyferm.backend.nft import _translate_match_parts

    expr, key, element = _translate_match_parts(
        Family.IP, _opt("icmp-type", "echo-request"), "icmp"
    )
    assert (expr, key, element) == ("icmp type echo-request", None, None)


def test_icmp_name_and_number_tables_agree() -> None:
    # _ICMP*_TYPE_MAP (iptables name -> nft name) and
    # _ICMP*_TYPE_BY_NUMBER (numeric operand -> readback name) are two
    # hand-maintained dictionaries; a type reachable both ways must emit
    # ONE canonical spelling, or `icmp-type redirect` and `icmp-type 5`
    # translate to different text.  The IANA type numbers below are the
    # linkage between them.
    from pyferm.backend.nft import (
        _ICMP6_TYPE_BY_NUMBER,
        _ICMP6_TYPE_MAP,
        _ICMP_TYPE_BY_NUMBER,
        _ICMP_TYPE_MAP,
    )

    iana_v4 = {
        "echo-reply": 0,
        "destination-unreachable": 3,
        "source-quench": 4,
        "redirect": 5,
        "echo-request": 8,
        "router-advertisement": 9,
        "router-solicitation": 10,
        "time-exceeded": 11,
        "parameter-problem": 12,
        "timestamp-request": 13,
        "timestamp-reply": 14,
        "address-mask-request": 17,
        "address-mask-reply": 18,
    }
    iana_v6 = {
        "destination-unreachable": 1,
        "packet-too-big": 2,
        "time-exceeded": 3,
        "parameter-problem": 4,
        "echo-request": 128,
        "echo-reply": 129,
        "nd-router-solicit": 133,
        "nd-router-advert": 134,
        "nd-neighbor-solicit": 135,
        "nd-neighbor-advert": 136,
        "nd-redirect": 137,
    }
    for name_map, by_number, iana in (
        (_ICMP_TYPE_MAP, _ICMP_TYPE_BY_NUMBER, iana_v4),
        (_ICMP6_TYPE_MAP, _ICMP6_TYPE_BY_NUMBER, iana_v6),
    ):
        for nft_name in name_map.values():
            assert nft_name in iana, (
                f"extend this test's IANA linkage for '{nft_name}'"
            )
            assert by_number[iana[nft_name]] == nft_name, nft_name


# ---------------------------------------------------------------------------
# translate_match structured split (_translate_match_parts)
# ---------------------------------------------------------------------------
from pyferm.backend.nft import _translate_match_parts  # noqa: E402


def test_match_parts_port_is_eligible() -> None:
    expr, key, element = _translate_match_parts(
        Family.IP, _opt("dport", "22"), "tcp"
    )
    assert (expr, key, element) == ("tcp dport 22", "tcp dport", "22")


def test_match_parts_address_is_eligible() -> None:
    expr, key, element = _translate_match_parts(
        Family.IP, _opt("source", "10.0.0.1"), None
    )
    assert (expr, key, element) == (
        "ip saddr 10.0.0.1",
        "ip saddr",
        "10.0.0.1",
    )


def test_match_parts_negated_is_not_eligible() -> None:
    expr, key, element = _translate_match_parts(
        Family.IP, _opt("dport", Negated("23")), "tcp"
    )
    assert (key, element) == (None, None)
    assert expr == "tcp dport != 23"


def test_match_parts_state_is_not_eligible() -> None:
    _expr, key, element = _translate_match_parts(
        Family.IP, _opt("state", "NEW", module="state"), None
    )
    assert (key, element) == (None, None)


def test_match_parts_expr_matches_translate_match_wrapper() -> None:
    # The wrapper must never drift from the parts' expr.
    opt = _opt("dport", "1024-2048")
    assert _translate_match_parts(Family.IP, opt, "tcp")[0] == translate_match(
        Family.IP, opt, "tcp"
    )


# ---------------------------------------------------------------------------
# build_verdict
# ---------------------------------------------------------------------------
from pyferm.backend.nft import build_verdict  # noqa: E402


def test_build_verdict_core_targets() -> None:
    def _v(target: str) -> str:
        return build_verdict(Family.IP, "filter", "jump", target, {}).to_text()

    assert _v("ACCEPT") == "accept"
    assert _v("DROP") == "drop"
    assert _v("RETURN") == "return"
    assert _v("QUEUE") == "queue"
    assert _v("MASQUERADE") == "masquerade"


def test_build_verdict_jump_goto_to_chain() -> None:
    assert (
        build_verdict(Family.IP, "filter", "jump", "mychain", {}).to_text()
        == "jump mychain"
    )
    assert (
        build_verdict(Family.IP, "nat", "goto", "mychain", {}).to_text()
        == "goto nat_mychain"
    )


def test_build_verdict_reject_with_companion() -> None:
    companions = {
        "reject-with": _opt(
            "reject-with", "icmp-port-unreachable", module="REJECT"
        )
    }
    result = build_verdict(
        Family.IP, "filter", "jump", "REJECT", companions
    ).to_text()
    assert result == "reject with icmp type port-unreachable"
    companions6 = {
        "reject-with": _opt(
            "reject-with", "icmp6-port-unreachable", module="REJECT"
        )
    }
    result6 = build_verdict(
        Family.IP6, "filter", "jump", "REJECT", companions6
    ).to_text()
    assert result6 == "reject with icmpv6 type port-unreachable"
    assert (
        build_verdict(Family.IP, "filter", "jump", "REJECT", {}).to_text()
        == "reject"
    )


def test_build_verdict_nat_and_log() -> None:
    snat = {
        "to-source": _opt(
            "to-source", Multi(values=["1.2.3.4"]), module="SNAT"
        )
    }
    assert (
        build_verdict(Family.IP, "nat", "jump", "SNAT", snat).to_text()
        == "snat to 1.2.3.4"
    )
    dnat = {
        "to-destination": _opt(
            "to-destination", Multi(values=["10.0.0.5"]), module="DNAT"
        )
    }
    assert (
        build_verdict(Family.IP, "nat", "jump", "DNAT", dnat).to_text()
        == "dnat to 10.0.0.5"
    )
    log = {"log-prefix": _opt("log-prefix", "DROP: ", module="LOG")}
    assert (
        build_verdict(Family.IP, "filter", "jump", "LOG", log).to_text()
        == 'log prefix "DROP: "'
    )
    assert (
        build_verdict(Family.IP, "filter", "jump", "LOG", {}).to_text()
        == "log"
    )


def test_build_verdict_uncovered_target_is_error() -> None:
    with pytest.raises(
        FermError, match=r"^SNAT target not yet supported by nft backend$"
    ):
        build_verdict(Family.IP, "nat", "jump", "SNAT", {})
    with pytest.raises(
        FermError, match=r"^DNAT target not yet supported by nft backend$"
    ):
        build_verdict(Family.IP, "nat", "jump", "DNAT", {})


def test_build_verdict_eb_target_keywords_are_refused() -> None:
    # The ebtables target keywords share companion names with the inet
    # NAT targets (to-source/to-destination), so without the explicit
    # guard they would fall through to the user-chain branch, swallow
    # the companion and emit a jump to a chain that never exists.
    comp = {"to-source": _opt("to-source", "aa:bb:cc:00:11:22")}
    with pytest.raises(
        FermError, match=r"^eb target 'snat' \(or jump to a chain"
    ):
        build_verdict(Family.EB, "nat", "jump", "snat", comp)
    with pytest.raises(
        FermError, match=r"^eb target 'redirect' \(or jump to a chain"
    ):
        build_verdict(Family.EB, "broute", "jump", "redirect", {})
    # MARK is the one eb keyword that collides with the ip/ip6 MARK
    # target handled ABOVE the eb guard; if the guard's domain check
    # broke, this exact shape (companion present) would silently emit
    # `meta mark set ...` instead of refusing -- and the registry sweep
    # below cannot see that, since it passes empty companions.
    with pytest.raises(
        FermError, match=r"^eb target 'MARK' \(or jump to a chain"
    ):
        build_verdict(
            Family.EB,
            "filter",
            "jump",
            "MARK",
            {"set-mark": _opt("set-mark", "0x2", module="MARK")},
        )
    # an actual user chain in the eb domain still translates
    verdict = build_verdict(Family.EB, "filter", "jump", "mychain", {})
    assert verdict.to_text() == "jump mychain"


@pytest.mark.parametrize(
    ("domain", "target"),
    [
        (Family.IP, "TARPIT"),
        (Family.IP, "MIRROR"),
        (Family.IP, "SET"),
        (Family.IP, "AUDIT"),
        # HL translates only under ip6 (its xt family); the ip pass must
        # keep refusing via the folded "ip" registry (parser convention)
        (Family.IP, "HL"),
        (Family.IP6, "TARPIT"),
    ],
)
def test_build_verdict_extension_target_keywords_are_refused(
    domain: Family, target: str
) -> None:
    # A registered target keyword with no nft translation must refuse at
    # translate time; the user-chain fallthrough would emit a jump to a
    # chain that never exists, which `nft -f` rejects only at apply time
    # while --test/--noexec --lines report success.
    with pytest.raises(
        FermError,
        match=rf"^target '{target}' \(or jump to a chain of that name\)"
        r" not yet supported by nft backend$",
    ):
        build_verdict(domain, "filter", "jump", target, {})


def test_build_verdict_never_jumps_to_a_registered_target() -> None:
    # Total sweep over the target registry (the 2026-07-09 ad-hoc probe,
    # formalized): whatever build_verdict does with a registered target
    # keyword -- translate or refuse -- it must never emit a jump/goto
    # carrying the keyword as a chain name.
    from pyferm.modules import TARGET_DEFS

    for defs_family, domain in (
        ("ip", Family.IP),
        ("ip", Family.IP6),
        ("arp", Family.ARP),
        ("eb", Family.EB),
    ):
        for target in TARGET_DEFS.get(defs_family, {}):
            try:
                verdict = build_verdict(domain, "filter", "jump", target, {})
            except FermError:
                continue
            text = verdict.to_text()
            assert not text.startswith(("jump ", "goto ")), (
                f"{domain}: registered target '{target}' emitted '{text}'"
            )


def test_build_verdict_user_chain_named_like_no_target_still_jumps() -> None:
    # The guard reads the target registry, not a name heuristic: an
    # ordinary user chain keeps translating.
    verdict = build_verdict(Family.IP, "filter", "jump", "LOGDROP", {})
    assert verdict.to_text() == "jump LOGDROP"


def test_build_verdict_log_level() -> None:
    log = {
        "log-prefix": _opt("log-prefix", "x: ", module="LOG"),
        "log-level": _opt("log-level", "info", module="LOG"),
    }
    assert (
        build_verdict(Family.IP, "filter", "jump", "LOG", log).to_text()
        == 'log prefix "x: " level info'
    )
    # iptables' syslog spellings map to nft's (error -> err); numeric
    # levels resolve through the same syslog table
    for scalar in ("error", "3"):
        level = {"log-level": _opt("log-level", scalar, module="LOG")}
        assert (
            build_verdict(Family.IP, "filter", "jump", "LOG", level).to_text()
            == "log level err"
        )
    # `warn` is nft's default and the kernel readback drops it -- emit
    # the bare statement or --plan never converges
    for scalar in ("warning", "4"):
        level = {"log-level": _opt("log-level", scalar, module="LOG")}
        assert (
            build_verdict(Family.IP, "filter", "jump", "LOG", level).to_text()
            == "log"
        )
    with pytest.raises(FermError, match=r"^log-level 'chatty' not yet"):
        build_verdict(
            Family.IP,
            "filter",
            "jump",
            "LOG",
            {"log-level": _opt("log-level", "chatty", module="LOG")},
        )


def test_build_verdict_nflog() -> None:
    # NFLOG is nft's `log group N`; fields follow the kernel readback
    # order of prefix, then group, then queue-threshold
    group = {"nflog-group": _opt("nflog-group", "2", module="NFLOG")}
    assert (
        build_verdict(Family.IP, "filter", "jump", "NFLOG", group).to_text()
        == "log group 2"
    )
    full = {
        "nflog-group": _opt("nflog-group", "2", module="NFLOG"),
        "nflog-prefix": _opt("nflog-prefix", "y: ", module="NFLOG"),
        "nflog-threshold": _opt("nflog-threshold", "20", module="NFLOG"),
    }
    assert (
        build_verdict(Family.IP, "filter", "jump", "NFLOG", full).to_text()
        == 'log prefix "y: " group 2 queue-threshold 20'
    )
    # xt_NFLOG defaults to group 0 when none is given
    assert (
        build_verdict(Family.IP, "filter", "jump", "NFLOG", {}).to_text()
        == "log group 0"
    )
    # --nflog-range is accepted-but-ignored by the kernel; there is no
    # honest nft spelling for it
    with pytest.raises(FermError, match=r"^option 'nflog-range' not yet"):
        build_verdict(
            Family.IP,
            "filter",
            "jump",
            "NFLOG",
            {"nflog-range": _opt("nflog-range", "64", module="NFLOG")},
        )
    with pytest.raises(FermError, match=r"^invalid nflog-group 'x'"):
        build_verdict(
            Family.IP,
            "filter",
            "jump",
            "NFLOG",
            {"nflog-group": _opt("nflog-group", "x", module="NFLOG")},
        )


def test_build_verdict_unsupported_reject_with_is_error() -> None:
    comp = {
        "reject-with": _opt("reject-with", "bogus-reject", module="REJECT")
    }
    with pytest.raises(
        FermError,
        match=r"^reject-with 'bogus-reject' not yet supported by nft "
        r"backend$",
    ):
        build_verdict(Family.IP, "filter", "jump", "REJECT", comp)


from pyferm.backend.nft import _reject_for  # noqa: E402


@pytest.mark.parametrize(
    ("domain", "scalar", "expected"),
    [
        # -- ip: the full _REJECT_WITH map
        (
            "ip",
            "icmp-port-unreachable",
            "reject with icmp type port-unreachable",
        ),
        (
            "ip",
            "icmp-net-unreachable",
            "reject with icmp type net-unreachable",
        ),
        (
            "ip",
            "icmp-host-unreachable",
            "reject with icmp type host-unreachable",
        ),
        (
            "ip",
            "icmp-admin-prohibited",
            "reject with icmp type admin-prohibited",
        ),
        ("ip", "tcp-reset", "reject with tcp reset"),
        # -- ip6: the native icmp6 spellings
        (
            "ip6",
            "icmp6-port-unreachable",
            "reject with icmpv6 type port-unreachable",
        ),
        ("ip6", "icmp6-no-route", "reject with icmpv6 type no-route"),
        (
            "ip6",
            "icmp6-adm-prohibited",
            "reject with icmpv6 type admin-prohibited",
        ),
        (
            "ip6",
            "icmp6-addr-unreachable",
            "reject with icmpv6 type addr-unreachable",
        ),
        ("ip6", "tcp-reset", "reject with tcp reset"),
        # -- ip6: ip4 reject names remapped to icmp6 (the oracle's aliases)
        ("ip6", "icmp-net-unreachable", "reject with icmpv6 type no-route"),
        (
            "ip6",
            "icmp-host-unreachable",
            "reject with icmpv6 type addr-unreachable",
        ),
        (
            "ip6",
            "icmp-host-prohibited",
            "reject with icmpv6 type admin-prohibited",
        ),
        (
            "ip6",
            "icmp-net-prohibited",
            "reject with icmpv6 type admin-prohibited",
        ),
        (
            "ip6",
            "icmp-port-unreachable",
            "reject with icmpv6 type port-unreachable",
        ),
        # -- ip: the canonical types Phase 5 added (nft 'prot', not 'proto')
        (
            "ip",
            "icmp-proto-unreachable",
            "reject with icmp type prot-unreachable",
        ),
        ("ip", "icmp-net-prohibited", "reject with icmp type net-prohibited"),
        (
            "ip",
            "icmp-host-prohibited",
            "reject with icmp type host-prohibited",
        ),
        # -- ip6: the canonical types Phase 5 added
        ("ip6", "icmp6-policy-fail", "reject with icmpv6 type policy-fail"),
        ("ip6", "icmp6-reject-route", "reject with icmpv6 type reject-route"),
        # -- ip: short aliases resolve to the same nft spec as the canonical
        ("ip", "net-unreach", "reject with icmp type net-unreachable"),
        ("ip", "proto-unreach", "reject with icmp type prot-unreachable"),
        ("ip", "host-prohib", "reject with icmp type host-prohibited"),
        ("ip", "admin-prohib", "reject with icmp type admin-prohibited"),
        ("ip", "tcp-rst", "reject with tcp reset"),
        # -- ip6: short aliases resolve to the icmpv6 spec
        ("ip6", "no-route", "reject with icmpv6 type no-route"),
        ("ip6", "adm-prohibited", "reject with icmpv6 type admin-prohibited"),
        ("ip6", "addr-unreach", "reject with icmpv6 type addr-unreachable"),
        ("ip6", "port-unreach", "reject with icmpv6 type port-unreachable"),
        ("ip6", "policy-fail", "reject with icmpv6 type policy-fail"),
        ("ip6", "reject-route", "reject with icmpv6 type reject-route"),
    ],
)
def test_reject_for_covers_the_full_mapping(
    domain: Family, scalar: str, expected: str
) -> None:
    assert _reject_for(domain, scalar) == expected


def test_build_verdict_jump_to_builtin_is_error() -> None:
    with pytest.raises(FermError, match="built-in chain 'INPUT'"):
        build_verdict(Family.IP, "filter", "jump", "INPUT", {})


def test_build_verdict_masquerade_to_ports() -> None:
    comp = {
        "to-ports": _opt(
            "to-ports", Multi(values=["1024-2048"]), module="MASQUERADE"
        )
    }
    assert (
        build_verdict(
            Family.IP, "nat", "jump", "MASQUERADE", comp, has_transport=True
        ).to_text()
        == "masquerade to :1024-2048"
    )


def test_build_verdict_port_nat_without_transport_is_error() -> None:
    # finding C1: nft rejects an `... to <addr>:<port>` mapping that has no
    # preceding transport match, so fail at translate time instead of
    # emitting a script that nft would reject at apply (forcing a rollback).
    masq = {
        "to-ports": _opt(
            "to-ports", Multi(values=["1024-2048"]), module="MASQUERADE"
        )
    }
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        build_verdict(Family.IP, "nat", "jump", "MASQUERADE", masq)
    redir = {
        "to-ports": _opt("to-ports", Multi(values=["8080"]), module="REDIRECT")
    }
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        build_verdict(Family.IP, "nat", "jump", "REDIRECT", redir)
    snat = {
        "to-source": _opt(
            "to-source", Multi(values=["1.2.3.4:1024"]), module="SNAT"
        )
    }
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        build_verdict(Family.IP, "nat", "jump", "SNAT", snat)
    dnat = {
        "to-destination": _opt(
            "to-destination", Multi(values=["10.0.0.1:8080"]), module="DNAT"
        )
    }
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        build_verdict(Family.IP, "nat", "jump", "DNAT", dnat)


def test_build_verdict_port_nat_with_transport_renders() -> None:
    # With a transport match established the port mapping is valid nft.
    redir = {
        "to-ports": _opt("to-ports", Multi(values=["8080"]), module="REDIRECT")
    }
    assert (
        build_verdict(
            Family.IP, "nat", "jump", "REDIRECT", redir, has_transport=True
        ).to_text()
        == "redirect to :8080"
    )
    dnat = {
        "to-destination": _opt(
            "to-destination", Multi(values=["10.0.0.1:8080"]), module="DNAT"
        )
    }
    assert (
        build_verdict(
            Family.IP, "nat", "jump", "DNAT", dnat, has_transport=True
        ).to_text()
        == "dnat to 10.0.0.1:8080"
    )


def test_build_verdict_portless_nat_needs_no_transport() -> None:
    # A port-less NAT target (the common case) is valid without a transport
    # match -- only the `:port` form triggers the C1 guard.
    snat = {
        "to-source": _opt(
            "to-source", Multi(values=["1.2.3.4"]), module="SNAT"
        )
    }
    assert (
        build_verdict(Family.IP, "nat", "jump", "SNAT", snat).to_text()
        == "snat to 1.2.3.4"
    )


def test_build_verdict_ip6_portless_nat_renders_without_transport() -> None:
    # An IPv6 NAT host carries its own colons; `_nat_has_port` must NOT treat
    # them as a port, or a plain `dnat to fe80::1` would falsely require a
    # transport match (decision C1).
    plain = {
        "to-destination": _opt(
            "to-destination", Multi(values=["fe80::1"]), module="DNAT"
        )
    }
    assert (
        build_verdict(Family.IP6, "nat", "jump", "DNAT", plain).to_text()
        == "dnat to fe80::1"
    )


def test_build_verdict_ip6_portless_snat_renders_without_transport() -> None:
    # Mirror of the DNAT ip6 case on the SNAT path: the host's own colons
    # must not be read as a port, so the family-aware `_nat_has_port` check
    # must see the real domain (a `None`-substituted domain would mistake the
    # colons for a port and falsely demand a transport match).
    plain = {
        "to-source": _opt(
            "to-source", Multi(values=["fe80::1"]), module="SNAT"
        )
    }
    assert (
        build_verdict(Family.IP6, "nat", "jump", "SNAT", plain).to_text()
        == "snat to fe80::1"
    )


def test_nat_has_port_is_family_aware() -> None:
    # IPv4: any `:` is the port separator.  IPv6: the host's own colons do
    # not count -- only a bracketed `]:port` does (decision C1).  The
    # bracketed form is unreachable through build_verdict (the `[`/`]` fail
    # address validation first), so this pins the discriminator directly.
    from pyferm.backend.nft import _nat_has_port

    assert _nat_has_port(Family.IP, "1.2.3.4:1024") is True
    assert _nat_has_port(Family.IP, "1.2.3.4") is False
    assert _nat_has_port(Family.IP6, "fe80::1") is False
    assert _nat_has_port(Family.IP6, "[fe80::1]:80") is True


def test_build_verdict_ip6_reject_accepts_ip4_spelling() -> None:
    comp = {
        "reject-with": _opt(
            "reject-with", "icmp-port-unreachable", module="REJECT"
        )
    }
    assert (
        build_verdict(Family.IP6, "filter", "jump", "REJECT", comp).to_text()
        == "reject with icmpv6 type port-unreachable"
    )


def test_build_verdict_log_prefix_bare_keyword_is_quoted() -> None:
    """A log prefix that is itself an nft keyword must be double-quoted.

    nft's grammar requires a quoted string after ``log prefix``; emitting a
    bare word such as ``drop`` or ``tcp`` is syntactically invalid/ambiguous.
    Regression for the bug where ``nft_quote`` returned the text unquoted when
    it matched ``_NFT_BARE_RE``.
    """
    # Bare keyword "drop" -- previously emitted as unquoted `log prefix drop`.
    log_drop = {"log-prefix": _opt("log-prefix", "drop", module="LOG")}
    assert (
        build_verdict(Family.IP, "filter", "jump", "LOG", log_drop).to_text()
        == 'log prefix "drop"'
    )
    # Bare number "22" -- also matches the bare-word regex.
    log_num = {"log-prefix": _opt("log-prefix", "22", module="LOG")}
    assert (
        build_verdict(Family.IP, "filter", "jump", "LOG", log_num).to_text()
        == 'log prefix "22"'
    )
    # Space-containing prefix was already quoted; confirm it still is.
    log_space = {"log-prefix": _opt("log-prefix", "drop: ", module="LOG")}
    assert (
        build_verdict(Family.IP, "filter", "jump", "LOG", log_space).to_text()
        == 'log prefix "drop: "'
    )


# ---------------------------------------------------------------------------
# translate_rule
# ---------------------------------------------------------------------------
from pyferm.backend.nft import translate_rule  # noqa: E402
from pyferm.rules import RenderedRule  # noqa: E402


def _rule(*options: RenderedOption) -> RenderedRule:
    return RenderedRule(options=list(options), script=None)


def _target(value: str) -> RenderedOption:
    return _opt("jump", value, kind=OptionKind.TARGET)


def test_translate_rule_skips_match_module_marker() -> None:
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("match", "state", kind=OptionKind.MATCH_MODULE),
            _opt("state", "ESTABLISHED,RELATED", module="state"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "ct state established,related",
        "accept",
    ]


def test_translate_rule_bare_match_module_refuses() -> None:
    # A bare `mod hbh` / `mod dst` / `mod eui64` IS the match (extension
    # header presence, EUI-64 check); the iptables backend emits `-m hbh`,
    # so skipping the marker would silently widen the rule to all packets.
    for module in ("hbh", "dst", "eui64"):
        with pytest.raises(FermError, match=f"bare 'mod {module}'"):
            translate_rule(
                Family.IP6,
                "filter",
                _rule(
                    _opt("match", module, kind=OptionKind.MATCH_MODULE),
                    _target("ACCEPT"),
                ),
            )


def test_translate_rule_bare_limit_module_refuses() -> None:
    # xt_limit with zero flags is a REAL limiter (default rate 3/hour,
    # burst 5); dropping the marker would silently remove the rate limit.
    with pytest.raises(FermError, match="bare 'mod limit'"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("match", "limit", kind=OptionKind.MATCH_MODULE),
                _target("ACCEPT"),
            ),
        )


def test_translate_rule_bare_inert_module_still_skips() -> None:
    # xt_state/xt_conntrack accept zero flags and then match every packet,
    # so their bare load carries no semantics and the marker may drop.
    for module in ("state", "conntrack"):
        nft = translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("match", module, kind=OptionKind.MATCH_MODULE),
                _target("ACCEPT"),
            ),
        )
        assert [s.to_text() for s in nft.statements] == ["accept"]


def test_translate_rule_eb_mark_target_refuses() -> None:
    # The parser remaps eb MARK to ebtables' `mark` spelling before it
    # reaches the backend; the eb-target guard must catch the remapped
    # form instead of emitting a `jump mark` to a chain that never exists.
    with pytest.raises(FermError, match="eb target 'mark'"):
        translate_rule(
            Family.EB,
            "filter",
            _rule(
                _target("mark"),
                _opt("set-mark", "1", module="mark"),
            ),
        )


def test_translate_rule_port_suppresses_redundant_proto() -> None:
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("dport", "22"),
            _opt("source", "10.0.0.1"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "tcp dport 22",
        "ip saddr 10.0.0.1",
        "accept",
    ]


def test_translate_rule_icmp_type_suppresses_redundant_proto() -> None:
    # `icmp type` implies the l4proto dependency, and the kernel readback
    # omits the `meta l4proto icmp` prefix for such a rule -- emitting it
    # would leave --plan diffing an already-applied ruleset forever (the
    # same readback asymmetry ports handle via has_port).
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "icmp", kind=OptionKind.PROTO),
            _opt("icmp-type", "echo-request", module="icmp"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "icmp type echo-request",
        "accept",
    ]


def test_translate_rule_tcp_flags_suppresses_redundant_proto() -> None:
    # `tcp flags` elides `meta l4proto tcp` in the kernel readback, the
    # same asymmetry ports and icmp-type handle (verified live: a
    # maxseg-only rule KEEPS the prefix, so only the flags match
    # suppresses it).
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("syn", None, module="tcp"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "tcp flags & (fin | syn | rst | ack) == syn",
        "accept",
    ]


def test_translate_rule_limit_burst_pairs_with_limit() -> None:
    # `--limit-burst` is a companion of the SAME xt_limit match, not a
    # separate one; nft spells the pair as one statement (the kernel
    # readback always prints an explicit burst).
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("match", "limit", kind=OptionKind.MATCH_MODULE),
            _opt("limit", "5/second", module="limit"),
            _opt("limit-burst", "7", module="limit"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "limit rate 5/second burst 7 packets",
        "accept",
    ]


def test_translate_rule_limit_burst_without_limit_uses_default_rate() -> None:
    # iptables' `-m limit --limit-burst 7` keeps xt_limit's default rate
    # of 3/hour; the nft spelling makes that default explicit.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("match", "limit", kind=OptionKind.MATCH_MODULE),
            _opt("limit-burst", "7", module="limit"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "limit rate 3/hour burst 7 packets",
        "accept",
    ]


def test_translate_rule_invalid_limit_burst_is_error() -> None:
    for bad in ("0", "abc", "-1"):
        with pytest.raises(FermError, match=r"^invalid limit burst"):
            translate_rule(
                Family.IP,
                "filter",
                _rule(
                    _opt("limit", "5/second", module="limit"),
                    _opt("limit-burst", bad, module="limit"),
                    _target("ACCEPT"),
                ),
            )


def test_translate_rule_burst_with_multiple_limits_is_refused() -> None:
    # RenderedRule flattens xt_limit instances, so a burst cannot be
    # paired back with its own `limit`; refusing beats attaching one
    # burst to every limit statement (which mismatches xt_limit).
    with pytest.raises(
        FermError,
        match=r"^'limit-burst' with more than one 'limit' per rule",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("limit", "3/second", module="limit"),
                _opt("limit-burst", "5", module="limit"),
                _opt("limit", "10/minute", module="limit"),
                _target("ACCEPT"),
            ),
        )
    with pytest.raises(
        FermError, match=r"^more than one 'limit-burst' per rule"
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("limit", "3/second", module="limit"),
                _opt("limit-burst", "5", module="limit"),
                _opt("limit-burst", "8", module="limit"),
                _target("ACCEPT"),
            ),
        )


def test_translate_rule_two_limits_without_burst_translate() -> None:
    # Two burst-less xt_limit instances AND together; the ambiguity the
    # refusal above guards against only exists once a burst appears.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("limit", "3/second", module="limit"),
            _opt("limit", "10/minute", module="limit"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "limit rate 3/second",
        "limit rate 10/minute",
        "accept",
    ]


def test_translate_rule_multiport_setref_is_refused() -> None:
    # Named-set references are wired only for the flat addr/iface/port
    # selectors; through mod multiport the reference must refuse, not
    # fall through to a mistranslation.
    with pytest.raises(
        FermError,
        match=r"^option 'destination-ports' cannot reference a named set$",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("protocol", "tcp", kind=OptionKind.PROTO),
                _opt(
                    "destination-ports",
                    SetRef("ports", ["22"]),
                    module="multiport",
                ),
                _target("ACCEPT"),
            ),
        )


def test_translate_rule_bare_proto_emits_l4proto() -> None:
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "icmp", kind=OptionKind.PROTO),
            _target("DROP"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "meta l4proto icmp",
        "drop",
    ]


def test_translate_rule_ip6_icmp_normalized() -> None:
    nft = translate_rule(
        Family.IP6,
        "filter",
        _rule(
            _opt("protocol", "icmp", kind=OptionKind.PROTO),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "meta l4proto ipv6-icmp",
        "accept",
    ]


def test_nft_l4proto_ip6_icmp_spellings_normalize() -> None:
    # All three ICMP spellings must normalize to the proto-58 name under ip6
    # so `meta l4proto` matches ICMPv6, not proto 1.  Each spelling is
    # asserted so dropping one from the membership tuple is caught.
    from pyferm.backend.nft import _nft_l4proto

    assert _nft_l4proto(Family.IP6, "icmp") == "ipv6-icmp"
    assert _nft_l4proto(Family.IP6, "icmpv6") == "ipv6-icmp"
    assert _nft_l4proto(Family.IP6, "ipv6-icmp") == "ipv6-icmp"


def test_nft_l4proto_ip4_and_other_protos_pass_through() -> None:
    # The rewrite is ip6-only: ip4 keeps the raw `icmp`, and any non-ICMP
    # protocol is returned verbatim regardless of family.
    from pyferm.backend.nft import _nft_l4proto

    assert _nft_l4proto(Family.IP, "icmp") == "icmp"
    assert _nft_l4proto(Family.IP6, "tcp") == "tcp"


def test_translate_rule_protocol_injection_is_error() -> None:
    # A protocol operand carrying whitespace/`;`/`#`
    # would break out of `meta l4proto <value>` and flip a DROP into accept;
    # `nft -c` does not catch the `;#` form, so the ferm side must reject it.
    with pytest.raises(FermError, match="invalid protocol"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("protocol", "tcp accept;#", kind=OptionKind.PROTO),
                _target("DROP"),
            ),
        )
    # The same value must be rejected on the port-context path (a port match
    # pins the protocol scalar too), not only the `meta l4proto` emission.
    with pytest.raises(FermError, match="invalid protocol"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("protocol", "tcp accept", kind=OptionKind.PROTO),
                _opt("dport", "22"),
                _target("DROP"),
            ),
        )


def test_translate_rule_legit_protocols_render() -> None:
    # A numeric proto and a hyphenated service name are legitimate and must
    # still render (the protocol guard rejects metacharacters, not these).  A
    # known protocol number folds to the name the kernel stores it as (47 ->
    # gre) so
    # --plan does not show a phantom diff against the readback.
    numeric = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "47", kind=OptionKind.PROTO),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in numeric.statements] == [
        "meta l4proto gre",
        "accept",
    ]
    named = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "ipv6-icmp", kind=OptionKind.PROTO),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in named.statements] == [
        "meta l4proto ipv6-icmp",
        "accept",
    ]


def _addrtype(name: str, value: Value) -> RenderedOption:
    return _opt(name, value, module="addrtype")


def _fib_texts(domain: Family, *options: RenderedOption) -> list[str]:
    rule = translate_rule(domain, "filter", _rule(*options, _target("ACCEPT")))
    return [s.to_text() for s in rule.statements]


def test_translate_rule_addrtype_single_type() -> None:
    # dst-type/src-type pick the daddr/saddr fib selector; the iptables
    # LOCAL spelling reads back lowercase.
    assert _fib_texts(Family.IP, _addrtype("dst-type", "LOCAL")) == [
        "fib daddr type local",
        "accept",
    ]
    assert _fib_texts(Family.IP, _addrtype("src-type", "LOCAL")) == [
        "fib saddr type local",
        "accept",
    ]


def test_translate_rule_addrtype_comma_list_sorts_into_rtn_order() -> None:
    # a comma-list emits one anonymous literal pre-sorted into kernel RTN
    # order (local=2 before broadcast=3), matching the list readback.
    assert _fib_texts(Family.IP, _addrtype("dst-type", "BROADCAST,LOCAL")) == [
        "fib daddr type { local, broadcast }",
        "accept",
    ]


def test_translate_rule_addrtype_negation() -> None:
    assert _fib_texts(
        Family.IP, _addrtype("dst-type", PreNegated("LOCAL"))
    ) == ["fib daddr type != local", "accept"]
    # the kernel accepts a negated list and re-sorts it into RTN order too
    assert _fib_texts(
        Family.IP, _addrtype("src-type", PreNegated("broadcast,local,unspec"))
    ) == ["fib saddr type != { unspec, local, broadcast }", "accept"]


def test_translate_rule_addrtype_ip6() -> None:
    assert _fib_texts(Family.IP6, _addrtype("dst-type", "LOCAL")) == [
        "fib daddr type local",
        "accept",
    ]


@pytest.mark.parametrize("bad", ["NAT", "throw", "xresolve", "bogus"])
def test_translate_rule_addrtype_untranslatable_type_refused(
    bad: str,
) -> None:
    with pytest.raises(
        FermError,
        match=rf"^address type '{bad}' has no nft fib equivalent$",
    ):
        _fib_texts(Family.IP, _addrtype("dst-type", bad))


def test_translate_rule_addrtype_limit_iface_qualifies_selector() -> None:
    assert _fib_texts(
        Family.IP,
        _addrtype("dst-type", "LOCAL"),
        _addrtype("limit-iface-in", None),
    ) == ["fib daddr . iif type local", "accept"]
    assert _fib_texts(
        Family.IP,
        _addrtype("src-type", "LOCAL"),
        _addrtype("limit-iface-out", None),
    ) == ["fib saddr . oif type local", "accept"]


def test_translate_rule_addrtype_both_limit_iface_flags_refused() -> None:
    with pytest.raises(
        FermError,
        match=r"^'limit-iface-in' and 'limit-iface-out' are mutually",
    ):
        _fib_texts(
            Family.IP,
            _addrtype("dst-type", "LOCAL"),
            _addrtype("limit-iface-in", None),
            _addrtype("limit-iface-out", None),
        )


def test_translate_rule_addrtype_limit_iface_without_type_refused() -> None:
    with pytest.raises(
        FermError,
        match=r"needs a src-type or dst-type match",
    ):
        _fib_texts(Family.IP, _addrtype("limit-iface-in", None))


def test_translate_rule_addrtype_src_and_dst_type_emit_two_fibs() -> None:
    # --src-type X --dst-type Y is one legal iptables match -> two
    # independent fib expressions.
    assert _fib_texts(
        Family.IP,
        _addrtype("src-type", "LOCAL"),
        _addrtype("dst-type", "UNICAST"),
    ) == [
        "fib saddr type local",
        "fib daddr type unicast",
        "accept",
    ]
    # the limit-iface modifier applies to BOTH selectors.
    assert _fib_texts(
        Family.IP,
        _addrtype("src-type", "LOCAL"),
        _addrtype("dst-type", "UNICAST"),
        _addrtype("limit-iface-in", None),
    ) == [
        "fib saddr . iif type local",
        "fib daddr . iif type unicast",
        "accept",
    ]


def test_translate_rule_addrtype_arp_keeps_generic_refusal() -> None:
    # arp/eb have no fib translation; the type match falls through to the
    # generic refusal untouched, not a broken `fib` emission.
    with pytest.raises(
        FermError, match=r"^option 'dst-type' not yet supported"
    ):
        _fib_texts(Family.ARP, _addrtype("dst-type", "LOCAL"))


# ---------------------------------------------------------------------------
# QoS: dscp match, DSCP/CLASSIFY targets, tos/TOS refusal
# ---------------------------------------------------------------------------


def _dscp_match(domain: Family, name: str, value: Value) -> str:
    return translate_match(domain, _opt(name, value, module="dscp"), None)


@pytest.mark.parametrize(
    ("value", "spelled"),
    [
        ("0", "cs0"),
        ("1", "lephb"),
        ("0x2c", "va"),
        ("0x3f", "0x3f"),  # unnamed codepoint stays hex
        ("46", "ef"),  # decimal accepted via int(x, 0)
        ("63", "0x3f"),  # boundary ok, spells as hex
    ],
)
def test_translate_match_dscp_numeric_canon(value: str, spelled: str) -> None:
    assert _dscp_match(Family.IP, "dscp", value) == f"ip dscp {spelled}"


@pytest.mark.parametrize("bad", ["64", "-1", "0x40"])
def test_translate_match_dscp_out_of_range_refused(bad: str) -> None:
    with pytest.raises(FermError, match=r"dscp value .* out of range 0-63"):
        _dscp_match(Family.IP, "dscp", bad)


def test_translate_match_dscp_ip6_selector() -> None:
    assert _dscp_match(Family.IP6, "dscp", "0x2c") == "ip6 dscp va"


@pytest.mark.parametrize(
    ("given", "spelled"),
    [
        ("af31", "af31"),
        ("EF", "ef"),  # case-insensitive input
        ("be", "cs0"),  # best-effort resolves to 0x00 -> cs0
    ],
)
def test_translate_match_dscp_class_canon(given: str, spelled: str) -> None:
    assert _dscp_match(Family.IP, "dscp-class", given) == f"ip dscp {spelled}"


def test_translate_match_dscp_class_bogus_refused() -> None:
    with pytest.raises(FermError, match=r"unknown dscp class 'bogus'"):
        _dscp_match(Family.IP, "dscp-class", "bogus")


def test_translate_match_dscp_not_set_eligible() -> None:
    # class names have no rank in sort_set_elements, so the match must not
    # advertise a set_key (a folded set could not converge under --plan).
    _, set_key, element = _translate_match_parts(
        Family.IP, _opt("dscp-class", "ef", module="dscp"), None
    )
    assert (set_key, element) == (None, None)


def test_translate_match_dscp_arp_keeps_generic_refusal() -> None:
    with pytest.raises(FermError, match=r"^option 'dscp' not yet supported"):
        _dscp_match(Family.ARP, "dscp", "0x2c")


def _dscp_target(domain: Family, *companions: RenderedOption) -> list[str]:
    rule = translate_rule(
        domain, "mangle", _rule(_target("DSCP"), *companions)
    )
    return [s.to_text() for s in rule.statements]


def test_build_verdict_dscp_set_dscp_numeric() -> None:
    # 26 decimal == 0x1a == af31.
    assert _dscp_target(Family.IP, _opt("set-dscp", "26", module="DSCP")) == [
        "ip dscp set af31"
    ]


def test_build_verdict_dscp_set_dscp_class() -> None:
    assert _dscp_target(
        Family.IP, _opt("set-dscp-class", "af31", module="DSCP")
    ) == ["ip dscp set af31"]


def test_build_verdict_dscp_ip6_selector() -> None:
    assert _dscp_target(
        Family.IP6, _opt("set-dscp-class", "af31", module="DSCP")
    ) == ["ip6 dscp set af31"]


def test_build_verdict_dscp_both_options_refused() -> None:
    with pytest.raises(FermError, match=r"^DSCP target not yet supported"):
        _dscp_target(
            Family.IP,
            _opt("set-dscp", "1", module="DSCP"),
            _opt("set-dscp-class", "ef", module="DSCP"),
        )


def test_build_verdict_dscp_neither_option_refused() -> None:
    with pytest.raises(FermError, match=r"^DSCP target not yet supported"):
        _dscp_target(Family.IP)


def _classify(value: str) -> list[str]:
    rule = translate_rule(
        Family.IP,
        "mangle",
        _rule(
            _target("CLASSIFY"), _opt("set-class", value, module="CLASSIFY")
        ),
    )
    return [s.to_text() for s in rule.statements]


@pytest.mark.parametrize(
    ("given", "spelled"),
    [
        ("0001:0020", "1:20"),  # leading zeros strip in both halves
        ("abcd:ffff", "abcd:ffff"),  # already canonical, lowercase
        ("ffff:ffff", "root"),  # tc special
        ("0:0", "none"),  # tc special
        ("00ff:0abc", "ff:abc"),
    ],
)
def test_build_verdict_classify_readback_canon(
    given: str, spelled: str
) -> None:
    assert _classify(given) == [f"meta priority set {spelled}"]


@pytest.mark.parametrize("bad", ["1", "abcde:1", ":1", "1:"])
def test_build_verdict_classify_bad_handle_refused(bad: str) -> None:
    with pytest.raises(FermError, match=r"invalid tc class"):
        _classify(bad)


def test_build_verdict_classify_missing_option_refused() -> None:
    rule = _rule(_target("CLASSIFY"))
    with pytest.raises(FermError, match=r"^CLASSIFY target not yet supported"):
        translate_rule(Family.IP, "mangle", rule)


def test_translate_match_tos_refused_with_no_nft_equivalent() -> None:
    with pytest.raises(
        FermError,
        match=r"^option 'tos' has no nft equivalent",
    ):
        translate_match(Family.IP, _opt("tos", "0x10", module="tos"), None)


def test_build_verdict_tos_refused_with_no_nft_equivalent() -> None:
    # set-tos is collected as a companion so the target fires the TOS
    # message rather than the generic "option not supported" match refusal.
    rule = _rule(
        _target("TOS"),
        _opt("set-tos", "Maximize-Throughput", module="TOS"),
    )
    with pytest.raises(
        FermError,
        match=r"^target 'TOS' has no nft equivalent",
    ):
        translate_rule(Family.IP, "mangle", rule)


def test_translate_rule_reject_with_companion_order() -> None:
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("dport", "80"),
            _target("REJECT"),
            _opt("reject-with", "icmp-port-unreachable", module="REJECT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "tcp dport 80",
        "reject with icmp type port-unreachable",
    ]


def test_translate_rule_comment_attaches() -> None:
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _target("ACCEPT"),
            _opt("comment", "allow ssh", module="comment"),
        ),
    )
    assert nft.comment == "allow ssh"
    assert [s.to_text() for s in nft.statements] == ["accept"]


def test_translate_rule_snat_multi_value() -> None:
    nft = translate_rule(
        Family.IP,
        "nat",
        _rule(
            _opt("source", "10.0.0.0/8"),
            _target("SNAT"),
            _opt("to-source", Multi(values=["5.6.7.8"]), module="SNAT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "ip saddr 10.0.0.0/8",
        "snat to 5.6.7.8",
    ]


def test_translate_rule_port_before_proto_is_order_independent() -> None:
    # A port option textually preceding `protocol` must still resolve.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("dport", "22"),
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == ["tcp dport 22", "accept"]


def test_translate_rule_goto_user_chain() -> None:
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("goto", "mychain", kind=OptionKind.TARGET),
        ),
    )
    assert [s.to_text() for s in nft.statements] == ["goto mychain"]


# ---------------------------------------------------------------------------
# Additional coverage tests
# ---------------------------------------------------------------------------
from pyferm.backend.nft import build_verdict  # noqa: E402, F811


def test_unwrap_value_prenegated() -> None:
    assert unwrap_value(PreNegated("22")) == ("22", True)


def test_unwrap_value_bare_multi_is_error() -> None:
    with pytest.raises(FermError, match="single nft match"):
        unwrap_value(Multi(values=["22", "80"]))


def test_build_verdict_redirect_to_ports() -> None:
    comp = {
        "to-ports": _opt("to-ports", Multi(values=["8080"]), module="REDIRECT")
    }
    assert (
        build_verdict(
            Family.IP, "nat", "jump", "REDIRECT", comp, has_transport=True
        ).to_text()
        == "redirect to :8080"
    )
    assert (
        build_verdict(Family.IP, "nat", "jump", "REDIRECT", {}).to_text()
        == "redirect"
    )


def test_build_verdict_tcp_reset_reject() -> None:
    comp = {"reject-with": _opt("reject-with", "tcp-reset", module="REJECT")}
    assert (
        build_verdict(Family.IP, "filter", "jump", "REJECT", comp).to_text()
        == "reject with tcp reset"
    )


def test_build_verdict_tcp_reset_reject_ip6() -> None:
    # nft renders `tcp reset` family-agnostically; the ip6 family accepts
    # `reject with tcp reset` just like ip4 (closes the _REJECT_WITH_IP6 gap).
    comp = {"reject-with": _opt("reject-with", "tcp-reset", module="REJECT")}
    assert (
        build_verdict(Family.IP6, "filter", "jump", "REJECT", comp).to_text()
        == "reject with tcp reset"
    )


# --- NftBackend.render -----------------------------------------------------

import re  # noqa: E402

from pyferm.backend.nft import NftBackend  # noqa: E402
from pyferm.config import Options  # noqa: E402
from pyferm.domains import DomainInfo  # noqa: E402


def test_render_emits_save_text_for_one_family() -> None:
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    chain = table.chains.setdefault("INPUT", ChainInfo(policy="DROP"))
    chain.rules.append(_rule(_target("ACCEPT")))
    rendered = NftBackend().render(Family.IP, info, Options(test=True))
    assert rendered.commands == []
    save = rendered.save
    assert save is not None
    assert "add table ip ferm\n" in save
    assert "flush table ip ferm\n" in save
    assert (
        "add chain ip ferm INPUT "
        "{ type filter hook input priority 0; policy drop; }\n"
    ) in save
    assert "add rule ip ferm INPUT accept\n" in save


def test_render_merges_tables_without_chain_collision() -> None:
    info = DomainInfo()
    f = info.tables.setdefault("filter", TableInfo())
    f.chains.setdefault("INPUT", ChainInfo()).rules.append(
        _rule(_target("ACCEPT"))
    )
    m = info.tables.setdefault("mangle", TableInfo())
    m.chains.setdefault("INPUT", ChainInfo()).rules.append(
        _rule(_target("DROP"))
    )
    save = NftBackend().render(Family.IP, info, Options(test=True)).save
    assert save is not None
    assert "add rule ip ferm INPUT accept\n" in save
    assert "add rule ip ferm mangle_INPUT drop\n" in save


def test_render_preserve_is_error() -> None:
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    table.preserve_regexes.append(re.compile("foo"))
    with pytest.raises(FermError, match="@preserve not yet supported"):
        NftBackend().render(Family.IP, info, Options(test=True))


# --- commit / capture_previous / rollback ---------------------------------

from pyferm.backend.base import Rendered  # noqa: E402


def test_commit_emits_lines_and_pipes_save() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    emitted: list[str] = []
    applied: list[str] = []
    rendered = Rendered(save="add table ip ferm\n")
    NftBackend().commit(
        Family.IP,
        info,
        rendered,
        Options(lines=True, noexec=False),
        execute=lambda _c: None,
        emit_line=emitted.append,
        restore=lambda _di, save: applied.append(save),
    )
    assert "add table ip ferm\n" in emitted
    assert applied == ["add table ip ferm\n"]


def test_commit_noexec_does_not_apply() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    applied: list[str] = []
    NftBackend().commit(
        Family.IP,
        info,
        Rendered(save="x\n"),
        Options(noexec=True),
        execute=lambda _c: None,
        emit_line=lambda _t: None,
        restore=lambda _di, save: applied.append(save),
    )
    assert applied == []


def test_commit_shell_wraps_heredoc() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    emitted: list[str] = []
    NftBackend().commit(
        Family.IP,
        info,
        Rendered(save="x\n"),
        Options(shell=True, lines=True, noexec=True),
        execute=lambda _c: None,
        emit_line=emitted.append,
        restore=lambda _di, _save: None,
    )
    assert emitted[0] == "nft -f - <<EOT\n"
    assert emitted[-1] == "EOT\n"


def test_shell_rollback_notice_announces_on_stderr() -> None:
    # nft's --shell restores are silenced (`2>/dev/null`); the notice breaks
    # that silence with an stderr echo after the restores (parity with the
    # live "Firewall rules rolled back." message).
    notice = NftBackend().shell_rollback_notice()
    assert notice is not None
    assert notice.endswith(">&2\n")
    assert "rolled back" in notice


def test_capture_previous_stores_own_table_snapshot() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    calls: list[str] = []

    def cap(cmd: str) -> str:
        calls.append(cmd)
        return "table ip ferm {\n}\n"

    NftBackend().capture_previous(
        Family.IP,
        info,
        Options(),
        execute=lambda _c: None,
        read_save=lambda _tool: None,
        capture=cap,
    )
    assert calls == ["nft list table ip ferm"]
    assert info.previous == "table ip ferm {\n}\n"


def test_capture_previous_first_run_is_no_table() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    NftBackend().capture_previous(
        Family.IP,
        info,
        Options(),
        execute=lambda _c: None,
        read_save=lambda _tool: None,
        capture=lambda _cmd: None,
    )
    assert info.previous is None


def test_rollback_restores_captured_snapshot() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    info.enabled = True
    info.previous = "table ip ferm {\n}\n"
    applied: list[str] = []
    NftBackend().rollback(
        Family.IP,
        info,
        Options(),
        execute=lambda _c: None,
        restore=lambda _di, save: applied.append(save),
    )
    assert applied == ["table ip ferm {\n}\n"]


def test_rollback_first_run_deletes_table() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    info.enabled = True
    info.previous = None
    calls: list[str] = []
    NftBackend().rollback(
        Family.IP,
        info,
        Options(),
        execute=calls.append,
        restore=lambda _di, _save: None,
    )
    assert calls == ["nft delete table ip ferm"]


# --- Fix 2: lifecycle branch coverage ----------------------------------------


def test_commit_restore_failure_returns_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}

    def boom(_di: object, _save: str) -> None:
        raise FermError("nft rejected")

    rc = NftBackend().commit(
        Family.IP,
        info,
        Rendered(save="x\n"),
        Options(noexec=False),
        execute=lambda _c: None,
        emit_line=lambda _t: None,
        restore=boom,
    )
    assert rc == 1
    assert "nft rejected" in capsys.readouterr().err


def test_commit_none_save_is_internal_error() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    with pytest.raises(FermError):
        NftBackend().commit(
            Family.IP,
            info,
            Rendered(save=None),
            Options(noexec=False),
            execute=lambda _c: None,
            emit_line=lambda _t: None,
            restore=lambda _di, _s: None,
        )


def test_rollback_disabled_is_noop() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    info.enabled = False
    info.previous = "table ip ferm {\n}\n"
    calls: list[str] = []
    applied: list[str] = []
    NftBackend().rollback(
        Family.IP,
        info,
        Options(),
        execute=calls.append,
        restore=lambda _di, s: applied.append(s),
    )
    assert calls == []
    assert applied == []


def test_read_previous_joins_verbatim() -> None:
    info = DomainInfo()
    assert (
        NftBackend().read_previous(["table ip ferm {\n", "}\n"], info)
        == "table ip ferm {\n}\n"
    )


# --- shell_snapshot (finding C2) -------------------------------------------


def test_shell_snapshot_emits_nft_save_and_delete_restore() -> None:
    # finding C2: --nft --interactive --shell must emit a real anti-lockout
    # net.  Snapshot ferm's table to a tempfile; on restore delete the
    # freshly-applied table then re-load the dump (mirrors the live
    # rollback).  `2>/dev/null || true` keep a first-run/already-gone table
    # from aborting the generated script.
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    snapshot = NftBackend().shell_snapshot(Family.IP, info)
    assert snapshot is not None
    assert snapshot.setup == (
        "ip_tmp=$(mktemp ferm.XXXXXXXXXX)\n",
        "nft list table ip ferm >$ip_tmp 2>/dev/null || true\n",
    )
    assert snapshot.restore == (
        "nft delete table ip ferm 2>/dev/null || true\nnft -f $ip_tmp\n"
    )


def test_shell_snapshot_maps_eb_family_to_bridge() -> None:
    # The snapshot list/delete must use the nft family, not the ferm domain
    # name (eb -> bridge), so it targets the table the backend actually built.
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    snapshot = NftBackend().shell_snapshot(Family.EB, info)
    assert snapshot is not None
    assert "list table bridge ferm" in snapshot.setup[1]
    assert "delete table bridge ferm" in snapshot.restore


def test_render_user_chain_collision_is_error() -> None:
    # filter/mangle_INPUT (user chain, bare name) collides with
    # mangle/INPUT after nft_chain_name disambiguates it to "mangle_INPUT".
    # sorted(tables) -> filter before mangle, so filter's chain is inserted
    # first and mangle/INPUT hits the collision guard.
    info = DomainInfo()
    f = info.tables.setdefault("filter", TableInfo())
    f.chains.setdefault("mangle_INPUT", ChainInfo())
    m = info.tables.setdefault("mangle", TableInfo())
    m.chains.setdefault("INPUT", ChainInfo())
    with pytest.raises(FermError, match="collision"):
        NftBackend().render(Family.IP, info, Options(test=True))


# --- Fix 1: capture_previous --test reads the mock FILE (not the path string)


def test_capture_previous_test_mode_reads_mock_file(tmp_path: Path) -> None:
    snap = tmp_path / "prev.nft"
    snap.write_text("table ip ferm {\n}\n", encoding="latin-1")
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    NftBackend().capture_previous(
        Family.IP,
        info,
        Options(test=True, mock_previous={"ip": str(snap)}),
        execute=lambda _c: None,
        read_save=lambda _tool: None,
        capture=lambda _cmd: None,
    )
    assert info.previous == "table ip ferm {\n}\n"


import errno  # noqa: E402
import os  # noqa: E402


def test_capture_previous_mock_reads_high_bytes_verbatim(
    tmp_path: Path,
) -> None:
    # The mock-previous file is opened latin-1 (BYTE_ENCODING) so every byte
    # 0x00-0xFF round-trips into the rollback snapshot.  Reading it under the
    # locale default would choke on a non-UTF-8 byte (0xFF here) -- the
    # snapshot the admin must get back verbatim for rollback to restore the
    # real ruleset.
    snap = tmp_path / "prev.nft"
    snap.write_bytes(b"table ip ferm {\n  comment \xff\n}\n")
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    NftBackend().capture_previous(
        Family.IP,
        info,
        Options(test=True, mock_previous={"ip": str(snap)}),
        execute=lambda _c: None,
        read_save=lambda _tool: None,
        capture=lambda _cmd: None,
    )
    assert info.previous == "table ip ferm {\n  comment \xff\n}\n"


def test_capture_previous_mock_open_failure_reports_os_reason(
    tmp_path: Path,
) -> None:
    # A missing mock file must surface the OS reason (strerror), never a bare
    # None or the noisy "[Errno N] ...: '<path>'" repr -- the admin needs to
    # know why the rollback snapshot could not be read.
    missing = tmp_path / "does-not-exist.nft"
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    with pytest.raises(FermError) as excinfo:
        NftBackend().capture_previous(
            Family.IP,
            info,
            Options(test=True, mock_previous={"ip": str(missing)}),
            execute=lambda _c: None,
            read_save=lambda _tool: None,
            capture=lambda _cmd: None,
        )
    assert str(excinfo.value) == os.strerror(errno.ENOENT)


# ---------------------------------------------------------------------------
# Operand escaping / validation hardening (review 2026-06-14, fixes 1-5)
#
# The nft backend interpolates config-derived operands into the save script;
# a value carrying whitespace / `;` / `#` / `"` previously broke out of its
# nft token (a DROP rule silently rendered as `accept`).  Each operand class
# is now escaped (quoted-string contexts) or grammar-validated (bare-token /
# bare-identifier contexts).  `INJECT` is the canonical exploit payload.
# ---------------------------------------------------------------------------

from pyferm.backend.nft import nft_chain_name  # noqa: E402

INJECT = "1.2.3.4 accept;#"


# --- Fix 1: chain-name identifier validation (jump/goto + add chain) ---


def test_nft_chain_name_rejects_non_identifier() -> None:
    with pytest.raises(FermError, match="valid nft identifier"):
        nft_chain_name("filter", 'evil" accept;#')


def test_nft_chain_name_rejects_whitespace_in_non_filter() -> None:
    with pytest.raises(FermError, match="valid nft identifier"):
        nft_chain_name("nat", "evil accept")


def test_build_verdict_jump_to_injected_chain_is_error() -> None:
    with pytest.raises(FermError, match="valid nft identifier"):
        build_verdict(Family.IP, "filter", "jump", "FOO accept;#", {})


def test_nft_chain_name_accepts_disambiguated_names() -> None:
    # positive control: valid names must still pass unchanged.
    assert nft_chain_name("filter", "INPUT") == "INPUT"
    assert nft_chain_name("mangle", "mychain") == "mangle_mychain"


# --- Fix 2: address + NAT-target grammar validation ---


def test_translate_match_address_rejects_injection() -> None:
    with pytest.raises(FermError, match="invalid address"):
        translate_match(Family.IP, _opt("source", INJECT), None)


def test_build_verdict_snat_rejects_injection() -> None:
    snat = {
        "to-source": _opt("to-source", Multi(values=[INJECT]), module="SNAT")
    }
    with pytest.raises(FermError, match="invalid address"):
        build_verdict(Family.IP, "nat", "jump", "SNAT", snat)


def test_build_verdict_dnat_rejects_injection() -> None:
    dnat = {
        "to-destination": _opt(
            "to-destination", Multi(values=[INJECT]), module="DNAT"
        )
    }
    with pytest.raises(FermError, match="invalid address"):
        build_verdict(Family.IP, "nat", "jump", "DNAT", dnat)


def test_translate_match_address_accepts_cidr_and_ipv6() -> None:
    # positive control: CIDR / IPv6 / range must not over-reject.
    assert (
        translate_match(Family.IP, _opt("source", "10.0.0.0/24"), None)
        == "ip saddr 10.0.0.0/24"
    )
    assert (
        translate_match(Family.IP6, _opt("destination", "fe80::/64"), None)
        == "ip6 daddr fe80::/64"
    )


# --- Fix 3: port + to-ports grammar validation ---


def test_translate_match_port_rejects_injection() -> None:
    with pytest.raises(FermError, match="invalid port"):
        translate_match(Family.IP, _opt("dport", "22 accept;#"), "tcp")


def test_build_verdict_masquerade_to_ports_rejects_injection() -> None:
    # has_transport=True to reach the port validator (the C1 guard is checked
    # first); the injected port must still be rejected.
    comp = {
        "to-ports": _opt(
            "to-ports", Multi(values=["80 accept;#"]), module="MASQUERADE"
        )
    }
    with pytest.raises(FermError, match="invalid port"):
        build_verdict(
            Family.IP, "nat", "jump", "MASQUERADE", comp, has_transport=True
        )


def test_translate_match_port_accepts_range() -> None:
    # positive control: a port range must still translate.
    assert (
        translate_match(Family.IP, _opt("dport", "1024-2048"), "tcp")
        == "tcp dport 1024-2048"
    )


# --- Fix 4: interface quoting (quoted-string context) ---


def test_translate_match_iface_rejects_embedded_quote() -> None:
    # nft has no escape for a literal `"`; the old `\"` escape let the value
    # break out of its token and flip the verdict (DROP->accept).  The value
    # must now be rejected, not emitted (review 2026-06-14).
    opt = _opt("in-interface", 'eth0" accept;#')
    with pytest.raises(FermError, match="cannot quote"):
        translate_match(Family.IP, opt, None)


def test_translate_match_iface_translates_iptables_wildcard() -> None:
    # ferm configs carry the iptables wildcard spelling `eth+`; nft's string
    # wildcard is `*` and a literal `+` silently matches nothing, so the
    # trailing `+` must become `*` inside the quotes.
    assert (
        translate_match(Family.IP, _opt("in-interface", "eth+"), None)
        == 'iifname "eth*"'
    )


def test_translate_match_iface_interior_plus_stays_literal() -> None:
    # only a TRAILING `+` is a wildcard in iptables; `a+b` is a literal name.
    assert (
        translate_match(Family.IP, _opt("out-interface", "a+b"), None)
        == 'oifname "a+b"'
    )


def test_set_elements_translate_wildcard_and_need_interval() -> None:
    # the named-set arm shares the wildcard translation, and nft demands
    # `flags interval` on an ifname set holding a prefix element (a plain
    # literal-only set needs no flag).
    from pyferm.backend.nft import NftSetType, _set_type_and_elements
    from pyferm.values import SetRef

    type_, interval, elements = _set_type_and_elements(
        Family.IP, "iifname", SetRef("ifs", ["eth+", "ppp0"])
    )
    assert type_ is NftSetType.IFNAME
    assert interval is True
    assert elements == sorted(['"eth*"', '"ppp0"'])

    _, no_interval, literal = _set_type_and_elements(
        Family.IP, "oifname", SetRef("ifs", ["a+b", "ppp0"])
    )
    assert no_interval is False
    assert literal == sorted(['"a+b"', '"ppp0"'])


# --- Fix 5: state vocabulary + limit-rate validation ---


def test_translate_match_state_rejects_unknown_keyword() -> None:
    with pytest.raises(FermError, match="state"):
        translate_match(
            Family.IP, _opt("state", "BOGUS", module="state"), None
        )


def test_translate_match_state_negated_multivalue_is_valid() -> None:
    # A negated multi-state match must use the masked bang form ("none
    # of the bits"): the `!=` spelling compares the WHOLE register
    # against the OR of the bits -- true for nearly every packet --
    # which is not what iptables' `! --state a,b` means (verified
    # against the netlink bytecode 2026-07-10).  A single member keeps
    # `!=` (one state bit at a time makes it faithful, and it is the
    # pre-existing canon).
    assert (
        translate_match(
            Family.IP,
            _opt("state", Negated("ESTABLISHED,RELATED"), module="state"),
            None,
        )
        == "ct state ! established,related"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("state", Negated("INVALID"), module="state"),
            None,
        )
        == "ct state != invalid"
    )


def test_translate_match_limit_rejects_injection() -> None:
    with pytest.raises(FermError, match="invalid rate"):
        translate_match(
            Family.IP, _opt("limit", "3/second;drop", module="limit"), None
        )


# --- Review 2026-06-14 C1: quoted-string sinks reject, never escape ---

from pyferm.backend.nft import _nft_quote_string, _validate_port  # noqa: E402


@pytest.mark.parametrize(
    "payload",
    ['a" accept #', "a\\b", "line\nfeed", "carriage\rreturn", "ctrl\x01byte"],
)
def test_nft_quote_string_rejects_unquotable(payload: str) -> None:
    # nft has no in-string escape for `"`; escaping it flipped verdicts.
    with pytest.raises(FermError, match="cannot quote"):
        _nft_quote_string(payload)


@pytest.mark.parametrize(
    "payload", ["eth*", "ppp+", "lan.10", "INPUT-dropped W: "]
)
def test_nft_quote_string_accepts_legitimate(payload: str) -> None:
    assert _nft_quote_string(payload) == f'"{payload}"'


def test_render_comment_rejects_embedded_quote() -> None:
    # the comment sink shares the chokepoint; a `"` must be rejected.
    with pytest.raises(FermError, match="cannot quote"):
        render_comment('legit" accept;#')


# --- Review 2026-06-14 H1: colon port ranges normalize to nft dash form ---


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("1000:2000", "1000-2000"),
        # named halves resolve to numbers (the readback prints numbers;
        # the dash-joined `ssh-http` spelling would not even parse as a
        # range under nft, which reads it as one service name)
        ("ssh:http", "22-80"),
        ("22", "22"),
        ("1000-2000", "1000-2000"),
        # numeric boundaries: the guard checks shape, not the 0..65535 range.
        ("0", "0"),
        ("65535", "65535"),
        ("0:65535", "0-65535"),
        # A reversed range is shape-valid and passes through unchanged --
        # rejecting lo>hi is nft's job downstream, not this injection guard's.
        ("2000:1000", "2000-1000"),
    ],
)
def test_validate_port_normalizes_colon_range(
    given: str, expected: str
) -> None:
    assert _validate_port(given) == expected


@pytest.mark.parametrize("given", [":2000", "1000:", ":", "a:b:c"])
def test_validate_port_rejects_half_open_range(given: str) -> None:
    with pytest.raises(FermError, match="invalid port"):
        _validate_port(given)


@pytest.mark.parametrize(
    "given",
    [
        pytest.param("", id="empty"),
        pytest.param("22 ", id="trailing-space"),
        pytest.param("22 80", id="embedded-space"),
        pytest.param("-22", id="leading-dash"),
        pytest.param("80;#", id="injection-semicolon"),
        pytest.param('80"', id="injection-quote"),
    ],
)
def test_validate_port_rejects_malformed_shape(given: str) -> None:
    # The \A...\Z anchors reject any token-breaking metacharacter or stray
    # whitespace that could otherwise flip an nft verdict.
    with pytest.raises(FermError, match="invalid port"):
        _validate_port(given)


def test_translate_match_dport_colon_range() -> None:
    assert (
        translate_match(Family.IP, _opt("dport", "60000:61000"), "tcp")
        == "tcp dport 60000-61000"
    )


def test_translate_match_dport_negated_colon_range() -> None:
    assert (
        translate_match(Family.IP, _opt("dport", Negated("1000:2000")), "tcp")
        == "tcp dport != 1000-2000"
    )


# ---------------------------------------------------------------------------
# collapse pass (_collapse_chain_rules)
# ---------------------------------------------------------------------------
from pyferm.backend.nft import _collapse_chain_rules  # noqa: E402


def _port_rule(port: str, verdict: str = "accept") -> NftRule:
    return NftRule(
        statements=[
            NftMatch(f"tcp dport {port}", set_key="tcp dport", element=port),
            NftVerdict(verdict),
        ]
    )


def test_collapse_merges_adjacent_ports() -> None:
    out = _collapse_chain_rules(
        [_port_rule("22"), _port_rule("80"), _port_rule("443")]
    )
    assert len(out) == 1
    assert out[0].statements[0].to_text() == "tcp dport { 22, 80, 443 }"
    assert out[0].statements[1].to_text() == "accept"


def test_collapse_differing_verdict_folds_to_vmap() -> None:
    # Same selector, differing key AND verdict: a set cannot express it, so the
    # vmap pass folds the run into one verdict map ordered by key.
    out = _collapse_chain_rules(
        [_port_rule("22", "accept"), _port_rule("80", "drop")]
    )
    assert len(out) == 1
    assert (
        out[0].statements[0].to_text()
        == "tcp dport vmap { 22 : accept, 80 : drop }"
    )


def test_collapse_stops_at_differing_comment() -> None:
    a = _port_rule("22")
    b = _port_rule("80")
    b.comment = "note"
    out = _collapse_chain_rules([a, b])
    assert len(out) == 2


def test_collapse_only_adjacent() -> None:
    # An intervening non-equivalent rule splits the run into two singletons.
    middle = NftRule(statements=[NftVerdict("drop")])
    out = _collapse_chain_rules([_port_rule("22"), middle, _port_rule("80")])
    assert len(out) == 3


def test_collapse_negated_stays_linear() -> None:
    def neg(port: str) -> NftRule:
        return NftRule(
            statements=[NftMatch(f"tcp dport != {port}"), NftVerdict("drop")]
        )

    out = _collapse_chain_rules([neg("22"), neg("80")])
    assert len(out) == 2  # set_key is None -> non-eligible


def test_collapse_two_independent_dimensions_to_fixpoint() -> None:
    def rule(saddr: str, daddr: str) -> NftRule:
        return NftRule(
            statements=[
                NftMatch(
                    f"ip saddr {saddr}", set_key="ip saddr", element=saddr
                ),
                NftMatch(
                    f"ip daddr {daddr}", set_key="ip daddr", element=daddr
                ),
                NftVerdict("accept"),
            ]
        )

    out = _collapse_chain_rules(
        [rule("a", "c"), rule("a", "d"), rule("b", "c"), rule("b", "d")]
    )
    # daddr collapses within each saddr, then saddr collapses across the two.
    assert len(out) == 1
    assert out[0].statements[0].to_text() == "ip saddr { a, b }"
    assert out[0].statements[1].to_text() == "ip daddr { c, d }"


def test_collapse_idempotent() -> None:
    once = _collapse_chain_rules([_port_rule("22"), _port_rule("80")])
    assert _collapse_chain_rules(once) == once


def test_collapse_meta_l4proto_no_port() -> None:
    # Two adjacent proto-only rules fold into meta l4proto { tcp, udp }
    # (the no-port construction site tags element=l4; selector is eligible).
    def proto_rule(l4: str) -> NftRule:
        return NftRule(
            statements=[
                NftMatch(
                    f"meta l4proto {l4}", set_key="meta l4proto", element=l4
                ),
                NftVerdict("accept"),
            ]
        )

    out = _collapse_chain_rules([proto_rule("tcp"), proto_rule("udp")])
    assert len(out) == 1
    assert out[0].statements[0].to_text() == "meta l4proto { tcp, udp }"


def test_collapse_second_axis_order_insensitive() -> None:
    # Siblings with daddr lists accumulated in different orders must still
    # fold on the saddr axis: equality is by canonical order, not list ==.
    def rule(saddr: str, daddrs: list[str]) -> NftRule:
        return NftRule(
            statements=[
                NftMatch("ip saddr p", set_key="ip saddr", element=saddr),
                NftMatch("ip daddr p", set_key="ip daddr", elements=daddrs),
                NftVerdict("accept"),
            ]
        )

    out = _collapse_chain_rules(
        [
            rule("10.0.0.1", ["10.0.0.3", "10.0.0.4"]),
            rule("10.0.0.2", ["10.0.0.4", "10.0.0.3"]),
        ]
    )
    assert len(out) == 1
    assert out[0].statements[0].to_text() == "ip saddr { 10.0.0.1, 10.0.0.2 }"
    assert out[0].statements[1].to_text() == "ip daddr { 10.0.0.3, 10.0.0.4 }"


# ---------------------------------------------------------------------------
# Phase 5: verdict-map (vmap) fold
# ---------------------------------------------------------------------------
from pyferm.backend.nft import (  # noqa: E402
    NftVmap,
    _is_vmap_verdict,
    _vmap_candidate,
)


def test_nftvmap_to_text_orders_by_numeric_key() -> None:
    vmap = NftVmap(
        "tcp dport", [("443", "drop"), ("22", "accept"), ("80", "drop")]
    )
    assert (
        vmap.to_text()
        == "tcp dport vmap { 22 : accept, 80 : drop, 443 : drop }"
    )


def test_nftvmap_to_text_orders_l4proto_by_protocol_number() -> None:
    # The vmap key reuses the set sorter: protocol names order by number
    # (icmp=1, tcp=6, udp=17), matching nft's stored readback order.
    vmap = NftVmap(
        "meta l4proto",
        [("udp", "drop"), ("tcp", "accept"), ("icmp", "return")],
    )
    assert vmap.to_text() == (
        "meta l4proto vmap { icmp : return, tcp : accept, udp : drop }"
    )


@pytest.mark.parametrize(
    ("expr", "eligible"),
    [
        ("accept", True),
        ("drop", True),
        ("return", True),
        ("jump mychain", True),
        ("goto mychain", True),
        # 'continue'/'queue' are verdicts nft would accept in a vmap, but our
        # emitter never folds them, so they stay out of the allow-list.
        ("continue", False),
        ("queue", False),
        ("reject", False),
        ("reject with icmp type port-unreachable", False),
        ('log prefix "x"', False),
        ("snat to 1.2.3.4", False),
    ],
)
def test_is_vmap_verdict_allow_list(expr: str, eligible: bool) -> None:
    assert _is_vmap_verdict(NftVerdict(expr)) is eligible


def test_is_vmap_verdict_rejects_non_verdict_statement() -> None:
    assert _is_vmap_verdict(NftMatch("tcp dport 22")) is False


def test_vmap_candidate_rejects_folded_set_rule() -> None:
    # A rule already folded into a set (elements != None) is not a single-key
    # vmap leaf, so the vmap pass leaves it alone.
    folded = NftRule(
        statements=[
            NftMatch("tcp dport", set_key="tcp dport", elements=["22", "80"]),
            NftVerdict("accept"),
        ]
    )
    assert _vmap_candidate(folded) is None


def test_collapse_vmap_run_of_one_stays_linear() -> None:
    out = _collapse_chain_rules([_port_rule("22", "accept")])
    assert len(out) == 1
    assert out[0].statements[0].to_text() == "tcp dport 22"
    assert out[0].statements[1].to_text() == "accept"


def test_collapse_vmap_reject_breaks_run() -> None:
    # reject is not a vmap-eligible verdict (nft rejects it inside a vmap),
    # so the pair stays as two linear rules.
    reject = NftRule(
        statements=[
            NftMatch("tcp dport 80", set_key="tcp dport", element="80"),
            NftVerdict("reject"),
        ]
    )
    out = _collapse_chain_rules([_port_rule("22", "accept"), reject])
    assert len(out) == 2


def test_collapse_vmap_duplicate_key_ends_run() -> None:
    # nft rejects a vmap with duplicate keys; a repeated key ends the run,
    # so the duplicate stays a separate linear rule.
    out = _collapse_chain_rules(
        [
            _port_rule("22", "accept"),
            _port_rule("80", "drop"),
            _port_rule("22", "return"),
        ]
    )
    assert len(out) == 2
    assert (
        out[0].statements[0].to_text()
        == "tcp dport vmap { 22 : accept, 80 : drop }"
    )
    assert out[1].statements[0].to_text() == "tcp dport 22"
    assert out[1].statements[1].to_text() == "return"


def test_collapse_vmap_does_not_cross_selectors() -> None:
    saddr = NftRule(
        statements=[
            NftMatch(
                "ip saddr 10.0.0.1", set_key="ip saddr", element="10.0.0.1"
            ),
            NftVerdict("drop"),
        ]
    )
    out = _collapse_chain_rules([_port_rule("22", "accept"), saddr])
    assert len(out) == 2  # different set_key -> not one vmap


def test_collapse_vmap_folds_jump_and_goto() -> None:
    a = NftRule(
        statements=[
            NftMatch("tcp dport 22", set_key="tcp dport", element="22"),
            NftVerdict("jump sub"),
        ]
    )
    b = NftRule(
        statements=[
            NftMatch("tcp dport 80", set_key="tcp dport", element="80"),
            NftVerdict("goto sub"),
        ]
    )
    out = _collapse_chain_rules([a, b])
    assert len(out) == 1
    assert (
        out[0].statements[0].to_text()
        == "tcp dport vmap { 22 : jump sub, 80 : goto sub }"
    )


def test_collapse_vmap_idempotent() -> None:
    once = _collapse_chain_rules(
        [_port_rule("22", "accept"), _port_rule("80", "drop")]
    )
    assert _collapse_chain_rules(once) == once


# commit() delta-apply tests

import subprocess  # noqa: E402
import sys as _sys  # noqa: E402


def _run_apply(tmp_path: Path, ferm: str, mock: str | None) -> str:
    ferm_file = tmp_path / "c.ferm"
    ferm_file.write_text(ferm, encoding="utf-8")
    cmd = [
        _sys.executable,
        "-m",
        "pyferm",
        "--nft",
        "--test",
        "--noexec",
        "--lines",
    ]
    if mock is not None:
        mock_file = tmp_path / "prev.save"
        mock_file.write_text(mock, encoding="utf-8")
        cmd.append(f"--test-mock-previous=ip={mock_file}")
    cmd.append(str(ferm_file))
    proc = subprocess.run(
        cmd, capture_output=True, encoding="utf-8", check=False
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


_FERM = (
    "domain ip table filter chain INPUT {\n"
    "    policy ACCEPT;\n"
    "    proto tcp dport 22 ACCEPT;\n"
    "    proto tcp dport 80 ACCEPT;\n"
    "}\n"
)
_MOCK_ONE_RULE = (
    "table ip ferm {\n"
    "\tchain INPUT {\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t\ttcp dport 22 accept\n"
    "\t}\n"
    "}\n"
)


def test_commit_delta_is_default_under_nft(tmp_path: Path) -> None:
    out = _run_apply(tmp_path, _FERM, _MOCK_ONE_RULE)
    # delta path: flushes the CHAIN, never the table
    assert "flush chain ip ferm INPUT" in out
    assert "flush table ip ferm" not in out


def test_commit_full_reload_opts_out(tmp_path: Path) -> None:
    ferm_file = tmp_path / "c.ferm"
    ferm_file.write_text(_FERM, encoding="utf-8")
    mock_file = tmp_path / "prev.save"
    mock_file.write_text(_MOCK_ONE_RULE, encoding="utf-8")
    proc = subprocess.run(
        [
            _sys.executable,
            "-m",
            "pyferm",
            "--nft",
            "--full-reload",
            "--test",
            "--noexec",
            "--lines",
            f"--test-mock-previous=ip={mock_file}",
            str(ferm_file),
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    # Full reload atomically replaces the whole table (delete + re-add) rather
    # than `flush table`, which would keep a removed base chain's declaration
    # (hook + policy) alive.  See _full_reload_text.
    assert "delete table ip ferm" in proc.stdout
    assert "flush table ip ferm" not in proc.stdout


def test_commit_first_run_falls_back_to_full_reload(tmp_path: Path) -> None:
    # no mock-previous -> previous is None -> needs_full_reload -> full reload
    out = _run_apply(tmp_path, _FERM, None)
    assert "delete table ip ferm" in out
    assert "flush table ip ferm" not in out


def test_commit_idempotent_delta_emits_nothing(tmp_path: Path) -> None:
    # Mock must match exactly what pyferm renders (anonymous set collapsed:
    # "tcp dport { 22, 80 } accept", not two separate rules).
    mock = (
        "table ip ferm {\n"
        "\tchain INPUT {\n"
        "\t\ttype filter hook input priority filter; policy accept;\n"
        "\t\ttcp dport { 22, 80 } accept\n"
        "\t}\n"
        "}\n"
    )
    out = _run_apply(tmp_path, _FERM, mock)
    assert out == ""  # empty delta -> nothing emitted, nft -f skipped


_FERM_SET_INTERVAL = (
    "domain ip table filter chain INPUT {\n"
    "    policy ACCEPT;\n"
    "    @set $s = (10.0.0.0/24);\n"
    "    proto tcp saddr $s ACCEPT;\n"
    "}\n"
)
_MOCK_SET_PLAIN = (
    "table ip ferm {\n"
    "\tset s {\n"
    "\t\ttype ipv4_addr\n"
    "\t\telements = { 10.0.0.1 }\n"
    "\t}\n"
    "\tchain INPUT {\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t\ttcp saddr @s accept\n"
    "\t}\n"
    "}\n"
)


def test_commit_set_retype_falls_back_to_full_reload(tmp_path: Path) -> None:
    # The set flips ipv4_addr -> interval (a CIDR element), so the diff carries
    # a set 'remove' -> build_nft_delta returns None -> commit full-reloads
    # rather than emit a refcount-unsafe 'delete set'.
    out = _run_apply(tmp_path, _FERM_SET_INTERVAL, _MOCK_SET_PLAIN)
    # full reload (whole-table replace), not a delta
    assert "delete table ip ferm" in out
    assert "flush table ip ferm" not in out


def test_commit_full_reload_noflush_neither_flushes_nor_deletes(
    tmp_path: Path,
) -> None:
    # --noflush keeps the apply append-only: serialize_table emits no `flush
    # table`, and the full-reload transform must not inject `delete table`
    # either (that would defeat append-only semantics).
    ferm_file = tmp_path / "c.ferm"
    ferm_file.write_text(_FERM, encoding="utf-8")
    proc = subprocess.run(
        [
            _sys.executable,
            "-m",
            "pyferm",
            "--nft",
            "--full-reload",
            "--noflush",
            "--test",
            "--noexec",
            "--lines",
            str(ferm_file),
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "flush table ip ferm" not in proc.stdout
    assert "delete table ip ferm" not in proc.stdout


# ---------------------------------------------------------------------------
# translate_rule: empty named-set invariant
# ---------------------------------------------------------------------------


def test_translate_rule_rejects_empty_named_set() -> None:
    # The caller drops empty-set rules (a v4-only set on the ip6 pass);
    # if one slips through, that is a broken contract, not a silent emit.
    rule = RenderedRule(
        options=[
            RenderedOption("daddr", SetRef("x", []), OptionKind.OPTION, None)
        ],
        script=None,
    )
    with pytest.raises(FermError, match="internal error"):
        translate_rule(Family.IP6, "filter", rule)


# ---------------------------------------------------------------------------
# translate_rule: structured match/verdict metadata (mutation-hardening)
# ---------------------------------------------------------------------------


def test_translate_rule_port_match_carries_set_metadata() -> None:
    # A folded set is built from set_key/element, not by reverse-parsing expr;
    # the structured fields on the emitted match must survive translation.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("dport", "22"),
            _target("ACCEPT"),
        ),
    )
    match = nft.statements[0]
    assert isinstance(match, NftMatch)
    assert (match.expr, match.set_key, match.element) == (
        "tcp dport 22",
        "tcp dport",
        "22",
    )


def test_translate_rule_l4proto_carries_set_metadata() -> None:
    # The bare-proto `meta l4proto` match is set-eligible too, so it keeps the
    # `meta l4proto` set_key and the protocol element for folding.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "icmp", kind=OptionKind.PROTO),
            _target("DROP"),
        ),
    )
    match = nft.statements[0]
    assert isinstance(match, NftMatch)
    assert (match.expr, match.set_key, match.element) == (
        "meta l4proto icmp",
        "meta l4proto",
        "icmp",
    )


def test_translate_rule_negated_proto_emits_inequality() -> None:
    # A negated protocol keeps its `!=` and is NOT set-eligible.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", Negated("tcp"), kind=OptionKind.PROTO),
            _target("DROP"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "meta l4proto != tcp",
        "drop",
    ]


def test_translate_rule_without_target_appends_no_verdict() -> None:
    # A rule carrying only matches (no target) must not synthesize a verdict.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(_opt("source", "10.0.0.1")),
    )
    assert [s.to_text() for s in nft.statements] == ["ip saddr 10.0.0.1"]


def test_translate_rule_nat_to_ports_uses_transport_context() -> None:
    # A tcp protocol establishes the transport match a port-bearing NAT needs,
    # so `REDIRECT to-ports` translates instead of being rejected.
    nft = translate_rule(
        Family.IP,
        "nat",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _target("REDIRECT"),
            _opt("to-ports", "8080", module="REDIRECT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "meta l4proto tcp",
        "redirect to :8080",
    ]


def test_translate_rule_verdict_receives_family_domain() -> None:
    # build_verdict must be handed the rule's family: an ip6 reject-with only
    # resolves via the icmpv6 map, so a wrong/None domain would fail it.
    nft = translate_rule(
        Family.IP6,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("dport", "80"),
            _target("REJECT"),
            _opt("reject-with", "icmp6-port-unreachable", module="REJECT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "tcp dport 80",
        "reject with icmpv6 type port-unreachable",
    ]


def test_translate_rule_comment_before_matches_keeps_matches() -> None:
    # The comment option must `continue`, not terminate option processing:
    # a comment ahead of the matches must not drop the rest of the rule.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("comment", "hi", module="comment"),
            _opt("source", "10.0.0.1"),
            _target("ACCEPT"),
        ),
    )
    assert nft.comment == "hi"
    assert [s.to_text() for s in nft.statements] == [
        "ip saddr 10.0.0.1",
        "accept",
    ]


def test_translate_rule_companion_before_matches_keeps_matches() -> None:
    # A target companion (reject-with) must `continue`, not terminate the loop,
    # so a match option following it is still emitted.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _target("REJECT"),
            _opt("reject-with", "icmp-port-unreachable", module="REJECT"),
            _opt("source", "10.0.0.1"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "meta l4proto tcp",
        "ip saddr 10.0.0.1",
        "reject with icmp type port-unreachable",
    ]


def test_translate_rule_address_setref_selector_and_ref() -> None:
    # A SetRef match renders `<selector> @name` and keeps the SetRef plus the
    # structured selector for the later set-declaration pass.
    setref = SetRef("myset", ["10.0.0.1"])
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(_opt("source", setref), _target("ACCEPT")),
    )
    match = nft.statements[0]
    assert isinstance(match, NftMatch)
    assert match.expr == "ip saddr @myset"
    assert match.set_selector == "ip saddr"
    assert match.setref == setref


def test_translate_rule_port_setref_uses_protocol_selector() -> None:
    # A port SetRef selector needs the rule protocol (tcp/udp); dropping it
    # would fail the tcp/udp guard.
    setref = SetRef("ports", ["22"])
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("dport", setref),
            _target("ACCEPT"),
        ),
    )
    match = nft.statements[0]
    assert isinstance(match, NftMatch)
    assert match.expr == "tcp dport @ports"
    assert match.set_selector == "tcp dport"


# ---------------------------------------------------------------------------
# translate_rule: mod set match-set -> named-set match
# ---------------------------------------------------------------------------

from pyferm.backend.nft import _collect_set_declarations  # noqa: E402


def _match_set_opt(
    operand: Value, flags: str, *, negated: bool = False
) -> RenderedOption:
    """Build a ``mod set match-set`` option as the ``sc`` code emits it."""
    value: Value = Params([operand, flags])
    if negated:
        value = PreNegated(value)
    return _opt("match-set", value, module="set")


def test_translate_rule_match_set_src() -> None:
    setref = SetRef("badguys", ["10.1.2.3"])
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(_match_set_opt(setref, "src"), _target("DROP")),
    )
    match = nft.statements[0]
    assert isinstance(match, NftMatch)
    assert match.expr == "ip saddr @badguys"
    assert match.set_selector == "ip saddr"
    assert match.setref == setref


def test_translate_rule_match_set_dst() -> None:
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _match_set_opt(SetRef("badguys", ["10.1.2.3"]), "dst"),
            _target("DROP"),
        ),
    )
    match = nft.statements[0]
    assert isinstance(match, NftMatch)
    assert match.expr == "ip daddr @badguys"
    assert match.set_selector == "ip daddr"


def test_translate_rule_match_set_ip6() -> None:
    nft = translate_rule(
        Family.IP6,
        "filter",
        _rule(
            _match_set_opt(SetRef("badguys", ["fe80::1"]), "src"),
            _target("DROP"),
        ),
    )
    match = nft.statements[0]
    assert isinstance(match, NftMatch)
    assert match.expr == "ip6 saddr @badguys"
    assert match.set_selector == "ip6 saddr"


def test_translate_rule_match_set_negated_renders_inequality() -> None:
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _match_set_opt(
                SetRef("badguys", ["10.1.2.3"]), "dst", negated=True
            ),
            _target("DROP"),
        ),
    )
    match = nft.statements[0]
    assert isinstance(match, NftMatch)
    assert match.expr == "ip daddr != @badguys"


def test_translate_rule_match_set_external_name_refused() -> None:
    # A bare (non-$var) name is an external ipset, unreachable from nft.
    with pytest.raises(
        FermError,
        match=(
            r"external ipset 'blocklist' cannot be referenced from nftables; "
            r"declare it with @set \$blocklist ="
        ),
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(_match_set_opt("blocklist", "src"), _target("DROP")),
        )


def test_translate_rule_match_set_multi_flag_refused() -> None:
    # `(src dst)` arrives comma-joined; it needs a concatenated set type.
    with pytest.raises(
        FermError,
        match=r"^option 'match-set': multiple set-match flags need",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _match_set_opt(SetRef("x", ["10.1.2.3"]), "src,dst"),
                _target("DROP"),
            ),
        )


def test_translate_rule_match_set_declaration_pickup() -> None:
    # The emitted match carries the SetRef + selector, so the later
    # declaration pass sees the named set with no match-set awareness.
    setref = SetRef("badguys", ["10.1.2.3"])
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(_match_set_opt(setref, "src"), _target("DROP")),
    )
    from pyferm.backend.nft import _SetDecl

    decls = _collect_set_declarations(Family.IP, {"INPUT": [nft]})
    assert "badguys" in decls
    badguys_decl = decls["badguys"]
    assert isinstance(badguys_decl, _SetDecl)
    assert badguys_decl.elements == ["10.1.2.3"]


def test_translate_rule_match_set_empty_set_guard_sees_nested() -> None:
    # A family-filtered-empty set nested in Params must still trip the guard
    # the caller relies on to drop the rule before translation.
    rule = RenderedRule(
        options=[
            _match_set_opt(SetRef("x", []), "src"),
            _target("DROP"),
        ],
        script=None,
    )
    with pytest.raises(FermError, match="internal error"):
        translate_rule(Family.IP6, "filter", rule)


def test_translate_rule_match_set_empty_set_guard_sees_negated_nested() -> (
    None
):
    rule = RenderedRule(
        options=[
            _match_set_opt(SetRef("x", []), "src", negated=True),
            _target("DROP"),
        ],
        script=None,
    )
    with pytest.raises(FermError, match="internal error"):
        translate_rule(Family.IP6, "filter", rule)


def test_translate_rule_match_set_second_setref_refused() -> None:
    # The one-set-per-rule guard must count the SetRef nested in match-set.
    with pytest.raises(FermError, match="at most one named set"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("source", SetRef("a", ["10.0.0.1"])),
                _match_set_opt(SetRef("b", ["10.0.0.2"]), "src"),
                _target("DROP"),
            ),
        )


def test_translate_rule_match_set_second_setref_refused_when_negated() -> None:
    with pytest.raises(FermError, match="at most one named set"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("source", SetRef("a", ["10.0.0.1"])),
                _match_set_opt(SetRef("b", ["10.0.0.2"]), "dst", negated=True),
                _target("DROP"),
            ),
        )


def test_translate_match_negated_interface_keeps_inequality() -> None:
    # A negated interface must keep its `!=`; the shared `_op` negation prefix
    # is easy to lose on the interface arm specifically.
    assert (
        translate_match(Family.IP, _opt("in-interface", Negated("eth0")), None)
        == 'iifname != "eth0"'
    )


# ---------------------------------------------------------------------------
# serialize_table: named-set declaration emission (mutation-hardening)
# ---------------------------------------------------------------------------


def test_serialize_table_emits_named_set_declarations() -> None:
    from pyferm.backend.nft import NftSetType, _SetDecl

    decls: dict[str, _SetDecl | _DynSetDecl] = {
        "ports": _SetDecl(NftSetType.INET_SERVICE, False, ["22", "80"]),
        "nets": _SetDecl(NftSetType.IPV4_ADDR, True, ["10.0.0.0/8"]),
    }
    table = NftTable(family="ip", name="ferm")
    out = serialize_table(
        table, [NftRegularChain("c")], {"c": []}, decls, noflush=False
    )
    # Declarations are emitted by sorted name; the interval flag is present
    # only on the set that needs it, and elements render as a set body.
    assert (
        "add set ip ferm nets { type ipv4_addr; flags interval; }\n"
        "add element ip ferm nets { 10.0.0.0/8 }\n"
        "add set ip ferm ports { type inet_service; }\n"
        "add element ip ferm ports { 22, 80 }\n"
    ) in out


def test_serialize_table_chain_absent_from_rules_map() -> None:
    # A chain with no entry in the rules map contributes no rule lines (the
    # `rules.get(name, [])` default must be an empty list, not None).
    table = NftTable(family="ip", name="ferm")
    out = serialize_table(
        table, [NftRegularChain("empty")], {}, {}, noflush=True
    )
    assert out == "add table ip ferm\nadd chain ip ferm empty\n"


def test_serialize_table_rule_without_statements_has_no_separator() -> None:
    # An empty rule (no statements, no comment) renders `add rule ... <chain>`
    # with no trailing separator.
    table = NftTable(family="ip", name="ferm")
    out = serialize_table(
        table,
        [NftRegularChain("c")],
        {"c": [NftRule([])]},
        {},
        noflush=True,
    )
    assert "add rule ip ferm c\n" in out


# ---------------------------------------------------------------------------
# _set_type_and_elements: per-selector typing + interval flag
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "selector", "elements", "type_name", "interval"),
    [
        (Family.IP, "ip daddr", ["10.0.0.1"], "IPV4_ADDR", False),
        (Family.IP6, "ip6 daddr", ["fe80::1"], "IPV6_ADDR", False),
        (Family.IP, "tcp sport", ["22"], "INET_SERVICE", False),
        (Family.IP, "tcp dport", ["22"], "INET_SERVICE", False),
        # A plain host must NOT need `flags interval`; a CIDR must.
        (Family.IP, "ip saddr", ["10.0.0.1"], "IPV4_ADDR", False),
        (Family.IP, "ip saddr", ["10.0.0.0/8"], "IPV4_ADDR", True),
    ],
)
def test_set_type_and_elements_selector_typing(
    domain: Family,
    selector: str,
    elements: list[Value],
    type_name: str,
    interval: bool,
) -> None:
    from pyferm.backend.nft import NftSetType, _set_type_and_elements

    type_, flags_interval, _ = _set_type_and_elements(
        domain, selector, SetRef("s", elements)
    )
    assert type_ is getattr(NftSetType, type_name)
    assert flags_interval is interval


def test_classify_target_unfolds_per_array_element(tmp_path: Path) -> None:
    # A non-set-eligible dscp match array stays a cartesian unfold, so the
    # CLASSIFY verdict is carried onto each resulting rule.
    ferm = (
        "domain ip table mangle chain OUTPUT {\n"
        '    mod dscp dscp (0x0a 0x2e) CLASSIFY set-class "1:10";\n'
        "}\n"
    )
    out = _run_apply(tmp_path, ferm, None)
    assert "ip dscp af11 meta priority set 1:10" in out
    assert "ip dscp ef meta priority set 1:10" in out


# --- 2026-07-10 vocabulary batch: ct status, NFQUEUE, TTL/HL, SYNPROXY,
# --- NETMAP, masked mark, mod hl.  Emission spellings pinned against a
# --- live kernel readback (see tests/integration/test_nft_live_vocabulary).


def test_translate_match_ctstate_nat_pseudo_states_are_ct_status() -> None:
    # the kernel readback prints status bits deduplicated in ascending
    # IPS_* bit order (snat 0x10 before dnat 0x20)
    assert (
        translate_match(
            Family.IP,
            _opt("ctstate", "DNAT,SNAT,DNAT", module="conntrack"),
            None,
        )
        == "ct status snat,dnat"
    )
    # negation is the masked bang form even for a single member: the
    # status register holds MANY bits, so whole-value `!=` would match
    # nearly everything instead of "bit not set"
    assert (
        translate_match(
            Family.IP,
            _opt("ctstate", Negated("DNAT"), module="conntrack"),
            None,
        )
        == "ct status ! dnat"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("ctstate", Negated("DNAT,SNAT"), module="conntrack"),
            None,
        )
        == "ct status ! snat,dnat"
    )


def test_translate_match_ct_state_list_is_bit_sorted() -> None:
    # kernel readback re-sorts a state list into bit order; emitting the
    # source order left --plan diffing an applied ruleset forever
    assert (
        translate_match(
            Family.IP,
            _opt("state", "RELATED,ESTABLISHED", module="state"),
            None,
        )
        == "ct state established,related"
    )


def test_translate_match_ctstatus() -> None:
    assert (
        translate_match(
            Family.IP,
            _opt("ctstatus", "CONFIRMED,ASSURED", module="conntrack"),
            None,
        )
        == "ct status assured,confirmed"
    )
    # xt spells the bit SEEN_REPLY; nft spells it seen-reply
    assert (
        translate_match(
            Family.IP,
            _opt("ctstatus", "SEEN_REPLY", module="conntrack"),
            None,
        )
        == "ct status seen-reply"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("ctstatus", Negated("EXPECTED"), module="conntrack"),
            None,
        )
        == "ct status ! expected"
    )
    # NONE is an empty status mask with no nft ct status spelling
    with pytest.raises(FermError, match=r"^ct status 'none' not yet"):
        translate_match(
            Family.IP, _opt("ctstatus", "NONE", module="conntrack"), None
        )
    with pytest.raises(FermError, match=r"^ct status 'banana' not yet"):
        translate_match(
            Family.IP, _opt("ctstatus", "BANANA", module="conntrack"), None
        )


def test_translate_match_hl_comparators() -> None:
    # mod hl is xt_ttl's ip6 twin; readback prints `>`/`<`
    assert (
        translate_match(Family.IP6, _opt("hl-eq", "255", module="hl"), None)
        == "ip6 hoplimit 255"
    )
    assert (
        translate_match(Family.IP6, _opt("hl-gt", "254", module="hl"), None)
        == "ip6 hoplimit > 254"
    )
    assert (
        translate_match(Family.IP6, _opt("hl-lt", "1", module="hl"), None)
        == "ip6 hoplimit < 1"
    )
    assert (
        translate_match(
            Family.IP6, _opt("hl-eq", Negated("64"), module="hl"), None
        )
        == "ip6 hoplimit != 64"
    )
    with pytest.raises(FermError, match=r"^invalid hl 'banana'"):
        translate_match(Family.IP6, _opt("hl-eq", "banana", module="hl"), None)
    # ip6t_hl is ip6-only; the ip pass falls through to the refusal
    with pytest.raises(FermError, match=r"^option 'hl-eq' not yet"):
        translate_match(Family.IP, _opt("hl-eq", "255", module="hl"), None)


def test_build_verdict_nfqueue() -> None:
    # the kernel reads `queue num N` back as `queue [flags ...] to N`
    # and a bare NFQUEUE as `queue to 0`
    assert (
        build_verdict(Family.IP, "filter", "jump", "NFQUEUE", {}).to_text()
        == "queue to 0"
    )
    num = {"queue-num": _opt("queue-num", "65535", module="NFQUEUE")}
    assert (
        build_verdict(Family.IP, "filter", "jump", "NFQUEUE", num).to_text()
        == "queue to 65535"
    )
    balance = {"queue-balance": _opt("queue-balance", "0:3", module="NFQUEUE")}
    assert (
        build_verdict(
            Family.IP, "filter", "jump", "NFQUEUE", balance
        ).to_text()
        == "queue to 0-3"
    )
    bypass = {
        "queue-num": _opt("queue-num", "1", module="NFQUEUE"),
        "queue-bypass": _opt("queue-bypass", None, module="NFQUEUE"),
    }
    assert (
        build_verdict(Family.IP, "filter", "jump", "NFQUEUE", bypass).to_text()
        == "queue flags bypass to 1"
    )
    # flags print in bypass,fanout order regardless of source order
    fanout = {
        "queue-cpu-fanout": _opt("queue-cpu-fanout", None, module="NFQUEUE"),
        "queue-balance": _opt("queue-balance", "0:3", module="NFQUEUE"),
        "queue-bypass": _opt("queue-bypass", None, module="NFQUEUE"),
    }
    assert (
        build_verdict(Family.IP, "filter", "jump", "NFQUEUE", fanout).to_text()
        == "queue flags bypass,fanout to 0-3"
    )


def test_build_verdict_nfqueue_refusals() -> None:
    both = {
        "queue-num": _opt("queue-num", "1", module="NFQUEUE"),
        "queue-balance": _opt("queue-balance", "0:3", module="NFQUEUE"),
    }
    with pytest.raises(FermError, match=r"mutually exclusive"):
        build_verdict(Family.IP, "filter", "jump", "NFQUEUE", both)
    # xt_NFQUEUE itself refuses --queue-cpu-fanout without --queue-balance
    lone_fanout = {
        "queue-cpu-fanout": _opt("queue-cpu-fanout", None, module="NFQUEUE")
    }
    with pytest.raises(FermError, match=r"needs 'queue-balance'"):
        build_verdict(Family.IP, "filter", "jump", "NFQUEUE", lone_fanout)
    for bad in ("65536", "banana", "-1"):
        num = {"queue-num": _opt("queue-num", bad, module="NFQUEUE")}
        with pytest.raises(FermError, match=r"^invalid queue-num"):
            build_verdict(Family.IP, "filter", "jump", "NFQUEUE", num)
    for bad in ("0", "3:banana", "0-3"):
        balance = {
            "queue-balance": _opt("queue-balance", bad, module="NFQUEUE")
        }
        with pytest.raises(FermError, match=r"^invalid queue-balance"):
            build_verdict(Family.IP, "filter", "jump", "NFQUEUE", balance)


def test_build_verdict_ttl_and_hl_set() -> None:
    ttl = {"ttl-set": _opt("ttl-set", "42", module="TTL")}
    assert (
        build_verdict(Family.IP, "mangle", "jump", "TTL", ttl).to_text()
        == "ip ttl set 42"
    )
    hl = {"hl-set": _opt("hl-set", "255", module="HL")}
    assert (
        build_verdict(Family.IP6, "mangle", "jump", "HL", hl).to_text()
        == "ip6 hoplimit set 255"
    )
    # nft's payload-set grammar has no arithmetic form
    inc = {"ttl-inc": _opt("ttl-inc", "1", module="TTL")}
    with pytest.raises(FermError, match=r"^option 'ttl-inc' not yet"):
        build_verdict(Family.IP, "mangle", "jump", "TTL", inc)
    dec = {"hl-dec": _opt("hl-dec", "1", module="HL")}
    with pytest.raises(FermError, match=r"^option 'hl-dec' not yet"):
        build_verdict(Family.IP6, "mangle", "jump", "HL", dec)
    with pytest.raises(FermError, match=r"^TTL target not yet supported"):
        build_verdict(Family.IP, "mangle", "jump", "TTL", {})
    bad = {"ttl-set": _opt("ttl-set", "256", module="TTL")}
    with pytest.raises(FermError, match=r"^invalid ttl-set '256'"):
        build_verdict(Family.IP, "mangle", "jump", "TTL", bad)
    # TTL is ip-only: the ip6 pass falls through to the registry refusal
    with pytest.raises(FermError, match=r"^target 'TTL'"):
        build_verdict(Family.IP6, "mangle", "jump", "TTL", ttl)


def test_build_verdict_synproxy() -> None:
    def comp(**names: str | None) -> dict[str, RenderedOption]:
        return {
            key.replace("_", "-"): _opt(
                key.replace("_", "-"), value, module="SYNPROXY"
            )
            for key, value in names.items()
        }

    # readback order is fixed: mss, wscale, timestamp, sack-perm
    full = comp(sack_perm=None, timestamp=None, wscale="7", mss="1460")
    assert (
        build_verdict(Family.IP, "filter", "jump", "SYNPROXY", full).to_text()
        == "synproxy mss 1460 wscale 7 timestamp sack-perm"
    )
    # mss/wscale read back as a PAIR whenever either is given (the nft
    # frontend raises both kernel flags; the absent one prints as 0)
    assert (
        build_verdict(
            Family.IP, "filter", "jump", "SYNPROXY", comp(mss="1460")
        ).to_text()
        == "synproxy mss 1460 wscale 0"
    )
    assert (
        build_verdict(
            Family.IP6, "filter", "jump", "SYNPROXY", comp(wscale="7")
        ).to_text()
        == "synproxy mss 0 wscale 7"
    )
    assert (
        build_verdict(
            Family.IP, "filter", "jump", "SYNPROXY", comp(sack_perm=None)
        ).to_text()
        == "synproxy sack-perm"
    )
    assert (
        build_verdict(Family.IP, "filter", "jump", "SYNPROXY", {}).to_text()
        == "synproxy"
    )
    # nft's synproxy grammar has no --ecn twin
    with pytest.raises(FermError, match=r"^option 'ecn' has no nft"):
        build_verdict(Family.IP, "filter", "jump", "SYNPROXY", comp(ecn=None))
    with pytest.raises(FermError, match=r"^invalid synproxy mss"):
        build_verdict(
            Family.IP, "filter", "jump", "SYNPROXY", comp(mss="banana")
        )


def _flag(name: str, module: str) -> RenderedOption:
    return _opt(name, None, module=module)


def test_build_verdict_nat_flags() -> None:
    # xt --random / --random-fully / --persistent read back in a fixed order
    # (random/fully-random first, persistent last), comma-joined, no space;
    # --random-fully is the xt spelling of nft's fully-random.
    snat = {
        "to-source": _opt(
            "to-source", Multi(values=["1.2.3.4"]), module="SNAT"
        ),
        "random": _flag("random", "SNAT"),
        "persistent": _flag("persistent", "SNAT"),
    }
    assert (
        build_verdict(Family.IP, "nat", "jump", "SNAT", snat).to_text()
        == "snat to 1.2.3.4 random,persistent"
    )
    dnat = {
        "to-destination": _opt(
            "to-destination", Multi(values=["10.0.0.5"]), module="DNAT"
        ),
        "persistent": _flag("persistent", "DNAT"),
    }
    assert (
        build_verdict(Family.IP, "nat", "jump", "DNAT", dnat).to_text()
        == "dnat to 10.0.0.5 persistent"
    )
    # MASQUERADE takes flags with no to-ports (the bare-verb return path)
    masq = {"random": _flag("random", "MASQUERADE")}
    assert (
        build_verdict(Family.IP, "nat", "jump", "MASQUERADE", masq).to_text()
        == "masquerade random"
    )
    both = {
        "random": _flag("random", "MASQUERADE"),
        "random-fully": _flag("random-fully", "MASQUERADE"),
    }
    assert (
        build_verdict(Family.IP, "nat", "jump", "MASQUERADE", both).to_text()
        == "masquerade random,fully-random"
    )
    fully = {"random-fully": _flag("random-fully", "MASQUERADE")}
    assert (
        build_verdict(Family.IP, "nat", "jump", "MASQUERADE", fully).to_text()
        == "masquerade fully-random"
    )
    # REDIRECT to-ports + random needs a transport match
    redirect = {
        "to-ports": _opt(
            "to-ports", Multi(values=["8081"]), module="REDIRECT"
        ),
        "random": _flag("random", "REDIRECT"),
    }
    assert (
        build_verdict(
            Family.IP, "nat", "jump", "REDIRECT", redirect, has_transport=True
        ).to_text()
        == "redirect to :8081 random"
    )
    # flag order in the companion dict must NOT change the emission order
    reordered = {
        "persistent": _flag("persistent", "SNAT"),
        "to-source": _opt(
            "to-source", Multi(values=["1.2.3.4"]), module="SNAT"
        ),
        "random": _flag("random", "SNAT"),
    }
    assert (
        build_verdict(Family.IP, "nat", "jump", "SNAT", reordered).to_text()
        == "snat to 1.2.3.4 random,persistent"
    )


def test_build_verdict_same_still_refuses_with_random_companion() -> None:
    # SAME shares the `random` flag with the translated NAT targets, so the
    # flag is now collected as a companion for it too; without a SAME arm in
    # build_verdict the target must keep falling into the registry refusal
    # instead of the user-chain fallthrough.
    same = {"random": _flag("random", "SAME")}
    with pytest.raises(
        FermError,
        match=r"^target 'SAME' \(or jump to a chain of that name\)"
        r" not yet supported by nft backend$",
    ):
        build_verdict(Family.IP, "nat", "jump", "SAME", same)


def test_build_verdict_ct_notrack() -> None:
    notrack = {"notrack": _flag("notrack", "CT")}
    assert (
        build_verdict(Family.IP, "raw", "jump", "CT", notrack).to_text()
        == "notrack"
    )
    # the CT notrack path emits the same spelling as the standalone NOTRACK
    assert (
        build_verdict(Family.IP, "raw", "jump", "NOTRACK", {}).to_text()
        == "notrack"
    )


def test_build_verdict_ct_refusals() -> None:
    # a bare CT (no companion) has no nft spelling (the xt oracle refuses too)
    with pytest.raises(
        FermError, match=r"^CT target not yet supported by nft backend$"
    ):
        build_verdict(Family.IP, "raw", "jump", "CT", {})
    # every other CT option needs object declarations that are out of scope
    for option in (
        "helper",
        "ctevents",
        "expevents",
        "zone-orig",
        "zone-reply",
        "zone",
        "timeout",
    ):
        comp = {option: _opt(option, "x", module="CT")}
        with pytest.raises(
            FermError, match=rf"^CT target option '{option}' not yet"
        ):
            build_verdict(Family.IP, "raw", "jump", "CT", comp)
    # an unsupported option beside notrack still refuses (refusal wins)
    both = {
        "notrack": _flag("notrack", "CT"),
        "helper": _opt("helper", "ftp", module="CT"),
    }
    with pytest.raises(FermError, match=r"^CT target option 'helper' not yet"):
        build_verdict(Family.IP, "raw", "jump", "CT", both)


def test_build_verdict_checksum_refused() -> None:
    comp = {"checksum-fill": _flag("checksum-fill", "CHECKSUM")}
    with pytest.raises(FermError, match=r"^CHECKSUM target has no nft"):
        build_verdict(Family.IP, "mangle", "jump", "CHECKSUM", comp)


def _tproxy(**names: str | None) -> dict[str, RenderedOption]:
    return {
        key.replace("_", "-"): _opt(
            key.replace("_", "-"),
            Multi(values=[value]) if value is not None else None,
            module="TPROXY",
        )
        for key, value in names.items()
    }


def test_build_verdict_tproxy() -> None:
    # a bare on-port maps to `tproxy to :P accept`
    assert (
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "TPROXY",
            _tproxy(on_port="3129"),
            has_transport=True,
        ).to_text()
        == "tproxy to :3129 accept"
    )
    # on-ip adds the address; ip6 brackets it
    assert (
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "TPROXY",
            _tproxy(on_port="3130", on_ip="127.0.0.1"),
            has_transport=True,
        ).to_text()
        == "tproxy to 127.0.0.1:3130 accept"
    )
    assert (
        build_verdict(
            Family.IP6,
            "mangle",
            "jump",
            "TPROXY",
            _tproxy(on_port="3131", on_ip="fe80::1"),
            has_transport=True,
        ).to_text()
        == "tproxy to [fe80::1]:3131 accept"
    )
    # --tproxy-mark folds to the kernel and/or mark rewrite between the
    # destination and the terminal accept
    assert (
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "TPROXY",
            _tproxy(on_port="3129", tproxy_mark="0x1/0x1"),
            has_transport=True,
        ).to_text()
        == "tproxy to :3129 meta mark set meta mark | 0x00000001 accept"
    )


def test_build_verdict_tproxy_refusals() -> None:
    # xt_TPROXY needs a transport match (the kernel rejects the applied rule)
    with pytest.raises(FermError, match=r"needs a transport protocol match"):
        build_verdict(
            Family.IP, "mangle", "jump", "TPROXY", _tproxy(on_port="3129")
        )
    # and always demands on-port (the xt oracle refuses a bare/on-ip-only form)
    with pytest.raises(FermError, match=r"TPROXY needs 'on-port'"):
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "TPROXY",
            _tproxy(on_ip="127.0.0.1"),
            has_transport=True,
        )
    for bad in ("65536", "banana", "-1"):
        with pytest.raises(FermError, match=r"^invalid on-port"):
            build_verdict(
                Family.IP,
                "mangle",
                "jump",
                "TPROXY",
                _tproxy(on_port=bad),
                has_transport=True,
            )


def test_masked_mark_set_canon() -> None:
    from pyferm.backend.nft import _masked_mark_set

    # a bare value (no slash) or a full mask is a plain set
    assert _masked_mark_set("0x1") == "meta mark set 0x00000001"
    assert _masked_mark_set("0x1/0xffffffff") == "meta mark set 0x00000001"
    # small values still pad to 8 hex digits
    assert (
        _masked_mark_set("0x5/0x5") == "meta mark set meta mark | 0x00000005"
    )
    # value == mask -> A collapses to all-ones -> the OR-only form
    assert (
        _masked_mark_set("0x1/0x1") == "meta mark set meta mark | 0x00000001"
    )
    # value == 0 -> the AND-only form (clear the masked bits)
    assert (
        _masked_mark_set("0x0/0xff") == "meta mark set meta mark & 0xffffff00"
    )
    # the general and/or form; the AND operand already carries the OR bits
    assert (
        _masked_mark_set("0x12/0xff")
        == "meta mark set meta mark & 0xffffff12 | 0x00000012"
    )


def test_masked_mark_set_refusals() -> None:
    from pyferm.backend.nft import _masked_mark_set

    # a zero mask is a no-op assignment the kernel does not round-trip
    with pytest.raises(FermError, match=r"has a zero mask"):
        _masked_mark_set("0x0/0x0")
    # a value with bits outside its mask canonicalizes differently
    with pytest.raises(FermError, match=r"has bits outside its mask"):
        _masked_mark_set("0x3/0x1")


def test_translate_rule_time_hour_day_span() -> None:
    def time_opt(name: str, value: Value) -> RenderedOption:
        return _opt(name, value, module="time")

    # hour: seconds trimmed when zero, xt default stop 23:59:59
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            time_opt("timestart", "09:00"),
            time_opt("timestop", "18:00"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        'meta hour "09:00"-"18:00"',
        "accept",
    ]
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(time_opt("timestart", "09:30:30"), _target("ACCEPT")),
    )
    assert nft.statements[0].to_text() == 'meta hour "09:30:30"-"23:59:59"'
    # day: numeric-ordered quoted names, dedup, a single day unbraced
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(time_opt("weekdays", "Sat,Mon,Mon,Tue"), _target("ACCEPT")),
    )
    assert (
        nft.statements[0].to_text()
        == 'meta day { "Monday", "Tuesday", "Saturday" }'
    )
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(time_opt("weekdays", "Sun"), _target("ACCEPT")),
    )
    assert nft.statements[0].to_text() == 'meta day "Sunday"'
    # xt numeric days (Mon=1..Sun=7) map to nft's Sunday=0 order
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(time_opt("weekdays", "7,1"), _target("ACCEPT")),
    )
    assert nft.statements[0].to_text() == 'meta day { "Sunday", "Monday" }'
    # negated weekdays -> !=
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(time_opt("weekdays", Negated(value="Mon,Tue")), _target("DROP")),
    )
    assert nft.statements[0].to_text() == 'meta day != { "Monday", "Tuesday" }'
    # time: full-datetime range, plus open >= / <= bounds
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            time_opt("datestart", "2026-01-01"),
            time_opt("datestop", "2026-12-31"),
            _target("ACCEPT"),
        ),
    )
    assert (
        nft.statements[0].to_text()
        == 'meta time "2026-01-01 00:00:00"-"2026-12-31 00:00:00"'
    )
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(time_opt("datestart", "2026-06-01T09:30:00"), _target("ACCEPT")),
    )
    assert nft.statements[0].to_text() == 'meta time >= "2026-06-01 09:30:00"'
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(time_opt("datestop", "2026-12-31"), _target("DROP")),
    )
    assert nft.statements[0].to_text() == 'meta time <= "2026-12-31 00:00:00"'
    # hour, day, and time compose in a fixed order within one rule
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            time_opt("timestart", "09:00"),
            time_opt("timestop", "17:00"),
            time_opt("weekdays", "Mon,Fri"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        'meta hour "09:00"-"17:00"',
        'meta day { "Monday", "Friday" }',
        "accept",
    ]


def test_translate_rule_time_refusals() -> None:
    def time_opt(name: str, value: Value) -> RenderedOption:
        return _opt(name, value, module="time")

    for refused in ("monthday", "kerneltz", "contiguous"):
        with pytest.raises(FermError, match=rf"mod time '{refused}' not yet"):
            translate_rule(
                Family.IP,
                "filter",
                _rule(
                    time_opt(refused, "1"),
                    time_opt("timestart", "09:00"),
                    _target("ACCEPT"),
                ),
            )
    # days and weekdays are aliases of one xt flag; both at once conflicts
    with pytest.raises(
        FermError, match=r"cannot combine 'days' and 'weekdays'"
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                time_opt("days", "Mon"),
                time_opt("weekdays", "Tue"),
                _target("ACCEPT"),
            ),
        )
    with pytest.raises(FermError, match=r"unknown weekday 'Funday'"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(time_opt("weekdays", "Funday"), _target("ACCEPT")),
        )
    with pytest.raises(FermError, match=r"invalid time 'noon'"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(time_opt("timestart", "noon"), _target("ACCEPT")),
        )
    with pytest.raises(FermError, match=r"invalid date 'someday'"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(time_opt("datestart", "someday"), _target("ACCEPT")),
        )


def test_two_tproxy_marks_do_not_collapse() -> None:
    # different verdict text = different rules; the collapse/vmap pass must
    # not fold two tproxy rules that differ only in their mark rewrite
    def tproxy_rule(mark: str) -> NftRule:
        return NftRule(
            statements=[
                NftMatch(
                    "tcp dport 3129", set_key="tcp dport", element="3129"
                ),
                NftVerdict(
                    f"tproxy to :3129 meta mark set meta mark | {mark} accept"
                ),
            ]
        )

    out = _collapse_chain_rules(
        [tproxy_rule("0x00000001"), tproxy_rule("0x00000002")]
    )
    assert len(out) == 2


def _netmap_rule(
    match_name: str, match_value: Value, to_value: str
) -> RenderedRule:
    return _rule(
        _opt(match_name, match_value),
        _target("NETMAP"),
        _opt("to", to_value, module="NETMAP"),
    )


def test_translate_rule_netmap_prefix_map_sides() -> None:
    # prerouting/output rewrite the destination, postrouting/input the
    # source; the map key is the rule's own same-side address match
    nft = translate_rule(
        Family.IP,
        "nat",
        _netmap_rule("destination", "10.66.0.0/24", "192.0.2.0/24"),
        chain="PREROUTING",
    )
    assert [s.to_text() for s in nft.statements] == [
        "ip daddr 10.66.0.0/24",
        "dnat ip prefix to ip daddr map { 10.66.0.0/24 : 192.0.2.0/24 }",
    ]
    nft = translate_rule(
        Family.IP,
        "nat",
        _netmap_rule("source", "192.0.2.0/24", "10.66.0.0/24"),
        chain="POSTROUTING",
    )
    assert [s.to_text() for s in nft.statements] == [
        "ip saddr 192.0.2.0/24",
        "snat ip prefix to ip saddr map { 192.0.2.0/24 : 10.66.0.0/24 }",
    ]
    nft = translate_rule(
        Family.IP6,
        "nat",
        _netmap_rule("destination", "fd00:7::/64", "fd00:9::/64"),
        chain="OUTPUT",
    )
    assert [s.to_text() for s in nft.statements] == [
        "ip6 daddr fd00:7::/64",
        "dnat ip6 prefix to ip6 daddr map { fd00:7::/64 : fd00:9::/64 }",
    ]


def test_translate_rule_netmap_refusals() -> None:
    rule = _netmap_rule("destination", "10.66.0.0/24", "192.0.2.0/24")
    # the hook side is unknown in a custom chain (or without chain context)
    for chain in ("dmz_map", None):
        with pytest.raises(FermError, match=r"built-in nat chain"):
            translate_rule(Family.IP, "nat", rule, chain=chain)
    # ...and outside the nat table (where xt restricts NETMAP anyway)
    with pytest.raises(FermError, match=r"built-in nat chain"):
        translate_rule(Family.IP, "mangle", rule, chain="PREROUTING")
    # the map key must be the same-side address match
    wrong_side = _netmap_rule("source", "10.66.0.0/24", "192.0.2.0/24")
    with pytest.raises(FermError, match=r"exactly one 'destination' match"):
        translate_rule(Family.IP, "nat", wrong_side, chain="PREROUTING")
    negated = _netmap_rule(
        "destination", Negated("10.66.0.0/24"), "192.0.2.0/24"
    )
    with pytest.raises(FermError, match=r"negated 'destination'"):
        translate_rule(Family.IP, "nat", negated, chain="PREROUTING")
    mismatch = _netmap_rule("destination", "10.66.0.0/25", "192.0.2.0/24")
    with pytest.raises(FermError, match=r"prefix lengths differ"):
        translate_rule(Family.IP, "nat", mismatch, chain="PREROUTING")
    host_bits = _netmap_rule("destination", "10.66.0.1/24", "192.0.2.0/24")
    with pytest.raises(FermError, match=r"host bits set"):
        translate_rule(Family.IP, "nat", host_bits, chain="PREROUTING")
    bare = _netmap_rule("destination", "10.66.0.0/24", "192.0.2.1")
    with pytest.raises(FermError, match=r"explicit prefix length"):
        translate_rule(Family.IP, "nat", bare, chain="PREROUTING")
    family_mix = _netmap_rule("destination", "10.66.0.0/24", "fd00:9::/64")
    with pytest.raises(FermError, match=r"does not match the ip family"):
        translate_rule(Family.IP, "nat", family_mix, chain="PREROUTING")
    without_to = _rule(_opt("destination", "10.66.0.0/24"), _target("NETMAP"))
    with pytest.raises(FermError, match=r"^NETMAP target not yet"):
        translate_rule(Family.IP, "nat", without_to, chain="PREROUTING")


def test_module_qualified_companions_do_not_swallow_match_options() -> None:
    # `mss` (tcp match) and `to` (string match) share their spelling with
    # SYNPROXY's and NETMAP's companion options; the match-module twin
    # must translate as a match (batch 8), not vanish into a companion
    tcp_mss = _rule(
        _opt("protocol", "tcp", kind=OptionKind.PROTO),
        _opt("mss", "1400", module="tcp"),
        _target("ACCEPT"),
    )
    nft = translate_rule(Family.IP, "filter", tcp_mss, chain="INPUT")
    assert [s.to_text() for s in nft.statements] == [
        "tcp option maxseg size 1400",
        "accept",
    ]
    string_to = _rule(
        _opt("to", "100", module="string"),
        _target("ACCEPT"),
    )
    with pytest.raises(FermError, match=r"^option 'to' not yet"):
        translate_rule(Family.IP, "filter", string_to, chain="INPUT")


# --- 2026-07-10 vocabulary batch 5 (light part): statistic, pkttype,
# --- TCPOPTSTRIP.  Emission spellings pinned against a live kernel readback
# --- (see tests/integration/test_nft_live_vocabulary).


def _statistic(name: str, value: Value) -> RenderedOption:
    return _opt(name, value, module="statistic")


def _statistic_texts(*stat_opts: RenderedOption) -> list[str]:
    nft = translate_rule(
        Family.IP, "filter", _rule(*stat_opts, _target("ACCEPT"))
    )
    return [s.to_text() for s in nft.statements]


def test_translate_rule_statistic_random() -> None:
    # xt stores the probability as round(p * 2**31); nft matches it with a
    # masked meta random.  p == 1.0 yields a threshold above the mask, which
    # nft accepts (the match is then always true).
    assert _statistic_texts(
        _statistic("mode", "random"), _statistic("probability", "0.5")
    ) == ["meta random & 2147483647 < 1073741824", "accept"]
    assert _statistic_texts(
        _statistic("mode", "random"), _statistic("probability", "1.0")
    ) == ["meta random & 2147483647 < 2147483648", "accept"]
    assert _statistic_texts(
        _statistic("mode", "random"), _statistic("probability", "0")
    ) == ["meta random & 2147483647 < 0", "accept"]


def test_translate_rule_statistic_nth() -> None:
    # the bare `numgen inc mod N P` form; xt's --packet defaults to 0
    assert _statistic_texts(
        _statistic("mode", "nth"),
        _statistic("every", "10"),
        _statistic("packet", "3"),
    ) == ["numgen inc mod 10 3", "accept"]
    assert _statistic_texts(
        _statistic("mode", "nth"), _statistic("every", "10")
    ) == ["numgen inc mod 10 0", "accept"]


def test_translate_rule_statistic_negated_mode_refused() -> None:
    with pytest.raises(FermError, match=r"^mod statistic 'mode' cannot be"):
        _statistic_texts(
            _statistic("mode", Negated("random")),
            _statistic("probability", "0.5"),
        )


def test_translate_rule_statistic_nth_without_every_refused() -> None:
    with pytest.raises(FermError, match=r"^mod statistic mode nth needs"):
        _statistic_texts(_statistic("mode", "nth"))


def test_translate_rule_statistic_probability_out_of_range_refused() -> None:
    for bad in ("1.5", "-0.1", "2"):
        with pytest.raises(FermError, match=r"outside \[0, 1\]"):
            _statistic_texts(
                _statistic("mode", "random"),
                _statistic("probability", bad),
            )


def test_translate_rule_statistic_unknown_mode_refused() -> None:
    with pytest.raises(FermError, match=r"^unknown statistic mode 'banana'"):
        _statistic_texts(_statistic("mode", "banana"))


def test_translate_rule_statistic_random_without_probability_refused() -> None:
    with pytest.raises(
        FermError, match=r"^mod statistic mode random needs a 'probability'"
    ):
        _statistic_texts(_statistic("mode", "random"))


def test_translate_rule_statistic_packet_ge_every_refused() -> None:
    # xt requires --packet < --every (packet is 0-based)
    with pytest.raises(FermError, match=r"must be less than every"):
        _statistic_texts(
            _statistic("mode", "nth"),
            _statistic("every", "10"),
            _statistic("packet", "10"),
        )


def test_translate_rule_statistic_invalid_scalars_refused() -> None:
    with pytest.raises(FermError, match=r"^invalid statistic probability"):
        _statistic_texts(
            _statistic("mode", "random"),
            _statistic("probability", "abc"),
        )
    for bad in ("0", "abc"):
        with pytest.raises(FermError, match=r"^invalid statistic every"):
            _statistic_texts(
                _statistic("mode", "nth"), _statistic("every", bad)
            )
    with pytest.raises(FermError, match=r"^invalid statistic packet"):
        _statistic_texts(
            _statistic("mode", "nth"),
            _statistic("every", "10"),
            _statistic("packet", "abc"),
        )


def test_translate_rule_statistic_missing_mode_refused() -> None:
    with pytest.raises(FermError, match=r"^mod statistic needs a 'mode'"):
        _statistic_texts(_statistic("probability", "0.5"))


def test_translate_rule_statistic_module_qualified_collection() -> None:
    # `every`/`packet` also name mod nth's own keywords; a non-statistic
    # `every` must NOT be folded into a statistic match (it falls through to
    # the generic refusal instead).
    rule = _rule(
        _opt("every", "10", module="nth"),
        _target("ACCEPT"),
    )
    with pytest.raises(FermError, match=r"^option 'every' not yet"):
        translate_rule(Family.IP, "filter", rule)


def test_translate_match_pkttype() -> None:
    # xt's `unicast` reads back from the kernel as `host`
    assert (
        translate_match(
            Family.IP, _opt("pkt-type", "unicast", module="pkttype"), None
        )
        == "meta pkttype host"
    )
    assert (
        translate_match(
            Family.IP, _opt("pkt-type", "broadcast", module="pkttype"), None
        )
        == "meta pkttype broadcast"
    )
    assert (
        translate_match(
            Family.IP, _opt("pkt-type", "multicast", module="pkttype"), None
        )
        == "meta pkttype multicast"
    )
    assert (
        translate_match(
            Family.IP,
            _opt("pkt-type", Negated("unicast"), module="pkttype"),
            None,
        )
        == "meta pkttype != host"
    )


def test_translate_match_pkttype_invalid_refused() -> None:
    with pytest.raises(FermError, match=r"^invalid pkttype 'banana'"):
        translate_match(
            Family.IP, _opt("pkt-type", "banana", module="pkttype"), None
        )


def _tcpoptstrip_rule(
    strip: str | None, *, protocol: str | None = "tcp"
) -> RenderedRule:
    options: list[RenderedOption] = []
    if protocol is not None:
        options.append(_opt("protocol", protocol, kind=OptionKind.PROTO))
    options.append(_target("TCPOPTSTRIP"))
    if strip is not None:
        options.append(_opt("strip-options", strip, module="TCPOPTSTRIP"))
    return _rule(*options)


def test_translate_rule_tcpoptstrip_names() -> None:
    # every xt mnemonic maps to its nft reset keyword; the rule carries no
    # verdict, only the reset series after the proto match
    nft = translate_rule(
        Family.IP,
        "mangle",
        _tcpoptstrip_rule("mss,wscale,sack-permitted,sack,timestamp,md5"),
    )
    assert [s.to_text() for s in nft.statements] == [
        "meta l4proto tcp",
        "reset tcp option maxseg",
        "reset tcp option window",
        "reset tcp option sack-perm",
        "reset tcp option sack",
        "reset tcp option timestamp",
        "reset tcp option md5sig",
    ]


def test_translate_rule_tcpoptstrip_numbers_respell() -> None:
    # the kernel respells known option kinds to names; unknown numbers stay
    # numeric
    nft = translate_rule(
        Family.IP, "mangle", _tcpoptstrip_rule("0,1,2,3,4,5,8,19,30,34")
    )
    assert [s.to_text() for s in nft.statements] == [
        "meta l4proto tcp",
        "reset tcp option eol",
        "reset tcp option nop",
        "reset tcp option maxseg",
        "reset tcp option window",
        "reset tcp option sack-perm",
        "reset tcp option sack",
        "reset tcp option timestamp",
        "reset tcp option md5sig",
        "reset tcp option mptcp",
        "reset tcp option fastopen",
    ]
    nft = translate_rule(Family.IP, "mangle", _tcpoptstrip_rule("6,254"))
    assert [s.to_text() for s in nft.statements] == [
        "meta l4proto tcp",
        "reset tcp option 6",
        "reset tcp option 254",
    ]


def test_translate_rule_tcpoptstrip_refusals() -> None:
    with pytest.raises(
        FermError, match=r"^TCPOPTSTRIP needs a tcp protocol match"
    ):
        translate_rule(
            Family.IP, "mangle", _tcpoptstrip_rule("mss", protocol=None)
        )
    with pytest.raises(FermError, match=r"^unknown tcp option 'banana'"):
        translate_rule(Family.IP, "mangle", _tcpoptstrip_rule("banana"))
    with pytest.raises(FermError, match=r"^invalid tcp option '256'"):
        translate_rule(Family.IP, "mangle", _tcpoptstrip_rule("256"))
    with pytest.raises(FermError, match=r"^TCPOPTSTRIP needs 'strip-options'"):
        translate_rule(Family.IP, "mangle", _tcpoptstrip_rule(None))


# --- 2026-07-10 vocabulary batch 5 (stateful part): mod recent, mod
# --- hashlimit via implicit dynamic sets.  Element spellings and the recent
# --- calibration formula are pinned against a live kernel readback and real
# --- xt_recent (see tests/integration/test_nft_live_vocabulary and the
# --- opt-in tests/e2e/test_recent_calibration).

from pyferm.backend.nft import (  # noqa: E402
    NftSetUpdate,
    _build_recent_specs,
    _DynSetDecl,
    _nft_time_canon,
    _reduce_rate,
)


def _recent(name: str, value: Value = None) -> RenderedOption:
    return _opt(name, value, module="recent")


def _recent_rule(
    *opts: RenderedOption, verdict: str | None = None
) -> RenderedRule:
    options = [_opt("match", "recent", kind=OptionKind.MATCH_MODULE), *opts]
    if verdict is not None:
        options.append(_target(verdict))
    return _rule(*options)


def _hashlimit_rule(
    *opts: RenderedOption, proto: str = "tcp", verdict: str = "ACCEPT"
) -> RenderedRule:
    return _rule(
        _opt("protocol", proto, kind=OptionKind.PROTO),
        _opt("match", "hashlimit", kind=OptionKind.MATCH_MODULE),
        *opts,
        _target(verdict),
    )


def _recent_texts(domain: Family, *rules: RenderedRule) -> list[list[str]]:
    specs = _build_recent_specs(domain, rules)
    return [
        [
            s.to_text()
            for s in translate_rule(
                domain, "filter", rule, chain="c", recent_specs=specs
            ).statements
        ]
        for rule in rules
    ]


def _hashlimit_text(
    domain: Family, *opts: RenderedOption, proto: str = "tcp"
) -> list[str]:
    rule = _hashlimit_rule(*opts, proto=proto)
    return [
        s.to_text()
        for s in translate_rule(domain, "filter", rule, chain="c").statements
    ]


# --- time canon + rate reducer (the calibration primitives) ---


def test_nft_time_canon_full_decomposition() -> None:
    assert _nft_time_canon(60_000) == "1m"
    assert _nft_time_canon(90_000) == "1m30s"
    assert _nft_time_canon(61_000) == "1m1s"
    assert _nft_time_canon(300_000) == "5m"
    assert _nft_time_canon(3_600_000) == "1h"
    assert _nft_time_canon(86_400_000) == "1d"
    assert _nft_time_canon(500) == "500ms"
    assert _nft_time_canon(86_400_000 + 3_600_000 + 1) == "1d1h1ms"


def test_nft_time_canon_rejects_nonpositive() -> None:
    with pytest.raises(FermError, match=r"timeout must be positive"):
        _nft_time_canon(0)


def test_reduce_rate_calibration_pins() -> None:
    # chain-maze: T=2 H=4 S=60 -> 8/minute; stuart: T=2 H=8 S=300 -> 192/hour;
    # single check rule: T=1 H=4 S=60 -> 4/minute.  Smallest integer unit.
    assert _reduce_rate(8, 60) == (8, "minute")
    assert _reduce_rate(16, 300) == (192, "hour")
    assert _reduce_rate(4, 60) == (4, "minute")
    assert _reduce_rate(10, 5) == (2, "second")


def test_reduce_rate_irreducible_refused() -> None:
    with pytest.raises(FermError, match=r"no integer nft rate unit"):
        _reduce_rate(1, 7)


# --- recent translation ---


def test_recent_check_then_set_calibrated_uniform_spec() -> None:
    # chain-maze structure: rcheck first (goto), bare set second (NOP).  Both
    # rules of the name emit the identical calibrated element spec; T=2.
    check = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("hitcount", "4"),
        _recent("name", "SSH"),
        verdict="bad",
    )
    bare = _recent_rule(_recent("set"), _recent("name", "SSH"))
    spec = (
        "update @recent_SSH { ip saddr timeout 1m "
        "limit rate over 8/minute burst 7 packets }"
    )
    assert _recent_texts(Family.IP, check, bare) == [
        [spec, "jump bad"],
        [spec],
    ]


def test_recent_ip6_and_rdest_direction() -> None:
    check = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("hitcount", "4"),
        _recent("name", "V6"),
        _recent("rdest"),
        verdict="bad",
    )
    bare = _recent_rule(
        _recent("set"), _recent("name", "V6"), _recent("rdest")
    )
    spec = (
        "update @recent_V6 { ip6 daddr timeout 1m "
        "limit rate over 8/minute burst 7 packets }"
    )
    assert _recent_texts(Family.IP6, check, bare) == [
        [spec, "jump bad"],
        [spec],
    ]


def test_recent_set_only_with_verdict_timeout_only() -> None:
    # A name with no check rules and a bare `set` carrying a real verdict is
    # legal: the element spec is timeout-only, so the update matches
    # unconditionally and the verdict always fires (as xt --set does).
    bare = _recent_rule(
        _recent("set"),
        _recent("seconds", "60"),
        _recent("name", "GUARD"),
        verdict="DROP",
    )
    assert _recent_texts(Family.IP, bare) == [
        ["update @recent_GUARD { ip saddr timeout 1m }", "drop"]
    ]


def test_recent_stuart_set_first_calibration() -> None:
    # stuart-ha-server: bare set first, update H=8 S=300 second;
    # T=2 -> 192/hour.
    bare = _recent_rule(_recent("set"), _recent("name", "SSH"))
    upd = _recent_rule(
        _recent("update"),
        _recent("seconds", "300"),
        _recent("hitcount", "8"),
        _recent("name", "SSH"),
        verdict="bad",
    )
    spec = (
        "update @recent_SSH { ip saddr timeout 5m "
        "limit rate over 192/hour burst 15 packets }"
    )
    assert _recent_texts(Family.IP, bare, upd) == [[spec], [spec, "jump bad"]]


def test_recent_refuses_unsupported_verbs() -> None:
    for verb in ("remove", "rttl", "reap", "mask"):
        value = "255.255.255.0" if verb == "mask" else None
        rule = _recent_rule(
            _recent("set"),
            _recent(verb, value),
            _recent("name", "X"),
        )
        with pytest.raises(
            FermError,
            match=rf"^mod recent '{verb}' is not supported by the nft "
            r"backend$",
        ):
            _build_recent_specs(Family.IP, [rule])


def test_recent_refuses_negation() -> None:
    rule = _recent_rule(
        _recent("set"),
        _opt("seconds", Negated("60"), module="recent"),
        _recent("name", "X"),
    )
    with pytest.raises(
        FermError,
        match=r"^mod recent 'seconds' cannot be negated for the nft backend$",
    ):
        _build_recent_specs(Family.IP, [rule])


def test_recent_refuses_non_ip_family() -> None:
    rule = _recent_rule(_recent("set"), _recent("name", "X"))
    with pytest.raises(
        FermError,
        match=r"^mod recent needs the ip or ip6 family for nft$",
    ):
        _build_recent_specs(Family.ARP, [rule])


def test_recent_refuses_no_verb_or_multiple() -> None:
    with pytest.raises(
        FermError,
        match=r"^mod recent needs exactly one of set/rcheck/update for the "
        r"nft backend$",
    ):
        _build_recent_specs(Family.IP, [_recent_rule(_recent("name", "X"))])
    both = _recent_rule(
        _recent("set"), _recent("rcheck"), _recent("name", "X")
    )
    with pytest.raises(
        FermError,
        match=r"^mod recent needs exactly one of set/rcheck/update for the "
        r"nft backend$",
    ):
        _build_recent_specs(Family.IP, [both])


def test_recent_refuses_missing_or_invalid_name() -> None:
    with pytest.raises(
        FermError, match=r"^mod recent needs a 'name' for the nft backend$"
    ):
        _build_recent_specs(Family.IP, [_recent_rule(_recent("set"))])
    bad = _recent_rule(_recent("set"), _recent("name", "bad-name"))
    with pytest.raises(
        FermError,
        match=r"^invalid recent name 'bad-name' for the nft backend$",
    ):
        _build_recent_specs(Family.IP, [bad])


def test_recent_refuses_hitcount_without_seconds() -> None:
    rule = _recent_rule(
        _recent("rcheck"),
        _recent("hitcount", "4"),
        _recent("name", "X"),
    )
    with pytest.raises(
        FermError,
        match=r"^mod recent 'hitcount' needs 'seconds' for the nft backend$",
    ):
        _build_recent_specs(Family.IP, [rule])


def test_recent_refuses_check_without_pair() -> None:
    rule = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("name", "X"),
    )
    with pytest.raises(
        FermError,
        match=r"^mod recent rcheck/update needs 'seconds' and 'hitcount' for "
        r"the nft backend$",
    ):
        _build_recent_specs(Family.IP, [rule])


def test_recent_refuses_no_seconds_anywhere() -> None:
    rule = _recent_rule(_recent("set"), _recent("name", "X"), verdict="DROP")
    with pytest.raises(
        FermError,
        match=r"^mod recent 'X' has no seconds anywhere; the window is "
        r"undefined for the nft backend$",
    ):
        _build_recent_specs(Family.IP, [rule])


def test_recent_refuses_conflicting_seconds() -> None:
    a = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("hitcount", "4"),
        _recent("name", "X"),
        verdict="bad",
    )
    b = _recent_rule(
        _recent("update"),
        _recent("seconds", "120"),
        _recent("hitcount", "4"),
        _recent("name", "X"),
        verdict="bad",
    )
    with pytest.raises(
        FermError,
        match=r"^mod recent 'X' has conflicting seconds for the nft backend$",
    ):
        _build_recent_specs(Family.IP, [a, b])


def test_recent_refuses_conflicting_directions() -> None:
    a = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("hitcount", "4"),
        _recent("name", "X"),
        verdict="bad",
    )
    b = _recent_rule(_recent("set"), _recent("name", "X"), _recent("rdest"))
    with pytest.raises(
        FermError,
        match=r"^mod recent 'X' mixes rsource and rdest for the nft backend$",
    ):
        _build_recent_specs(Family.IP, [a, b])


def test_recent_refuses_conflicting_hitcounts() -> None:
    a = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("hitcount", "4"),
        _recent("name", "X"),
        verdict="bad",
    )
    b = _recent_rule(
        _recent("update"),
        _recent("seconds", "60"),
        _recent("hitcount", "8"),
        _recent("name", "X"),
        verdict="bad",
    )
    with pytest.raises(
        FermError,
        match=r"^mod recent 'X' has conflicting hitcounts for the nft "
        r"backend$",
    ):
        _build_recent_specs(Family.IP, [a, b])


def test_recent_refuses_rsource_rdest_together() -> None:
    rule = _recent_rule(
        _recent("set"),
        _recent("name", "X"),
        _recent("rsource"),
        _recent("rdest"),
    )
    with pytest.raises(
        FermError,
        match=r"^mod recent cannot combine rsource and rdest for the nft "
        r"backend$",
    ):
        _build_recent_specs(Family.IP, [rule])


def test_recent_refuses_set_verdict_with_check_rules() -> None:
    check = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("hitcount", "4"),
        _recent("name", "SSH"),
        verdict="bad",
    )
    guarded_set = _recent_rule(
        _recent("set"),
        _recent("name", "SSH"),
        verdict="DROP",
    )
    with pytest.raises(
        FermError,
        match=r"^mod recent 'SSH' set rule carries a verdict but the name has "
        r"check rules for the nft backend$",
    ):
        _build_recent_specs(Family.IP, [check, guarded_set])


def test_recent_refuses_irreducible_rate() -> None:
    # hitcount 2 keeps T*H == 2 > 1, so the rate reducer still runs (a lone
    # hitcount 1 now yields a limitless spec and never reaches the reducer).
    rule = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "7"),
        _recent("hitcount", "2"),
        _recent("name", "X"),
        verdict="bad",
    )
    with pytest.raises(
        FermError,
        match=r"^average rate 2/7s has no integer nft rate unit for the nft "
        r"backend$",
    ):
        _build_recent_specs(Family.IP, [rule])


def test_recent_refuses_non_numeric_seconds() -> None:
    rule = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "abc"),
        _recent("hitcount", "4"),
        _recent("name", "X"),
        verdict="bad",
    )
    with pytest.raises(
        FermError,
        match=r"^invalid recent seconds 'abc' for the nft backend$",
    ):
        _build_recent_specs(Family.IP, [rule])


# --- hashlimit translation ---


def test_hashlimit_upto_conform_form() -> None:
    assert _hashlimit_text(
        Family.IP,
        _opt("hashlimit-upto", "3/minute", module="hashlimit"),
        _opt("hashlimit-name", "ssh_brute", module="hashlimit"),
        _opt("hashlimit-mode", "srcip", module="hashlimit"),
    ) == [
        "meta l4proto tcp",
        "update @hashlimit_ssh_brute { ip saddr timeout 1m "
        "limit rate 3/minute burst 5 packets }",
        "accept",
    ]


def test_hashlimit_above_over_form_with_burst() -> None:
    assert _hashlimit_text(
        Family.IP,
        _opt("hashlimit-above", "10/second", module="hashlimit"),
        _opt("hashlimit-burst", "20", module="hashlimit"),
        _opt("hashlimit-name", "flood", module="hashlimit"),
        _opt("hashlimit-mode", "srcip", module="hashlimit"),
    ) == [
        "meta l4proto tcp",
        "update @hashlimit_flood { ip saddr "
        "limit rate over 10/second burst 20 packets }",
        "accept",
    ]


def test_hashlimit_persecond_no_timeout() -> None:
    # /second without htable-expire carries no element timeout.
    assert _hashlimit_text(
        Family.IP,
        _opt("hashlimit-upto", "5/second", module="hashlimit"),
        _opt("hashlimit-name", "ps", module="hashlimit"),
        _opt("hashlimit-mode", "srcip", module="hashlimit"),
    ) == [
        "meta l4proto tcp",
        "update @hashlimit_ps { ip saddr "
        "limit rate 5/second burst 5 packets }",
        "accept",
    ]


def test_hashlimit_concat_key_and_masks_and_expire() -> None:
    texts = _hashlimit_text(
        Family.IP,
        _opt("hashlimit-above", "10/second", module="hashlimit"),
        _opt("hashlimit-name", "conc", module="hashlimit"),
        _opt("hashlimit-mode", "srcip,dstport", module="hashlimit"),
        _opt("hashlimit-srcmask", "24", module="hashlimit"),
        _opt("hashlimit-htable-expire", "90000", module="hashlimit"),
    )
    # the port in the key implies l4proto, so no `meta l4proto tcp` prefix
    assert texts == [
        "update @hashlimit_conc { ip saddr & 255.255.255.0 . tcp dport "
        "timeout 1m30s limit rate over 10/second burst 5 packets }",
        "accept",
    ]


def test_hashlimit_ip6_mask() -> None:
    assert _hashlimit_text(
        Family.IP6,
        _opt("hashlimit-upto", "3/minute", module="hashlimit"),
        _opt("hashlimit-name", "v6", module="hashlimit"),
        _opt("hashlimit-mode", "srcip", module="hashlimit"),
        _opt("hashlimit-srcmask", "64", module="hashlimit"),
    ) == [
        "meta l4proto tcp",
        "update @hashlimit_v6 { ip6 saddr & ffff:ffff:ffff:ffff:: "
        "timeout 1m limit rate 3/minute burst 5 packets }",
        "accept",
    ]


def test_hashlimit_legacy_synonym() -> None:
    # bare `hashlimit` is xt's legacy synonym for hashlimit-upto
    assert _hashlimit_text(
        Family.IP,
        _opt("hashlimit", "3/minute", module="hashlimit"),
        _opt("hashlimit-name", "leg", module="hashlimit"),
        _opt("hashlimit-mode", "srcip", module="hashlimit"),
    ) == [
        "meta l4proto tcp",
        "update @hashlimit_leg { ip saddr timeout 1m "
        "limit rate 3/minute burst 5 packets }",
        "accept",
    ]


def _hl(*opts: RenderedOption, proto: str = "tcp") -> RenderedRule:
    return _hashlimit_rule(*opts, proto=proto)


def test_hashlimit_refuses_missing_mode() -> None:
    with pytest.raises(
        FermError,
        match=r"^mod hashlimit needs 'hashlimit-mode' for the nft backend$",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _hl(
                _opt("hashlimit-upto", "3/minute", module="hashlimit"),
                _opt("hashlimit-name", "x", module="hashlimit"),
            ),
            chain="c",
        )


def test_hashlimit_refuses_missing_name() -> None:
    with pytest.raises(
        FermError,
        match=r"^mod hashlimit needs 'hashlimit-name' for the nft backend$",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _hl(
                _opt("hashlimit-upto", "3/minute", module="hashlimit"),
                _opt("hashlimit-mode", "srcip", module="hashlimit"),
            ),
            chain="c",
        )


def test_hashlimit_refuses_invalid_name() -> None:
    with pytest.raises(
        FermError,
        match=r"^invalid hashlimit name 'bad-x' for the nft backend$",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _hl(
                _opt("hashlimit-upto", "3/minute", module="hashlimit"),
                _opt("hashlimit-name", "bad-x", module="hashlimit"),
                _opt("hashlimit-mode", "srcip", module="hashlimit"),
            ),
            chain="c",
        )


def test_hashlimit_refuses_negation() -> None:
    with pytest.raises(
        FermError,
        match=r"^mod hashlimit 'hashlimit-upto' cannot be negated for the nft "
        r"backend$",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _hl(
                _opt(
                    "hashlimit-upto", Negated("3/minute"), module="hashlimit"
                ),
                _opt("hashlimit-name", "x", module="hashlimit"),
                _opt("hashlimit-mode", "srcip", module="hashlimit"),
            ),
            chain="c",
        )


def test_hashlimit_refuses_port_mode_without_transport() -> None:
    with pytest.raises(
        FermError,
        match=r"^hashlimit mode 'srcport' needs a tcp/udp protocol for the "
        r"nft backend$",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _hashlimit_rule(
                _opt("hashlimit-upto", "3/minute", module="hashlimit"),
                _opt("hashlimit-name", "x", module="hashlimit"),
                _opt("hashlimit-mode", "srcport", module="hashlimit"),
                proto="icmp",
            ),
            chain="c",
        )


def test_hashlimit_refuses_byte_and_bad_rates() -> None:
    # a byte rate leaves N non-numeric (rate message); a rate with no or an
    # unknown unit is a unit message -- each pinned to its full string.
    cases = {
        "1kb/second": (
            r"^unsupported hashlimit rate '1kb/second' for the nft backend$"
        ),
        "3": r"^unsupported hashlimit rate unit in '3' for the nft backend$",
        "5/fortnight": (
            r"^unsupported hashlimit rate unit in '5/fortnight' for the nft "
            r"backend$"
        ),
    }
    for bad, message in cases.items():
        with pytest.raises(FermError, match=message):
            translate_rule(
                Family.IP,
                "filter",
                _hl(
                    _opt("hashlimit-upto", bad, module="hashlimit"),
                    _opt("hashlimit-name", "x", module="hashlimit"),
                    _opt("hashlimit-mode", "srcip", module="hashlimit"),
                ),
                chain="c",
            )


def test_hashlimit_refuses_unknown_mode() -> None:
    with pytest.raises(
        FermError,
        match=r"^unsupported hashlimit mode 'srcip,banana' for the nft "
        r"backend$",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _hl(
                _opt("hashlimit-upto", "3/minute", module="hashlimit"),
                _opt("hashlimit-name", "x", module="hashlimit"),
                _opt("hashlimit-mode", "srcip,banana", module="hashlimit"),
            ),
            chain="c",
        )


def test_hashlimit_refuses_upto_and_above_together() -> None:
    with pytest.raises(
        FermError,
        match=r"^mod hashlimit cannot combine upto and above for the nft "
        r"backend$",
    ):
        translate_rule(
            Family.IP,
            "filter",
            _hl(
                _opt("hashlimit-upto", "3/minute", module="hashlimit"),
                _opt("hashlimit-above", "5/minute", module="hashlimit"),
                _opt("hashlimit-name", "x", module="hashlimit"),
                _opt("hashlimit-mode", "srcip", module="hashlimit"),
            ),
            chain="c",
        )


def test_hashlimit_refuses_non_ip_family() -> None:
    with pytest.raises(
        FermError,
        match=r"^mod hashlimit needs the ip or ip6 family for nft$",
    ):
        translate_rule(
            Family.ARP,
            "filter",
            _hl(
                _opt("hashlimit-upto", "3/minute", module="hashlimit"),
                _opt("hashlimit-name", "x", module="hashlimit"),
                _opt("hashlimit-mode", "srcip", module="hashlimit"),
            ),
            chain="c",
        )


# --- dynamic set declaration collection + serialization ---


def _dyn_rule(update: NftSetUpdate) -> NftRule:
    return NftRule(statements=[update])


def test_collect_dynamic_set_declarations() -> None:
    upd = NftSetUpdate(
        "recent_SSH",
        "ip saddr",
        "ipv4_addr",
        "1m",
        "rate over 8/minute burst 7 packets",
    )
    decls = _collect_set_declarations(Family.IP, {"c": [_dyn_rule(upd)]})
    assert decls == {
        "recent_SSH": _DynSetDecl(
            "ipv4_addr",
            "ip saddr",
            "1m",
            "rate over 8/minute burst 7 packets",
        )
    }
    decl = decls["recent_SSH"]
    assert isinstance(decl, _DynSetDecl)
    assert decl.with_timeout


def test_serialize_dynamic_set_flags_and_size() -> None:
    table = NftTable(family="ip", name="ferm")
    chains: list[NftBaseChain | NftRegularChain] = [NftRegularChain("c")]
    upd = NftSetUpdate(
        "recent_SSH",
        "ip saddr",
        "ipv4_addr",
        "1m",
        "rate over 8/minute burst 7 packets",
    )
    rules = {"c": [_dyn_rule(upd)]}
    decls = _collect_set_declarations(Family.IP, rules)
    out = serialize_table(table, chains, rules, decls, noflush=False)
    assert (
        "add set ip ferm recent_SSH { type ipv4_addr; size 65535; "
        "flags dynamic,timeout; }\n"
    ) in out


def test_serialize_dynamic_set_without_timeout() -> None:
    table = NftTable(family="ip", name="ferm")
    chains: list[NftBaseChain | NftRegularChain] = [NftRegularChain("c")]
    upd = NftSetUpdate(
        "hashlimit_ps",
        "ip saddr",
        "ipv4_addr",
        None,
        "rate 5/second burst 5 packets",
    )
    rules = {"c": [_dyn_rule(upd)]}
    decls = _collect_set_declarations(Family.IP, rules)
    out = serialize_table(table, chains, rules, decls, noflush=False)
    assert (
        "add set ip ferm hashlimit_ps { type ipv4_addr; size 65535; "
        "flags dynamic; }\n"
    ) in out


def test_dynamic_set_conflicts_with_static_set_name() -> None:
    # A user @set literally named `recent_SSH` collides with the implicit set.
    static = NftMatch(
        "ip saddr @recent_SSH",
        set_key=None,
        setref=SetRef(name="recent_SSH", elements=["10.0.0.1"]),
        set_selector="ip saddr",
    )
    upd = NftSetUpdate(
        "recent_SSH",
        "ip saddr",
        "ipv4_addr",
        "1m",
        "rate over 8/minute burst 7 packets",
    )
    rules = {"c": [_dyn_rule(upd), NftRule(statements=[static])]}
    with pytest.raises(FermError, match=r"collides with a stateful set"):
        _collect_set_declarations(Family.IP, rules)


def test_dynamic_set_conflicting_declarations_refused() -> None:
    a = NftSetUpdate("recent_X", "ip saddr", "ipv4_addr", "1m", None)
    b = NftSetUpdate("recent_X", "ip saddr", "ipv4_addr", None, None)
    rules = {"c": [_dyn_rule(a), _dyn_rule(b)]}
    with pytest.raises(FermError, match=r"conflicting declarations"):
        _collect_set_declarations(Family.IP, rules)


def test_dynamic_set_same_type_different_key_refused() -> None:
    # hashlimit mode srcip vs dstip under one name: the nft TYPE coincides
    # (both ipv4_addr) but the keys mean different buckets -- the conflict
    # identity must cover the key expression, not just the declared type.
    a = NftSetUpdate(
        "hashlimit_S",
        "ip saddr",
        "ipv4_addr",
        "1m",
        "rate 3/minute burst 5 packets",
    )
    b = NftSetUpdate(
        "hashlimit_S",
        "ip daddr",
        "ipv4_addr",
        "1m",
        "rate 3/minute burst 5 packets",
    )
    rules = {"c": [_dyn_rule(a), _dyn_rule(b)]}
    with pytest.raises(FermError, match=r"conflicting declarations"):
        _collect_set_declarations(Family.IP, rules)


def test_dynamic_set_same_key_different_limit_refused() -> None:
    # One name, two rates: the element's stateful expression is fixed at
    # creation, so whichever rule fires first would silently win -- refuse.
    a = NftSetUpdate(
        "hashlimit_S",
        "ip saddr",
        "ipv4_addr",
        "1m",
        "rate 3/minute burst 5 packets",
    )
    b = NftSetUpdate(
        "hashlimit_S",
        "ip saddr",
        "ipv4_addr",
        "1m",
        "rate 9/minute burst 5 packets",
    )
    rules = {"c": [_dyn_rule(a), _dyn_rule(b)]}
    with pytest.raises(FermError, match=r"conflicting declarations"):
        _collect_set_declarations(Family.IP, rules)


# --- 2026-07-10 vocabulary batch 7: connbytes, connlimit, quota, iprange,
# --- MARK/CONNMARK mark arithmetic.  Value spellings (>=/</&, quota units,
# --- the mark and/or canon) are pinned against a live kernel readback in
# --- tests/integration/test_nft_live_vocabulary.

from pyferm.backend.nft import (  # noqa: E402
    NftQuota,
    _connlimit_update,
    _finalize_connlimit_names,
    _quota_canon,
)


def _connbytes(value: Value, direction: Value, mode: Value) -> RenderedRule:
    return _rule(
        _opt("connbytes", value, module="connbytes"),
        _opt("connbytes-dir", direction, module="connbytes"),
        _opt("connbytes-mode", mode, module="connbytes"),
        _target("ACCEPT"),
    )


def test_connbytes_range_forms() -> None:
    # exact full text (not startswith): a mutant returning `ge`/`lt` or the
    # wrong bound must fail
    cases = {
        ("1048576:", "both", "bytes"): "ct bytes >= 1048576",
        ("100:200", "original", "packets"): "ct original packets 100-200",
        (":5000", "both", "bytes"): "ct bytes 0-5000",
        ("4096", "both", "bytes"): "ct bytes >= 4096",
        ("1024:", "reply", "bytes"): "ct reply bytes >= 1024",
    }
    for (value, direction, mode), expected in cases.items():
        nft = translate_rule(
            Family.IP, "filter", _connbytes(value, direction, mode)
        )
        assert nft.statements[0].to_text() == expected


def test_connbytes_negated_forms() -> None:
    # negated N: -> <, negated interval -> !=
    nft = translate_rule(
        Family.IP, "filter", _connbytes(PreNegated("500:"), "reply", "avgpkt")
    )
    assert nft.statements[0].to_text() == "ct reply avgpkt < 500"
    nft = translate_rule(
        Family.IP,
        "filter",
        _connbytes(PreNegated("100:200"), "both", "packets"),
    )
    assert nft.statements[0].to_text() == "ct packets != 100-200"
    # negated :M -> != 0-M (calibration pin)
    nft = translate_rule(
        Family.IP, "filter", _connbytes(PreNegated(":5000"), "both", "bytes")
    )
    assert nft.statements[0].to_text() == "ct bytes != 0-5000"


def test_connbytes_refusals() -> None:
    # dir and mode are both mandatory
    with pytest.raises(FermError, match=r"needs both 'connbytes-dir'"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("connbytes", "100:", module="connbytes"),
                _opt("connbytes-dir", "both", module="connbytes"),
                _target("ACCEPT"),
            ),
        )
    with pytest.raises(FermError, match=r"invalid connbytes-dir 'sideways'"):
        translate_rule(
            Family.IP, "filter", _connbytes("100:", "sideways", "bytes")
        )
    with pytest.raises(FermError, match=r"invalid connbytes-mode 'octets'"):
        translate_rule(
            Family.IP, "filter", _connbytes("100:", "both", "octets")
        )
    with pytest.raises(FermError, match=r"cannot be negated"):
        translate_rule(
            Family.IP,
            "filter",
            _connbytes("100:", PreNegated("both"), "bytes"),
        )
    with pytest.raises(FermError, match=r"has lo > hi"):
        translate_rule(
            Family.IP, "filter", _connbytes("200:100", "both", "bytes")
        )
    # u64 ceiling (wider than quota's u63)
    with pytest.raises(FermError, match=r"exceeds 2\^64-1"):
        translate_rule(
            Family.IP,
            "filter",
            _connbytes(f"{2**64}:", "both", "bytes"),
        )


def test_quota_unit_canon() -> None:
    # tabular, literally these borders: the largest evenly-dividing unit, no
    # gbytes (2^30 stays mbytes), an indivisible count in bytes
    assert _quota_canon(1024) == "1 kbytes"
    assert _quota_canon(1023) == "1023 bytes"
    assert _quota_canon(1048576) == "1 mbytes"
    assert _quota_canon(1048575) == "1048575 bytes"
    assert _quota_canon(2**30) == "1024 mbytes"
    assert _quota_canon(2**31) == "2048 mbytes"
    assert _quota_canon(1500000) == "1500000 bytes"
    assert _quota_canon(2048) == "2 kbytes"


def _quota_rule(value: str) -> RenderedRule:
    return _rule(_opt("quota", value, module="quota"), _target("ACCEPT"))


def test_quota_statement_and_validation() -> None:
    nft = translate_rule(Family.IP, "filter", _quota_rule("1048576"))
    assert isinstance(nft.statements[0], NftQuota)
    assert nft.statements[0].to_text() == "quota 1 mbytes"
    with pytest.raises(FermError, match=r"invalid quota 'lots'"):
        translate_rule(Family.IP, "filter", _quota_rule("lots"))
    # nft's ceiling is 2^63-1 (narrower than connbytes' u64)
    with pytest.raises(FermError, match=r"exceeds nft's 2\^63-1"):
        translate_rule(Family.IP, "filter", _quota_rule(str(2**63)))


def test_two_quotas_do_not_collapse() -> None:
    # a quota is stateful accounting; folding two rules onto one quota would
    # merge their byte counters (the tproxy-mark regression-pin shape)
    def quota_rule(unit: str) -> NftRule:
        return NftRule(
            statements=[
                NftMatch("tcp dport 22", set_key="tcp dport", element="22"),
                NftQuota(f"quota {unit}"),
                NftVerdict("accept"),
            ]
        )

    out = _collapse_chain_rules(
        [quota_rule("1 mbytes"), quota_rule("2 mbytes")]
    )
    assert len(out) == 2


def _iprange(name: str, value: Value) -> RenderedRule:
    return _rule(_opt(name, value, module="iprange"), _target("ACCEPT"))


def test_iprange_address_ranges() -> None:
    nft = translate_rule(
        Family.IP, "filter", _iprange("src-range", "10.0.0.1-10.0.0.5")
    )
    assert nft.statements[0].to_text() == "ip saddr 10.0.0.1-10.0.0.5"
    nft = translate_rule(
        Family.IP,
        "filter",
        _iprange("dst-range", PreNegated("192.168.0.1-192.168.0.10")),
    )
    assert (
        nft.statements[0].to_text() == "ip daddr != 192.168.0.1-192.168.0.10"
    )
    nft = translate_rule(
        Family.IP6,
        "filter",
        _iprange("src-range", "2001:db8::1-2001:db8::ff"),
    )
    assert nft.statements[0].to_text() == "ip6 saddr 2001:db8::1-2001:db8::ff"


def test_iprange_refusals() -> None:
    # an ip6 bound in an ip rule (wrong family) refuses before nft -c would
    with pytest.raises(FermError, match=r"does not match the ip family"):
        translate_rule(
            Family.IP, "filter", _iprange("src-range", "10.0.0.1-fe80::1")
        )
    # a malformed range (no dash) refuses
    with pytest.raises(FermError, match=r"invalid iprange '10.0.0.1'"):
        translate_rule(Family.IP, "filter", _iprange("src-range", "10.0.0.1"))
    # arp has no saddr/daddr range; falls through to the generic refusal
    with pytest.raises(FermError, match=r"not yet supported"):
        translate_rule(
            Family.ARP, "filter", _iprange("src-range", "10.0.0.1-10.0.0.5")
        )


def _mark_comp(name: str, value: Value, target: str) -> RenderedOption:
    return _opt(name, value, module=target)


def test_mark_arith_canon_both_registers() -> None:
    # the and/or canon, the bitwise ops, and set-mark's effective mask, on
    # meta mark (MARK) and ct mark (CONNMARK)
    for target, register in (("MARK", "meta mark"), ("CONNMARK", "ct mark")):
        cases = {
            ("set-xmark", "0x2/0xff"): (
                f"{register} set {register} & 0xffffff02 | 0x00000002"
            ),
            ("or-mark", "0x4"): f"{register} set {register} | 0x00000004",
            ("and-mark", "0xf0"): f"{register} set {register} & 0x000000f0",
            ("xor-mark", "0x8"): f"{register} set {register} ^ 0x00000008",
            # set-mark uses the effective mask m' = v|m, so 0xff/0x0f is legal
            (
                "set-mark",
                "0xff/0x0f",
            ): f"{register} set {register} | 0x000000ff",
        }
        for (op, value), expected in cases.items():
            comp = {op: _mark_comp(op, value, target)}
            assert (
                build_verdict(
                    Family.IP, "mangle", "jump", target, comp
                ).to_text()
                == expected
            )


def test_mark_arith_refusals() -> None:
    # set-xmark with value bits outside its mask (set-mark's effective-mask
    # rescue does NOT apply to set-xmark)
    with pytest.raises(FermError, match=r"has bits outside its mask"):
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "MARK",
            {"set-xmark": _mark_comp("set-xmark", "0x3/0x1", "MARK")},
        )
    # a zero mask is a no-op assignment the kernel does not round-trip
    with pytest.raises(FermError, match=r"has a zero mask"):
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "MARK",
            {"set-xmark": _mark_comp("set-xmark", "0x0/0x0", "MARK")},
        )
    # more than one op cannot be ordered; refuse with the target's message
    with pytest.raises(FermError, match=r"^MARK target not yet supported"):
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "MARK",
            {
                "or-mark": _mark_comp("or-mark", "0x4", "MARK"),
                "and-mark": _mark_comp("and-mark", "0xf0", "MARK"),
            },
        )
    # CONNMARK save/restore with a mask mixes two masked registers; refuse
    with pytest.raises(FermError, match=r"mixes two masked registers"):
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "CONNMARK",
            {
                "save-mark": _mark_comp("save-mark", None, "CONNMARK"),
                "nfmask": _mark_comp("nfmask", "0xff", "CONNMARK"),
            },
        )


def _connlimit(*opts: RenderedOption) -> RenderedRule:
    return _rule(*opts, _target("DROP"))


def _cl(name: str, value: Value = None) -> RenderedOption:
    return _opt(name, value, module="connlimit")


def _connlimit_name(rule: NftRule) -> str:
    for stmt in rule.statements:
        if isinstance(stmt, NftSetUpdate):
            return stmt.name
    raise AssertionError("rule carries no connlimit set update")


def test_connlimit_update_forms() -> None:
    # above -> count over N with an & netmask key
    upd = _connlimit_update(
        Family.IP,
        _connlimit(_cl("connlimit-above", "20"), _cl("connlimit-mask", "24")),
    )
    assert upd.verb == "add"
    assert upd.key_expr == "ip saddr & 255.255.255.0 ct count over 20"
    assert upd.set_type == "ipv4_addr"
    # upto -> count N; a full mask (absent) has no &
    upd = _connlimit_update(Family.IP, _connlimit(_cl("connlimit-upto", "5")))
    assert upd.key_expr == "ip saddr ct count 5"
    # daddr side
    upd = _connlimit_update(
        Family.IP,
        _connlimit(
            _cl("connlimit-above", "10"),
            _cl("connlimit-mask", "24"),
            _cl("connlimit-daddr"),
        ),
    )
    assert upd.key_expr == "ip daddr & 255.255.255.0 ct count over 10"
    # ip6 mask -> shorthand netmask
    upd = _connlimit_update(
        Family.IP6,
        _connlimit(_cl("connlimit-above", "5"), _cl("connlimit-mask", "64")),
    )
    assert upd.key_expr == "ip6 saddr & ffff:ffff:ffff:ffff:: ct count over 5"
    assert upd.set_type == "ipv6_addr"
    # negated upto behaves like above (upto = "not above")
    upd = _connlimit_update(
        Family.IP, _connlimit(_cl("connlimit-upto", PreNegated("5")))
    )
    assert upd.key_expr == "ip saddr ct count over 5"


def test_connlimit_refusals() -> None:
    # exactly one of upto/above
    exactly_one = (
        r"^mod connlimit needs exactly one of connlimit-upto/connlimit-above "
        r"for the nft backend$"
    )
    with pytest.raises(FermError, match=exactly_one):
        _connlimit_update(
            Family.IP,
            _connlimit(
                _cl("connlimit-above", "10"), _cl("connlimit-upto", "5")
            ),
        )
    with pytest.raises(FermError, match=exactly_one):
        _connlimit_update(Family.IP, _connlimit(_cl("connlimit-mask", "24")))
    # saddr and daddr together
    with pytest.raises(
        FermError,
        match=r"^mod connlimit cannot combine saddr and daddr for the nft "
        r"backend$",
    ):
        _connlimit_update(
            Family.IP,
            _connlimit(
                _cl("connlimit-above", "10"),
                _cl("connlimit-saddr"),
                _cl("connlimit-daddr"),
            ),
        )
    # a zero mask keys the whole address space as one bucket
    with pytest.raises(
        FermError,
        match=r"^connlimit-mask 0 keys the whole address space as one bucket; "
        r"refused for the nft backend$",
    ):
        _connlimit_update(
            Family.IP,
            _connlimit(
                _cl("connlimit-above", "10"), _cl("connlimit-mask", "0")
            ),
        )
    # mask out of range
    with pytest.raises(
        FermError,
        match=r"^connlimit mask '33' exceeds /32 for the nft backend$",
    ):
        _connlimit_update(
            Family.IP,
            _connlimit(
                _cl("connlimit-above", "10"), _cl("connlimit-mask", "33")
            ),
        )
    # count is not a mark value (u32)
    with pytest.raises(
        FermError,
        match=r"^invalid connlimit count 'lots' for the nft backend$",
    ):
        _connlimit_update(
            Family.IP, _connlimit(_cl("connlimit-above", "lots"))
        )
    # arp has no address key
    with pytest.raises(
        FermError,
        match=r"^mod connlimit needs the ip or ip6 family for nft$",
    ):
        _connlimit_update(Family.ARP, _connlimit(_cl("connlimit-above", "10")))


def _translated_connlimit(*opts: RenderedOption) -> NftRule:
    return translate_rule(Family.IP, "filter", _connlimit(*opts))


def test_connlimit_names_stable_and_distinct() -> None:
    # an inserted UNRELATED rule must not rename a connlimit set (stable
    # content hash, not a positional index)
    unrelated = NftRule(
        statements=[NftMatch("tcp dport 22"), NftVerdict("accept")]
    )
    without = [
        translate_rule(
            Family.IP,
            "filter",
            _connlimit(
                _cl("connlimit-above", "20"), _cl("connlimit-mask", "24")
            ),
        )
    ]
    _finalize_connlimit_names(Family.IP, "filter", "INPUT", without)
    with_extra = [
        unrelated,
        translate_rule(
            Family.IP,
            "filter",
            _connlimit(
                _cl("connlimit-above", "20"), _cl("connlimit-mask", "24")
            ),
        ),
    ]
    _finalize_connlimit_names(Family.IP, "filter", "INPUT", with_extra)
    name_without = _connlimit_name(without[0])
    name_with = _connlimit_name(with_extra[1])
    assert name_without == name_with
    assert name_without.startswith("connlimit_")

    # different matches -> different names
    a = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("source", "10.0.0.1"),
            _cl("connlimit-above", "20"),
            _cl("connlimit-mask", "24"),
            _target("DROP"),
        ),
    )
    b = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("source", "10.0.0.2"),
            _cl("connlimit-above", "20"),
            _cl("connlimit-mask", "24"),
            _target("DROP"),
        ),
    )
    rules = [a, b]
    _finalize_connlimit_names(Family.IP, "filter", "INPUT", rules)
    assert _connlimit_name(a) != _connlimit_name(b)


def test_connlimit_identical_rules_get_distinct_ordinals() -> None:
    # two byte-identical connlimit rules must get DIFFERENT sets (xt gives
    # each rule its own conncount tree), and collapse must NOT fold them
    def make() -> NftRule:
        return translate_rule(
            Family.IP,
            "filter",
            _connlimit(
                _cl("connlimit-above", "20"), _cl("connlimit-mask", "24")
            ),
        )

    rules = [make(), make()]
    _finalize_connlimit_names(Family.IP, "filter", "FORWARD", rules)
    assert _connlimit_name(rules[0]) != _connlimit_name(rules[1])
    # finalization precedes collapse; distinct names keep collapse from
    # merging the two per-rule counters into one
    out = _collapse_chain_rules(rules)
    assert len(out) == 2


def test_connlimit_sentinel_surviving_is_internal_error() -> None:
    # a connlimit set that reaches declaration collection unfinalized is a
    # wiring bug (the post-pass was skipped), not a config error
    sentinel_rule = _translated_connlimit(
        _cl("connlimit-above", "20"), _cl("connlimit-mask", "24")
    )
    with pytest.raises(FermError, match=r"internal error.*unfinalized name"):
        _collect_set_declarations(Family.IP, {"c": [sentinel_rule]})


def test_connlimit_sets_aggregate_by_name() -> None:
    # two connlimit rules with distinct names yield two declarations
    a = _translated_connlimit(
        _cl("connlimit-above", "20"), _cl("connlimit-mask", "24")
    )
    b = _translated_connlimit(_cl("connlimit-upto", "5"))
    rules = [a, b]
    _finalize_connlimit_names(Family.IP, "filter", "INPUT", rules)
    decls = _collect_set_declarations(Family.IP, {"c": rules})
    connlimit_decls = {
        name: d for name, d in decls.items() if name.startswith("connlimit_")
    }
    assert len(connlimit_decls) == 2
    assert all(isinstance(d, _DynSetDecl) for d in connlimit_decls.values())


# --- 2026-07-10 nft fix regression + mutation-kill batch.  Covers the two
# --- product fixes (lone recent hitcount 1 emits a limitless spec; hashlimit
# --- htable-max refuses while htable-size/gcinterval are ignored), the
# --- option-loop `continue` sites, and boundary pins for the batch-5/7
# --- primitives (_hashlimit_key, _clock_parts, _setmark_effective).

from pyferm.backend.nft import (  # noqa: E402
    _TIME_OF_DAY_RE,
    _clock_parts,
    _hashlimit_key,
    _recent_update,
    _setmark_effective,
)


def _has_stmt(rule: NftRule, text: str) -> bool:
    return any(s.to_text() == text for s in rule.statements)


# --- fix (a): lone recent hitcount 1 -> no limit clause ---


def test_recent_lone_hitcount_one_has_no_limit_clause() -> None:
    # T*H == 1 degenerates to "match from the first in-window packet"; the
    # limitless update expresses that, while the formula's `burst 0` is
    # rejected by nft outright.  Holds for either check verb.
    for verb in ("rcheck", "update"):
        rule = _recent_rule(
            _recent(verb),
            _recent("seconds", "60"),
            _recent("hitcount", "1"),
            _recent("name", "X"),
            verdict="bad",
        )
        texts = _recent_texts(Family.IP, rule)[0]
        assert texts[0] == "update @recent_X { ip saddr timeout 1m }"
        assert all("limit" not in t and "burst" not in t for t in texts)


def test_recent_two_rules_hitcount_one_still_calibrates() -> None:
    # T=2, H=1: numerator 2 > 1, so the limit clause returns (burst 1) -- the
    # fix only suppresses the clause when T*H == 1, not whenever H == 1.
    check = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("hitcount", "1"),
        _recent("name", "P"),
        verdict="bad",
    )
    bare = _recent_rule(_recent("set"), _recent("name", "P"))
    spec = (
        "update @recent_P { ip saddr timeout 1m "
        "limit rate over 2/minute burst 1 packets }"
    )
    assert _recent_texts(Family.IP, check, bare) == [
        [spec, "jump bad"],
        [spec],
    ]


def test_recent_single_rcheck_hitcount_three_burst_two() -> None:
    # T=1, H=3: numerator 3 -> 3/minute burst 2 (the general formula stays
    # intact for a single check rule with hitcount > 1).
    rule = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("hitcount", "3"),
        _recent("name", "Q"),
        verdict="bad",
    )
    spec = (
        "update @recent_Q { ip saddr timeout 1m "
        "limit rate over 3/minute burst 2 packets }"
    )
    assert _recent_texts(Family.IP, rule) == [[spec, "jump bad"]]


def test_recent_update_without_prepass_spec_is_internal_error() -> None:
    # a recent rule reaching translate_rule with a spec dict that lacks its
    # name is a wiring bug (the whole-family pre-pass was skipped).
    rule = _recent_rule(
        _recent("set"), _recent("seconds", "60"), _recent("name", "X")
    )
    with pytest.raises(FermError, match=r"without its pre-pass spec"):
        _recent_update(Family.IP, rule, {})


# --- fix (b): hashlimit htable-* knobs ---


def test_hashlimit_htable_max_refused() -> None:
    with pytest.raises(
        FermError,
        match=r"^mod hashlimit 'hashlimit-htable-max' has no nft equivalent "
        r"for the nft backend$",
    ):
        _hashlimit_text(
            Family.IP,
            _opt("hashlimit-upto", "3/minute", module="hashlimit"),
            _opt("hashlimit-name", "x", module="hashlimit"),
            _opt("hashlimit-mode", "srcip", module="hashlimit"),
            _opt("hashlimit-htable-max", "100", module="hashlimit"),
        )


def test_hashlimit_htable_size_and_gcinterval_ignored() -> None:
    # htable-size/gcinterval are pure performance knobs with no match
    # semantics; nft sizes and expires dynamic sets itself, so a rule
    # carrying them must translate byte-identically to one without them.
    base = (
        _opt("hashlimit-upto", "3/minute", module="hashlimit"),
        _opt("hashlimit-name", "ig", module="hashlimit"),
        _opt("hashlimit-mode", "srcip", module="hashlimit"),
    )
    plain = _hashlimit_text(Family.IP, *base)
    tuned = _hashlimit_text(
        Family.IP,
        *base,
        _opt("hashlimit-htable-size", "4096", module="hashlimit"),
        _opt("hashlimit-htable-gcinterval", "1000", module="hashlimit"),
    )
    assert tuned == plain
    assert any("update @hashlimit_ig" in t for t in tuned)


def test_hashlimit_htable_expire_boundaries() -> None:
    def hl(expire: str) -> list[str]:
        return _hashlimit_text(
            Family.IP,
            _opt("hashlimit-upto", "3/minute", module="hashlimit"),
            _opt("hashlimit-name", "e", module="hashlimit"),
            _opt("hashlimit-mode", "srcip", module="hashlimit"),
            _opt("hashlimit-htable-expire", expire, module="hashlimit"),
        )

    with pytest.raises(
        FermError,
        match=r"^stateful timeout must be positive for the nft backend$",
    ):
        hl("0")
    with pytest.raises(
        FermError,
        match=r"^invalid hashlimit htable-expire 'abc' for the nft backend$",
    ):
        hl("abc")


# --- option-loop `continue` sites (translate_rule): a later independent
# --- match must still emit after each dynamic/stateful module branch ---


def test_option_loop_continues_after_connbytes() -> None:
    rule = _rule(
        _opt("protocol", "tcp", kind=OptionKind.PROTO),
        _opt("connbytes", "100:", module="connbytes"),
        _opt("connbytes-dir", "both", module="connbytes"),
        _opt("connbytes-mode", "bytes", module="connbytes"),
        _opt("dport", "80"),
        _target("ACCEPT"),
    )
    nft = translate_rule(Family.IP, "filter", rule)
    assert _has_stmt(nft, "ct bytes >= 100")
    assert _has_stmt(nft, "tcp dport 80")


def test_option_loop_continues_after_connlimit() -> None:
    rule = _rule(
        _opt("protocol", "tcp", kind=OptionKind.PROTO),
        _cl("connlimit-above", "20"),
        _cl("connlimit-mask", "24"),
        _opt("dport", "80"),
        _target("DROP"),
    )
    nft = translate_rule(Family.IP, "filter", rule)
    assert _has_stmt(nft, "tcp dport 80")
    assert any(isinstance(s, NftSetUpdate) for s in nft.statements)


def test_option_loop_continues_after_quota() -> None:
    rule = _rule(
        _opt("protocol", "tcp", kind=OptionKind.PROTO),
        _opt("quota", "1048576", module="quota"),
        _opt("dport", "80"),
        _target("ACCEPT"),
    )
    nft = translate_rule(Family.IP, "filter", rule)
    assert _has_stmt(nft, "quota 1 mbytes")
    assert _has_stmt(nft, "tcp dport 80")


def test_option_loop_continues_after_match_set() -> None:
    rule = _rule(
        _opt("protocol", "tcp", kind=OptionKind.PROTO),
        _match_set_opt(SetRef("badguys", ["10.0.0.1"]), "src"),
        _opt("dport", "80"),
        _target("DROP"),
    )
    nft = translate_rule(Family.IP, "filter", rule)
    assert _has_stmt(nft, "ip saddr @badguys")
    assert _has_stmt(nft, "tcp dport 80")


def test_connbytes_emits_single_statement() -> None:
    # three connbytes options fold into ONE `ct ... bytes` statement (emitted
    # at the first option, then the loop skips the rest).
    rule = _rule(
        _opt("connbytes", "100:", module="connbytes"),
        _opt("connbytes-mode", "bytes", module="connbytes"),
        _opt("connbytes-dir", "both", module="connbytes"),
        _target("ACCEPT"),
    )
    nft = translate_rule(Family.IP, "filter", rule)
    ct_stmts = [s for s in nft.statements if s.to_text() == "ct bytes >= 100"]
    assert len(ct_stmts) == 1


def test_collect_set_declarations_gathers_dynamic_and_static() -> None:
    # a dynamic (hashlimit) set rule followed by a static @set-backed
    # match-set rule in one chain -> declarations for BOTH sets (the inner
    # loop must not break after the dynamic arm).
    dyn = translate_rule(
        Family.IP,
        "filter",
        _hashlimit_rule(
            _opt("hashlimit-upto", "3/minute", module="hashlimit"),
            _opt("hashlimit-name", "hl", module="hashlimit"),
            _opt("hashlimit-mode", "srcip", module="hashlimit"),
        ),
    )
    static = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _match_set_opt(SetRef("badguys", ["10.0.0.1"]), "src"),
            _target("DROP"),
        ),
    )
    decls = _collect_set_declarations(Family.IP, {"c": [dyn, static]})
    assert "hashlimit_hl" in decls
    assert "badguys" in decls


# --- _hashlimit_key: exact (key_expr, set_type) per mode ---


@pytest.mark.parametrize(
    ("domain", "mode", "opts", "protocol", "expected"),
    [
        (Family.IP, "srcip", {}, "tcp", ("ip saddr", "ipv4_addr")),
        (Family.IP, "dstip", {}, "tcp", ("ip daddr", "ipv4_addr")),
        (Family.IP, "srcport", {}, "tcp", ("tcp sport", "inet_service")),
        (Family.IP, "dstport", {}, "tcp", ("tcp dport", "inet_service")),
        (
            Family.IP,
            "srcip,dstport",
            {},
            "tcp",
            ("ip saddr . tcp dport", "ipv4_addr . inet_service"),
        ),
        (
            Family.IP,
            "srcip,srcport,dstport",
            {},
            "tcp",
            (
                "ip saddr . tcp sport . tcp dport",
                "ipv4_addr . inet_service . inet_service",
            ),
        ),
        (Family.IP6, "srcip", {}, "tcp", ("ip6 saddr", "ipv6_addr")),
        (Family.IP6, "dstport", {}, "tcp", ("tcp dport", "inet_service")),
        (
            Family.IP6,
            "srcip,dstport",
            {},
            "tcp",
            ("ip6 saddr . tcp dport", "ipv6_addr . inet_service"),
        ),
        (
            Family.IP,
            "srcip",
            {
                "hashlimit-srcmask": _opt(
                    "hashlimit-srcmask", "24", module="hashlimit"
                )
            },
            "tcp",
            ("ip saddr & 255.255.255.0", "ipv4_addr"),
        ),
        (
            Family.IP,
            "dstip",
            {
                "hashlimit-dstmask": _opt(
                    "hashlimit-dstmask", "16", module="hashlimit"
                )
            },
            "tcp",
            ("ip daddr & 255.255.0.0", "ipv4_addr"),
        ),
    ],
)
def test_hashlimit_key_modes(
    domain: Family,
    mode: str,
    opts: dict[str, RenderedOption],
    protocol: str,
    expected: tuple[str, str],
) -> None:
    assert _hashlimit_key(domain, mode, opts, protocol) == expected


# --- _clock_parts boundaries ---


@pytest.mark.parametrize(
    ("scalar", "expected"),
    [("00:00:00", (0, 0, 0)), ("23:59:59", (23, 59, 59))],
)
def test_clock_parts_valid_boundaries(
    scalar: str, expected: tuple[int, int, int]
) -> None:
    match = _TIME_OF_DAY_RE.match(scalar)
    assert match is not None
    assert _clock_parts(match, scalar, "time") == expected


@pytest.mark.parametrize("scalar", ["24:00:00", "00:60:00", "00:00:60"])
def test_clock_parts_out_of_range_refused(scalar: str) -> None:
    match = _TIME_OF_DAY_RE.match(scalar)
    assert match is not None
    with pytest.raises(
        FermError, match=rf"^invalid time '{scalar}' for nft backend$"
    ):
        _clock_parts(match, scalar, "time")


# --- _setmark_effective boundaries ---


def test_setmark_effective_boundaries() -> None:
    assert _setmark_effective("0x0/0x0") == "0x0/0x0"
    assert (
        _setmark_effective("0xffffffff/0xffffffff") == "0xffffffff/0xffffffff"
    )
    with pytest.raises(
        FermError,
        match=r"^invalid set-mark '0x100000000/0x0' for nft backend$",
    ):
        _setmark_effective("0x100000000/0x0")


# --- connlimit mask boundaries (full mask needs no `& netmask`) ---


def test_connlimit_full_mask_has_no_ampersand() -> None:
    upd = _connlimit_update(
        Family.IP,
        _connlimit(_cl("connlimit-above", "10"), _cl("connlimit-mask", "32")),
    )
    assert upd.key_expr == "ip saddr ct count over 10"
    upd6 = _connlimit_update(
        Family.IP6,
        _connlimit(_cl("connlimit-above", "10"), _cl("connlimit-mask", "128")),
    )
    assert upd6.key_expr == "ip6 saddr ct count over 10"


def test_connlimit_oversized_mask_refused() -> None:
    with pytest.raises(
        FermError,
        match=r"^connlimit mask '33' exceeds /32 for the nft backend$",
    ):
        _connlimit_update(
            Family.IP,
            _connlimit(
                _cl("connlimit-above", "10"), _cl("connlimit-mask", "33")
            ),
        )
    with pytest.raises(
        FermError,
        match=r"^connlimit mask '129' exceeds /128 for the nft backend$",
    ):
        _connlimit_update(
            Family.IP6,
            _connlimit(
                _cl("connlimit-above", "10"), _cl("connlimit-mask", "129")
            ),
        )


# --- build_verdict: HL refusal, SNAT port threading ---


def test_build_verdict_hl_target_needs_hl_set() -> None:
    with pytest.raises(FermError, match=r"^HL target not yet supported"):
        build_verdict(Family.IP6, "mangle", "jump", "HL", {})


def test_build_verdict_snat_threads_port() -> None:
    # mirror of the DNAT port case: the `:port` form must survive onto the
    # emitted snat verdict when the rule established a transport.
    snat = {
        "to-source": _opt(
            "to-source", Multi(values=["1.2.3.4:1024"]), module="SNAT"
        )
    }
    assert (
        build_verdict(
            Family.IP, "nat", "jump", "SNAT", snat, has_transport=True
        ).to_text()
        == "snat to 1.2.3.4:1024"
    )


# --- tcp-flags implies l4proto (like icmp-type/syn) ---


def test_translate_rule_tcp_flags_option_suppresses_l4proto() -> None:
    # a real tcp-flags match (not just --syn) implies l4proto tcp, so the
    # `meta l4proto tcp` prefix is suppressed exactly as for icmp-type.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("tcp-flags", Params(values=["SYN,RST", "SYN"]), module="tcp"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "tcp flags & (syn | rst) == syn",
        "accept",
    ]


# --- u64/u63 ceilings (the success side; the refusals live above) ---


def test_connbytes_u64_max_translates() -> None:
    nft = translate_rule(
        Family.IP,
        "filter",
        _connbytes("18446744073709551615:", "both", "bytes"),
    )
    assert nft.statements[0].to_text() == "ct bytes >= 18446744073709551615"


def test_quota_u63_max_translates() -> None:
    nft = translate_rule(
        Family.IP, "filter", _quota_rule("9223372036854775807")
    )
    assert isinstance(nft.statements[0], NftQuota)
    assert nft.statements[0].to_text() == "quota 9223372036854775807 bytes"


# --- every dynamic set declaration carries `flags dynamic` ---


def _dynamic_add_set_lines(
    family: Family, chain_name: str, rules: list[NftRule]
) -> list[str]:
    table = NftTable(family=family.nft_name, name="ferm")
    chains: list[NftBaseChain | NftRegularChain] = [
        NftRegularChain(chain_name)
    ]
    payload = {chain_name: rules}
    decls = _collect_set_declarations(family, payload)
    out = serialize_table(table, chains, payload, decls, noflush=False)
    return [line for line in out.splitlines() if line.startswith("add set")]


def test_dynamic_sets_carry_flags_dynamic() -> None:
    recent_rule = _recent_rule(
        _recent("rcheck"),
        _recent("seconds", "60"),
        _recent("hitcount", "3"),
        _recent("name", "R"),
        verdict="DROP",
    )
    specs = _build_recent_specs(Family.IP, [recent_rule])
    recent_nft = translate_rule(
        Family.IP, "filter", recent_rule, chain="c", recent_specs=specs
    )
    hashlimit_nft = translate_rule(
        Family.IP,
        "filter",
        _hashlimit_rule(
            _opt("hashlimit-upto", "3/minute", module="hashlimit"),
            _opt("hashlimit-name", "H", module="hashlimit"),
            _opt("hashlimit-mode", "srcip", module="hashlimit"),
        ),
    )
    connlimit_nft = translate_rule(
        Family.IP,
        "filter",
        _connlimit(_cl("connlimit-above", "20"), _cl("connlimit-mask", "24")),
    )
    _finalize_connlimit_names(Family.IP, "filter", "c", [connlimit_nft])
    for label, rules in (
        ("recent", [recent_nft]),
        ("hashlimit", [hashlimit_nft]),
        ("connlimit", [connlimit_nft]),
    ):
        lines = _dynamic_add_set_lines(Family.IP, "c", rules)
        assert lines, f"{label} produced no add set line"
        assert all("flags dynamic" in line for line in lines), label


# --- ip6 parity for family-agnostic constructs ---


def test_family_agnostic_constructs_match_under_ip6() -> None:
    # these constructs carry no address family, so ip6 must emit identically
    # to ip; one representative assertion per construct.
    assert (
        build_verdict(Family.IP6, "filter", "jump", "NFQUEUE", {}).to_text()
        == build_verdict(Family.IP, "filter", "jump", "NFQUEUE", {}).to_text()
    )
    assert (
        translate_match(
            Family.IP6, _opt("pkt-type", "unicast", module="pkttype"), None
        )
        == "meta pkttype host"
    )
    stat = _rule(
        _statistic("mode", "random"),
        _statistic("probability", "0.5"),
        _target("ACCEPT"),
    )
    assert [
        s.to_text()
        for s in translate_rule(Family.IP6, "filter", stat).statements
    ] == ["meta random & 2147483647 < 1073741824", "accept"]
    tcpopt = translate_rule(Family.IP6, "mangle", _tcpoptstrip_rule("mss"))
    assert [s.to_text() for s in tcpopt.statements] == [
        "meta l4proto tcp",
        "reset tcp option maxseg",
    ]
    time_rule = _rule(
        _opt("weekdays", "Mon,Fri", module="time"), _target("ACCEPT")
    )
    assert (
        translate_rule(Family.IP6, "filter", time_rule).statements[0].to_text()
        == 'meta day { "Monday", "Friday" }'
    )
    assert (
        translate_rule(Family.IP6, "filter", _quota_rule("1048576"))
        .statements[0]
        .to_text()
        == "quota 1 mbytes"
    )


# ---------------------------------------------------------------------------
# 2026-07-10 mutation-kill batch 2
#
# Full-anchored refusal messages and behaviour pins for the surviving nft.py
# mutants: control-flow in NftBackend.commit/render/rollback (fake-runner
# seams), translate_rule/build_verdict/_translate_match_parts branches, the
# mark/dscp/ct/connbytes/hashlimit/statistic/netmap/nfqueue primitives, and
# the collapse/vmap fold helpers.  Message tests assert the EXACT runtime
# string (str(exc.value) ==) so an XX-wrapped / upper-cased / None-replaced
# literal diverges and dies.
# ---------------------------------------------------------------------------

from pyferm.backend.nft import (  # noqa: E402
    _CT_STATE_RANK,
    _connbytes_match,
    _connbytes_range,
    _connbytes_u64,
    _connlimit_count,
    _ct_bitmask_expr,
    _datetime_iso,
    _dscp_class_value,
    _dscp_value,
    _elements_equal,
    _full_reload_text,
    _hashlimit_key_implies_l4proto,
    _hashlimit_rate,
    _hashlimit_update,
    _icmp_type_expr,
    _iprange_bound,
    _mark_value,
    _masked_mark_expr,
    _masked_mark_set,
    _merge_run,
    _netmap_verdict,
    _nflog_verdict,
    _nfqueue_verdict,
    _prefix_length_mask,
    _quota_statement,
    _statistic_match,
    _stmt_equal,
    _synproxy_verdict,
    _tcp_flags_expr,
    _tcpopt_nft_name,
    _time_day_match,
    _time_hour_match,
    _time_of_day,
    _tproxy_verdict,
    _translate_match_set,
)


def _msg(exc: pytest.ExceptionInfo[FermError]) -> str:
    return str(exc.value)


# --- _tcp_flags_expr -------------------------------------------------------


def test_tcp_flags_unsupported_shape_message_anchored() -> None:
    # not-Params, wrong arity, and non-str members all share ONE refusal.
    for value in (
        "not-params",
        Params(values=["only-one"]),
        Params(values=[Negated("x"), "syn"]),
    ):
        with pytest.raises(FermError) as exc:
            _tcp_flags_expr(value)
        assert _msg(exc) == "unsupported value shape for nft backend"


def test_tcp_flags_negated_none_refused() -> None:
    # neg must stay a real bool: a negated MASK/NONE has no infix form.
    with pytest.raises(FermError) as exc:
        _tcp_flags_expr(Negated(Params(values=["SYN", "NONE"])))
    assert (
        _msg(exc)
        == "negated tcp-flags NONE cannot be expressed for nft backend"
    )


# --- _mark_value / _masked_mark_set / _masked_mark_expr --------------------


def test_mark_value_partial_mask_refused() -> None:
    with pytest.raises(FermError) as exc:
        _mark_value("0x1/0x2")
    assert (
        _msg(exc) == "masked mark '0x1/0x2' not yet supported by nft backend"
    )


def test_masked_mark_set_invalid_and_zero_mask() -> None:
    with pytest.raises(FermError) as exc:
        _masked_mark_set("zz/0x1")
    assert _msg(exc) == "invalid tproxy-mark 'zz/0x1' for nft backend"
    with pytest.raises(FermError) as exc:
        _masked_mark_set("0x1/0x0")
    assert (
        _msg(exc)
        == "tproxy-mark '0x1/0x0' has a zero mask (a no-op) for nft backend"
    )


def test_masked_mark_expr_invalid_message() -> None:
    with pytest.raises(FermError) as exc:
        _masked_mark_expr("meta mark", "0x1/zz", False)
    assert _msg(exc) == "invalid mark '0x1/zz' for nft backend"


# --- _icmp_type_expr -------------------------------------------------------


def test_icmp_type_expr_refusals_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _icmp_type_expr(Family.IP, "300", False)
    assert _msg(exc) == "invalid icmp type '300' for nft backend"
    with pytest.raises(FermError) as exc:
        _icmp_type_expr(Family.IP, "3/1", True)
    assert (
        _msg(exc) == "negated icmp type/code match cannot be expressed as "
        "infix nft matches"
    )
    with pytest.raises(FermError) as exc:
        _icmp_type_expr(Family.IP, "bogus", False)
    assert _msg(exc) == "icmp-type 'bogus' not yet supported by nft backend"


def test_icmp_type_octet_boundary() -> None:
    # 255 is the max octet; the readback keeps an unmapped number verbatim.
    assert _icmp_type_expr(Family.IP, "255", False) == "icmp type 255"


# --- _dscp_value / _dscp_class_value ---------------------------------------


def test_dscp_value_refusals_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _dscp_value("dscp", "zz")
    assert (
        _msg(exc) == "option 'dscp': invalid dscp value 'zz' for nft backend"
    )
    with pytest.raises(FermError) as exc:
        _dscp_value("dscp", "99")
    assert (
        _msg(exc)
        == "option 'dscp': dscp value '99' out of range 0-63 for nft backend"
    )


def test_dscp_class_value_refusal_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _dscp_class_value("dscp-class", "bogus")
    assert (
        _msg(exc)
        == "option 'dscp-class': unknown dscp class 'bogus' for nft backend"
    )


# --- _iprange_bound --------------------------------------------------------


def test_iprange_bound_refusals_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _iprange_bound(Family.IP, "1.2.3.4.5")
    assert _msg(exc) == "invalid iprange bound '1.2.3.4.5' for the nft backend"
    with pytest.raises(FermError) as exc:
        _iprange_bound(Family.IP, "fe80::1")
    assert (
        _msg(exc) == "iprange bound 'fe80::1' does not match the ip family "
        "for the nft backend"
    )


# --- _ct_bitmask_expr ------------------------------------------------------


def test_ct_bitmask_single_negated_state_uses_inequality() -> None:
    # a single-member negated `ct state` keeps the `!=` canon; the multi and
    # the `ct status` selector use the masked bang form instead.
    assert _ct_bitmask_expr("ct state", ["new"], _CT_STATE_RANK, True) == (
        "ct state != new"
    )
    assert _ct_bitmask_expr("ct state", ["new"], _CT_STATE_RANK, False) == (
        "ct state new"
    )


def test_ct_bitmask_two_negated_states_use_bang_form() -> None:
    expr, _key, _element = _translate_match_parts(
        Family.IP,
        _opt("state", Negated("NEW,ESTABLISHED"), module="state"),
        None,
    )
    assert expr == "ct state ! established,new"


# --- _nfqueue_verdict ------------------------------------------------------


def test_nfqueue_refusals_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _nfqueue_verdict(
            {
                "queue-num": _opt("queue-num", "1"),
                "queue-balance": _opt("queue-balance", "1:2"),
            }
        )
    assert (
        _msg(exc) == "'queue-num' and 'queue-balance' are mutually exclusive "
        "for the nft backend"
    )
    with pytest.raises(FermError) as exc:
        _nfqueue_verdict({"queue-cpu-fanout": _opt("queue-cpu-fanout", None)})
    assert (
        _msg(exc) == "option 'queue-cpu-fanout' needs 'queue-balance' for the "
        "nft backend"
    )


def test_nfqueue_balance_partition_from_left() -> None:
    # `low:high` must split on the FIRST colon; a right-split would mis-read
    # a malformed triple, but the readback form is a straight low-high range.
    verdict = _nfqueue_verdict({"queue-balance": _opt("queue-balance", "1:3")})
    assert verdict.to_text() == "queue to 1-3"


# --- _synproxy_verdict -----------------------------------------------------


def test_synproxy_mss_u16_max_accepted() -> None:
    # 65535 is the u16 ceiling (inclusive); the wscale twin reads back as 0.
    verdict = _synproxy_verdict(
        {"mss": _opt("mss", "65535", module="SYNPROXY")}
    )
    assert verdict.to_text() == "synproxy mss 65535 wscale 0"


# --- _tproxy_verdict -------------------------------------------------------


def test_tproxy_refusals_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _tproxy_verdict(Family.IP, {}, has_transport=False)
    assert (
        _msg(exc)
        == "TPROXY needs a transport protocol match (tcp/udp) for the "
        "nft backend"
    )
    with pytest.raises(FermError) as exc:
        _tproxy_verdict(Family.IP, {}, has_transport=True)
    assert _msg(exc) == "TPROXY needs 'on-port' for the nft backend"


def test_tproxy_on_port_u16_max_accepted() -> None:
    verdict = _tproxy_verdict(
        Family.IP,
        {"on-port": _opt("on-port", "65535", module="TPROXY")},
        has_transport=True,
    )
    assert verdict.to_text() == "tproxy to :65535 accept"


# --- _netmap_verdict -------------------------------------------------------


def test_netmap_outside_nat_chain_refused_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _netmap_verdict(Family.IP, "filter", "INPUT", {}, [])
    assert _msg(exc) == (
        "NETMAP translates only inside a built-in nat chain "
        "(PREROUTING/OUTPUT rewrite the destination, "
        "POSTROUTING/INPUT the source) for the nft backend"
    )


# --- _translate_match_set --------------------------------------------------


def test_match_set_refusals_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _translate_match_set(Family.IP, Params(values=["extipset", "src"]))
    assert _msg(exc) == (
        "option 'match-set': external ipset 'extipset' cannot be "
        "referenced from nftables; declare it with @set $extipset = "
        "(...) or keep the iptables backend"
    )
    with pytest.raises(FermError) as exc:
        _translate_match_set(
            Family.IP, Params(values=[SetRef("s", ["1.1.1.1"]), "src,dst"])
        )
    assert _msg(exc) == (
        "option 'match-set': multiple set-match flags need a "
        "concatenated set type that @set does not declare"
    )
    with pytest.raises(FermError) as exc:
        _translate_match_set(
            Family.IP, Params(values=[SetRef("s", ["1.1.1.1"]), "bogus"])
        )
    assert _msg(exc) == (
        "option 'match-set': unsupported set-match flag 'bogus' "
        "for the nft backend"
    )


def test_match_set_wrong_arity_is_internal_error() -> None:
    # A non-Params / wrong-length value is a caller contract breach: the
    # guard is `not Params or len != 2`, so a 1-element Params must still
    # route to internal_error, never fall through to the unpack.
    with pytest.raises(FermError, match="internal error"):
        _translate_match_set(Family.IP, Params(values=["only-one"]))


# --- _nflog_verdict --------------------------------------------------------


def test_nflog_threshold_refused_and_accepted() -> None:
    with pytest.raises(FermError) as exc:
        _nflog_verdict({"nflog-threshold": _opt("nflog-threshold", "0")})
    assert _msg(exc) == "invalid nflog-threshold '0' for nft backend"
    ok = _nflog_verdict({"nflog-threshold": _opt("nflog-threshold", "1")})
    assert ok.to_text() == "log group 0 queue-threshold 1"


def test_nflog_group_u16_max_accepted() -> None:
    ok = _nflog_verdict({"nflog-group": _opt("nflog-group", "65535")})
    assert ok.to_text() == "log group 65535"


# --- _statistic_match ------------------------------------------------------


def test_statistic_refusals_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _statistic_match({"mode": _opt("mode", "random", module="statistic")})
    assert (
        _msg(exc) == "mod statistic mode random needs a 'probability' for the "
        "nft backend"
    )
    with pytest.raises(FermError) as exc:
        _statistic_match(
            {
                "mode": _opt("mode", "random", module="statistic"),
                "probability": _opt("probability", "2", module="statistic"),
            }
        )
    assert (
        _msg(exc)
        == "statistic probability '2' is outside [0, 1] for the nft backend"
    )
    with pytest.raises(FermError) as exc:
        _statistic_match(
            {
                "mode": _opt("mode", "nth", module="statistic"),
                "every": _opt("every", "10", module="statistic"),
                "packet": _opt("packet", "abc", module="statistic"),
            }
        )
    assert _msg(exc) == "invalid statistic packet 'abc' for nft backend"


# --- _prefix_length_mask ---------------------------------------------------


def test_prefix_length_mask_refusals_and_boundaries() -> None:
    with pytest.raises(FermError) as exc:
        _prefix_length_mask(Family.IP, "zz")
    assert _msg(exc) == "invalid hashlimit mask 'zz' for the nft backend"
    # /32 and /128 are the inclusive ceilings; one past refuses.
    assert _prefix_length_mask(Family.IP, "32") == "255.255.255.255"
    assert _prefix_length_mask(Family.IP6, "128") == (
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    )
    with pytest.raises(FermError) as exc:
        _prefix_length_mask(Family.IP, "33")
    assert _msg(exc) == "hashlimit mask '33' exceeds /32 for nft"
    with pytest.raises(FermError) as exc:
        _prefix_length_mask(Family.IP6, "129")
    assert _msg(exc) == "hashlimit mask '129' exceeds /128 for nft"


# --- _connbytes ------------------------------------------------------------


def test_connbytes_range_forms_and_refusals() -> None:
    # negated open lower bound flips >= to < (readback spelling, not ge/lt)
    assert _connbytes_range("ct bytes", "100", True) == "ct bytes < 100"
    # inclusive N:M lo == hi is a legal 1-wide interval, not lo > hi
    assert _connbytes_range("ct bytes", "5:5", False) == "ct bytes 5-5"
    with pytest.raises(FermError) as exc:
        _connbytes_range("ct bytes", ":", False)
    assert _msg(exc) == "invalid connbytes range ':' for the nft backend"


def test_connbytes_u64_and_match_refusals() -> None:
    with pytest.raises(FermError) as exc:
        _connbytes_u64("abc")
    assert _msg(exc) == "invalid connbytes value 'abc' for the nft backend"
    with pytest.raises(FermError) as exc:
        _connbytes_match({})
    assert (
        _msg(exc)
        == "mod connbytes needs a 'connbytes' value for the nft backend"
    )
    with pytest.raises(FermError) as exc:
        _connbytes_match(
            {"connbytes": _opt("connbytes", "100:", module="connbytes")}
        )
    assert _msg(exc) == (
        "mod connbytes needs both 'connbytes-dir' and 'connbytes-mode' "
        "for the nft backend"
    )
    with pytest.raises(FermError) as exc:
        _connbytes_match(
            {
                "connbytes": _opt("connbytes", "100:", module="connbytes"),
                "connbytes-dir": _opt(
                    "connbytes-dir", Negated("both"), module="connbytes"
                ),
                "connbytes-mode": _opt(
                    "connbytes-mode", "bytes", module="connbytes"
                ),
            }
        )
    assert (
        _msg(exc)
        == "mod connbytes dir/mode cannot be negated for the nft backend"
    )


# --- _quota_statement ------------------------------------------------------


def test_quota_over_ceiling_refused_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _quota_statement(_opt("quota", "9223372036854775808", module="quota"))
    assert _msg(exc) == (
        "quota '9223372036854775808' exceeds nft's 2^63-1 ceiling "
        "for the nft backend"
    )


# --- _connlimit_count ------------------------------------------------------


def test_connlimit_count_u32_boundary() -> None:
    assert _connlimit_count("4294967295") == "4294967295"
    with pytest.raises(FermError) as exc:
        _connlimit_count("4294967296")
    assert (
        _msg(exc)
        == "connlimit count '4294967296' exceeds 2^32-1 for the nft backend"
    )


# --- _hashlimit_rate / _hashlimit_update -----------------------------------


def test_hashlimit_rate_lower_boundary() -> None:
    # 1 packet is the minimum legal rate (the guard is `< 1`, not `<= 1`).
    assert _hashlimit_rate("1/second") == ("1", "second")


def _hlrule(*opts: RenderedOption) -> RenderedRule:
    return _rule(*opts, _target("ACCEPT"))


def test_hashlimit_update_refusals_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _hashlimit_update(
            Family.IP,
            _hlrule(
                _opt("hashlimit-name", "x", module="hashlimit"),
                _opt("hashlimit-mode", "srcip", module="hashlimit"),
            ),
            "tcp",
        )
    assert (
        _msg(exc)
        == "mod hashlimit needs an upto/above rate for the nft backend"
    )
    with pytest.raises(FermError) as exc:
        _hashlimit_update(
            Family.IP,
            _hlrule(
                _opt("hashlimit-upto", "3/minute", module="hashlimit"),
                _opt("hashlimit-name", "x", module="hashlimit"),
                _opt("hashlimit-mode", "srcip", module="hashlimit"),
                _opt("hashlimit-burst", "zz", module="hashlimit"),
            ),
            "tcp",
        )
    assert _msg(exc) == "invalid hashlimit burst 'zz' for the nft backend"


def test_hashlimit_update_threads_set_type() -> None:
    # the emitted update carries the address set type from the mode key, not
    # a dropped/None placeholder.
    upd = _hashlimit_update(
        Family.IP,
        _hlrule(
            _opt("hashlimit-upto", "3/minute", module="hashlimit"),
            _opt("hashlimit-name", "h", module="hashlimit"),
            _opt("hashlimit-mode", "srcip", module="hashlimit"),
        ),
        "tcp",
    )
    assert upd.set_type == "ipv4_addr"


# --- _hashlimit_key_implies_l4proto ----------------------------------------


def test_hashlimit_key_implies_l4proto_requires_both() -> None:
    # only a `hashlimit`-module `hashlimit-mode` option carrying a port token
    # implies l4proto; a same-named option from another module must NOT.
    port_mode = _opt("hashlimit-mode", "srcport", module="hashlimit")
    assert _hashlimit_key_implies_l4proto([port_mode]) is True
    assert (
        _hashlimit_key_implies_l4proto(
            [_opt("hashlimit-mode", "dstport", module="hashlimit")]
        )
        is True
    )
    # wrong module -> the AND guard rejects it
    assert (
        _hashlimit_key_implies_l4proto(
            [_opt("hashlimit-mode", "srcport", module="time")]
        )
        is False
    )
    # right module/name but an address-only key -> no port token
    assert (
        _hashlimit_key_implies_l4proto(
            [_opt("hashlimit-mode", "srcip", module="hashlimit")]
        )
        is False
    )


# --- _tcpopt_nft_name ------------------------------------------------------


def test_tcpopt_number_boundary() -> None:
    # 255 is the inclusive max tcp option number.
    assert _tcpopt_nft_name("255") == "255"
    with pytest.raises(FermError) as exc:
        _tcpopt_nft_name("256")
    assert _msg(exc) == "invalid tcp option '256' for nft backend"


# --- _time_of_day / _datetime_iso / _time_* --------------------------------


def test_time_of_day_out_of_range_message() -> None:
    with pytest.raises(FermError) as exc:
        _time_of_day("24:00")
    assert _msg(exc) == "invalid time '24:00' for nft backend"


def test_datetime_iso_invalid_message() -> None:
    with pytest.raises(FermError) as exc:
        _datetime_iso("2020-1-1")
    assert _msg(exc) == "invalid date '2020-1-1' for nft backend"
    with pytest.raises(FermError) as exc:
        _datetime_iso("2020-01-01T24:00")
    assert _msg(exc) == "invalid date '2020-01-01T24:00' for nft backend"


def test_time_hour_default_low_bound() -> None:
    # a lone timestop keeps xt's implicit 00:00 start (a literal, not XX-ed).
    assert _time_hour_match(
        {"timestop": _opt("timestop", "12:00", module="time")}
    ) == ('meta hour "00:00"-"12:00"')


def test_time_day_combined_keys_refused_anchored() -> None:
    with pytest.raises(FermError) as exc:
        _time_day_match(
            {
                "days": _opt("days", "Mon", module="time"),
                "weekdays": _opt("weekdays", "Tue", module="time"),
            }
        )
    assert (
        _msg(exc)
        == "mod time cannot combine 'days' and 'weekdays' for the nft backend"
    )


# --- _classify_priority (via CLASSIFY) -------------------------------------


def test_classify_priority_zero_minor_not_none() -> None:
    # 0:5 is NOT the tc `none` sentinel (that is 0:0); the AND guard keeps a
    # non-zero minor from collapsing to none.
    verdict = build_verdict(
        Family.IP,
        "mangle",
        "jump",
        "CLASSIFY",
        {"set-class": _opt("set-class", "0:5", module="CLASSIFY")},
    )
    assert verdict.to_text() == "meta priority set 0:5"


# --- build_verdict: CONNMARK / DSCP / MARK / CHECKSUM ----------------------


def test_build_verdict_connmark_masked_register_refused() -> None:
    for key in ("ctmask", "mask"):
        with pytest.raises(FermError) as exc:
            build_verdict(
                Family.IP,
                "mangle",
                "jump",
                "CONNMARK",
                {key: _opt(key, "0xff", module="CONNMARK")},
            )
        assert _msg(exc) == (
            f"CONNMARK '{key}' mixes two masked registers; nft "
            "cannot express it for the nft backend"
        )


def test_build_verdict_connmark_two_arith_ops_refused() -> None:
    with pytest.raises(FermError) as exc:
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "CONNMARK",
            {
                "set-mark": _opt("set-mark", "1", module="CONNMARK"),
                "and-mark": _opt("and-mark", "2", module="CONNMARK"),
            },
        )
    assert _msg(exc) == "CONNMARK target not yet supported by nft backend"


def test_build_verdict_dscp_invalid_value_and_class() -> None:
    with pytest.raises(FermError) as exc:
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "DSCP",
            {"set-dscp": _opt("set-dscp", "99", module="DSCP")},
        )
    assert _msg(exc) == (
        "option 'set-dscp': dscp value '99' out of range 0-63 for nft backend"
    )
    with pytest.raises(FermError) as exc:
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "DSCP",
            {"set-dscp-class": _opt("set-dscp-class", "bogus", module="DSCP")},
        )
    assert _msg(exc) == (
        "option 'set-dscp-class': unknown dscp class 'bogus' for nft backend"
    )


def test_build_verdict_mark_arith_zero_mask_names_option() -> None:
    with pytest.raises(FermError) as exc:
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "MARK",
            {"set-xmark": _opt("set-xmark", "0x5/0x0", module="MARK")},
        )
    assert (
        _msg(exc)
        == "set-xmark '0x5/0x0' has a zero mask (a no-op) for nft backend"
    )
    with pytest.raises(FermError) as exc:
        build_verdict(
            Family.IP,
            "mangle",
            "jump",
            "MARK",
            {"set-mark": _opt("set-mark", "0x0/0x0", module="MARK")},
        )
    assert (
        _msg(exc)
        == "set-mark '0x0/0x0' has a zero mask (a no-op) for nft backend"
    )


def test_build_verdict_checksum_refused_anchored() -> None:
    with pytest.raises(FermError) as exc:
        build_verdict(Family.IP, "mangle", "jump", "CHECKSUM", {})
    assert _msg(exc) == (
        "CHECKSUM target has no nft equivalent (kernels since 4.19 "
        "handle virtio checksum offload without it); use the iptables "
        "backend for this rule"
    )


# --- _translate_match_parts branch behaviour -------------------------------


def _translate_match(domain: Family, option: RenderedOption) -> str:
    return _translate_match_parts(domain, option, "tcp")[0]


def test_match_parts_negated_operators_keep_bang() -> None:
    # the `_op(neg)` threading must pass the real neg flag, not a constant:
    # each negated form keeps its `!= ` prefix.
    assert (
        _translate_match_parts(
            Family.IP,
            _opt("destination-ports", Negated("22"), module="multiport"),
            "tcp",
        )[0]
        == "tcp dport != 22"
    )
    assert (
        _translate_match_parts(Family.IP, _opt("dscp", Negated("10")), None)[0]
        == "ip dscp != af11"
    )
    assert (
        _translate_match_parts(Family.ARP, _opt("opcode", Negated("1")), None)[
            0
        ]
        == "arp operation != request"
    )
    assert (
        _translate_match_parts(Family.IP, _opt("ttl-gt", Negated("5")), None)[
            0
        ]
        == "ip ttl != > 5"
    )


def test_match_parts_dscp_invalid_names_option() -> None:
    with pytest.raises(FermError) as exc:
        _translate_match_parts(Family.IP, _opt("dscp", "zz"), None)
    assert (
        _msg(exc) == "option 'dscp': invalid dscp value 'zz' for nft backend"
    )
    with pytest.raises(FermError) as exc:
        _translate_match_parts(Family.IP, _opt("dscp-class", "bogus"), None)
    assert (
        _msg(exc)
        == "option 'dscp-class': unknown dscp class 'bogus' for nft backend"
    )


def test_match_parts_length_and_mac_refusals() -> None:
    with pytest.raises(FermError) as exc:
        _translate_match_parts(Family.IP, _opt("length", "5:x"), None)
    assert _msg(exc) == "invalid length '5:x' for nft backend"
    with pytest.raises(FermError) as exc:
        _translate_match_parts(Family.IP, _opt("mac-source", "zz"), None)
    assert _msg(exc) == "invalid mac 'zz' for nft backend"


def test_match_parts_iprange_boolean_guard() -> None:
    # `not sep or not low or not high` must reject a missing bound with the
    # iprange message, not slip through to the per-bound validator.
    for scalar in ("10.0.0.1-", "-10.0.0.2"):
        with pytest.raises(FermError) as exc:
            _translate_match_parts(Family.IP, _opt("src-range", scalar), None)
        assert _msg(exc) == f"invalid iprange '{scalar}' for the nft backend"


# --- collapse / vmap fold helpers ------------------------------------------


def _set_match(element: str) -> NftMatch:
    return NftMatch(
        f"tcp dport {element}", set_key="tcp dport", element=element
    )


def test_elements_equal_none_semantics() -> None:
    assert _elements_equal(None, None) is True
    assert _elements_equal(None, ["22"]) is False
    assert _elements_equal(["22", "80"], ["80", "22"]) is True


def test_stmt_equal_type_and_expr_paths() -> None:
    # a match vs a verdict is never equal (the isinstance AND guard); two
    # plain-expr matches compare by expr.
    assert _stmt_equal(_set_match("22"), NftVerdict("accept")) is False
    assert (
        _stmt_equal(NftMatch("ct state new"), NftMatch("ct state new")) is True
    )
    assert (
        _stmt_equal(NftMatch("ct state new"), NftMatch("ct state old"))
        is False
    )
    # eligible + plain of the SAME expr falls to the expr path (both set_key
    # must be non-None to take the structured path).
    assert _stmt_equal(_set_match("22"), NftMatch("tcp dport 22")) is True


def test_merge_run_extends_prefolded_and_keeps_comment() -> None:
    prefolded = NftRule(
        [
            NftMatch(
                "tcp dport 22", set_key="tcp dport", elements=["22", "80"]
            ),
            NftVerdict("accept"),
        ],
        comment="keepme",
    )
    single = NftRule([_set_match("443"), NftVerdict("accept")])
    merged = _merge_run([prefolded, single], 0, 1, 0)
    assert merged.statements[0].to_text() == "tcp dport { 22, 80, 443 }"
    assert merged.comment == "keepme"


def test_collapse_folds_full_run_of_singles() -> None:
    rules = [
        NftRule([_set_match(p), NftVerdict("accept")])
        for p in ("22", "80", "443", "8080")
    ]
    out = _collapse_chain_rules(rules)
    assert len(out) == 1
    assert out[0].statements[0].to_text() == "tcp dport { 22, 80, 443, 8080 }"


def test_vmap_candidate_rejects_non_leaf_shapes() -> None:
    # set_key present but no single element -> not a vmap leaf
    no_element = NftRule(
        [NftMatch("tcp dport", set_key="tcp dport"), NftVerdict("accept")]
    )
    assert _vmap_candidate(no_element) is None
    # element present but no set_key (e.g. a negated match) -> not a leaf
    no_key = NftRule(
        [NftMatch("tcp dport 22", element="22"), NftVerdict("accept")]
    )
    assert _vmap_candidate(no_key) is None
    # a real leaf still folds
    leaf = NftRule([_set_match("22"), NftVerdict("accept")])
    assert _vmap_candidate(leaf) == ("tcp dport", "22", "accept")


def test_full_reload_text_rewrites_flush_to_delete() -> None:
    save = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add rule ip ferm INPUT accept\n"
    )
    out = _full_reload_text(save, "ip")
    assert "delete table ip ferm\nadd table ip ferm\n" in out
    assert "flush table ip ferm\n" not in out


# ---------------------------------------------------------------------------
# 2026-07-10 mutation-kill batch 2 (part 2): lifecycle control flow
#
# NftBackend.commit/render/rollback thread family/delta/full-reload decisions
# through fake runner seams (project memory: runner default None + late
# binding -- the seam stays untouched).  These pin the delta-vs-full-reload
# choice, the applied stdin text, and which domain_info reaches `restore`.
# ---------------------------------------------------------------------------

_KILL2_SAVE = (
    "add table ip ferm\n"
    "flush table ip ferm\n"
    "add chain ip ferm INPUT "
    "{ type filter hook input priority filter; policy accept; }\n"
    "add rule ip ferm INPUT tcp dport 22 accept\n"
    "add rule ip ferm INPUT tcp dport 80 accept\n"
)
_KILL2_PREV_ONE = (
    "table ip ferm {\n"
    "\tchain INPUT {\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t\ttcp dport 22 accept\n"
    "\t}\n"
    "}\n"
)
_KILL2_PREV_SAME = (
    "table ip ferm {\n"
    "\tchain INPUT {\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t\ttcp dport 22 accept\n"
    "\t\ttcp dport 80 accept\n"
    "\t}\n"
    "}\n"
)


class _CommitResult:
    def __init__(self) -> None:
        self.emitted: list[str] = []
        self.applied: list[str] = []
        self.restore_di: list[object] = []
        self.info: DomainInfo | None = None
        self.rc: int | None = None


def _run_commit(
    previous: str | None,
    options: Options,
    save: str = _KILL2_SAVE,
) -> _CommitResult:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    info.previous = previous
    result = _CommitResult()
    result.info = info

    def restore(di: object, text: str) -> None:
        result.restore_di.append(di)
        result.applied.append(text)

    result.rc = NftBackend().commit(
        Family.IP,
        info,
        Rendered(save=save),
        options,
        execute=lambda _c: None,
        emit_line=result.emitted.append,
        restore=restore,
    )
    return result


def test_commit_delta_flushes_chain_not_table() -> None:
    # previous carries one of the two rules -> a real delta that flushes the
    # chain and re-adds it, never the whole table.
    res = _run_commit(_KILL2_PREV_ONE, Options(noexec=False, lines=True))
    assert len(res.applied) == 1
    applied = res.applied[0]
    assert "flush chain ip ferm INPUT" in applied
    assert "delete table ip ferm" not in applied
    assert "flush table ip ferm" not in applied
    # the same delta text is what was shown under --lines
    assert any("flush chain ip ferm INPUT" in line for line in res.emitted)


def test_commit_idempotent_delta_applies_nothing() -> None:
    # previous already matches the rendered save -> empty delta -> nft -f is
    # skipped entirely (no restore call).
    res = _run_commit(_KILL2_PREV_SAME, Options(noexec=False, lines=True))
    assert res.applied == []
    assert res.emitted == []


def test_commit_first_run_full_reloads_with_delete_table() -> None:
    # no previous snapshot -> needs_full_reload -> whole-table replace via
    # delete+add table, never a bare `flush table`.
    res = _run_commit(None, Options(noexec=False, lines=True))
    assert len(res.applied) == 1
    applied = res.applied[0]
    assert "delete table ip ferm" in applied
    assert "flush table ip ferm" not in applied


def test_commit_full_reload_opt_out_forces_delete_table() -> None:
    # --full-reload turns off the delta even with a usable snapshot.
    res = _run_commit(
        _KILL2_PREV_ONE, Options(noexec=False, lines=True, full_reload=True)
    )
    assert len(res.applied) == 1
    assert "delete table ip ferm" in res.applied[0]


def test_commit_restore_receives_domain_info_not_none() -> None:
    # `restore(domain_info, apply_text)` must thread the real domain_info so
    # the applier can pick the right tool/family.
    res = _run_commit(None, Options(noexec=False, lines=False))
    assert res.restore_di == [res.info]


def test_commit_lines_false_emits_nothing() -> None:
    # the `options.lines and apply_text` guard must be AND: without --lines no
    # script text is echoed even though a full reload is applied.
    res = _run_commit(None, Options(noexec=False, lines=False))
    assert res.emitted == []
    assert len(res.applied) == 1  # still applied, just not echoed


def test_commit_noflush_full_reload_neither_flushes_nor_deletes() -> None:
    # --noflush keeps the apply append-only: no flush table (the save carries
    # none) and the full-reload transform must not inject delete table.
    save = _KILL2_SAVE.replace("flush table ip ferm\n", "")
    res = _run_commit(
        None, Options(noexec=False, lines=True, noflush=True), save=save
    )
    assert len(res.applied) == 1
    assert "flush table ip ferm" not in res.applied[0]
    assert "delete table ip ferm" not in res.applied[0]


# --- render: None-threading through the family pipeline --------------------


def _render_ip(info: DomainInfo, options: Options | None = None) -> str:
    save = (
        NftBackend()
        .render(Family.IP, info, options or Options(test=True))
        .save
    )
    assert save is not None
    return save


def test_render_threads_family_table_and_set_type() -> None:
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    inp = table.chains.setdefault("INPUT", ChainInfo(policy="DROP"))
    inp.rules.append(_rule(_opt("source", "10.0.0.1"), _target("ACCEPT")))
    inp.rules.append(
        _rule(
            _opt("source", SetRef("goodguys", ["10.0.0.0/24"])),
            _target("ACCEPT"),
        )
    )
    inp.rules.append(_rule(_target("mychain")))
    table.chains.setdefault("mychain", ChainInfo())
    save = _render_ip(info)
    # domain threaded into translate_rule -> real family prefix on the match
    assert "add rule ip ferm INPUT ip saddr 10.0.0.1 accept\n" in save
    # table threaded into the jump target name (filter keeps the bare name)
    assert "add rule ip ferm INPUT jump mychain\n" in save
    # domain threaded into _collect_set_declarations -> real set type
    assert (
        "add set ip ferm goodguys { type ipv4_addr; flags interval; }\n"
        in save
    )


def test_render_finalizes_connlimit_name_from_family_table_chain() -> None:
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    inp = table.chains.setdefault("INPUT", ChainInfo(policy="DROP"))
    inp.rules.append(
        _rule(
            _opt("connlimit-above", "20", module="connlimit"),
            _opt("connlimit-mask", "24", module="connlimit"),
            _target("DROP"),
        )
    )
    save = _render_ip(info)
    # the content hash folds (family, table, chain, rule text, ordinal); the
    # rendered name must match the value _finalize_connlimit_names computes
    # for exactly (ip, filter, INPUT).
    assert "connlimit_fc6b45d39967" in save
    assert save.count("connlimit_fc6b45d39967") == 2  # decl + update reference


def test_render_recent_rule_uses_prepass_specs() -> None:
    # render must build recent specs and thread them into translate_rule; a
    # dropped spec would raise internal_error instead.
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    inp = table.chains.setdefault("INPUT", ChainInfo(policy="ACCEPT"))
    inp.rules.append(
        _rule(
            _opt("rcheck", None, module="recent"),
            _opt("seconds", "60", module="recent"),
            _opt("hitcount", "3", module="recent"),
            _opt("name", "R", module="recent"),
            _target("DROP"),
        )
    )
    save = _render_ip(info)
    assert (
        "add rule ip ferm INPUT update @recent_R "
        "{ ip saddr timeout 1m limit rate over 3/minute "
        "burst 2 packets } drop\n"
    ) in save


def test_render_netmap_rule_threads_chain() -> None:
    # chain is only consumed by _netmap_verdict; dropping it makes NETMAP
    # refuse (no built-in nat chain known), so a successful render pins the
    # chain threading.
    info = DomainInfo()
    nat = info.tables.setdefault("nat", TableInfo())
    pre = nat.chains.setdefault("PREROUTING", ChainInfo(policy="ACCEPT"))
    pre.rules.append(
        _rule(
            _opt("destination", "10.0.0.0/24"),
            _opt("to", "192.168.0.0/24", module="NETMAP"),
            _target("NETMAP"),
        )
    )
    save = _render_ip(info)
    assert (
        "dnat ip prefix to ip daddr map { 10.0.0.0/24 : 192.168.0.0/24 }"
        in save
    )


def test_render_noflush_omits_flush_line() -> None:
    # noflush must thread to serialize_table (not a hardcoded False/None).
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    table.chains.setdefault("INPUT", ChainInfo(policy="DROP")).rules.append(
        _rule(_target("ACCEPT"))
    )
    save = _render_ip(info, Options(test=True, noflush=True))
    assert "flush table ip ferm" not in save
    assert save.startswith("add table ip ferm\n")


def test_render_preserve_message_anchored() -> None:
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    table.preserve_regexes.append(re.compile("foo"))
    with pytest.raises(FermError) as exc:
        NftBackend().render(Family.IP, info, Options(test=True))
    assert _msg(exc) == "@preserve not yet supported by nft backend"


# --- rollback --------------------------------------------------------------


def test_rollback_restore_receives_domain_info() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    info.enabled = True
    info.previous = "table ip ferm {\n}\n"
    seen: list[object] = []
    NftBackend().rollback(
        Family.IP,
        info,
        Options(),
        execute=lambda _c: None,
        restore=lambda di, _save: seen.append(di),
    )
    assert seen == [info]


# --- build_chains: arp base-chain map needs the real domain ----------------


def test_build_chains_arp_forward_has_no_mapping() -> None:
    # map_base_chain must receive the real domain: arp maps only filter
    # INPUT/OUTPUT, so an arp filter/FORWARD base chain refuses (the ip map
    # would wrongly accept it).
    table = TableInfo(chains={"FORWARD": ChainInfo()})
    with pytest.raises(FermError, match="not yet supported"):
        build_chains(Family.ARP, "filter", table)


# --- serialize_table: the dynamic-decl loop must CONTINUE, not break -------


def test_serialize_table_emits_all_dynamic_declarations() -> None:
    # two dynamic set declarations: the first must not `break` the loop and
    # swallow the second.
    hl_a = translate_rule(
        Family.IP,
        "filter",
        _hashlimit_rule(
            _opt("hashlimit-upto", "3/minute", module="hashlimit"),
            _opt("hashlimit-name", "aaa", module="hashlimit"),
            _opt("hashlimit-mode", "srcip", module="hashlimit"),
        ),
    )
    hl_b = translate_rule(
        Family.IP,
        "filter",
        _hashlimit_rule(
            _opt("hashlimit-upto", "3/minute", module="hashlimit"),
            _opt("hashlimit-name", "bbb", module="hashlimit"),
            _opt("hashlimit-mode", "srcip", module="hashlimit"),
        ),
    )
    lines = _dynamic_add_set_lines(Family.IP, "c", [hl_a, hl_b])
    names = {line.split()[4] for line in lines}
    assert names == {"hashlimit_aaa", "hashlimit_bbb"}


# --- render_comment boundary + _nft_time_canon + _reduce_rate --------------


def test_render_comment_boundary_inclusive() -> None:
    # the limit is inclusive: exactly NFT_COMMENT_MAX bytes pass, one more
    # refuses (the guard is `>`, not `>=`).
    assert render_comment("x" * 128) == 'comment "' + "x" * 128 + '"'
    with pytest.raises(FermError, match="exceeds nft limit"):
        render_comment("x" * 129)


def test_nft_time_canon_positive_boundary() -> None:
    # 1 ms is the minimum positive timeout (the guard is `<= 0`, not `<= 1`).
    assert _nft_time_canon(1) == "1ms"
    with pytest.raises(FermError, match="must be positive"):
        _nft_time_canon(0)


def test_reduce_rate_unit_quotient_one() -> None:
    # a quotient of exactly 1 at the smallest unit must be accepted (the guard
    # is `>= 1`): 1 packet per 1 second is `1/second`, not promoted to minute.
    assert _reduce_rate(1, 1) == (1, "second")


# ---------------------------------------------------------------------------
# 2026-07-10 mutation-kill batch 2 (part 3): mark register boundaries
#
# The 0/_MARK_MAX comparison edges in _mark_value / _masked_mark_expr /
# _masked_mark_set / _setmark_effective, plus the effective-mask arithmetic
# that a `int(0)` mutation would silently zero.
# ---------------------------------------------------------------------------


def test_mark_value_range_edges() -> None:
    # 0 is a legal mark (the guard is `0 <= value`, not `1 <=`/`0 <`).
    assert _mark_value("0") == "0x00000000"
    with pytest.raises(FermError) as exc:
        _mark_value("0x100000000")
    assert _msg(exc) == "invalid mark '0x100000000' for nft backend"
    # a non-full mask whose bits are unparsable still refuses as masked, not
    # as a bare value (full_mask stays False on the ValueError path).
    with pytest.raises(FermError) as exc:
        _mark_value("0x1/zz")
    assert _msg(exc) == "masked mark '0x1/zz' not yet supported by nft backend"


def test_masked_mark_expr_range_edges() -> None:
    # value 0 and mask 0 are both legal (lower bounds inclusive); a full mask
    # value with a partial mask is legal (upper bound inclusive).
    assert (
        _masked_mark_expr("meta mark", "0x0/0x1", False)
        == "meta mark & 0x00000001 == 0x00000000"
    )
    assert (
        _masked_mark_expr("meta mark", "0x0/0x0", False)
        == "meta mark & 0x00000000 == 0x00000000"
    )
    assert (
        _masked_mark_expr("meta mark", "0xffffffff/0x1", False)
        == "meta mark & 0x00000001 == 0xffffffff"
    )


def test_masked_mark_set_out_of_range_value() -> None:
    # the range guard is an AND: a value past _MARK_MAX must refuse even with
    # a legal mask (an OR would let it through to the arithmetic).
    with pytest.raises(FermError) as exc:
        _masked_mark_set("0x100000000/0x1")
    assert _msg(exc) == "invalid tproxy-mark '0x100000000/0x1' for nft backend"


def test_setmark_effective_folds_value_into_mask() -> None:
    # the effective mask is value | mask; a mutation that reads the mask as
    # int(0) would drop the mask bits and mis-fold 0x5/0x3 to 0x5/0x5.
    assert _setmark_effective("0x5/0x3") == "0x5/0x7"


# ---------------------------------------------------------------------------
# 2026-07-10 mutation-kill batch 2 (part 4): _collect_set_declarations refusals
#
# Full-anchored variants of the three declaration-collection guards (the
# unfinalized-connlimit sentinel, the dynamic-set conflict, and the
# stateful/named collision) so the XX/upper/None message mutants diverge.
# ---------------------------------------------------------------------------


def _hl_named(name: str, mode: str) -> NftRule:
    return translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("hashlimit-upto", "3/minute", module="hashlimit"),
            _opt("hashlimit-name", name, module="hashlimit"),
            _opt("hashlimit-mode", mode, module="hashlimit"),
            _target("ACCEPT"),
        ),
    )


def test_collect_unfinalized_connlimit_message_anchored() -> None:
    sentinel = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("connlimit-above", "20", module="connlimit"),
            _opt("connlimit-mask", "24", module="connlimit"),
            _target("DROP"),
        ),
    )
    with pytest.raises(FermError) as exc:
        _collect_set_declarations(Family.IP, {"c": [sentinel]})
    assert _msg(exc) == (
        "internal error: connlimit set reached declaration collection "
        "with an unfinalized name"
    )


def test_collect_dynamic_set_conflict_message_anchored() -> None:
    # two hashlimit rules share a name but declare different key types.
    with pytest.raises(FermError) as exc:
        _collect_set_declarations(
            Family.IP,
            {"c": [_hl_named("d", "srcip"), _hl_named("d", "dstport")]},
        )
    assert _msg(exc) == (
        "set 'hashlimit_d' has conflicting declarations for the nft backend"
    )


def test_collect_stateful_named_collision_message_anchored() -> None:
    # a static @set whose name collides with a dynamic (hashlimit) set.
    named = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("source", SetRef("hashlimit_dup", ["10.0.0.1"])),
            _target("DROP"),
        ),
    )
    with pytest.raises(FermError) as exc:
        _collect_set_declarations(
            Family.IP, {"c": [_hl_named("dup", "srcip"), named]}
        )
    assert _msg(exc) == (
        "named set 'hashlimit_dup' collides with a stateful set of "
        "the same name for the nft backend"
    )


# ---------------------------------------------------------------------------
# 2026-07-10 mutation-kill batch 2 (part 4b): _finalize_connlimit_names hash
#
# The set name is a content hash over (family, table, chain, rule text,
# per-text ordinal).  Pinning the exact names of two byte-identical rules
# catches the ordinal arithmetic, the join separators, and the digest slice
# width (all of which shift the hash).
# ---------------------------------------------------------------------------


def test_finalize_connlimit_exact_names_for_identical_rules() -> None:
    def make() -> NftRule:
        return translate_rule(
            Family.IP,
            "filter",
            _connlimit(
                _cl("connlimit-above", "20"), _cl("connlimit-mask", "24")
            ),
        )

    rules = [make(), make()]
    _finalize_connlimit_names(Family.IP, "filter", "FORWARD", rules)
    # ordinal 0 and ordinal 1 give two distinct, exact content hashes; any
    # drift in the ordinal step, the join glue, or the 12-char slice changes
    # these literals.
    assert _connlimit_name(rules[0]) == "connlimit_11467455846b"
    assert _connlimit_name(rules[1]) == "connlimit_37377a5e09a1"


# ---------------------------------------------------------------------------
# translate_rule: SET target -> add/update/delete @set statement
# ---------------------------------------------------------------------------
from pyferm.backend.nft import (  # noqa: E402
    _collect_set_target_names,
    _references_empty_named_set,
)

#: The family pre-pass render() computes; unit rules must mirror it, or
#: the empty runtime bucket trips the translate_rule wiring assertion.
_BUCKET_TARGETS = frozenset({"badguys"})


def _set_target_rule(
    verb_opt: str,
    setref: SetRef,
    flags: str = "src",
    *extra: RenderedOption,
) -> RenderedRule:
    return _rule(
        _opt(verb_opt, Params([setref, flags]), module="SET"),
        *extra,
        _target("SET"),
    )


def _translate_set_rule(domain: Family, rule: RenderedRule) -> NftRule:
    return translate_rule(domain, "filter", rule, set_targets=_BUCKET_TARGETS)


def test_set_target_add_update_delete_verbs() -> None:
    bucket = SetRef("badguys", [])
    add = _translate_set_rule(Family.IP, _set_target_rule("add-set", bucket))
    assert [s.to_text() for s in add.statements] == [
        "add @badguys { ip saddr }"
    ]
    update = _translate_set_rule(
        Family.IP,
        _set_target_rule(
            "add-set", bucket, "src", _opt("exist", None, module="SET")
        ),
    )
    assert [s.to_text() for s in update.statements] == [
        "update @badguys { ip saddr }"
    ]
    delete = _translate_set_rule(
        Family.IP6, _set_target_rule("del-set", bucket, "dst")
    )
    assert [s.to_text() for s in delete.statements] == [
        "delete @badguys { ip6 daddr }"
    ]


def test_set_target_timeout_respells_to_readback() -> None:
    nft = _translate_set_rule(
        Family.IP,
        _set_target_rule(
            "add-set",
            SetRef("badguys", []),
            "src",
            _opt("timeout", "3600", module="SET"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "add @badguys { ip saddr timeout 1h }"
    ]
    stmt = nft.statements[0]
    assert isinstance(stmt, NftSetUpdate)
    assert not stmt.owned


def test_set_target_timeout_zero_means_permanent() -> None:
    # xt's `--timeout 0` overrides a set default to "permanent"; the ferm
    # @set has no default, so a permanent element is one WITHOUT a timeout.
    nft = _translate_set_rule(
        Family.IP,
        _set_target_rule(
            "add-set",
            SetRef("badguys", []),
            "src",
            _opt("timeout", "0", module="SET"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "add @badguys { ip saddr }"
    ]


def test_set_target_refusals() -> None:
    bucket = SetRef("badguys", [])
    # add-set alongside del-set: each carries a set reference, so the
    # one-named-set-per-rule guard refuses before the SET branch runs.
    with pytest.raises(FermError, match=r"at most one named set"):
        _translate_set_rule(
            Family.IP,
            _rule(
                _opt("add-set", Params([bucket, "src"]), module="SET"),
                _opt("del-set", Params([bucket, "src"]), module="SET"),
                _target("SET"),
            ),
        )
    with pytest.raises(FermError, match=r"needs 'add-set' or 'del-set'"):
        _translate_set_rule(Family.IP, _rule(_target("SET")))
    with pytest.raises(FermError, match=r"only valid with 'add-set'"):
        _translate_set_rule(
            Family.IP,
            _set_target_rule(
                "del-set", bucket, "src", _opt("timeout", "60", module="SET")
            ),
        )
    with pytest.raises(FermError, match=r"only valid with 'add-set'"):
        _translate_set_rule(
            Family.IP,
            _set_target_rule(
                "del-set", bucket, "src", _opt("exist", None, module="SET")
            ),
        )
    with pytest.raises(FermError, match=r"multiple SET target flags"):
        _translate_set_rule(
            Family.IP, _set_target_rule("add-set", bucket, "src,dst")
        )
    with pytest.raises(FermError, match=r"unsupported SET target flag"):
        _translate_set_rule(
            Family.IP, _set_target_rule("add-set", bucket, "bogus")
        )
    with pytest.raises(FermError, match=r"external ipset"):
        _translate_set_rule(
            Family.IP,
            _rule(
                _opt("add-set", Params(["extern", "src"]), module="SET"),
                _target("SET"),
            ),
        )
    with pytest.raises(FermError, match=r"must be declared empty"):
        _translate_set_rule(
            Family.IP,
            _set_target_rule("add-set", SetRef("badguys", ["10.0.0.1"])),
        )
    with pytest.raises(FermError, match=r"invalid SET timeout"):
        _translate_set_rule(
            Family.IP,
            _set_target_rule(
                "add-set", bucket, "src", _opt("timeout", "1h", module="SET")
            ),
        )


def test_collect_set_target_names_and_empty_set_exemption() -> None:
    bucket = SetRef("badguys", [])
    set_rule = _set_target_rule("add-set", bucket)
    lookup = _rule(_match_set_opt(bucket, "src"), _target("DROP"))
    other_empty = _rule(
        _match_set_opt(SetRef("unrelated", []), "src"), _target("DROP")
    )
    names = _collect_set_target_names([set_rule, lookup, other_empty])
    assert names == _BUCKET_TARGETS
    # The mutating rule and the lookup survive; an empty set nobody
    # mutates keeps the drop semantics.
    assert not _references_empty_named_set(set_rule, names)
    assert not _references_empty_named_set(lookup, names)
    assert _references_empty_named_set(other_empty, names)
    assert _references_empty_named_set(lookup)


def test_collector_merges_lookup_with_set_target_both_orders() -> None:
    bucket = SetRef("badguys", [])
    set_rule = _translate_set_rule(
        Family.IP,
        _set_target_rule(
            "add-set", bucket, "src", _opt("timeout", "60", module="SET")
        ),
    )
    lookup = _translate_set_rule(
        Family.IP, _rule(_match_set_opt(bucket, "src"), _target("DROP"))
    )
    for order in ([set_rule, lookup], [lookup, set_rule]):
        decls = _collect_set_declarations(Family.IP, {"INPUT": order})
        decl = decls["badguys"]
        assert isinstance(decl, _DynSetDecl)
        assert not decl.owned
        assert decl.type_ == "ipv4_addr"
        assert decl.with_timeout


def test_collector_ors_timeout_flag_across_set_target_rules() -> None:
    bucket = SetRef("badguys", [])
    plain = _translate_set_rule(Family.IP, _set_target_rule("add-set", bucket))
    timed = _translate_set_rule(
        Family.IP,
        _set_target_rule(
            "add-set", bucket, "src", _opt("timeout", "60", module="SET")
        ),
    )
    # A permanent add and a timed add legally share one set; the flag is
    # the OR across uses, whichever rule the collector sees first.
    for order in ([plain, timed], [timed, plain]):
        decls = _collect_set_declarations(Family.IP, {"INPUT": order})
        decl = decls["badguys"]
        assert isinstance(decl, _DynSetDecl)
        assert decl.with_timeout


def test_collector_conflicts_set_target_with_port_lookup() -> None:
    # `dport $x` types the set inet_service; the addr-keyed SET target
    # cannot share it -- conflict, never a silent overwrite.
    port_lookup = _translate_set_rule(
        Family.IP,
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("dport", SetRef("badguys", ["22"])),
            _target("ACCEPT"),
        ),
    )
    set_rule = _translate_set_rule(
        Family.IP, _set_target_rule("add-set", SetRef("badguys", []))
    )
    with pytest.raises(FermError, match=r"conflicting declarations"):
        _collect_set_declarations(
            Family.IP, {"INPUT": [port_lookup, set_rule]}
        )
    with pytest.raises(FermError, match=r"collides with a stateful set"):
        _collect_set_declarations(
            Family.IP, {"INPUT": [set_rule, port_lookup]}
        )


def test_collector_keeps_owned_set_strictness() -> None:
    # A user SET-target set must not merge with a ferm-owned stateful set
    # (recent_*) of the same name.
    owned = NftSetUpdate(
        "badguys", "ip saddr", "ipv4_addr", "1h", "rate 1/minute"
    )
    user = _translate_set_rule(
        Family.IP, _set_target_rule("add-set", SetRef("badguys", []))
    )
    owned_rule = NftRule([owned])
    with pytest.raises(FermError, match=r"conflicting declarations"):
        _collect_set_declarations(Family.IP, {"INPUT": [owned_rule, user]})
    with pytest.raises(FermError, match=r"conflicting declarations"):
        _collect_set_declarations(Family.IP, {"INPUT": [user, owned_rule]})


# ---------------------------------------------------------------------------
# translate_match for the mss and tcp-option matches
# ---------------------------------------------------------------------------


def test_translate_mss_match_forms() -> None:
    assert (
        translate_match(Family.IP, _opt("mss", "536", module="tcpmss"), "tcp")
        == "tcp option maxseg size 536"
    )
    assert (
        translate_match(
            Family.IP, _opt("mss", "1400:1500", module="tcpmss"), "tcp"
        )
        == "tcp option maxseg size 1400-1500"
    )
    assert (
        translate_match(
            Family.IP, _opt("mss", Negated("536"), module="tcpmss"), "tcp"
        )
        == "tcp option maxseg size != 536"
    )
    with pytest.raises(FermError, match=r"needs a tcp protocol"):
        translate_match(Family.IP, _opt("mss", "536", module="tcpmss"), None)
    with pytest.raises(FermError, match=r"^invalid mss 'abc'"):
        translate_match(Family.IP, _opt("mss", "abc", module="tcpmss"), "tcp")
    with pytest.raises(FermError, match=r"^invalid mss '536:'"):
        translate_match(Family.IP, _opt("mss", "536:", module="tcpmss"), "tcp")


def test_translate_tcp_option_respells_known_kinds() -> None:
    # The kernel readback names known kinds (8 -> timestamp) and keeps
    # unknown ones numeric; emission must match it or --plan never
    # converges.
    assert (
        translate_match(
            Family.IP, _opt("tcp-option", "8", module="tcp"), "tcp"
        )
        == "tcp option timestamp exists"
    )
    assert (
        translate_match(
            Family.IP, _opt("tcp-option", "254", module="tcp"), "tcp"
        )
        == "tcp option 254 exists"
    )
    assert (
        translate_match(
            Family.IP, _opt("tcp-option", Negated("19"), module="tcp"), "tcp"
        )
        == "tcp option md5sig missing"
    )
    with pytest.raises(FermError, match=r"needs a tcp protocol"):
        translate_match(Family.IP, _opt("tcp-option", "8", module="tcp"), None)
    with pytest.raises(FermError, match=r"^invalid tcp-option '256'"):
        translate_match(
            Family.IP, _opt("tcp-option", "256", module="tcp"), "tcp"
        )
    with pytest.raises(FermError, match=r"^invalid tcp-option 'sack'"):
        translate_match(
            Family.IP, _opt("tcp-option", "sack", module="tcp"), "tcp"
        )


def test_tcp_option_match_implies_l4proto() -> None:
    # The tcp option MATCH forms drop the redundant `meta l4proto tcp`
    # (kernel readback omits it); SYNPROXY's `mss` companion must NOT
    # trigger the suppression -- its readback keeps the prefix.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("mss", "536", module="tcpmss"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "tcp option maxseg size 536",
        "accept",
    ]
    synproxy = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _opt("protocol", "tcp", kind=OptionKind.PROTO),
            _opt("syn", None, module="tcp"),
            _opt("mss", "1460", module="SYNPROXY"),
            _opt("wscale", "7", module="SYNPROXY"),
            _target("SYNPROXY"),
        ),
    )
    assert "synproxy mss 1460 wscale 7" in [
        s.to_text() for s in synproxy.statements
    ]
