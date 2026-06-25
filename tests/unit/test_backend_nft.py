# tests/unit/test_backend_nft.py
from __future__ import annotations

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
# nft_family + map_base_chain
# ---------------------------------------------------------------------------
from pyferm.backend.nft import map_base_chain, nft_family  # noqa: E402


def test_nft_family_maps_1to1() -> None:
    assert nft_family("ip") == "ip"
    assert nft_family("ip6") == "ip6"
    assert nft_family("arp") == "arp"
    assert nft_family("eb") == "bridge"


def test_nft_family_unknown_is_error() -> None:
    with pytest.raises(FermError, match="not yet supported"):
        nft_family("bogus")


def test_map_base_chain_known_pairs() -> None:
    spec = map_base_chain("ip", "filter", "INPUT")
    assert spec == ("filter", "input", 0)
    assert map_base_chain("ip", "nat", "POSTROUTING") == (
        "nat",
        "postrouting",
        100,
    )
    assert map_base_chain("ip", "mangle", "OUTPUT") == (
        "route",
        "output",
        -150,
    )


def test_map_base_chain_unmappable_is_error() -> None:
    with pytest.raises(FermError, match="not yet supported"):
        map_base_chain("eb", "broute", "BROUTING")
    with pytest.raises(FermError, match="not yet supported"):
        map_base_chain("arp", "nat", "PREROUTING")


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
    chains = build_chains("ip", "filter", table)
    by_name = {c.name: c for c in chains}
    assert isinstance(by_name["INPUT"], NftBaseChain)
    assert by_name["INPUT"].policy == "drop"
    assert by_name["INPUT"].hook == "input"
    assert by_name["INPUT"].type == "filter"
    assert isinstance(by_name["mychain"], NftRegularChain)


def test_build_chains_sorted_for_determinism() -> None:
    table = TableInfo(chains={"zeta": ChainInfo(), "alpha": ChainInfo()})
    names = [c.name for c in build_chains("ip", "filter", table)]
    assert names == ["alpha", "zeta"]


def test_nft_chain_name_disambiguates_non_filter() -> None:
    from pyferm.backend.nft import nft_chain_name

    assert nft_chain_name("filter", "INPUT") == "INPUT"
    assert nft_chain_name("mangle", "INPUT") == "mangle_INPUT"
    # mangle/INPUT becomes a distinct base chain, not a collision with filter.
    table = TableInfo(chains={"INPUT": ChainInfo()})
    chain = build_chains("ip", "mangle", table)[0]
    # mangle/OUTPUT -> route hook (the most error-prone mapping).
    table_out = TableInfo(chains={"OUTPUT": ChainInfo()})
    chain_out = build_chains("ip", "mangle", table_out)[0]
    assert isinstance(chain_out, NftBaseChain)
    assert chain_out.type == "route"

    assert chain.name == "mangle_INPUT"
    assert isinstance(chain, NftBaseChain)
    assert (chain.hook, chain.priority) == ("input", -150)


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
from pyferm.values import Value  # noqa: E402


def _opt(
    name: str,
    value: Value,
    kind: str = "option",
    module: str | None = None,
) -> RenderedOption:
    return RenderedOption(name=name, value=value, kind=kind, module=module)


def test_translate_match_addresses_and_ifaces() -> None:
    assert (
        translate_match("ip", _opt("source", "10.0.0.1"), None)
        == "ip saddr 10.0.0.1"
    )
    assert (
        translate_match("ip6", _opt("destination", "fe80::1"), None)
        == "ip6 daddr fe80::1"
    )
    assert (
        translate_match("ip", _opt("in-interface", "eth0"), None)
        == 'iifname "eth0"'
    )
    assert (
        translate_match("ip", _opt("out-interface", "eth1"), None)
        == 'oifname "eth1"'
    )


def test_translate_match_ports_use_rule_protocol() -> None:
    assert translate_match("ip", _opt("dport", "22"), "tcp") == "tcp dport 22"
    assert translate_match("ip", _opt("sport", "53"), "udp") == "udp sport 53"


def test_translate_match_port_without_protocol_errors() -> None:
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        translate_match("ip", _opt("dport", "22"), None)


def test_translate_match_negation() -> None:
    assert (
        translate_match("ip", _opt("source", Negated("10.0.0.1")), None)
        == "ip saddr != 10.0.0.1"
    )
    assert (
        translate_match("ip", _opt("dport", Negated("23")), "tcp")
        == "tcp dport != 23"
    )


def test_translate_match_state_and_limit() -> None:
    assert (
        translate_match(
            "ip", _opt("state", "ESTABLISHED,RELATED", module="state"), None
        )
        == "ct state established,related"
    )
    assert (
        translate_match("ip", _opt("limit", "3/second", module="limit"), None)
        == "limit rate 3/second"
    )


def test_translate_match_uncovered_is_error() -> None:
    with pytest.raises(FermError, match="not yet supported"):
        translate_match("ip", _opt("totally-unknown", "x"), None)


# ---------------------------------------------------------------------------
# translate_match structured split (_translate_match_parts)
# ---------------------------------------------------------------------------
from pyferm.backend.nft import (  # noqa: E402
    _SET_ELIGIBLE_SELECTORS,
    _translate_match_parts,
)


def test_match_parts_port_is_eligible() -> None:
    expr, key, element = _translate_match_parts(
        "ip", _opt("dport", "22"), "tcp"
    )
    assert (expr, key, element) == ("tcp dport 22", "tcp dport", "22")


def test_match_parts_address_is_eligible() -> None:
    expr, key, element = _translate_match_parts(
        "ip", _opt("source", "10.0.0.1"), None
    )
    assert (expr, key, element) == (
        "ip saddr 10.0.0.1",
        "ip saddr",
        "10.0.0.1",
    )


def test_match_parts_negated_is_not_eligible() -> None:
    expr, key, element = _translate_match_parts(
        "ip", _opt("dport", Negated("23")), "tcp"
    )
    assert (key, element) == (None, None)
    assert expr == "tcp dport != 23"


def test_match_parts_state_is_not_eligible() -> None:
    _expr, key, element = _translate_match_parts(
        "ip", _opt("state", "NEW", module="state"), None
    )
    assert (key, element) == (None, None)


def test_match_parts_expr_matches_translate_match_wrapper() -> None:
    # The wrapper must never drift from the parts' expr.
    opt = _opt("dport", "1024-2048")
    assert _translate_match_parts("ip", opt, "tcp")[0] == translate_match(
        "ip", opt, "tcp"
    )


def test_set_eligible_selectors_are_documented() -> None:
    assert "tcp dport" in _SET_ELIGIBLE_SELECTORS
    assert "ip saddr" in _SET_ELIGIBLE_SELECTORS
    assert "meta l4proto" in _SET_ELIGIBLE_SELECTORS
    assert "ip protocol" not in _SET_ELIGIBLE_SELECTORS  # never emitted


# ---------------------------------------------------------------------------
# build_verdict
# ---------------------------------------------------------------------------
from pyferm.backend.nft import build_verdict  # noqa: E402


def test_build_verdict_core_targets() -> None:
    def _v(target: str) -> str:
        return build_verdict("ip", "filter", "jump", target, {}).to_text()

    assert _v("ACCEPT") == "accept"
    assert _v("DROP") == "drop"
    assert _v("RETURN") == "return"
    assert _v("QUEUE") == "queue"
    assert _v("MASQUERADE") == "masquerade"


def test_build_verdict_jump_goto_to_chain() -> None:
    assert (
        build_verdict("ip", "filter", "jump", "mychain", {}).to_text()
        == "jump mychain"
    )
    assert (
        build_verdict("ip", "nat", "goto", "mychain", {}).to_text()
        == "goto nat_mychain"
    )


def test_build_verdict_reject_with_companion() -> None:
    companions = {
        "reject-with": _opt(
            "reject-with", "icmp-port-unreachable", module="REJECT"
        )
    }
    result = build_verdict(
        "ip", "filter", "jump", "REJECT", companions
    ).to_text()
    assert result == "reject with icmp type port-unreachable"
    companions6 = {
        "reject-with": _opt(
            "reject-with", "icmp6-port-unreachable", module="REJECT"
        )
    }
    result6 = build_verdict(
        "ip6", "filter", "jump", "REJECT", companions6
    ).to_text()
    assert result6 == "reject with icmpv6 type port-unreachable"
    assert (
        build_verdict("ip", "filter", "jump", "REJECT", {}).to_text()
        == "reject"
    )


def test_build_verdict_nat_and_log() -> None:
    snat = {
        "to-source": _opt(
            "to-source", Multi(values=["1.2.3.4"]), module="SNAT"
        )
    }
    assert (
        build_verdict("ip", "nat", "jump", "SNAT", snat).to_text()
        == "snat to 1.2.3.4"
    )
    dnat = {
        "to-destination": _opt(
            "to-destination", Multi(values=["10.0.0.5"]), module="DNAT"
        )
    }
    assert (
        build_verdict("ip", "nat", "jump", "DNAT", dnat).to_text()
        == "dnat to 10.0.0.5"
    )
    log = {"log-prefix": _opt("log-prefix", "DROP: ", module="LOG")}
    assert (
        build_verdict("ip", "filter", "jump", "LOG", log).to_text()
        == 'log prefix "DROP: "'
    )
    assert build_verdict("ip", "filter", "jump", "LOG", {}).to_text() == "log"


def test_build_verdict_uncovered_target_is_error() -> None:
    with pytest.raises(
        FermError, match=r"^SNAT target not yet supported by nft backend$"
    ):
        build_verdict("ip", "nat", "jump", "SNAT", {})
    with pytest.raises(
        FermError, match=r"^DNAT target not yet supported by nft backend$"
    ):
        build_verdict("ip", "nat", "jump", "DNAT", {})


def test_build_verdict_unsupported_reject_with_is_error() -> None:
    comp = {
        "reject-with": _opt("reject-with", "bogus-reject", module="REJECT")
    }
    with pytest.raises(
        FermError,
        match=r"^reject-with 'bogus-reject' not yet supported by nft "
        r"backend$",
    ):
        build_verdict("ip", "filter", "jump", "REJECT", comp)


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
    domain: str, scalar: str, expected: str
) -> None:
    assert _reject_for(domain, scalar) == expected


def test_build_verdict_jump_to_builtin_is_error() -> None:
    with pytest.raises(FermError, match="built-in chain 'INPUT'"):
        build_verdict("ip", "filter", "jump", "INPUT", {})


def test_build_verdict_masquerade_to_ports() -> None:
    comp = {
        "to-ports": _opt(
            "to-ports", Multi(values=["1024-2048"]), module="MASQUERADE"
        )
    }
    assert (
        build_verdict(
            "ip", "nat", "jump", "MASQUERADE", comp, has_transport=True
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
        build_verdict("ip", "nat", "jump", "MASQUERADE", masq)
    redir = {
        "to-ports": _opt("to-ports", Multi(values=["8080"]), module="REDIRECT")
    }
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        build_verdict("ip", "nat", "jump", "REDIRECT", redir)
    snat = {
        "to-source": _opt(
            "to-source", Multi(values=["1.2.3.4:1024"]), module="SNAT"
        )
    }
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        build_verdict("ip", "nat", "jump", "SNAT", snat)
    dnat = {
        "to-destination": _opt(
            "to-destination", Multi(values=["10.0.0.1:8080"]), module="DNAT"
        )
    }
    with pytest.raises(FermError, match="needs a tcp/udp protocol"):
        build_verdict("ip", "nat", "jump", "DNAT", dnat)


def test_build_verdict_port_nat_with_transport_renders() -> None:
    # With a transport match established the port mapping is valid nft.
    redir = {
        "to-ports": _opt("to-ports", Multi(values=["8080"]), module="REDIRECT")
    }
    assert (
        build_verdict(
            "ip", "nat", "jump", "REDIRECT", redir, has_transport=True
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
            "ip", "nat", "jump", "DNAT", dnat, has_transport=True
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
        build_verdict("ip", "nat", "jump", "SNAT", snat).to_text()
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
        build_verdict("ip6", "nat", "jump", "DNAT", plain).to_text()
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
        build_verdict("ip6", "nat", "jump", "SNAT", plain).to_text()
        == "snat to fe80::1"
    )


def test_nat_has_port_is_family_aware() -> None:
    # IPv4: any `:` is the port separator.  IPv6: the host's own colons do
    # not count -- only a bracketed `]:port` does (decision C1).  The
    # bracketed form is unreachable through build_verdict (the `[`/`]` fail
    # address validation first), so this pins the discriminator directly.
    from pyferm.backend.nft import _nat_has_port

    assert _nat_has_port("ip", "1.2.3.4:1024") is True
    assert _nat_has_port("ip", "1.2.3.4") is False
    assert _nat_has_port("ip6", "fe80::1") is False
    assert _nat_has_port("ip6", "[fe80::1]:80") is True


def test_build_verdict_ip6_reject_accepts_ip4_spelling() -> None:
    comp = {
        "reject-with": _opt(
            "reject-with", "icmp-port-unreachable", module="REJECT"
        )
    }
    assert (
        build_verdict("ip6", "filter", "jump", "REJECT", comp).to_text()
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
        build_verdict("ip", "filter", "jump", "LOG", log_drop).to_text()
        == 'log prefix "drop"'
    )
    # Bare number "22" -- also matches the bare-word regex.
    log_num = {"log-prefix": _opt("log-prefix", "22", module="LOG")}
    assert (
        build_verdict("ip", "filter", "jump", "LOG", log_num).to_text()
        == 'log prefix "22"'
    )
    # Space-containing prefix was already quoted; confirm it still is.
    log_space = {"log-prefix": _opt("log-prefix", "drop: ", module="LOG")}
    assert (
        build_verdict("ip", "filter", "jump", "LOG", log_space).to_text()
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
    return _opt("jump", value, kind="target")


def test_translate_rule_skips_match_module_marker() -> None:
    nft = translate_rule(
        "ip",
        "filter",
        _rule(
            _opt("match", "state", kind="match_module"),
            _opt("state", "ESTABLISHED,RELATED", module="state"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "ct state established,related",
        "accept",
    ]


def test_translate_rule_port_suppresses_redundant_proto() -> None:
    nft = translate_rule(
        "ip",
        "filter",
        _rule(
            _opt("protocol", "tcp", kind="proto"),
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


def test_translate_rule_bare_proto_emits_l4proto() -> None:
    nft = translate_rule(
        "ip",
        "filter",
        _rule(
            _opt("protocol", "icmp", kind="proto"),
            _target("DROP"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == [
        "meta l4proto icmp",
        "drop",
    ]


def test_translate_rule_ip6_icmp_normalized() -> None:
    nft = translate_rule(
        "ip6",
        "filter",
        _rule(
            _opt("protocol", "icmp", kind="proto"),
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

    assert _nft_l4proto("ip6", "icmp") == "ipv6-icmp"
    assert _nft_l4proto("ip6", "icmpv6") == "ipv6-icmp"
    assert _nft_l4proto("ip6", "ipv6-icmp") == "ipv6-icmp"


def test_nft_l4proto_ip4_and_other_protos_pass_through() -> None:
    # The rewrite is ip6-only: ip4 keeps the raw `icmp`, and any non-ICMP
    # protocol is returned verbatim regardless of family.
    from pyferm.backend.nft import _nft_l4proto

    assert _nft_l4proto("ip", "icmp") == "icmp"
    assert _nft_l4proto("ip6", "tcp") == "tcp"


def test_translate_rule_protocol_injection_is_error() -> None:
    # finding S1 (CRITICAL): a protocol operand carrying whitespace/`;`/`#`
    # would break out of `meta l4proto <value>` and flip a DROP into accept;
    # `nft -c` does not catch the `;#` form, so the ferm side must reject it.
    with pytest.raises(FermError, match="invalid protocol"):
        translate_rule(
            "ip",
            "filter",
            _rule(
                _opt("protocol", "tcp accept;#", kind="proto"),
                _target("DROP"),
            ),
        )
    # The same value must be rejected on the port-context path (a port match
    # pins the protocol scalar too), not only the `meta l4proto` emission.
    with pytest.raises(FermError, match="invalid protocol"):
        translate_rule(
            "ip",
            "filter",
            _rule(
                _opt("protocol", "tcp accept", kind="proto"),
                _opt("dport", "22"),
                _target("DROP"),
            ),
        )


def test_translate_rule_legit_protocols_render() -> None:
    # A numeric proto and a hyphenated service name are legitimate and must
    # still render (the S1 guard rejects metacharacters, not these).  A known
    # protocol number folds to the name the kernel stores it as (47 -> gre) so
    # --plan does not show a phantom diff against the readback.
    numeric = translate_rule(
        "ip",
        "filter",
        _rule(
            _opt("protocol", "47", kind="proto"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in numeric.statements] == [
        "meta l4proto gre",
        "accept",
    ]
    named = translate_rule(
        "ip",
        "filter",
        _rule(
            _opt("protocol", "ipv6-icmp", kind="proto"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in named.statements] == [
        "meta l4proto ipv6-icmp",
        "accept",
    ]


def test_translate_rule_reject_with_companion_order() -> None:
    nft = translate_rule(
        "ip",
        "filter",
        _rule(
            _opt("protocol", "tcp", kind="proto"),
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
        "ip",
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
        "ip",
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
        "ip",
        "filter",
        _rule(
            _opt("dport", "22"),
            _opt("protocol", "tcp", kind="proto"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == ["tcp dport 22", "accept"]


def test_translate_rule_goto_user_chain() -> None:
    nft = translate_rule(
        "ip",
        "filter",
        _rule(
            _opt("goto", "mychain", kind="target"),
        ),
    )
    assert [s.to_text() for s in nft.statements] == ["goto mychain"]


# ---------------------------------------------------------------------------
# Additional coverage tests
# ---------------------------------------------------------------------------
from pyferm.backend.nft import build_verdict  # noqa: E402, F811
from pyferm.values import PreNegated  # noqa: E402


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
            "ip", "nat", "jump", "REDIRECT", comp, has_transport=True
        ).to_text()
        == "redirect to :8080"
    )
    assert (
        build_verdict("ip", "nat", "jump", "REDIRECT", {}).to_text()
        == "redirect"
    )


def test_build_verdict_tcp_reset_reject() -> None:
    comp = {"reject-with": _opt("reject-with", "tcp-reset", module="REJECT")}
    assert (
        build_verdict("ip", "filter", "jump", "REJECT", comp).to_text()
        == "reject with tcp reset"
    )


def test_build_verdict_tcp_reset_reject_ip6() -> None:
    # nft renders `tcp reset` family-agnostically; the ip6 family accepts
    # `reject with tcp reset` just like ip4 (closes the _REJECT_WITH_IP6 gap).
    comp = {"reject-with": _opt("reject-with", "tcp-reset", module="REJECT")}
    assert (
        build_verdict("ip6", "filter", "jump", "REJECT", comp).to_text()
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
    rendered = NftBackend().render("ip", info, Options(test=True))
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
    save = NftBackend().render("ip", info, Options(test=True)).save
    assert save is not None
    assert "add rule ip ferm INPUT accept\n" in save
    assert "add rule ip ferm mangle_INPUT drop\n" in save


def test_render_preserve_is_error() -> None:
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    table.preserve_regexes.append(re.compile("foo"))
    with pytest.raises(FermError, match="@preserve not yet supported"):
        NftBackend().render("ip", info, Options(test=True))


# --- commit / capture_previous / rollback ---------------------------------

from pyferm.backend.base import Rendered  # noqa: E402


def test_commit_emits_lines_and_pipes_save() -> None:
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    emitted: list[str] = []
    applied: list[str] = []
    rendered = Rendered(save="add table ip ferm\n")
    NftBackend().commit(
        "ip",
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
        "ip",
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
        "ip",
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
        "ip",
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
        "ip",
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
        "ip",
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
        "ip",
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
        "ip",
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
            "ip",
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
        "ip",
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
    snapshot = NftBackend().shell_snapshot("ip", info)
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
    snapshot = NftBackend().shell_snapshot("eb", info)
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
        NftBackend().render("ip", info, Options(test=True))


# --- Fix 1: capture_previous --test reads the mock FILE (not the path string)


def test_capture_previous_test_mode_reads_mock_file(tmp_path: Path) -> None:
    snap = tmp_path / "prev.nft"
    snap.write_text("table ip ferm {\n}\n", encoding="latin-1")
    info = DomainInfo()
    info.tools = {"nft": "nft"}
    NftBackend().capture_previous(
        "ip",
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
        "ip",
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
            "ip",
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
        build_verdict("ip", "filter", "jump", "FOO accept;#", {})


def test_nft_chain_name_accepts_disambiguated_names() -> None:
    # positive control: valid names must still pass unchanged.
    assert nft_chain_name("filter", "INPUT") == "INPUT"
    assert nft_chain_name("mangle", "mychain") == "mangle_mychain"


# --- Fix 2: address + NAT-target grammar validation ---


def test_translate_match_address_rejects_injection() -> None:
    with pytest.raises(FermError, match="invalid address"):
        translate_match("ip", _opt("source", INJECT), None)


def test_build_verdict_snat_rejects_injection() -> None:
    snat = {
        "to-source": _opt("to-source", Multi(values=[INJECT]), module="SNAT")
    }
    with pytest.raises(FermError, match="invalid address"):
        build_verdict("ip", "nat", "jump", "SNAT", snat)


def test_build_verdict_dnat_rejects_injection() -> None:
    dnat = {
        "to-destination": _opt(
            "to-destination", Multi(values=[INJECT]), module="DNAT"
        )
    }
    with pytest.raises(FermError, match="invalid address"):
        build_verdict("ip", "nat", "jump", "DNAT", dnat)


def test_translate_match_address_accepts_cidr_and_ipv6() -> None:
    # positive control: CIDR / IPv6 / range must not over-reject.
    assert (
        translate_match("ip", _opt("source", "10.0.0.0/24"), None)
        == "ip saddr 10.0.0.0/24"
    )
    assert (
        translate_match("ip6", _opt("destination", "fe80::/64"), None)
        == "ip6 daddr fe80::/64"
    )


# --- Fix 3: port + to-ports grammar validation ---


def test_translate_match_port_rejects_injection() -> None:
    with pytest.raises(FermError, match="invalid port"):
        translate_match("ip", _opt("dport", "22 accept;#"), "tcp")


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
            "ip", "nat", "jump", "MASQUERADE", comp, has_transport=True
        )


def test_translate_match_port_accepts_range() -> None:
    # positive control: a port range must still translate.
    assert (
        translate_match("ip", _opt("dport", "1024-2048"), "tcp")
        == "tcp dport 1024-2048"
    )


# --- Fix 4: interface quoting (quoted-string context) ---


def test_translate_match_iface_rejects_embedded_quote() -> None:
    # nft has no escape for a literal `"`; the old `\"` escape let the value
    # break out of its token and flip the verdict (DROP->accept).  The value
    # must now be rejected, not emitted (review 2026-06-14).
    opt = _opt("in-interface", 'eth0" accept;#')
    with pytest.raises(FermError, match="cannot quote"):
        translate_match("ip", opt, None)


def test_translate_match_iface_preserves_wildcard() -> None:
    # positive control: nft string wildcard `*` must still pass.
    assert (
        translate_match("ip", _opt("in-interface", "eth*"), None)
        == 'iifname "eth*"'
    )


# --- Fix 5: state vocabulary + limit-rate validation ---


def test_translate_match_state_rejects_unknown_keyword() -> None:
    with pytest.raises(FermError, match="state"):
        translate_match("ip", _opt("state", "BOGUS", module="state"), None)


def test_translate_match_state_negated_multivalue_is_valid() -> None:
    # COR-2: negated comma-state is valid nft (anonymous-set negation).
    assert (
        translate_match(
            "ip",
            _opt("state", Negated("ESTABLISHED,RELATED"), module="state"),
            None,
        )
        == "ct state != established,related"
    )


def test_translate_match_limit_rejects_injection() -> None:
    with pytest.raises(FermError, match="invalid rate"):
        translate_match(
            "ip", _opt("limit", "3/second;drop", module="limit"), None
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
        ("ssh:http", "ssh-http"),
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
        translate_match("ip", _opt("dport", "60000:61000"), "tcp")
        == "tcp dport 60000-61000"
    )


def test_translate_match_dport_negated_colon_range() -> None:
    assert (
        translate_match("ip", _opt("dport", Negated("1000:2000")), "tcp")
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
    assert "flush table ip ferm" in proc.stdout  # legacy full reload


def test_commit_first_run_falls_back_to_full_reload(tmp_path: Path) -> None:
    # no mock-previous -> previous is None -> needs_full_reload -> full reload
    out = _run_apply(tmp_path, _FERM, None)
    assert "flush table ip ferm" in out


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
    assert "flush table ip ferm" in out  # full reload, not a delta


# ---------------------------------------------------------------------------
# translate_rule: empty named-set invariant
# ---------------------------------------------------------------------------
from pyferm.values import SetRef  # noqa: E402


def test_translate_rule_rejects_empty_named_set() -> None:
    # The caller drops empty-set rules (a v4-only set on the ip6 pass);
    # if one slips through, that is a broken contract, not a silent emit.
    rule = RenderedRule(
        options=[RenderedOption("daddr", SetRef("x", []), "option", None)],
        script=None,
    )
    with pytest.raises(FermError, match="internal error"):
        translate_rule("ip6", "filter", rule)
