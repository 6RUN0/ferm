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
    out = serialize_table(table, chains, rules, noflush=False)
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
    out = serialize_table(table, chains, {"c": []}, noflush=True)
    assert "flush table" not in out
    assert out.startswith("add table ip ferm\nadd chain ip ferm c\n")


def test_render_comment_rejects_over_limit() -> None:
    assert render_comment("ok") == 'comment "ok"'
    assert render_comment("two words") == 'comment "two words"'
    with pytest.raises(FermError, match="exceeds nft limit"):
        render_comment("x" * 129)


# ---------------------------------------------------------------------------
# Task 5: nft_family + map_base_chain
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
# Task 6: build_chains + nft_chain_name
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
# Task 7: unwrap_value + first_scalar
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
# Task 8: translate_match
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
# Task 9: build_verdict
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
# Task 10: translate_rule
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
    # still render (the S1 guard rejects metacharacters, not these).
    numeric = translate_rule(
        "ip",
        "filter",
        _rule(
            _opt("protocol", "47", kind="proto"),
            _target("ACCEPT"),
        ),
    )
    assert [s.to_text() for s in numeric.statements] == [
        "meta l4proto 47",
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


# --- Task 13: NftBackend.render --------------------------------------------

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


# --- Task 14: commit / capture_previous / rollback -------------------------

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
