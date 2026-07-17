"""
Exact refusal-message pins for the discrete nft backend helpers.

The vocabulary suites already exercise these refusal branches through the
CLI (``run_pyferm``), but a subprocess child imports the unmutated venv
install, so a mutation sweep cannot kill a message mutant that way -- and
the in-process mirrors that do exist match the message as an unanchored
substring, which an ``XX``-wrapped or upper-cased mutant still satisfies.
Each test here calls the helper directly and asserts the whole message
anchored (``^...$``), so the ``None`` / ``XX``-wrap / upper-case string
mutants all fall.
"""

from __future__ import annotations

import re

import pytest

from pyferm.backend.nft import _translate_match_parts, translate_rule
from pyferm.backend.nft.matches import (
    _ct_expiration_operand,
    _ipv4options_matches,
    _ipv6header_matches,
    _mark_value,
    _masked_mark_expr,
    _osf_match,
    _policy_match,
    _rpfilter_match,
    _socket_matches,
)
from pyferm.backend.nft.stateful import (
    _connbytes_range,
    _datetime_iso,
    _nth_match,
)
from pyferm.backend.nft.verdicts import (
    _CT_HELPER_PROTO,
    _ct_helper_object,
    _hmark_field,
    _hmark_verdict,
    _netmap_network,
    _nfqueue_verdict,
    _secmark_statement,
    _set_target_operand,
    _set_target_statement,
    _setmark_effective,
    build_verdict,
)
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.values import Negated, Params, SetRef
from tests.unit._nftrule import _opt, _rule


def _exact(message: str) -> str:
    """Anchor an exact expected message for ``pytest.raises(match=...)``."""
    return f"^{re.escape(message)}$"


# ---------------------------------------------------------------------------
# mod ipv4options
# ---------------------------------------------------------------------------


def test_ipv4options_ip_only_message() -> None:
    """The family guard names ipv4options as ip-only."""
    with pytest.raises(
        FermError,
        match=_exact("mod ipv4options is ip-only for the nft backend"),
    ):
        _ipv4options_matches(Family.IP6, {})


def test_ipv4options_any_refusal_message() -> None:
    """The ``any`` sibling ORs the flags, which one nft rule cannot spell."""
    with pytest.raises(
        FermError,
        match=_exact(
            "ipv4options 'any' ORs the option flags; nft cannot OR "
            "header-option presence in one rule"
        ),
    ):
        _ipv4options_matches(Family.IP, {"any": _opt("any", None)})


def test_ipv4options_needs_flags_message() -> None:
    """A bare ipv4options load with no ``flags`` refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("mod ipv4options needs 'flags' for the nft backend"),
    ):
        _ipv4options_matches(Family.IP, {})


def test_ipv4options_negated_list_message() -> None:
    """A negated multi-member flag list has no infix nft form."""
    with pytest.raises(
        FermError,
        match=_exact(
            "negated ipv4options flag list (misses at least one) cannot "
            "be expressed as infix nft matches"
        ),
    ):
        _ipv4options_matches(
            Family.IP, {"flags": _opt("flags", Negated("lsrr,rr"))}
        )


# ---------------------------------------------------------------------------
# mod ipv6header
# ---------------------------------------------------------------------------


def test_ipv6header_ip6_only_message() -> None:
    """The family guard names ipv6header as ip6-only."""
    with pytest.raises(
        FermError,
        match=_exact("mod ipv6header is ip6-only for the nft backend"),
    ):
        _ipv6header_matches(Family.IP, {})


def test_ipv6header_needs_header_message() -> None:
    """A bare ipv6header load with no ``header`` refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("mod ipv6header needs 'header' for the nft backend"),
    ):
        _ipv6header_matches(Family.IP6, {})


def test_ipv6header_without_soft_message() -> None:
    """Without ``soft`` the exact-set semantics have no nft exthdr form."""
    with pytest.raises(
        FermError,
        match=_exact(
            "mod ipv6header without 'soft' matches the exact header set; "
            "nft exthdr cannot express it"
        ),
    ):
        _ipv6header_matches(Family.IP6, {"header": _opt("header", "frag")})


def test_ipv6header_negated_list_message() -> None:
    """A negated multi-member header list has no infix nft form."""
    with pytest.raises(
        FermError,
        match=_exact(
            "negated ipv6header header list (misses at least one) cannot "
            "be expressed as infix nft matches"
        ),
    ):
        _ipv6header_matches(
            Family.IP6,
            {
                "header": _opt("header", Negated("frag,mh")),
                "soft": _opt("soft", None),
            },
        )


# ---------------------------------------------------------------------------
# mod osf
# ---------------------------------------------------------------------------


def test_osf_ip_only_message() -> None:
    """The family guard names osf as ip-only."""
    with pytest.raises(
        FermError,
        match=_exact("mod osf is ip-only for the nft backend"),
    ):
        _osf_match(Family.IP6, {})


def test_osf_log_refusal_message() -> None:
    """xt_osf's kernel logging has no nft osf equivalent."""
    with pytest.raises(
        FermError,
        match=_exact(
            "mod osf option 'log' has no nft equivalent "
            "(nft osf does not log fingerprint matches)"
        ),
    ):
        _osf_match(Family.IP, {"log": _opt("log", None)})


def test_osf_needs_genre_message() -> None:
    """A bare osf load with no ``genre`` refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("mod osf needs 'genre' for the nft backend"),
    ):
        _osf_match(Family.IP, {})


def test_osf_ttl_negation_message() -> None:
    """A negated ``ttl`` selector has no nft osf form."""
    with pytest.raises(
        FermError,
        match=_exact("mod osf 'ttl' cannot be negated for the nft backend"),
    ):
        _osf_match(
            Family.IP,
            {
                "genre": _opt("genre", "Linux"),
                "ttl": _opt("ttl", Negated("1")),
            },
        )


# ---------------------------------------------------------------------------
# mod policy
# ---------------------------------------------------------------------------


def test_policy_needs_dir_and_pol_message() -> None:
    """A policy match missing both ``dir`` and ``pol`` refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact(
            "mod policy needs both 'dir' and 'pol' for the nft backend"
        ),
    ):
        _policy_match({})


def test_policy_invalid_pol_message() -> None:
    """An unknown ``pol`` value refuses naming the operand."""
    with pytest.raises(
        FermError,
        match=_exact("invalid policy pol 'bogus' for nft backend"),
    ):
        _policy_match({"dir": _opt("dir", "in"), "pol": _opt("pol", "bogus")})


# ---------------------------------------------------------------------------
# mod rpfilter / mod socket
# ---------------------------------------------------------------------------


def test_rpfilter_family_message() -> None:
    """rpfilter is ip/ip6-only; another family refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("mod rpfilter is ip/ip6-only for the nft backend"),
    ):
        _rpfilter_match(Family.ARP, frozenset())


def test_rpfilter_accept_local_message() -> None:
    """``accept-local`` ORs a condition one fib match cannot spell."""
    with pytest.raises(
        FermError,
        match=_exact(
            "rpfilter 'accept-local' ORs a second local-source condition; "
            "nft cannot express it in one fib match"
        ),
    ):
        _rpfilter_match(Family.IP, frozenset({"accept-local"}))


def test_socket_family_message() -> None:
    """socket is ip/ip6-only; another family refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("mod socket is ip/ip6-only for the nft backend"),
    ):
        _socket_matches(Family.ARP, frozenset())


def test_socket_restore_skmark_no_longer_refuses() -> None:
    """
    ``restore-skmark`` translates now: no refusal, and the flag does not
    shape the matches (the mark-restore statement is injected later by
    ``translate_rule``, pinned in test_backend_nft_arp_socket.py).
    """
    matches = _socket_matches(Family.IP, frozenset({"restore-skmark"}))
    assert [m.to_text() for m in matches] == ["socket wildcard 0"]


# ---------------------------------------------------------------------------
# CT helper / SECMARK / SET target objects
# ---------------------------------------------------------------------------


def test_ct_helper_negation_message() -> None:
    """A negated ``helper`` name has no nft ct-helper object."""
    with pytest.raises(
        FermError,
        match=_exact("CT 'helper' cannot be negated for the nft backend"),
    ):
        _ct_helper_object(_opt("helper", Negated("ftp")))


def test_ct_helper_empty_name_message() -> None:
    """An empty ``helper`` name refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact(
            "CT target option 'helper' needs a helper name for the nft backend"
        ),
    ):
        _ct_helper_object(_opt("helper", ""))


def test_ct_helper_unsupported_proto_message() -> None:
    """A helper with no single-protocol object lists the supported set."""
    supported = ", ".join(sorted(_CT_HELPER_PROTO))
    with pytest.raises(
        FermError,
        match=_exact(
            f"CT helper 'nosuch' has no single-protocol nft ct-helper object "
            f"(supported: {supported}); use the iptables backend for this rule"
        ),
    ):
        _ct_helper_object(_opt("helper", "nosuch"))


def test_secmark_needs_selctx_message() -> None:
    """A SECMARK target missing ``selctx`` refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("SECMARK target needs 'selctx' for the nft backend"),
    ):
        _secmark_statement({})


def test_secmark_empty_selctx_message() -> None:
    """An empty ``selctx`` context refuses rather than emit ``{ "" }``."""
    with pytest.raises(
        FermError,
        match=_exact("SECMARK 'selctx' must be a non-empty security context"),
    ):
        _secmark_statement({"selctx": _opt("selctx", "")})


def test_set_target_external_ipset_message() -> None:
    """A bare (non-@set) SET target name is an external ipset and refuses."""
    with pytest.raises(
        FermError,
        match=_exact(
            "option 'add-set': external ipset 'blocklist' cannot be "
            "referenced from nftables; declare it with @set $blocklist = "
            "() or keep the iptables backend"
        ),
    ):
        _set_target_operand(_opt("add-set", Params(["blocklist", "src"])))


def test_set_target_multi_flag_message() -> None:
    """A comma-joined multi-flag SET target has no @set concatenated type."""
    with pytest.raises(
        FermError,
        match=_exact(
            "option 'add-set': multiple SET target flags need a "
            "concatenated set type that @set does not declare"
        ),
    ):
        _set_target_operand(
            _opt("add-set", Params([SetRef("x", []), "src,dst"]))
        )


def test_set_target_statement_needs_verb_message() -> None:
    """A SET target with neither add-set nor del-set refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact(
            "SET target needs 'add-set' or 'del-set' for the nft backend"
        ),
    ):
        _set_target_statement(Family.IP, {})


# ---------------------------------------------------------------------------
# HMARK / NETMAP / NFQUEUE / AUDIT verdicts
# ---------------------------------------------------------------------------


def test_hmark_field_no_equivalent_message() -> None:
    """A tuple field with no jhash selector refuses naming the field."""
    with pytest.raises(
        FermError,
        match=_exact(
            "HMARK tuple field 'spi' has no nft jhash equivalent for the "
            "nft backend"
        ),
    ):
        _hmark_field(Family.IP, "spi")


def test_hmark_masked_field_message() -> None:
    """A per-field mask has no faithful nft jhash form."""
    with pytest.raises(
        FermError,
        match=_exact(
            "HMARK 'hmark-src-prefix' has no nft jhash equivalent (jhash "
            "hashes fields whole) for the nft backend"
        ),
    ):
        _hmark_verdict(
            Family.IP, {"hmark-src-prefix": _opt("hmark-src-prefix", "24")}
        )


def test_hmark_needs_mandatory_options_message() -> None:
    """HMARK requires tuple, mod, and rnd together."""
    with pytest.raises(
        FermError,
        match=_exact(
            "HMARK needs 'hmark-tuple', 'hmark-mod', and 'hmark-rnd' for "
            "the nft backend"
        ),
    ):
        _hmark_verdict(Family.IP, {})


def test_netmap_network_needs_prefix_length_message() -> None:
    """A NETMAP operand without a prefix length refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact(
            "NETMAP prefix '10.0.0.0' needs an explicit prefix length "
            "for the nft backend"
        ),
    ):
        _netmap_network("10.0.0.0", Family.IP)


def test_nfqueue_cpu_fanout_needs_balance_message() -> None:
    """``queue-cpu-fanout`` without ``queue-balance`` refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact(
            "option 'queue-cpu-fanout' needs 'queue-balance' for the "
            "nft backend"
        ),
    ):
        _nfqueue_verdict({"queue-cpu-fanout": _opt("queue-cpu-fanout", None)})


def test_build_verdict_audit_needs_type_message() -> None:
    """An AUDIT target missing ``type`` refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("AUDIT needs 'type' for the nft backend"),
    ):
        build_verdict(Family.IP, "filter", "jump", "AUDIT", {})


def test_build_verdict_builtin_chain_jump_message() -> None:
    """
    A jump to a built-in chain of the same table refuses naming it.

    The refusal reads the ``table`` to decide the target is a built-in
    chain, so it must carry the real table, not a placeholder.
    """
    with pytest.raises(
        FermError,
        match=_exact(
            "jump/goto to built-in chain 'INPUT' not yet supported by "
            "nft backend"
        ),
    ):
        build_verdict(Family.IP, "filter", "jump", "INPUT", {})


# ---------------------------------------------------------------------------
# mod nth / date / connbytes / mark canon
# ---------------------------------------------------------------------------


def test_nth_needs_every_message() -> None:
    """A bare nth match with no ``every`` refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("mod nth needs 'every' for the nft backend"),
    ):
        _nth_match({})


def test_nth_nonzero_counter_message() -> None:
    """A non-zero ``counter`` has no numgen analogue."""
    with pytest.raises(
        FermError,
        match=_exact(
            "mod nth 'counter' has no numgen equivalent for the nft backend"
        ),
    ):
        _nth_match(
            {"every": _opt("every", "3"), "counter": _opt("counter", "5")}
        )


def test_datetime_iso_invalid_message() -> None:
    """A non-ISO date operand refuses naming the operand."""
    with pytest.raises(
        FermError,
        match=_exact("invalid date 'nonsense' for nft backend"),
    ):
        _datetime_iso("nonsense")


def test_datetime_iso_invalid_time_message() -> None:
    """
    A valid date with an unparsable clock refuses naming the operand.

    This reaches the second date guard (past the ``T`` split), distinct
    from the bare-date branch above.
    """
    with pytest.raises(
        FermError,
        match=_exact("invalid date '2020-01-01Tbadtime' for nft backend"),
    ):
        _datetime_iso("2020-01-01Tbadtime")


def test_connbytes_range_lo_gt_hi_message() -> None:
    """A connbytes range with lo > hi refuses naming the operand."""
    with pytest.raises(
        FermError,
        match=_exact("connbytes range '5:3' has lo > hi for the nft backend"),
    ):
        _connbytes_range("connbytes", "5:3", neg=False)


def test_connbytes_range_empty_message() -> None:
    """A bare ``:`` connbytes range is invalid and refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("invalid connbytes range ':' for the nft backend"),
    ):
        _connbytes_range("connbytes", ":", neg=False)


def test_mark_value_masked_refusal_message() -> None:
    """A partial-mask mark match operand refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("masked mark '0x1/0x2' not yet supported by nft backend"),
    ):
        _mark_value("0x1/0x2")


def test_mark_value_invalid_message() -> None:
    """A non-numeric mark operand refuses naming the operand."""
    with pytest.raises(
        FermError,
        match=_exact("invalid mark 'notanumber' for nft backend"),
    ):
        _mark_value("notanumber")


def test_masked_mark_expr_invalid_message() -> None:
    """A malformed masked mark operand refuses naming the operand."""
    with pytest.raises(
        FermError,
        match=_exact("invalid mark '0x1/zzz' for nft backend"),
    ):
        _masked_mark_expr("mark", "0x1/zzz", neg=False)


def test_ct_expiration_invalid_message() -> None:
    """A non-numeric ctexpire operand refuses naming the operand."""
    with pytest.raises(
        FermError,
        match=_exact("invalid ctexpire 'bogus' for nft backend"),
    ):
        _ct_expiration_operand("bogus")


def test_ct_expiration_half_open_range_message() -> None:
    """
    A half-open ``N:`` ctexpire range refuses (both bounds required).

    Reaching the raise needs the range guard to require ``sep`` AND both
    bounds numeric; a slackened guard would return ``5s-s`` instead.
    """
    with pytest.raises(
        FermError,
        match=_exact("invalid ctexpire '5:' for nft backend"),
    ):
        _ct_expiration_operand("5:")


def test_setmark_effective_invalid_message() -> None:
    """A malformed set-mark operand refuses naming the operand."""
    with pytest.raises(
        FermError,
        match=_exact("invalid set-mark '0x1/zzz' for nft backend"),
    ):
        _setmark_effective("0x1/zzz")


# ---------------------------------------------------------------------------
# per-match refusals reached through _translate_match_parts
# ---------------------------------------------------------------------------


def test_translate_connlabel_set_message() -> None:
    """connlabel ``set`` (label-on-match) has no nft match equivalent."""
    with pytest.raises(
        FermError,
        match=_exact(
            "connlabel 'set' (add the label on match) has no nft match "
            "equivalent"
        ),
    ):
        _translate_match_parts(
            Family.IP, _opt("set", None, module="connlabel"), None
        )


def test_translate_invalid_mac_message() -> None:
    """A malformed source/destination MAC operand refuses naming it."""
    with pytest.raises(
        FermError,
        match=_exact("invalid mac 'zz:zz:zz:zz:zz:zz' for nft backend"),
    ):
        _translate_match_parts(
            Family.IP, _opt("source-mac", "zz:zz:zz:zz:zz:zz"), None
        )


def test_translate_mss_needs_tcp_message() -> None:
    """An ``mss`` match without a tcp protocol refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact("option 'mss' needs a tcp protocol for the nft backend"),
    ):
        _translate_match_parts(
            Family.IP, _opt("mss", "1400", module="tcpmss"), "udp"
        )


def test_translate_tcp_option_needs_tcp_message() -> None:
    """A ``tcp-option`` match without a tcp protocol refuses by name."""
    with pytest.raises(
        FermError,
        match=_exact(
            "option 'tcp-option' needs a tcp protocol for the nft backend"
        ),
    ):
        _translate_match_parts(
            Family.IP, _opt("tcp-option", "4", module="tcp"), "udp"
        )


# ---------------------------------------------------------------------------
# rule-wide refusals reached through translate_rule
# ---------------------------------------------------------------------------


def test_translate_rule_two_named_sets_message() -> None:
    """Two SetRef options on one rule refuse (one named set per rule)."""
    with pytest.raises(
        FermError,
        match=_exact("at most one named set per rule in this version"),
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("source", SetRef("a", ["10.0.0.1"])),
                _opt("destination", SetRef("b", ["10.0.0.2"])),
            ),
        )


def test_translate_rule_two_limit_bursts_message() -> None:
    """Two ``limit-burst`` options cannot be paired to one limit match."""
    with pytest.raises(
        FermError,
        match=_exact(
            "more than one 'limit-burst' per rule cannot be paired for "
            "the nft backend"
        ),
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("limit-burst", "5", module="limit"),
                _opt("limit-burst", "6", module="limit"),
            ),
        )


def test_translate_rule_burst_with_two_limits_message() -> None:
    """A ``limit-burst`` with several ``limit`` matches cannot be paired."""
    with pytest.raises(
        FermError,
        match=_exact(
            "'limit-burst' with more than one 'limit' per rule cannot "
            "be paired for the nft backend"
        ),
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("limit-burst", "5", module="limit"),
                _opt("limit", "1/sec", module="limit"),
                _opt("limit", "2/sec", module="limit"),
            ),
        )


def test_translate_rule_limit_iface_mutually_exclusive_message() -> None:
    """``limit-iface-in`` and ``limit-iface-out`` are mutually exclusive."""
    with pytest.raises(
        FermError,
        match=_exact(
            "'limit-iface-in' and 'limit-iface-out' are mutually "
            "exclusive for the nft backend"
        ),
    ):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _opt("limit", "1/sec", module="limit"),
                _opt("limit-iface-in", None, module="limit"),
                _opt("limit-iface-out", None, module="limit"),
            ),
        )
