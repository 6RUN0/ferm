"""
Unit matrix for the nft *match* vocabulary.

Covers the simple meta/ct selectors, the rule-wide modules (policy /
ipv6header / ipv4options / rpfilter / socket), the implied-l4proto matches,
and the ``helper`` / ``nth`` matches.  Every emitted spelling below was
captured from a live ``nft list ruleset`` readback (nft v1.1.6) -- the
emission MUST equal the readback or ``--plan`` diffs an applied ruleset
forever.  The refusal tests pin the fail-open guards the dichotomy gate
cannot see (it accepts any non-empty translation, so a semantically widened
match would pass it).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.backend.nft import (
    _translate_match_parts,
    translate_match,
    translate_rule,
)
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.scope import OptionKind
from pyferm.values import Negated
from tests.unit._nftrule import _opt, _rule, _target

if TYPE_CHECKING:
    from pyferm.rules import RenderedOption


def _marker(module: str) -> RenderedOption:
    return _opt("match", module, kind=OptionKind.MATCH_MODULE)


def _texts(rule_options: list[RenderedOption], domain: Family) -> list[str]:
    nft = translate_rule(domain, "filter", _rule(*rule_options))
    return [s.to_text() for s in nft.statements]


# -- simple meta / ct selectors (positive + negated matrix) -------------


@pytest.mark.parametrize(
    ("domain", "option", "protocol", "expected"),
    [
        (Family.IP, _opt("cpu", "0", module="cpu"), None, "meta cpu 0"),
        (
            Family.IP,
            _opt("cpu", Negated("2"), module="cpu"),
            None,
            "meta cpu != 2",
        ),
        (
            Family.IP,
            _opt("src-group", "5", module="devgroup"),
            None,
            "iifgroup 5",
        ),
        (
            Family.IP,
            _opt("dst-group", Negated("0x10"), module="devgroup"),
            None,
            "oifgroup != 16",
        ),
        (
            Family.IP,
            _opt("realm", "42", module="realm"),
            None,
            "meta rtclassid 42",
        ),
        (
            Family.IP,
            _opt("realm", Negated("99"), module="realm"),
            None,
            "meta rtclassid != 99",
        ),
        (
            Family.IP,
            _opt("cgroup", "1048577", module="cgroup"),
            None,
            "meta cgroup 1048577",
        ),
        (
            Family.IP,
            _opt("cgroup", Negated("7"), module="cgroup"),
            None,
            "meta cgroup != 7",
        ),
        (
            Family.IP,
            _opt("ctorigsrc", "192.0.2.1", module="conntrack"),
            None,
            "ct original ip saddr 192.0.2.1",
        ),
        (
            Family.IP,
            _opt("ctorigdst", Negated("198.51.100.0/24"), module="conntrack"),
            None,
            "ct original ip daddr != 198.51.100.0/24",
        ),
        (
            Family.IP6,
            _opt("ctreplsrc", "2001:db8::1", module="conntrack"),
            None,
            "ct reply ip6 saddr 2001:db8::1",
        ),
        (
            Family.IP,
            _opt("ctrepldst", "192.0.2.9", module="conntrack"),
            None,
            "ct reply ip daddr 192.0.2.9",
        ),
        (
            Family.IP,
            _opt("ctorigsrcport", "80:90", module="conntrack"),
            None,
            "ct original proto-src 80-90",
        ),
        (
            Family.IP,
            _opt("ctorigdstport", Negated("443"), module="conntrack"),
            None,
            "ct original proto-dst != 443",
        ),
        (
            Family.IP,
            _opt("ctreplsrcport", "53", module="conntrack"),
            None,
            "ct reply proto-src 53",
        ),
        (
            Family.IP,
            _opt("ctrepldstport", "1024:2048", module="conntrack"),
            None,
            "ct reply proto-dst 1024-2048",
        ),
        # the readback drops the direction and respells 6 -> tcp
        (
            Family.IP,
            _opt("ctproto", "tcp", module="conntrack"),
            None,
            "ct protocol tcp",
        ),
        (
            Family.IP,
            _opt("ctproto", Negated("6"), module="conntrack"),
            None,
            "ct protocol != tcp",
        ),
        (
            Family.IP,
            _opt("ctproto", "99", module="conntrack"),
            None,
            "ct protocol 99",
        ),
        # `mh` is an nft keyword, so `ct protocol` also needs the
        # mobility-header respelling (readback-verified live)
        (
            Family.IP6,
            _opt("ctproto", "mh", module="conntrack"),
            None,
            "ct protocol mobility-header",
        ),
        # ip6's icmp is proto 58 (ipv6-icmp), not proto 1: the domain MUST
        # reach _nft_l4proto for this rewrite, or the emission would keep
        # the raw `icmp` name and match the wrong protocol number.
        (
            Family.IP6,
            _opt("ctproto", "icmp", module="conntrack"),
            None,
            "ct protocol ipv6-icmp",
        ),
        # scalar decomposes (100 -> 1m40s), a range keeps bare seconds,
        # zero prints 0s -- the asymmetric kernel readback, pinned live
        (
            Family.IP,
            _opt("ctexpire", "100", module="conntrack"),
            None,
            "ct expiration 1m40s",
        ),
        (
            Family.IP,
            _opt("ctexpire", "3600", module="conntrack"),
            None,
            "ct expiration 1h",
        ),
        (
            Family.IP,
            _opt("ctexpire", "3600:7200", module="conntrack"),
            None,
            "ct expiration 3600s-7200s",
        ),
        (
            Family.IP,
            _opt("ctexpire", "0", module="conntrack"),
            None,
            "ct expiration 0s",
        ),
        (
            Family.IP,
            _opt("ctexpire", Negated("100"), module="conntrack"),
            None,
            "ct expiration != 1m40s",
        ),
        (
            Family.IP,
            _opt("ctexpire", Negated("3600:7200"), module="conntrack"),
            None,
            "ct expiration != 3600s-7200s",
        ),
        (
            Family.IP,
            _opt("ctdir", "ORIGINAL", module="conntrack"),
            None,
            "ct direction original",
        ),
        (
            Family.IP,
            _opt("ctdir", "REPLY", module="conntrack"),
            None,
            "ct direction reply",
        ),
        (
            Family.IP,
            _opt("label", "40", module="connlabel"),
            None,
            "ct label 40",
        ),
        # negation must test the single bit: `ct label != 7` would
        # compare the whole 128-bit register and ACCEPT any connection
        # carrying bit 7 plus another label (fail-open)
        (
            Family.IP,
            _opt("label", Negated("7"), module="connlabel"),
            None,
            "ct label & 7 != 7",
        ),
        (
            Family.IP,
            _opt("ahspi", "1:1000", module="ah"),
            "ah",
            "ah spi 1-1000",
        ),
        (
            Family.IP,
            _opt("ahspi", Negated("500"), module="ah"),
            "ah",
            "ah spi != 500",
        ),
        (
            Family.IP6,
            _opt("espspi", "500", module="esp"),
            "esp",
            "esp spi 500",
        ),
        # mh: a scalar respells to the kernel-readback name, a range
        # stays numeric, an unmapped number stays numeric
        (
            Family.IP6,
            _opt("mh-type", "5", module="mh"),
            "mh",
            "mh type binding-update",
        ),
        (
            Family.IP6,
            _opt("mh-type", Negated("2"), module="mh"),
            "mh",
            "mh type != careof-test-init",
        ),
        (
            Family.IP6,
            _opt("mh-type", "2:4", module="mh"),
            "mh",
            "mh type 2-4",
        ),
        (
            Family.IP6,
            _opt("mh-type", "200", module="mh"),
            "mh",
            "mh type 200",
        ),
        (
            Family.IP6,
            _opt("hbh-len", "8", module="hbh"),
            None,
            "hbh hdrlength 8",
        ),
        (
            Family.IP6,
            _opt("dst-len", Negated("8"), module="dst"),
            None,
            "dst hdrlength != 8",
        ),
        (
            Family.IP6,
            _opt("rt-type", "0", module="rt"),
            None,
            "rt type 0",
        ),
        (
            Family.IP6,
            _opt("rt-segsleft", "1:3", module="rt"),
            None,
            "rt seg-left 1-3",
        ),
        (
            Family.IP6,
            _opt("rt-len", "8", module="rt"),
            None,
            "rt hdrlength 8",
        ),
        # dccp types emit deduplicated in ascending packet-type order
        (
            Family.IP,
            _opt("dccp-types", "RESPONSE,REQUEST,REQUEST", module="dccp"),
            "dccp",
            "dccp type { request, response }",
        ),
        (
            Family.IP,
            _opt("dccp-types", "SYNCACK", module="dccp"),
            "dccp",
            "dccp type syncack",
        ),
        (
            Family.IP,
            _opt("dccp-types", Negated("RESET,SYNC"), module="dccp"),
            "dccp",
            "dccp type != { reset, sync }",
        ),
        (
            Family.IP,
            _opt("dccp-types", Negated("SYNCACK"), module="dccp"),
            "dccp",
            "dccp type != syncack",
        ),
        (
            Family.IP,
            _opt("ecn-ip-ect", "0", module="ecn"),
            None,
            "ip ecn not-ect",
        ),
        (
            Family.IP,
            _opt("ecn-ip-ect", "3", module="ecn"),
            None,
            "ip ecn ce",
        ),
        (
            Family.IP6,
            _opt("ecn-ip-ect", "2", module="ecn"),
            None,
            "ip6 ecn ect0",
        ),
        (
            Family.IP,
            _opt("ecn-tcp-cwr", None, module="ecn"),
            "tcp",
            "tcp flags cwr",
        ),
        (
            Family.IP,
            _opt("ecn-tcp-ece", None, module="ecn"),
            "tcp",
            "tcp flags ece",
        ),
        # -- validator boundary sweep: the field maximum loads, the +1
        # refuses (its refusal is in the matrix below).  A device group /
        # realm is 32-bit, spi is 32-bit, an exthdr octet field is 8-bit,
        # a connlabel bit is 0-127, an mh-type / tcp-option kind is 8-bit.
        (
            Family.IP,
            _opt("src-group", "0", module="devgroup"),
            None,
            "iifgroup 0",
        ),
        (
            Family.IP,
            _opt("src-group", "4294967295", module="devgroup"),
            None,
            "iifgroup 4294967295",
        ),
        (
            Family.IP,
            _opt("realm", "0", module="realm"),
            None,
            "meta rtclassid 0",
        ),
        (
            Family.IP,
            _opt("ahspi", "4294967295", module="ah"),
            "ah",
            "ah spi 4294967295",
        ),
        (
            Family.IP,
            _opt("ahspi", "1:4294967295", module="ah"),
            "ah",
            "ah spi 1-4294967295",
        ),
        (
            Family.IP6,
            _opt("hbh-len", "255", module="hbh"),
            None,
            "hbh hdrlength 255",
        ),
        (
            Family.IP6,
            _opt("rt-segsleft", "255", module="rt"),
            None,
            "rt seg-left 255",
        ),
        (
            Family.IP,
            _opt("label", "127", module="connlabel"),
            None,
            "ct label 127",
        ),
        (
            Family.IP6,
            _opt("mh-type", "255", module="mh"),
            "mh",
            "mh type 255",
        ),
        (
            Family.IP,
            _opt("tcp-option", "255", module="tcp"),
            "tcp",
            "tcp option 255 exists",
        ),
        # -- negated operands that reach the shared `_op(neg)` seam: a
        # dropped negation here would flip esp/mh/ecn to the positive
        # match (fail-open), which the dichotomy gate cannot see.
        (
            Family.IP6,
            _opt("espspi", Negated("500"), module="esp"),
            "esp",
            "esp spi != 500",
        ),
        (
            Family.IP6,
            _opt("mh-type", Negated("2:4"), module="mh"),
            "mh",
            "mh type != 2-4",
        ),
        (
            Family.IP,
            _opt("ecn-ip-ect", Negated("3"), module="ecn"),
            None,
            "ip ecn != ce",
        ),
        # -- icmp-type numeric boundary: a whole-octet type / code loads,
        # the +1 refuses (matrix below); an unmapped number stays numeric.
        (
            Family.IP,
            _opt("icmp-type", "255", module="icmp"),
            "icmp",
            "icmp type 255",
        ),
        (
            Family.IP,
            _opt("icmp-type", "255/255", module="icmp"),
            "icmp",
            "icmp type 255 icmp code 255",
        ),
        # -- dccp set order follows the packet-type rank, not the member
        # spelling: `data` (rank 2) precedes `ack` (rank 3) though it
        # sorts after alphabetically -- a dropped sort key would reorder.
        (
            Family.IP,
            _opt("dccp-types", "data,ack", module="dccp"),
            "dccp",
            "dccp type { data, ack }",
        ),
    ],
)
def test_match_module_spellings(
    domain: Family,
    option: RenderedOption,
    protocol: str | None,
    expected: str,
) -> None:
    assert translate_match(domain, option, protocol) == expected


# -- refusals: values with no nft spelling -------------------------------


@pytest.mark.parametrize(
    ("domain", "option", "protocol", "message"),
    [
        (
            Family.IP,
            _opt("src-group", "0x10/0xff", module="devgroup"),
            None,
            "masked src-group",
        ),
        (
            Family.IP,
            _opt("dst-group", "wan", module="devgroup"),
            None,
            "symbolic dst-group",
        ),
        # interface groups are 32-bit
        (
            Family.IP,
            _opt("src-group", "4294967296", module="devgroup"),
            None,
            "invalid src-group",
        ),
        (
            Family.IP,
            _opt("cpu", "fast", module="cpu"),
            None,
            "invalid cpu",
        ),
        (
            Family.IP,
            _opt("cgroup", "top", module="cgroup"),
            None,
            "invalid cgroup classid",
        ),
        (
            Family.IP,
            _opt("realm", "cosmos", module="realm"),
            None,
            "symbolic realm",
        ),
        (
            Family.IP,
            _opt("label", "test", module="connlabel"),
            None,
            "needs a numeric label",
        ),
        (
            Family.IP,
            _opt("label", "128", module="connlabel"),
            None,
            "needs a numeric label",
        ),
        (
            Family.IP,
            _opt("set", None, module="connlabel"),
            None,
            "connlabel 'set'",
        ),
        (
            Family.IP,
            _opt("ctdir", "BOTH", module="conntrack"),
            None,
            "invalid ctdir",
        ),
        (
            Family.IP,
            _opt("ctexpire", "soon", module="conntrack"),
            None,
            "invalid ctexpire",
        ),
        (
            Family.IP,
            _opt("dccp-types", "INVALID", module="dccp"),
            "dccp",
            "no nft equivalent",
        ),
        (
            Family.IP,
            _opt("dccp-types", "REQUEST,BOGUS", module="dccp"),
            "dccp",
            "no nft equivalent",
        ),
        (
            Family.IP,
            _opt("ecn-ip-ect", "4", module="ecn"),
            None,
            "invalid ecn-ip-ect",
        ),
        (
            Family.IP,
            _opt("ecn-tcp-cwr", None, module="ecn"),
            "udp",
            "needs a tcp protocol",
        ),
        # mh type / the exthdr length fields are one octet; ah/esp spi
        # is 32-bit -- scalar AND range operands refuse past the width
        # (nft -c would reject the overflow only at apply time)
        (
            Family.IP6,
            _opt("mh-type", "300", module="mh"),
            "mh",
            "invalid mh-type",
        ),
        (
            Family.IP6,
            _opt("mh-type", "200:9999", module="mh"),
            "mh",
            "invalid mh-type",
        ),
        (
            Family.IP6,
            _opt("rt-segsleft", "1:300", module="rt"),
            None,
            "invalid rt-segsleft",
        ),
        (
            Family.IP,
            _opt("ahspi", "spdy", module="ah"),
            "ah",
            "invalid ahspi",
        ),
        (
            Family.IP,
            _opt("ahspi", "1:4294967296", module="ah"),
            "ah",
            "invalid ahspi",
        ),
        # xt_mh / the exthdr length matches are ip6-only: the ip pass
        # falls through to the generic refusal
        (
            Family.IP,
            _opt("mh-type", "5", module="mh"),
            "mh",
            "not yet supported",
        ),
        (
            Family.IP,
            _opt("hbh-len", "8", module="hbh"),
            None,
            "not yet supported",
        ),
        # IDLETIMER's companion shares the `label` spelling; the
        # connlabel branch is module-qualified, so it must NOT swallow it
        (
            Family.IP,
            _opt("label", "40", module="IDLETIMER"),
            None,
            "option 'label' not yet supported",
        ),
        # -- validator boundary +1: one past the field maximum refuses at
        # translate time (nft -c would only catch it at apply).
        (
            Family.IP6,
            _opt("hbh-len", "256", module="hbh"),
            None,
            "invalid hbh-len",
        ),
        (
            Family.IP6,
            _opt("mh-type", "256", module="mh"),
            "mh",
            "invalid mh-type",
        ),
        (
            Family.IP,
            _opt("tcp-option", "256", module="tcp"),
            "tcp",
            "invalid tcp-option",
        ),
        (
            Family.IP,
            _opt("icmp-type", "256", module="icmp"),
            "icmp",
            "invalid icmp type",
        ),
        (
            Family.IP,
            _opt("icmp-type", "3/256", module="icmp"),
            "icmp",
            "invalid icmp type",
        ),
        # -- a half-open colon range has no nft dash form: both ends must be
        # present numbers, so `1:` and `:2` refuse rather than emit `1-` etc.
        (
            Family.IP,
            _opt("ahspi", "1:", module="ah"),
            "ah",
            "invalid ahspi",
        ),
        (
            Family.IP,
            _opt("ahspi", ":2", module="ah"),
            "ah",
            "invalid ahspi",
        ),
        # -- the cgroup/helper matches are module-qualified: an option
        # spelled `cgroup`/`helper` carried by a different module must NOT
        # be swallowed by their branches (the connlabel/IDLETIMER precedent),
        # it falls through to the generic refusal.
        (
            Family.IP,
            _opt("cgroup", "5", module="realm"),
            None,
            "option 'cgroup' not yet supported",
        ),
        (
            Family.IP,
            _opt("helper", "ftp", module="conntrack"),
            None,
            "option 'helper' not yet supported",
        ),
    ],
)
def test_match_module_refusals(
    domain: Family,
    option: RenderedOption,
    protocol: str | None,
    message: str,
) -> None:
    with pytest.raises(FermError, match=message):
        _translate_match_parts(domain, option, protocol)


# -- rule-wide modules: policy / ipv6header / ipv4options ----------------


def test_policy_dir_in_translates() -> None:
    assert _texts(
        [
            _marker("policy"),
            _opt("dir", "in", module="policy"),
            _opt("pol", "ipsec", module="policy"),
            _target("ACCEPT"),
        ],
        Family.IP,
    ) == ["meta ipsec exists", "accept"]
    assert _texts(
        [
            _marker("policy"),
            _opt("dir", "in", module="policy"),
            _opt("pol", "none", module="policy"),
            _target("DROP"),
        ],
        Family.IP,
    ) == ["meta ipsec missing", "drop"]


@pytest.mark.parametrize(
    ("options", "message"),
    [
        # dir out has no meta ipsec equivalent -- silently emitting the
        # input-side test would widen/flip the match (fail-open)
        (
            [
                _opt("dir", "out", module="policy"),
                _opt("pol", "ipsec", module="policy"),
            ],
            "'dir out' has no nft equivalent",
        ),
        # any element option must refuse even when dir/pol translate
        (
            [
                _opt("dir", "in", module="policy"),
                _opt("pol", "ipsec", module="policy"),
                _opt("reqid", "5", module="policy"),
            ],
            "option 'reqid' not yet supported",
        ),
        (
            [
                _opt("dir", "in", module="policy"),
                _opt("pol", "ipsec", module="policy"),
                _opt("strict", None, module="policy"),
            ],
            "option 'strict' not yet supported",
        ),
        (
            [_opt("pol", "ipsec", module="policy")],
            "needs both 'dir' and 'pol'",
        ),
    ],
)
def test_policy_refusals(options: list[RenderedOption], message: str) -> None:
    with pytest.raises(FermError, match=message):
        translate_rule(
            Family.IP,
            "filter",
            _rule(_marker("policy"), *options, _target("ACCEPT")),
        )


def test_ipv6header_soft_translates_and_dedups() -> None:
    assert _texts(
        [
            _marker("ipv6header"),
            _opt("header", "frag,mh,frag", module="ipv6header"),
            _opt("soft", None, module="ipv6header"),
            _target("ACCEPT"),
        ],
        Family.IP6,
    ) == ["exthdr frag exists", "exthdr mh exists", "accept"]


def test_ipv6header_single_negated_member_is_missing() -> None:
    assert _texts(
        [
            _marker("ipv6header"),
            _opt("header", Negated("frag"), module="ipv6header"),
            _opt("soft", None, module="ipv6header"),
            _target("ACCEPT"),
        ],
        Family.IP6,
    ) == ["exthdr frag missing", "accept"]


@pytest.mark.parametrize(
    ("options", "message"),
    [
        # without soft, xt matches the EXACT header set -- an exists
        # chain would match a superset (fail-open)
        (
            [_opt("header", "hop", module="ipv6header")],
            "without 'soft' matches the exact header set",
        ),
        (
            [
                _opt("header", Negated("frag,mh"), module="ipv6header"),
                _opt("soft", None, module="ipv6header"),
            ],
            "negated ipv6header header list",
        ),
        # auth/esp have no exthdr spelling in nft v1.1.6
        (
            [
                _opt("header", "frag,auth", module="ipv6header"),
                _opt("soft", None, module="ipv6header"),
            ],
            "no nft exthdr equivalent",
        ),
    ],
)
def test_ipv6header_refusals(
    options: list[RenderedOption], message: str
) -> None:
    with pytest.raises(FermError, match=message):
        translate_rule(
            Family.IP6,
            "filter",
            _rule(_marker("ipv6header"), *options, _target("ACCEPT")),
        )


def test_ipv6header_is_ip6_only() -> None:
    with pytest.raises(FermError, match="ip6-only"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _marker("ipv6header"),
                _opt("header", "frag", module="ipv6header"),
                _opt("soft", None, module="ipv6header"),
                _target("ACCEPT"),
            ),
        )


def test_ipv4options_is_ip_only() -> None:
    with pytest.raises(FermError, match="ip-only"):
        translate_rule(
            Family.IP6,
            "filter",
            _rule(
                _marker("ipv4options"),
                _opt("flags", "lsrr", module="ipv4options"),
                _target("DROP"),
            ),
        )


def test_ipv4options_short_aliases() -> None:
    # `ts` and `ro` are xt spellings of timestamp/router-alert
    assert _texts(
        [
            _marker("ipv4options"),
            _opt("flags", "ts,ro", module="ipv4options"),
            _target("DROP"),
        ],
        Family.IP,
    ) == [
        "ip option timestamp exists",
        "ip option ra exists",
        "drop",
    ]


def test_ipv4options_flags_translate_with_absence() -> None:
    assert _texts(
        [
            _marker("ipv4options"),
            _opt("flags", "lsrr,!rr,router-alert", module="ipv4options"),
            _target("DROP"),
        ],
        Family.IP,
    ) == [
        "ip option lsrr exists",
        "ip option rr missing",
        "ip option ra exists",
        "drop",
    ]


@pytest.mark.parametrize(
    ("options", "message"),
    [
        # `any` ORs the flags; the AND chain would narrow the match on
        # multi-flag rules and silently drop the OR semantics
        (
            [
                _opt("flags", "lsrr,rr", module="ipv4options"),
                _opt("any", None, module="ipv4options"),
            ],
            "'any' ORs the option flags",
        ),
        (
            [_opt("flags", "cipso", module="ipv4options")],
            "no nft equivalent",
        ),
        (
            [_opt("flags", Negated("lsrr,rr"), module="ipv4options")],
            "negated ipv4options flag list",
        ),
        # a negated single `!`-member (double negation) has no xt
        # semantics worth guessing at -- it keeps the list refusal
        (
            [_opt("flags", Negated("!lsrr"), module="ipv4options")],
            "negated ipv4options flag list",
        ),
        # a negated SINGLE plain member takes the `missing` path, but only
        # for a flag with an nft keyword; `cipso` has none, so even the
        # single-member negation refuses rather than emit a phantom test
        (
            [_opt("flags", Negated("cipso"), module="ipv4options")],
            "ipv4options flag 'cipso' has no nft equivalent",
        ),
    ],
)
def test_ipv4options_refusals(
    options: list[RenderedOption], message: str
) -> None:
    with pytest.raises(FermError, match=message):
        translate_rule(
            Family.IP,
            "filter",
            _rule(_marker("ipv4options"), *options, _target("DROP")),
        )


def test_ipv4options_single_negated_member_is_missing() -> None:
    # a negated flag list of exactly one plain member (no `!` prefix)
    # translates to `ip option X missing`; the whole-list negation refusal
    # applies only to 2+ members (see test_ipv4options_refusals).
    assert _texts(
        [
            _marker("ipv4options"),
            _opt("flags", Negated("lsrr"), module="ipv4options"),
            _target("DROP"),
        ],
        Family.IP,
    ) == ["ip option lsrr missing", "drop"]


def test_ipv4options_emits_once_per_rule() -> None:
    # two ipv4options options collect into one rule-wide flags dict and emit
    # a single match set; a lost `ipv4options_emitted = True` latch would
    # double-emit the flags (the last option wins the dict, so both spell rr).
    assert _texts(
        [
            _marker("ipv4options"),
            _opt("flags", "lsrr", module="ipv4options"),
            _opt("flags", "rr", module="ipv4options"),
            _target("DROP"),
        ],
        Family.IP,
    ) == ["ip option rr exists", "drop"]


# -- bare-load modules: rpfilter / socket ---------------------------------


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        ((), "fib saddr . iif oif != 0"),
        (("loose",), "fib saddr oif != 0"),
        (("invert",), "fib saddr . iif oif 0"),
        (("validmark",), "fib saddr . mark . iif oif != 0"),
        (("validmark", "loose"), "fib saddr . mark oif != 0"),
        (("loose", "invert"), "fib saddr oif 0"),
    ],
)
def test_rpfilter_forms(flags: tuple[str, ...], expected: str) -> None:
    options = [_marker("rpfilter")]
    options += [_opt(flag, None, module="rpfilter") for flag in flags]
    options.append(_target("ACCEPT"))
    assert _texts(options, Family.IP) == [expected, "accept"]


@pytest.mark.parametrize("module", ["rpfilter", "socket"])
def test_rpfilter_and_socket_are_ip_only(module: str) -> None:
    # the fib/socket expressions exist for ip/ip6 hooks only; a broken
    # guard would silently translate on eb instead of refusing
    with pytest.raises(FermError, match="ip/ip6-only"):
        translate_rule(
            Family.EB,
            "filter",
            _rule(_marker(module), _target("ACCEPT")),
        )


def test_rpfilter_accept_local_refuses() -> None:
    with pytest.raises(FermError, match="accept-local"):
        translate_rule(
            Family.IP,
            "filter",
            _rule(
                _marker("rpfilter"),
                _opt("accept-local", None, module="rpfilter"),
                _target("ACCEPT"),
            ),
        )


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        ((), ["socket wildcard 0"]),
        (("transparent",), ["socket wildcard 0", "socket transparent 1"]),
        (("nowildcard",), ["socket wildcard <= 1"]),
        # alongside nowildcard the tautological wildcard bound drops
        (("transparent", "nowildcard"), ["socket transparent 1"]),
    ],
)
def test_socket_forms(flags: tuple[str, ...], expected: list[str]) -> None:
    options = [_marker("socket")]
    options += [_opt(flag, None, module="socket") for flag in flags]
    options.append(_target("ACCEPT"))
    assert _texts(options, Family.IP) == [*expected, "accept"]


def test_socket_restore_skmark_translates() -> None:
    # iptables-translate: --restore-skmark becomes `meta mark set socket
    # mark` after the socket matches (readback-verified live).
    assert _texts(
        [
            _marker("socket"),
            _opt("restore-skmark", None, module="socket"),
            _target("ACCEPT"),
        ],
        Family.IP,
    ) == ["socket wildcard 0", "meta mark set socket mark", "accept"]


def test_other_bare_modules_still_refuse() -> None:
    # the rpfilter/socket bare hook must not loosen the eui64 refusal
    with pytest.raises(FermError, match="bare 'mod eui64'"):
        translate_rule(
            Family.IP6,
            "filter",
            _rule(_marker("eui64"), _target("ACCEPT")),
        )


# -- rule-wide module: osf (passive OS fingerprint) ----------------------


def _osf(*options: RenderedOption) -> list[str]:
    return _texts(
        [_marker("osf"), *options, _target("DROP")],
        Family.IP,
    )


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        # genre alone -> name, no ttl clause (xt --ttl 0 default)
        ([_opt("genre", "Linux", module="osf")], 'osf name "Linux"'),
        # explicit ttl 0 folds to the same default (no ttl keyword)
        (
            [
                _opt("genre", "Windows", module="osf"),
                _opt("ttl", "0", module="osf"),
            ],
            'osf name "Windows"',
        ),
        # ttl 1 -> loose (accept a smaller live TTL), ttl 2 -> skip
        (
            [
                _opt("genre", "Windows", module="osf"),
                _opt("ttl", "1", module="osf"),
            ],
            'osf ttl loose name "Windows"',
        ),
        (
            [
                _opt("genre", "FreeBSD", module="osf"),
                _opt("ttl", "2", module="osf"),
            ],
            'osf ttl skip name "FreeBSD"',
        ),
        # negated genre -> name !=
        (
            [_opt("genre", Negated("Linux"), module="osf")],
            'osf name != "Linux"',
        ),
    ],
)
def test_osf_forms(options: list[RenderedOption], expected: str) -> None:
    assert _osf(*options) == [expected, "drop"]


@pytest.mark.parametrize(
    ("options", "message"),
    [
        # --log has no nft equivalent -- dropping it would silently lose the
        # fingerprint logging the rule asked for (fail-open guard)
        (
            [
                _opt("genre", "Linux", module="osf"),
                _opt("log", "1", module="osf"),
            ],
            "option 'log' has no nft equivalent",
        ),
        # genre is the match key; without it there is nothing to spell
        (
            [_opt("ttl", "1", module="osf")],
            "needs 'genre'",
        ),
        # only the three documented ttl levels map
        (
            [
                _opt("genre", "Linux", module="osf"),
                _opt("ttl", "9", module="osf"),
            ],
            "'ttl 9' has no nft equivalent",
        ),
        # osf carries no negatable knob; a negated ttl is a wiring/config
        # error that must fail loud rather than silently emit the positive
        (
            [
                _opt("genre", "Linux", module="osf"),
                _opt("ttl", Negated("1"), module="osf"),
            ],
            r"mod osf 'ttl' cannot be negated",
        ),
    ],
)
def test_osf_refusals(options: list[RenderedOption], message: str) -> None:
    with pytest.raises(FermError, match=message):
        translate_rule(
            Family.IP,
            "filter",
            _rule(_marker("osf"), *options, _target("DROP")),
        )


def test_osf_is_ip_only() -> None:
    # osf is registered ip-only; the family guard is fail-loud belt-and-braces
    from pyferm.backend.nft.matches import _osf_match

    opts = {"genre": _opt("genre", "Linux", module="osf")}
    with pytest.raises(FermError, match="ip-only"):
        _osf_match(Family.IP6, opts)


# -- implied l4proto ------------------------------------------------------


def _proto(value: str) -> RenderedOption:
    return _opt("protocol", value, kind=OptionKind.PROTO)


def test_dccp_types_suppress_l4proto_prefix() -> None:
    # the kernel readback drops `meta l4proto dccp` before `dccp type`
    assert _texts(
        [
            _proto("dccp"),
            _opt("dccp-types", "REQUEST", module="dccp"),
            _target("DROP"),
        ],
        Family.IP,
    ) == ["dccp type request", "drop"]


def test_ah_esp_spi_suppress_l4proto_prefix() -> None:
    assert _texts(
        [
            _proto("ah"),
            _marker("ah"),
            _opt("ahspi", "500", module="ah"),
            _target("ACCEPT"),
        ],
        Family.IP,
    ) == ["ah spi 500", "accept"]
    assert _texts(
        [
            _proto("esp"),
            _marker("esp"),
            _opt("espspi", "500", module="esp"),
            _target("ACCEPT"),
        ],
        Family.IP6,
    ) == ["esp spi 500", "accept"]


def test_mh_type_keeps_l4proto_prefix() -> None:
    # unlike dccp/ah/esp the readback KEEPS the prefix, spelled
    # mobility-header (`meta l4proto mh` is an nft syntax error)
    assert _texts(
        [
            _proto("mh"),
            _opt("mh-type", "5", module="mh"),
            _target("ACCEPT"),
        ],
        Family.IP6,
    ) == ["meta l4proto mobility-header", "mh type binding-update", "accept"]


def test_bare_proto_mh_spells_mobility_header() -> None:
    assert _texts([_proto("mh"), _target("ACCEPT")], Family.IP6) == [
        "meta l4proto mobility-header",
        "accept",
    ]


def test_bare_proto_hopopt_spells_ip() -> None:
    # nft parses `hopopt` but reads it back as protocol 0's name `ip`
    assert _texts([_proto("hopopt"), _target("ACCEPT")], Family.IP6) == [
        "meta l4proto ip",
        "accept",
    ]


@pytest.mark.parametrize(
    ("number", "name"),
    [
        ("0", "ip"),
        ("43", "ipv6-route"),
        ("44", "ipv6-frag"),
        ("59", "ipv6-nonxt"),
        ("60", "ipv6-opts"),
    ],
)
def test_bare_proto_number_folds_to_readback_name(
    number: str, name: str
) -> None:
    # a known protocol NUMBER reads back as its nft name; a stale entry
    # in the number table means a phantom --plan diff forever
    assert _texts([_proto(number), _target("ACCEPT")], Family.IP6) == [
        f"meta l4proto {name}",
        "accept",
    ]


# -- helper match -------------------------------------------------------


def test_helper_match_positive() -> None:
    # xt_helper matches the ct helper name; nft spells it a quoted string.
    assert (
        translate_match(
            Family.IP, _opt("helper", "ftp", module="helper"), None
        )
        == 'ct helper "ftp"'
    )


def test_helper_match_empty_refused() -> None:
    with pytest.raises(FermError, match=r"^mod helper needs a non-empty"):
        translate_match(Family.IP, _opt("helper", "", module="helper"), None)


# -- nth match (-> numgen inc mod N P) ----------------------------------


def test_nth_every_defaults_packet_zero() -> None:
    assert _texts(
        [_opt("every", "4", module="nth"), _target("ACCEPT")], Family.IP
    ) == ["numgen inc mod 4 0", "accept"]


def test_nth_every_with_packet() -> None:
    assert _texts(
        [
            _opt("every", "8", module="nth"),
            _opt("packet", "3", module="nth"),
            _target("ACCEPT"),
        ],
        Family.IP,
    ) == ["numgen inc mod 8 3", "accept"]


def test_nth_default_counter_start_zero_allowed() -> None:
    # counter 0 / start 0 are the defaults; they must be accepted, not
    # refused (only a non-zero value has no numgen analogue).
    assert _texts(
        [
            _opt("every", "4", module="nth"),
            _opt("counter", "0", module="nth"),
            _opt("start", "0", module="nth"),
            _target("ACCEPT"),
        ],
        Family.IP,
    ) == ["numgen inc mod 4 0", "accept"]


@pytest.mark.parametrize("stateful_name", ["counter", "start"])
def test_nth_nonzero_counter_or_start_refused(stateful_name: str) -> None:
    with pytest.raises(
        FermError, match=rf"^mod nth '{stateful_name}' has no numgen"
    ):
        _texts(
            [
                _opt("every", "4", module="nth"),
                _opt(stateful_name, "3", module="nth"),
                _target("ACCEPT"),
            ],
            Family.IP,
        )


@pytest.mark.parametrize("stateful_name", ["counter", "start"])
def test_nth_nondigit_counter_or_start_refused(stateful_name: str) -> None:
    with pytest.raises(FermError, match=rf"^invalid nth {stateful_name} 'x'"):
        _texts(
            [
                _opt("every", "4", module="nth"),
                _opt(stateful_name, "x", module="nth"),
                _target("ACCEPT"),
            ],
            Family.IP,
        )


def test_nth_without_every_refused() -> None:
    with pytest.raises(FermError, match=r"^mod nth needs 'every'"):
        _texts(
            [_opt("packet", "0", module="nth"), _target("ACCEPT")], Family.IP
        )


def test_nth_packet_not_less_than_every_refused() -> None:
    with pytest.raises(FermError, match=r"^nth packet '4' must be less"):
        _texts(
            [
                _opt("every", "4", module="nth"),
                _opt("packet", "4", module="nth"),
                _target("ACCEPT"),
            ],
            Family.IP,
        )


def test_nth_every_zero_refused() -> None:
    with pytest.raises(FermError, match=r"^invalid nth every '0'"):
        _texts(
            [_opt("every", "0", module="nth"), _target("ACCEPT")], Family.IP
        )


def test_nth_every_nondigit_refused() -> None:
    # `_nth_numgen` is shared with the statistic-nth path via a `label`
    # argument; this pins the `"nth"`-labeled every/packet refusals (an
    # argument swap that mislabels one path would slip past the statistic
    # tests otherwise).
    with pytest.raises(FermError, match=r"^invalid nth every 'abc'"):
        _texts(
            [_opt("every", "abc", module="nth"), _target("ACCEPT")], Family.IP
        )


def test_nth_packet_nondigit_refused() -> None:
    with pytest.raises(FermError, match=r"^invalid nth packet 'xy'"):
        _texts(
            [
                _opt("every", "4", module="nth"),
                _opt("packet", "xy", module="nth"),
                _target("ACCEPT"),
            ],
            Family.IP,
        )


@pytest.mark.parametrize("field", ["every", "counter", "start"])
def test_nth_latin1_superscript_digit_refused(field: str) -> None:
    # `str.isdigit()` is true for the latin-1 superscript a config's bytes
    # decode to (b2/b3/b9 -> ) but int() rejects it; the validator must
    # give a clean ferm refusal, never a ValueError traceback.
    options = [_opt("every", "4", module="nth")] if field != "every" else []
    options.append(_opt(field, "²", module="nth"))
    options.append(_target("ACCEPT"))
    with pytest.raises(FermError, match=rf"^invalid nth {field} "):
        _texts(options, Family.IP)


def test_statistic_nth_and_mod_nth_coexist_module_qualified() -> None:
    # `every`/`packet` name BOTH mod statistic and mod nth keywords; the
    # rule-wide collections are module-qualified, so a rule carrying
    # `mod statistic mode nth` AND a standalone `mod nth` emits two
    # independent numgen matches without cross-contaminating each other's
    # every (5 stays with statistic, 3 with nth).
    assert _texts(
        [
            _opt("mode", "nth", module="statistic"),
            _opt("every", "5", module="statistic"),
            _opt("every", "3", module="nth"),
            _target("ACCEPT"),
        ],
        Family.IP,
    ) == ["numgen inc mod 5 0", "numgen inc mod 3 0", "accept"]
