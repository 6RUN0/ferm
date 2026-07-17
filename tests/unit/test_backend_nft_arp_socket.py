"""
Unit matrix for the arp/socket vocabulary batch: named arp opcodes, the
arptables mangle target, and socket ``restore-skmark``.

Every emitted spelling was captured live (nft v1.1.6, arptables-translate
and iptables-translate cross-checks).  The opcode names map through the
ARPTABLES numbering, not IANA's: arptables spells 9 ``ARP_NAK`` where
IANA (and the nft readback) has 9 = InARP-Reply, so ``opcode ARP_NAK``
deliberately emits ``arp operation inreply`` -- the number is the
semantic the kernel matches, the readback name is only the spelling.
The mangle emissions pin the arptables-translate shape (guards, rewrite
order, empty CONTINUE verdict) because the kernel readback preserves the
written form verbatim; arptables-translate's own MAC spelling is NOT the
canon (it sign-extends octets into garbage).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.backend.nft import translate_match, translate_rule
from pyferm.backend.nft.assemble import _is_vmap_verdict
from pyferm.backend.nft.verdicts import (
    _ARP_MANGLE_COMPANIONS,
    _arp_mangle_statement,
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


def _texts(
    domain: Family, *options: RenderedOption, table: str = "filter"
) -> list[str]:
    # End-to-end through translate_rule, NOT _arp_mangle_statement in
    # isolation: this seam pins the companion registration in assemble.py
    # (an unregistered mangle-* option would refuse in the match path
    # before the mangle translation ever ran).
    nft = translate_rule(domain, table, _rule(*options))
    return [s.to_text() for s in nft.statements]


_MANGLE_GUARDS = "arp htype 1 arp hlen 6 arp plen 4"


# -- named arp opcodes (S6) ----------------------------------------------


@pytest.mark.parametrize(
    ("name", "operation"),
    [
        ("Request", "request"),
        ("Reply", "reply"),
        ("Request_Reverse", "rrequest"),
        ("Reply_Reverse", "rreply"),
        ("DRARP_Request", "5"),
        ("DRARP_Reply", "6"),
        ("DRARP_Error", "7"),
        ("InARP_Request", "inrequest"),
        # THE trap this table exists for: arptables' ARP_NAK is number 9,
        # which the IANA-following readback spells `inreply` (its own
        # nak is 10, unreachable by arptables name).
        ("ARP_NAK", "inreply"),
    ],
)
def test_named_opcode_translates(name: str, operation: str) -> None:
    assert (
        translate_match(Family.ARP, _opt("opcode", name), None)
        == f"arp operation {operation}"
    )


@pytest.mark.parametrize("spelling", ["request", "REQUEST", "Request"])
def test_named_opcode_is_case_insensitive(spelling: str) -> None:
    assert (
        translate_match(Family.ARP, _opt("opcode", spelling), None)
        == "arp operation request"
    )


def test_named_opcode_negation() -> None:
    assert (
        translate_match(Family.ARP, _opt("opcode", Negated("Arp_Nak")), None)
        == "arp operation != inreply"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "nak",  # nft readback spelling, NOT an arptables name
        "inreply",  # ditto
        "ARP-NAK",  # dash for underscore
        "arp_na\u212a",  # KELVIN SIGN: str.lower() maps it onto arp_nak
        "\u017foo",  # LATIN SMALL LETTER LONG S casefolds toward 's'
        "",
    ],
)
def test_named_opcode_refuses_off_table(bad: str) -> None:
    with pytest.raises(FermError, match=r"\Ainvalid arp opcode "):
        translate_match(Family.ARP, _opt("opcode", bad), None)


# -- arp mangle target ----------------------------------------------------


@pytest.mark.parametrize(
    ("option", "value", "rewrite"),
    [
        ("mangle-ip-s", "192.0.2.1", "arp saddr ip set 192.0.2.1"),
        ("mangle-ip-d", "192.0.2.9", "arp daddr ip set 192.0.2.9"),
        (
            "mangle-mac-s",
            "0:1:2:3:4:5",
            "arp saddr ether set 00:01:02:03:04:05",
        ),
        (
            "mangle-mac-d",
            "AA:BB:CC:0:11:22",
            "arp daddr ether set aa:bb:cc:00:11:22",
        ),
    ],
)
def test_arp_mangle_single_rewrites(
    option: str, value: str, rewrite: str
) -> None:
    assert _texts(Family.ARP, _opt(option, value), _target("mangle")) == [
        _MANGLE_GUARDS,
        f"{rewrite} accept",
    ]


def test_arp_mangle_combined_emits_canonical_order() -> None:
    # The arptables-translate order (saddr ip, saddr ether, daddr ip,
    # daddr ether) regardless of config order; the kernel readback
    # preserves the written rewrite order verbatim, so this round-trips.
    assert _texts(
        Family.ARP,
        _opt("mangle-mac-d", "6:7:8:9:a:b"),
        _opt("mangle-ip-d", "192.0.2.9"),
        _opt("mangle-mac-s", "0:1:2:3:4:5"),
        _opt("mangle-ip-s", "192.0.2.1"),
        _target("mangle"),
    ) == [
        _MANGLE_GUARDS,
        "arp saddr ip set 192.0.2.1 "
        "arp saddr ether set 00:01:02:03:04:05 "
        "arp daddr ip set 192.0.2.9 "
        "arp daddr ether set 06:07:08:09:0a:0b accept",
    ]


def test_arp_mangle_guards_precede_the_matches() -> None:
    # nft merges adjacent arp payload loads and prints the fields in
    # header-offset order: htype/hlen/plen sit below operation, so the
    # guards MUST come first or the kernel readback reorders the rule
    # into a phantom --plan diff (verified live).
    assert _texts(
        Family.ARP,
        _opt("opcode", "Reply"),
        _opt("mangle-ip-s", "192.0.2.1"),
        _target("mangle"),
    ) == [
        _MANGLE_GUARDS,
        "arp operation reply",
        "arp saddr ip set 192.0.2.1 accept",
    ]


@pytest.mark.parametrize(
    ("operand", "suffix"),
    [("ACCEPT", " accept"), ("DROP", " drop"), ("CONTINUE", "")],
)
def test_arp_mangle_target_verdicts(operand: str, suffix: str) -> None:
    # CONTINUE is the arptables-translate empty form: the rule ends at
    # `set ...` (rewrites run, then fall-through) -- no trailing space.
    assert _texts(
        Family.ARP,
        _opt("mangle-ip-s", "192.0.2.1"),
        _opt("mangle-target", operand),
        _target("mangle"),
    ) == [_MANGLE_GUARDS, f"arp saddr ip set 192.0.2.1{suffix}"]


def test_arp_mangle_continue_without_rewrites_is_guards_only() -> None:
    # An empty verdict over an empty rewrite list leaves nothing to
    # append: the rule is the bare guards match (a valid verdict-less
    # nft rule), never an empty statement.
    assert _texts(
        Family.ARP,
        _opt("mangle-target", "CONTINUE"),
        _target("mangle"),
    ) == [_MANGLE_GUARDS]


@pytest.mark.parametrize("operand", ["RETURN", "accept", "NFQUEUE", ""])
def test_arp_mangle_target_refuses_off_whitelist(operand: str) -> None:
    # RETURN in particular: the nft kernel would take `return`, but
    # arptables rejects it ("bad target for --mangle-target"), and
    # accepting it would accept a config the oracle refuses.
    with pytest.raises(FermError, match=r"\Ainvalid mangle-target "):
        _texts(
            Family.ARP,
            _opt("mangle-ip-s", "192.0.2.1"),
            _opt("mangle-target", operand),
            _target("mangle"),
        )


@pytest.mark.parametrize(
    "bad",
    [
        "192.0.2.01",  # leading zero (inet_pton ambiguity)
        "0xc0000201",  # hex form
        "3221225985",  # int form
        "2001:db8::1",  # ip6 literal (_validate_address would pass it)
        "192.0.2.1\n",
        "example.com",  # a hostname resolves before the backend
    ],
)
def test_arp_mangle_refuses_non_ipv4_literal(bad: str) -> None:
    with pytest.raises(FermError, match=r"\Ainvalid arp mangle ip "):
        _texts(
            Family.ARP,
            _opt("mangle-ip-s", bad),
            _target("mangle"),
        )


def test_arp_mangle_refuses_bad_mac() -> None:
    with pytest.raises(FermError, match=r"\Ainvalid mac "):
        _texts(
            Family.ARP,
            _opt("mangle-mac-s", "aa-bb-cc-00-11-22"),
            _target("mangle"),
        )


def test_arp_mangle_bare_jump_is_a_legal_noop() -> None:
    # `jump mangle` with no mangle-* option mangles nothing and takes
    # the default ACCEPT verdict -- guards plus accept.
    assert _texts(Family.ARP, _target("mangle")) == [
        _MANGLE_GUARDS,
        "accept",
    ]


@pytest.mark.parametrize(
    "target",
    [_target("other_chain"), _target("ACCEPT"), None],
)
def test_arp_mangle_companion_without_mangle_target_refuses(
    target: RenderedOption | None,
) -> None:
    # The _TARGET_COMPANIONS registration takes mangle-* out of the
    # match path for EVERY arp target; only the `mangle` dispatch
    # consumes them, so any other (or no) target must refuse rather
    # than silently drop the rewrite (fail-open).
    options = [_opt("mangle-ip-s", "192.0.2.1")]
    if target is not None:
        options.append(target)
    with pytest.raises(
        FermError, match=r"\Aoption 'mangle-ip-s' needs the arp "
    ):
        _texts(Family.ARP, *options)


def test_non_arp_jump_mangle_stays_a_user_chain() -> None:
    # Only arptables reads `-j mangle` as a target; in the ip domain the
    # name is an ordinary user chain.
    assert _texts(Family.IP, _target("mangle")) == ["jump mangle"]


def test_arp_mangle_companion_partition_is_consistent() -> None:
    # The guard set must cover exactly the rewrite table plus the
    # verdict knob; a future companion outside it would silently fall
    # through the fail-open guard.
    assert {
        "mangle-ip-s",
        "mangle-ip-d",
        "mangle-mac-s",
        "mangle-mac-d",
        "mangle-target",
    } == _ARP_MANGLE_COMPANIONS


def test_arp_mangle_statement_is_not_a_vmap_verdict() -> None:
    statement = _arp_mangle_statement(
        {"mangle-ip-s": _opt("mangle-ip-s", "192.0.2.1")}
    )
    assert statement is not None
    assert not _is_vmap_verdict(statement)


# -- socket restore-skmark ------------------------------------------------


@pytest.mark.parametrize(
    ("flags", "matches"),
    [
        (("restore-skmark",), ["socket wildcard 0"]),
        (
            ("transparent", "restore-skmark"),
            ["socket wildcard 0", "socket transparent 1"],
        ),
        (
            ("nowildcard", "transparent", "restore-skmark"),
            ["socket transparent 1"],
        ),
    ],
)
def test_restore_skmark_statement_order(
    flags: tuple[str, ...], matches: list[str]
) -> None:
    # iptables-translate: matches first, then `meta mark set socket
    # mark`, then the verdict (readback-verified live).
    options = [_marker("socket")]
    options += [_opt(flag, None, module="socket") for flag in flags]
    options.append(_target("ACCEPT"))
    assert _texts(Family.IP, *options) == [
        *matches,
        "meta mark set socket mark",
        "accept",
    ]


def test_restore_skmark_without_target_is_valid_and_not_vmap() -> None:
    # xt allows a verdict-less rule (match + mark restore, then fall
    # through); the trailing statement must not be folded as a vmap
    # verdict, or a collapse would drop the mark write.
    nft = translate_rule(
        Family.IP,
        "filter",
        _rule(
            _marker("socket"),
            _opt("restore-skmark", None, module="socket"),
        ),
    )
    texts = [s.to_text() for s in nft.statements]
    assert texts == ["socket wildcard 0", "meta mark set socket mark"]
    assert not _is_vmap_verdict(nft.statements[-1])


def test_restore_skmark_stays_ip_only() -> None:
    with pytest.raises(FermError, match=r"\Amod socket is ip/ip6-only"):
        _texts(
            Family.EB,
            _marker("socket"),
            _opt("restore-skmark", None, module="socket"),
            _target("ACCEPT"),
        )
