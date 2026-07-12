"""
Unit matrix for the nft *target* vocabulary (targets with no table object).

Covers the AUDIT, CONNSECMARK, and HMARK targets and the CT target's
object-free options (notrack / zone / events).  Every emitted spelling was
captured from a live ``nft list ruleset`` readback (nft v1.1.6) -- the emission
MUST equal the readback or ``--plan`` diffs an applied ruleset forever.  HMARK
maps xt's hash to nft ``jhash``: the DISTRIBUTION, not the exact mark value
(the recent/hashlimit bar).  The refusal tests pin the fail-open guards the
dichotomy gate cannot see (a silently-dropped CT option, a per-field mask jhash
cannot express, an unhashable tuple field).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.backend.nft import build_verdict, translate_rule
from pyferm.backend.nft.verdicts import _ct_target_statements
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.values import Negated, Value
from tests.unit._nftrule import _opt, _rule, _target

if TYPE_CHECKING:
    from pyferm.rules import RenderedOption


def _texts(rule_options: list[RenderedOption], domain: Family) -> list[str]:
    nft = translate_rule(domain, "filter", _rule(*rule_options))
    return [s.to_text() for s in nft.statements]


def _ct(companions: dict[str, RenderedOption]) -> str:
    # CT builds an ordered statement list (its `helper` knob declares a `ct
    # helper` object, covered in the objects matrix), joined here as it would
    # emit in a rule.
    return " ".join(s.to_text() for s in _ct_target_statements(companions))


def _ct_opt(name: str, value: Value) -> RenderedOption:
    return _opt(name, value, module="CT")


def _connsecmark(*flags: str, domain: Family = Family.IP) -> str:
    companions = {
        flag: _opt(flag, None, module="CONNSECMARK") for flag in flags
    }
    return build_verdict(
        domain, "mangle", "jump", "CONNSECMARK", companions
    ).to_text()


def _hmark(opts: dict[str, str], *, domain: Family = Family.IP) -> str:
    companions = {
        name.replace("_", "-"): _opt(
            name.replace("_", "-"), value, module="HMARK"
        )
        for name, value in opts.items()
    }
    return build_verdict(
        domain, "mangle", "jump", "HMARK", companions
    ).to_text()


# -- AUDIT --------------------------------------------------------------


def test_audit_translates_to_audit_log() -> None:
    for kind in ("accept", "drop", "reject"):
        assert _texts(
            [
                _target("AUDIT"),
                _opt("type", kind, module="AUDIT"),
            ],
            Family.IP,
        ) == ["log level audit"]


def test_audit_type_validates() -> None:
    with pytest.raises(FermError, match="invalid AUDIT type"):
        build_verdict(
            Family.IP,
            "filter",
            "jump",
            "AUDIT",
            {"type": _opt("type", "foo", module="AUDIT")},
        )
    with pytest.raises(FermError, match="AUDIT needs 'type'"):
        build_verdict(Family.IP, "filter", "jump", "AUDIT", {})


# -- CONNSECMARK --------------------------------------------------------


def test_connsecmark_save() -> None:
    assert _connsecmark("save") == "ct secmark set meta secmark"


def test_connsecmark_restore() -> None:
    assert _connsecmark("restore") == "meta secmark set ct secmark"


def test_connsecmark_ip6() -> None:
    # the secmark move carries no family-prefixed selector, so ip6 emits the
    # identical text -- pin it so a future domain-aware refactor stays honest.
    assert (
        _connsecmark("save", domain=Family.IP6)
        == "ct secmark set meta secmark"
    )
    assert (
        _connsecmark("restore", domain=Family.IP6)
        == "meta secmark set ct secmark"
    )


def test_connsecmark_both_refused() -> None:
    with pytest.raises(FermError, match=r"^CONNSECMARK target not yet"):
        _connsecmark("save", "restore")


def test_connsecmark_neither_refused() -> None:
    with pytest.raises(FermError, match=r"^CONNSECMARK target not yet"):
        _connsecmark()


# -- HMARK positives ----------------------------------------------------


def test_hmark_full_ip() -> None:
    assert _hmark(
        {
            "hmark_tuple": "src,dst,sport,dport,proto",
            "hmark_mod": "10",
            "hmark_rnd": "0xabc",
            "hmark_offset": "100",
        }
    ) == (
        "meta mark set jhash ip saddr . ip daddr . th sport . th dport . "
        "meta l4proto mod 10 seed 0xabc offset 100"
    )


def test_hmark_ip6() -> None:
    assert (
        _hmark(
            {"hmark_tuple": "src,dst", "hmark_mod": "8", "hmark_rnd": "0xabc"},
            domain=Family.IP6,
        )
        == "meta mark set jhash ip6 saddr . ip6 daddr mod 8 seed 0xabc"
    )


def test_hmark_seed_decimal_canon_to_hex() -> None:
    # xt --hmark-rnd takes decimal or hex; nft prints the seed as 0x-hex, so
    # a decimal rnd must canonicalize (2748 -> 0xabc) or --plan phantoms.
    assert (
        _hmark({"hmark_tuple": "src", "hmark_mod": "8", "hmark_rnd": "2748"})
        == "meta mark set jhash ip saddr mod 8 seed 0xabc"
    )


def test_hmark_offset_zero_omitted() -> None:
    # the readback drops `offset 0`, so the emitter must too.
    assert (
        _hmark(
            {
                "hmark_tuple": "src",
                "hmark_mod": "8",
                "hmark_rnd": "1",
                "hmark_offset": "0",
            }
        )
        == "meta mark set jhash ip saddr mod 8 seed 0x1"
    )


def test_hmark_single_field() -> None:
    assert (
        _hmark({"hmark_tuple": "dport", "hmark_mod": "4", "hmark_rnd": "0x0"})
        == "meta mark set jhash th dport mod 4 seed 0x0"
    )


# -- HMARK refusals -----------------------------------------------------


@pytest.mark.parametrize(
    "mask",
    [
        "hmark_src_prefix",
        "hmark_dst_prefix",
        "hmark_sport_mask",
        "hmark_dport_mask",
        "hmark_spi_mask",
        "hmark_proto_mask",
    ],
)
def test_hmark_per_field_mask_refused(mask: str) -> None:
    # jhash hashes fields whole; a per-field mask/prefix has no faithful nft
    # form and must refuse rather than hash the unmasked field (fail-open).
    with pytest.raises(FermError, match=r"has no nft jhash equivalent"):
        _hmark(
            {
                "hmark_tuple": "src",
                "hmark_mod": "8",
                "hmark_rnd": "1",
                mask: "24",
            }
        )


@pytest.mark.parametrize("field", ["spi", "ct", "bogus"])
def test_hmark_unhashable_tuple_field_refused(field: str) -> None:
    with pytest.raises(
        FermError, match=rf"^HMARK tuple field '{field}' has no nft jhash"
    ):
        _hmark(
            {"hmark_tuple": f"src,{field}", "hmark_mod": "8", "hmark_rnd": "1"}
        )


@pytest.mark.parametrize(
    "opts",
    [
        {"hmark_tuple": "src", "hmark_rnd": "1"},  # no mod
        {"hmark_tuple": "src", "hmark_mod": "8"},  # no rnd
        {"hmark_mod": "8", "hmark_rnd": "1"},  # no tuple
    ],
    ids=["no-mod", "no-rnd", "no-tuple"],
)
def test_hmark_missing_mandatory_refused(opts: dict[str, str]) -> None:
    with pytest.raises(FermError, match=r"^HMARK needs 'hmark-tuple'"):
        _hmark(opts)


def test_hmark_empty_tuple_refused() -> None:
    with pytest.raises(FermError, match=r"^HMARK 'hmark-tuple' is empty"):
        _hmark({"hmark_tuple": ",", "hmark_mod": "8", "hmark_rnd": "1"})


def test_hmark_u32_max_accepted() -> None:
    # mod/rnd/offset are u32; the boundary value loads (nft rejects u32+1).
    assert _hmark(
        {
            "hmark_tuple": "src",
            "hmark_mod": "4294967295",
            "hmark_rnd": "0xffffffff",
            "hmark_offset": "4294967295",
        }
    ) == (
        "meta mark set jhash ip saddr mod 4294967295 seed 0xffffffff "
        "offset 4294967295"
    )


@pytest.mark.parametrize("operand", ["hmark_rnd", "hmark_mod", "hmark_offset"])
@pytest.mark.parametrize("value", ["010", "08", "0123"])
def test_hmark_leading_zero_refused(operand: str, value: str) -> None:
    # iptables reads a leading-zero operand as C octal (010 -> 8); a decimal
    # read would give 10.  Rather than silently disagree -- or crash on the
    # base-0 int() the old parser used -- the backend refuses cleanly.
    opts = {"hmark_tuple": "src", "hmark_mod": "8", "hmark_rnd": "1"}
    opts[operand] = value
    with pytest.raises(FermError, match=r"^invalid HMARK "):
        _hmark(opts)


def test_hmark_mod_and_offset_accept_hex() -> None:
    # iptables takes 0x-hex for mod/offset as well as rnd; nft prints mod and
    # offset back in decimal, so the hex input canonicalizes to decimal.
    assert _hmark(
        {
            "hmark_tuple": "src",
            "hmark_mod": "0x100",
            "hmark_rnd": "5",
            "hmark_offset": "0x10",
        }
    ) == ("meta mark set jhash ip saddr mod 256 seed 0x5 offset 16")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        # u32 overflow: nft rejects (or a modulus silently wraps) above u32,
        # so ferm refuses rather than emit a value the kernel won't take.
        ("hmark_mod", "4294967296", r"^invalid HMARK hmark-mod"),
        ("hmark_rnd", "0x100000000", r"^invalid HMARK hmark-rnd"),
        ("hmark_offset", "4294967296", r"^invalid HMARK hmark-offset"),
        ("hmark_mod", "0", r"^invalid HMARK hmark-mod"),
        ("hmark_mod", "abc", r"^invalid HMARK hmark-mod"),
        ("hmark_rnd", "zzz", r"^invalid HMARK hmark-rnd"),
        # int(x, 0) would take these; the oracle (iptables) rejects them, so
        # ferm must too or the same config diverges between backends.
        ("hmark_rnd", "1_000", r"^invalid HMARK hmark-rnd"),
        ("hmark_rnd", "0o17", r"^invalid HMARK hmark-rnd"),
        # non-ASCII digits pass str.isdigit()/int() but nft takes ASCII only.
        ("hmark_mod", "٢١", r"^invalid HMARK hmark-mod"),
        ("hmark_offset", "٢١", r"^invalid HMARK hmark-offset"),
        ("hmark_rnd", "٢١", r"^invalid HMARK hmark-rnd"),
    ],
)
def test_hmark_operand_out_of_range_refused(
    field: str, value: str, message: str
) -> None:
    with pytest.raises(FermError, match=message):
        _hmark(
            {
                "hmark_tuple": "src",
                "hmark_mod": "8",
                "hmark_rnd": "1",
                field: value,
            }
        )


# -- CT target: events --------------------------------------------------


def test_ct_events_reorder_to_canon() -> None:
    # nft prints ct event bits in a fixed order; an out-of-order input must
    # emit in that order or --plan phantoms.
    assert (
        _ct({"ctevents": _ct_opt("ctevents", "destroy,new,related")})
        == "ct event set new,related,destroy"
    )


def test_ct_events_full_set_canon() -> None:
    assert (
        _ct(
            {
                "ctevents": _ct_opt(
                    "ctevents",
                    "label,protoinfo,reply,assured,destroy,related,new",
                )
            }
        )
        == "ct event set new,related,destroy,reply,assured,protoinfo,label"
    )


def test_ct_events_dedup() -> None:
    assert (
        _ct({"ctevents": _ct_opt("ctevents", "new,new,related")})
        == "ct event set new,related"
    )


@pytest.mark.parametrize(
    "bad", ["helper", "mark", "natseqinfo", "secmark", "bogus"]
)
def test_ct_event_without_nft_bit_refused(bad: str) -> None:
    with pytest.raises(FermError, match=rf"^CT event '{bad}' has no nft"):
        _ct({"ctevents": _ct_opt("ctevents", f"new,{bad}")})


def test_ct_events_empty_refused() -> None:
    with pytest.raises(FermError, match=r"^CT 'ctevents' needs at least one"):
        _ct({"ctevents": _ct_opt("ctevents", "")})


def test_ct_events_negated_refused() -> None:
    with pytest.raises(FermError, match=r"^CT 'ctevents' cannot be negated"):
        _ct({"ctevents": _ct_opt("ctevents", Negated("new"))})


# -- CT target: zones ---------------------------------------------------


def test_ct_zone_plain() -> None:
    assert _ct({"zone": _ct_opt("zone", "5")}) == "ct zone set 5"


def test_ct_zone_directional() -> None:
    assert (
        _ct({"zone-orig": _ct_opt("zone-orig", "5")})
        == "ct original zone set 5"
    )
    assert (
        _ct({"zone-reply": _ct_opt("zone-reply", "7")})
        == "ct reply zone set 7"
    )


def test_ct_zone_bounds() -> None:
    assert _ct({"zone": _ct_opt("zone", "0")}) == "ct zone set 0"
    assert _ct({"zone": _ct_opt("zone", "65535")}) == "ct zone set 65535"


@pytest.mark.parametrize("zone_name", ["zone", "zone-orig", "zone-reply"])
def test_ct_zone_overflow_refused(zone_name: str) -> None:
    # every zone form shares _ct_zone_value and must refuse 65536 with its
    # own name in the message.
    with pytest.raises(
        FermError, match=rf"^CT {zone_name} '65536' exceeds 0-65535"
    ):
        _ct({zone_name: _ct_opt(zone_name, "65536")})


@pytest.mark.parametrize("zone_name", ["zone", "zone-orig", "zone-reply"])
def test_ct_zone_nondigit_refused(zone_name: str) -> None:
    with pytest.raises(FermError, match=rf"^invalid CT {zone_name} 'abc'"):
        _ct({zone_name: _ct_opt(zone_name, "abc")})


@pytest.mark.parametrize("zone_name", ["zone", "zone-orig", "zone-reply"])
def test_ct_zone_latin1_superscript_digit_refused(zone_name: str) -> None:
    # a latin-1 superscript passes str.isdigit() but not int(); the guard
    # must give a clean refusal, never a ValueError traceback.
    with pytest.raises(FermError, match=rf"^invalid CT {zone_name} "):
        _ct({zone_name: _ct_opt(zone_name, "²")})


def test_ct_all_three_zone_forms_fixed_order() -> None:
    # plain then original then reply, the static loop order, regardless of
    # companion dict key order.
    companions = {
        "zone-reply": _ct_opt("zone-reply", "7"),
        "zone": _ct_opt("zone", "1"),
        "zone-orig": _ct_opt("zone-orig", "5"),
    }
    assert _ct(companions) == (
        "ct zone set 1 ct original zone set 5 ct reply zone set 7"
    )


# -- CT target: multi-statement + refusals ------------------------------


def test_ct_multi_statement_fixed_order() -> None:
    # notrack -> zone -> event, the order nft keeps on readback, regardless
    # of the companion dict's own key order.
    companions = {
        "ctevents": _ct_opt("ctevents", "new,destroy"),
        "notrack": _opt("notrack", None, module="CT"),
        "zone": _ct_opt("zone", "1"),
    }
    assert _ct(companions) == "notrack ct zone set 1 ct event set new,destroy"


def test_ct_bare_refused() -> None:
    with pytest.raises(
        FermError, match=r"^CT target not yet supported by nft backend$"
    ):
        _ct({})


# `helper` is a supported CT option (it declares a `ct helper` object, covered
# in the objects matrix); only expevents/timeout still lack an nft form.
@pytest.mark.parametrize("unsupported", ["expevents", "timeout"])
def test_ct_object_options_refused(unsupported: str) -> None:
    with pytest.raises(
        FermError, match=rf"^CT target option '{unsupported}' not yet"
    ):
        _ct({unsupported: _ct_opt(unsupported, "x")})


def test_ct_refusal_short_circuits_translatable_sibling() -> None:
    # `CT expevents new zone 1`: the unsupported expevents must refuse UP FRONT
    # -- emitting `ct zone set 1` and dropping expevents would be a fail-open
    # mangle (the firewall silently loses the requested behavior).
    with pytest.raises(
        FermError, match=r"^CT target option 'expevents' not yet"
    ):
        _ct(
            {
                "expevents": _ct_opt("expevents", "new"),
                "zone": _ct_opt("zone", "1"),
            }
        )
