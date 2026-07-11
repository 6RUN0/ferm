"""
Unit matrix for the batch-11a nft vocabulary (CONNSECMARK / HMARK).

These two targets need no table object (unlike batch 11b's secmark/ct
helper).  Every emitted spelling was captured from a live ``nft list
ruleset`` readback (nft v1.1.6) -- the emission MUST equal the readback or
``--plan`` diffs an applied ruleset forever.  HMARK maps xt's hash to nft
``jhash``: the DISTRIBUTION, not the exact mark value (the recent/hashlimit
bar); the refusal tests pin the fail-open guards (a per-field mask jhash
cannot express, an unhashable tuple field) the dichotomy gate cannot see.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.backend.nft import build_verdict
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.rules import RenderedOption
from pyferm.scope import OptionKind

if TYPE_CHECKING:
    from pyferm.values import Value


def _opt(name: str, value: Value, module: str) -> RenderedOption:
    return RenderedOption(
        name=name, value=value, kind=OptionKind.OPTION, module=module
    )


def _connsecmark(*flags: str, domain: Family = Family.IP) -> str:
    companions = {flag: _opt(flag, None, "CONNSECMARK") for flag in flags}
    return build_verdict(
        domain, "mangle", "jump", "CONNSECMARK", companions
    ).to_text()


def _hmark(opts: dict[str, str], *, domain: Family = Family.IP) -> str:
    companions = {
        name.replace("_", "-"): _opt(name.replace("_", "-"), value, "HMARK")
        for name, value in opts.items()
    }
    return build_verdict(
        domain, "mangle", "jump", "HMARK", companions
    ).to_text()


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
