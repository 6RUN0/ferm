"""
Unit matrix for the batch-10 nft vocabulary (helper / CT-target / nth).

Every emitted spelling below was captured from a live ``nft list ruleset``
readback (nft v1.1.6) -- the emission MUST equal the readback or ``--plan``
diffs an applied ruleset forever.  The refusal tests pin the fail-open
guards the dichotomy gate cannot see (it accepts any non-empty translation,
so a silently-dropped CT option or per-counter nth state would pass it).
"""

from __future__ import annotations

import pytest

from pyferm.backend.nft import (
    build_verdict,
    translate_match,
    translate_rule,
)
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.rules import RenderedOption, RenderedRule
from pyferm.scope import OptionKind
from pyferm.values import Negated, Value


def _opt(
    name: str,
    value: Value,
    kind: OptionKind = OptionKind.OPTION,
    module: str | None = None,
) -> RenderedOption:
    return RenderedOption(name=name, value=value, kind=kind, module=module)


def _rule(*options: RenderedOption) -> RenderedRule:
    return RenderedRule(options=list(options), script=None)


def _target(value: str) -> RenderedOption:
    return _opt("jump", value, kind=OptionKind.TARGET)


def _texts(rule_options: list[RenderedOption], domain: Family) -> list[str]:
    nft = translate_rule(domain, "filter", _rule(*rule_options))
    return [s.to_text() for s in nft.statements]


def _ct(companions: dict[str, RenderedOption]) -> str:
    return build_verdict(Family.IP, "raw", "jump", "CT", companions).to_text()


def _ct_opt(name: str, value: Value) -> RenderedOption:
    return _opt(name, value, module="CT")


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


@pytest.mark.parametrize("unsupported", ["helper", "expevents", "timeout"])
def test_ct_object_options_refused(unsupported: str) -> None:
    with pytest.raises(
        FermError, match=rf"^CT target option '{unsupported}' not yet"
    ):
        _ct({unsupported: _ct_opt(unsupported, "x")})


def test_ct_refusal_short_circuits_translatable_sibling() -> None:
    # `CT helper ftp zone 1`: the unsupported helper must refuse UP FRONT --
    # emitting `ct zone set 1` and dropping the helper would be a fail-open
    # mangle (the firewall silently loses the helper assignment).
    with pytest.raises(FermError, match=r"^CT target option 'helper' not yet"):
        _ct(
            {
                "helper": _ct_opt("helper", "ftp"),
                "zone": _ct_opt("zone", "1"),
            }
        )
