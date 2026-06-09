"""Unit tests for :mod:`pyferm.values` (the value model + deferred layer).

Targets the documented Perl-isms: Perl truthiness vs Python, the uniform
splice in ``realize_deferred`` (including ``resolve``'s ``[[]]`` empty
case), and the negation rules.
"""

from __future__ import annotations

import pytest

from pyferm.errors import FermError
from pyferm.values import (
    Deferred,
    Multi,
    Negated,
    Params,
    PreNegated,
    Value,
    cat,
    contains_deferred,
    deferred_cat,
    eval_bool,
    flatten,
    format_bool,
    join_value,
    negate_value,
    perl_true,
    realize_deferred,
    to_array,
)


def test_perl_true_matches_perl_not_python() -> None:
    assert perl_true("0") is False
    assert perl_true("") is False
    assert perl_true(None) is False
    assert perl_true(0) is False
    # Only the exact "0"/"" strings are false; these are true in Perl.
    assert perl_true("0.0") is True
    assert perl_true("00") is True
    assert perl_true("x") is True
    assert perl_true([]) is True  # a ref is always true


def test_flatten_descends_arrays_but_keeps_other_refs() -> None:
    keep = Negated("x")
    assert flatten("a", ["b", ["c"]], keep) == ["a", "b", "c", keep]


def test_cat_concatenates_and_rejects_refs() -> None:
    assert cat("a", ["b", "c"], "d") == "abcd"
    with pytest.raises(FermError, match="String expected"):
        cat("a", Negated("b"))


def test_deferred_cat_realizes_then_concatenates() -> None:
    inner = Deferred(lambda _domain, *_a: ["X"], [])
    assert deferred_cat("ip", "a", inner, "b") == ["aXb"]


def test_join_value_scalar_array_and_negated() -> None:
    assert join_value(",", "x") == "x"
    assert join_value(",", ["a", "b", "c"]) == "a,b,c"
    assert join_value(",", Negated(["a", "b"])) == Negated("a,b")


def test_negate_value_default_and_pre_negated() -> None:
    assert negate_value("x") == Negated("x")
    assert negate_value("x", "pre_negated") == PreNegated("x")


def test_negate_value_rejects_double_negation() -> None:
    with pytest.raises(FermError, match="double negation"):
        negate_value(Negated("x"))
    with pytest.raises(FermError, match="double negation"):
        negate_value(PreNegated("x"))


def test_negate_value_array_needs_allow_flag() -> None:
    with pytest.raises(FermError, match="negate an array"):
        negate_value(["a", "b"])
    assert negate_value(["a", "b"], allow_array=True) == Negated(["a", "b"])


def test_format_bool_uses_perl_truthiness() -> None:
    assert format_bool(True) == "1"
    assert format_bool(False) == "0"
    assert format_bool("0") == "0"
    assert format_bool("x") == "1"


def test_to_array_scalar_list_and_deferred() -> None:
    assert to_array("x") == ["x"]
    assert to_array(["a", "b"]) == ["a", "b"]
    deferred = Deferred(lambda _d, *_a: [], [])
    assert to_array(deferred) == [deferred]


def test_to_array_rejects_other_refs() -> None:
    with pytest.raises(FermError):
        to_array(Negated("x"))


def test_eval_bool_scalar_and_array() -> None:
    assert eval_bool("0") is False
    assert eval_bool("x") is True
    assert eval_bool(None) is False
    assert eval_bool([]) is False
    assert eval_bool(["a"]) is True


def test_contains_deferred_recurses_into_arrays() -> None:
    deferred = Deferred(lambda _d, *_a: [], [])
    assert contains_deferred("a", deferred) is True
    assert contains_deferred("a", ["b", [deferred]]) is True
    assert contains_deferred("a", ["b", "c"]) is False


def test_realize_deferred_splices_results_uniformly() -> None:
    def addrs(_domain: str, *_args: Value) -> list[Value]:
        return ["1.2.3.4", "5.6.7.8"]

    assert realize_deferred("ip", Deferred(addrs, []), "tail") == [
        "1.2.3.4",
        "5.6.7.8",
        "tail",
    ]


def test_realize_deferred_recurses_into_params() -> None:
    def echo(_domain: str, *args: Value) -> list[Value]:
        return list(args)

    inner = Deferred(echo, ["a"])
    outer = Deferred(echo, [inner, "b"])
    assert realize_deferred("ip", outer) == ["a", "b"]


def test_realize_deferred_empty_resolve_keeps_empty_array() -> None:
    # resolve returns [[]] for "no records"; the element must survive as a
    # single empty array, not vanish (mirrors Perl ``return []``).
    empty = Deferred(lambda _d, *_a: [[]], [])
    assert realize_deferred("ip", empty) == [[]]


def test_value_wrappers_are_value_typed() -> None:
    # Smoke check the dataclasses construct and compare by value.
    assert Params(["a", "b"]) == Params(["a", "b"])
    assert Multi(["a"]) == Multi(["a"])
