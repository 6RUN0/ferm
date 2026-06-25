"""Frozen value objects: replace round-trips and rebind raises."""

from __future__ import annotations

import dataclasses
from typing import cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyferm.values import Multi, Negated, Params, SetRef, Value

_SCALARS = st.text(max_size=6)
_LISTS = st.lists(_SCALARS, max_size=4)


@given(_SCALARS)
def test_negated_round_trip(value: str) -> None:
    obj = Negated(value)
    assert dataclasses.replace(obj) == obj
    with pytest.raises(dataclasses.FrozenInstanceError):
        obj.value = "other"  # type: ignore[misc]


@given(_LISTS)
def test_multi_round_trip_and_binding_frozen(values: list[str]) -> None:
    obj = Multi(cast("list[Value]", values))
    assert dataclasses.replace(obj) == obj
    with pytest.raises(dataclasses.FrozenInstanceError):
        obj.values = []  # type: ignore[misc]


@given(st.text(max_size=6), _LISTS)
def test_setref_round_trip(name: str, elements: list[str]) -> None:
    obj = SetRef(name, cast("list[Value]", elements))
    assert dataclasses.replace(obj) == obj
    with pytest.raises(dataclasses.FrozenInstanceError):
        obj.elements = []  # type: ignore[misc]


@given(_LISTS)
def test_params_round_trip(values: list[str]) -> None:
    obj = Params(cast("list[Value]", values))
    assert dataclasses.replace(obj) == obj
    with pytest.raises(dataclasses.FrozenInstanceError):
        obj.values = []  # type: ignore[misc]
