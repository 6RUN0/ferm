"""negate_value rejects double negation, arrays, and named sets."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyferm.errors import FermError
from pyferm.values import Negated, PreNegated, SetRef, Value, negate_value


@given(st.text(max_size=6))
def test_double_negation_always_rejected(scalar: str) -> None:
    once = negate_value(scalar)
    assert isinstance(once, (Negated, PreNegated))
    with pytest.raises(FermError, match=r"double negation is not allowed"):
        negate_value(once)
    with pytest.raises(FermError, match=r"double negation is not allowed"):
        negate_value(negate_value(scalar, klass="pre_negated"))


@given(st.lists(st.text(max_size=4), min_size=1, max_size=4))
def test_negate_rejects_array_and_named_set(elements: list[Value]) -> None:
    # The other two reject branches of negate_value, kept out of the scalar
    # property above: a bare array (without allow_array) and a named set.
    with pytest.raises(FermError, match=r"negate an array"):
        negate_value(elements)
    with pytest.raises(FermError, match=r"negate a named set"):
        negate_value(SetRef("s", elements))
