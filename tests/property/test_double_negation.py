"""negate_value rejects double negation on any wrapped scalar."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyferm.errors import FermError
from pyferm.values import Negated, PreNegated, negate_value


@given(st.text(max_size=6))
def test_double_negation_always_rejected(scalar: str) -> None:
    once = negate_value(scalar)
    assert isinstance(once, (Negated, PreNegated))
    with pytest.raises(FermError, match="double negation"):
        negate_value(once)
    with pytest.raises(FermError, match="double negation"):
        negate_value(negate_value(scalar, klass="pre_negated"))
