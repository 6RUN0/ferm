"""Cartesian unfold: rule count equals array product, option order kept."""

from __future__ import annotations

import math

from hypothesis import given
from hypothesis import strategies as st

from pyferm.rules import RenderedRule, mkrules2
from pyferm.scope import Rule, append_option

_ARRAYS = st.lists(
    st.lists(
        st.text(
            alphabet=st.characters(min_codepoint=97, max_codepoint=122),
            max_size=3,
        ),
        min_size=1,
        max_size=3,
    ),
    min_size=1,
    max_size=3,
)


@given(_ARRAYS)
def test_unfold_count_and_order(arrays: list[list[str]]) -> None:
    rule = Rule()
    names = [f"opt{i}" for i in range(len(arrays))]
    for name, values in zip(names, arrays, strict=True):
        append_option(rule, name, list(values))
    out: list[RenderedRule] = []
    mkrules2("ip", out, rule)
    assert len(out) == math.prod(len(a) for a in arrays)
    for rendered in out:  # every leaf preserves the original option order
        assert [o.name for o in rendered.options] == names
