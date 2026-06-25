"""Validators never let a separator/injection byte through (always-reject)."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyferm.backend.iptables import _validate_chain_name, _validate_table_name
from pyferm.backend.nft import _nft_quote_string
from pyferm.errors import FermError

_IPT_BAD = st.sampled_from(list(" :*[") + [chr(c) for c in range(0x20)])
_NAME = st.text(st.characters(min_codepoint=33, max_codepoint=122), max_size=8)


@given(prefix=_NAME, bad=_IPT_BAD, suffix=_NAME)
def test_ipt_chain_name_rejects_any_separator(
    prefix: str, bad: str, suffix: str
) -> None:
    with pytest.raises(FermError):
        _validate_chain_name(prefix + bad + suffix)


@given(prefix=_NAME, bad=_IPT_BAD, suffix=_NAME)
def test_ipt_table_name_rejects_any_separator(
    prefix: str, bad: str, suffix: str
) -> None:
    with pytest.raises(FermError):
        _validate_table_name(prefix + bad + suffix)


@given(text=st.text(min_size=1, max_size=12))
def test_nft_quote_never_returns_unquotable(text: str) -> None:
    try:
        out = _nft_quote_string(text)
    except FermError:
        return  # rejection is the safe outcome
    assert '"' not in out[1:-1]
    assert "\\" not in out
