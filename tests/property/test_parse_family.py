"""parse_family accepts exactly the four families, rejects all else."""

from __future__ import annotations

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from pyferm.domains import parse_family
from pyferm.errors import FermError

_FAMILIES = ("ip", "ip6", "arp", "eb")


@given(st.text(max_size=8))
@example("ip")
@example("ip6")
@example("arp")
@example("eb")
def test_parse_family_partition(name: str) -> None:
    if name in _FAMILIES:
        assert parse_family(name) == name
        assert parse_family(parse_family(name)) == name  # idempotent
    else:
        with pytest.raises(FermError):
            parse_family(name)
