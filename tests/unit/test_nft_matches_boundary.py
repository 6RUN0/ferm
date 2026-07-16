"""nft match-operand boundary canonicalization."""

from __future__ import annotations

import pytest

from pyferm.backend.nft.matches import _uint_or_range
from pyferm.errors import FermError


def test_uint_or_range_accepts_low_equal_to_maximum() -> None:
    """
    A range whose bound equals the field maximum is in-range, not over.

    The overflow guard rejects only values strictly greater than the
    field width; ``maximum:maximum`` is the last legal range and must
    canonicalize to the dash form rather than refuse.
    """
    assert _uint_or_range("icmp type", "255:255", 255) == "255-255"


def test_uint_or_range_rejects_low_above_maximum() -> None:
    """A range whose low bound exceeds the maximum refuses by name."""
    with pytest.raises(FermError, match="invalid icmp type '256:256'"):
        _uint_or_range("icmp type", "256:256", 255)
