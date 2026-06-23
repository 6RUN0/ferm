"""
Canonical ordering of anonymous-set elements (shared, leaf module).

Both the nft backend emitter and the plan canonicalizer order set elements
through this single function so the two diff sides converge byte-for-byte.
The order is non-semantic for nft (a set is an unordered union), so sorting
the human-facing output costs nothing and buys determinism.
"""

from __future__ import annotations

import ipaddress

RANK_NUMBER = 0
RANK_INTERVAL = 1
RANK_ADDRESS = 2
RANK_UNPARSABLE = 3


def _classify_address_range(
    low: str, high: str
) -> tuple[int, int, int] | None:
    """
    Return ``(version, low, high)`` if ``low``-``high`` is an address range.

    Both ends must be bare host addresses of the same family (nft has no
    cross-family interval).  ``ip_address`` rejects CIDRs, empty strings and
    any further dash, so a malformed end returns ``None`` and the caller drops
    the token to the unparsable bucket.
    """
    try:
        lo = ipaddress.ip_address(low)
        hi = ipaddress.ip_address(high)
    except ValueError:
        return None
    if lo.version != hi.version:
        return None
    return lo.version, int(lo), int(hi)


def classify(element: str) -> tuple[int, object]:
    """
    Return (rank, natural-key) for one element; rank groups like with like.

    ``str.isdigit()`` is True for non-ASCII digits (``"²"``) that ``int`` then
    rejects, so every numeric branch guards with ``isascii()`` -- an
    unconvertible element drops to the unparsable bucket instead of crashing
    the whole sort (runs on unvalidated kernel-side text via the plan canon).

    A dashed token is an interval: a numeric port range (``1024-2048``) or an
    address range (``10.0.0.0-10.0.0.255``).  Both need ``flags interval`` on
    the nft set and a stable order against a kernel readback, so neither may
    fall to the unparsable bucket.
    """
    if element.isascii() and element.isdigit():
        return RANK_NUMBER, int(element)
    low, dash, high = element.partition("-")
    if dash:
        if (
            low.isascii()
            and low.isdigit()
            and high.isascii()
            and high.isdigit()
        ):
            return RANK_INTERVAL, (int(low), int(high))
        address_range = _classify_address_range(low, high)
        if address_range is not None:
            return RANK_INTERVAL, address_range
    try:
        net = ipaddress.ip_network(element, strict=False)
    except ValueError:
        return RANK_UNPARSABLE, ()
    return RANK_ADDRESS, (
        net.version,
        int(net.network_address),
        net.prefixlen,
    )


def sort_set_elements(elements: list[str]) -> list[str]:
    """Return *elements* in the one canonical order (see module docstring)."""

    def key(item: tuple[int, str]) -> tuple[object, ...]:
        index, element = item
        rank, natural = classify(element)
        if rank == RANK_UNPARSABLE:
            # Keep unparsable elements last, in original order (stable).
            return (rank, index)
        return (rank, natural, element)

    return [element for _, element in sorted(enumerate(elements), key=key)]
