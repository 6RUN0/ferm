"""
Canonical ordering of anonymous-set elements (shared, leaf module).

Both the nft backend emitter and the plan canonicalizer order set elements
through this single function so the two diff sides converge byte-for-byte.
The order is non-semantic for nft (a set is an unordered union), so sorting
the human-facing output costs nothing and buys determinism.
"""

from __future__ import annotations

import ipaddress

_RANK_NUMBER = 0
_RANK_INTERVAL = 1
_RANK_ADDRESS = 2
_RANK_UNPARSABLE = 3


def _classify(element: str) -> tuple[int, object]:
    """
    Return (rank, natural-key) for one element; rank groups like with like.

    ``str.isdigit()`` is True for non-ASCII digits (``"²"``) that ``int`` then
    rejects, so every numeric branch guards with ``isascii()`` -- an
    unconvertible element drops to the unparsable bucket instead of crashing
    the whole sort (runs on unvalidated kernel-side text via the plan canon).
    """
    if element.isascii() and element.isdigit():
        return _RANK_NUMBER, int(element)
    low, dash, high = element.partition("-")
    if (
        dash
        and low.isascii()
        and low.isdigit()
        and high.isascii()
        and high.isdigit()
    ):
        return _RANK_INTERVAL, (int(low), int(high))
    try:
        net = ipaddress.ip_network(element, strict=False)
    except ValueError:
        return _RANK_UNPARSABLE, ()
    return _RANK_ADDRESS, (
        net.version,
        int(net.network_address),
        net.prefixlen,
    )


def sort_set_elements(elements: list[str]) -> list[str]:
    """Return *elements* in the one canonical order (see module docstring)."""

    def key(item: tuple[int, str]) -> tuple[object, ...]:
        index, element = item
        rank, natural = _classify(element)
        if rank == _RANK_UNPARSABLE:
            # Keep unparsable elements last, in original order (stable).
            return (rank, index)
        return (rank, natural, element)

    return [element for _, element in sorted(enumerate(elements), key=key)]
