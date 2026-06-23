"""
Canonical ordering and form of set elements (shared, leaf module).

Two concerns live here, both keyed off the one :func:`classify` ranking:

* :func:`sort_set_elements` orders elements deterministically.  The nft
  emitter uses it so the generated script is stable; order is non-semantic
  for nft (a set is an unordered union), so the sort costs nothing.
* :func:`canonicalize_set_elements` additionally rewrites each element to the
  textual form the kernel stores on readback (a prefix-aligned range collapses
  to a CIDR, host bits are masked, a ``/32``-``/128`` host loses its prefix,
  an address is lower-cased and zero-compressed).  The plan diff compares
  element strings, so both diff sides must pass through it or an unchanged set
  reads as a perpetual modification.
"""

from __future__ import annotations

import ipaddress

RANK_NUMBER = 0
RANK_INTERVAL = 1
RANK_ADDRESS = 2
RANK_PROTONAME = 3
RANK_UNPARSABLE = 4

#: nft canonical L4-protocol keyword -> IP protocol number.  nft stores a
#: ``meta l4proto`` / ``inet_proto`` set member as its *name* but orders the
#: set by protocol *number* on readback (``{ udp, tcp }`` -> ``{ tcp, udp }``),
#: so the sorter must key these names by number to match the kernel form.
#: Spellings and numbers are nft's own (verified against nft v1.1.6); a name
#: nft does not know cannot survive a readback, so it stays unparsable.
_NFT_L4PROTO_NUMBER: dict[str, int] = {
    "icmp": 1,
    "igmp": 2,
    "ipencap": 4,
    "tcp": 6,
    "egp": 8,
    "udp": 17,
    "dccp": 33,
    "ipv6": 41,
    "rsvp": 46,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "ipv6-icmp": 58,
    "ospf": 89,
    "mtp": 92,
    "ipip": 94,
    "pim": 103,
    "ipcomp": 108,
    "carp": 112,
    "l2tp": 115,
    "sctp": 132,
    "mobility-header": 135,
    "udplite": 136,
    "mpls-in-ip": 137,
}

#: Inverse of :data:`_NFT_L4PROTO_NUMBER` (number -> canonical nft name).
#: nft reads a numeric ``meta l4proto`` operand back as its name (``6`` ->
#: ``tcp``), so the emitter normalizes a known number to the name the kernel
#: will store; a number with no well-known name has none and stays numeric.
_NFT_L4PROTO_NAME: dict[int, str] = {
    number: name for name, number in _NFT_L4PROTO_NUMBER.items()
}


def l4proto_name(proto: str) -> str:
    """
    Map a numeric L4 protocol to the nft name the kernel stores it as.

    ``meta l4proto 6`` reads back from the kernel as ``meta l4proto tcp``, so a
    desired side keeping the number shows a phantom ``--plan`` change.  A known
    number folds to its name; a name, a range, or an unknown number is returned
    verbatim (nft keeps an unknown number numeric).
    """
    if proto.isascii() and proto.isdigit():
        return _NFT_L4PROTO_NAME.get(int(proto), proto)
    return proto


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

    A known L4-protocol *name* (``tcp``, ``udp``) gets its own rank keyed by
    protocol number: nft orders a ``meta l4proto`` set by number while storing
    names, so without this a folded ``{ udp, tcp }`` would read back reordered
    and show a phantom plan change.
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
        proto_number = _NFT_L4PROTO_NUMBER.get(element)
        if proto_number is not None:
            return RANK_PROTONAME, proto_number
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


def sort_vmap_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """
    Return verdict-map ``(key, verdict)`` pairs in canonical key order.

    nft stores a ``vmap`` ordered by its key exactly as it orders a set
    (verified on the kernel readback), so the key reuses :func:`classify`
    while the verdict travels with it.  A pair whose key is unparsable stays
    last in input order (stable), matching :func:`sort_set_elements`.
    """

    def key(item: tuple[int, tuple[str, str]]) -> tuple[object, ...]:
        index, (element, _verdict) = item
        rank, natural = classify(element)
        if rank == RANK_UNPARSABLE:
            return (rank, index)
        return (rank, natural, element)

    return [pair for _, pair in sorted(enumerate(pairs), key=key)]


def _nft_network_text(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> str:
    """Spell a network the way nft stores it: a host loses its full prefix."""
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def _collapse_address_range(low: str, high: str) -> str | None:
    """
    Spell an address range as nft stores it, or ``None`` if it is not one.

    A range that is exactly one power-of-two block aligned to its size
    collapses to a CIDR (a single-host block drops its prefix); any other
    span keeps canonical endpoints ``lo-hi``.  A malformed, cross-family or
    reversed range returns ``None`` so the caller leaves the token verbatim
    (nft rejects it at apply; the canon must not crash on kernel text).
    """
    try:
        lo = ipaddress.ip_address(low)
        hi = ipaddress.ip_address(high)
    except ValueError:
        return None
    if lo.version != hi.version or int(hi) < int(lo):
        return None
    size = int(hi) - int(lo) + 1
    aligned_block = (size & (size - 1)) == 0 and int(lo) % size == 0
    if not aligned_block:
        return f"{lo}-{hi}"
    prefixlen = lo.max_prefixlen - (size.bit_length() - 1)
    if prefixlen == lo.max_prefixlen:
        return str(lo)
    return f"{lo}/{prefixlen}"


def canonicalize_element(element: str) -> str:
    """
    Rewrite one element to the textual form nft stores it as on readback.

    A prefix-aligned address range collapses to a CIDR
    (``10.0.0.0-10.0.0.255`` -> ``10.0.0.0/24``); a non-aligned range keeps
    canonical endpoints (``10.2.0.1-10.2.0.10``); a CIDR's host bits are masked
    and a single-host ``/32``/``/128`` drops its prefix; an address is
    lower-cased and zero-compressed.  Numeric port ranges and unparsable tokens
    are left verbatim.  Total (never raises): runs on unvalidated kernel text.
    """
    rank, _ = classify(element)
    if rank == RANK_INTERVAL:
        low, _, high = element.partition("-")
        if low.isascii() and low.isdigit():
            return element  # numeric port range: nft keeps it verbatim
        collapsed = _collapse_address_range(low, high)
        return collapsed if collapsed is not None else element
    if rank == RANK_ADDRESS:
        try:
            return _nft_network_text(
                ipaddress.ip_network(element, strict=False)
            )
        except ValueError:
            return element
    return element


def _drop_contained_networks(canonical: list[str]) -> list[str]:
    """
    Drop any address element wholly contained in another (nft absorbs it).

    nft accepts an anonymous set with a host inside a prefix (or a prefix
    inside a wider prefix), then reads back only the containing block
    (``{ 10.0.0.0/24, 10.0.0.5 }`` -> ``{ 10.0.0.0/24 }``); ``nft -c`` does not
    reject this for anonymous sets, so without mirroring the absorption the
    desired side keeps an element the kernel side can never have -- a perpetual
    phantom diff.  Only ``ip_network``-parsable elements participate; a port
    range or protocol name is not a network and is left untouched.  Equal
    canonical forms are already deduped upstream, so a kept network is never a
    duplicate of the one that covers it.
    """
    v4: dict[str, ipaddress.IPv4Network] = {}
    v6: dict[str, ipaddress.IPv6Network] = {}
    for elem in canonical:
        try:
            net = ipaddress.ip_network(elem, strict=False)
        except ValueError:
            continue  # port range / protocol name / unparsable: not a network
        if isinstance(net, ipaddress.IPv4Network):
            v4[elem] = net
        else:
            v6[elem] = net
    kept: list[str] = []
    for elem in canonical:
        v4net = v4.get(elem)
        if v4net is not None and any(
            other is not v4net and v4net.subnet_of(other)
            for other in v4.values()
        ):
            continue  # a wider v4 element already covers this one
        v6net = v6.get(elem)
        if v6net is not None and any(
            other is not v6net and v6net.subnet_of(other)
            for other in v6.values()
        ):
            continue  # a wider v6 element already covers this one
        kept.append(elem)
    return kept


def canonicalize_set_elements(
    elements: list[str], *, absorb_contained: bool = True
) -> list[str]:
    """
    Rewrite each element to nft's stored form, dedup, then order canonically.

    Two distinct source spellings can collapse to one kernel form
    (``10.0.0.0-10.0.0.255`` and ``10.0.0.0/24``); a set is a union, so the
    kernel readback holds one.  Deduping keeps the desired side from carrying
    a phantom duplicate the current side can never have.

    ``absorb_contained`` mirrors the kernel's *anonymous*-set absorption (a
    host inside a prefix, a prefix inside a wider one is silently swallowed)
    via :func:`_drop_contained_networks`.  A *named* interval set does the
    opposite: nft rejects the overlap (``conflicting intervals``) rather than
    absorbing it, so the named-set diff side passes ``absorb_contained=False``
    to keep both elements.  That matches the emitter (which never absorbs) and
    lets the ``nft -c`` precheck surface the bad config rather than a false
    'no changes'.
    """
    canonical = list(dict.fromkeys(canonicalize_element(e) for e in elements))
    if absorb_contained:
        canonical = _drop_contained_networks(canonical)
    return sort_set_elements(canonical)
