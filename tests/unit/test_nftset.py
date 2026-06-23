from pyferm.nftset import (
    RANK_ADDRESS,
    RANK_INTERVAL,
    RANK_UNPARSABLE,
    canonicalize_element,
    canonicalize_set_elements,
    classify,
    sort_set_elements,
)


def test_ports_sort_numerically_not_lexically() -> None:
    # "100" < "22" lexically but 22 < 100 numerically.
    assert sort_set_elements(["443", "22", "100", "80"]) == [
        "22",
        "80",
        "100",
        "443",
    ]


def test_intervals_sort_by_low_then_high() -> None:
    assert sort_set_elements(["1024-2048", "80", "22-23"]) == [
        "80",
        "22-23",
        "1024-2048",
    ]


def test_addresses_sort_by_value() -> None:
    assert sort_set_elements(["10.0.0.5", "10.0.0.1", "10.0.0.0/8"]) == [
        "10.0.0.0/8",
        "10.0.0.1",
        "10.0.0.5",
    ]


def test_unparsable_sort_last_preserving_order() -> None:
    # Protocol names are unparsable -> appended last in original order,
    # after the numeric "6".
    assert sort_set_elements(["udp", "6", "tcp"]) == ["6", "udp", "tcp"]


def test_is_pure_does_not_mutate_input() -> None:
    src = ["80", "22"]
    sort_set_elements(src)
    assert src == ["80", "22"]


def test_idempotent() -> None:
    once = sort_set_elements(["443", "22", "80"])
    assert sort_set_elements(once) == once


def test_unicode_digits_do_not_crash() -> None:
    # "²".isdigit() is True but int("²") raises; such elements (and interval
    # endpoints) must fall through to the unparsable bucket, never crash the
    # sort. Unparsable elements keep their original relative order.
    assert sort_set_elements(["1-²", "²", "5"]) == ["5", "1-²", "²"]


def test_interval_uses_first_dash_as_separator() -> None:
    # partition("-") takes the FIRST dash; rpartition("-") would take the last.
    # An element like "1-2-3" has two dashes: partition yields low="1",
    # high="2-3" (non-digit high -> unparsable bucket); rpartition yields
    # low="1-2" (non-digit low -> also unparsable). Both branches fail the
    # digit guard for different reasons, so the only observable difference is
    # that a proper interval "10-20" must not be reclassified as unparsable
    # when mixed with a host address that sorts before it.
    # Concrete: 10.0.0.1 (RANK_ADDRESS) must sort before an interval 10-20
    # (RANK_INTERVAL), and that in turn before unparsable.
    result = sort_set_elements(["10-20", "10.0.0.1", "5"])
    # 5 -> RANK_NUMBER (rank 0), 10-20 -> RANK_INTERVAL (rank 1),
    # 10.0.0.1 -> RANK_ADDRESS (rank 2).
    assert result == ["5", "10-20", "10.0.0.1"]


def test_host_address_with_host_bits_sorts_as_address() -> None:
    # strict=False means "10.0.0.1/8" is accepted and yields network
    # 10.0.0.0/8.  With strict=True or strict=None it raises ValueError and
    # the element falls to the unparsable bucket, causing wrong ordering.
    result = sort_set_elements(["10.0.0.1/8", "10.0.0.5", "80"])
    # 80 -> RANK_NUMBER, 10.0.0.1/8 and 10.0.0.5 -> RANK_ADDRESS.
    # 10.0.0.1/8 has network_address 10.0.0.0, prefixlen 8 -> sorts before
    # 10.0.0.5 (prefixlen 32, address 10.0.0.5).
    assert result[0] == "80"
    assert result[1] == "10.0.0.1/8"
    assert result[2] == "10.0.0.5"


def test_ipv4_address_range_classifies_as_interval() -> None:
    # An address range a-b (both ends host addresses) is an interval, not an
    # unparsable token: nft needs `flags interval` to hold it, and the order
    # must be stable against a kernel readback.
    rank, _ = classify("10.0.0.0-10.0.0.255")
    assert rank == RANK_INTERVAL


def test_ipv6_address_range_classifies_as_interval() -> None:
    rank, _ = classify("2001:db8::1-2001:db8::ff")
    assert rank == RANK_INTERVAL


def test_address_range_sorts_before_cidr_and_after_number() -> None:
    # RANK ordering: number (0) < interval (1) < address/CIDR (2).  A range
    # sorts before a bare CIDR even when its low address is numerically
    # larger, because the rank dominates the key.
    result = sort_set_elements(
        ["192.168.0.0/16", "10.0.0.0-10.0.0.255", "10.0.0.5"]
    )
    assert result == ["10.0.0.0-10.0.0.255", "10.0.0.5", "192.168.0.0/16"]


def test_address_ranges_sort_by_low_then_high() -> None:
    result = sort_set_elements(
        ["10.0.1.0-10.0.1.255", "10.0.0.0-10.0.0.255", "10.0.0.0-10.0.0.10"]
    )
    assert result == [
        "10.0.0.0-10.0.0.10",
        "10.0.0.0-10.0.0.255",
        "10.0.1.0-10.0.1.255",
    ]


def test_cross_version_range_is_unparsable() -> None:
    # A range whose ends are different families is not a valid nft interval;
    # it must not masquerade as one (fail-closed to the unparsable bucket).
    rank, _ = classify("10.0.0.0-2001:db8::1")
    assert rank == RANK_UNPARSABLE


def test_malformed_address_range_is_unparsable() -> None:
    # A non-address high end drops the whole token to the unparsable bucket
    # rather than crashing the sort (runs on unvalidated kernel-side text).
    assert classify("10.0.0.0-nonsense")[0] == RANK_UNPARSABLE
    assert classify("10.0.0.0-")[0] == RANK_UNPARSABLE
    assert classify("-10.0.0.0")[0] == RANK_UNPARSABLE


def test_bare_cidr_stays_address_not_interval() -> None:
    # A CIDR has no dash, so it remains RANK_ADDRESS; the set-level
    # flags-interval detection handles CIDR separately via the "/" check.
    assert classify("192.168.0.0/16")[0] == RANK_ADDRESS


# -- canonicalize_element: match nft's stored readback form -----------------
# nft normalizes set elements on readback; the plan diff compares element
# strings, so each side must canonicalize to the same form or an unchanged
# set reads as a perpetual modification.  Forms below were verified against
# real nft (`unshare -rn nft -f`): a prefix-aligned range collapses to CIDR,
# a non-aligned range is kept, host bits are masked, and a /32-/128 host
# loses its prefix.


def test_prefix_aligned_ipv4_range_collapses_to_cidr() -> None:
    assert canonicalize_element("10.0.0.0-10.0.0.255") == "10.0.0.0/24"
    assert canonicalize_element("10.1.0.0-10.1.1.255") == "10.1.0.0/23"


def test_prefix_aligned_ipv6_range_collapses_to_cidr() -> None:
    element = "2001:db8:2::-2001:db8:2:0:ffff:ffff:ffff:ffff"
    assert canonicalize_element(element) == "2001:db8:2::/64"


def test_non_aligned_range_keeps_canonical_endpoints() -> None:
    assert canonicalize_element("10.2.0.1-10.2.0.10") == "10.2.0.1-10.2.0.10"


def test_single_host_range_drops_prefix() -> None:
    # A range whose ends are equal is one /32 (/128) host; nft stores it as a
    # bare address, not `x/32`.
    assert canonicalize_element("10.0.5.5-10.0.5.5") == "10.0.5.5"
    assert canonicalize_element("2001:db8:9::-2001:db8:9::") == "2001:db8:9::"


def test_host_cidr_drops_prefix() -> None:
    assert canonicalize_element("10.0.0.5/32") == "10.0.0.5"
    assert canonicalize_element("2001:db8::5/128") == "2001:db8::5"


def test_cidr_host_bits_are_masked() -> None:
    assert canonicalize_element("10.3.0.5/24") == "10.3.0.0/24"


def test_address_is_lowercased_and_compressed() -> None:
    assert canonicalize_element("2001:DB8:0:0::1") == "2001:db8::1"


def test_bare_host_is_unchanged() -> None:
    assert canonicalize_element("172.16.0.5") == "172.16.0.5"


def test_numeric_port_range_is_left_verbatim() -> None:
    assert canonicalize_element("1024-2048") == "1024-2048"


def test_unparsable_element_is_left_verbatim() -> None:
    assert canonicalize_element("10.0.0.0-nonsense") == "10.0.0.0-nonsense"
    assert canonicalize_element('"eth0"') == '"eth0"'


def test_reversed_range_is_left_verbatim() -> None:
    # low > high cannot summarize; nft rejects it at apply, so leave it as-is
    # rather than crash the canon (runs on unvalidated kernel text).
    assert canonicalize_element("10.0.0.255-10.0.0.0") == "10.0.0.255-10.0.0.0"


def test_canonicalize_is_idempotent() -> None:
    # The kernel form is a fixed point: canon(canon(x)) == canon(x) on both
    # diff sides, so they settle instead of oscillating.
    for element in ("10.0.0.0-10.0.0.255", "10.0.0.5/32", "2001:DB8::1"):
        once = canonicalize_element(element)
        assert canonicalize_element(once) == once


def test_canonicalize_set_elements_canonicalizes_then_sorts() -> None:
    result = canonicalize_set_elements(
        ["192.168.0.0/16", "10.0.0.0-10.0.0.255", "10.0.0.5/32"]
    )
    # Range -> CIDR (rank address now), host /32 -> bare host, then ordered.
    assert result == ["10.0.0.0/24", "10.0.0.5", "192.168.0.0/16"]


def test_canonicalize_set_elements_dedups_colliding_forms() -> None:
    # A range and the CIDR it collapses to are one set member; the kernel
    # readback holds one, so the desired side must not carry both or it shows
    # a phantom "modify".
    result = canonicalize_set_elements(["10.0.0.0-10.0.0.255", "10.0.0.0/24"])
    assert result == ["10.0.0.0/24"]


def test_canonicalize_ipv4_mapped_ipv6_matches_ipaddress() -> None:
    # IPv4-mapped IPv6 keeps dotted-quad form; a regular embedded-v4 address
    # renders as hex.  Pin both so a future `ipaddress` change is caught
    # rather than silently re-introducing a phantom diff.
    assert canonicalize_element("::ffff:10.0.0.1") == "::ffff:10.0.0.1"
    assert canonicalize_element("64:ff9b::10.0.0.1") == "64:ff9b::a00:1"


def test_canonicalize_full_address_space_is_zero_prefix() -> None:
    assert canonicalize_element("0.0.0.0-255.255.255.255") == "0.0.0.0/0"
    assert canonicalize_element("0.0.0.0/0") == "0.0.0.0/0"
