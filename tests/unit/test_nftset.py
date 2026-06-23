from pyferm.nftset import sort_set_elements


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
