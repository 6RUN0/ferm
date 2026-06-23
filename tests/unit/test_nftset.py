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
