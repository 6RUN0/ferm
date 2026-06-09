"""Unit tests for :mod:`pyferm.resolver`.

Covers the numeric-address classifier, the Net::DNS-style IPv6 expansion,
zone-file parsing, and the ``resolve`` control flow: family-default record
type, the numeric fast-path family filter, the silent NXDOMAIN/NOERROR
skips, the empty-result ``[[]]`` sentinel, and the NS/MX two-pass
resolution.
"""

from __future__ import annotations

import pytest

from pyferm.errors import FermError
from pyferm.resolver import (
    ZonefileResolver,
    identify_numeric_address,
    resolve,
    set_resolver_provider,
)

_ZONE = """\
v4.example.com.        IN A    192.0.2.1
v6.example.com.        IN AAAA 2001:db8::1
txt.example.com.       IN TXT  "no A or AAAA here"
ds.example.com.        IN A    192.0.2.2
ds.example.com.        IN AAAA 2001:db8::2
ds-rr.example.com.     IN A    192.0.2.3
ds-rr.example.com.     IN A    192.0.2.4
ns.example.com         IN NS   ds.example.com.
mx.example.com         IN MX   10 ds.example.com.
"""


@pytest.fixture
def zone() -> ZonefileResolver:
    return ZonefileResolver.from_text(_ZONE)


def test_identify_numeric_address_ipv4() -> None:
    assert identify_numeric_address("192.0.2.1") == "A"
    assert identify_numeric_address("192.0.2.0/24") == "A"  # netmask stripped


def test_identify_numeric_address_ipv6() -> None:
    assert identify_numeric_address("2001:db8::1") == "AAAA"
    assert identify_numeric_address("::1") == "AAAA"
    assert identify_numeric_address("2001:db8::/32") == "AAAA"


def test_identify_numeric_address_hostname_is_none() -> None:
    assert identify_numeric_address("v4.example.com") is None
    assert identify_numeric_address("not-an-ip") is None


def test_resolve_a_record(zone: ZonefileResolver) -> None:
    assert resolve("ip", "v4.example.com", resolver=zone) == ["192.0.2.1"]


def test_resolve_defaults_to_aaaa_for_ip6_and_expands(
    zone: ZonefileResolver,
) -> None:
    # Net::DNS textual form: fully expanded, leading zeros stripped.
    assert resolve("ip6", "v6.example.com", resolver=zone) == [
        "2001:db8:0:0:0:0:0:1"
    ]


def test_resolve_explicit_type_overrides_family(
    zone: ZonefileResolver,
) -> None:
    assert resolve("ip6", "ds.example.com", "A", resolver=zone) == [
        "192.0.2.2"
    ]


def test_resolve_multiple_records_keep_order(
    zone: ZonefileResolver,
) -> None:
    assert resolve("ip", "ds-rr.example.com", resolver=zone) == [
        "192.0.2.3",
        "192.0.2.4",
    ]


def test_resolve_array_argument(zone: ZonefileResolver) -> None:
    names = ["v4.example.com", "ds.example.com"]
    assert resolve("ip", names, resolver=zone) == ["192.0.2.1", "192.0.2.2"]


def test_resolve_numeric_fast_path_filters_family(
    zone: ZonefileResolver,
) -> None:
    # Right family survives untouched; wrong family is dropped.
    assert resolve("ip", "203.0.113.5", resolver=zone) == ["203.0.113.5"]
    assert resolve("ip6", "203.0.113.5", resolver=zone) == [[]]


def test_resolve_numeric_ipv6_passes_through_uncompressed(
    zone: ZonefileResolver,
) -> None:
    # A numeric literal is NOT normalized, unlike a resolved record.
    assert resolve("ip6", "2001:db8::1", resolver=zone) == ["2001:db8::1"]


def test_resolve_nxdomain_is_silent(zone: ZonefileResolver) -> None:
    assert resolve("ip", "nonexistent.example.com", resolver=zone) == [[]]


def test_resolve_noerror_wrong_type_is_silent(
    zone: ZonefileResolver,
) -> None:
    # Name exists (TXT) but has no A record: NOERROR, skipped silently.
    assert resolve("ip", "txt.example.com", resolver=zone) == [[]]


def test_resolve_other_errorstring_raises() -> None:
    class FailingResolver:
        def search(self, hostname: str, rrtype: str) -> object:
            from pyferm.resolver import SearchResult

            return SearchResult(False, [], "SERVFAIL")

    with pytest.raises(FermError, match="DNS query for 'h' failed: SERVFAIL"):
        resolve("ip", "h", resolver=FailingResolver())  # type: ignore[arg-type]


def test_resolve_ns_two_pass(zone: ZonefileResolver) -> None:
    # NS -> ds.example.com -> A record (ip family).
    result = resolve("ip", "ns.example.com", "NS", resolver=zone)
    assert result == ["192.0.2.2"]


def test_resolve_mx_two_pass_aaaa(zone: ZonefileResolver) -> None:
    assert resolve("ip6", "mx.example.com", "MX", resolver=zone) == [
        "2001:db8:0:0:0:0:0:2"
    ]


def test_resolve_rejects_non_string_type(zone: ZonefileResolver) -> None:
    with pytest.raises(FermError, match="String expected"):
        resolve("ip", "v4.example.com", ["A"], resolver=zone)  # type: ignore[arg-type]


def test_resolve_uses_installed_provider() -> None:
    zone = ZonefileResolver.from_text(_ZONE)
    set_resolver_provider(lambda: zone)
    try:
        assert resolve("ip", "v4.example.com") == ["192.0.2.1"]
    finally:
        set_resolver_provider(None)


def test_resolve_without_provider_errors() -> None:
    set_resolver_provider(None)
    with pytest.raises(FermError, match="no resolver provider"):
        resolve("ip", "v4.example.com")
