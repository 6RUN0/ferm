"""Unit tests for :mod:`pyferm.resolver`.

Covers the numeric-address classifier, the Net::DNS-style IPv6 expansion,
zone-file parsing, and the ``resolve`` control flow: family-default record
type, the numeric fast-path family filter, the silent NXDOMAIN/NOERROR
skips, the empty-result (zero elements) case, and the NS/MX two-pass
resolution.  Also covers resolver selection (``pick_resolver``) and the
dnspython adapter (``SystemResolver``) against a stubbed ``dns.resolver``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.errors import FermError
from pyferm.resolver import (
    SystemResolver,
    ZonefileResolver,
    identify_numeric_address,
    pick_resolver,
    resolve,
    set_resolver_provider,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from pyferm.resolver import SearchResult
    from pyferm.values import Value

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
    names: list[Value] = ["v4.example.com", "ds.example.com"]
    assert resolve("ip", names, resolver=zone) == ["192.0.2.1", "192.0.2.2"]


def test_resolve_numeric_fast_path_filters_family(
    zone: ZonefileResolver,
) -> None:
    # Right family survives untouched; wrong family is dropped.
    assert resolve("ip", "203.0.113.5", resolver=zone) == ["203.0.113.5"]
    assert resolve("ip6", "203.0.113.5", resolver=zone) == []


def test_resolve_numeric_ipv6_passes_through_uncompressed(
    zone: ZonefileResolver,
) -> None:
    # A numeric literal is NOT normalized, unlike a resolved record.
    assert resolve("ip6", "2001:db8::1", resolver=zone) == ["2001:db8::1"]


def test_resolve_nxdomain_is_silent(zone: ZonefileResolver) -> None:
    assert resolve("ip", "nonexistent.example.com", resolver=zone) == []


def test_resolve_noerror_wrong_type_is_silent(
    zone: ZonefileResolver,
) -> None:
    # Name exists (TXT) but has no A record: NOERROR, skipped silently.
    assert resolve("ip", "txt.example.com", resolver=zone) == []


def test_resolve_other_errorstring_raises() -> None:
    class FailingResolver:
        def search(self, _hostname: str, _rrtype: str) -> object:
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
        resolve("ip", "v4.example.com", ["A"], resolver=zone)


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


def test_pick_resolver_production_path_is_system() -> None:
    # Without --test ferm queries live DNS (Perl pick_resolver, :1286).
    assert isinstance(pick_resolver(False, "rules/main.ferm"), SystemResolver)


def test_pick_resolver_test_reads_zonefile_next_to_script(
    tmp_path: Path,
) -> None:
    # Under --test the zonefile lives in the *script's* directory (Perl
    # m,^(.*/), on the current script path), so an @include'd file in
    # another directory resolves against its own zonefile.
    (tmp_path / "zonefile").write_text(
        "h.example.com. IN A 192.0.2.9\n", encoding="utf-8"
    )
    resolver = pick_resolver(True, str(tmp_path / "main.ferm"))
    assert resolve("ip", "h.example.com", resolver=resolver) == ["192.0.2.9"]


def test_pick_resolver_relative_script_reads_cwd_zonefile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A script path without a directory part falls back to ./zonefile.
    # The zonefile read is intercepted instead of chdir'ing into a
    # tmp dir: mutmut's trampoline resolves the relative source_paths
    # config against the cwd and breaks under a chdir'd test.
    seen: list[str] = []

    def fake_from_file(path: str) -> ZonefileResolver:
        seen.append(path)
        return ZonefileResolver.from_text("h.example.com. IN A 192.0.2.10\n")

    monkeypatch.setattr(
        "pyferm.resolver.ZonefileResolver.from_file", fake_from_file
    )
    resolver = pick_resolver(True, "main.ferm")
    assert seen == ["./zonefile"]
    assert resolve("ip", "h.example.com", resolver=resolver) == ["192.0.2.10"]


def test_pick_resolver_missing_zonefile_is_fatal(tmp_path: Path) -> None:
    with pytest.raises(FermError, match="Failed to read zonefile"):
        pick_resolver(True, str(tmp_path / "main.ferm"))


def _system_search(
    monkeypatch: pytest.MonkeyPatch, outcome: Callable[[], list[str]]
) -> tuple[SearchResult, tuple[object, ...]]:
    """Run ``SystemResolver.search`` against a stubbed ``dns.resolver``."""
    import dns.resolver

    seen: list[tuple[object, ...]] = []

    def fake_resolve(
        hostname: str, rrtype: str, search: bool = False
    ) -> list[str]:
        seen.append((hostname, rrtype, search))
        return outcome()

    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    return SystemResolver().search("h.example.com", "A"), seen[0]


def test_system_resolver_maps_answer_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, call = _system_search(monkeypatch, lambda: ["192.0.2.7"])
    assert result.found is True
    assert [(rr.type, rr.data) for rr in result.answer] == [("A", "192.0.2.7")]
    assert result.errorstring == "NOERROR"
    # search=True honours the resolv.conf search list, like Perl's
    # $res->search (as opposed to ->query).
    assert call == ("h.example.com", "A", True)


def test_system_resolver_nxdomain_is_silent_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A missing name must map to the "NXDOMAIN" errorstring that resolve()
    # skips silently -- not to a fatal DNS failure.
    def raise_nxdomain() -> list[str]:
        import dns.resolver

        raise dns.resolver.NXDOMAIN

    result, _ = _system_search(monkeypatch, raise_nxdomain)
    assert (result.found, result.answer) == (False, [])
    assert result.errorstring == "NXDOMAIN"


def test_system_resolver_no_answer_is_silent_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A name that exists without the queried type behaves like the mock's
    # NOERROR case: the host is skipped, the run continues.
    def raise_no_answer() -> list[str]:
        import dns.resolver

        raise dns.resolver.NoAnswer

    result, _ = _system_search(monkeypatch, raise_no_answer)
    assert (result.found, result.answer) == (False, [])
    assert result.errorstring == "NOERROR"


def test_system_resolver_failure_carries_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Any other DNS failure keeps its message, which resolve() turns into
    # a fatal "DNS query ... failed" -- a transient resolver outage must
    # abort the run instead of silently dropping firewall rules.
    def raise_failure() -> list[str]:
        import dns.exception

        # dnspython's DNSException.__init__ is untyped.
        raise dns.exception.DNSException(  # type: ignore[no-untyped-call]
            "connection timed out"
        )

    result, _ = _system_search(monkeypatch, raise_failure)
    assert result.found is False
    assert result.errorstring == "connection timed out"
