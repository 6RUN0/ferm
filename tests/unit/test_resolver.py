"""
Unit tests for :mod:`pyferm.resolver`.

Covers the numeric-address classifier, the Net::DNS-style IPv6 expansion,
zone-file parsing, and the ``resolve`` control flow: family-default record
type, the numeric fast-path family filter, the silent NXDOMAIN/NOERROR
skips, the empty-result (zero elements) case, and the NS/MX two-pass
resolution.  Also covers resolver selection (``pick_resolver``) and the
dnspython adapter (``SystemResolver``) against a stubbed ``dns.resolver``.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

import pytest

from pyferm.errors import FermError
from pyferm.resolver import (
    ResourceRecord,
    StubResolver,
    SystemResolver,
    ZonefileResolver,
    _canonical_name,
    _dnspython_available,
    _expand_ipv6,
    _make_record,
    _warn_stub_backend,
    identify_numeric_address,
    pick_resolver,
    resolve,
    set_resolver_provider,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
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


@pytest.fixture(autouse=True)
def _reset_backend_cache() -> Iterator[None]:
    _dnspython_available.cache_clear()
    _warn_stub_backend.cache_clear()
    yield
    _dnspython_available.cache_clear()
    _warn_stub_backend.cache_clear()


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


def test_expand_ipv6_rejects_unparsable_rdata() -> None:
    # A malformed AAAA rdata surfaces as a ferm error, not a bare
    # ipaddress traceback (sanctioned divergence: the oracle's Net::DNS
    # mangles the bytes and exits 0).
    with pytest.raises(FermError, match="cannot parse IPv6 address"):
        _expand_ipv6("not-an-address")


def test_canonical_name_lowercases_and_drops_trailing_dot() -> None:
    # Both the .lower() and the rstrip(".") matter: an upper-cased name or a
    # name keeping its trailing label separator would miss the zone lookup.
    assert _canonical_name("MAX.") == "max"
    assert _canonical_name("Ns.Example.Com.") == "ns.example.com"


def test_make_record_ns_canonicalizes_target() -> None:
    # An NS target is a hostname resolved again in a second pass, so it must
    # be canonicalized (lower-cased, trailing dot dropped) like a query name.
    assert _make_record("NS", ["NS1.EXAMPLE.COM."]) == ResourceRecord(
        "NS", "ns1.example.com"
    )


def test_make_record_mx_single_field_is_the_exchange() -> None:
    # A well-formed MX rdata is "priority exchange"; a lone field has no
    # priority, so the field itself is the exchange (no out-of-range read).
    assert _make_record("MX", ["10"]) == ResourceRecord("MX", "10")


def test_make_record_mx_uses_exchange_after_priority() -> None:
    assert _make_record("MX", ["10", "MAIL.EXAMPLE.COM."]) == ResourceRecord(
        "MX", "mail.example.com"
    )


def test_make_record_other_type_keeps_type_and_first_field() -> None:
    # An unhandled type is recorded verbatim (its first rdata field) only so
    # the name is known to exist; the type is preserved, not blanked.
    assert _make_record("TXT", ["hello"]) == ResourceRecord("TXT", "hello")


def test_make_record_empty_rdata_is_none() -> None:
    assert _make_record("A", []) is None


def test_resolve_a_record(zone: ZonefileResolver) -> None:
    assert resolve("ip", "v4.example.com", resolver=zone) == ["192.0.2.1"]


def test_resolve_numeric_literal_does_not_stop_the_loop(
    zone: ZonefileResolver,
) -> None:
    # After a numeric literal is emitted the loop must continue to the next
    # name (a break here would silently drop every following host).
    assert resolve(
        "ip", ["10.0.0.5", "v4.example.com"], "A", resolver=zone
    ) == [
        "10.0.0.5",
        "192.0.2.1",
    ]


def test_resolve_silent_miss_does_not_stop_the_loop(
    zone: ZonefileResolver,
) -> None:
    # A silently-missed name (NXDOMAIN/NOERROR) must not abort the loop; a
    # break would drop the resolvable name that follows it.
    assert resolve(
        "ip", ["nonexistent.example.com", "v4.example.com"], resolver=zone
    ) == ["192.0.2.1"]


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


def test_pick_resolver_uses_dnspython_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("pyferm.resolver._dnspython_available", lambda: True)
    assert isinstance(pick_resolver(False, "rules/main.ferm"), SystemResolver)


def test_pick_resolver_falls_back_to_stub_without_dnspython(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("pyferm.resolver._dnspython_available", lambda: False)
    assert isinstance(pick_resolver(False, "rules/main.ferm"), StubResolver)


def test_make_live_resolver_real_detect_without_dnspython(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib.util

    from pyferm.resolver import _make_live_resolver

    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: None)
    _dnspython_available.cache_clear()  # re-evaluate with patched find_spec
    assert isinstance(_make_live_resolver(), StubResolver)


def test_dnspython_available_swallows_find_spec_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib.util

    def boom(_name: str) -> object:
        raise ModuleNotFoundError("half-installed parent")

    monkeypatch.setattr(importlib.util, "find_spec", boom)
    _dnspython_available.cache_clear()
    assert _dnspython_available() is False


def test_stub_backend_warns_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from pyferm.resolver import _make_live_resolver

    monkeypatch.setattr("pyferm.resolver._dnspython_available", lambda: False)
    calls: list[str] = []

    def record(message: str) -> None:
        calls.append(message)

    monkeypatch.setattr("pyferm.resolver.warning", record)
    _make_live_resolver()
    _make_live_resolver()
    # lru_cache on _warn_stub_backend fires the diagnostic exactly once.
    assert len(calls) == 1
    assert "pyferm[dns]" in calls[0]


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


def test_zonefile_with_non_ascii_bytes_parses(tmp_path: Path) -> None:
    zone = tmp_path / "zone"
    zone.write_bytes(b"; comment \xff\nhost.example. IN A 192.0.2.1\n")
    resolver = ZonefileResolver.from_file(str(zone))
    # the non-UTF-8 comment byte must not abort the read
    assert resolver.records


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
    assert result.answer == []  # a loud failure still carries an empty answer
    assert result.errorstring == "connection timed out"


def test_stub_resolver_a_record(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(
        host: str, port: object, family: int, socktype: int, *, flags: int
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        # Pin every positional passed to getaddrinfo: an "A" query maps to
        # AF_INET (not AF_INET6), the hostname/socktype travel through
        # verbatim, and flags is pinned to 0 (no AI_V4MAPPED/AI_ADDRCONFIG).
        assert host == "v4.example.com"
        assert port is None
        assert family == socket.AF_INET
        assert socktype == socket.SOCK_STREAM
        assert flags == 0
        return [(family, socktype, 6, "", ("192.0.2.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = StubResolver().search("v4.example.com", "A")
    assert result.found is True
    assert [(rr.type, rr.data) for rr in result.answer] == [("A", "192.0.2.1")]
    # A successful lookup is a silent-miss-free NOERROR, never a bare None.
    assert result.errorstring == "NOERROR"


def test_stub_resolver_aaaa_dedup_and_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_getaddrinfo(
        _host: str, _port: object, family: int, socktype: int, **_kwargs: int
    ) -> list[tuple[int, int, int, str, tuple[str, int, int, int]]]:
        # duplicates (one per socktype) + a link-local scope suffix
        return [
            (family, socktype, 6, "", ("2001:db8::1", 0, 0, 0)),
            (family, socktype, 17, "", ("2001:db8::1", 0, 0, 0)),
            (family, socktype, 6, "", ("fe80::1%eth0", 0, 0, 2)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = StubResolver().search("v6.example.com", "AAAA")
    assert [rr.data for rr in result.answer] == ["2001:db8::1", "fe80::1"]


def test_stub_resolver_passes_ipv4_mapped_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Guard (spec): with flags=0 AF_INET6 does not yield ::ffff:a.b.c.d on
    # glibc, so this input is unreachable in practice. The guard pins that
    # StubResolver does NOT special-case it -- the address is surfaced
    # verbatim. (Were it ever to reach resolve()'s AAAA path, _expand_ipv6
    # would raise ValueError on the dotted-quad tail: a loud crash, never a
    # silent v4-into-ip6 leak.)
    def fake_getaddrinfo(
        _host: str, _port: object, family: int, socktype: int, **_kwargs: int
    ) -> list[tuple[int, int, int, str, tuple[str, int, int, int]]]:
        return [(family, socktype, 6, "", ("::ffff:192.0.2.1", 0, 0, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = StubResolver().search("mapped.example.com", "AAAA")
    assert [rr.data for rr in result.answer] == ["::ffff:192.0.2.1"]


def _stub_gaierror(
    monkeypatch: pytest.MonkeyPatch, errno: int | None
) -> SearchResult:
    def fake_getaddrinfo(*_args: object, **_kwargs: object) -> object:
        raise socket.gaierror(errno, "boom")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return StubResolver().search("h.example.com", "A")


@pytest.mark.parametrize(
    ("errno", "errorstring"),
    [
        pytest.param(socket.EAI_NONAME, "NXDOMAIN", id="noname-nxdomain"),
        pytest.param(
            # EAI_NODATA/EAI_ADDRFAMILY: name exists, no record of this family.
            getattr(socket, "EAI_NODATA", None) or socket.EAI_ADDRFAMILY,
            "NOERROR",
            id="nodata-noerror",
        ),
        pytest.param(socket.EAI_AGAIN, "SERVFAIL", id="again-servfail"),
        # errno None (any unmapped code) must fail closed, not silent.
        pytest.param(None, "SERVFAIL", id="unmapped-loud-servfail"),
    ],
)
def test_stub_gaierror_maps_to_errorstring(
    monkeypatch: pytest.MonkeyPatch, errno: int | None, errorstring: str
) -> None:
    result = _stub_gaierror(monkeypatch, errno)
    assert result.found is False
    assert result.answer == []
    assert result.errorstring == errorstring


def test_stub_servfail_propagates_through_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_getaddrinfo(*_args: object, **_kwargs: object) -> object:
        raise socket.gaierror(socket.EAI_AGAIN, "temporary failure")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(FermError, match="DNS query for 'h' failed: SERVFAIL"):
        resolve("ip", "h", resolver=StubResolver())


def test_stub_ns_type_is_clear_error() -> None:
    with pytest.raises(FermError, match="needs the optional dnspython"):
        StubResolver().search("ns.example.com", "NS")


def test_stub_mx_type_is_clear_error() -> None:
    with pytest.raises(FermError, match="install pyferm\\[dns\\]"):
        StubResolver().search("mx.example.com", "MX")
