"""Name resolution for ``@resolve()`` (A/AAAA/NS/MX, numeric fast-path).

Faithful port of ferm's resolver from ``reference/src/ferm``:
``pick_resolver`` (``:1286``), ``identify_numeric_address`` (``:1306``) and
``resolve`` (``:1314``).  ``@resolve(host[, type])`` is parsed into a deferred
value whose callable is :func:`resolve`; it runs late (during rule
realization), so a host can expand into several rules.

ferm chooses a resolver per call via ``pick_resolver``: the system resolver
normally, or -- under ``--test`` -- a mock reading a ``zonefile`` next to the
input.  This port mirrors that with a :class:`Resolver` protocol and a
module-level provider (the stand-in for Perl's ``%option``/``$script``
globals): the CLI installs one with :func:`set_resolver_provider`, while unit
tests pass a :class:`ZonefileResolver` to :func:`resolve` directly.

IPv6 addresses are emitted in Net::DNS' textual form -- fully expanded to
eight groups but with per-group leading zeros stripped (so ``2001:db8::1``
becomes ``2001:db8:0:0:0:0:0:1``) -- because the Perl oracle's golden output
uses exactly that.  Only addresses
that come back from a resource record are normalized; a numeric literal that
matches the queried family is passed through untouched, as Perl does.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from pyferm.errors import FermError, error
from pyferm.values import Value, to_array

_NETMASK_RE = re.compile(r"/\d+$")
_IPV4_RE = re.compile(r"\d+\.\d+\.\d+\.\d+")
_IPV6_RE = re.compile(r"[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F:]*")


def identify_numeric_address(value: str) -> str | None:
    """Classify a literal address as ``"A"``/``"AAAA"`` (Perl ``:1306``).

    Strips an optional ``/prefix`` netmask first, then matches the IPv4 and
    IPv6 shapes verbatim from Perl; returns ``None`` for a hostname.
    """
    value = _NETMASK_RE.sub("", value)
    if _IPV4_RE.fullmatch(value):
        return "A"
    if _IPV6_RE.fullmatch(value):
        return "AAAA"
    return None


def _expand_ipv6(address: str) -> str:
    """Render an IPv6 address in Net::DNS form (expanded, no leading zeros)."""
    groups = ipaddress.IPv6Address(address).exploded.split(":")
    return ":".join(format(int(group, 16), "x") for group in groups)


@dataclass
class ResourceRecord:
    """One answer record: its type and the relevant rdata text.

    ``data`` is the address for ``A``/``AAAA``, the target for ``NS`` and the
    exchange for ``MX`` -- the single field ``resolve`` consumes per type.
    """

    type: str
    data: str


@dataclass
class SearchResult:
    """The outcome of one query (Perl's ``$query`` plus ``errorstring``).

    ``found`` is the truthiness of Perl's ``$resolver->search`` return: true
    only when the answer holds records of the queried type.  ``errorstring``
    distinguishes a silent miss (empty/``NOERROR``/``NXDOMAIN``) from a real
    failure, exactly as ``resolve`` branches on it (``:1336``).
    """

    found: bool
    answer: list[ResourceRecord]
    errorstring: str | None


class Resolver(Protocol):
    """A DNS source: the slice of Net::DNS' resolver that ``resolve`` uses."""

    def search(self, hostname: str, rrtype: str) -> SearchResult:
        """Look up ``rrtype`` records for ``hostname`` (Perl ``->search``)."""
        ...


@dataclass
class ZonefileResolver:
    """A mock resolver answering from a parsed zone file (the ``--test`` path).

    Replaces ``Net::DNS::Resolver::Mock``: it parses the simple
    ``name [TTL] IN TYPE rdata`` lines of the test ``zonefile`` and answers
    queries from them, reproducing the NXDOMAIN/NOERROR distinction the Perl
    mock yields.
    """

    records: dict[str, list[ResourceRecord]] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str) -> ZonefileResolver:
        """Parse a zone file into a resolver (Perl ``zonefile_read``)."""
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise FermError(
                f"Failed to read zonefile {path}: {exc.strerror}"
            ) from exc
        return cls.from_text(text)

    @classmethod
    def from_text(cls, text: str) -> ZonefileResolver:
        """Parse zone-file text into a resolver."""
        records: dict[str, list[ResourceRecord]] = {}
        for raw in text.splitlines():
            line = raw.split(";", 1)[0].strip()
            if not line:
                continue
            fields = line.split()
            try:
                cls_index = fields.index("IN")
            except ValueError:
                continue
            if cls_index == 0 or cls_index + 1 >= len(fields):
                continue
            name = _canonical_name(fields[0])
            rrtype = fields[cls_index + 1]
            rdata = fields[cls_index + 2:]
            record = _make_record(rrtype, rdata)
            if record is not None:
                records.setdefault(name, []).append(record)
        return cls(records=records)

    def search(self, hostname: str, rrtype: str) -> SearchResult:
        """Answer from the parsed zone, mirroring the mock's error strings."""
        name = _canonical_name(hostname)
        all_records = self.records.get(name)
        if all_records is None:
            return SearchResult(False, [], "NXDOMAIN")
        matching = [rr for rr in all_records if rr.type == rrtype]
        if matching:
            return SearchResult(True, matching, "NOERROR")
        return SearchResult(False, [], "NOERROR")


class SystemResolver:
    """The production resolver, backed by ``dnspython`` (Perl ``Net::DNS``)."""

    def search(
        self, hostname: str, rrtype: str
    ) -> SearchResult:  # pragma: no cover - needs live DNS
        """Query the system resolver, mapping failures to error strings."""
        import dns.exception
        import dns.resolver

        try:
            answer = dns.resolver.resolve(hostname, rrtype, search=True)
        except dns.resolver.NXDOMAIN:
            return SearchResult(False, [], "NXDOMAIN")
        except dns.resolver.NoAnswer:
            return SearchResult(False, [], "NOERROR")
        except dns.exception.DNSException as exc:
            return SearchResult(False, [], str(exc) or "SERVFAIL")

        records: list[ResourceRecord] = []
        for rr in answer:
            record = _make_record(rrtype, str(rr).split())
            if record is not None:
                records.append(record)
        return SearchResult(bool(records), records, "NOERROR")


def _canonical_name(name: str) -> str:
    """Normalize a domain name for lookup: drop a trailing dot, lowercase."""
    return name.rstrip(".").lower()


def _make_record(rrtype: str, rdata: list[str]) -> ResourceRecord | None:
    """Build a :class:`ResourceRecord` from zone-file/answer rdata fields.

    Mirrors which field Perl reads per type: ``address`` for ``A``/``AAAA``,
    ``nsdname`` for ``NS``, and the ``exchange`` (after the priority) for
    ``MX``.  Other types are recorded only so the name is known to exist.
    """
    if not rdata:
        return None
    if rrtype in ("A", "AAAA"):
        return ResourceRecord(rrtype, rdata[0])
    if rrtype == "NS":
        return ResourceRecord(rrtype, _canonical_name(rdata[0]))
    if rrtype == "MX":
        exchange = rdata[1] if len(rdata) > 1 else rdata[0]
        return ResourceRecord(rrtype, _canonical_name(exchange))
    return ResourceRecord(rrtype, rdata[0])


class ResolverProvider(Protocol):
    """A factory for the per-call resolver (Perl's ``pick_resolver``)."""

    def __call__(self) -> Resolver:
        """Return the resolver to use for the next ``resolve`` call."""
        ...


_provider: ResolverProvider | None = None


def set_resolver_provider(provider: ResolverProvider | None) -> None:
    """Install the resolver factory the CLI builds from its options.

    Stands in for Perl's ``pick_resolver`` reading the ``%option``/``$script``
    globals; :func:`resolve` calls it once per top-level invocation.
    """
    global _provider
    _provider = provider


def pick_resolver(test: bool, script_path: str) -> Resolver:
    """Choose a resolver for one run (Perl ``pick_resolver``, ``:1286``).

    Returns the live :class:`SystemResolver` normally, or a
    :class:`ZonefileResolver` reading the ``zonefile`` next to ``script_path``
    under ``--test`` (the directory rule is Perl's ``m,^(.*/),`` or ``./``).
    """
    if not test:
        return SystemResolver()
    match = re.match(r"^(.*/)", script_path)
    parent = match.group(1) if match else "./"
    return ZonefileResolver.from_file(parent + "zonefile")


def _current_resolver() -> Resolver:
    """Return the installed resolver, erroring if the CLI set none."""
    if _provider is None:
        error("internal error: no resolver provider configured")
    return _provider()


def resolve(
    domain: str,
    names: Value,
    rrtype: str | None = None,
    *,
    resolver: Resolver | None = None,
) -> list[Value]:
    """Resolve hostnames to addresses (Perl ``resolve``, ``:1314``).

    ``names`` is a single host or a ferm array; ``rrtype`` defaults to ``A``
    (or ``AAAA`` for the ``ip6`` family).  Numeric literals skip the lookup
    and survive only when they match the queried family.  ``NS``/``MX``
    answers are hostnames, so they are resolved again in a second pass.

    Returns the addresses as a list; an empty result is the empty list (zero
    elements), so :func:`pyferm.values.realize_deferred` splices nothing and a
    rule whose only address came from an empty ``@resolve`` drops out entirely.
    The oracle's ``return [] unless length @result`` guard (``:1365``) is dead
    code -- ``length`` forces scalar context, so the count's digit length is
    always truthy -- leaving ``return @result`` with an empty ``@result``.
    """
    if rrtype is not None and not isinstance(rrtype, str):
        error("String expected")
    if resolver is None:
        resolver = _current_resolver()
    if not rrtype:
        rrtype = "AAAA" if domain == "ip6" else "A"

    result: list[Value] = []
    for hostname in to_array(names):
        host = hostname if isinstance(hostname, str) else str(hostname)
        numeric_type = identify_numeric_address(host)
        if numeric_type is not None:
            if numeric_type == rrtype:
                result.append(host)
            continue

        outcome = resolver.search(host, rrtype)
        if not outcome.found:
            errorstring = outcome.errorstring
            if not errorstring or errorstring in ("NOERROR", "NXDOMAIN"):
                continue
            error(f"DNS query for '{host}' failed: {errorstring}")
        for record in outcome.answer:
            if record.type != rrtype:
                continue
            data = record.data
            if rrtype == "AAAA":
                data = _expand_ipv6(data)
            result.append(data)

    if rrtype in ("NS", "MX"):
        result = resolve(domain, result, None, resolver=resolver)

    return result
