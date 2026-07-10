"""Statement/chain dataclasses, operand validators, text canon helpers."""

from __future__ import annotations

import re
import socket
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Final

from ...domains import Family
from ...errors import FermError, internal_error
from ...nftset import (
    l4proto_name,
    set_body,
    sort_set_elements,
    sort_vmap_pairs,
)
from ...streams import BYTE_ENCODING
from ...values import (
    Multi,
    Negated,
    Params,
    PreNegated,
    SetRef,
    Value,
)

#: nft comment byte limit; over -> a plain ferm error.
NFT_COMMENT_MAX: Final[int] = 128

#: ``DomainInfo.tools`` key for the single nft binary.
TOOL_NFT: Final[str] = "nft"

#: An nft address operand: IPv4/IPv6/hex digits, CIDR ``/``, range ``-``,
#: and ``:`` (IPv6 and NAT ``addr:port``).  Rejects every token-breaking
#: metacharacter.
_NFT_ADDR_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9A-Fa-f.:/-]+\Z")

#: An nft port operand: a numeric/service port or ``lo-hi`` range.  Service
#: names (``ssh``) are accepted (nft resolves them); metacharacters are not.
_NFT_PORT_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[0-9A-Za-z][0-9A-Za-z-]*\Z"
)

#: ferm/iptables write a closed port range as ``lo:hi``; nft's grammar uses
#: ``lo-hi``, so a colon range is normalized to the dash form.  Both ends
#: must be present -- half-open ``:hi`` / ``lo:`` has no nft spelling here
#: and is rejected (fail-closed) rather than mistranslated (review
#: 2026-06-14).
_NFT_PORT_COLON_RANGE_RE: Final[re.Pattern[str]] = re.compile(
    r"\A([0-9A-Za-z]+):([0-9A-Za-z]+)\Z"
)

#: An already-dash-spelled numeric range passes through unchanged.
_NFT_PORT_DASH_RANGE_RE: Final[re.Pattern[str]] = re.compile(r"\A\d+-\d+\Z")

#: Bytes nft cannot represent inside a double-quoted string: a literal
#: quote, a backslash, or any control byte.  nft has no escape for these,
#: so :func:`_nft_quote_string` rejects rather than escapes them.
_NFT_UNQUOTABLE_RE: Final[re.Pattern[str]] = re.compile(r'["\\\x00-\x1f]')

#: An nft set/map identifier: must start with a letter, then word chars only.
_NFT_SET_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[A-Za-z][A-Za-z0-9_]*\Z"
)

#: First rejected name length (empirically confirmed: 255 accepted, 256 not).
_NFT_NAME_MAXLEN: Final[int] = 256


def _validate_address(scalar: str) -> str:
    """Return *scalar* if it is a safe nft address operand, else error."""
    if not _NFT_ADDR_RE.match(scalar):
        raise FermError(f"invalid address '{scalar}' for nft backend")
    return scalar


def _validate_set_name(name: str) -> str:
    """Return *name* if it is a safe nft set identifier, else error."""
    if not _NFT_SET_NAME_RE.match(name) or len(name) >= _NFT_NAME_MAXLEN:
        raise FermError(f"invalid set name '{name}' for nft backend")
    return name


def _validate_port(scalar: str) -> str:
    """
    Return a safe nft port operand, normalizing colon ranges, else error.

    ferm/iptables spell a closed port range ``lo:hi`` while nft's grammar
    wants ``lo-hi``; the colon form is rewritten to the dash form so a
    config that compiles under the iptables backend also compiles under
    ``--nft`` (review 2026-06-14).  Half-open ranges (``:hi`` / ``lo:``)
    have no nft equivalent here and fall through to the error rather than
    being mistranslated.
    """
    match = _NFT_PORT_COLON_RANGE_RE.match(scalar)
    if match:
        return (
            f"{_resolve_port_token(match.group(1))}"
            f"-{_resolve_port_token(match.group(2))}"
        )
    if _NFT_PORT_DASH_RANGE_RE.match(scalar):
        return scalar
    return _resolve_port_token(scalar)


def _resolve_port_token(token: str) -> str:
    """
    Return one port operand as the number the kernel readback prints.

    nft resolves a service name (``ssh``, ``http``) at parse time and
    ``nft list ruleset`` prints the number, so a name emitted verbatim
    leaves ``--plan`` diffing an applied ruleset forever.  Resolution
    goes through the same ``/etc/services`` database nft consults; a
    name it does not know would not parse under ``nft -f`` either, so
    it refuses at translate time.
    """
    if token.isdigit():
        return token
    if _NFT_PORT_RE.match(token):
        try:
            return str(socket.getservbyname(token))
        except OSError:
            raise FermError(
                f"unknown service name '{token}' for nft backend"
            ) from None
    raise FermError(f"invalid port '{token}' for nft backend")


def _validate_protocol(scalar: str) -> str:
    """
    Return *scalar* if it is a safe nft protocol operand, else error.

    The ``protocol`` value reaches ``meta l4proto {value}`` (and the
    ``tcp/udp dport`` port context) verbatim.  A numeric proto (``47``) or a
    service-name-shaped token (``tcp``, ``gre``, ``ipv6-icmp``) is the only
    legitimate shape, so the port regex -- alnum plus ``-`` -- already models
    it exactly while rejecting every token-breaking metacharacter
    (whitespace / ``;`` / ``#`` / ``"``) that would otherwise flip a verdict
    (review 2026-06-14; ``nft -c`` does NOT catch the ``;#`` form).
    """
    if not _NFT_PORT_RE.match(scalar):
        raise FermError(f"invalid protocol '{scalar}' for nft backend")
    return scalar


@dataclass
class NftTable:
    """One nft table: ``table <family> <name>``."""

    family: str
    name: str


@dataclass
class NftBaseChain:
    """A base chain on a hook (carries type/hook/priority/policy)."""

    name: str
    type: str
    hook: str
    priority: int
    policy: str | None = None


@dataclass
class NftRegularChain:
    """A user-defined chain (no hook)."""

    name: str


class NftStatement(ABC):
    """
    One nft statement (match / verdict / stateful).

    Serialization dispatches on the subclass via :meth:`to_text` rather
    than a string tag, mirroring the dataclass dispatch ``base.py`` uses
    for ``Rendered``.
    """

    @abstractmethod
    def to_text(self) -> str:
        """Render this statement as one nft expression fragment."""


@dataclass
class NftMatch(NftStatement):
    """
    A match expression already rendered to nft text.

    ``expr`` is the rendered single/non-eligible form (e.g. ``tcp dport 22``).
    A set-eligible match also carries ``set_key`` (the selector left of the
    set, e.g. ``tcp dport``) and ``element`` (the operand, e.g. ``22``) as
    structured comparison keys.  ``elements`` is set only after the collapse
    pass merges a run; ``to_text`` then renders an anonymous set.
    """

    expr: str
    set_key: str | None = None
    element: str | None = None
    elements: list[str] | None = None
    setref: SetRef | None = None
    set_selector: str | None = None

    def to_text(self) -> str:
        """Render the match, as an anonymous set once a run is collapsed."""
        if self.elements is not None:
            # A collapsed run always carries set_key (the merge pass
            # copies it from the anchor); fail loud rather than emit
            # a literal "None {...}" (an `assert` would vanish under -O).
            if self.set_key is None:
                raise internal_error()
            # A non-adjacent repeated operand can merge into one run twice;
            # dedup so the set has no duplicate member.
            unique = list(dict.fromkeys(self.elements))
            return f"{self.set_key} {set_body(sort_set_elements(unique))}"
        return self.expr


@dataclass
class NftVerdict(NftStatement):
    """
    A verdict/target statement.

    Examples: ``accept``, ``drop``, ``jump X``, ``snat to ...``.
    """

    expr: str

    def to_text(self) -> str:
        """Return the pre-rendered verdict expression verbatim."""
        return self.expr


@dataclass
class NftVmap(NftStatement):
    """
    A verdict map folded from a run of adjacent single-key leaf rules.

    ``set_key`` is the selector left of the map (e.g. ``tcp dport``); each
    ``(key, verdict)`` pair carries one rule's distinguishing operand and its
    terminal verdict.  :meth:`to_text` orders the pairs by the key's canonical
    rank, since nft stores a vmap key-ordered like a set, so a ``--plan`` over
    an unchanged ruleset converges instead of showing a phantom change.
    """

    set_key: str
    pairs: list[tuple[str, str]]

    def to_text(self) -> str:
        """Render ``<set_key> vmap { k1 : v1, ... }`` in canonical order."""
        rendered = ", ".join(
            f"{key} : {verdict}"
            for key, verdict in sort_vmap_pairs(self.pairs)
        )
        return f"{self.set_key} vmap {{ {rendered} }}"


@dataclass
class NftReset(NftStatement):
    """
    A ``reset tcp option <name>`` mangle statement (TCPOPTSTRIP).

    A rule may carry several of these (one per stripped option) and no
    verdict.  Kept a distinct subclass rather than an :class:`NftVerdict`
    so the collapse/vmap passes -- which key off ``NftMatch`` and
    ``NftVerdict`` -- leave it linear untouched (a reset is neither a
    match nor a vmap-eligible verdict).
    """

    expr: str

    def to_text(self) -> str:
        """Return the pre-rendered reset statement verbatim."""
        return self.expr


@dataclass
class NftSetUpdate(NftStatement):
    """
    A ``<verb> @<name> { <key>[ timeout <t>][ limit <rate> ] }`` statement.

    Backs ``mod recent`` / ``mod hashlimit`` (``verb="update"``) and
    ``mod connlimit`` (``verb="add"``) via an implicit dynamic set: the
    statement both mutates the set (recording ``<key>``) and, through its
    optional ``limit rate`` or an ``ct count`` tail baked into ``key_expr``,
    gates the rule's verdict.  It carries the declaration facts (``set_type``;
    a ``timeout`` implies the ``,timeout`` flag) so
    :func:`_collect_set_declarations` can raise the matching
    :class:`_DynSetDecl` without re-parsing the key.  The brace order is pinned
    to the kernel readback: key, then timeout, then limit.  Kept a distinct
    subclass (like :class:`NftReset`) so the collapse/vmap passes -- which key
    off :class:`NftMatch`/:class:`NftVerdict` -- leave it untouched.
    """

    name: str
    key_expr: str
    set_type: str
    timeout: str | None = None
    limit: str | None = None
    verb: str = "update"
    #: True for the ferm-owned implicit sets (recent/hashlimit/connlimit),
    #: whose full element spec is the declaration identity; False for a
    #: user ``@set`` mutated by the SET target, where several rules with
    #: differing keys/timeouts legally share one set (identity: type only).
    owned: bool = True

    def to_text(self) -> str:
        """Render ``<verb> @<name> { ... }`` in pinned brace order."""
        parts = [self.key_expr]
        if self.timeout is not None:
            parts.append(f"timeout {self.timeout}")
        if self.limit is not None:
            parts.append(f"limit {self.limit}")
        return f"{self.verb} @{self.name} {{ {' '.join(parts)} }}"


@dataclass
class NftQuota(NftStatement):
    """
    A ``quota <n> <unit>`` statement (``mod quota``).

    Kept a distinct subclass (like :class:`NftReset`) rather than an
    :class:`NftMatch` so the collapse/vmap passes -- which key off
    :class:`NftMatch`/:class:`NftVerdict` -- leave it linear: a quota is
    stateful accounting per rule, and folding two rules onto one quota would
    merge their byte counters.
    """

    expr: str

    def to_text(self) -> str:
        """Return the pre-rendered quota statement verbatim."""
        return self.expr


@dataclass
class NftRule:
    """One rule: ordered statements plus an optional comment."""

    statements: list[NftStatement]
    comment: str | None = None


def _chain_header(chain: NftBaseChain | NftRegularChain) -> str:
    """Render the ``add chain ...`` body for one chain."""
    if isinstance(chain, NftBaseChain):
        body = (
            f"type {chain.type} hook {chain.hook} priority {chain.priority};"
        )
        if chain.policy is not None:
            body += f" policy {chain.policy};"
        return f"{{ {body} }}"
    return ""


def _nft_quote_string(text: str) -> str:
    """
    Wrap *text* in nft double-quotes, rejecting bytes nft cannot quote.

    nft's string lexer has NO escape for a literal double-quote -- a
    backslash is kept as content and the quote still terminates the string,
    so the old backslash-quote escape silently let a value break out of its
    token and flip a verdict (review 2026-06-14, reproduced on nftables
    v1.1.6).  A value containing a double-quote, a backslash, or any control
    byte (newline / CR included) therefore raises a ferm error rather than
    being emitted.  Used wherever nft mandates a quoted string (``comment``,
    ``interface``, ``log prefix``); legitimate operands (``eth*``, ``ppp+``,
    log labels with spaces) contain none of these bytes.
    """
    if _NFT_UNQUOTABLE_RE.search(text):
        raise FermError(f"value {text!r} has a character nft cannot quote")
    return f'"{text}"'


def _nft_ifname(name: str) -> str:
    """
    Quote an interface name, translating the iptables trailing wildcard.

    ferm configs carry the iptables wildcard spelling (``eth+``); nft's
    string wildcard is ``*`` and treats ``+`` as a literal byte, so an
    untranslated ``eth+`` silently matches nothing -- ``nft -c`` accepts
    the rule, the interactive rollback never fires, and the intended
    match is a no-op.  Only a TRAILING ``+`` is a wildcard in iptables;
    an interior ``+`` (``a+b``) stays literal.
    """
    return _nft_quote_string(re.sub(r"\+\Z", "*", name))


def render_comment(comment: str) -> str:
    """
    Render a validated ``comment "<text>"`` suffix.

    Over :data:`NFT_COMMENT_MAX` bytes -> a ferm error, never truncation.
    """
    if len(comment.encode(BYTE_ENCODING)) > NFT_COMMENT_MAX:
        raise FermError(
            f"comment exceeds nft limit of {NFT_COMMENT_MAX} bytes"
        )
    return f"comment {_nft_quote_string(comment)}"


#: Shared refusal for a match/NAT value whose runtime shape (list, missing
#: scalar, ...) has no nft translation; used verbatim by both value
#: extractors below and by the tcp-flags Params unpacking in ``matches.py``.
_UNSUPPORTED_VALUE_SHAPE: Final[str] = (
    "unsupported value shape for nft backend"
)


def unwrap_value(value: Value) -> tuple[str, bool]:
    """
    Return ``(scalar, negated)`` for a simple match value.

    A ``Negated``/``PreNegated`` tag with a >1-element list payload has no
    infix nft equivalent (cf. the silent tail-drop in
    ``iptables.py:148-154``) -> a ferm error, never a silent drop.
    """
    negated = False
    if isinstance(value, (Negated, PreNegated)):
        inner = value.value
        if isinstance(inner, list):
            if len(inner) > 1:
                raise FermError("multi-value match cannot be negated in nft")
            value = inner[0] if inner else ""
        else:
            value = inner
        negated = True
    if isinstance(value, (Params, Multi)):
        raise FermError(
            "multi-value cannot be expressed as a single nft match"
        )
    if not isinstance(value, str):
        raise FermError(_UNSUPPORTED_VALUE_SHAPE)
    return value, negated


def first_scalar(value: Value) -> str:
    """
    Extract the first scalar from a NAT-style value.

    NAT arguments arrive ``Multi``-wrapped (``to-source`` ->
    ``Multi(['1.2.3.4'])``); a plain scalar passes through.  Used where a
    single address/port is expected (SNAT/DNAT/redirect targets).
    """
    if isinstance(value, (Multi, Params)):
        if not value.values or not isinstance(value.values[0], str):
            raise FermError(_UNSUPPORTED_VALUE_SHAPE)
        return value.values[0]
    if isinstance(value, str):
        return value
    raise FermError(_UNSUPPORTED_VALUE_SHAPE)


def _bounded_uint(scalar: str, maximum: int, label: str) -> int:
    """Return *scalar* as an unsigned int in ``[0, maximum]``, else error."""
    if not scalar.isdigit() or int(scalar) > maximum:
        raise FermError(f"invalid {label} '{scalar}' for nft backend")
    return int(scalar)


def _op(neg: bool) -> str:
    """Return the nft inequality prefix for a (possibly) negated match."""
    return "!= " if neg else ""


def _addr_set_type(domain: Family) -> str:
    """Return the nft address-set element type for *domain* (ip vs ip6)."""
    return "ipv4_addr" if domain is Family.IP else "ipv6_addr"


def _nft_l4proto(domain: Family, proto: str) -> str:
    """
    Normalize a protocol for nft ``meta l4proto`` (cf. ``iptables.py``).

    Under ip6 the rendered protocol is still the raw ``icmp`` (the
    ``icmp``->``icmpv6`` rewrite lives in the iptables backend's
    ``format_option`` and is NOT in the rule); ``meta l4proto icmp`` in an
    ip6 table matches proto 1, not 58, so it must become the ip6 ICMP
    protocol name.  ``ipv6-icmp`` is the /etc/protocols name for proto 58.
    """
    if domain == "ip6" and proto in ("icmp", "icmpv6", "ipv6-icmp"):
        return "ipv6-icmp"
    # A bare protocol NUMBER reads back from the kernel as its canonical nft
    # name (`meta l4proto 6` -> `tcp`); fold a known number so the desired side
    # matches the readback and --plan shows no phantom change.
    return l4proto_name(proto)


#: nft time unit spans in milliseconds, largest first, for canonicalising a
#: ``timeout``/rate period.  ``nft list`` prints the full decomposition with
#: zero components dropped (``90s`` -> ``1m30s``, ``500ms`` -> ``500ms``).
_TIME_UNITS_MS: Final[tuple[tuple[str, int], ...]] = (
    ("d", 86_400_000),
    ("h", 3_600_000),
    ("m", 60_000),
    ("s", 1_000),
    ("ms", 1),
)


def _nft_time_canon(milliseconds: int) -> str:
    """
    Render *milliseconds* as nft's canonical time literal.

    Full d/h/m/s/ms decomposition, largest unit first, zero components
    dropped: ``60000`` -> ``1m``, ``90000`` -> ``1m30s``, ``500`` -> ``500ms``.
    """
    if milliseconds <= 0:
        raise FermError(
            "stateful timeout must be positive for the nft backend"
        )
    parts: list[str] = []
    remainder = milliseconds
    for unit, span in _TIME_UNITS_MS:
        whole, remainder = divmod(remainder, span)
        if whole:
            parts.append(f"{whole}{unit}")
    return "".join(parts)
