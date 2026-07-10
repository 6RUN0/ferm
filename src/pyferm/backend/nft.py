"""
The native nftables backend (Phase 2).

Translates each :class:`pyferm.rules.RenderedRule` to a small internal
nft-expression model and serializes it (``to_text``) into one atomic
``nft -f`` script over ``table <family> ferm`` only.
"""

from __future__ import annotations

import enum
import grp
import hashlib
import ipaddress
import pwd
import re
import socket
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

from pyferm.backend.base import (
    Backend,
    ExecuteCapture,
    ExecuteCommand,
    LineEmitter,
    Rendered,
    RestoreDomain,
    SaveReader,
)
from pyferm.domains import (
    ICMP6_REJECT_MAP,
    NFT_CT_STATES,
    NFT_TABLE_NAME,
    Family,
    ShellSnapshot,
)
from pyferm.errors import FermError, internal_error
from pyferm.modules import PORT_PROTOCOLS, TARGET_DEFS
from pyferm.nftset import (
    RANK_ADDRESS,
    RANK_INTERVAL,
    classify,
    l4proto_name,
    set_body,
    sort_set_elements,
    sort_vmap_pairs,
)
from pyferm.plan import build_nft_delta, needs_full_reload
from pyferm.rules import (
    CORE_TARGETS,
    RenderedOption,
    RenderedRule,
    is_netfilter_builtin_chain,
    is_netfilter_module_target,
)
from pyferm.scope import OptionKind
from pyferm.streams import BYTE_ENCODING
from pyferm.values import (
    Multi,
    Negated,
    Params,
    PreNegated,
    SetRef,
    Value,
    iter_setrefs,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pyferm.config import Options
    from pyferm.domains import DomainInfo, TableInfo

#: nft comment byte limit; over -> a plain ferm error.
NFT_COMMENT_MAX: Final[int] = 128
#: ``DomainInfo.tools`` key for the single nft binary.
TOOL_NFT: Final[str] = "nft"

# ---------------------------------------------------------------------------
# Operand escaping / validation (review 2026-06-14).
#
# Config-derived operands are interpolated into the save script.  A value
# carrying whitespace / ``;`` / ``#`` / ``"`` would otherwise break out of
# its nft token (turning a DROP rule into ``accept``), and ``nft -c`` does
# NOT catch the ``;#`` line-comment form -- so the ferm side is the only
# defense.  Quoted-string contexts (interface, comment, log prefix) are
# escaped via :func:`_nft_quote_string`; bare-token contexts (address /
# port / rate) and bare-identifier contexts (chain name) are grammar-
# validated here, raising a plain ferm error rather than emitting a script
# nft would mis-apply.
# ---------------------------------------------------------------------------

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
#: An nft ``limit rate`` value: ``N`` or ``N/unit`` (``3/second``).
_NFT_RATE_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(\d+)(?:/([A-Za-z]+))?\Z"
)
#: nft's limit units; xt_limit accepts any (case-insensitive) prefix of
#: these, so ``10/min``/``10/m`` expand to ``10/minute``.
_NFT_RATE_UNITS: Final[tuple[str, ...]] = ("second", "minute", "hour", "day")
#: An nft chain identifier (bare word; nft has no quoted-chain-name form).
_NFT_CHAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[A-Za-z][A-Za-z0-9_-]*\Z"
)
#: An nft set/map identifier: must start with a letter, then word chars only.
_NFT_SET_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[A-Za-z][A-Za-z0-9_]*\Z"
)
#: First rejected name length (empirically confirmed: 255 accepted, 256 not).
_NFT_NAME_MAXLEN: Final[int] = 256
#: ct state keywords nft accepts for ``ct state`` (the ferm ``state`` module
#: maps to iptables ``--state``, whose vocabulary is this set).
_CT_STATES: Final[frozenset[str]] = frozenset(NFT_CT_STATES)
#: ct state bit values: the kernel readback prints a state list
#: deduplicated in ascending bit order, so emission pre-sorts to match
#: (the _FIB_TYPE_RANK pattern).
_CT_STATE_RANK: Final[dict[str, int]] = {
    "invalid": 0x01,
    "established": 0x02,
    "related": 0x04,
    "new": 0x08,
    "untracked": 0x40,
}
#: ct status bits (IPS_* order), same readback-order contract.  The
#: xt_conntrack-only SNAT/DNAT pseudo-states live in this register, not
#: in ct state.
_CT_STATUS_RANK: Final[dict[str, int]] = {
    "expected": 0x01,
    "seen-reply": 0x02,
    "assured": 0x04,
    "confirmed": 0x08,
    "snat": 0x10,
    "dnat": 0x20,
}
_CT_NAT_PSEUDO_STATES: Final[frozenset[str]] = frozenset({"snat", "dnat"})
#: the --ctstatus vocabulary xt_conntrack accepts, minus NONE (an empty
#: status mask, which no nft ``ct status`` spelling can express).
_CTSTATUS_TOKENS: Final[frozenset[str]] = frozenset(
    {"expected", "seen-reply", "assured", "confirmed"}
)


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


#: A numeric port or a closed numeric range; service/protocol NAMES are
#: rejected because their nft type and sort order cannot be inferred here.
_SET_PORT_NUMERIC_RE: Final[re.Pattern[str]] = re.compile(r"\A\d+([-:]\d+)?\Z")


class NftSetType(enum.StrEnum):
    """nft named-set element type keyword (emitted verbatim into scripts)."""

    INET_SERVICE = "inet_service"
    IPV4_ADDR = "ipv4_addr"
    IPV6_ADDR = "ipv6_addr"
    IFNAME = "ifname"


@dataclass
class _SetDecl:
    """A named-set declaration: type plus ordered, validated elements."""

    type_: NftSetType
    flags_interval: bool
    elements: list[str]


#: The kernel injects ``size 65535`` into an implicit dynamic set; emit it
#: explicitly so ``--plan`` converges against the readback.
_DYN_SET_SIZE: Final[int] = 65535

#: Placeholder set name a connlimit ``NftSetUpdate`` carries until the
#: per-chain post-pass assigns its content-hash name (the final name depends
#: on the fully rendered rule text, unavailable inside ``translate_rule``).
_CONNLIMIT_SENTINEL: Final[str] = "?"


@dataclass
class _DynSetDecl:
    """
    A dynamic (stateful) named-set declaration for recent/hashlimit.

    Unlike :class:`_SetDecl`, it carries no config elements (the kernel
    accrues them at runtime via ``update @set``) and always prints an explicit
    ``size 65535``.  ``type_`` is the full nft type expression, a single
    keyword (``ipv4_addr``) or a concatenation (``ipv4_addr . inet_service``).

    Beyond ``type_``, the fields exist for the collector's conflict
    equality, not for emission: a dynamic element's stateful expression is
    fixed at creation and every touching rule consumes from it, so one name
    MUST mean one element spec.  Same nft type is not enough -- ``srcip``
    and ``dstip`` keys, or two different rates, share a type yet mean
    different buckets.
    """

    type_: str
    key_expr: str
    timeout: str | None
    limit: str | None

    @property
    def with_timeout(self) -> bool:
        """True when the elements bear a timeout (``,timeout`` flag)."""
        return self.timeout is not None


def _set_type_and_elements(
    domain: Family, selector: str, setref: SetRef
) -> tuple[NftSetType, bool, list[str]]:
    """
    Infer (nft type, flags-interval, validated sorted elements) for a set.

    The type comes from the use-site *selector* (a port match needs
    ``inet_service``, an address match ``ipv4_addr``/``ipv6_addr``, an
    interface match ``ifname``); the elements are validated with the very
    same validators the corresponding single-operand match uses, so a set
    cannot smuggle an operand a literal match would reject.

    Port elements must be numeric ports or numeric ranges.  A service or
    protocol NAME would land in the unparsable sort bucket whose order is
    not stable against a kernel readback, producing a never-converging
    phantom diff, so it is rejected outright (fail-closed).
    """
    raw = [str(element) for element in setref.elements]
    if selector.endswith(("dport", "sport")):
        for element in raw:
            if not _SET_PORT_NUMERIC_RE.match(element):
                raise FermError(
                    f"named set element '{element}' must be a numeric port "
                    "or range; service/protocol names are not supported"
                )
        elements = [_validate_port(element) for element in raw]
        type_ = NftSetType.INET_SERVICE
    elif "saddr" in selector or "daddr" in selector:
        elements = [_validate_address(element) for element in raw]
        type_ = (
            NftSetType.IPV4_ADDR if domain == "ip" else NftSetType.IPV6_ADDR
        )
    elif selector.endswith(("iifname", "oifname")):
        elements = [_nft_ifname(element) for element in raw]
        type_ = NftSetType.IFNAME
    else:
        raise FermError(f"named set selector '{selector}' not supported")
    flags_interval = any(
        (rank := classify(element)[0]) == RANK_INTERVAL
        or (rank == RANK_ADDRESS and "/" in element)
        for element in elements
    ) or (
        # nft treats a trailing `*` in a NAMED ifname set element as a
        # prefix and rejects the declaration without `flags interval`
        # (anonymous sets and vmaps need no flag; verified on nft v1.1.6).
        type_ is NftSetType.IFNAME
        and any(element.endswith('*"') for element in elements)
    )
    return type_, flags_interval, sort_set_elements(elements)


def _collect_set_declarations(
    domain: Family, rules: dict[str, list[NftRule]]
) -> dict[str, _SetDecl | _DynSetDecl]:
    """
    Aggregate named-set declarations over one family's rules.

    Keyed by name within this ``render()``: every ferm table merges into one
    ``table <family> ferm``, so a name is family-scoped.  Two arms feed the
    single dict -- static sets read structurally from :attr:`NftMatch.setref`
    (never reverse-parsed out of the rendered text) and dynamic sets from
    :class:`NftSetUpdate` (recent/hashlimit).  A name reused with a differing
    selector or element set, or across the static/dynamic kinds, is a conflict
    (error); the same name across several chains or tables of one family is one
    object (dedup).  The unified namespace is the collision guard the spec
    requires: an implicit ``recent_<x>``/``hashlimit_<x>`` set cannot silently
    shadow a user ``@set`` of the same name.
    """
    decls: dict[str, _SetDecl | _DynSetDecl] = {}
    selectors: dict[str, str] = {}
    for chain_rules in rules.values():
        for rule in chain_rules:
            for stmt in rule.statements:
                if isinstance(stmt, NftSetUpdate):
                    if stmt.name == _CONNLIMIT_SENTINEL:
                        # The connlimit post-pass runs in render() before the
                        # collapse pass and MUST have renamed every sentinel;
                        # one surviving here is a wiring bug, not config error.
                        raise internal_error(
                            "connlimit set reached declaration collection "
                            "with an unfinalized name"
                        )
                    dyn = _DynSetDecl(
                        stmt.set_type,
                        stmt.key_expr,
                        stmt.timeout,
                        stmt.limit,
                    )
                    existing = decls.get(stmt.name)
                    if existing is not None and existing != dyn:
                        raise FermError(
                            f"set '{stmt.name}' has conflicting declarations "
                            "for the nft backend"
                        )
                    decls[stmt.name] = dyn
                    continue
                if not isinstance(stmt, NftMatch) or stmt.setref is None:
                    continue
                setref = stmt.setref
                name = _validate_set_name(setref.name)
                if stmt.set_selector is None:
                    raise internal_error()  # structural; -O would void assert
                selector = stmt.set_selector
                type_, flags_interval, elements = _set_type_and_elements(
                    domain, selector, setref
                )
                prior = decls.get(name)
                if isinstance(prior, _DynSetDecl):
                    raise FermError(
                        f"named set '{name}' collides with a stateful set of "
                        "the same name for the nft backend"
                    )
                if name in selectors and selectors[name] != selector:
                    raise FermError(
                        f"named set '{name}' used with conflicting selectors "
                        f"'{selectors[name]}' and '{selector}'"
                    )
                if prior is not None and prior.elements != elements:
                    raise FermError(
                        f"named set '{name}' has conflicting element sets"
                    )
                selectors[name] = selector
                decls[name] = _SetDecl(type_, flags_interval, elements)
    return decls


def serialize_table(
    table: NftTable,
    chains: list[NftBaseChain | NftRegularChain],
    rules: dict[str, list[NftRule]],
    decls: dict[str, _SetDecl | _DynSetDecl],
    *,
    noflush: bool,
) -> str:
    """
    Serialize one family's table as an atomic ``nft -f`` script.

    Emits ``add table`` (idempotent), then ``flush table`` unless
    ``noflush`` (the ``--noflush`` decision lives HERE, not in the
    applier), then every named-set declaration, then every
    chain, then every rule.  ``chains`` is pre-sorted by the caller for
    deterministic golden output; ``decls`` is emitted by sorted name.
    """
    prefix = f"{table.family} {table.name}"
    lines = [f"add table {prefix}\n"]
    if not noflush:
        lines.append(f"flush table {prefix}\n")
    for name in sorted(decls):
        decl = decls[name]
        if isinstance(decl, _DynSetDecl):
            dyn_flags = "dynamic,timeout" if decl.with_timeout else "dynamic"
            lines.append(
                f"add set {prefix} {name} {{ type {decl.type_}; "
                f"size {_DYN_SET_SIZE}; flags {dyn_flags}; }}\n"
            )
            continue
        flags = " flags interval;" if decl.flags_interval else ""
        lines.append(
            f"add set {prefix} {name} {{ type {decl.type_};{flags} }}\n"
        )
        if decl.elements:
            lines.append(
                f"add element {prefix} {name} {set_body(decl.elements)}\n"
            )
    for chain in chains:
        header = _chain_header(chain)
        suffix = f" {header}" if header else ""
        lines.append(f"add chain {prefix} {chain.name}{suffix}\n")
    for chain in chains:
        for rule in rules.get(chain.name, []):
            parts = [stmt.to_text() for stmt in rule.statements]
            if rule.comment is not None:
                parts.append(render_comment(rule.comment))
            tail = " ".join(parts)
            sep = " " if tail else ""
            lines.append(f"add rule {prefix} {chain.name}{sep}{tail}\n")
    return "".join(lines)


def _full_reload_text(save: str, family: str) -> str:
    """
    Convert a flush-form save into an atomic whole-table replace.

    ``flush table`` empties chains of rules but keeps their declarations, so a
    base chain dropped from the config survives empty-but-hooked (still
    enforcing its policy) and a removed named set keeps its definition.
    Replacing the single ``flush table`` line with ``delete table`` +
    ``add table`` drops every leftover chain/set and rebuilds from scratch,
    converging like ``iptables-restore``.  The leading ``add table`` already in
    ``save`` makes the ``delete`` safe on a first run, and the whole script
    stays one atomic ``nft -f`` transaction.

    The transform is applied only to the apply text, never to ``save`` itself:
    ``save`` is also parsed by :func:`build_nft_delta` and backs the ``.nft``
    goldens, and by contract carries only ``add``/``flush`` table verbs -- the
    ``delete table`` reset is introduced here, into the apply text alone, which
    is fed straight to ``nft -f`` and never re-parsed.
    """
    prefix = f"{family} {NFT_TABLE_NAME}"
    flush_line = f"flush table {prefix}\n"
    replacement = f"delete table {prefix}\nadd table {prefix}\n"
    # No flush line (e.g. a save with nothing to flush) -> nothing to rewrite,
    # so this is a no-op; the leftover-chain hazard only exists where a flush
    # would have kept declarations alive.
    return save.replace(flush_line, replacement, 1)


# ---------------------------------------------------------------------------
# ferm ontology -> nft family / base-chain mapping
# ---------------------------------------------------------------------------


class BaseChainSpec(NamedTuple):
    """The nft base-chain declaration a ferm built-in chain maps to."""

    chain_type: str
    hook: str
    priority: int


#: (table, chain) -> (nft type, hook, priority).  Numeric priorities for
#: cross-version portability.
_BASE_CHAIN_MAP: Final[dict[tuple[str, str], BaseChainSpec]] = {
    ("filter", "INPUT"): BaseChainSpec("filter", "input", 0),
    ("filter", "FORWARD"): BaseChainSpec("filter", "forward", 0),
    ("filter", "OUTPUT"): BaseChainSpec("filter", "output", 0),
    ("nat", "PREROUTING"): BaseChainSpec("nat", "prerouting", -100),
    ("nat", "INPUT"): BaseChainSpec("nat", "input", 100),
    ("nat", "OUTPUT"): BaseChainSpec("nat", "output", -100),
    ("nat", "POSTROUTING"): BaseChainSpec("nat", "postrouting", 100),
    ("mangle", "PREROUTING"): BaseChainSpec("filter", "prerouting", -150),
    ("mangle", "INPUT"): BaseChainSpec("filter", "input", -150),
    ("mangle", "FORWARD"): BaseChainSpec("filter", "forward", -150),
    ("mangle", "OUTPUT"): BaseChainSpec("route", "output", -150),
    ("mangle", "POSTROUTING"): BaseChainSpec("filter", "postrouting", -150),
    ("raw", "PREROUTING"): BaseChainSpec("filter", "prerouting", -300),
    ("raw", "OUTPUT"): BaseChainSpec("filter", "output", -300),
}

#: arp supports only filter/INPUT and filter/OUTPUT.
_ARP_BASE_CHAIN_MAP: Final[dict[tuple[str, str], BaseChainSpec]] = {
    ("filter", "INPUT"): BaseChainSpec("filter", "input", 0),
    ("filter", "OUTPUT"): BaseChainSpec("filter", "output", 0),
}


def map_base_chain(
    domain: Family,
    table: str,
    chain: str,
) -> BaseChainSpec:
    """
    Map ``(table, built-in chain)`` to ``(nft type, hook, priority)``.

    A miss (broute/BROUTING, arp nat/mangle, unknown pair) raises
    :class:`~pyferm.errors.FermError` -- "built-in" does not imply
    "mappable".
    """
    table_map = _ARP_BASE_CHAIN_MAP if domain == "arp" else _BASE_CHAIN_MAP
    spec = table_map.get((table, chain))
    if spec is None:
        raise FermError(
            f"chain '{table}/{chain}' not yet supported by nft backend"
        )
    return spec


# ---------------------------------------------------------------------------
# chain-name disambiguation + chain-list builder
# ---------------------------------------------------------------------------


def nft_chain_name(table: str, chain: str) -> str:
    """
    Disambiguate a chain name inside the merged ``ferm`` table.

    The ``filter`` table keeps bare names (the common case, clean golden);
    every other table is prefixed ``<table>_<chain>`` so ``filter/INPUT``
    and ``mangle/INPUT`` do not collide.  Applied identically to chain
    definitions and to ``jump``/``goto`` targets.

    The final identifier is validated against nft's bare-word grammar (nft
    has no quoted-chain-name form): a name with whitespace/metacharacters
    would otherwise inject statements into ``add chain``/``jump`` -> a plain
    ferm error instead (review 2026-06-14, fix 1).
    """
    name = chain if table == "filter" else f"{table}_{chain}"
    if not _NFT_CHAIN_RE.match(name):
        raise FermError(f"chain name '{chain}' is not a valid nft identifier")
    return name


def build_chains(
    domain: Family,
    table: str,
    table_info: TableInfo,
) -> list[NftBaseChain | NftRegularChain]:
    """
    Build the sorted chain list for one table.

    :func:`is_netfilter_builtin_chain` selects the base-vs-user branch;
    :func:`map_base_chain` resolves the concrete hook (and errors on
    unmappable built-ins).  Policy is lowercased to nft spelling
    (``DROP`` -> ``drop``).  Names are disambiguated via
    :func:`nft_chain_name`.  Output is sorted for
    deterministic golden output.
    """
    chains: list[NftBaseChain | NftRegularChain] = []
    for name in sorted(table_info.chains):
        chain_info = table_info.chains[name]
        nft_name = nft_chain_name(table, name)
        if is_netfilter_builtin_chain(table, name):
            chain_type, hook, default_priority = map_base_chain(
                domain, table, name
            )
            # A config override (`chain X priority -1`) replaces the
            # hardcoded default; otherwise keep the _BASE_CHAIN_MAP value.
            priority = (
                chain_info.priority
                if chain_info.priority is not None
                else default_priority
            )
            policy = (
                chain_info.policy.lower()
                if chain_info.policy is not None
                else None
            )
            chains.append(
                NftBaseChain(
                    nft_name, chain_type, hook, priority, policy=policy
                )
            )
        else:
            if chain_info.priority is not None:
                raise FermError(
                    f"priority is only valid on a base chain, not "
                    f"user chain '{name}'"
                )
            chains.append(NftRegularChain(nft_name))
    return chains


# ---------------------------------------------------------------------------
# value unwrapping helpers
# ---------------------------------------------------------------------------


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
        raise FermError("unsupported value shape for nft backend")
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
            raise FermError("unsupported value shape for nft backend")
        return value.values[0]
    if isinstance(value, str):
        return value
    raise FermError("unsupported value shape for nft backend")


# ---------------------------------------------------------------------------
# translate_match
# ---------------------------------------------------------------------------

#: canonical option name -> nft address keyword.
_ADDR_KEYWORD: Final[dict[str, str]] = {
    "source": "saddr",
    "destination": "daddr",
}
#: canonical option name -> nft interface keyword.
_IFACE_KEYWORD: Final[dict[str, str]] = {
    "in-interface": "iifname",
    "out-interface": "oifname",
}
#: port option names; the nft keyword equals the ferm name.
_PORT_KEYWORD: Final[dict[str, str]] = {"sport": "sport", "dport": "dport"}
#: multiport option name -> nft port keyword.  The both-directions
#: ``ports`` form matches source OR destination; no single nft match
#: spells that disjunction, so it stays refused.
_MULTIPORT_KEYWORD: Final[dict[str, str]] = {
    "source-ports": "sport",
    "destination-ports": "dport",
}
#: xt_limit ``--limit-burst``: a positive packet count.
_NFT_BURST_RE: Final[re.Pattern[str]] = re.compile(r"\A[1-9]\d*\Z")
#: xt_limit's default rate, made explicit when only a burst is given.
_NFT_DEFAULT_LIMIT_RATE: Final[str] = "3/hour"


def _op(neg: bool) -> str:
    """Return the nft inequality prefix for a (possibly) negated match."""
    return "!= " if neg else ""


#: xt ``--pkt-type`` value -> nft ``meta pkttype`` keyword.  The kernel
#: respells ``unicast`` as ``host`` on readback, so it is emitted directly;
#: broadcast/multicast are spelled the same in both.
_PKTTYPE_MAP: Final[dict[str, str]] = {
    "unicast": "host",
    "broadcast": "broadcast",
    "multicast": "multicast",
}


#: iptables ``--icmp-type`` name -> nft ``icmp type`` name (ip family).
#: Only the top-level (code-less) type names translate; the iptables
#: subtype names (``network-unreachable``, ...) are type+code pairs with
#: no single nft type keyword and refuse cleanly.
_ICMP_TYPE_MAP: Final[dict[str, str]] = {
    "echo-reply": "echo-reply",
    "pong": "echo-reply",
    "destination-unreachable": "destination-unreachable",
    "source-quench": "source-quench",
    "redirect": "redirect",
    "echo-request": "echo-request",
    "ping": "echo-request",
    "router-advertisement": "router-advertisement",
    "router-solicitation": "router-solicitation",
    "time-exceeded": "time-exceeded",
    "ttl-exceeded": "time-exceeded",
    "parameter-problem": "parameter-problem",
    "timestamp-request": "timestamp-request",
    "timestamp-reply": "timestamp-reply",
    "address-mask-request": "address-mask-request",
    "address-mask-reply": "address-mask-reply",
}
#: iptables ``--icmpv6-type`` name -> nft ``icmpv6 type`` name.  The ND
#: names are respelled to nft's ``nd-*`` vocabulary; the shared names
#: keep their spelling (verified against nft v1.1.6).
_ICMP6_TYPE_MAP: Final[dict[str, str]] = {
    "destination-unreachable": "destination-unreachable",
    "packet-too-big": "packet-too-big",
    "time-exceeded": "time-exceeded",
    "ttl-exceeded": "time-exceeded",
    "parameter-problem": "parameter-problem",
    "echo-request": "echo-request",
    "ping": "echo-request",
    "echo-reply": "echo-reply",
    "pong": "echo-reply",
    "router-solicitation": "nd-router-solicit",
    "router-advertisement": "nd-router-advert",
    "neighbour-solicitation": "nd-neighbor-solicit",
    "neighbor-solicitation": "nd-neighbor-solicit",
    "neighbour-advertisement": "nd-neighbor-advert",
    "neighbor-advertisement": "nd-neighbor-advert",
    "redirect": "nd-redirect",
}
#: iptables numeric ``type`` or ``type/code`` form (one octet each).
_ICMP_NUMERIC_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(\d{1,3})(?:/(\d{1,3}))?\Z"
)
#: An icmp type/code is one octet.
_ICMP_OCTET_MAX: Final[int] = 255
#: A packet/ct mark is a 32-bit value.
_MARK_MAX: Final[int] = 0xFFFFFFFF
#: u16 ceiling shared by NFQUEUE queue numbers and synproxy mss/wscale.
_U16_MAX: Final[int] = 0xFFFF
#: the 8-bit IPv4 TTL / IPv6 hop-limit ceiling.
_HOPLIMIT_MAX: Final[int] = 255
#: An nflog group is a 16-bit netlink group number.
_NFLOG_GROUP_MAX: Final[int] = 65535
#: numeric icmp type -> the name the kernel readback prints it as
#: (captured from a live nft v1.1.6 ``nft list ruleset``).  A numeric
#: operand must emit that name, else the applied rule reads back
#: differently and ``--plan`` never converges; a number absent here
#: prints back numeric and stays as-is.  Codes always read back numeric.
_ICMP_TYPE_BY_NUMBER: Final[dict[int, str]] = {
    0: "echo-reply",
    3: "destination-unreachable",
    4: "source-quench",
    5: "redirect",
    8: "echo-request",
    9: "router-advertisement",
    10: "router-solicitation",
    11: "time-exceeded",
    12: "parameter-problem",
    13: "timestamp-request",
    14: "timestamp-reply",
    15: "info-request",
    16: "info-reply",
    17: "address-mask-request",
    18: "address-mask-reply",
}
#: numeric icmpv6 type -> kernel-readback name (same capture).
_ICMP6_TYPE_BY_NUMBER: Final[dict[int, str]] = {
    1: "destination-unreachable",
    2: "packet-too-big",
    3: "time-exceeded",
    4: "parameter-problem",
    128: "echo-request",
    129: "echo-reply",
    130: "mld-listener-query",
    131: "mld-listener-report",
    132: "mld-listener-done",
    133: "nd-router-solicit",
    134: "nd-router-advert",
    135: "nd-neighbor-solicit",
    136: "nd-neighbor-advert",
    137: "nd-redirect",
    138: "router-renumbering",
    141: "ind-neighbor-solicit",
    142: "ind-neighbor-advert",
    143: "mld2-listener-report",
}
#: TCP flag names in header bit order -- the kernel-readback order for
#: both the mask parenthesis and the comparison list.
_TCP_FLAG_ORDER: Final[tuple[str, ...]] = (
    "fin",
    "syn",
    "rst",
    "psh",
    "ack",
    "urg",
)
#: numeric arp opcode -> the operation name the kernel readback prints
#: (captured live from nft v1.1.6); unknown numbers stay numeric.
_ARP_OPERATION_BY_NUMBER: Final[dict[int, str]] = {
    1: "request",
    2: "reply",
    3: "rrequest",
    4: "rreply",
    8: "inrequest",
    9: "inreply",
    10: "nak",
}
#: A numeric low-high range operand (uid/gid, length after the colon
#: rewrite): the readback keeps the dash form.
_NUMERIC_RANGE_RE: Final[re.Pattern[str]] = re.compile(r"\A\d+-\d+\Z")
#: A colon-separated MAC address; the readback lowercases it.
_MAC_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\Z"
)
#: xt_ttl option name -> the comparator the kernel readback prints
#: (``gt``/``lt`` read back as ``>``/``<``).
_TTL_COMPARATOR: Final[dict[str, str]] = {
    "ttl-eq": "",
    "ttl-gt": "> ",
    "ttl-lt": "< ",
}
#: mod hl, xt_ttl's ip6 twin: the same comparator shapes over
#: ``ip6 hoplimit`` (readback prints ``>``/``<`` -- verified live).
_HL_COMPARATOR: Final[dict[str, str]] = {
    "hl-eq": "",
    "hl-gt": "> ",
    "hl-lt": "< ",
}
#: iptables addrtype value -> nft fib route type, keyed by kernel RTN
#: number (RTN_UNSPEC=0 ... RTN_PROHIBIT=8).  A type-list readback is
#: re-sorted into this order, so a comma-list literal must be emitted
#: pre-sorted the same way or --plan diffs an already-applied ruleset
#: forever.  throw/nat/xresolve carry no fib type and refuse.
_FIB_TYPE_RANK: Final[dict[str, int]] = {
    "unspec": 0,
    "unicast": 1,
    "local": 2,
    "broadcast": 3,
    "anycast": 4,
    "multicast": 5,
    "blackhole": 6,
    "unreachable": 7,
    "prohibit": 8,
}
#: addrtype option name -> the fib address selector it queries.
_FIB_SELECTOR: Final[dict[str, str]] = {
    "src-type": "saddr",
    "dst-type": "daddr",
}
#: dscp codepoint -> the class name nft's readback prints; every other
#: value in 0-63 reads back as 0x%02x.  Pinned by
#: tests/e2e/readback/driver.py (nft v1.1.6); re-capture on an nft bump
#: rather than editing by hand.  nft knows lephb (0x01) and va (0x2c),
#: which the iptables --dscp-class input table below does not.
_DSCP_NAMES: Final[dict[int, str]] = {
    0x00: "cs0",
    0x01: "lephb",
    0x08: "cs1",
    0x0A: "af11",
    0x0C: "af12",
    0x0E: "af13",
    0x10: "cs2",
    0x12: "af21",
    0x14: "af22",
    0x16: "af23",
    0x18: "cs3",
    0x1A: "af31",
    0x1C: "af32",
    0x1E: "af33",
    0x20: "cs4",
    0x22: "af41",
    0x24: "af42",
    0x26: "af43",
    0x28: "cs5",
    0x2C: "va",
    0x2E: "ef",
    0x30: "cs6",
    0x38: "cs7",
}
#: iptables --dscp-class name -> codepoint (the input class table).  `be`
#: (best effort) is 0x00, so it emits as cs0 after canonicalization.
_DSCP_CLASS: Final[dict[str, int]] = {
    "cs0": 0x00,
    "cs1": 0x08,
    "cs2": 0x10,
    "cs3": 0x18,
    "cs4": 0x20,
    "cs5": 0x28,
    "cs6": 0x30,
    "cs7": 0x38,
    "af11": 0x0A,
    "af12": 0x0C,
    "af13": 0x0E,
    "af21": 0x12,
    "af22": 0x14,
    "af23": 0x16,
    "af31": 0x1A,
    "af32": 0x1C,
    "af33": 0x1E,
    "af41": 0x22,
    "af42": 0x24,
    "af43": 0x26,
    "ef": 0x2E,
    "be": 0x00,
}
#: max dscp codepoint (the 6-bit DSCP field).
_DSCP_MAX: Final[int] = 0x3F
#: tc classid handle for CLASSIFY: two 1-4 hex-digit halves.  A wider half
#: is rejected -- the kernel refuses it too.
_CLASSID_RE: Final = re.compile(r"\A([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})\Z")
#: tc reserves handle ffff:ffff for the root qdisc (spelled ``root``).
_TC_HANDLE_ROOT: Final[int] = 0xFFFF


def _tcp_flag_list(scalar: str) -> list[str]:
    """Parse one iptables flag list into header-bit order (``ALL`` too)."""
    if scalar.lower() == "all":
        return list(_TCP_FLAG_ORDER)
    seen: set[str] = set()
    for raw in scalar.split(","):
        token = raw.lower()
        if token not in _TCP_FLAG_ORDER:
            raise FermError(f"unknown tcp flag '{raw}' for nft backend")
        seen.add(token)
    return [flag for flag in _TCP_FLAG_ORDER if flag in seen]


def _tcp_flags_expr(value: Value) -> str:
    """
    Translate ``--tcp-flags MASK COMP`` to the kernel-readback spelling.

    The readback prints the BITWISE form (``tcp flags & (fin | syn) ==
    syn``), not iptables-translate's slash form; a single-flag mask is
    unparenthesized and a multi-flag comparison carries no parentheses
    (all verified live).  ``COMP == NONE`` reads back as the
    flag-absence form ``tcp flags ! fin,syn``; its negation would need
    a ``!= 0x0`` the readback respells, so it refuses.
    """
    neg = False
    if isinstance(value, (Negated, PreNegated)):
        value = value.value
        neg = True
    if not isinstance(value, Params):
        raise FermError("unsupported value shape for nft backend")
    try:
        mask_raw, comp_raw = value.values
    except ValueError:
        raise FermError("unsupported value shape for nft backend") from None
    if not isinstance(mask_raw, str) or not isinstance(comp_raw, str):
        raise FermError("unsupported value shape for nft backend")
    mask = _tcp_flag_list(mask_raw)
    if comp_raw.lower() == "none":
        if neg:
            raise FermError(
                "negated tcp-flags NONE cannot be expressed for nft backend"
            )
        return f"tcp flags ! {','.join(mask)}"
    comp = _tcp_flag_list(comp_raw)
    mask_text = mask[0] if len(mask) == 1 else f"({' | '.join(mask)})"
    operator = "!=" if neg else "=="
    return f"tcp flags & {mask_text} {operator} {' | '.join(comp)}"


def _owner_value(name: str, scalar: str) -> str:
    """
    Canonicalize a ``--uid-owner``/``--gid-owner`` operand to a number.

    nft resolves a user/group name at parse time and the kernel
    readback prints the id, so a name emitted verbatim would leave
    ``--plan`` diffing forever; numeric ids and dash ranges pass
    through (the readback keeps both).
    """
    if scalar.isdigit() or _NUMERIC_RANGE_RE.match(scalar):
        return scalar
    if name == "uid-owner":
        try:
            return str(pwd.getpwnam(scalar).pw_uid)
        except KeyError:
            raise FermError(
                f"unknown user '{scalar}' for nft backend"
            ) from None
    try:
        return str(grp.getgrnam(scalar).gr_gid)
    except KeyError:
        raise FermError(f"unknown group '{scalar}' for nft backend") from None


def _nft_rate(scalar: str) -> str:
    """
    Normalize an xt_limit rate to nft's spelling.

    xt_limit accepts any case-insensitive prefix of the unit
    (``10/min``, ``10/m``) and treats a bare number as per-second; nft's
    grammar wants the full lowercase unit (upstream reference:
    ``iptables-translate``).  Passing the abbreviated form through would
    emit a script ``nft -f`` rejects only at apply time.
    """
    match = _NFT_RATE_RE.match(scalar)
    if match:
        count, prefix = match.group(1), match.group(2)
        if prefix is None:
            return f"{count}/second"
        lowered = prefix.lower()
        for unit in _NFT_RATE_UNITS:
            if unit.startswith(lowered):
                return f"{count}/{unit}"
    raise FermError(f"invalid rate '{scalar}' for nft backend")


def _mark_value(scalar: str) -> str:
    """
    Canonicalize a mark operand to the kernel-readback spelling.

    nft prints a mark as 8-digit hex (``0x00000002``), so any other
    emission leaves ``--plan`` diffing an applied ruleset forever.
    Accepts the iptables decimal/hex forms; the ``value/mask`` form has
    no single infix nft match and refuses.
    """
    if "/" in scalar:
        base, _, mask = scalar.partition("/")
        try:
            full_mask = int(mask, 0) == _MARK_MAX
        except ValueError:
            full_mask = False
        if not full_mask:
            raise FermError(
                f"masked mark '{scalar}' not yet supported by nft backend"
            )
        # (mark & 0xffffffff) == value IS the plain equality
        scalar = base
    try:
        value = int(scalar, 0)
    except ValueError:
        raise FermError(f"invalid mark '{scalar}' for nft backend") from None
    if not 0 <= value <= _MARK_MAX:
        raise FermError(f"invalid mark '{scalar}' for nft backend")
    return f"0x{value:08x}"


def _masked_mark_set(
    scalar: str,
    option_name: str = "tproxy-mark",
    register: str = "meta mark",
) -> str:
    """
    Spell a ``value[/mask]`` mark rewrite as an nft *register* assignment.

    Shared by TPROXY's ``--tproxy-mark`` and the MARK/CONNMARK ``set-xmark``
    forms (``register`` selects ``meta mark`` or ``ct mark``).  xt computes
    ``newmark = (mark & ~mask) ^ value``; the kernel canonicalizes the and/xor
    tree to an and/or form when ``value`` lies within ``mask`` (xor over zeroed
    bits is or), and the ``& A`` operand it prints already carries the ``| V``
    bits -- ``A = ~mask | value`` does, so the and/or emission round-trips.  A
    full mask (or the xt default when the mask is omitted) folds to a plain
    set.  A value with bits outside its mask has a different canonical form
    that would not round-trip, and a zero mask is an identity assignment; both
    refuse.
    """
    base, sep, mask = scalar.partition("/")
    if not sep:
        return f"{register} set {_mark_value(base)}"
    try:
        value = int(base, 0)
        mask_value = int(mask, 0)
    except ValueError:
        raise FermError(
            f"invalid {option_name} '{scalar}' for nft backend"
        ) from None
    if not (0 <= value <= _MARK_MAX and 0 <= mask_value <= _MARK_MAX):
        raise FermError(f"invalid {option_name} '{scalar}' for nft backend")
    if mask_value == 0:
        raise FermError(
            f"{option_name} '{scalar}' has a zero mask (a no-op) for nft "
            "backend"
        )
    if value & ~mask_value & _MARK_MAX:
        raise FermError(
            f"{option_name} '{scalar}' value has bits outside its mask for "
            f"nft backend"
        )
    if mask_value == _MARK_MAX:
        return f"{register} set {_mark_value(base)}"
    and_operand = (~mask_value | value) & _MARK_MAX
    if and_operand == _MARK_MAX and value != 0:
        return f"{register} set {register} | 0x{value:08x}"
    if value == 0:
        return f"{register} set {register} & 0x{and_operand:08x}"
    return f"{register} set {register} & 0x{and_operand:08x} | 0x{value:08x}"


def _setmark_effective(scalar: str) -> str:
    """
    Rewrite ``--set-mark value/mask`` to the xmark form the kernel compiles.

    xt's MARK/CONNMARK ``--set-mark`` clears then sets only the masked bits
    but does so with an EFFECTIVE mask ``m' = value | mask``, so a value with
    bits outside the literal mask (``0xff/0x0f``) is legal and its result is
    ``(mark & ~m') | value``.  Substituting ``m'`` before the and/or canon
    keeps the ``value`` within its mask, so the shared ``set-mark`` path never
    needs the ``value ⊄ mask`` guard.  A bare value (no mask) passes through
    to the plain-set path unchanged.
    """
    base, sep, mask = scalar.partition("/")
    if not sep:
        return scalar
    try:
        value = int(base, 0)
        mask_value = int(mask, 0)
    except ValueError:
        raise FermError(
            f"invalid set-mark '{scalar}' for nft backend"
        ) from None
    if not (0 <= value <= _MARK_MAX and 0 <= mask_value <= _MARK_MAX):
        raise FermError(f"invalid set-mark '{scalar}' for nft backend")
    return f"0x{value:x}/0x{value | mask_value:x}"


def _mark_arith_operand(option: RenderedOption) -> str:
    """Validate an and/or/xor-mark operand and spell it as 8-digit hex."""
    scalar, _ = unwrap_value(option.value)
    return _mark_value(scalar)


def _mark_arith_set(
    register: str, target: str, companions: dict[str, RenderedOption]
) -> str:
    """
    Spell one MARK/CONNMARK mark-arithmetic op as a *register* rewrite.

    Exactly one of ``set-mark``/``set-xmark``/``and-mark``/``or-mark``/
    ``xor-mark`` may be present (``provided != 1`` refuses with the target's
    own message); ``set-mark``/``set-xmark`` fold to the and/or canon (via
    :func:`_masked_mark_set`, with ``set-mark``'s effective mask applied
    first), and the bitwise ops emit ``<reg> set <reg> <op> 0x%08x`` in the
    kernel-readback spelling (``&``/``|``/``^``).
    """
    setmark = companions.get("set-mark")
    setxmark = companions.get("set-xmark")
    andmark = companions.get("and-mark")
    ormark = companions.get("or-mark")
    xormark = companions.get("xor-mark")
    provided = sum(
        option is not None
        for option in (setmark, setxmark, andmark, ormark, xormark)
    )
    if provided != 1:
        raise FermError(f"{target} target not yet supported by nft backend")
    if setxmark is not None:
        scalar, _ = unwrap_value(setxmark.value)
        return _masked_mark_set(scalar, "set-xmark", register)
    if setmark is not None:
        scalar, _ = unwrap_value(setmark.value)
        return _masked_mark_set(
            _setmark_effective(scalar), "set-mark", register
        )
    if andmark is not None:
        return f"{register} set {register} & {_mark_arith_operand(andmark)}"
    if ormark is not None:
        return f"{register} set {register} | {_mark_arith_operand(ormark)}"
    if (
        xormark is None
    ):  # narrowed by provided == 1; keep the checker convinced
        raise internal_error()
    return f"{register} set {register} ^ {_mark_arith_operand(xormark)}"


def _masked_mark_expr(selector: str, scalar: str, neg: bool) -> str | None:
    """
    Spell a partial-mask xt mark match as nft's infix bitwise form.

    Returns None when the plain-equality path applies instead.
    xt matches ``(mark & mask) == value``; the kernel readback prints
    both operands as 8-digit hex (``& 0x00000003 == 0x00000000``) --
    verified live.  A full mask folds to plain equality inside
    :func:`_mark_value` instead.
    """
    if "/" not in scalar:
        return None
    base, _, mask = scalar.partition("/")
    try:
        value = int(base, 0)
        mask_value = int(mask, 0)
    except ValueError:
        raise FermError(f"invalid mark '{scalar}' for nft backend") from None
    if mask_value == _MARK_MAX:
        return None
    if not (0 <= value <= _MARK_MAX and 0 <= mask_value <= _MARK_MAX):
        raise FermError(f"invalid mark '{scalar}' for nft backend")
    operator = "!=" if neg else "=="
    return f"{selector} & 0x{mask_value:08x} {operator} 0x{value:08x}"


def _icmp_type_expr(domain: Family, scalar: str, neg: bool) -> str:
    """
    Translate one ``icmp-type`` operand to an nft match expression.

    The selector keyword follows the *domain* (``icmpv6`` under ip6, cf.
    :func:`_nft_l4proto`), not the rendered protocol, which stays the raw
    ``icmp`` spelling.  Accepted operands mirror what iptables accepts:
    a top-level type name (mapped per family), a numeric type, or a
    numeric ``type/code`` pair.  A negated ``type/code`` pair refuses --
    ``!(type == t && code == c)`` has no infix nft equivalent, and the
    De Morgan misreading ``type != t code != c`` would match the wrong
    packets.
    """
    keyword = "icmpv6" if domain is Family.IP6 else "icmp"
    by_number = (
        _ICMP6_TYPE_BY_NUMBER if domain is Family.IP6 else _ICMP_TYPE_BY_NUMBER
    )
    numeric = _ICMP_NUMERIC_RE.match(scalar)
    if numeric:
        type_num, code_num = numeric.group(1), numeric.group(2)
        if int(type_num) > _ICMP_OCTET_MAX or (
            code_num is not None and int(code_num) > _ICMP_OCTET_MAX
        ):
            raise FermError(f"invalid icmp type '{scalar}' for nft backend")
        type_text = by_number.get(int(type_num), type_num)
        if code_num is None:
            return f"{keyword} type {_op(neg)}{type_text}"
        if neg:
            raise FermError(
                "negated icmp type/code match cannot be expressed as "
                "infix nft matches"
            )
        return f"{keyword} type {type_text} {keyword} code {code_num}"
    table = _ICMP6_TYPE_MAP if domain is Family.IP6 else _ICMP_TYPE_MAP
    name = table.get(scalar)
    if name is None:
        raise FermError(
            f"icmp-type '{scalar}' not yet supported by nft backend"
        )
    return f"{keyword} type {_op(neg)}{name}"


def _fib_type_literal(scalar: str) -> str:
    """
    Render the fib type operand from an iptables addrtype value.

    A comma-list is sorted into kernel RTN order (the readback re-sorts it,
    negated lists included), so the emitted literal already matches what
    ``nft list ruleset`` prints back.  A type with no fib equivalent
    (throw/nat/xresolve, or anything unknown) refuses by name.
    """
    ordered: list[str] = []
    for token in scalar.split(","):
        lowered = token.strip().lower()
        if lowered not in _FIB_TYPE_RANK:
            raise FermError(
                f"address type '{token.strip()}' has no nft fib equivalent"
            )
        ordered.append(lowered)
    ordered.sort(key=lambda type_name: _FIB_TYPE_RANK[type_name])
    if len(ordered) == 1:
        return ordered[0]
    return f"{{ {', '.join(ordered)} }}"


def _fib_type_match(name: str, value: Value, iface: str) -> str:
    """
    Build the ``fib <selector>[ . iif|oif] type <literal>`` match.

    *iface* is the routing-interface qualifier collected rule-wide from
    addrtype's limit-iface-in/out flags ("" when absent); it applies to
    every fib match in the rule.  fib works in both ip and ip6 with no
    family prefix, so the selector needs no ``domain``.
    """
    scalar, neg = unwrap_value(value)
    selector = _FIB_SELECTOR[name]
    return f"fib {selector}{iface} type {_op(neg)}{_fib_type_literal(scalar)}"


def _dscp_canon(value: int) -> str:
    """Spell a dscp codepoint as nft's kernel readback does (name or 0xNN)."""
    return _DSCP_NAMES.get(value, f"0x{value:02x}")


def _dscp_value(name: str, scalar: str) -> int:
    """Parse a numeric dscp value (``int(x, 0)``, 0-63) or refuse by name."""
    try:
        value = int(scalar, 0)
    except ValueError:
        raise FermError(
            f"option '{name}': invalid dscp value '{scalar}' for nft backend"
        ) from None
    if not 0 <= value <= _DSCP_MAX:
        raise FermError(
            f"option '{name}': dscp value '{scalar}' out of range 0-63 "
            f"for nft backend"
        )
    return value


def _dscp_class_value(name: str, scalar: str) -> int:
    """Resolve an iptables dscp class to its codepoint or refuse by name."""
    value = _DSCP_CLASS.get(scalar.lower())
    if value is None:
        raise FermError(
            f"option '{name}': unknown dscp class '{scalar}' for nft backend"
        )
    return value


def _classify_priority(scalar: str) -> str:
    """
    Render a tc classid (H:M) as nft's ``meta priority`` readback spells it.

    Leading zeros strip in each half and it lowercases (00ff:0abc -> ff:abc);
    the tc specials ffff:ffff and 0:0 read back as root and none.  A half
    wider than four hex digits is rejected, mirroring the kernel.
    """
    matched = _CLASSID_RE.match(scalar)
    if matched is None:
        raise FermError(
            f"option 'set-class': invalid tc class '{scalar}' for nft backend"
        )
    major = int(matched.group(1), 16)
    minor = int(matched.group(2), 16)
    if major == _TC_HANDLE_ROOT and minor == _TC_HANDLE_ROOT:
        return "root"
    if major == 0 and minor == 0:
        return "none"
    return f"{major:x}:{minor:x}"


def _tos_refusal(kind: str, name: str) -> FermError:
    """
    Build the shared TOS refusal (match ``tos`` and target ``TOS``).

    No single nft selector spans the whole 8-bit TOS byte with a mask, so
    silently emitting dscp alone would drop the ECN bits -- a fail-loud
    refusal instead, phrased so it does not promise a future fix.
    """
    return FermError(
        f"{kind} '{name}' has no nft equivalent (no single nft selector "
        f"covers the full 8-bit TOS byte with a mask; nft exposes dscp "
        f"and ecn separately)"
    )


def _ct_bitmask_expr(
    selector: str, members: list[str], rank: dict[str, int], neg: bool
) -> str:
    """
    Spell a ``ct state``/``ct status`` bitmask match in readback canon.

    The readback prints members deduplicated in ascending bit order.  A
    negated match must use the masked bang form (``ct status ! a,b``,
    "none of the bits set"): the ``!=`` spelling compares the WHOLE
    register against the OR of the bits -- true for nearly every packet
    -- which is not what iptables' ``! --ctstate a,b`` means (verified
    against the netlink bytecode).  The one exception: a packet's ct
    state register holds exactly one state bit, so a single-member
    negated state keeps the pre-existing ``!=`` canon (both forms
    round-trip and are faithful there).
    """
    ordered = sorted(set(members), key=rank.__getitem__)
    joined = ",".join(ordered)
    if not neg:
        return f"{selector} {joined}"
    if selector == "ct state" and len(ordered) == 1:
        return f"{selector} != {joined}"
    return f"{selector} ! {joined}"


def _nfqueue_verdict(companions: dict[str, RenderedOption]) -> NftVerdict:
    """
    Spell NFQUEUE as nft's ``queue`` statement.

    The kernel reads ``queue num N`` back as ``queue [flags ...] to N``
    (flags in bypass,fanout order; a bare NFQUEUE as ``queue to 0``), so
    that form is emitted directly.  xt_NFQUEUE refuses --queue-cpu-fanout
    without --queue-balance, so the translation refuses too.
    """
    num = companions.get("queue-num")
    balance = companions.get("queue-balance")
    if num is not None and balance is not None:
        raise FermError(
            "'queue-num' and 'queue-balance' are mutually exclusive for "
            "the nft backend"
        )
    if "queue-cpu-fanout" in companions and balance is None:
        raise FermError(
            "option 'queue-cpu-fanout' needs 'queue-balance' for the "
            "nft backend"
        )
    if balance is not None:
        scalar, _ = unwrap_value(balance.value)
        low, sep, high = scalar.partition(":")
        if not (sep and low.isdigit() and high.isdigit()):
            raise FermError(
                f"invalid queue-balance '{scalar}' for nft backend"
            )
        to = f"{int(low)}-{int(high)}"
    elif num is not None:
        scalar, _ = unwrap_value(num.value)
        if not scalar.isdigit() or int(scalar) > _U16_MAX:
            raise FermError(f"invalid queue-num '{scalar}' for nft backend")
        to = str(int(scalar))
    else:
        to = "0"
    flags = [
        flag
        for companion_name, flag in (
            ("queue-bypass", "bypass"),
            ("queue-cpu-fanout", "fanout"),
        )
        if companion_name in companions
    ]
    parts = ["queue"]
    if flags:
        parts.append(f"flags {','.join(flags)}")
    parts.append(f"to {to}")
    return NftVerdict(" ".join(parts))


def _hoplimit_verdict(
    target_value: str, companions: dict[str, RenderedOption]
) -> NftVerdict:
    """
    Spell ``--ttl-set``/``--hl-set`` as an nft hop-limit rewrite.

    The readback canon is ``ip ttl set N`` / ``ip6 hoplimit set N``.
    nft's payload-set grammar has no arithmetic form, so the inc/dec
    variants refuse.
    """
    prefix = "ttl" if target_value == "TTL" else "hl"
    for arith in (f"{prefix}-inc", f"{prefix}-dec"):
        if arith in companions:
            raise FermError(
                f"option '{arith}' not yet supported by nft backend"
            )
    comp = companions.get(f"{prefix}-set")
    if comp is None:
        raise FermError(
            f"{target_value} target not yet supported by nft backend"
        )
    scalar, _ = unwrap_value(comp.value)
    if not scalar.isdigit() or int(scalar) > _HOPLIMIT_MAX:
        raise FermError(f"invalid {prefix}-set '{scalar}' for nft backend")
    selector = "ip ttl" if target_value == "TTL" else "ip6 hoplimit"
    return NftVerdict(f"{selector} set {int(scalar)}")


def _synproxy_verdict(companions: dict[str, RenderedOption]) -> NftVerdict:
    """
    Spell SYNPROXY as nft's ``synproxy`` statement.

    The kernel readback prints the parts in a fixed order (mss, wscale,
    timestamp, sack-perm) and prints mss/wscale as a PAIR whenever either
    is given: the nft frontend raises both kernel flags together, so the
    absent one reads back as 0 -- verified live; the pair is emitted to
    match.  nft's synproxy grammar has no --ecn twin.
    """
    if "ecn" in companions:
        raise FermError("option 'ecn' has no nft synproxy equivalent")
    parts = ["synproxy"]
    mss = companions.get("mss")
    wscale = companions.get("wscale")
    if mss is not None or wscale is not None:
        for label, comp in (("mss", mss), ("wscale", wscale)):
            scalar = "0" if comp is None else unwrap_value(comp.value)[0]
            if not scalar.isdigit() or int(scalar) > _U16_MAX:
                raise FermError(
                    f"invalid synproxy {label} '{scalar}' for nft backend"
                )
            parts.append(f"{label} {int(scalar)}")
    if "timestamp" in companions:
        parts.append("timestamp")
    if "sack-perm" in companions:
        parts.append("sack-perm")
    return NftVerdict(" ".join(parts))


def _tproxy_verdict(
    domain: Family,
    companions: dict[str, RenderedOption],
    *,
    has_transport: bool,
) -> NftVerdict:
    """
    Spell TPROXY as nft's ``tproxy`` statement plus a terminal accept.

    xt_TPROXY needs a transport match (the kernel rejects the applied rule
    without one) and always demands ``--on-port`` (the xt oracle refuses a
    bare or on-ip-only form).  The readback keeps a bare on-port as
    ``tproxy to :P``, an on-ip mapping as ``tproxy to A:P`` (bracketed for
    ip6), and a ``--tproxy-mark`` as a following mark rewrite.  xt_TPROXY
    returns NF_ACCEPT, so a terminal accept is appended; the whole thing is
    one composite verdict statement (the NFQUEUE/SYNPROXY precedent).
    """
    if not has_transport:
        raise FermError(
            "TPROXY needs a transport protocol match (tcp/udp) for the "
            "nft backend"
        )
    on_port = companions.get("on-port")
    if on_port is None:
        raise FermError("TPROXY needs 'on-port' for the nft backend")
    port_scalar = first_scalar(on_port.value)
    if not port_scalar.isdigit() or int(port_scalar) > _U16_MAX:
        raise FermError(f"invalid on-port '{port_scalar}' for nft backend")
    port = str(int(port_scalar))
    on_ip = companions.get("on-ip")
    if on_ip is None:
        destination = f":{port}"
    else:
        addr = _validate_address(first_scalar(on_ip.value))
        destination = (
            f"[{addr}]:{port}" if domain is Family.IP6 else f"{addr}:{port}"
        )
    parts = [f"tproxy to {destination}"]
    mark = companions.get("tproxy-mark")
    if mark is not None:
        parts.append(_masked_mark_set(first_scalar(mark.value)))
    parts.append("accept")
    return NftVerdict(" ".join(parts))


#: built-in nat chain -> the address side xt NETMAP rewrites on its hook
#: (prerouting/output rewrite the destination, postrouting/input the
#: source).
_NETMAP_SIDE: Final[dict[str, str]] = {
    "PREROUTING": "daddr",
    "OUTPUT": "daddr",
    "INPUT": "saddr",
    "POSTROUTING": "saddr",
}


def _netmap_network(
    scalar: str, domain: Family
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """
    Parse a strict CIDR network of *domain*'s family, else a plain error.

    xt NETMAP silently masks host bits out of ``--to``; the nft map form
    spells the network literally, so a host-bit operand (or a bare
    address without a prefix length) refuses instead of being rewritten.
    """
    if "/" not in scalar:
        raise FermError(
            f"NETMAP prefix '{scalar}' needs an explicit prefix length "
            f"for the nft backend"
        )
    try:
        network = ipaddress.ip_network(scalar, strict=True)
    except ValueError as exc:
        raise FermError(f"NETMAP prefix '{scalar}': {exc}") from None
    if network.version != (4 if domain is Family.IP else 6):
        raise FermError(
            f"NETMAP prefix '{scalar}' does not match the {domain} family"
        )
    return network


def _netmap_verdict(
    domain: Family,
    table: str,
    chain: str | None,
    companions: dict[str, RenderedOption],
    options: list[RenderedOption],
) -> NftVerdict:
    """
    Spell NETMAP as nft's prefix-to-prefix NAT map.

    The readback canon is ``dnat ip prefix to ip daddr map { A : B }``.
    The nft map form needs the original prefix as its key, so the rule
    must carry a same-side address match of the same prefix length; and
    the hook side is only known statically inside a built-in nat chain
    (a custom chain can be jumped from either side).
    """
    side = _NETMAP_SIDE.get(chain or "") if table == "nat" else None
    if side is None:
        raise FermError(
            "NETMAP translates only inside a built-in nat chain "
            "(PREROUTING/OUTPUT rewrite the destination, "
            "POSTROUTING/INPUT the source) for the nft backend"
        )
    comp = companions.get("to")
    if comp is None:
        raise FermError("NETMAP target not yet supported by nft backend")
    match_name = "destination" if side == "daddr" else "source"
    operands = [o for o in options if o.name == match_name]
    if len(operands) != 1:
        raise FermError(
            f"NETMAP needs exactly one '{match_name}' match to name the "
            f"mapped prefix for the nft backend"
        )
    original, neg = unwrap_value(operands[0].value)
    if neg:
        raise FermError(
            f"NETMAP cannot map a negated '{match_name}' match for the "
            f"nft backend"
        )
    to_scalar, _ = unwrap_value(comp.value)
    original_net = _netmap_network(original, domain)
    to_net = _netmap_network(to_scalar, domain)
    if original_net.prefixlen != to_net.prefixlen:
        raise FermError(
            f"NETMAP prefix lengths differ ('{original}' vs '{to_scalar}') "
            f"for the nft backend"
        )
    statement = "dnat" if side == "daddr" else "snat"
    return NftVerdict(
        f"{statement} {domain} prefix to {domain} {side} "
        f"map {{ {original_net} : {to_net} }}"
    )


def _iprange_bound(domain: Family, scalar: str) -> str:
    """
    Validate one ``mod iprange`` boundary as an address of *domain*'s family.

    The bound passes the safe-operand regex (:func:`_validate_address`) and
    must be a literal address of the rule's family -- an ip6 bound in an ip
    rule refuses here rather than emitting a script ``nft -c`` would reject.
    """
    safe = _validate_address(scalar)
    try:
        addr = ipaddress.ip_address(safe)
    except ValueError:
        raise FermError(
            f"invalid iprange bound '{scalar}' for the nft backend"
        ) from None
    if addr.version != (4 if domain is Family.IP else 6):
        raise FermError(
            f"iprange bound '{scalar}' does not match the {domain} family "
            "for the nft backend"
        )
    return safe


def _translate_match_parts(
    domain: Family, option: RenderedOption, protocol: str | None
) -> tuple[str, str | None, str | None]:
    """
    Translate one match option to (expr, set_key, element).

    ``set_key``/``element`` are non-None only for an eligible, non-negated
    match; the element string is the SAME operand baked into ``expr`` (single
    source of truth -- no reverse-parsing).
    """
    name = option.name
    # The tcp-flags/syn shapes carry Params/None values that unwrap_value
    # refuses, so they dispatch before it.
    if name == "tcp-flags":
        return (_tcp_flags_expr(option.value), None, None)
    if name == "syn":
        # --syn is --tcp-flags FIN,SYN,RST,ACK SYN (a no-arg option)
        negated = isinstance(option.value, (Negated, PreNegated))
        operator = "!=" if negated else "=="
        return (
            f"tcp flags & (fin | syn | rst | ack) {operator} syn",
            None,
            None,
        )
    try:
        scalar, neg = unwrap_value(option.value)
    except FermError as exc:
        # the bare unwrap message ("multi-value cannot...") would leave
        # a corpus refusal anonymous; the option name makes it actionable
        raise FermError(f"option '{name}': {exc}") from None
    if name in _ADDR_KEYWORD:
        addr = _validate_address(scalar)
        key = _match_selector(domain, name, protocol)
        expr = f"{key} {_op(neg)}{addr}"
        return (expr, None, None) if neg else (expr, key, addr)
    if name in _IFACE_KEYWORD:
        # An interface is an nft quoted string; the iptables trailing-`+`
        # wildcard becomes nft's `*` inside the quotes.
        quoted = _nft_ifname(scalar)
        key = _match_selector(domain, name, protocol)
        expr = f"{key} {_op(neg)}{quoted}"
        # The element is the quoted form ('"eth0"'): a folded set renders
        # iifname { "eth0", "eth1" } which is valid nft syntax.
        return (expr, None, None) if neg else (expr, key, quoted)
    if name in _PORT_KEYWORD:
        # _match_selector carries the tcp/udp guard; it must fire before
        # the port operand is validated (error-order contract).
        key = _match_selector(domain, name, protocol)
        port = _validate_port(scalar)
        expr = f"{key} {_op(neg)}{port}"
        return (expr, None, None) if neg else (expr, key, port)
    if name in ("state", "ctstate"):
        # mod conntrack's ctstate and mod state translate to `ct state`;
        # the xt_conntrack-only SNAT/DNAT pseudo-states are ct STATUS
        # bits.  A mixed list matches ANY member in iptables (one OR
        # across both registers), which no single nft rule can spell.
        members = scalar.lower().split(",")
        for member in members:
            if member not in _CT_STATES and (
                member not in _CT_NAT_PSEUDO_STATES
            ):
                raise FermError(f"unknown ct state '{member}' for nft backend")
        states = [m for m in members if m in _CT_STATES]
        statuses = [m for m in members if m in _CT_NAT_PSEUDO_STATES]
        if states and statuses:
            raise FermError(
                f"option '{name}': a list mixing connection states and "
                f"SNAT/DNAT pseudo-states matches any of them; nft cannot "
                f"OR 'ct state' with 'ct status' in one rule"
            )
        if statuses:
            expr = _ct_bitmask_expr(
                "ct status", statuses, _CT_STATUS_RANK, neg
            )
        else:
            expr = _ct_bitmask_expr("ct state", states, _CT_STATE_RANK, neg)
        return (expr, None, None)
    if name == "ctstatus":
        # xt_conntrack --ctstatus, with the same any-bit OR semantics as
        # ctstate; NONE (an empty status mask) has no nft spelling.
        members = [m.lower().replace("_", "-") for m in scalar.split(",")]
        for member in members:
            if member not in _CTSTATUS_TOKENS:
                raise FermError(
                    f"ct status '{member}' not yet supported by nft backend"
                )
        return (
            _ct_bitmask_expr("ct status", members, _CT_STATUS_RANK, neg),
            None,
            None,
        )
    if name in _MULTIPORT_KEYWORD:
        if protocol not in PORT_PROTOCOLS:
            raise FermError(
                f"option '{name}' needs a tcp/udp protocol for the nft backend"
            )
        members = [_validate_port(member) for member in scalar.split(",")]
        key = f"{protocol} {_MULTIPORT_KEYWORD[name]}"
        if len(members) == 1:
            return (f"{key} {_op(neg)}{members[0]}", None, None)
        return (
            f"{key} {_op(neg)}{{ {', '.join(members)} }}",
            None,
            None,
        )
    if name == "limit":
        return (f"limit rate {_nft_rate(scalar)}", None, None)
    if name == "icmp-type":
        # Not set-eligible: a bare-word element has no canonical rank in
        # sort_set_elements (unparsable stays in input order), so a
        # folded { echo-request, echo-reply } set could not converge
        # under --plan.
        return (_icmp_type_expr(domain, scalar, neg), None, None)
    if name in ("dscp", "dscp-class") and domain in (Family.IP, Family.IP6):
        # Not set-eligible (icmp-type precedent): class names are bare words
        # with no rank in sort_set_elements, so a folded set could not
        # converge under --plan; a ferm array stays a cartesian unfold.
        # arp/eb have no dscp selector and fall through to the refusal.
        value = (
            _dscp_value(name, scalar)
            if name == "dscp"
            else _dscp_class_value(name, scalar)
        )
        return (f"{domain} dscp {_op(neg)}{_dscp_canon(value)}", None, None)
    if name == "tos":
        raise _tos_refusal("option", "tos")
    if name == "mark":
        # mod mark and mod connmark both spell their option `mark`; the
        # module tells the packet-mark selector from the ct one.
        selector = "ct mark" if option.module == "connmark" else "meta mark"
        masked = _masked_mark_expr(selector, scalar, neg)
        if masked is not None:
            return (masked, None, None)
        return (f"{selector} {_op(neg)}{_mark_value(scalar)}", None, None)
    if name in ("uid-owner", "gid-owner"):
        meta = "skuid" if name == "uid-owner" else "skgid"
        owner = _owner_value(name, scalar)
        return (f"meta {meta} {_op(neg)}{owner}", None, None)
    if name == "length":
        if ":" in scalar:
            low, _, high = scalar.partition(":")
            if low.isdigit() and high.isdigit():
                scalar = f"{low}-{high}"
            else:
                raise FermError(f"invalid length '{scalar}' for nft backend")
        elif not (scalar.isdigit() or _NUMERIC_RANGE_RE.match(scalar)):
            raise FermError(f"invalid length '{scalar}' for nft backend")
        return (f"meta length {_op(neg)}{scalar}", None, None)
    if name == "opcode":
        if not scalar.isdigit():
            raise FermError(f"invalid arp opcode '{scalar}' for nft backend")
        operation = _ARP_OPERATION_BY_NUMBER.get(int(scalar), scalar)
        return (f"arp operation {_op(neg)}{operation}", None, None)
    if name in _TTL_COMPARATOR and domain is not Family.IP6:
        # xt_ttl is ip-only (mod hl is its ip6 twin below), so the ip6
        # pass falls through to the generic refusal.
        if not scalar.isdigit():
            raise FermError(f"invalid ttl '{scalar}' for nft backend")
        return (
            f"ip ttl {_op(neg)}{_TTL_COMPARATOR[name]}{scalar}",
            None,
            None,
        )
    if name in _HL_COMPARATOR and domain is Family.IP6:
        # ip6t_hl is ip6-only; the ip pass falls through to the refusal.
        if not scalar.isdigit():
            raise FermError(f"invalid hl '{scalar}' for nft backend")
        return (
            f"ip6 hoplimit {_op(neg)}{_HL_COMPARATOR[name]}{scalar}",
            None,
            None,
        )
    if name == "mac-source":
        if not _MAC_RE.match(scalar):
            raise FermError(f"invalid mac '{scalar}' for nft backend")
        return (f"ether saddr {_op(neg)}{scalar.lower()}", None, None)
    if name in ("source-mac", "destination-mac"):
        # the arp family spells its MAC selectors arp saddr/daddr ether
        if not _MAC_RE.match(scalar):
            raise FermError(f"invalid mac '{scalar}' for nft backend")
        side = "saddr" if name == "source-mac" else "daddr"
        return (
            f"arp {side} ether {_op(neg)}{scalar.lower()}",
            None,
            None,
        )
    if name == "pkt-type":
        # Not set-eligible (icmp-type precedent): the packet-type words are
        # bare tokens with no rank in sort_set_elements.  xt's `unicast`
        # reads back from the kernel as `host`, so it is emitted as `host`.
        kind = _PKTTYPE_MAP.get(scalar)
        if kind is None:
            raise FermError(f"invalid pkttype '{scalar}' for nft backend")
        return (f"meta pkttype {_op(neg)}{kind}", None, None)
    if name in ("src-range", "dst-range") and domain in (
        Family.IP,
        Family.IP6,
    ):
        # mod iprange address ranges; arp/eb have no saddr/daddr range and
        # fall through to the generic refusal.  Not set-eligible: a range is
        # a single interval operand, not a foldable member.
        side = "saddr" if name == "src-range" else "daddr"
        low, sep, high = scalar.partition("-")
        if not sep or not low or not high:
            raise FermError(f"invalid iprange '{scalar}' for the nft backend")
        low_addr = _iprange_bound(domain, low)
        high_addr = _iprange_bound(domain, high)
        return (
            f"{domain} {side} {_op(neg)}{low_addr}-{high_addr}",
            None,
            None,
        )
    raise FermError(f"option '{name}' not yet supported by nft backend")


def translate_match(
    domain: Family, option: RenderedOption, protocol: str | None
) -> str:
    """Translate one match option to an nft expression."""
    return _translate_match_parts(domain, option, protocol)[0]


def _match_selector(domain: Family, name: str, protocol: str | None) -> str:
    """
    Return the nft selector text for an address/interface/port keyword.

    The single source of the selector for :func:`_translate_match_parts`
    (which appends an operand) and :func:`_setref_selector` (which appends
    a set reference) -- previously two mirrored computations that could
    drift.  The port arm carries the shared tcp/udp guard.  Callers vet
    ``name`` against the keyword maps first; an unknown name here is an
    internal error.
    """
    if name in _ADDR_KEYWORD:
        return f"{domain} {_ADDR_KEYWORD[name]}"
    if name in _IFACE_KEYWORD:
        return _IFACE_KEYWORD[name]
    if name in _PORT_KEYWORD:
        if protocol not in PORT_PROTOCOLS:
            raise FermError(
                f"option '{name}' needs a tcp/udp protocol for the nft backend"
            )
        return f"{protocol} {_PORT_KEYWORD[name]}"
    raise internal_error()


def _setref_selector(domain: Family, name: str, protocol: str | None) -> str:
    """
    Return the nft selector left of a set reference (@name).

    Used in :func:`translate_rule` when the option value is a
    :class:`~pyferm.values.SetRef`.
    """
    if (
        name not in _ADDR_KEYWORD
        and name not in _IFACE_KEYWORD
        and name not in _PORT_KEYWORD
    ):
        raise FermError(f"option '{name}' cannot reference a named set")
    return _match_selector(domain, name, protocol)


#: ``mod set match-set`` direction flag -> nft address selector.
_MATCH_SET_FLAG: Final[dict[str, str]] = {"src": "saddr", "dst": "daddr"}
#: match-set's value is always ``Params([SetRef|name, flag])`` (the ``sc``
#: keyword code), so exactly two positional elements.
_MATCH_SET_PARAM_COUNT: Final[int] = 2


def _translate_match_set(domain: Family, value: Value) -> NftMatch:
    """
    Translate ``mod set match-set $x <dir>`` to an nft named-set match.

    The value is ``Params([SetRef, flag])`` (``PreNegated`` around it for the
    ``! match-set`` form).  Only a ferm-owned ``@set`` (a :class:`SetRef`)
    translates; a bare name is an external ipset -- a distinct kernel
    subsystem nft cannot reference across tables -- and refuses with a
    migration hint.  The comma-joined multi-flag form (``src,dst``) would need
    a concatenated set type that ``@set`` never declares, so it refuses too.
    The emitted :class:`NftMatch` carries the SetRef and its family-prefixed
    selector, the same shape the address arm produces, so
    :func:`_collect_set_declarations` picks up the declaration unchanged.
    """
    negated = False
    if isinstance(value, (Negated, PreNegated)):
        value = value.value
        negated = True
    if (
        not isinstance(value, Params)
        or len(value.values) != _MATCH_SET_PARAM_COUNT
    ):
        raise internal_error()
    operand, flags = value.values
    if not isinstance(operand, SetRef):
        raise FermError(
            f"option 'match-set': external ipset '{operand}' cannot be "
            f"referenced from nftables; declare it with @set ${operand} = "
            "(...) or keep the iptables backend"
        )
    if not isinstance(flags, str):
        raise internal_error()
    if "," in flags:
        raise FermError(
            "option 'match-set': multiple set-match flags need a "
            "concatenated set type that @set does not declare"
        )
    selector_tail = _MATCH_SET_FLAG.get(flags)
    if selector_tail is None:
        raise FermError(
            f"option 'match-set': unsupported set-match flag '{flags}' "
            "for the nft backend"
        )
    selector = f"{domain} {selector_tail}"
    expr = f"{selector} {_op(negated)}@{_validate_set_name(operand.name)}"
    return NftMatch(expr, set_key=None, setref=operand, set_selector=selector)


# ---------------------------------------------------------------------------
# build_verdict
# ---------------------------------------------------------------------------

#: target VALUE -> nft verdict; QUEUE is core, REJECT is not.  Derived from
#: :data:`CORE_TARGETS` so the two cannot drift; every core target lower-cases
#: to its nft spelling (ACCEPT->accept, ...), preserving insertion order.
_VERDICT_TARGET: Final[dict[str, str]] = {
    target: target.lower() for target in CORE_TARGETS
}
#: ebtables target keywords (``modules.py`` ``target_x("eb", ...)``):
#: they are targets, never user chains, and have no nft bridge-family
#: translation yet, so :func:`build_verdict` refuses them explicitly.
#: The parser rewrites the eb ``MARK`` keyword to ebtables' ``mark``
#: spelling before it reaches the backend, so both forms are guarded.
_EB_TARGETS: Final[frozenset[str]] = frozenset(
    {"arpreply", "dnat", "redirect", "snat", "MARK", "mark"}
)
#: iptables ``reject-with`` canonical name -> nft reject spec, ip family.
#: Covers every type ``iptables -j REJECT`` accepts; the short aliases
#: (``net-unreach`` ...) resolve to these keys via :data:`_REJECT_ALIAS`.
#: nft spells iptables ``icmp-proto-unreachable`` as ``prot-unreachable``
#: (verified against nft v1.1.6).
_REJECT_WITH: Final[dict[str, str]] = {
    "icmp-net-unreachable": "reject with icmp type net-unreachable",
    "icmp-host-unreachable": "reject with icmp type host-unreachable",
    "icmp-proto-unreachable": "reject with icmp type prot-unreachable",
    "icmp-port-unreachable": "reject with icmp type port-unreachable",
    "icmp-net-prohibited": "reject with icmp type net-prohibited",
    "icmp-host-prohibited": "reject with icmp type host-prohibited",
    "icmp-admin-prohibited": "reject with icmp type admin-prohibited",
    "tcp-reset": "reject with tcp reset",
}
#: iptables ip-family short alias -> canonical :data:`_REJECT_WITH` key.
_REJECT_ALIAS: Final[dict[str, str]] = {
    "net-unreach": "icmp-net-unreachable",
    "host-unreach": "icmp-host-unreachable",
    "proto-unreach": "icmp-proto-unreachable",
    "port-unreach": "icmp-port-unreachable",
    "net-prohib": "icmp-net-prohibited",
    "host-prohib": "icmp-host-prohibited",
    "admin-prohib": "icmp-admin-prohibited",
    "tcp-rst": "tcp-reset",
}
#: ip6 ``reject-with`` canonical name -> nft reject spec (icmpv6 types plus
#: the family-agnostic tcp reset).  Covers every type ``ip6tables -j REJECT``
#: accepts; short aliases resolve via :data:`_REJECT_ALIAS_IP6`.
_REJECT_WITH_IP6: Final[dict[str, str]] = {
    "icmp6-no-route": "reject with icmpv6 type no-route",
    "icmp6-adm-prohibited": "reject with icmpv6 type admin-prohibited",
    "icmp6-addr-unreachable": "reject with icmpv6 type addr-unreachable",
    "icmp6-port-unreachable": "reject with icmpv6 type port-unreachable",
    "icmp6-policy-fail": "reject with icmpv6 type policy-fail",
    "icmp6-reject-route": "reject with icmpv6 type reject-route",
    "tcp-reset": "reject with tcp reset",
}
#: ip6 short alias -> canonical :data:`_REJECT_WITH_IP6` key.
_REJECT_ALIAS_IP6: Final[dict[str, str]] = {
    "no-route": "icmp6-no-route",
    "adm-prohibited": "icmp6-adm-prohibited",
    "addr-unreach": "icmp6-addr-unreachable",
    "port-unreach": "icmp6-port-unreachable",
    "policy-fail": "icmp6-policy-fail",
    "reject-route": "icmp6-reject-route",
}
#: The error a port-bearing NAT verdict raises without a transport match
#: nft would reject the applied script, so fail at translate.
_NAT_PORT_NEEDS_PROTO: Final[str] = (
    "NAT to a port needs a tcp/udp protocol match for the nft backend"
)
#: iptables ``--log-level`` spelling (name or syslog number) -> nft level
#: keyword.  nft's default level (``warn``) is dropped by the kernel
#: readback, so :func:`build_verdict` omits it from the emission.
_LOG_LEVEL_MAP: Final[dict[str, str]] = {
    "emerg": "emerg",
    "panic": "emerg",
    "0": "emerg",
    "alert": "alert",
    "1": "alert",
    "crit": "crit",
    "2": "crit",
    "error": "err",
    "err": "err",
    "3": "err",
    "warning": "warn",
    "warn": "warn",
    "4": "warn",
    "notice": "notice",
    "5": "notice",
    "info": "info",
    "6": "info",
    "debug": "debug",
    "7": "debug",
}


def _nat_has_port(domain: Family, operand: str) -> bool:
    """
    Return whether a NAT address operand carries a ``:port``.

    nft accepts an ``addr:port`` mapping only after a transport match.  In an
    IPv4 family any ``:`` is the port separator.  An IPv6 host carries its own
    ``:`` colons, so those must NOT count as a port (else a port-less
    ``dnat to fe80::1`` would falsely demand a transport match); a port is
    bracketed (``[2001:db8::1]:80``), i.e. a ``]:``.  That bracketed form is
    in practice already rejected upstream by :func:`_validate_address` (the
    ``[``/``]`` are not in ``_NFT_ADDR_RE``), so the ``]:`` arm is defensive;
    the load-bearing case is the ip6 ``return False`` that avoids the false
    positive on a plain IPv6 host.
    """
    if domain == "ip6":
        return "]:" in operand
    return ":" in operand


def _reject_for(domain: Family, scalar: str) -> str:
    if domain == "ip6":
        # normalize an ip4 reject spelling written in an ip6 domain before
        # the ip6 lookup (shared oracle ip4->icmp6 alias set)
        scalar = ICMP6_REJECT_MAP.get(scalar, scalar)
        scalar = _REJECT_ALIAS_IP6.get(scalar, scalar)
        spec = _REJECT_WITH_IP6.get(scalar)
    else:
        scalar = _REJECT_ALIAS.get(scalar, scalar)
        spec = _REJECT_WITH.get(scalar)
    if spec is None:
        raise FermError(
            f"reject-with '{scalar}' not yet supported by nft backend"
        )
    return spec


def _nflog_verdict(companions: dict[str, RenderedOption]) -> NftVerdict:
    """
    NFLOG shape: nft ``log group N`` with optional prefix/threshold.

    Field order follows the kernel readback (prefix, group,
    queue-threshold) so an applied rule reads back byte-identically.
    ``--nflog-range`` is accepted-but-ignored by xt_NFLOG; there is no
    honest nft spelling for it, so it refuses rather than mistranslate
    to ``snaplen``.  A missing group keeps xt_NFLOG's default 0.
    """
    if "nflog-range" in companions:
        raise FermError(
            "option 'nflog-range' not yet supported by nft backend"
        )
    parts = ["log"]
    prefix = companions.get("nflog-prefix")
    if prefix is not None:
        scalar, _ = unwrap_value(prefix.value)
        parts.append(f"prefix {_nft_quote_string(scalar)}")
    group_num = "0"
    group = companions.get("nflog-group")
    if group is not None:
        scalar, _ = unwrap_value(group.value)
        if not scalar.isdigit() or int(scalar) > _NFLOG_GROUP_MAX:
            raise FermError(f"invalid nflog-group '{scalar}' for nft backend")
        group_num = scalar
    parts.append(f"group {group_num}")
    threshold = companions.get("nflog-threshold")
    if threshold is not None:
        scalar, _ = unwrap_value(threshold.value)
        if not scalar.isdigit() or int(scalar) == 0:
            raise FermError(
                f"invalid nflog-threshold '{scalar}' for nft backend"
            )
        parts.append(f"queue-threshold {scalar}")
    return NftVerdict(" ".join(parts))


#: xt NAT flag option -> nft spelling, in the fixed kernel-readback order
#: (random / fully-random first, persistent last).  ``--random-fully`` is
#: the xt spelling of nft's ``fully-random``.
_NAT_FLAG_SPELLING: Final[tuple[tuple[str, str], ...]] = (
    ("random", "random"),
    ("random-fully", "fully-random"),
    ("persistent", "persistent"),
)


def _nat_flags(companions: dict[str, RenderedOption]) -> str:
    """
    Spell the NAT flag companions as an nft suffix (``""`` when none).

    xt's ``--random`` / ``--random-fully`` / ``--persistent`` read back from
    nft in a fixed order, comma-joined with no surrounding space; the
    returned string carries a single leading space so a caller appends it
    unconditionally.
    """
    flags = [
        spelling
        for option_name, spelling in _NAT_FLAG_SPELLING
        if option_name in companions
    ]
    return f" {','.join(flags)}" if flags else ""


def _nat_to_ports(
    verb: str,
    companions: dict[str, RenderedOption],
    *,
    has_transport: bool,
) -> NftVerdict:
    """
    MASQUERADE/REDIRECT shape: an OPTIONAL ``to-ports`` companion.

    Without one the bare verb is a complete statement (unlike the
    SNAT/DNAT shape, which raises); with one, a transport match is
    required first (nft would reject the applied script).  NAT flags append
    to both forms, so a flag-only ``masquerade random`` still emits.
    """
    flags = _nat_flags(companions)
    comp = companions.get("to-ports")
    if comp is not None:
        if not has_transport:
            raise FermError(_NAT_PORT_NEEDS_PROTO)
        port = _validate_port(first_scalar(comp.value))
        return NftVerdict(f"{verb} to :{port}{flags}")
    return NftVerdict(f"{verb}{flags}")


def _nat_to_addr(
    verb: str,
    target: str,
    comp_key: str,
    domain: Family,
    companions: dict[str, RenderedOption],
    *,
    has_transport: bool,
) -> NftVerdict:
    """
    SNAT/DNAT shape: a MANDATORY address companion (raises without one).

    A port-bearing address mapping additionally requires a transport
    match, mirroring the to-ports shape's guard.
    """
    comp = companions.get(comp_key)
    if comp is None:
        raise FermError(f"{target} target not yet supported by nft backend")
    addr = _validate_address(first_scalar(comp.value))
    if _nat_has_port(domain, addr) and not has_transport:
        raise FermError(_NAT_PORT_NEEDS_PROTO)
    return NftVerdict(f"{verb} to {addr}{_nat_flags(companions)}")


def build_verdict(
    domain: Family,
    table: str,
    target_name: str,
    target_value: str,
    companions: dict[str, RenderedOption],
    *,
    has_transport: bool = False,
) -> NftVerdict:
    """
    Build the verdict statement from the ``jump`` marker value.

    Dispatches on ``target_value`` (the discriminator, since every target
    arrives as ``name='jump'``): core verdicts, NAT/LOG/REJECT (which take
    a companion option), or a ``jump``/``goto`` to a chain in the SAME
    iptables table (name disambiguated via :func:`nft_chain_name`).

    ``has_transport`` reports whether the rule established an L4 protocol
    (port match or ``meta l4proto tcp/udp``); a port-bearing NAT mapping
    without one is rejected at translate time, since nft would
    otherwise reject the applied script and force a rollback.
    """
    if target_value in _VERDICT_TARGET:
        return NftVerdict(_VERDICT_TARGET[target_value])
    if target_value == "MASQUERADE":
        return _nat_to_ports(
            "masquerade", companions, has_transport=has_transport
        )
    if target_value == "REDIRECT":
        return _nat_to_ports(
            "redirect", companions, has_transport=has_transport
        )
    if target_value == "LOG":
        parts = ["log"]
        comp = companions.get("log-prefix")
        if comp is not None:
            scalar, _ = unwrap_value(comp.value)
            parts.append(f"prefix {_nft_quote_string(scalar)}")
        level = companions.get("log-level")
        if level is not None:
            scalar, _ = unwrap_value(level.value)
            mapped = _LOG_LEVEL_MAP.get(scalar.lower())
            if mapped is None:
                raise FermError(
                    f"log-level '{scalar}' not yet supported by nft backend"
                )
            if mapped != "warn":  # nft's default; the readback drops it
                parts.append(f"level {mapped}")
        return NftVerdict(" ".join(parts))
    if target_value == "NFLOG":
        return _nflog_verdict(companions)
    if target_value == "REJECT":
        comp = companions.get("reject-with")
        if comp is None:
            return NftVerdict("reject")
        scalar, _ = unwrap_value(comp.value)
        return NftVerdict(_reject_for(domain, scalar))
    if target_value == "SNAT":
        return _nat_to_addr(
            "snat",
            "SNAT",
            "to-source",
            domain,
            companions,
            has_transport=has_transport,
        )
    if target_value == "DNAT":
        return _nat_to_addr(
            "dnat",
            "DNAT",
            "to-destination",
            domain,
            companions,
            has_transport=has_transport,
        )
    if target_value == "TCPMSS":
        clamp = companions.get("clamp-mss-to-pmtu")
        setmss = companions.get("set-mss")
        if clamp is not None and setmss is None:
            return NftVerdict("tcp option maxseg size set rt mtu")
        if setmss is not None and clamp is None:
            scalar, _ = unwrap_value(setmss.value)
            if not scalar.isdigit():
                raise FermError(f"invalid set-mss '{scalar}' for nft backend")
            return NftVerdict(f"tcp option maxseg size set {scalar}")
        raise FermError("TCPMSS target not yet supported by nft backend")
    if target_value == "TEE":
        comp = companions.get("gateway")
        if comp is None:
            raise FermError("TEE target not yet supported by nft backend")
        addr = _validate_address(first_scalar(comp.value))
        return NftVerdict(f"dup to {addr}")
    if target_value == "NOTRACK":
        return NftVerdict("notrack")
    if target_value == "TRACE":
        return NftVerdict("meta nftrace set 1")
    if target_value == "CONNMARK":
        # save/restore-mark with nfmask/ctmask/mask carries bits BETWEEN the
        # packet and ct registers under two independent masks; nft's grammar
        # has no single expression for that (iptables-translate emits a form
        # the kernel silently collapses), so it refuses rather than mangle it.
        for masked in ("nfmask", "ctmask", "mask"):
            if masked in companions:
                raise FermError(
                    f"CONNMARK '{masked}' mixes two masked registers; nft "
                    "cannot express it for the nft backend"
                )
        has_save = "save-mark" in companions
        has_restore = "restore-mark" in companions
        has_arith = any(
            op in companions
            for op in (
                "set-mark",
                "set-xmark",
                "and-mark",
                "or-mark",
                "xor-mark",
            )
        )
        provided = sum((has_save, has_restore, has_arith))
        if provided != 1:
            raise FermError("CONNMARK target not yet supported by nft backend")
        if has_save:
            return NftVerdict("ct mark set meta mark")
        if has_restore:
            return NftVerdict("meta mark set ct mark")
        return NftVerdict(_mark_arith_set("ct mark", "CONNMARK", companions))
    # The eb-family MARK keyword stays under the eb guard below (its
    # companion spellings are ebtables-specific), so this branch handles
    # the ip/ip6/arp target only.
    if target_value == "MARK" and domain is not Family.EB:
        return NftVerdict(_mark_arith_set("meta mark", "MARK", companions))
    if target_value == "DSCP" and domain in (Family.IP, Family.IP6):
        # Exactly one of set-dscp / set-dscp-class (TCPMSS/CONNMARK pattern);
        # the selector is family-prefixed like the dscp match.  arp/eb fall
        # through to the registry refusal below.
        setdscp = companions.get("set-dscp")
        setclass = companions.get("set-dscp-class")
        if setdscp is not None and setclass is None:
            scalar, _ = unwrap_value(setdscp.value)
            value = _dscp_value("set-dscp", scalar)
        elif setclass is not None and setdscp is None:
            scalar, _ = unwrap_value(setclass.value)
            value = _dscp_class_value("set-dscp-class", scalar)
        else:
            raise FermError("DSCP target not yet supported by nft backend")
        return NftVerdict(f"{domain} dscp set {_dscp_canon(value)}")
    if target_value == "CLASSIFY":
        comp = companions.get("set-class")
        if comp is None:
            raise FermError("CLASSIFY target not yet supported by nft backend")
        scalar, _ = unwrap_value(comp.value)
        return NftVerdict(f"meta priority set {_classify_priority(scalar)}")
    if target_value == "TOS":
        raise _tos_refusal("target", "TOS")
    if target_value == "NFQUEUE":
        return _nfqueue_verdict(companions)
    # TTL is the ip twin of ip6's HL; each other family falls through to
    # the registry refusal below.
    if target_value == "TTL" and domain is Family.IP:
        return _hoplimit_verdict("TTL", companions)
    if target_value == "HL" and domain is Family.IP6:
        return _hoplimit_verdict("HL", companions)
    if target_value == "SYNPROXY" and domain in (Family.IP, Family.IP6):
        return _synproxy_verdict(companions)
    if target_value == "TPROXY" and domain in (Family.IP, Family.IP6):
        return _tproxy_verdict(domain, companions, has_transport=has_transport)
    if target_value == "CT":
        # Only --notrack has an nft spelling; the remaining CT options need
        # object declarations (ct helper/timeout/zone) that are out of scope,
        # and a bare CT is untranslatable (the xt oracle refuses it too).
        for unsupported in (
            "helper",
            "ctevents",
            "expevents",
            "zone-orig",
            "zone-reply",
            "zone",
            "timeout",
        ):
            if unsupported in companions:
                raise FermError(
                    f"CT target option '{unsupported}' not yet supported by "
                    f"nft backend"
                )
        if "notrack" in companions:
            return NftVerdict("notrack")
        raise FermError("CT target not yet supported by nft backend")
    if target_value == "CHECKSUM":
        raise FermError(
            "CHECKSUM target has no nft equivalent (kernels since 4.19 "
            "handle virtio checksum offload without it); use the iptables "
            "backend for this rule"
        )
    # The ebtables target keywords share companion option names with the
    # inet NAT targets (snat/to-source, dnat/to-destination), so without
    # this guard they would fall through to the user-chain branch below,
    # swallow the companion and emit a jump to a chain that never exists
    # -- a silently-broken script instead of a clean refusal.
    if domain is Family.EB and target_value in _EB_TARGETS:
        # The keyword alone cannot tell the built-in target from a user
        # chain that happens to share its name, so the message names
        # both readings.
        raise FermError(
            f"eb target '{target_value}' (or jump to a chain of that "
            f"name) not yet supported by nft backend"
        )
    # Every remaining registered target keyword (TARPIT, MARK, NOTRACK,
    # ...) has no nft translation either; without this registry guard it
    # would fall through to the user-chain branch below and emit a jump
    # to a chain that never exists -- rejected by `nft -f` only at apply
    # time, while --test/--noexec --lines report success.  Same
    # keyword-vs-chain ambiguity as the eb guard, so the message names
    # both readings.  ip6 folds to the "ip" registry family (the parser
    # convention, cf. graph._defs_family).
    defs_family = "ip" if domain is Family.IP6 else domain.value
    if is_netfilter_module_target(TARGET_DEFS, defs_family, target_value):
        raise FermError(
            f"target '{target_value}' (or jump to a chain of that name) "
            f"not yet supported by nft backend"
        )
    # A jump/goto to a chain in the same iptables table.  nft forbids
    # jumping to a base chain (one with a hook), so a jump/goto whose
    # target is a built-in chain has NO nft equivalent -> a plain ferm
    # error (ontology gap), NOT a silently-broken script.
    if is_netfilter_builtin_chain(table, target_value):
        raise FermError(
            f"jump/goto to built-in chain '{target_value}' not yet "
            f"supported by nft backend"
        )
    return NftVerdict(f"{target_name} {nft_chain_name(table, target_value)}")


# ---------------------------------------------------------------------------
# translate_rule — two-pass rule assembly
# ---------------------------------------------------------------------------

#: option names that are companion arguments of a target, consumed by
#: :func:`build_verdict` rather than emitted as matches.
_TARGET_COMPANIONS: Final[tuple[str, ...]] = (
    "reject-with",
    "to-source",
    "to-destination",
    "log-prefix",
    "log-level",
    "to-ports",
    "nflog-group",
    "nflog-prefix",
    "nflog-threshold",
    "nflog-range",
    "set-mark",
    "set-xmark",
    "and-mark",
    "or-mark",
    "xor-mark",
    "set-mss",
    "clamp-mss-to-pmtu",
    "gateway",
    "save-mark",
    "restore-mark",
    "nfmask",
    "ctmask",
    "mask",
    "set-dscp",
    "set-dscp-class",
    "set-class",
    # TOS companions: collected so the target refuses with the TOS message
    # rather than the generic "option not supported" from the match path.
    "set-tos",
    "and-tos",
    "or-tos",
    "xor-tos",
    "queue-num",
    "queue-balance",
    "queue-bypass",
    "queue-cpu-fanout",
    "ttl-set",
    "ttl-dec",
    "ttl-inc",
    "hl-set",
    "hl-dec",
    "hl-inc",
    "wscale",
    "sack-perm",
    "timestamp",
    "ecn",
    "strip-options",
    # NAT flag options (SNAT/DNAT/MASQUERADE/REDIRECT); flag options carry
    # no argument and reach build_verdict as bare-name companions.
    "random",
    "random-fully",
    "persistent",
    # CT notrack (the only CT companion with an nft spelling); the other
    # seven CT options are module-qualified below to dodge the `helper`
    # collision with the `mod helper` match.
    "notrack",
    # TPROXY companions.
    "on-port",
    "on-ip",
    "tproxy-mark",
    # CHECKSUM's only option; collected so the target refuses with the
    # CHECKSUM message rather than a generic match-path "not supported".
    "checksum-fill",
)

#: companion names that collide with a match option of the same spelling
#: (`mss` is both SYNPROXY's option and the tcp match's; `to` is NETMAP's
#: and the string match's; each `CT` option shares a name with a match
#: module -- notably `helper` with `mod helper`), so they are consumed as
#: companions only when the introducing module IS that target.
_MODULE_COMPANIONS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("NETMAP", "to"),
        ("SYNPROXY", "mss"),
        ("CT", "helper"),
        ("CT", "ctevents"),
        ("CT", "expevents"),
        ("CT", "zone-orig"),
        ("CT", "zone-reply"),
        ("CT", "zone"),
        ("CT", "timeout"),
    }
)


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


def _references_empty_named_set(rule: RenderedRule) -> bool:
    """
    Whether *rule* matches on a named set that filtered empty for its family.

    A v4-only set on the ip6 pass of a dual-stack rule (or a ``@set $x = ()``)
    matches nothing.  The caller drops such a rule before translation, exactly
    as an empty inline address list drops one under the iptables backend and
    the Perl oracle -- otherwise the family would emit a dangling ``@name``
    reference plus an empty ``add set`` declaration.
    """
    return any(
        not setref.elements
        for o in rule.options
        for setref in iter_setrefs(o.value)
    )


#: xt stores ``--probability p`` as ``round(p * 2**31)`` and nft matches it
#: with ``meta random & <mask> < <threshold>`` where the mask is the top of
#: the 31-bit range the ``meta random`` expression yields.
_STATISTIC_RANDOM_MASK: Final[int] = 2**31 - 1


def _statistic_match(options: dict[str, RenderedOption]) -> str:
    """
    Translate a ``mod statistic`` match to its nft expression.

    ``mode random`` maps to ``meta random & <mask> < <threshold>`` (an
    average-probability sampler) and ``mode nth`` to ``numgen inc mod N P``
    (a deterministic every-Nth counter; ``P`` is xt's 0-based ``--packet``,
    which defaults to 0).  The options are collected rule-wide and
    module-qualified by the caller because ``every``/``packet`` collide with
    ``mod nth``'s own keywords.  A statistic match is a matcher, never a
    verdict, so it must not route through the target companion path (which
    would silently drop it and fail open).
    """
    mode_opt = options.get("mode")
    if mode_opt is None:
        raise FermError("mod statistic needs a 'mode' for the nft backend")
    mode, mode_neg = unwrap_value(mode_opt.value)
    if mode_neg:
        raise FermError(
            "mod statistic 'mode' cannot be negated for the nft backend"
        )
    if mode == "random":
        prob_opt = options.get("probability")
        if prob_opt is None:
            raise FermError(
                "mod statistic mode random needs a 'probability' for the "
                "nft backend"
            )
        scalar, _ = unwrap_value(prob_opt.value)
        try:
            probability = float(scalar)
        except ValueError:
            raise FermError(
                f"invalid statistic probability '{scalar}' for nft backend"
            ) from None
        if not 0.0 <= probability <= 1.0:
            raise FermError(
                f"statistic probability '{scalar}' is outside [0, 1] for "
                "the nft backend"
            )
        threshold = round(probability * 2**31)
        return f"meta random & {_STATISTIC_RANDOM_MASK} < {threshold}"
    if mode == "nth":
        every_opt = options.get("every")
        if every_opt is None:
            raise FermError(
                "mod statistic mode nth needs 'every' for the nft backend"
            )
        every_scalar, _ = unwrap_value(every_opt.value)
        if not every_scalar.isdigit() or int(every_scalar) == 0:
            raise FermError(
                f"invalid statistic every '{every_scalar}' for nft backend"
            )
        packet_opt = options.get("packet")
        # xt defaults --packet to 0 (0-based) when omitted; ferm passes the
        # bare `mode nth every N` through, so the nft offset defaults to 0.
        if packet_opt is None:
            packet_scalar = "0"
        else:
            packet_scalar, _ = unwrap_value(packet_opt.value)
            if not packet_scalar.isdigit():
                raise FermError(
                    f"invalid statistic packet '{packet_scalar}' for nft "
                    "backend"
                )
        if int(packet_scalar) >= int(every_scalar):
            raise FermError(
                f"statistic packet '{packet_scalar}' must be less than "
                f"every '{every_scalar}' for the nft backend"
            )
        return f"numgen inc mod {int(every_scalar)} {int(packet_scalar)}"
    raise FermError(f"unknown statistic mode '{mode}' for the nft backend")


#: xt TCPOPTSTRIP mnemonic -> nft ``reset tcp option`` keyword.
_TCPOPT_NAME: Final[dict[str, str]] = {
    "wscale": "window",
    "mss": "maxseg",
    "sack-permitted": "sack-perm",
    "sack": "sack",
    "timestamp": "timestamp",
    "md5": "md5sig",
}
#: tcp option NUMBER -> nft ``reset tcp option`` keyword.  The kernel
#: respells these known option kinds to names on readback (pinned live);
#: any other number in 0-255 stays numeric.
_TCPOPT_NUM_NAME: Final[dict[int, str]] = {
    0: "eol",
    1: "nop",
    2: "maxseg",
    3: "window",
    4: "sack-perm",
    5: "sack",
    8: "timestamp",
    19: "md5sig",
    30: "mptcp",
    34: "fastopen",
}
#: the highest tcp option kind (a single byte).
_TCP_OPTION_MAX: Final[int] = 255


def _tcpopt_nft_name(token: str) -> str:
    """Map one xt strip-options token (mnemonic or number) to nft."""
    if token in _TCPOPT_NAME:
        return _TCPOPT_NAME[token]
    if token.isdigit():
        number = int(token)
        if number > _TCP_OPTION_MAX:
            raise FermError(f"invalid tcp option '{token}' for nft backend")
        return _TCPOPT_NUM_NAME.get(number, str(number))
    raise FermError(f"unknown tcp option '{token}' for nft backend")


def _tcpoptstrip_resets(
    companions: dict[str, RenderedOption], protocol: str | None
) -> list[NftReset]:
    """
    Spell TCPOPTSTRIP as a series of ``reset tcp option <x>`` statements.

    One reset per stripped option, in user order.  nft's reset acts on the
    tcp header, so the rule must carry a ``proto tcp`` match (xt requires
    ``-p tcp`` too); the precedent is the NAT-to-a-port transport guard.
    """
    if protocol != "tcp":
        raise FermError(
            "TCPOPTSTRIP needs a tcp protocol match for the nft backend"
        )
    comp = companions.get("strip-options")
    if comp is None:
        raise FermError(
            "TCPOPTSTRIP needs 'strip-options' for the nft backend"
        )
    scalar, _ = unwrap_value(comp.value)
    return [
        NftReset(f"reset tcp option {_tcpopt_nft_name(token.strip())}")
        for token in scalar.split(",")
    ]


# ---------------------------------------------------------------------------
# Stateful vocabulary: mod recent / mod hashlimit via implicit dynamic sets
# ---------------------------------------------------------------------------

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
#: rate unit spans in seconds, smallest first: the reducer picks the smallest
#: unit that renders ``T*H/S`` as an integer count, matching the readback
#: (``8/60s`` -> ``8/minute``, ``16/300s`` -> ``192/hour``).
_RATE_UNITS: Final[tuple[tuple[str, int], ...]] = (
    ("second", 1),
    ("minute", 60),
    ("hour", 3_600),
    ("day", 86_400),
)
#: xt rate-unit spelling (with abbreviations) -> nft rate unit.
_HASHLIMIT_UNIT: Final[dict[str, str]] = {
    "sec": "second",
    "second": "second",
    "min": "minute",
    "minute": "minute",
    "hour": "hour",
    "day": "day",
}
#: rate unit -> the period nft prints as the element ``timeout`` when a
#: hashlimit rule gives no explicit htable-expire (``/second`` stays
#: timeout-less: a bare ``flags dynamic`` element is legal, pinned live).
_HASHLIMIT_PERIOD_TIMEOUT: Final[dict[str, str]] = {
    "minute": "1m",
    "hour": "1h",
    "day": "1d",
}
#: hashlimit-mode token -> canonical emission order rank.  The readback keeps
#: our emission order verbatim, so a fixed rank makes concatenated keys stable.
_HASHLIMIT_MODE_ORDER: Final[tuple[str, ...]] = (
    "srcip",
    "dstip",
    "srcport",
    "dstport",
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


def _reduce_rate(numerator: int, seconds: int) -> tuple[int, str]:
    """
    Express ``numerator/seconds`` packets-per-second as ``N/<unit>``.

    Picks the smallest nft rate unit that yields an integer ``N >= 1``; an
    average rate that no unit renders whole (an irreducible ``T*H/S``)
    refuses.
    """
    for unit, span in _RATE_UNITS:
        product = numerator * span
        if product % seconds == 0 and product // seconds >= 1:
            return product // seconds, unit
    raise FermError(
        f"average rate {numerator}/{seconds}s has no integer nft rate unit "
        "for the nft backend"
    )


@dataclass(frozen=True)
class _RecentFacts:
    """Per-rule mod recent facts, structurally parsed once (fail-closed)."""

    name: str
    is_check: bool
    seconds: str | None
    hitcount: str | None
    direction: str
    has_verdict: bool


@dataclass(frozen=True)
class _RecentSpec:
    """Per-name aggregate: the uniform element spec every rule of it emits."""

    direction: str
    timeout: str
    limit: str | None


def _recent_scalar(opts: dict[str, RenderedOption], key: str) -> str | None:
    """Return a numeric recent option's scalar, or None when absent."""
    option = opts.get(key)
    if option is None:
        return None
    scalar, _ = unwrap_value(option.value)
    if not scalar.isdigit():
        raise FermError(f"invalid recent {key} '{scalar}' for the nft backend")
    return scalar


def _recent_facts(domain: Family, rule: RenderedRule) -> _RecentFacts | None:
    """
    Parse a rule's ``mod recent`` options into structured facts, or None.

    Refuses per-rule: a non-ip/ip6 family; a negated option; the unsupported
    ``remove``/``rttl``/``reap``/``mask`` verbs; a missing or multiple
    set/rcheck/update verb; a missing/invalid name; a hitcount without seconds;
    and a check verb lacking the seconds+hitcount the token-bucket needs.
    """
    recent_opts = [o for o in rule.options if o.module == "recent"]
    if not recent_opts:
        return None
    if domain not in (Family.IP, Family.IP6):
        raise FermError("mod recent needs the ip or ip6 family for nft")
    opts: dict[str, RenderedOption] = {}
    for option in recent_opts:
        if isinstance(option.value, (Negated, PreNegated)):
            raise FermError(
                f"mod recent '{option.name}' cannot be negated for the nft "
                "backend"
            )
        opts[option.name] = option
    for unsupported in ("remove", "rttl", "reap", "mask"):
        if unsupported in opts:
            raise FermError(
                f"mod recent '{unsupported}' is not supported by the nft "
                "backend"
            )
    verbs = [verb for verb in ("set", "rcheck", "update") if verb in opts]
    if len(verbs) != 1:
        raise FermError(
            "mod recent needs exactly one of set/rcheck/update for the nft "
            "backend"
        )
    is_check = verbs[0] in ("rcheck", "update")
    name_option = opts.get("name")
    if name_option is None:
        raise FermError("mod recent needs a 'name' for the nft backend")
    raw_name, _ = unwrap_value(name_option.value)
    try:
        _validate_set_name(f"recent_{raw_name}")
    except FermError:
        raise FermError(
            f"invalid recent name '{raw_name}' for the nft backend"
        ) from None
    if "rsource" in opts and "rdest" in opts:
        raise FermError(
            "mod recent cannot combine rsource and rdest for the nft backend"
        )
    direction = "daddr" if "rdest" in opts else "saddr"
    seconds = _recent_scalar(opts, "seconds")
    hitcount = _recent_scalar(opts, "hitcount")
    if hitcount is not None and seconds is None:
        raise FermError(
            "mod recent 'hitcount' needs 'seconds' for the nft backend"
        )
    if is_check and (seconds is None or hitcount is None):
        raise FermError(
            "mod recent rcheck/update needs 'seconds' and 'hitcount' for the "
            "nft backend"
        )
    has_verdict = any(o.kind is OptionKind.TARGET for o in rule.options)
    return _RecentFacts(
        raw_name, is_check, seconds, hitcount, direction, has_verdict
    )


def _build_recent_specs(
    domain: Family, rules: Iterable[RenderedRule]
) -> dict[str, _RecentSpec]:
    """
    Aggregate every mod recent rule of one family into per-name specs.

    A dynamic set's stateful (limit) expression is fixed when the element is
    created and every add/update touching it consumes a token, so all rules of
    a name MUST emit the identical element spec.  ``T`` counts the name's
    update-emitting rules; ``R = T*H/S`` (integer-reduced) and ``B = T*H - 1``
    are calibrated against real xt_recent (2026-07-10 live pin).  Refuses a
    name with conflicting seconds/direction/hitcount, a name with no seconds
    anywhere, or a bare ``set`` carrying a real verdict when the name also has
    check rules (the verdict would fire only on overflow, unlike xt).
    """
    facts_by_name: dict[str, list[_RecentFacts]] = {}
    for rule in rules:
        facts = _recent_facts(domain, rule)
        if facts is not None:
            facts_by_name.setdefault(facts.name, []).append(facts)
    specs: dict[str, _RecentSpec] = {}
    for name, facts_list in facts_by_name.items():
        seconds_values = {
            f.seconds for f in facts_list if f.seconds is not None
        }
        if len(seconds_values) > 1:
            raise FermError(
                f"mod recent '{name}' has conflicting seconds for the nft "
                "backend"
            )
        if not seconds_values:
            raise FermError(
                f"mod recent '{name}' has no seconds anywhere; the window is "
                "undefined for the nft backend"
            )
        directions = {f.direction for f in facts_list}
        if len(directions) > 1:
            raise FermError(
                f"mod recent '{name}' mixes rsource and rdest for the nft "
                "backend"
            )
        hitcounts = {f.hitcount for f in facts_list if f.hitcount is not None}
        if len(hitcounts) > 1:
            raise FermError(
                f"mod recent '{name}' has conflicting hitcounts for the nft "
                "backend"
            )
        has_check = any(f.is_check for f in facts_list)
        if has_check and any(
            not f.is_check and f.has_verdict for f in facts_list
        ):
            raise FermError(
                f"mod recent '{name}' set rule carries a verdict but the name "
                "has check rules for the nft backend"
            )
        seconds = int(next(iter(seconds_values)))
        timeout = _nft_time_canon(seconds * 1000)
        limit: str | None = None
        if has_check:
            hits = int(next(iter(hitcounts)))
            numerator = len(facts_list) * hits
            if numerator > 1:
                rate, unit = _reduce_rate(numerator, seconds)
                limit = (
                    f"rate over {rate}/{unit} burst {numerator - 1} packets"
                )
            # T*H == 1 degenerates to "match from the first in-window
            # packet"; the limitless update expresses that exactly, while
            # the formula's `burst 0` is rejected by nft outright.
        specs[name] = _RecentSpec(next(iter(directions)), timeout, limit)
    return specs


def _recent_update(
    domain: Family,
    rule: RenderedRule,
    recent_specs: dict[str, _RecentSpec] | None,
) -> NftSetUpdate:
    """Emit one rule's ``update @recent_<name> { ... }`` from its spec."""
    facts = _recent_facts(domain, rule)
    if facts is None:
        raise internal_error()  # caller gates on a recent option present
    if recent_specs is None or facts.name not in recent_specs:
        # The per-name spec is a whole-family pre-pass; a caller reaching
        # translate_rule for a recent rule without it is a wiring bug.
        raise internal_error(
            "recent rule reached translate_rule without its pre-pass spec"
        )
    spec = recent_specs[facts.name]
    set_type = "ipv4_addr" if domain == Family.IP else "ipv6_addr"
    return NftSetUpdate(
        f"recent_{facts.name}",
        f"{domain} {spec.direction}",
        set_type,
        spec.timeout,
        spec.limit,
    )


def _prefix_length_mask(domain: Family, length: str) -> str:
    """Render a hashlimit prefix length as the nft address mask literal."""
    if not length.isdigit():
        raise FermError(
            f"invalid hashlimit mask '{length}' for the nft backend"
        )
    bits = int(length)
    if domain == Family.IP:
        if bits > 32:  # noqa: PLR2004 - IPv4 prefix ceiling
            raise FermError(f"hashlimit mask '{length}' exceeds /32 for nft")
        return str(ipaddress.IPv4Network(f"0.0.0.0/{bits}").netmask)
    if bits > 128:  # noqa: PLR2004 - IPv6 prefix ceiling
        raise FermError(f"hashlimit mask '{length}' exceeds /128 for nft")
    return str(ipaddress.IPv6Network(f"::/{bits}").netmask)


def _hashlimit_rate(scalar: str) -> tuple[str, str]:
    """
    Parse an xt hashlimit rate ``N/unit`` into ``(N, nft-unit)``.

    Byte rates (``1kb/s`` and kin) leave ``N`` non-numeric and refuse, as do
    fractional counts and unknown units -- packet rates over time only.
    """
    number, _, unit = scalar.partition("/")
    if not number.isdigit() or int(number) < 1:
        raise FermError(
            f"unsupported hashlimit rate '{scalar}' for the nft backend"
        )
    nft_unit = _HASHLIMIT_UNIT.get(unit)
    if nft_unit is None:
        raise FermError(
            f"unsupported hashlimit rate unit in '{scalar}' for the nft "
            "backend"
        )
    return str(int(number)), nft_unit


def _hashlimit_key(
    domain: Family,
    mode_scalar: str,
    opts: dict[str, RenderedOption],
    protocol: str | None,
) -> tuple[str, str]:
    """
    Build the concatenated hashlimit key and its nft set type from the mode.

    Modes emit in the canonical order srcip, dstip, srcport, dstport;
    src/dstmask narrow the address key with an ``& <mask>``; a port mode
    without a tcp/udp protocol refuses.
    """
    tokens = mode_scalar.split(",")
    unknown = [t for t in tokens if t not in _HASHLIMIT_MODE_ORDER]
    if unknown:
        raise FermError(
            f"unsupported hashlimit mode '{mode_scalar}' for the nft backend"
        )
    addr_type = "ipv4_addr" if domain == Family.IP else "ipv6_addr"
    keys: list[str] = []
    types: list[str] = []
    for token in _HASHLIMIT_MODE_ORDER:
        if token not in tokens:
            continue
        if token in ("srcip", "dstip"):
            side = "saddr" if token == "srcip" else "daddr"
            mask = opts.get(
                "hashlimit-srcmask"
                if token == "srcip"
                else "hashlimit-dstmask"
            )
            key = f"{domain} {side}"
            if mask is not None:
                length, _ = unwrap_value(mask.value)
                key += f" & {_prefix_length_mask(domain, length)}"
            keys.append(key)
            types.append(addr_type)
        else:
            if protocol not in PORT_PROTOCOLS:
                raise FermError(
                    f"hashlimit mode '{token}' needs a tcp/udp protocol for "
                    "the nft backend"
                )
            port = "sport" if token == "srcport" else "dport"
            keys.append(f"{protocol} {port}")
            types.append("inet_service")
    return " . ".join(keys), " . ".join(types)


def _hashlimit_timeout(
    opts: dict[str, RenderedOption], unit: str
) -> str | None:
    """
    Resolve the element timeout for a hashlimit rule.

    htable-expire (milliseconds) wins; otherwise the rate period stands in
    (``/minute`` -> ``1m``), and a bare ``/second`` rate carries no timeout
    (a timeout-less element under ``flags dynamic`` is legal, pinned live).
    """
    expire = opts.get("hashlimit-htable-expire")
    if expire is not None:
        milliseconds, _ = unwrap_value(expire.value)
        if not milliseconds.isdigit():
            raise FermError(
                f"invalid hashlimit htable-expire '{milliseconds}' for the "
                "nft backend"
            )
        return _nft_time_canon(int(milliseconds))
    return _HASHLIMIT_PERIOD_TIMEOUT.get(unit)


def _hashlimit_update(
    domain: Family, rule: RenderedRule, protocol: str | None
) -> NftSetUpdate:
    """
    Emit one rule's ``update @hashlimit_<name> { ... }`` statement.

    Self-contained per rule (every parameter lives on the rule); the cross-rule
    "one name, one shape" invariant is the declaration-conflict guard in
    :func:`_collect_set_declarations`.  ``upto`` gives the conform rate,
    ``above`` the ``over`` rate; hashlimit takes no ``T`` compensation (xt
    taxes its shared htable identically).
    """
    opts = {o.name: o for o in rule.options if o.module == "hashlimit"}
    if domain not in (Family.IP, Family.IP6):
        raise FermError("mod hashlimit needs the ip or ip6 family for nft")
    for option in opts.values():
        if isinstance(option.value, (Negated, PreNegated)):
            raise FermError(
                f"mod hashlimit '{option.name}' cannot be negated for the nft "
                "backend"
            )
    if "hashlimit-htable-max" in opts:
        # The dynamic set's capacity is pinned to the kernel's implicit
        # `size 65535` for --plan readback parity; honouring a user cap
        # would need that convergence re-verified, so refuse instead of
        # silently overriding a deliberate memory/DoS ceiling.
        raise FermError(
            "mod hashlimit 'hashlimit-htable-max' has no nft equivalent "
            "for the nft backend"
        )
    # hashlimit-htable-size and hashlimit-htable-gcinterval are pure
    # performance-tuning knobs (initial bucket count, GC cadence) with no
    # match semantics; nft sizes and expires dynamic sets itself, so they
    # are deliberately ignored rather than refused.
    name_option = opts.get("hashlimit-name")
    if name_option is None:
        raise FermError(
            "mod hashlimit needs 'hashlimit-name' for the nft backend"
        )
    raw_name, _ = unwrap_value(name_option.value)
    try:
        _validate_set_name(f"hashlimit_{raw_name}")
    except FermError:
        raise FermError(
            f"invalid hashlimit name '{raw_name}' for the nft backend"
        ) from None
    # `hashlimit` is xt's legacy synonym for `hashlimit-upto`.
    upto = opts.get("hashlimit-upto") or opts.get("hashlimit")
    above = opts.get("hashlimit-above")
    if upto is not None and above is not None:
        raise FermError(
            "mod hashlimit cannot combine upto and above for the nft backend"
        )
    rate_option = upto if upto is not None else above
    if rate_option is None:
        raise FermError(
            "mod hashlimit needs an upto/above rate for the nft backend"
        )
    rate_scalar, _ = unwrap_value(rate_option.value)
    rate, unit = _hashlimit_rate(rate_scalar)
    burst = "5"
    burst_option = opts.get("hashlimit-burst")
    if burst_option is not None:
        burst, _ = unwrap_value(burst_option.value)
        if not _NFT_BURST_RE.match(burst):
            raise FermError(
                f"invalid hashlimit burst '{burst}' for the nft backend"
            )
    prefix = "rate over" if above is not None else "rate"
    limit = f"{prefix} {rate}/{unit} burst {burst} packets"
    mode_option = opts.get("hashlimit-mode")
    if mode_option is None:
        raise FermError(
            "mod hashlimit needs 'hashlimit-mode' for the nft backend"
        )
    mode_scalar, _ = unwrap_value(mode_option.value)
    key_expr, set_type = _hashlimit_key(domain, mode_scalar, opts, protocol)
    timeout = _hashlimit_timeout(opts, unit)
    return NftSetUpdate(
        f"hashlimit_{raw_name}", key_expr, set_type, timeout, limit
    )


def _hashlimit_key_implies_l4proto(options: Iterable[RenderedOption]) -> bool:
    """
    Report whether a hashlimit port mode puts a proto selector in the key.

    A ``srcport``/``dstport`` mode emits ``<proto> sport|dport`` inside the
    dynamic-set key, which -- like an explicit port match -- makes the kernel
    drop the ``meta l4proto`` prefix on readback; emitting it anyway would
    leave ``--plan`` diffing forever.
    """
    for option in options:
        if option.module == "hashlimit" and option.name == "hashlimit-mode":
            scalar, _ = unwrap_value(option.value)
            if any(
                token in ("srcport", "dstport") for token in scalar.split(",")
            ):
                return True
    return False


# ---------------------------------------------------------------------------
# mod time: meta hour / meta day / meta time
# ---------------------------------------------------------------------------

#: nft weekday index (Sunday=0) -> readback name.
_NFT_DAY_NAMES: Final[tuple[str, ...]] = (
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
)
#: xt weekday name/abbreviation -> nft index.  Numeric xt days (1..7,
#: Monday=1..Sunday=7) map with ``n % 7`` so Sunday's xt 7 becomes nft 0.
_XT_DAY_TO_NFT: Final[dict[str, int]] = {
    "monday": 1,
    "mon": 1,
    "tuesday": 2,
    "tue": 2,
    "wednesday": 3,
    "wed": 3,
    "thursday": 4,
    "thu": 4,
    "friday": 5,
    "fri": 5,
    "saturday": 6,
    "sat": 6,
    "sunday": 0,
    "sun": 0,
}
_TIME_OF_DAY_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(\d{1,2}):(\d{2})(?::(\d{2}))?\Z"
)
_DATE_RE: Final[re.Pattern[str]] = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})\Z")
_CLOCK_HOUR_MAX: Final[int] = 23
_CLOCK_FIELD_MAX: Final[int] = 59
_DAYS_PER_WEEK: Final[int] = 7


def _clock_parts(
    match: re.Match[str], scalar: str, kind: str
) -> tuple[int, int, int]:
    """Return validated ``(hour, minute, second)`` from a clock match."""
    hour, minute = int(match.group(1)), int(match.group(2))
    second = int(match.group(3)) if match.group(3) is not None else 0
    if not (
        0 <= hour <= _CLOCK_HOUR_MAX
        and 0 <= minute <= _CLOCK_FIELD_MAX
        and 0 <= second <= _CLOCK_FIELD_MAX
    ):
        raise FermError(f"invalid {kind} '{scalar}' for nft backend")
    return hour, minute, second


def _time_of_day(scalar: str) -> str:
    """
    Normalize an xt ``HH:MM[:SS]`` clock value to the nft readback spelling.

    nft prints a ``meta hour`` bound as ``HH:MM``, appending ``:SS`` only
    when the seconds are non-zero (per boundary), so emission trims a zero
    seconds field to keep an applied rule diff-free under ``--plan``.
    """
    match = _TIME_OF_DAY_RE.match(scalar)
    if match is None:
        raise FermError(f"invalid time '{scalar}' for nft backend")
    hour, minute, second = _clock_parts(match, scalar, "time")
    if second:
        return f"{hour:02d}:{minute:02d}:{second:02d}"
    return f"{hour:02d}:{minute:02d}"


def _datetime_iso(scalar: str) -> str:
    """
    Normalize an xt ISO8601 ``date[Thh:mm[:ss]]`` to nft's full form.

    nft prints a ``meta time`` bound as ``YYYY-MM-DD hh:mm:ss`` (seconds
    always present, ``T`` rendered as a space), so a bare date gains a
    ``00:00:00`` clock and a ``T`` separator becomes a space.
    """
    date_part, sep, time_part = scalar.partition("T")
    if _DATE_RE.match(date_part) is None:
        raise FermError(f"invalid date '{scalar}' for nft backend")
    if not sep:
        clock = "00:00:00"
    else:
        match = _TIME_OF_DAY_RE.match(time_part)
        if match is None:
            raise FermError(f"invalid date '{scalar}' for nft backend")
        hour, minute, second = _clock_parts(match, scalar, "date")
        clock = f"{hour:02d}:{minute:02d}:{second:02d}"
    return f"{date_part} {clock}"


def _time_hour_match(options: dict[str, RenderedOption]) -> str | None:
    """Build ``meta hour "S"-"E"`` from timestart/timestop (xt defaults)."""
    start = options.get("timestart")
    stop = options.get("timestop")
    if start is None and stop is None:
        return None
    low = _time_of_day(first_scalar(start.value)) if start else "00:00"
    high = _time_of_day(first_scalar(stop.value)) if stop else "23:59:59"
    return f'meta hour "{low}"-"{high}"'


def _time_day_match(options: dict[str, RenderedOption]) -> str | None:
    """
    Build ``meta day`` from days/weekdays (aliases of one xt flag).

    Names are printed in nft's numeric order (Sunday first) and quoted; a
    single day drops the braces (kernel readback, negation included).  Both
    keys at once is an xt conflict, so it refuses.
    """
    days = options.get("days")
    weekdays = options.get("weekdays")
    if days is not None and weekdays is not None:
        raise FermError(
            "mod time cannot combine 'days' and 'weekdays' for the nft backend"
        )
    option = days if days is not None else weekdays
    if option is None:
        return None
    scalar, neg = unwrap_value(option.value)
    indices = sorted(
        {_xt_day_index(token) for token in scalar.split(",") if token.strip()}
    )
    names = [f'"{_NFT_DAY_NAMES[index]}"' for index in indices]
    body = names[0] if len(names) == 1 else f"{{ {', '.join(names)} }}"
    return f"meta day {_op(neg)}{body}"


def _xt_day_index(token: str) -> int:
    """Map one xt weekday (name/abbreviation/1..7) to its nft index."""
    lowered = token.strip().lower()
    if lowered in _XT_DAY_TO_NFT:
        return _XT_DAY_TO_NFT[lowered]
    if lowered.isdigit() and 1 <= int(lowered) <= _DAYS_PER_WEEK:
        return int(lowered) % _DAYS_PER_WEEK
    raise FermError(f"unknown weekday '{token.strip()}' for nft backend")


def _time_span_match(options: dict[str, RenderedOption]) -> str | None:
    """Build ``meta time`` from datestart/datestop (range / >= / <=)."""
    start = options.get("datestart")
    stop = options.get("datestop")
    low = _datetime_iso(first_scalar(start.value)) if start else None
    high = _datetime_iso(first_scalar(stop.value)) if stop else None
    if low is not None and high is not None:
        return f'meta time "{low}"-"{high}"'
    if low is not None:
        return f'meta time >= "{low}"'
    if high is not None:
        return f'meta time <= "{high}"'
    return None


def _time_matches(options: dict[str, RenderedOption]) -> list[NftMatch]:
    """
    Translate a rule's ``mod time`` options to 0-3 nft meta matches.

    hour/day/time are independent selectors emitted in a fixed order.
    monthday, kerneltz, and contiguous have no faithful nft equivalent
    (monthday has no meta selector; kerneltz/contiguous change the local-time
    and cross-midnight semantics nft's UTC-anchored evaluation cannot mirror),
    so they refuse.
    """
    for refused in ("monthday", "kerneltz", "contiguous"):
        if refused in options:
            raise FermError(
                f"mod time '{refused}' not yet supported by nft backend"
            )
    matches: list[NftMatch] = []
    for builder in (_time_hour_match, _time_day_match, _time_span_match):
        expr = builder(options)
        if expr is not None:
            matches.append(NftMatch(expr))
    return matches


# ---------------------------------------------------------------------------
# mod connbytes: ct [dir] bytes|packets|avgpkt
# ---------------------------------------------------------------------------

#: ct byte/packet counters are 64-bit; the guard is wider than quota's 2^63-1.
_CONNBYTES_MAX: Final[int] = 2**64 - 1
_CONNBYTES_DIRS: Final[frozenset[str]] = frozenset(
    {"original", "reply", "both"}
)
_CONNBYTES_MODES: Final[frozenset[str]] = frozenset(
    {"bytes", "packets", "avgpkt"}
)


def _connbytes_u64(scalar: str) -> str:
    """Validate a connbytes bound as an unsigned 64-bit integer."""
    if not scalar.isdigit():
        raise FermError(
            f"invalid connbytes value '{scalar}' for the nft backend"
        )
    value = int(scalar)
    if value > _CONNBYTES_MAX:
        raise FermError(
            f"connbytes value '{scalar}' exceeds 2^64-1 for the nft backend"
        )
    return str(value)


def _connbytes_range(selector: str, value: str, neg: bool) -> str:
    """
    Spell a connbytes range operand in the kernel-readback form.

    xt's ``lo:hi`` window maps to the readback's comparison spelling:
    ``N:`` (or a bare ``N``, which xt reads as ``N:``) is ``>= N``, ``:M``
    is the closed ``0-M`` interval, and ``N:M`` is ``N-M``.  Negation flips
    ``>=`` to ``<`` for the open lower bound and prefixes ``!=`` for the
    interval forms -- the ``>=``/``<`` symbols are the readback spelling, not
    iptables-translate's ``ge``/``lt``.
    """
    low, sep, high = value.partition(":")
    if not sep:  # bare N -> N: (open upper bound)
        bound = _connbytes_u64(value)
        return f"{selector} {'<' if neg else '>='} {bound}"
    if low and not high:  # N:
        bound = _connbytes_u64(low)
        return f"{selector} {'<' if neg else '>='} {bound}"
    if not low and high:  # :M -> 0-M
        upper = _connbytes_u64(high)
        return f"{selector} {'!= ' if neg else ''}0-{upper}"
    if not low and not high:  # bare ':'
        raise FermError(
            f"invalid connbytes range '{value}' for the nft backend"
        )
    lower = _connbytes_u64(low)
    upper = _connbytes_u64(high)
    if int(low) > int(high):
        raise FermError(
            f"connbytes range '{value}' has lo > hi for the nft backend"
        )
    return f"{selector} {'!= ' if neg else ''}{lower}-{upper}"


def _connbytes_match(opts: dict[str, RenderedOption]) -> NftMatch:
    """
    Translate a rule's ``mod connbytes`` options to one ``ct`` counter match.

    The three options are collected rule-wide (the ``mod time`` precedent);
    ``connbytes-dir`` and ``connbytes-mode`` are both mandatory (xt refuses
    without them), and neither may be negated.  ``dir both`` drops the
    direction prefix; ``original``/``reply`` prefix the selector.
    """
    value_opt = opts.get("connbytes")
    if value_opt is None:
        raise FermError(
            "mod connbytes needs a 'connbytes' value for the nft backend"
        )
    dir_opt = opts.get("connbytes-dir")
    mode_opt = opts.get("connbytes-mode")
    if dir_opt is None or mode_opt is None:
        raise FermError(
            "mod connbytes needs both 'connbytes-dir' and 'connbytes-mode' "
            "for the nft backend"
        )
    direction, dir_neg = unwrap_value(dir_opt.value)
    mode, mode_neg = unwrap_value(mode_opt.value)
    if dir_neg or mode_neg:
        raise FermError(
            "mod connbytes dir/mode cannot be negated for the nft backend"
        )
    if direction not in _CONNBYTES_DIRS:
        raise FermError(
            f"invalid connbytes-dir '{direction}' for the nft backend"
        )
    if mode not in _CONNBYTES_MODES:
        raise FermError(f"invalid connbytes-mode '{mode}' for the nft backend")
    prefix = "" if direction == "both" else f"{direction} "
    selector = f"ct {prefix}{mode}"
    value, neg = unwrap_value(value_opt.value)
    return NftMatch(_connbytes_range(selector, value, neg))


# ---------------------------------------------------------------------------
# mod quota: quota <n> <unit>
# ---------------------------------------------------------------------------

#: nft rejects a quota >= 2^63 ("Value too large"); the ceiling is narrower
#: than connbytes' full u64.
_QUOTA_MAX: Final[int] = 2**63 - 1
#: The three quota units the kernel readback uses, largest first (there is no
#: ``gbytes``; the ladder tops out at ``mbytes``).
_QUOTA_UNITS: Final[tuple[tuple[int, str], ...]] = (
    (1024 * 1024, "mbytes"),
    (1024, "kbytes"),
)


def _quota_canon(value: int) -> str:
    """
    Spell a byte quota in the largest evenly-dividing kernel unit.

    The readback prints ``2 kbytes`` for 2048 and ``1 mbytes`` for 2^20 but
    keeps an indivisible count in bytes (1500000 stays ``1500000 bytes``).
    There is no ``gbytes``, so 2^30 reads back as ``1024 mbytes``.
    """
    for divisor, unit in _QUOTA_UNITS:
        if value and value % divisor == 0:
            return f"{value // divisor} {unit}"
    return f"{value} bytes"


def _quota_statement(option: RenderedOption) -> NftQuota:
    """
    Translate a ``mod quota --quota N`` match to the nft ``quota`` statement.

    The ferm ``quota=s`` keyword carries no ``!``, so the negated ``quota
    over`` readback form cannot arise here; the value is validated against
    nft's 2^63-1 ceiling and canonicalised to the kernel's printed unit.
    """
    scalar, _ = unwrap_value(option.value)
    if not scalar.isdigit():
        raise FermError(f"invalid quota '{scalar}' for the nft backend")
    value = int(scalar)
    if value > _QUOTA_MAX:
        raise FermError(
            f"quota '{scalar}' exceeds nft's 2^63-1 ceiling for the nft "
            "backend"
        )
    return NftQuota(f"quota {_quota_canon(value)}")


# ---------------------------------------------------------------------------
# mod connlimit: an implicit per-rule dynamic set + ct count
# ---------------------------------------------------------------------------

#: connlimit's connection count is a 32-bit value.
_CONNLIMIT_COUNT_MAX: Final[int] = 0xFFFFFFFF


def _connlimit_count(scalar: str) -> str:
    """Validate a connlimit connection count as an unsigned 32-bit integer."""
    if not scalar.isdigit():
        raise FermError(
            f"invalid connlimit count '{scalar}' for the nft backend"
        )
    value = int(scalar)
    if value > _CONNLIMIT_COUNT_MAX:
        raise FermError(
            f"connlimit count '{scalar}' exceeds 2^32-1 for the nft backend"
        )
    return str(value)


def _connlimit_update(domain: Family, rule: RenderedRule) -> NftSetUpdate:
    """
    Translate a rule's ``mod connlimit`` to a per-rule ``add @set { ... }``.

    xt_connlimit allocates one ``nf_conncount`` tree PER RULE, so every rule
    gets its own implicit dynamic set (never shared).  The set carries the
    address key (``ip|ip6 saddr|daddr``, narrowed by ``connlimit-mask`` to
    ``& <netmask>``) plus a ``ct count [over] N`` stateful expression on the
    element.  The name is a placeholder here; :func:`_finalize_connlimit_names`
    assigns the stable content-hash name once the full rule text is known.
    Exactly one of ``connlimit-upto``/``connlimit-above`` (upto = ``count N``,
    above = ``count over N``; each negates to the other); ``saddr`` and
    ``daddr`` flags together, or a zero/oversized mask, refuse.
    """
    if domain not in (Family.IP, Family.IP6):
        raise FermError("mod connlimit needs the ip or ip6 family for nft")
    opts = {o.name: o for o in rule.options if o.module == "connlimit"}
    upto = opts.get("connlimit-upto")
    above = opts.get("connlimit-above")
    if (upto is not None) == (above is not None):
        raise FermError(
            "mod connlimit needs exactly one of connlimit-upto/"
            "connlimit-above for the nft backend"
        )
    rate_option = upto if upto is not None else above
    assert rate_option is not None  # exactly one is set (checked above)
    count_scalar, neg = unwrap_value(rate_option.value)
    count = _connlimit_count(count_scalar)
    # upto = "not above"; a negated upto behaves like above and vice versa.
    over = (above is not None) != neg
    count_expr = f"ct count over {count}" if over else f"ct count {count}"
    if "connlimit-saddr" in opts and "connlimit-daddr" in opts:
        raise FermError(
            "mod connlimit cannot combine saddr and daddr for the nft backend"
        )
    side = "daddr" if "connlimit-daddr" in opts else "saddr"
    key = f"{domain} {side}"
    mask_option = opts.get("connlimit-mask")
    if mask_option is not None:
        length, _ = unwrap_value(mask_option.value)
        if not length.isdigit():
            raise FermError(
                f"invalid connlimit mask '{length}' for the nft backend"
            )
        bits = int(length)
        max_bits = 32 if domain == Family.IP else 128
        if bits == 0:
            raise FermError(
                "connlimit-mask 0 keys the whole address space as one "
                "bucket; refused for the nft backend"
            )
        if bits > max_bits:
            raise FermError(
                f"connlimit mask '{length}' exceeds /{max_bits} for the nft "
                "backend"
            )
        if bits < max_bits:  # a full mask needs no `& netmask`
            key += f" & {_prefix_length_mask(domain, length)}"
    set_type = "ipv4_addr" if domain == Family.IP else "ipv6_addr"
    return NftSetUpdate(
        _CONNLIMIT_SENTINEL, f"{key} {count_expr}", set_type, verb="add"
    )


def _finalize_connlimit_names(
    domain: Family, table: str, chain: str, rules: list[NftRule]
) -> None:
    """
    Assign each connlimit set a stable content-hash name, in place.

    Runs per chain in ``render()`` STRICTLY BEFORE the collapse pass: the
    name depends on the fully rendered rule text (unknown inside
    ``translate_rule``, where siblings are invisible), so the sentinel stands
    in until here.  The name hashes (family, table, chain, rule text with the
    sentinel still in place -- which breaks the name<->text cycle, and an
    ordinal that separates textually identical rules).  Ordering matters two
    ways: distinct names give collapse distinct ``NftSetUpdate`` texts, so it
    never folds two connlimit rules into one (which would merge their per-rule
    counters); and the ordinal guarantees two byte-identical rules still get
    separate sets, exactly as xt gives them separate conncount trees.
    """
    ordinals: dict[str, int] = {}
    for rule in rules:
        for stmt in rule.statements:
            if (
                isinstance(stmt, NftSetUpdate)
                and stmt.name == _CONNLIMIT_SENTINEL
            ):
                text = " ".join(s.to_text() for s in rule.statements)
                ordinal = ordinals.get(text, 0)
                ordinals[text] = ordinal + 1
                digest = hashlib.sha256(
                    "\x00".join(
                        (domain.value, table, chain, text, str(ordinal))
                    ).encode(BYTE_ENCODING)
                ).hexdigest()[:12]
                stmt.name = f"connlimit_{digest}"


#: Match modules whose BARE ``mod X`` load matches every packet (their xt
#: parse accepts zero flags and then checks nothing), so dropping the
#: ``-m`` marker loses no semantics.  Every other bare load either IS the
#: match (``hbh``/``dst``/``eui64`` header checks, ``limit``'s implicit
#: default rate) or is invalid iptables (mandatory options); both refuse
#: rather than silently widen the rule.  A marker whose module contributes
#: at least one option to the rule is always skippable: the options carry
#: (or refuse) the semantics.
_BARE_INERT_MATCH_MODULES: Final[frozenset[str]] = frozenset(
    {"state", "conntrack"}
)


def translate_rule(
    domain: Family,
    table: str,
    rule: RenderedRule,
    *,
    chain: str | None = None,
    recent_specs: dict[str, _RecentSpec] | None = None,
) -> NftRule:
    """
    Translate one RenderedRule to an NftRule (two-pass).

    Pass intent: ``match_module`` markers are dropped (``-m`` is implicit
    in nft); ``comment`` becomes the rule comment; the ``protocol`` option
    sets the port context and emits ``meta l4proto`` ONLY when no port
    match subsumes it; ``kind == 'target'`` records the verdict discriminator
    and companion options feed it.  Match statements keep their source order
    (nft is order-sensitive); the verdict is appended last.

    ``chain`` is the ORIGINAL (pre-``nft_chain_name``) chain name, the hook
    context for verdicts whose translation depends on the hook side (NETMAP);
    ``None`` means unknown, making such a verdict refuse cleanly.
    """
    if _references_empty_named_set(rule):
        raise internal_error(
            "a rule over a family-filtered empty named set reached "
            "translate_rule; the caller must drop it first"
        )
    # First pass: resolve rule-wide context (the l4 protocol and whether a
    # port match exists) so a port option that textually precedes the
    # `protocol` option still translates correctly (order-independent).
    has_port = any(
        o.name in _PORT_KEYWORD or o.name in _MULTIPORT_KEYWORD
        for o in rule.options
    )
    # `icmp type` and `tcp flags` (like a port match) imply their l4proto
    # dependency, and the kernel readback omits the `meta l4proto` prefix
    # for such a rule, so emitting it would leave --plan diffing forever.
    # (A maxseg-only rule KEEPS the prefix -- verified live -- so the
    # TCPMSS verdict does not join this set.)
    has_implied_l4proto = any(
        o.name in ("icmp-type", "tcp-flags", "syn") for o in rule.options
    ) or _hashlimit_key_implies_l4proto(rule.options)
    # `--limit-burst` is a companion of the SAME xt_limit match, folded
    # into the limit statement below (the kernel readback always prints
    # an explicit burst, so the pair must emit as one statement).
    # RenderedRule flattens module instances, so with several `limit`
    # options (or several bursts) a burst cannot be paired back with
    # its own match -- refuse rather than attach one burst to every
    # limit statement.
    limit_count = sum(o.name == "limit" for o in rule.options)
    has_limit = limit_count > 0
    burst: str | None = None
    for option in rule.options:
        if option.name == "limit-burst":
            scalar, _ = unwrap_value(option.value)
            if not _NFT_BURST_RE.match(scalar):
                raise FermError(
                    f"invalid limit burst '{scalar}' for nft backend"
                )
            if burst is not None:
                raise FermError(
                    "more than one 'limit-burst' per rule cannot be "
                    "paired for the nft backend"
                )
            burst = scalar
    if burst is not None and limit_count > 1:
        raise FermError(
            "'limit-burst' with more than one 'limit' per rule cannot "
            "be paired for the nft backend"
        )
    # addrtype's --limit-iface-in/out are no-arg flags on the SAME match as
    # src-/dst-type; each qualifies the fib selector with the routing input
    # or output interface.  Collected rule-wide (like the burst) so the
    # modifier reaches every fib match regardless of source order.  arp/eb
    # have no fib translation, so their addrtype falls through to the
    # generic refusal untouched.
    fib_capable = domain in (Family.IP, Family.IP6)
    fib_iface = ""
    if fib_capable:
        iface_in = any(o.name == "limit-iface-in" for o in rule.options)
        iface_out = any(o.name == "limit-iface-out" for o in rule.options)
        if iface_in and iface_out:
            raise FermError(
                "'limit-iface-in' and 'limit-iface-out' are mutually "
                "exclusive for the nft backend"
            )
        if (iface_in or iface_out) and not any(
            o.name in _FIB_SELECTOR for o in rule.options
        ):
            raise FermError(
                "'limit-iface-in'/'limit-iface-out' needs a src-type or "
                "dst-type match for the nft backend"
            )
        fib_iface = " . iif" if iface_in else " . oif" if iface_out else ""
    protocol: str | None = None
    for option in rule.options:
        if option.kind is OptionKind.PROTO:
            protocol, _ = unwrap_value(option.value)
            protocol = _validate_protocol(protocol)
            break
    # nft's `... to <addr>:<port>` NAT mapping is "only valid after transport
    # protocol match" -- a port match or a `meta l4proto tcp/udp` covers it,
    # both implied by the rule carrying a port-bearing protocol.
    has_transport = protocol in PORT_PROTOCOLS

    # Guard: at most one SetRef option per rule (a second would need two
    # named-set declarations sharing one rule, which is not supported yet).
    setref_count = sum(1 for o in rule.options for _ in iter_setrefs(o.value))
    if setref_count > 1:
        raise FermError("at most one named set per rule in this version")

    # mod statistic's options depend on each other (mode selects which of
    # probability/every/packet apply), so they are collected rule-wide.  The
    # collection is module-qualified: `every`/`packet` also name `mod nth`'s
    # own keywords, which must NOT be folded into a statistic match.
    statistic_opts: dict[str, RenderedOption] = {
        o.name: o for o in rule.options if o.module == "statistic"
    }

    # mod time spreads across several options (timestart/timestop/days/...)
    # that fold into up to three independent meta matches, so they are
    # collected rule-wide and emitted at the first time option (the
    # statistic/hashlimit precedent).
    time_opts: dict[str, RenderedOption] = {
        o.name: o for o in rule.options if o.module == "time"
    }

    # mod connbytes' value/dir/mode options depend on each other and fold
    # into one `ct` counter match, so they are collected rule-wide and
    # emitted at the first connbytes option (the statistic/time precedent).
    connbytes_opts: dict[str, RenderedOption] = {
        o.name: o for o in rule.options if o.module == "connbytes"
    }

    # Second pass: emit matches in source order; verdict appended last.
    matches: list[NftStatement] = []
    comment: str | None = None
    target_name: str | None = None
    target_value: str | None = None
    companions: dict[str, RenderedOption] = {}
    statistic_emitted = False
    recent_emitted = False
    hashlimit_emitted = False
    time_emitted = False
    connbytes_emitted = False
    connlimit_emitted = False

    for option in rule.options:
        name, kind = option.name, option.kind
        if kind is OptionKind.MATCH_MODULE:
            # The -m marker is implicit in nft only when the module's
            # options carry the semantics; a bare load of anything outside
            # the inert set is itself the match and must not drop.
            module_name, _ = unwrap_value(option.value)
            if module_name not in _BARE_INERT_MATCH_MODULES and not any(
                o.module == module_name
                and o.kind is not OptionKind.MATCH_MODULE
                for o in rule.options
            ):
                raise FermError(
                    f"bare 'mod {module_name}' (module load without any "
                    f"of its options) not yet supported by nft backend"
                )
            continue
        if name == "comment":
            comment, _ = unwrap_value(option.value)
            continue
        if kind is OptionKind.PROTO:
            scalar, neg = unwrap_value(option.value)
            scalar = _validate_protocol(scalar)
            # a port or icmp-type match already implies l4proto
            if not has_port and not has_implied_l4proto:
                l4 = _nft_l4proto(domain, scalar)
                expr = f"meta l4proto {_op(neg)}{l4}"
                if neg:
                    matches.append(NftMatch(expr))
                else:
                    matches.append(
                        NftMatch(expr, set_key="meta l4proto", element=l4)
                    )
            continue
        if kind is OptionKind.TARGET:
            target_value, _ = unwrap_value(option.value)
            target_name = name
            continue
        if (
            name in _TARGET_COMPANIONS
            or (option.module, name) in _MODULE_COMPANIONS
        ):
            companions[name] = option
            continue
        if option.module == "statistic":
            # Emitted once, at the position of the first statistic option, so
            # the match keeps its source order among the other matches.
            if not statistic_emitted:
                matches.append(NftMatch(_statistic_match(statistic_opts)))
                statistic_emitted = True
            continue
        if option.module == "time":
            # Up to three meta matches, emitted once at the first time option
            # so they keep source order among the other matches.
            if not time_emitted:
                matches.extend(_time_matches(time_opts))
                time_emitted = True
            continue
        if option.module == "recent":
            # One dynamic-set update per rule, at the first recent option so
            # it keeps source order; the limit spec comes from the pre-pass.
            if not recent_emitted:
                matches.append(_recent_update(domain, rule, recent_specs))
                recent_emitted = True
            continue
        if option.module == "hashlimit":
            if not hashlimit_emitted:
                matches.append(_hashlimit_update(domain, rule, protocol))
                hashlimit_emitted = True
            continue
        if option.module == "connbytes":
            # One `ct` counter match per rule, at the first connbytes option
            # so it keeps source order (the statistic/time precedent).
            if not connbytes_emitted:
                matches.append(_connbytes_match(connbytes_opts))
                connbytes_emitted = True
            continue
        if option.module == "connlimit":
            # One per-rule dynamic-set `add` per rule, at the first connlimit
            # option; its set name is finalized in a post-pass (render()).
            if not connlimit_emitted:
                matches.append(_connlimit_update(domain, rule))
                connlimit_emitted = True
            continue
        if option.module == "quota":
            # A stateful quota statement, kept off NftMatch so collapse/vmap
            # never fold two rules onto one byte counter.
            matches.append(_quota_statement(option))
            continue
        if isinstance(option.value, SetRef):
            setref = option.value
            key = _setref_selector(domain, name, protocol)
            expr = f"{key} @{_validate_set_name(setref.name)}"
            matches.append(
                NftMatch(expr, set_key=None, setref=setref, set_selector=key)
            )
            continue
        if name == "match-set":
            matches.append(_translate_match_set(domain, option.value))
            continue
        if fib_capable and name in ("limit-iface-in", "limit-iface-out"):
            continue  # consumed as the fib selector modifier (first pass)
        if fib_capable and name in _FIB_SELECTOR:
            # Not set-eligible (set_key stays None): a bare route-type word
            # has no rank in sort_set_elements, so a folded set could not
            # converge under --plan; a comma-list is a single literal here.
            matches.append(
                NftMatch(_fib_type_match(name, option.value, fib_iface))
            )
            continue
        if name == "limit-burst":
            # consumed by the limit match; alone it keeps xt_limit's
            # default rate (emitted here to preserve source order)
            if not has_limit:
                matches.append(
                    NftMatch(
                        f"limit rate {_NFT_DEFAULT_LIMIT_RATE} "
                        f"burst {burst} packets"
                    )
                )
            continue
        expr, set_key, element = _translate_match_parts(
            domain, option, protocol
        )
        if name == "limit" and burst is not None:
            expr += f" burst {burst} packets"
        matches.append(NftMatch(expr, set_key=set_key, element=element))

    statements: list[NftStatement] = list(matches)
    if target_value == "TCPOPTSTRIP":
        # TCPOPTSTRIP appends a series of reset statements (one per stripped
        # option) and no verdict; build_verdict is typed for exactly one
        # verdict, so it is spelled here (the mangle-MARK precedent for a
        # verdict-less rule).
        statements.extend(_tcpoptstrip_resets(companions, protocol))
    elif target_value == "NETMAP" and domain in (Family.IP, Family.IP6):
        # NETMAP needs the rule's own address match (the map key) and the
        # chain's hook side, which build_verdict does not see; arp/eb fall
        # through to its registry refusal.
        statements.append(
            _netmap_verdict(domain, table, chain, companions, rule.options)
        )
    elif target_value is not None:
        statements.append(
            build_verdict(
                domain,
                table,
                target_name or "jump",
                target_value,
                companions,
                has_transport=has_transport,
            )
        )
    return NftRule(statements=statements, comment=comment)


# ---------------------------------------------------------------------------
# Collapse pass: fold adjacent leaf rules into anonymous sets
# ---------------------------------------------------------------------------


def _elements_equal(a: list[str] | None, b: list[str] | None) -> bool:
    """
    Compare folded element lists by canonical order (order-insensitive).

    A second-dimension fold leaves siblings with already-merged element lists;
    comparing them order-sensitively would miss the fold when the first axis
    accumulated them in different orders ([c, d] vs [d, c]).  Canonical order
    makes the equality robust by construction.
    """
    if a is None or b is None:
        return a is None and b is None
    return sort_set_elements(a) == sort_set_elements(b)


def _stmt_equal(a: NftStatement, b: NftStatement) -> bool:
    """Return True if two statements are identical for collapse purposes."""
    if isinstance(a, NftMatch) and isinstance(b, NftMatch):
        if a.set_key is not None and b.set_key is not None:
            return (
                a.set_key == b.set_key
                and a.element == b.element
                and _elements_equal(a.elements, b.elements)
            )
        return a.expr == b.expr
    return type(a) is type(b) and a.to_text() == b.to_text()


def _collapse_axis(a: NftRule, b: NftRule) -> int | None:
    """Return the single differing eligible position, or None."""
    if a.comment != b.comment or len(a.statements) != len(b.statements):
        return None
    pairs = zip(a.statements, b.statements, strict=False)
    differing = [
        k for k, (sa, sb) in enumerate(pairs) if not _stmt_equal(sa, sb)
    ]
    if len(differing) != 1:
        return None
    k = differing[0]
    sa, sb = a.statements[k], b.statements[k]
    if (
        isinstance(sa, NftMatch)
        and isinstance(sb, NftMatch)
        and sa.set_key is not None
        and sa.set_key == sb.set_key
    ):
        return k
    return None


def _merge_run(
    rules: list[NftRule], start: int, end: int, axis: int
) -> NftRule:
    """Merge ``rules[start..end]`` into one rule with a set at *axis*."""
    base = rules[start]
    anchor = base.statements[axis]
    assert isinstance(anchor, NftMatch)
    elements: list[str] = []
    for rule in rules[start : end + 1]:
        match = rule.statements[axis]
        assert isinstance(match, NftMatch)
        if match.elements is not None:
            elements.extend(match.elements)
        elif match.element is not None:
            elements.append(match.element)
    statements = list(base.statements)
    statements[axis] = NftMatch(
        anchor.expr, set_key=anchor.set_key, elements=elements
    )
    return NftRule(statements=statements, comment=base.comment)


def _collapse_one_pass(rules: list[NftRule]) -> tuple[list[NftRule], bool]:
    """One left-to-right merge pass; returns (rules, changed)."""
    out: list[NftRule] = []
    changed = False
    count = len(rules)
    index = 0
    while index < count:
        axis = (
            _collapse_axis(rules[index], rules[index + 1])
            if index + 1 < count
            else None
        )
        if axis is None:
            out.append(rules[index])
            index += 1
            continue
        end = index + 1
        while (
            end + 1 < count
            and _collapse_axis(rules[index], rules[end + 1]) == axis
        ):
            end += 1
        out.append(_merge_run(rules, index, end, axis))
        changed = True
        index = end + 1
    return out, changed


#: Pure-verdict values our emitter produces that nft also accepts as a vmap
#: value.  'reject'/'log'/NAT/'counter' are statements nft rejects inside a
#: vmap, so a rule carrying one breaks the run and stays linear (verified on
#: nft v1.1.6).  'queue' is a verdict we emit but deliberately do not fold.
_VMAP_VERDICTS: Final[frozenset[str]] = frozenset({"accept", "drop", "return"})

#: A vmap leaf rule is exactly one set-eligible match plus its verdict.
_VMAP_LEAF_STATEMENTS: Final[int] = 2


def _is_vmap_verdict(statement: NftStatement) -> bool:
    """Return whether *statement* is a verdict nft allows as a vmap value."""
    if not isinstance(statement, NftVerdict):
        return False
    return statement.expr in _VMAP_VERDICTS or statement.expr.startswith(
        ("jump ", "goto ")
    )


def _vmap_candidate(rule: NftRule) -> tuple[str, str, str] | None:
    """
    Return ``(set_key, key, verdict)`` if *rule* is a single-key vmap leaf.

    A candidate is exactly ``[<set-eligible match>, <vmap verdict>]`` carrying
    a single (not already folded) operand and no comment; anything else returns
    ``None`` so the run breaks and the rule stays linear (safe-bias).
    """
    if (
        rule.comment is not None
        or len(rule.statements) != _VMAP_LEAF_STATEMENTS
    ):
        return None
    match, verdict = rule.statements
    if (
        not isinstance(match, NftMatch)
        or match.set_key is None
        or match.element is None
        or match.elements is not None
    ):
        return None
    if not _is_vmap_verdict(verdict):
        return None
    assert isinstance(verdict, NftVerdict)
    return match.set_key, match.element, verdict.expr


def _collapse_vmap(rules: list[NftRule]) -> list[NftRule]:
    """
    Fold a run of adjacent single-key rules into one verdict map.

    Runs after the set-collapse fixpoint, so any adjacent same-selector singles
    left here necessarily differ in verdict (equal-verdict singles already
    merged into a set).  A duplicate key ends the run (nft rejects a vmap with
    duplicate keys), and a run of length 1 is left linear.
    """
    out: list[NftRule] = []
    count = len(rules)
    index = 0
    while index < count:
        candidate = _vmap_candidate(rules[index])
        if candidate is None:
            out.append(rules[index])
            index += 1
            continue
        set_key, first_key, first_verdict = candidate
        pairs: list[tuple[str, str]] = [(first_key, first_verdict)]
        keys_seen = {first_key}
        end = index
        while end + 1 < count:
            following = _vmap_candidate(rules[end + 1])
            if (
                following is None
                or following[0] != set_key
                or following[1] in keys_seen
            ):
                break
            pairs.append((following[1], following[2]))
            keys_seen.add(following[1])
            end += 1
        if end > index:
            out.append(NftRule(statements=[NftVmap(set_key, pairs)]))
        else:
            out.append(rules[index])
        index = end + 1
    return out


def _collapse_chain_rules(rules: list[NftRule]) -> list[NftRule]:
    """
    Fold adjacent leaf rules into anonymous sets, then into verdict maps.

    The set pass iterates to a fixpoint: each pass strictly reduces the rule
    count, so the loop terminates.  Only adjacent rules merge (nft is
    order-sensitive); the predicate is the safety boundary, not array
    provenance.  The vmap pass runs once over the settled result.
    """
    changed = True
    while changed:
        rules, changed = _collapse_one_pass(rules)
    return _collapse_vmap(rules)


class NftBackend(Backend):
    """The native nftables backend (Phase 2, all families via ``nft -f``)."""

    def tool_names(self, domain: Family) -> dict[str, str]:
        """Return the single family-independent ``nft`` binary."""
        del domain
        return {"nft": "nft"}

    def render(
        self, domain: Family, domain_info: DomainInfo, options: Options
    ) -> Rendered:
        """
        Build the atomic ``nft -f`` script for one family.

        nft is always save-shaped: no slow/eb command fallback, so
        ``Rendered.commands`` stays empty.  All ferm tables merge into ONE
        ``table <family> ferm``; chain names disambiguated via
        :func:`nft_chain_name` applied identically here and to
        jump/goto targets in :func:`build_verdict`.  ``@preserve`` is a
        plain error; a residual nft-name collision is a ferm
        error, NOT silent rule loss.
        """
        table = NftTable(family=domain.nft_name, name=NFT_TABLE_NAME)
        chains: list[NftBaseChain | NftRegularChain] = []
        rules: dict[str, list[NftRule]] = {}
        # mod recent's per-name element spec (timeout + calibrated rate) needs
        # facts spread across several rules of the family (the window lives on
        # the check rule, the bare `set` is target-less), so it is aggregated
        # in a whole-family pre-pass before any rule is translated.
        recent_specs = _build_recent_specs(
            domain,
            (
                rule
                for table_info in domain_info.tables.values()
                for chain_rules in table_info.chains.values()
                for rule in chain_rules.rules
            ),
        )
        for tbl in sorted(domain_info.tables):
            table_info = domain_info.tables[tbl]
            if table_info.preserve_regexes:
                raise FermError("@preserve not yet supported by nft backend")
            chains.extend(build_chains(domain, tbl, table_info))
            for original in sorted(table_info.chains):
                nft_name = nft_chain_name(tbl, original)
                if nft_name in rules:
                    raise FermError(
                        f"nft chain name collision '{nft_name}' in table "
                        f"{NFT_TABLE_NAME}"
                    )
                translated = [
                    translate_rule(
                        domain,
                        tbl,
                        rule,
                        chain=original,
                        recent_specs=recent_specs,
                    )
                    for rule in table_info.chains[original].rules
                    if not _references_empty_named_set(rule)
                ]
                # Assign connlimit set names from the final rule text BEFORE
                # collapse: distinct names keep collapse from folding two
                # connlimit rules into one (which would merge per-rule
                # conncount trees).  The order is load-bearing.
                _finalize_connlimit_names(domain, tbl, original, translated)
                rules[nft_name] = _collapse_chain_rules(translated)
        decls = _collect_set_declarations(domain, rules)
        save = serialize_table(
            table, chains, rules, decls, noflush=options.noflush
        )
        return Rendered(save=save)

    def commit(
        self,
        domain: Family,
        domain_info: DomainInfo,
        rendered: Rendered,
        options: Options,
        *,
        execute: ExecuteCommand,
        emit_line: LineEmitter,
        restore: RestoreDomain,
    ) -> int | None:
        """
        Apply one family: delta by default, full flush-replace as opt-out.

        Under ``--nft`` the default is an incremental delta against the
        captured ``domain_info.previous`` snapshot, so unchanged chains keep
        their packet/byte counters and unchanged named sets keep their kernel
        state.  ``--full-reload``, a first run / empty snapshot
        (:func:`needs_full_reload`), or a refcount-unsafe diff (any set
        ``remove``/retype -> ``build_nft_delta`` returns ``None``) fall back to
        the legacy ``flush table`` + full rebuild from ``render().save``.
        Inspection (``--lines``/``--shell``) shows exactly the text that will
        be applied.  An empty delta emits nothing and skips ``nft -f`` entirely
        (idempotency).
        """
        del execute  # nft is always save-shaped; no slow commands
        save = rendered.save
        if save is None:
            raise internal_error()
        family = domain.nft_name
        use_delta = not options.full_reload and not needs_full_reload(
            domain_info.previous
        )
        apply_text = save
        full_reload = True
        if use_delta:
            assert domain_info.previous is not None
            delta = build_nft_delta(domain_info.previous, save, family=family)
            if delta is not None:
                # None -> refcount-unsafe; keep apply_text == save (full
                # reload).  "" stays "" -> empty-delta no-op below.
                apply_text = delta
                full_reload = False
        if full_reload and not options.noflush:
            # Whole-table replace, not `flush table`: the latter keeps a
            # removed base chain's declaration (hook + policy) alive.
            # --noflush stays append-only (no flush line to rewrite).
            apply_text = _full_reload_text(save, family)
        if options.lines and apply_text:
            tool = domain_info.tools[TOOL_NFT]
            if options.shell:
                emit_line(f"{tool} -f - <<EOT\n")
            emit_line(apply_text)
            if options.shell:
                emit_line("EOT\n")
        if options.noexec:
            return None
        if not apply_text:
            return None  # empty delta: nothing to apply
        try:
            restore(domain_info, apply_text)
        except FermError as exc:
            print(exc, file=sys.stderr)
            return 1
        return None

    def capture_previous(
        self,
        domain: Family,
        domain_info: DomainInfo,
        options: Options,
        *,
        execute: ExecuteCommand,
        read_save: SaveReader,
        capture: ExecuteCapture,
    ) -> None:
        """
        Snapshot ONLY ferm's own table for rollback.

        Unlike x_tables, nft snapshots a single table via ``capture``
        (``nft list table <family> ferm``), not the whole ``*-save`` dump;
        ``read_save``/``execute`` are unused.  A first run (no ferm table
        yet) leaves ``previous`` ``None``.

        Under ``--test`` the mock path (``--test-mock-previous=fam=path``)
        is opened and read via :meth:`read_previous` -- the same contract
        as the iptables backend.  This makes ``read_previous``
        an active code path in test mode.
        """
        del read_save, execute
        family = domain.nft_name
        if options.test:
            mock = options.mock_previous.get(domain)
            if mock is not None:
                try:
                    handle = Path(mock).open(  # noqa: SIM115
                        encoding=BYTE_ENCODING
                    )
                except OSError as exc:
                    raise FermError(exc.strerror or str(exc)) from exc
                with handle:
                    domain_info.previous = self.read_previous(
                        handle, domain_info
                    )
            return
        snapshot = capture(
            f"{domain_info.tools[TOOL_NFT]} list table {family} "
            f"{NFT_TABLE_NAME}"
        )
        domain_info.previous = snapshot or None

    def rollback(
        self,
        domain: Family,
        domain_info: DomainInfo,
        options: Options,
        *,
        execute: ExecuteCommand,
        restore: RestoreDomain,
    ) -> None:
        """
        Restore ferm's own table, or delete it on a first-run snapshot.

        Skips a family no rule enabled.  With a captured snapshot the table
        is restored verbatim; without one (first run) the table is deleted,
        since there was nothing to restore.
        """
        del options
        if not domain_info.enabled:
            return
        family = domain.nft_name
        if domain_info.previous:
            restore(domain_info, domain_info.previous)
        else:
            execute(
                f"{domain_info.tools[TOOL_NFT]} delete table {family} "
                f"{NFT_TABLE_NAME}"
            )

    def read_previous(
        self, lines: Iterable[str], domain_info: DomainInfo
    ) -> str:
        """
        Return the raw nft snapshot verbatim.

        Invoked both by :meth:`capture_previous` under ``--test``
        (reading from the mock-previous file) and by the general
        ``--test-mock-previous`` path when the test harness opens the
        file directly.  ``domain_info`` is unused (nft needs no parse).
        """
        del domain_info
        return "".join(lines)

    def shell_snapshot(
        self, domain: Family, domain_info: DomainInfo
    ) -> ShellSnapshot | None:
        """
        Build the ``--shell`` anti-lockout snapshot for a family.

        Mirrors the live :meth:`rollback`: dump ferm's own table to a tempfile,
        and on restore delete the freshly-applied table before re-loading the
        dump.  A first run captures an empty file, so the delete alone removes
        ferm's table -- the same "nothing to restore" outcome as the live path.
        ``2>/dev/null`` + ``|| true`` keep a missing table (the first-run dump)
        or an already-gone table (the delete) from aborting the script.
        """
        nft = domain_info.tools[TOOL_NFT]
        family = domain.nft_name
        tmp = f"{domain}_tmp"
        return ShellSnapshot(
            setup=(
                f"{tmp}=$(mktemp ferm.XXXXXXXXXX)\n",
                f"{nft} list table {family} {NFT_TABLE_NAME} "
                f">${tmp} 2>/dev/null || true\n",
            ),
            restore=(
                f"{nft} delete table {family} {NFT_TABLE_NAME} "
                f"2>/dev/null || true\n"
                f"{nft} -f ${tmp}\n"
            ),
        )

    def shell_rollback_notice(self) -> str | None:
        """
        Announce the otherwise-silent ``--shell`` rollback on stderr.

        The per-family :meth:`shell_snapshot` restores swallow their output
        (``2>/dev/null``), so a timed-out admin would be reverted in silence.
        This line (emitted once, after every family's restore) mirrors the live
        path's "Firewall rules rolled back." message.
        """
        return "echo 'ferm: rolled back to the previous firewall rules.' >&2\n"
