"""
The native nftables backend (Phase 2).

Translates each :class:`pyferm.rules.RenderedRule` to a small internal
nft-expression model and serializes it (``to_text``) into one atomic
``nft -f`` script over ``table <family> ferm`` only.
"""

from __future__ import annotations

import enum
import re
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
from pyferm.modules import PORT_PROTOCOLS
from pyferm.nftset import (
    RANK_ADDRESS,
    RANK_INTERVAL,
    classify,
    l4proto_name,
    sort_set_elements,
    sort_vmap_pairs,
)
from pyferm.plan import build_nft_delta, needs_full_reload
from pyferm.rules import (
    CORE_TARGETS,
    RenderedOption,
    RenderedRule,
    is_netfilter_builtin_chain,
)
from pyferm.scope import OptionKind
from pyferm.streams import BYTE_ENCODING
from pyferm.values import Multi, Negated, Params, PreNegated, SetRef, Value

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
#: Bytes nft cannot represent inside a double-quoted string: a literal
#: quote, a backslash, or any control byte.  nft has no escape for these,
#: so :func:`_nft_quote_string` rejects rather than escapes them.
_NFT_UNQUOTABLE_RE: Final[re.Pattern[str]] = re.compile(r'["\\\x00-\x1f]')
#: An nft ``limit rate`` value: ``N`` or ``N/unit`` (``3/second``).
_NFT_RATE_RE: Final[re.Pattern[str]] = re.compile(r"\A\d+(?:/[A-Za-z]+)?\Z")
#: An nft chain identifier (bare word; nft has no quoted-chain-name form).
_NFT_CHAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[A-Za-z][A-Za-z0-9_]*\Z"
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
        scalar = f"{match.group(1)}-{match.group(2)}"
    if not _NFT_PORT_RE.match(scalar):
        raise FermError(f"invalid port '{scalar}' for nft backend")
    return scalar


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
            joined = ", ".join(sort_set_elements(unique))
            return f"{self.set_key} {{ {joined} }}"
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
) -> dict[str, _SetDecl]:
    """
    Aggregate named-set declarations over one family's rules.

    Keyed by name within this ``render()``: every ferm table merges into one
    ``table <family> ferm``, so a name is family-scoped.  The selector is
    read structurally from :attr:`NftMatch.set_selector` (never reverse-parsed
    out of the rendered text).  A name reused with a differing selector or a
    differing element set is a conflict (error); the same name across several
    chains or tables of one family is one object (dedup).
    """
    decls: dict[str, _SetDecl] = {}
    selectors: dict[str, str] = {}
    for chain_rules in rules.values():
        for rule in chain_rules:
            for stmt in rule.statements:
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
                if name in selectors and selectors[name] != selector:
                    raise FermError(
                        f"named set '{name}' used with conflicting selectors "
                        f"'{selectors[name]}' and '{selector}'"
                    )
                if name in decls and decls[name].elements != elements:
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
    decls: dict[str, _SetDecl],
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
        flags = " flags interval;" if decl.flags_interval else ""
        lines.append(
            f"add set {prefix} {name} {{ type {decl.type_};{flags} }}\n"
        )
        if decl.elements:
            joined = ", ".join(decl.elements)
            lines.append(f"add element {prefix} {name} {{ {joined} }}\n")
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
#: Selectors that may carry an anonymous set (the collapse allow-list).
#: ``ip protocol`` is intentionally absent: the backend emits protocol as
#: ``meta l4proto``, so a separate ``ip protocol`` selector is never produced.
_SET_ELIGIBLE_SELECTORS: Final[frozenset[str]] = frozenset(
    {
        "tcp dport",
        "tcp sport",
        "udp dport",
        "udp sport",
        "udplite dport",
        "udplite sport",
        "dccp dport",
        "dccp sport",
        "sctp dport",
        "sctp sport",
        "ip saddr",
        "ip daddr",
        "ip6 saddr",
        "ip6 daddr",
        "meta l4proto",
        "iifname",
        "oifname",
    }
)


def _op(neg: bool) -> str:
    """Return the nft inequality prefix for a (possibly) negated match."""
    return "!= " if neg else ""


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
    scalar, neg = unwrap_value(option.value)
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
    if name == "state":
        members = scalar.lower().split(",")
        for member in members:
            if member not in _CT_STATES:
                raise FermError(f"unknown ct state '{member}' for nft backend")
        return (f"ct state {_op(neg)}{','.join(members)}", None, None)
    if name == "limit":
        if not _NFT_RATE_RE.match(scalar):
            raise FermError(f"invalid rate '{scalar}' for nft backend")
        return (f"limit rate {scalar}", None, None)
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


# ---------------------------------------------------------------------------
# build_verdict
# ---------------------------------------------------------------------------

#: target VALUE -> nft verdict; QUEUE is core, REJECT is not.  Derived from
#: :data:`CORE_TARGETS` so the two cannot drift; every core target lower-cases
#: to its nft spelling (ACCEPT->accept, ...), preserving insertion order.
_VERDICT_TARGET: Final[dict[str, str]] = {
    target: target.lower() for target in CORE_TARGETS
}
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
    required first (nft would reject the applied script).
    """
    comp = companions.get("to-ports")
    if comp is not None:
        if not has_transport:
            raise FermError(_NAT_PORT_NEEDS_PROTO)
        port = _validate_port(first_scalar(comp.value))
        return NftVerdict(f"{verb} to :{port}")
    return NftVerdict(verb)


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
    return NftVerdict(f"{verb} to {addr}")


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
        comp = companions.get("log-prefix")
        if comp is not None:
            scalar, _ = unwrap_value(comp.value)
            return NftVerdict(f"log prefix {_nft_quote_string(scalar)}")
        return NftVerdict("log")
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
    "to-ports",
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
        isinstance(o.value, SetRef) and not o.value.elements
        for o in rule.options
    )


def translate_rule(domain: Family, table: str, rule: RenderedRule) -> NftRule:
    """
    Translate one RenderedRule to an NftRule (two-pass).

    Pass intent: ``match_module`` markers are dropped (``-m`` is implicit
    in nft); ``comment`` becomes the rule comment; the ``protocol`` option
    sets the port context and emits ``meta l4proto`` ONLY when no port
    match subsumes it; ``kind == 'target'`` records the verdict discriminator
    and companion options feed it.  Match statements keep their source order
    (nft is order-sensitive); the verdict is appended last.
    """
    if _references_empty_named_set(rule):
        raise internal_error(
            "a rule over a family-filtered empty named set reached "
            "translate_rule; the caller must drop it first"
        )
    # First pass: resolve rule-wide context (the l4 protocol and whether a
    # port match exists) so a port option that textually precedes the
    # `protocol` option still translates correctly (order-independent).
    has_port = any(o.name in _PORT_KEYWORD for o in rule.options)
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
    setref_count = sum(isinstance(o.value, SetRef) for o in rule.options)
    if setref_count > 1:
        raise FermError("at most one named set per rule in this version")

    # Second pass: emit matches in source order; verdict appended last.
    matches: list[NftStatement] = []
    comment: str | None = None
    target_name: str | None = None
    target_value: str | None = None
    companions: dict[str, RenderedOption] = {}

    for option in rule.options:
        name, kind = option.name, option.kind
        if kind is OptionKind.MATCH_MODULE:
            continue  # -m marker is implicit in nft
        if name == "comment":
            comment, _ = unwrap_value(option.value)
            continue
        if kind is OptionKind.PROTO:
            scalar, neg = unwrap_value(option.value)
            scalar = _validate_protocol(scalar)
            if not has_port:  # a port match already implies l4proto
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
        if name in _TARGET_COMPANIONS:
            companions[name] = option
            continue
        if isinstance(option.value, SetRef):
            setref = option.value
            key = _setref_selector(domain, name, protocol)
            expr = f"{key} @{_validate_set_name(setref.name)}"
            matches.append(
                NftMatch(expr, set_key=None, setref=setref, set_selector=key)
            )
            continue
        expr, set_key, element = _translate_match_parts(
            domain, option, protocol
        )
        matches.append(NftMatch(expr, set_key=set_key, element=element))

    statements: list[NftStatement] = list(matches)
    if target_value is not None:
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
                rules[nft_name] = _collapse_chain_rules(
                    [
                        translate_rule(domain, tbl, rule)
                        for rule in table_info.chains[original].rules
                        if not _references_empty_named_set(rule)
                    ]
                )
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
