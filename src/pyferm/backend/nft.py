"""
The native nftables backend (Phase 2).

Translates each :class:`pyferm.rules.RenderedRule` to a small internal
nft-expression model and serializes it (``to_text``) into one atomic
``nft -f`` script over ``table <family> ferm`` only.  See design
``docs/superpowers/specs/2026-06-13-ferm-phase2-nft-backend-design.md``.
"""

from __future__ import annotations

import re
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from pyferm.backend.base import (
    Backend,
    ExecuteCapture,
    ExecuteCommand,
    LineEmitter,
    Rendered,
    RestoreDomain,
    SaveReader,
)
from pyferm.domains import ShellSnapshot
from pyferm.errors import FermError, internal_error
from pyferm.nftset import sort_set_elements
from pyferm.rules import (
    RenderedOption,
    RenderedRule,
    is_netfilter_builtin_chain,
)
from pyferm.streams import BYTE_ENCODING
from pyferm.values import Multi, Negated, Params, PreNegated, Value

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pyferm.config import Options
    from pyferm.domains import DomainInfo, TableInfo

#: nft comment byte limit (design §3); over -> a plain ferm error.
NFT_COMMENT_MAX: int = 128
#: ferm's own table name in every family (design §5).
NFT_TABLE_NAME: str = "ferm"
#: ``DomainInfo.tools`` key for the single nft binary (decision 2).
TOOL_NFT: str = "nft"

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
_NFT_ADDR_RE = re.compile(r"\A[0-9A-Fa-f.:/-]+\Z")
#: An nft port operand: a numeric/service port or ``lo-hi`` range.  Service
#: names (``ssh``) are accepted (nft resolves them); metacharacters are not.
_NFT_PORT_RE = re.compile(r"\A[0-9A-Za-z][0-9A-Za-z-]*\Z")
#: ferm/iptables write a closed port range as ``lo:hi``; nft's grammar uses
#: ``lo-hi``, so a colon range is normalized to the dash form.  Both ends
#: must be present -- half-open ``:hi`` / ``lo:`` has no nft spelling here
#: and is rejected (fail-closed) rather than mistranslated (review
#: 2026-06-14).
_NFT_PORT_COLON_RANGE_RE = re.compile(r"\A([0-9A-Za-z]+):([0-9A-Za-z]+)\Z")
#: Bytes nft cannot represent inside a double-quoted string: a literal
#: quote, a backslash, or any control byte.  nft has no escape for these,
#: so :func:`_nft_quote_string` rejects rather than escapes them.
_NFT_UNQUOTABLE_RE = re.compile(r'["\\\x00-\x1f]')
#: An nft ``limit rate`` value: ``N`` or ``N/unit`` (``3/second``).
_NFT_RATE_RE = re.compile(r"\A\d+(?:/[A-Za-z]+)?\Z")
#: An nft chain identifier (bare word; nft has no quoted-chain-name form).
_NFT_CHAIN_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]*\Z")
#: ct state keywords nft accepts for ``ct state`` (the ferm ``state`` module
#: maps to iptables ``--state``, whose vocabulary is this set).
_CT_STATES: frozenset[str] = frozenset(
    {"new", "established", "related", "invalid", "untracked"}
)


def _validate_address(scalar: str) -> str:
    """Return *scalar* if it is a safe nft address operand, else error."""
    if not _NFT_ADDR_RE.match(scalar):
        raise FermError(f"invalid address '{scalar}' for nft backend")
    return scalar


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
    """One nft table: ``table <family> <name>`` (design §5)."""

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
    for ``Rendered`` (design §4.1).
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

    def to_text(self) -> str:
        """Render the match, as an anonymous set once a run is collapsed."""
        if self.elements is not None:
            # A collapsed run always carries set_key (the merge pass
            # copies it from the anchor); fail loud rather than emit
            # a literal "None {...}".
            assert self.set_key is not None
            joined = ", ".join(sort_set_elements(self.elements))
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


def render_comment(comment: str) -> str:
    """
    Render a validated ``comment "<text>"`` suffix (design §3).

    Over :data:`NFT_COMMENT_MAX` bytes -> a ferm error, never truncation.
    """
    if len(comment.encode(BYTE_ENCODING)) > NFT_COMMENT_MAX:
        raise FermError(
            f"comment exceeds nft limit of {NFT_COMMENT_MAX} bytes"
        )
    return f"comment {_nft_quote_string(comment)}"


def serialize_table(
    table: NftTable,
    chains: list[NftBaseChain | NftRegularChain],
    rules: dict[str, list[NftRule]],
    *,
    noflush: bool,
) -> str:
    """
    Serialize one family's table as an atomic ``nft -f`` script (design §7).

    Emits ``add table`` (idempotent), then ``flush table`` unless
    ``noflush`` (the ``--noflush`` decision lives HERE, not in the
    applier -- design §7), then every chain, then every rule.  ``chains``
    is pre-sorted by the caller for deterministic golden output.
    """
    prefix = f"{table.family} {table.name}"
    lines = [f"add table {prefix}\n"]
    if not noflush:
        lines.append(f"flush table {prefix}\n")
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


# ---------------------------------------------------------------------------
# Task 5: ferm ontology -> nft family / base-chain mapping (design §5)
# ---------------------------------------------------------------------------

#: ferm family -> nft family, 1:1 (design §5).
_NFT_FAMILY: dict[str, str] = {
    "ip": "ip",
    "ip6": "ip6",
    "arp": "arp",
    "eb": "bridge",
}

#: (table, chain) -> (nft type, hook, priority).  Numeric priorities for
#: cross-version portability (design §5).
_BASE_CHAIN_MAP: dict[tuple[str, str], tuple[str, str, int]] = {
    ("filter", "INPUT"): ("filter", "input", 0),
    ("filter", "FORWARD"): ("filter", "forward", 0),
    ("filter", "OUTPUT"): ("filter", "output", 0),
    ("nat", "PREROUTING"): ("nat", "prerouting", -100),
    ("nat", "INPUT"): ("nat", "input", 100),
    ("nat", "OUTPUT"): ("nat", "output", -100),
    ("nat", "POSTROUTING"): ("nat", "postrouting", 100),
    ("mangle", "PREROUTING"): ("filter", "prerouting", -150),
    ("mangle", "INPUT"): ("filter", "input", -150),
    ("mangle", "FORWARD"): ("filter", "forward", -150),
    ("mangle", "OUTPUT"): ("route", "output", -150),
    ("mangle", "POSTROUTING"): ("filter", "postrouting", -150),
    ("raw", "PREROUTING"): ("filter", "prerouting", -300),
    ("raw", "OUTPUT"): ("filter", "output", -300),
}

#: arp supports only filter/INPUT and filter/OUTPUT (design §5).
_ARP_BASE_CHAIN_MAP: dict[tuple[str, str], tuple[str, str, int]] = {
    ("filter", "INPUT"): ("filter", "input", 0),
    ("filter", "OUTPUT"): ("filter", "output", 0),
}


def nft_family(domain: str) -> str:
    """Map a ferm family to its nft family name (design §5)."""
    family = _NFT_FAMILY.get(domain)
    if family is None:
        raise FermError(f"domain '{domain}' not yet supported by nft backend")
    return family


def map_base_chain(
    domain: str,
    table: str,
    chain: str,
) -> tuple[str, str, int]:
    """
    Map ``(table, built-in chain)`` to ``(nft type, hook, priority)``.

    A miss (broute/BROUTING, arp nat/mangle, unknown pair) raises
    :class:`~pyferm.errors.FermError` -- "built-in" does not imply
    "mappable" (design §5).
    """
    table_map = _ARP_BASE_CHAIN_MAP if domain == "arp" else _BASE_CHAIN_MAP
    spec = table_map.get((table, chain))
    if spec is None:
        raise FermError(
            f"chain '{table}/{chain}' not yet supported by nft backend"
        )
    return spec


# ---------------------------------------------------------------------------
# Task 6: chain-name disambiguation + chain-list builder (design §5)
# ---------------------------------------------------------------------------


def nft_chain_name(table: str, chain: str) -> str:
    """
    Disambiguate a chain name inside the merged ``ferm`` table (decision 9).

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
    domain: str,
    table: str,
    table_info: TableInfo,
) -> list[NftBaseChain | NftRegularChain]:
    """
    Build the sorted chain list for one table (design §5).

    :func:`is_netfilter_builtin_chain` selects the base-vs-user branch;
    :func:`map_base_chain` resolves the concrete hook (and errors on
    unmappable built-ins).  Policy is lowercased to nft spelling
    (``DROP`` -> ``drop``).  Names are disambiguated via
    :func:`nft_chain_name` (decision 9).  Output is sorted for
    deterministic golden output.
    """
    chains: list[NftBaseChain | NftRegularChain] = []
    for name in sorted(table_info.chains):
        chain_info = table_info.chains[name]
        nft_name = nft_chain_name(table, name)
        if is_netfilter_builtin_chain(table, name):
            chain_type, hook, priority = map_base_chain(domain, table, name)
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
            chains.append(NftRegularChain(nft_name))
    return chains


# ---------------------------------------------------------------------------
# Task 7: value unwrapping helpers (decision 8)
# ---------------------------------------------------------------------------


def unwrap_value(value: Value) -> tuple[str, bool]:
    """
    Return ``(scalar, negated)`` for a simple match value (decision 8).

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
    Extract the first scalar from a NAT-style value (decision 8).

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
# Task 8: translate_match (decision 8)
# ---------------------------------------------------------------------------

#: canonical option name -> nft address keyword (decision 8).
_ADDR_KEYWORD: dict[str, str] = {"source": "saddr", "destination": "daddr"}
#: canonical option name -> nft interface keyword.
_IFACE_KEYWORD: dict[str, str] = {
    "in-interface": "iifname",
    "out-interface": "oifname",
}
#: port option names; the nft keyword equals the ferm name.
_PORT_KEYWORD: dict[str, str] = {"sport": "sport", "dport": "dport"}
#: protocols that admit a port match (mirrors PORT_PROTOCOLS, modules.py).
_PORT_PROTOCOLS: tuple[str, ...] = ("tcp", "udp", "udplite", "dccp", "sctp")


def _op(neg: bool) -> str:
    """Return the nft inequality prefix for a (possibly) negated match."""
    return "!= " if neg else ""


def translate_match(
    domain: str, option: RenderedOption, protocol: str | None
) -> str:
    """
    Translate one match option to an nft expression (decision 8).

    Keyed on the CANONICAL ``RenderedOption.name`` (``source``/
    ``in-interface``/...), not the ferm alias.  ``protocol`` is the rule's
    realized l4 protocol (from the preceding ``protocol`` option), needed
    because a port match carries ``module=None``.  An uncovered match -> a
    plain ferm error (design §3).
    """
    name = option.name
    scalar, neg = unwrap_value(option.value)
    if name in _ADDR_KEYWORD:
        addr = _validate_address(scalar)
        return f"{domain} {_ADDR_KEYWORD[name]} {_op(neg)}{addr}"
    if name in _IFACE_KEYWORD:
        # An interface is an nft quoted string (it may carry a `*` wildcard,
        # preserved inside the quotes), so escape rather than validate.
        return f"{_IFACE_KEYWORD[name]} {_op(neg)}{_nft_quote_string(scalar)}"
    if name in _PORT_KEYWORD:
        if protocol not in _PORT_PROTOCOLS:
            raise FermError(
                f"option '{name}' needs a tcp/udp protocol for the nft backend"
            )
        port = _validate_port(scalar)
        return f"{protocol} {_PORT_KEYWORD[name]} {_op(neg)}{port}"
    if name == "state":
        members = scalar.lower().split(",")
        for member in members:
            if member not in _CT_STATES:
                raise FermError(f"unknown ct state '{member}' for nft backend")
        return f"ct state {_op(neg)}{','.join(members)}"
    if name == "limit":
        if not _NFT_RATE_RE.match(scalar):
            raise FermError(f"invalid rate '{scalar}' for nft backend")
        return f"limit rate {scalar}"
    raise FermError(f"option '{name}' not yet supported by nft backend")


# ---------------------------------------------------------------------------
# Task 9: build_verdict (decision 8)
# ---------------------------------------------------------------------------

#: target VALUE -> nft verdict (decision 8); QUEUE is core, REJECT is not.
_VERDICT_TARGET: dict[str, str] = {
    "ACCEPT": "accept",
    "DROP": "drop",
    "RETURN": "return",
    "QUEUE": "queue",
}
#: iptables reject-with name -> nft reject spec, ip family.
_REJECT_WITH: dict[str, str] = {
    "icmp-port-unreachable": "reject with icmp type port-unreachable",
    "icmp-net-unreachable": "reject with icmp type net-unreachable",
    "icmp-host-unreachable": "reject with icmp type host-unreachable",
    "icmp-admin-prohibited": "reject with icmp type admin-prohibited",
    "tcp-reset": "reject with tcp reset",
}
#: ip6 reject-with spellings (icmpv6, plus the family-agnostic tcp reset).
_REJECT_WITH_IP6: dict[str, str] = {
    "icmp6-port-unreachable": "reject with icmpv6 type port-unreachable",
    "icmp6-no-route": "reject with icmpv6 type no-route",
    "icmp6-adm-prohibited": "reject with icmpv6 type admin-prohibited",
    "icmp6-addr-unreachable": "reject with icmpv6 type addr-unreachable",
    "tcp-reset": "reject with tcp reset",
}
#: ip4 reject-with names the oracle remaps to icmp6 under ip6
#: (``iptables.py:82-89``); a user may write the ip4 spelling in an ip6
#: domain, so normalize before the ip6 lookup or a valid config would
#: falsely raise "not yet supported".
_ICMP6_REJECT_ALIAS: dict[str, str] = {
    "icmp-net-unreachable": "icmp6-no-route",
    "icmp-host-unreachable": "icmp6-addr-unreachable",
    "icmp-port-unreachable": "icmp6-port-unreachable",
    "icmp-net-prohibited": "icmp6-adm-prohibited",
    "icmp-host-prohibited": "icmp6-adm-prohibited",
    "icmp-admin-prohibited": "icmp6-adm-prohibited",
}


#: The error a port-bearing NAT verdict raises without a transport match
#: (decision C1): nft would reject the applied script, so fail at translate.
_NAT_PORT_NEEDS_PROTO = (
    "NAT to a port needs a tcp/udp protocol match for the nft backend"
)


def _nat_has_port(domain: str, operand: str) -> bool:
    """
    Return whether a NAT address operand carries a ``:port`` (decision C1).

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


def _reject_for(domain: str, scalar: str) -> str:
    if domain == "ip6":
        scalar = _ICMP6_REJECT_ALIAS.get(scalar, scalar)
        spec = _REJECT_WITH_IP6.get(scalar)
    else:
        spec = _REJECT_WITH.get(scalar)
    if spec is None:
        raise FermError(
            f"reject-with '{scalar}' not yet supported by nft backend"
        )
    return spec


def build_verdict(
    domain: str,
    table: str,
    target_name: str,
    target_value: str,
    companions: dict[str, RenderedOption],
    *,
    has_transport: bool = False,
) -> NftVerdict:
    """
    Build the verdict statement from the ``jump`` marker value (decision 8).

    Dispatches on ``target_value`` (the discriminator, since every target
    arrives as ``name='jump'``): core verdicts, NAT/LOG/REJECT (which take
    a companion option), or a ``jump``/``goto`` to a chain in the SAME
    iptables table (name disambiguated via :func:`nft_chain_name`).

    ``has_transport`` reports whether the rule established an L4 protocol
    (port match or ``meta l4proto tcp/udp``); a port-bearing NAT mapping
    without one is rejected at translate time (decision C1), since nft would
    otherwise reject the applied script and force a rollback.
    """
    if target_value in _VERDICT_TARGET:
        return NftVerdict(_VERDICT_TARGET[target_value])
    if target_value == "MASQUERADE":
        comp = companions.get("to-ports")
        if comp is not None:
            if not has_transport:
                raise FermError(_NAT_PORT_NEEDS_PROTO)
            port = _validate_port(first_scalar(comp.value))
            return NftVerdict(f"masquerade to :{port}")
        return NftVerdict("masquerade")
    if target_value == "REDIRECT":
        comp = companions.get("to-ports")
        if comp is not None:
            if not has_transport:
                raise FermError(_NAT_PORT_NEEDS_PROTO)
            port = _validate_port(first_scalar(comp.value))
            return NftVerdict(f"redirect to :{port}")
        return NftVerdict("redirect")
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
        comp = companions.get("to-source")
        if comp is None:
            raise FermError("SNAT target not yet supported by nft backend")
        addr = _validate_address(first_scalar(comp.value))
        if _nat_has_port(domain, addr) and not has_transport:
            raise FermError(_NAT_PORT_NEEDS_PROTO)
        return NftVerdict(f"snat to {addr}")
    if target_value == "DNAT":
        comp = companions.get("to-destination")
        if comp is None:
            raise FermError("DNAT target not yet supported by nft backend")
        addr = _validate_address(first_scalar(comp.value))
        if _nat_has_port(domain, addr) and not has_transport:
            raise FermError(_NAT_PORT_NEEDS_PROTO)
        return NftVerdict(f"dnat to {addr}")
    # A jump/goto to a chain in the same iptables table.  nft forbids
    # jumping to a base chain (one with a hook), so a jump/goto whose
    # target is a built-in chain has NO nft equivalent -> a plain ferm
    # error (design §3/§5 ontology gap), NOT a silently-broken script.
    if is_netfilter_builtin_chain(table, target_value):
        raise FermError(
            f"jump/goto to built-in chain '{target_value}' not yet "
            f"supported by nft backend"
        )
    return NftVerdict(f"{target_name} {nft_chain_name(table, target_value)}")


# ---------------------------------------------------------------------------
# Task 10: translate_rule — two-pass rule assembly (decision 8)
# ---------------------------------------------------------------------------

#: option names that are companion arguments of a target, consumed by
#: :func:`build_verdict` rather than emitted as matches (decision 8).
_TARGET_COMPANIONS: tuple[str, ...] = (
    "reject-with",
    "to-source",
    "to-destination",
    "log-prefix",
    "to-ports",
)


def _nft_l4proto(domain: str, proto: str) -> str:
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
    return proto


def translate_rule(domain: str, table: str, rule: RenderedRule) -> NftRule:
    """
    Translate one RenderedRule to an NftRule (decision 8, two-pass).

    Pass intent: ``match_module`` markers are dropped (``-m`` is implicit
    in nft); ``comment`` becomes the rule comment; the ``protocol`` option
    sets the port context and emits ``meta l4proto`` ONLY when no port
    match subsumes it; ``kind == 'target'`` records the verdict discriminator
    and companion options feed it.  Match statements keep their source order
    (nft is order-sensitive); the verdict is appended last.
    """
    # First pass: resolve rule-wide context (the l4 protocol and whether a
    # port match exists) so a port option that textually precedes the
    # `protocol` option still translates correctly (order-independent).
    has_port = any(o.name in _PORT_KEYWORD for o in rule.options)
    protocol: str | None = None
    for option in rule.options:
        if option.kind == "proto":
            protocol, _ = unwrap_value(option.value)
            protocol = _validate_protocol(protocol)
            break
    # nft's `... to <addr>:<port>` NAT mapping is "only valid after transport
    # protocol match" -- a port match or a `meta l4proto tcp/udp` covers it,
    # both implied by the rule carrying a port-bearing protocol (decision C1).
    has_transport = protocol in _PORT_PROTOCOLS

    # Second pass: emit matches in source order; verdict appended last.
    matches: list[NftStatement] = []
    comment: str | None = None
    target_name: str | None = None
    target_value: str | None = None
    companions: dict[str, RenderedOption] = {}

    for option in rule.options:
        name, kind = option.name, option.kind
        if kind == "match_module":
            continue  # -m marker is implicit in nft
        if name == "comment":
            comment, _ = unwrap_value(option.value)
            continue
        if kind == "proto":
            scalar, neg = unwrap_value(option.value)
            scalar = _validate_protocol(scalar)
            if not has_port:  # a port match already implies l4proto
                l4 = _nft_l4proto(domain, scalar)
                matches.append(NftMatch(f"meta l4proto {_op(neg)}{l4}"))
            continue
        if kind == "target":
            target_value, _ = unwrap_value(option.value)
            target_name = name
            continue
        if name in _TARGET_COMPANIONS:
            companions[name] = option
            continue
        matches.append(NftMatch(translate_match(domain, option, protocol)))

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


class NftBackend(Backend):
    """The native nftables backend (Phase 2, all families via ``nft -f``)."""

    def tool_names(self, domain: str) -> dict[str, str]:
        """Return the single family-independent ``nft`` binary (decision 2)."""
        nft_family(domain)  # validates the family early
        return {"nft": "nft"}

    def render(
        self, domain: str, domain_info: DomainInfo, options: Options
    ) -> Rendered:
        """
        Build the atomic ``nft -f`` script for one family (design §7).

        nft is always save-shaped: no slow/eb command fallback, so
        ``Rendered.commands`` stays empty.  All ferm tables merge into ONE
        ``table <family> ferm`` (design §5); chain names disambiguated via
        :func:`nft_chain_name` (decision 9) applied identically here and to
        jump/goto targets in :func:`build_verdict`.  ``@preserve`` is a
        plain error (design §8); a residual nft-name collision is a ferm
        error, NOT silent rule loss.
        """
        table = NftTable(family=nft_family(domain), name=NFT_TABLE_NAME)
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
                        f"nft chain name collision '{nft_name}' in table ferm"
                    )
                rules[nft_name] = [
                    translate_rule(domain, tbl, rule)
                    for rule in table_info.chains[original].rules
                ]
        save = serialize_table(table, chains, rules, noflush=options.noflush)
        return Rendered(save=save)

    def commit(
        self,
        domain: str,
        domain_info: DomainInfo,
        rendered: Rendered,
        options: Options,
        *,
        execute: ExecuteCommand,
        emit_line: LineEmitter,
        restore: RestoreDomain,
    ) -> int | None:
        """
        Emit the save under --lines and pipe it to ``nft -f -`` (design §7).

        nft is always save-shaped, so the slow ``execute`` seam is unused.
        Under ``--shell`` the save is wrapped in a ``<<EOT`` heredoc; under
        ``--noexec`` nothing is applied.  A :class:`FermError` from the
        applier maps to a non-zero status, as the iptables backend does.
        """
        del domain, execute  # nft is always save-shaped; no slow commands
        save = rendered.save
        if save is None:
            raise internal_error()
        if options.lines:
            tool = domain_info.tools[TOOL_NFT]
            if options.shell:
                emit_line(f"{tool} -f - <<EOT\n")
            emit_line(save)
            if options.shell:
                emit_line("EOT\n")
        if options.noexec:
            return None
        try:
            restore(domain_info, save)
        except FermError as exc:
            print(exc, file=sys.stderr)
            return 1
        return None

    def capture_previous(
        self,
        domain: str,
        domain_info: DomainInfo,
        options: Options,
        *,
        execute: ExecuteCommand,
        read_save: SaveReader,
        capture: ExecuteCapture,
    ) -> None:
        """
        Snapshot ONLY ferm's own table for rollback (design §6/§7).

        Unlike x_tables, nft snapshots a single table via ``capture``
        (``nft list table <family> ferm``), not the whole ``*-save`` dump;
        ``read_save``/``execute`` are unused.  A first run (no ferm table
        yet) leaves ``previous`` ``None``.

        Under ``--test`` the mock path (``--test-mock-previous=fam=path``)
        is opened and read via :meth:`read_previous` -- the same contract
        as the iptables backend (design §7).  This makes ``read_previous``
        an active code path in test mode.
        """
        del read_save, execute
        family = nft_family(domain)
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
            f"{domain_info.tools[TOOL_NFT]} list table {family} ferm"
        )
        domain_info.previous = snapshot or None

    def rollback(
        self,
        domain: str,
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
        family = nft_family(domain)
        if domain_info.previous:
            restore(domain_info, domain_info.previous)
        else:
            execute(
                f"{domain_info.tools[TOOL_NFT]} delete table {family} ferm"
            )

    def read_previous(
        self, lines: Iterable[str], domain_info: DomainInfo
    ) -> str:
        """
        Return the raw nft snapshot verbatim (design §7).

        Invoked both by :meth:`capture_previous` under ``--test``
        (reading from the mock-previous file) and by the general
        ``--test-mock-previous`` path when the test harness opens the
        file directly.  ``domain_info`` is unused (nft needs no parse).
        """
        del domain_info
        return "".join(lines)

    def shell_snapshot(
        self, domain: str, domain_info: DomainInfo
    ) -> ShellSnapshot | None:
        """
        Build the ``--shell`` anti-lockout snapshot for a family (finding C2).

        Mirrors the live :meth:`rollback`: dump ferm's own table to a tempfile,
        and on restore delete the freshly-applied table before re-loading the
        dump.  A first run captures an empty file, so the delete alone removes
        ferm's table -- the same "nothing to restore" outcome as the live path.
        ``2>/dev/null`` + ``|| true`` keep a missing table (the first-run dump)
        or an already-gone table (the delete) from aborting the script.
        """
        nft = domain_info.tools[TOOL_NFT]
        family = nft_family(domain)
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
