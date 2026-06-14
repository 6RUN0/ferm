"""
The native nftables backend (Phase 2).

Translates each :class:`pyferm.rules.RenderedRule` to a small internal
nft-expression model and serializes it (``to_text``) into one atomic
``nft -f`` script over ``table <family> ferm`` only.  See design
``docs/superpowers/specs/2026-06-13-ferm-phase2-nft-backend-design.md``.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pyferm.errors import FermError
from pyferm.rules import (
    RenderedOption,
    RenderedRule,
    is_netfilter_builtin_chain,
)
from pyferm.streams import BYTE_ENCODING
from pyferm.values import Multi, Negated, Params, PreNegated, Value

if TYPE_CHECKING:
    from pyferm.domains import TableInfo

#: nft comment byte limit (design §3); over -> a plain ferm error.
NFT_COMMENT_MAX: int = 128
#: ferm's own table name in every family (design §5).
NFT_TABLE_NAME: str = "ferm"

#: A bare nft token needs no quoting.
_NFT_BARE_RE = re.compile(r"[-_a-zA-Z0-9./:]+\Z")


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

    Example: ``tcp dport 22``.
    """

    expr: str

    def to_text(self) -> str:
        """Return the pre-rendered match expression verbatim."""
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


def nft_quote(text: str) -> str:
    r"""
    Quote a string for an nft double-quoted token (design §4.1).

    nft uses C-style strings: backslash and double-quote are escaped; a
    bare word is returned unquoted.  Used for ``log prefix`` payloads
    where escaping is explicit (no JSON wire).
    """
    if _NFT_BARE_RE.match(text):
        return text
    return _nft_quote_string(text)


def _chain_header(chain: NftBaseChain | NftRegularChain) -> str:
    """Render the ``add chain ...`` body for one chain."""
    if isinstance(chain, NftBaseChain):
        body = (
            f"type {chain.type} hook {chain.hook} "
            f"priority {chain.priority};"
        )
        if chain.policy is not None:
            body += f" policy {chain.policy};"
        return f"{{ {body} }}"
    return ""


def _nft_quote_string(text: str) -> str:
    """
    Wrap *text* in nft double-quotes, escaping backslash and quote.

    Unlike :func:`nft_quote`, this never returns a bare word -- used
    wherever nft syntax mandates a quoted string (``comment``,
    ``log prefix``).
    """
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


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
            lines.append(
                f"add rule {prefix} {chain.name}{sep}{tail}\n"
            )
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
    """
    return chain if table == "filter" else f"{table}_{chain}"


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
        return f"{domain} {_ADDR_KEYWORD[name]} {_op(neg)}{scalar}"
    if name in _IFACE_KEYWORD:
        return f'{_IFACE_KEYWORD[name]} {_op(neg)}"{scalar}"'
    if name in _PORT_KEYWORD:
        if protocol not in _PORT_PROTOCOLS:
            raise FermError(
                f"option '{name}' needs a tcp/udp protocol for the nft backend"
            )
        return f"{protocol} {_PORT_KEYWORD[name]} {_op(neg)}{scalar}"
    if name == "state":
        return f"ct state {_op(neg)}{scalar.lower()}"
    if name == "limit":
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
#: ip6 reject-with spellings (icmpv6).
_REJECT_WITH_IP6: dict[str, str] = {
    "icmp6-port-unreachable": "reject with icmpv6 type port-unreachable",
    "icmp6-no-route": "reject with icmpv6 type no-route",
    "icmp6-adm-prohibited": "reject with icmpv6 type admin-prohibited",
    "icmp6-addr-unreachable": "reject with icmpv6 type addr-unreachable",
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
) -> NftVerdict:
    """
    Build the verdict statement from the ``jump`` marker value (decision 8).

    Dispatches on ``target_value`` (the discriminator, since every target
    arrives as ``name='jump'``): core verdicts, NAT/LOG/REJECT (which take
    a companion option), or a ``jump``/``goto`` to a chain in the SAME
    iptables table (name disambiguated via :func:`nft_chain_name`).
    """
    if target_value in _VERDICT_TARGET:
        return NftVerdict(_VERDICT_TARGET[target_value])
    if target_value == "MASQUERADE":
        comp = companions.get("to-ports")
        if comp is not None:
            return NftVerdict(f"masquerade to :{first_scalar(comp.value)}")
        return NftVerdict("masquerade")
    if target_value == "REDIRECT":
        comp = companions.get("to-ports")
        if comp is not None:
            return NftVerdict(f"redirect to :{first_scalar(comp.value)}")
        return NftVerdict("redirect")
    if target_value == "LOG":
        comp = companions.get("log-prefix")
        if comp is not None:
            scalar, _ = unwrap_value(comp.value)
            return NftVerdict(f"log prefix {nft_quote(scalar)}")
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
        return NftVerdict(f"snat to {first_scalar(comp.value)}")
    if target_value == "DNAT":
        comp = companions.get("to-destination")
        if comp is None:
            raise FermError("DNAT target not yet supported by nft backend")
        return NftVerdict(f"dnat to {first_scalar(comp.value)}")
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
    "reject-with", "to-source", "to-destination", "log-prefix", "to-ports",
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
            break

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
                domain, table, target_name or "jump", target_value, companions
            )
        )
    return NftRule(statements=statements, comment=comment)
