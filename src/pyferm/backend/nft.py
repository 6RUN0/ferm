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

from pyferm.errors import FermError
from pyferm.streams import BYTE_ENCODING
from pyferm.rules import is_netfilter_builtin_chain
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
    """Map ``(table, built-in chain)`` to ``(nft type, hook, priority)``.

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
