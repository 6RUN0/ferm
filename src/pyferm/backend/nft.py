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

#: nft comment byte limit (design §3); over -> a plain ferm error.
NFT_COMMENT_MAX: int = 128
#: ferm's own table name in every family (design §5).
NFT_TABLE_NAME: str = "ferm"

#: A bare nft token needs no quoting.
_NFT_BARE_RE = re.compile(r"[-_a-zA-Z0-9./:]+$")


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
    """One nft statement (match / verdict / stateful).

    Serialization dispatches on the subclass via :meth:`to_text` rather
    than a string tag, mirroring the dataclass dispatch ``base.py`` uses
    for ``Rendered`` (design §4.1).
    """

    @abstractmethod
    def to_text(self) -> str:
        """Render this statement as one nft expression fragment."""


@dataclass
class NftMatch(NftStatement):
    """A match expression already rendered to nft text (e.g. ``tcp dport 22``)."""

    expr: str

    def to_text(self) -> str:
        return self.expr


@dataclass
class NftVerdict(NftStatement):
    """A verdict/target statement (``accept``/``drop``/``jump X``/``snat to ...``)."""

    expr: str

    def to_text(self) -> str:
        return self.expr


@dataclass
class NftRule:
    """One rule: ordered statements plus an optional comment."""

    statements: list[NftStatement]
    comment: str | None = None


def nft_quote(text: str) -> str:
    r"""Quote a string for an nft double-quoted token (design §4.1).

    nft uses C-style strings: backslash and double-quote are escaped; a
    bare word is returned unquoted.  Used for ``log prefix`` and
    ``comment`` payloads, where escaping is now explicit (no JSON wire).
    """
    if _NFT_BARE_RE.match(text):
        return text
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


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
    """Always wrap *text* in nft double-quotes, escaping backslash and quote.

    Unlike :func:`nft_quote`, this never returns a bare word -- used
    wherever nft syntax mandates a quoted string (``comment``,
    ``log prefix``).
    """
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_comment(comment: str) -> str:
    """Render a validated ``comment "<text>"`` suffix (design §3).

    Over :data:`NFT_COMMENT_MAX` bytes -> a ferm error, never truncation.
    """
    if len(comment.encode("latin-1")) > NFT_COMMENT_MAX:
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
    """Serialize one family's table as an atomic ``nft -f`` script (design §7).

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
