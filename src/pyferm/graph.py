# src/pyferm/graph.py
"""
The eval-free chain control-flow graph behind ``ferm --graph`` (port-only).

Parses one config with Parser.parse_to_block, walks the structural tree
carrying (domains, tables, chains) context, accumulates nodes/edges per
(domain, table) cluster, classifies nodes at freeze, and renders d2/DOT.
No eval, kernel, resolver, or previous-ruleset I/O (see spec §1).
"""

# The builder reuses the parser's own recognition constants (_CORE_TARGETS)
# by design, so pyright's private-usage rule is off here (mirrors walker.py).
# pyright: reportPrivateUsage=false
from __future__ import annotations

import enum
import re
from dataclasses import dataclass

from ._treescan import _CHAIN_VALUE_BOUNDARY, _str_tokens, _unquote
from .rules import _CORE_TARGETS

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ID_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)


class EdgeKind(enum.StrEnum):
    """Edge label; the value IS the rendered label. VERDICT = no label."""

    JUMP = "jump"
    GOTO = "goto"
    SUBCHAIN = "subchain"
    POLICY = "policy"
    VERDICT = ""


class NodeKind(enum.StrEnum):
    """Node role; drives the renderer's shape/style. USER is the default."""

    BUILTIN = "builtin"
    USER = "user"
    UNDEFINED = "undefined"
    VERDICT = "verdict"


@dataclass(frozen=True)
class Cluster:
    """One (domain, table) subgraph; nodes and edges are pre-sorted."""

    domain: str
    table: str
    nodes: tuple[tuple[str, NodeKind], ...]
    edges: tuple[tuple[str, str, EdgeKind], ...]


@dataclass(frozen=True)
class ChainGraph:
    """The whole graph; clusters sorted by (domain, table)."""

    clusters: tuple[Cluster, ...]


def _san(part: str) -> str:
    """Escape one id part injectively: unsafe byte -> _XX, '_' -> _5f."""
    return "".join(ch if ch in _ID_SAFE else f"_{ord(ch):02x}" for ch in part)


def _cluster_id(domain: str, table: str) -> str:
    """Injective id: '__' delimiter never appears inside _san output."""
    return f"{_san(domain)}__{_san(table)}"


def _escape_ident(name: str) -> str:
    r"""Escape a name for a DOT/d2 quoted string: '\' then '"' then C0/C1."""
    name = name.replace("\\", "\\\\").replace('"', '\\"')
    return _CONTROL_CHARS_RE.sub(lambda m: f"\\x{ord(m.group()):02x}", name)


def _header_value(toks: list[str], i: int) -> tuple[tuple[str, ...], int]:
    """
    Collect literal value(s) after a header keyword at toks[i].

    Handles a bare single value and a ``(A B ...)`` array; $-names are
    dropped (non-literal, eval-free contract). Returns (values, next_index).
    """
    values: list[str] = []
    if i < len(toks) and toks[i] == "(":
        i += 1
        while i < len(toks) and toks[i] != ")":
            name = toks[i]
            i += 1
            if not name.startswith("$"):
                values.append(_unquote(name))
        if i < len(toks) and toks[i] == ")":
            i += 1
    elif i < len(toks) and toks[i] not in _CHAIN_VALUE_BOUNDARY:
        name = toks[i]
        i += 1
        if not name.startswith("$"):
            values.append(_unquote(name))
    return tuple(values), i


def _header_context(
    span: object,
) -> tuple[
    tuple[str, ...] | None,
    tuple[str, ...] | None,
    tuple[str, ...] | None,
    str | None,
]:
    """
    Extract header-context updates and the policy target.

    Returns (new_domains, new_tables, new_chains, policy_target). Reads
    every embedded ``domain``/``table``/``chain`` value and the policy
    tail from one HeaderNode's ``(keyword, *value_span)``. A ``policy`` token
    yields a target only when it is a header keyword (not preceded by ``mod``,
    which introduces the policy *match module*) and the next token is a core
    target (the oracle rejects any other policy, ferm:2647-2648). Non-literal
    ``$var`` values are skipped (no phantom cluster). ``None`` fields keep the
    inherited context.
    """
    toks = list(_str_tokens(span))  # type: ignore[arg-type]
    new_domains: tuple[str, ...] | None = None
    new_tables: tuple[str, ...] | None = None
    new_chains: tuple[str, ...] | None = None
    policy_target: str | None = None
    prev: str | None = None
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in ("domain", "table", "chain"):
            values, j = _header_value(toks, i + 1)
            if values:  # empty means the value was a skipped $var
                if tok == "domain":
                    new_domains = values
                elif tok == "table":
                    new_tables = values
                else:
                    new_chains = values
            prev, i = tok, j
            continue
        if tok == "policy" and prev != "mod":
            nxt = toks[i + 1] if i + 1 < len(toks) else None
            if nxt in _CORE_TARGETS:
                policy_target = nxt
            prev, i = tok, i + 2
            continue
        prev, i = tok, i + 1
    return new_domains, new_tables, new_chains, policy_target
