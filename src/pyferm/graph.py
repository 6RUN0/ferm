# src/pyferm/graph.py
"""
The eval-free chain control-flow graph behind ``ferm --graph`` (port-only).

Parses one config with Parser.parse_to_block, walks the structural tree
carrying (domains, tables, chains) context, accumulates nodes/edges per
(domain, table) cluster, classifies nodes at freeze, and renders d2/DOT.
No eval, kernel, resolver, or previous-ruleset I/O (see spec §1).
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass

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
