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
from typing import TYPE_CHECKING

from ._treescan import (
    _CHAIN_VALUE_BOUNDARY,
    _child_blocks,
    _declared_chains,
    _str_tokens,
    _subchain_names,
    _unquote,
)
from .modules import MATCH_DEFS, PROTO_DEFS, TARGET_DEFS
from .parser import MAX_BLOCK_DEPTH
from .rules import _CORE_TARGETS, is_netfilter_builtin_chain
from .tree import (
    Block,
    BlockNode,
    DefNode,
    HeaderNode,
    RuleNode,
    SubchainNode,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

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


_KIND_BY_JUMP_KW = {
    "jump": EdgeKind.JUMP,
    "goto": EdgeKind.GOTO,
    "realgoto": EdgeKind.GOTO,  # deprecated alias -> goto (spec §3)
}


def _jump_edges(span: object) -> Iterator[tuple[EdgeKind, str]]:
    """Yield (kind, literal target) for each jump/goto/realgoto in a span."""
    toks = list(_str_tokens(span))  # type: ignore[arg-type]
    for i, tok in enumerate(toks):
        if tok in _KIND_BY_JUMP_KW and i + 1 < len(toks):
            target = toks[i + 1]
            if not target.startswith("$"):
                yield _KIND_BY_JUMP_KW[tok], _unquote(target)


def _fold_family(domain: str) -> str:
    """Map a domain to its defs family (ip6 folds to ip; parser.py:657)."""
    return "ip" if domain == "ip6" else domain


def _family_targets(family: str) -> frozenset[str]:
    """Recognised verdict tokens of a family: core targets + module targets."""
    return frozenset(_CORE_TARGETS) | frozenset(TARGET_DEFS.get(family, {}))


def _build_kw_has_params() -> dict[str, frozenset[str]]:
    """
    Per-family set of registry keywords that take an argument.

    Union over the three registries: a flat keyword->params map does not
    exist (registry is family->module->keywords), and the eval-free scan
    needs to know, without an active module, whether the previous token is
    an option key whose value must be skipped. has-params if ANY module of
    the family gives the keyword non-None params (conservative: over-skips).
    """
    index: dict[str, set[str]] = {}
    for registry in (PROTO_DEFS, MATCH_DEFS, TARGET_DEFS):
        for family, modules in registry.items():
            fam = index.setdefault(family, set())
            for module in modules.values():
                for kw, keyword in module.keywords.items():
                    if keyword.params is not None:
                        fam.add(kw)
    return {family: frozenset(kws) for family, kws in index.items()}


_KW_HAS_PARAMS = _build_kw_has_params()


@dataclass
class _ClusterAcc:
    """Mutable per-(domain, table) accumulator; frozen into a Cluster later."""

    declared: set[str]
    edges: set[tuple[str, str, EdgeKind]]
    names: set[str]


def _acc_for(
    acc: dict[tuple[str, str], _ClusterAcc], domain: str, table: str
) -> _ClusterAcc:
    return acc.setdefault(
        (domain, table), _ClusterAcc(declared=set(), edges=set(), names=set())
    )


def _scan_verdicts(span: object, family: str) -> list[str]:  # noqa: ARG001
    """Recognised verdict target tokens in a span (Task 6 fills this in)."""
    return []


def _scan_span(
    node: RuleNode | DefNode | SubchainNode,
) -> tuple[object, ...] | None:
    """
    Tokens of a leaf node to scan for the enclosing chain; None = skip.

    A scalar ``@def $x = ...`` RHS is a stored VALUE, not a rule: scanning
    it fabricates phantom edges (``@def $x = jump foo;`` -> a bogus
    caller->foo jump), so scalar defs are skipped whole. A function
    ``@def &f() = { ... }`` body lives INSIDE the DefNode span and IS
    replayed in the caller's chain, so it keeps the lexical attribution
    (spec section 4 pin). A braced ``@subchain "sc" { ... }`` carries its
    body INSIDE the span; only the pre-``{`` head (the subchain edge and
    name) is attributed to the outer chain -- the body is elided
    (documented blind spot), never leaked to the parent. The split
    compares STRUCTURAL tokens, so a quoted name containing ``{``
    survives intact.
    """
    if isinstance(node, DefNode):
        toks = list(_str_tokens(node.span))
        return node.span if len(toks) > 1 and toks[1] == "&" else None
    if isinstance(node, SubchainNode):
        head: list[object] = []
        for tok in node.span:
            if tok == "{":
                break
            head.append(tok)
        return tuple(head)
    return node.span


def _declare(
    acc: dict[tuple[str, str], _ClusterAcc],
    domains: tuple[str, ...],
    tables: tuple[str, ...],
    names: tuple[str, ...],
) -> None:
    for domain in domains:
        for table in tables:
            ca = _acc_for(acc, domain, table)
            for name in names:
                ca.declared.add(name)
                ca.names.add(name)


def _emit_span(
    acc: dict[tuple[str, str], _ClusterAcc],
    domains: tuple[str, ...],
    tables: tuple[str, ...],
    chains: tuple[str, ...],
    span: object,
) -> None:
    """Emit jump/goto/subchain/verdict edges from a rule/def/subchain span."""
    jumps = list(_jump_edges(span))
    subs = list(_subchain_names(span))  # type: ignore[arg-type]
    declared_here = list(_declared_chains(span))  # type: ignore[arg-type]
    for domain in domains:
        family = _fold_family(domain)
        verdicts = _scan_verdicts(span, family)
        for table in tables:
            ca = _acc_for(acc, domain, table)
            for name in declared_here:
                ca.declared.add(name)
                ca.names.add(name)
            for src in chains:
                ca.names.add(src)
                for kind, dst in jumps:
                    ca.edges.add((src, dst, kind))
                    ca.names.add(dst)
                for name in subs:
                    ca.edges.add((src, name, EdgeKind.SUBCHAIN))
                    ca.declared.add(name)
                    ca.names.add(name)
                for dst in verdicts:
                    ca.edges.add((src, dst, EdgeKind.VERDICT))
                    ca.names.add(dst)


def _walk(
    block: Block,
    domains: tuple[str, ...],
    tables: tuple[str, ...],
    chains: tuple[str, ...],
    acc: dict[tuple[str, str], _ClusterAcc],
    depth: int,
) -> None:
    if depth > MAX_BLOCK_DEPTH:
        return
    # A rule-prefixed @subchain body is a SIBLING BlockNode immediately
    # after the RuleNode that names the subchain; attribute it to the
    # subchain, not the outer chain. Keyed on _subchain_names, so a plain
    # rule-group block (proto tcp { ... }) is NOT re-attributed. The
    # pending marker is a per-call local: it cannot leak across block
    # boundaries.
    pending_subchain: tuple[str, ...] | None = None
    for node in block.statements:
        d, t, c = domains, tables, chains
        if isinstance(node, BlockNode) and pending_subchain is not None:
            body_chains, pending_subchain = pending_subchain, None
            for child in _child_blocks(node):
                _walk(child, d, t, body_chains, acc, depth + 1)
            continue
        pending_subchain = None
        if isinstance(node, HeaderNode):
            nd, nt, nc, policy_target = _header_context(
                (node.keyword, *node.value_span)
            )
            if nd is not None:
                d = nd
            if nt is not None:
                t = nt
            if nc is not None:
                # entering a chain context defaults the table to filter
                if not t:
                    t = ("filter",)
                c = nc
                _declare(acc, d, t, nc)
            if policy_target is not None and c:
                eff_tables = t or ("filter",)
                for domain in d:
                    for table in eff_tables:
                        ca = _acc_for(acc, domain, table)
                        for src in c:
                            ca.edges.add((src, policy_target, EdgeKind.POLICY))
                            ca.names.add(src)
                            ca.names.add(policy_target)
        elif isinstance(node, (RuleNode, DefNode, SubchainNode)) and c:
            eff_tables = t or ("filter",)
            scan = _scan_span(node)
            if scan is not None:
                _emit_span(acc, d, eff_tables, c, scan)
            if isinstance(node, RuleNode):
                subs = tuple(_subchain_names(node.span))
                if subs:
                    pending_subchain = subs
        for child in _child_blocks(node):
            _walk(child, d, t, c, acc, depth + 1)


def _classify(name: str, declared: set[str], family: str) -> NodeKind:
    """Priority BUILTIN > USER > VERDICT > UNDEFINED (spec §3)."""
    if is_netfilter_builtin_chain("", name):
        return NodeKind.BUILTIN
    if name in declared:
        return NodeKind.USER
    if name in _family_targets(family):
        return NodeKind.VERDICT
    return NodeKind.UNDEFINED


def _freeze(acc: dict[tuple[str, str], _ClusterAcc]) -> ChainGraph:
    clusters: list[Cluster] = []
    for (domain, table), ca in acc.items():
        family = _fold_family(domain)
        nodes = tuple(
            sorted(
                (name, _classify(name, ca.declared, family))
                for name in ca.names
            )
        )
        edges = tuple(sorted(ca.edges))
        clusters.append(Cluster(domain, table, nodes, edges))
    return ChainGraph(
        tuple(sorted(clusters, key=lambda c: (c.domain, c.table)))
    )


def collect_graph(root: Block) -> ChainGraph:
    """Build the chain control-flow graph from a parse_to_block tree."""
    acc: dict[tuple[str, str], _ClusterAcc] = {}
    _walk(root, ("ip",), (), (), acc, 0)
    return _freeze(acc)
