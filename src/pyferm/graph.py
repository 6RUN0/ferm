# src/pyferm/graph.py
"""
The eval-free chain control-flow graph behind ``ferm --graph`` (port-only).

Parses one config with Parser.parse_to_block, walks the structural tree
carrying (domains, tables, chains) context, accumulates nodes/edges per
(domain, table) cluster, classifies nodes at freeze, and renders d2/DOT.
No eval, kernel, resolver, or previous-ruleset I/O (see spec §1).
"""

# The builder reuses the eval-free scan primitives from ``_treescan`` (the
# ``_str_tokens``/``_chain_decls``/... helpers) by design, so pyright's
# private-usage rule is off here (mirrors walker.py).
# pyright: reportPrivateUsage=false
from __future__ import annotations

import enum
import functools
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, NamedTuple

from ._treescan import (
    _CHAIN_VALUE_BOUNDARY,
    _JUMP_KW,
    _NAME_RE,
    _chain_decls,
    _child_blocks,
    _is_quoted_interpolation,
    _jump_pairs,
    _str_tokens,
    _subchain_names,
    _subchain_pairs,
    _unquote,
)
from .domains import DEFAULT_TABLE
from .modules import MATCH_DEFS, PROTO_DEFS, TARGET_DEFS
from .parser import _LOCATION_KEYWORDS, MAX_BLOCK_DEPTH
from .rules import CORE_TARGETS, is_netfilter_builtin_chain
from .streams import escape_control_chars
from .tree import (
    Block,
    BlockNode,
    DefNode,
    HeaderNode,
    RuleNode,
    SubchainNode,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

_ID_SAFE: Final[frozenset[str]] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)


class EdgeKind(enum.StrEnum):
    """Edge label; the value IS the rendered label. VERDICT = no label."""

    JUMP = "jump"
    GOTO = "goto"
    SUBCHAIN = "subchain"
    POLICY = "policy"
    VERDICT = ""

    @classmethod
    def from_jump_keyword(cls, keyword: str) -> EdgeKind:
        """
        Map a jump/goto/realgoto keyword to its edge kind.

        ``realgoto`` is the deprecated alias for ``goto``.
        """
        return _KIND_BY_JUMP_KEYWORD[keyword]

    @classmethod
    def from_subchain_keyword(cls, keyword: str) -> EdgeKind:
        """
        Map an @subchain/@gotosubchain keyword to its edge kind.

        ``@gotosubchain`` carries goto semantics (jumps to the subchain
        without a return); ``@subchain``/the deprecated bare ``subchain``
        keep the ordinary subchain edge.
        """
        return _KIND_BY_SUBCHAIN_KEYWORD[keyword]


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

    @property
    def dot_id(self) -> str:
        """Injective subgraph/block id, shared by both renderers."""
        return _cluster_id(self.domain, self.table)

    @property
    def label(self) -> str:
        """Escaped ``domain/table`` display label, shared by both renderers."""
        return f"{_escape_ident(self.domain)}/{_escape_ident(self.table)}"


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
    return escape_control_chars(name)


def _header_value(toks: list[str], i: int) -> tuple[tuple[str, ...], int]:
    """
    Collect literal value(s) after a header keyword at toks[i].

    Handles a bare single value and a ``(A B ...)`` array; $-names, and a
    quoted double-quote interpolation (``"$x"``/``"@arr"``), are dropped
    (non-literal, eval-free contract). Returns (values, next_index).
    """
    values: list[str] = []
    if i < len(toks) and toks[i] == "(":
        i += 1
        while i < len(toks) and toks[i] != ")":
            if toks[i] == "$":
                i += 1
                if i < len(toks) and _NAME_RE.fullmatch(toks[i]):
                    i += 1
                continue
            if toks[i].startswith("$"):
                i += 1  # defensive: a glued "$name" token
                continue
            if not _is_quoted_interpolation(toks[i]):
                values.append(_unquote(toks[i]))
            i += 1
        if i < len(toks) and toks[i] == ")":
            i += 1
    elif i < len(toks) and toks[i] not in _CHAIN_VALUE_BOUNDARY:
        if toks[i] == "$":
            i += 1
            if i < len(toks) and _NAME_RE.fullmatch(toks[i]):
                i += 1
        elif not toks[i].startswith("$"):
            if not _is_quoted_interpolation(toks[i]):
                values.append(_unquote(toks[i]))
            i += 1
        else:
            i += 1  # defensive: a glued "$name" token
    return tuple(values), i


class HeaderContext(NamedTuple):
    """Header-context updates, the policy target, and the rule tail."""

    new_domains: tuple[str, ...] | None
    new_tables: tuple[str, ...] | None
    new_chains: tuple[str, ...] | None
    policy_target: str | None
    tail: tuple[str, ...]


def _header_context(span: Sequence[object]) -> HeaderContext:
    """
    Extract header-context updates, the policy target, and the rule tail.

    Returns a :class:`HeaderContext`. The header prefix is a contiguous
    run of location specifiers -- the
    ``domain``/``table``/``chain`` keywords (each + a scalar or ``(...)``
    array value) and the ``policy`` fold -- taken from one HeaderNode's
    ``(keyword, *value_span)``. Scanning STOPS at the first token that is
    not a header keyword: in the flat inline form
    (``chain INPUT proto tcp ... ACCEPT;``) the parser fuses the whole rule
    into the header span, and everything after the location run is the
    inline rule ``tail`` returned for edge emission. Stopping there also
    stops an option value spelled like a header keyword (``dport domain``)
    from being misread as a location, and it structurally excludes the
    policy *match module*: ``mod`` is not a header keyword, so ``mod policy
    dir in`` stops at ``mod`` and never treats ``policy`` as the fold. A
    reached ``policy`` token yields a target only when the next token is a
    core target (the oracle rejects any other policy, ferm:2647-2648).
    Non-literal ``$var`` values are skipped (no phantom cluster). ``None``
    context fields keep the inherited context. The tail is a slice of the
    flattened string tokens, so it preserves quoting (``_str_tokens`` is
    idempotent on plain strings) for the downstream ``_emit_span`` scanners.
    """
    toks = list(_str_tokens(span))
    new_domains: tuple[str, ...] | None = None
    new_tables: tuple[str, ...] | None = None
    new_chains: tuple[str, ...] | None = None
    policy_target: str | None = None
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in _LOCATION_KEYWORDS:
            values, j = _header_value(toks, i + 1)
            if values:  # empty means the value was a skipped $var
                if tok == "domain":
                    new_domains = values
                elif tok == "table":
                    new_tables = values
                else:
                    new_chains = values
            i = j
            continue
        if tok == "policy":
            nxt = toks[i + 1] if i + 1 < len(toks) else None
            if nxt in CORE_TARGETS:
                policy_target = nxt
            i += 2
            continue
        break  # first non-header token: the inline rule tail starts here
    return HeaderContext(
        new_domains, new_tables, new_chains, policy_target, tuple(toks[i:])
    )


#: Backs :meth:`EdgeKind.from_jump_keyword`; ``realgoto`` is the deprecated
#: alias for ``goto``.
_KIND_BY_JUMP_KEYWORD: Final[dict[str, EdgeKind]] = {
    "jump": EdgeKind.JUMP,
    "goto": EdgeKind.GOTO,
    "realgoto": EdgeKind.GOTO,
}

#: Backs :meth:`EdgeKind.from_subchain_keyword` (the parser gives goto
#: jumptype only to a subchain keyword starting with ``@go``).
_KIND_BY_SUBCHAIN_KEYWORD: Final[dict[str, EdgeKind]] = {
    "@subchain": EdgeKind.SUBCHAIN,
    "subchain": EdgeKind.SUBCHAIN,
    "@gotosubchain": EdgeKind.GOTO,
}


def _jump_edges(toks: Sequence[str]) -> Iterator[tuple[EdgeKind, str]]:
    """Yield (kind, literal target) for each jump/goto/realgoto in a span."""
    for kw, target in _jump_pairs(toks):
        yield EdgeKind.from_jump_keyword(kw), target


def _subchain_edges(toks: Sequence[str]) -> Iterator[tuple[EdgeKind, str]]:
    """Yield (kind, literal name) for each @subchain/@gotosubchain span hit."""
    for kw, name in _subchain_pairs(toks):
        yield EdgeKind.from_subchain_keyword(kw), name


def _fold_family(domain: str) -> str:
    """Map a domain to its defs family (ip6 folds to ip; parser.py:657)."""
    return "ip" if domain == "ip6" else domain


@functools.cache
def _family_targets(family: str) -> frozenset[str]:
    """
    Recognised verdict tokens of a family: core targets + module targets.

    Cached: called per (span, domain) in _scan_verdicts and per node in
    _classify, over a handful of distinct families per run; the registry
    is immutable after import.
    """
    return frozenset(CORE_TARGETS) | frozenset(TARGET_DEFS.get(family, {}))


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


_KW_HAS_PARAMS: Final[dict[str, frozenset[str]]] = _build_kw_has_params()


@dataclass
class _ClusterAcc:
    """Mutable per-(domain, table) accumulator; frozen into a Cluster later."""

    declared: set[str]
    edges: set[tuple[str, str, EdgeKind]]
    names: set[str]


def _scan_verdicts(toks: Sequence[str], family: str) -> list[str]:
    """
    Recognised verdict target tokens in a span, with FP suppression.

    Emits any token in the family's target set as a verdict leaf, except:
    (1) the token right after a jump/goto/realgoto keyword (that is the
    jump target); (2) an option value whose previous significant token is
    a registry keyword with params -- for the ``(...)`` array form the whole
    group is skipped; (3) quoted candidates never match a bare target name.

    Known blind spot: rule 2 skips exactly ONE value token, so the second
    word of a two-argument option is scanned again -- a trailing argument
    spelled like a target (``chunk-types only ACCEPT``) emits a phantom
    verdict edge.
    """
    targets = _family_targets(family)
    params_keys = _KW_HAS_PARAMS.get(family, frozenset())
    out: list[str] = []
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok in _JUMP_KW:  # rule 1: skip the jump keyword and its target
            i += 2
            continue
        prev = toks[i - 1] if i > 0 else None
        if prev in params_keys:  # rule 2: option value
            if tok == "(":
                depth = 1
                i += 1
                while i < len(toks) and depth:
                    if toks[i] == "(":
                        depth += 1
                    elif toks[i] == ")":
                        depth -= 1
                    i += 1
                continue
            i += 1
            continue
        if tok in targets:  # rule 3: a quoted token is not a bare target
            out.append(tok)
        i += 1
    return out


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


def _classify(name: str, declared: set[str], family: str) -> NodeKind:
    """Priority BUILTIN > USER > VERDICT > UNDEFINED (spec §3)."""
    if is_netfilter_builtin_chain("", name):
        return NodeKind.BUILTIN
    if name in declared:
        return NodeKind.USER
    if name in _family_targets(family):
        return NodeKind.VERDICT
    return NodeKind.UNDEFINED


class _GraphBuilder:
    """Owns the mutable per-(domain, table) accumulator built by one walk."""

    def __init__(self) -> None:
        self._acc: dict[tuple[str, str], _ClusterAcc] = {}

    def acc_for(self, domain: str, table: str) -> _ClusterAcc:
        return self._acc.setdefault(
            (domain, table),
            _ClusterAcc(declared=set(), edges=set(), names=set()),
        )

    def declare(
        self,
        domains: tuple[str, ...],
        tables: tuple[str, ...],
        names: tuple[str, ...],
    ) -> None:
        for domain in domains:
            for table in tables:
                ca = self.acc_for(domain, table)
                for name in names:
                    ca.declared.add(name)
                    ca.names.add(name)

    def emit_span(
        self,
        domains: tuple[str, ...],
        tables: tuple[str, ...],
        chains: tuple[str, ...],
        span: Sequence[object],
    ) -> None:
        """Emit jump/goto/subchain/verdict edges from a leaf span."""
        # one materialized token list feeds all four scanners (and the
        # per-domain verdict scan) instead of each re-filtering the span
        toks = list(_str_tokens(span))
        jumps = list(_jump_edges(toks))
        subs = list(_subchain_edges(toks))
        declared_here = list(_chain_decls(toks))
        for domain in domains:
            family = _fold_family(domain)
            verdicts = _scan_verdicts(toks, family)
            for table in tables:
                ca = self.acc_for(domain, table)
                for name in declared_here:
                    ca.declared.add(name)
                    ca.names.add(name)
                for src in chains:
                    ca.names.add(src)
                    for kind, dst in jumps:
                        ca.edges.add((src, dst, kind))
                        ca.names.add(dst)
                    for kind, name in subs:
                        ca.edges.add((src, name, kind))
                        ca.declared.add(name)
                        ca.names.add(name)
                    for dst in verdicts:
                        ca.edges.add((src, dst, EdgeKind.VERDICT))
                        ca.names.add(dst)

    def walk(
        self,
        block: Block,
        domains: tuple[str, ...],
        tables: tuple[str, ...],
        chains: tuple[str, ...],
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
                    self.walk(child, d, t, body_chains, depth + 1)
                continue
            pending_subchain = None
            if isinstance(node, HeaderNode):
                ctx = _header_context((node.keyword, *node.value_span))
                if ctx.new_domains is not None:
                    d = ctx.new_domains
                if ctx.new_tables is not None:
                    t = ctx.new_tables
                if ctx.new_chains is not None:
                    # entering a chain context defaults the table to filter
                    if not t:
                        t = (DEFAULT_TABLE,)
                    c = ctx.new_chains
                    self.declare(d, t, ctx.new_chains)
                if ctx.policy_target is not None and c:
                    eff_tables = t or (DEFAULT_TABLE,)
                    for domain in d:
                        for table in eff_tables:
                            ca = self.acc_for(domain, table)
                            for src in c:
                                ca.edges.add(
                                    (src, ctx.policy_target, EdgeKind.POLICY)
                                )
                                ca.names.add(src)
                                ca.names.add(ctx.policy_target)
                if ctx.tail and c:
                    # flat inline form: the fused rule tail is a rule in
                    # the current chain, routed through the same
                    # edge/verdict path as a braced rule (context updates
                    # already applied above).
                    self.emit_span(d, t or (DEFAULT_TABLE,), c, ctx.tail)
            elif isinstance(node, (RuleNode, DefNode, SubchainNode)) and c:
                eff_tables = t or (DEFAULT_TABLE,)
                scan = _scan_span(node)
                if scan is not None:
                    self.emit_span(d, eff_tables, c, scan)
                if isinstance(node, RuleNode):
                    subs = tuple(_subchain_names(node.span))
                    if subs:
                        pending_subchain = subs
            for child in _child_blocks(node):
                self.walk(child, d, t, c, depth + 1)

    def freeze(self) -> ChainGraph:
        clusters: list[Cluster] = []
        for (domain, table), ca in self._acc.items():
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
    builder = _GraphBuilder()
    builder.walk(root, ("ip",), (), (), 0)
    return builder.freeze()


_DOT_NODE_ATTR: Final[dict[NodeKind, str]] = {
    NodeKind.BUILTIN: " [shape=box]",
    NodeKind.UNDEFINED: " [style=dashed]",
    NodeKind.VERDICT: " [shape=plaintext]",
}


def _quote_ident(name: str) -> str:
    """Quote an escaped identifier for both renderers (DOT and d2)."""
    return f'"{_escape_ident(name)}"'


def render_dot(graph: ChainGraph) -> str:
    """Render the graph as Graphviz DOT (deterministic; spec §5)."""
    lines = ["digraph ferm {"]
    for cluster in graph.clusters:
        lines.append(f"  subgraph cluster_{cluster.dot_id} {{")
        lines.append(f'    label="{cluster.label}";')
        for name, kind in cluster.nodes:
            attr = _DOT_NODE_ATTR.get(kind, "")
            lines.append(f"    {_quote_ident(name)}{attr};")
        for src, dst, edge_kind in cluster.edges:
            label = f' [label="{edge_kind}"]' if edge_kind else ""
            lines.append(
                f"    {_quote_ident(src)} -> {_quote_ident(dst)}{label};"
            )
        lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


_D2_NODE_STYLE: Final[dict[NodeKind, str]] = {
    NodeKind.BUILTIN: "shape: hexagon",
    NodeKind.UNDEFINED: "style.stroke-dash: 3",
    NodeKind.VERDICT: "shape: oval",
}


def render_d2(graph: ChainGraph) -> str:
    """
    Render the graph as d2 (deterministic; spec section 5).

    Every node gets its own line (USER nodes bare, others styled) so the
    two renderers' node sets never diverge. Ids are quoted unconditionally
    to dodge d2 reserved keys (label/shape/style/...).
    """
    lines: list[str] = []
    for cluster in graph.clusters:
        lines.append(f'{cluster.dot_id}: "{cluster.label}" {{')
        for name, kind in cluster.nodes:
            style = _D2_NODE_STYLE.get(kind)
            if style:
                lines.append(f"  {_quote_ident(name)}: {{ {style} }}")
            else:
                lines.append(f"  {_quote_ident(name)}")
        for src, dst, edge_kind in cluster.edges:
            label = f": {edge_kind}" if edge_kind else ""
            lines.append(
                f"  {_quote_ident(src)} -> {_quote_ident(dst)}{label}"
            )
        lines.append("}")
    return "\n".join(lines) + "\n"
