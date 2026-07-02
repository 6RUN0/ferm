"""
The eval-free static-analysis engine behind ``ferm --lint``.

Six structural analyzers over the ``Parser.parse_to_block`` tree (both
@if branches structured, never the ephemeral walk tree), run through an
ordered registry (ANALYZERS) yielding Severity-tiered Finding records:
jump-cycle (error); unused-definition, undefined-jump,
unreachable-chain, duplicate-definition (warnings); deprecated-keyword
(info). Nothing evaluates the config: no kernel, resolver, or
previous-ruleset I/O is touched.

The analysis is literal-syntactic by design. Closed since the first
slice: double-quoted "$x" interpolation counts as a use, the realgoto
alias is a jump edge, and @def &f functions are tracked (an uncalled
function is an unused definition). Still pinned as limitations: $var
jump targets are invisible; the chain namespace flattens (domain,
table) and both @if branches feed ONE graph, so jump-cycle can
over-report a phantom loop (the conservatism direction flips there);
jump-cycle also credits a nested @def body to its lexically enclosing
chain (phantom edges from uncalled functions) yet cannot see a loop
routed through a function CALL (its one false-negative gap); a chain
literally named after a deprecated keyword false-fires
deprecated-keyword; a braceless ``@if $c @def $x = 2;`` hides the
guarded statement inside the condition span; unreachable-chain is
in-degree only (a dead A<->B island or a self-loop is not reported --
jump-cycle covers the island, unless its edges route through a
function call); @include and @hook spans are not scanned. These
limits are pinned by tests and inherited -- and documented -- by
``--lint``.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from .parser import DEPRECATED_KEYWORDS, MAX_BLOCK_DEPTH
from .rules import is_netfilter_builtin_chain
from .tree import (
    Block,
    DefNode,
    HeaderNode,
    NodeVisitor,
    RuleNode,
    SubchainNode,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

    from .tree import IfNode, Node, SetNode

_NAME_RE = re.compile(r"\w+")

#: The oracle's double-quote interpolation form: "$" immediately
#: followed by word chars. There is no ${name} form in ferm.
_INTERPOLATION_RE = re.compile(r"\$(\w+)")


def _index_of(span: Sequence[object], token: str) -> int | None:
    """Return the index of the first ``token`` in a span, or None if absent."""
    for i, tok in enumerate(span):
        if tok == token:
            return i
    return None


def _iter_var_refs(span: Sequence[object]) -> Iterator[str]:
    """
    Yield the $-variable names ($name) mentioned in a raw token span.

    The tokenizer lexes "$" as its own single-char token, so a bare
    variable reference is ALWAYS the token pair ("$", name) -- never a
    glued "$name". A double-quoted token is additionally scanned for
    the oracle's interpolation form ("prefix $x" mentions $x); a
    single-quoted token stays literal (ferm never interpolates it) and
    the ${name} spelling does not exist in ferm (the oracle passes it
    through verbatim), so neither counts as a use. Line sentinels and
    other non-str tokens are skipped.
    """
    for i, tok in enumerate(span):
        if tok == "$" and i + 1 < len(span):
            nxt = span[i + 1]
            if isinstance(nxt, str) and _NAME_RE.fullmatch(nxt):
                yield "$" + nxt
        elif isinstance(tok, str) and _is_quoted(tok) and tok[0] == '"':
            for match in _INTERPOLATION_RE.finditer(_unquote(tok)):
                yield "$" + match.group(1)


def _iter_func_refs(span: Sequence[object]) -> Iterator[str]:
    """
    Yield the &-function names (&name) mentioned in a raw token span.

    Like "$", the tokenizer lexes "&" as its own token, so a function
    reference is always the pair ("&", name). Callers must exclude a
    definition's own head, or the name would count as a self-mention.
    """
    for i, tok in enumerate(span):
        if tok == "&" and i + 1 < len(span):
            nxt = span[i + 1]
            if isinstance(nxt, str) and _NAME_RE.fullmatch(nxt):
                yield "&" + nxt


def _function_def_name(span: Sequence[object]) -> str | None:
    """
    Return the '&name' a function @def declares, or None if absent.

    The first &-pair LEFT of '=' is the declared name (parameters are
    $-vars, so they cannot shadow it).
    """
    eq_index = _index_of(span, "=")
    return next(_iter_func_refs(span[:eq_index]), None)


class _DefCollector(NodeVisitor):
    """
    Collect declared @def names and every name mentioned in leaf spans.

    Declarations come from DefNode; mentions from every leaf token span. Both
    @if branches are visible because _walk_all descends into the structured
    then_body/else_body sub-Blocks (structural, not post-eval).
    """

    def __init__(self) -> None:
        """Start with empty declaration and mention registries."""
        self.declared: dict[str, Node] = {}
        self.mentioned: set[str] = set()

    def visit_DefNode(self, node: DefNode) -> None:  # noqa: N802
        """
        Record the declared @def name (LHS) and the RHS mentions.

        A function def ``@def &f($p) = ...`` declares the function name
        (kept WITH its ``&`` sigil in the same registry as $-vars); the
        ``$p`` before ``=`` are parameters (locals), so they are neither
        declared nor counted as global mentions -- only the body (after
        ``=``) contributes mentions, of $-vars and of &-calls alike, so
        a call inside another function's body marks the callee used
        (transitive liveness is NOT computed). A variable def
        ``@def $x = ...`` declares its first $-pair and mentions the
        rest.
        """
        span = node.span
        eq_index = _index_of(span, "=")
        # a '&' left of '=' (or anywhere, when there is no '=') marks a
        # function def; span[:None] is the whole span, covering both.
        is_function_def = "&" in span[:eq_index]
        body = span[eq_index + 1 :] if eq_index is not None else ()
        if is_function_def:
            name = _function_def_name(span)
            if name is not None:
                self.declared.setdefault(name, node)
            self.mentioned.update(_iter_var_refs(body))
            self.mentioned.update(_iter_func_refs(body))
            return
        refs = list(_iter_var_refs(span))
        if refs:
            self.declared.setdefault(refs[0], node)
            self.mentioned.update(refs[1:])
        # a var-def RHS may call a function; the head has no '&'.
        self.mentioned.update(_iter_func_refs(span))

    def visit_SetNode(self, node: SetNode) -> None:  # noqa: N802
        """Record var mentions in an @set span."""
        self.mentioned.update(_iter_var_refs(node.span))
        self.mentioned.update(_iter_func_refs(node.span))

    def visit_RuleNode(self, node: RuleNode) -> None:  # noqa: N802
        """Record var mentions in a rule span."""
        self.mentioned.update(_iter_var_refs(node.span))
        self.mentioned.update(_iter_func_refs(node.span))

    def visit_IfNode(self, node: IfNode) -> None:  # noqa: N802
        """Record var mentions in an @if condition; branches via _walk_all."""
        self.mentioned.update(_iter_var_refs(node.cond_span))
        self.mentioned.update(_iter_func_refs(node.cond_span))


def _child_blocks(node: Node) -> Iterator[Block]:
    """
    Yield every structured sub-Block a node carries.

    Block bodies AND both @if branch bodies, so analysis descends into ALL
    nesting -- including untaken @if branches, the key capability the walk
    tree lacks.
    """
    for attr in ("body", "then_body", "else_body"):
        child = getattr(node, attr, None)
        if isinstance(child, Block):
            yield child


def _walk_all(block: Block, visitor: NodeVisitor, depth: int = 0) -> None:
    """
    Visit every statement of a block and recurse into its sub-Blocks.

    ``depth`` caps recursion at MAX_BLOCK_DEPTH (defence in depth: the
    parse_to_block tree is already depth-bounded by _StructuralParser).
    """
    if depth > MAX_BLOCK_DEPTH:
        return
    for node in block.statements:
        visitor.visit(node)
        for child in _child_blocks(node):
            _walk_all(child, visitor, depth + 1)


def find_unused_defs(root: Block) -> list[str]:
    """
    Return declared @def names never mentioned in any leaf span.

    Consumes a Parser.parse_to_block tree. The contract is narrowed to
    SYNTACTIC references.

    Function names (``@def &f``) are tracked with their ``&`` sigil: an
    uncalled function is reported as ``&foo``; a call from any span --
    including another function's body -- counts as a use (transitive
    liveness is not computed, a safe-direction limitation). A function
    parameter shares the global ``mentioned`` namespace, so a same-named
    unused global def can be masked (a pinned limitation of the
    literal-syntactic contract).
    """
    collector = _DefCollector()
    _walk_all(root, collector)
    return sorted(
        name for name in collector.declared if name not in collector.mentioned
    )


#: Subchain declaration keywords -- each names a chain.
_SUBCHAIN_KW = frozenset({"@subchain", "subchain", "@gotosubchain"})

#: Rule keywords that create an explicit jump edge to a chain. realgoto
#: is the deprecated alias of goto: the eval path remaps it, but the
#: structural tree keeps the original token.
_JUMP_KW = ("jump", "goto", "realgoto")

#: A quoted token needs at least an opening and a closing quote.
_QUOTE_PAIR_MIN_LEN = 2

#: Structural boundaries that stand where a ``chain`` name would be, i.e. a
#: bare ``chain`` with no name (malformed input). NOT a name-run terminator:
#: ``chain`` takes exactly ONE value (a single name or a parenthesised array),
#: so a name colliding with a header keyword (``chain table {}``) is still the
#: chain name, not a stop word.
_CHAIN_VALUE_BOUNDARY = frozenset({"{", "}", ";"})


def _str_tokens(span: Sequence[object]) -> Iterator[str]:
    """Yield only the plain string tokens (skip Line sentinels / non-str)."""
    for tok in span:
        if isinstance(tok, str):
            yield tok


def _is_quoted(tok: str) -> bool:
    """Return whether a token is wrapped in a matching quote pair."""
    return (
        len(tok) >= _QUOTE_PAIR_MIN_LEN
        and tok[0] in ("'", '"')
        and tok[-1] == tok[0]
    )


def _unquote(tok: str) -> str:
    """Strip a matching pair of surrounding quotes from a token."""
    return tok[1:-1] if _is_quoted(tok) else tok


def _declared_chains(span: Sequence[object]) -> Iterator[str]:
    """
    Yield every chain name a token span declares.

    Scans for an EMBEDDED ``chain <name>...`` sub-sequence -- not just a
    leading token -- so both the nested ``chain FOO {}`` and the dominant
    one-line ``table filter chain FOO {}`` forms (one collapsed HeaderNode)
    are harvested, plus a ``chain (A B)`` array and a ``... chain X policy``
    header. ``chain`` takes exactly ONE value (a single name or a
    parenthesised array), matching the oracle's getvalues -- so a name
    colliding with a header keyword is still harvested. Also yields a quoted
    ``@subchain "NAME"`` declaration. $var names are skipped (literal-only).
    """
    toks = list(_str_tokens(span))
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "chain":
            i += 1
            if i < len(toks) and toks[i] == "(":
                # array form ``chain (A B ...)``: collect names up to ')'.
                i += 1
                while i < len(toks) and toks[i] != ")":
                    name = toks[i]
                    i += 1
                    if not name.startswith("$"):
                        yield _unquote(name)
                if i < len(toks) and toks[i] == ")":
                    i += 1
            elif i < len(toks) and toks[i] not in _CHAIN_VALUE_BOUNDARY:
                # bare form: exactly ONE name, even one spelled like a keyword.
                name = toks[i]
                i += 1
                if not name.startswith("$"):
                    yield _unquote(name)
            continue
        if tok in _SUBCHAIN_KW:
            i += 1
            if i < len(toks) and _is_quoted(toks[i]):
                yield _unquote(toks[i])
            continue
        i += 1


def _subchain_names(span: Sequence[object]) -> Iterator[str]:
    """
    Yield the chain names a quoted @subchain declares in a span.

    Unlike _declared_chains (declaration sites of ANY kind), this
    yields ONLY subchain names: an @subchain carries an implicit jump
    from its enclosing rule, so these names are reached without any
    literal jump/goto/realgoto token.
    """
    toks = list(_str_tokens(span))
    for i, tok in enumerate(toks):
        if tok in _SUBCHAIN_KW and i + 1 < len(toks):
            candidate = toks[i + 1]
            if _is_quoted(candidate):
                yield _unquote(candidate)


def _jump_targets(span: Sequence[object]) -> Iterator[str]:
    """Yield literal jump/goto/realgoto targets in a span ($var skipped)."""
    toks = list(_str_tokens(span))
    for i, tok in enumerate(toks):
        if tok in _JUMP_KW and i + 1 < len(toks):
            target = toks[i + 1]
            if not target.startswith("$"):
                yield _unquote(target)


class _ChainCollector(NodeVisitor):
    """
    Collect declared chain names from ALL declaration sites and jump targets.

    Chains are declared by ``chain FOO {}`` (a HeaderNode, embedded in its
    keyword+value_span), by a quoted ``@subchain``, and by the one-line
    ``table filter chain FOO {}`` header -- NOT only SubchainNode. A
    SubchainNode-only or leading-``chain``-only visitor would false-flag every
    normally declared user chain. Chains/jumps inside @if branches and match
    blocks are covered for free by _walk_all descending the structured
    sub-Blocks.
    """

    def __init__(self) -> None:
        """Start with empty chain, jump and subchain registries."""
        self.declared: set[str] = set()
        self.jumps: list[str] = []
        self.subchains: set[str] = set()

    def visit_HeaderNode(self, node: HeaderNode) -> None:  # noqa: N802
        """Harvest chain names embedded in a header's keyword + value span."""
        self.declared.update(
            _declared_chains((node.keyword, *node.value_span))
        )

    def visit_RuleNode(self, node: RuleNode) -> None:  # noqa: N802
        """Collect jumps, plus a mid-rule @subchain chain declaration."""
        self.declared.update(_declared_chains(node.span))
        self.jumps.extend(_jump_targets(node.span))
        self.subchains.update(_subchain_names(node.span))

    def visit_SubchainNode(self, node: SubchainNode) -> None:  # noqa: N802
        """Harvest a leading @subchain chain declaration."""
        self.declared.update(_declared_chains(node.span))
        self.subchains.update(_subchain_names(node.span))

    def visit_DefNode(self, node: DefNode) -> None:  # noqa: N802
        """
        Harvest chain declarations and jumps from a @def span.

        Function bodies are stored as flat spans on the DefNode, so a
        ``jump FOO`` (or an @subchain) inside ``@def &f = ...`` is
        visible only here -- without this visit a chain reached solely
        from a function body would look unreachable and a broken jump
        inside a body would go unreported.
        """
        self.declared.update(_declared_chains(node.span))
        self.jumps.extend(_jump_targets(node.span))
        self.subchains.update(_subchain_names(node.span))


def find_undefined_chain_jumps(root: Block) -> list[str]:
    """
    Return jump/goto targets whose chain is declared nowhere.

    Consumes a Parser.parse_to_block tree. Harvests chain names from all
    literal declaration sites (embedded ``chain <NAME>`` in a header, quoted
    @subchain). The contract is narrowed to literal (syntactic) names; $var
    targets/names and @include-file chains are pinned known limitations.
    A further pinned false-negative (a missed undefined jump): the chain
    namespace is flattened to one global set, so a jump to a chain defined
    only in another (domain, table) is not reported.
    """
    collector = _ChainCollector()
    _walk_all(root, collector)
    return sorted({t for t in collector.jumps if t not in collector.declared})


class _DeprecatedKeywordCollector(NodeVisitor):
    """Collect DEPRECATED_KEYWORDS tokens from rule-position spans."""

    def __init__(self) -> None:
        """Start with an empty hit registry."""
        self.hits: set[str] = set()

    def _scan(self, span: Sequence[object]) -> None:
        for tok in _str_tokens(span):
            if tok in DEPRECATED_KEYWORDS:
                self.hits.add(tok)

    def visit_RuleNode(self, node: RuleNode) -> None:  # noqa: N802
        """Scan a rule span (the position realgoto occupies)."""
        self._scan(node.span)

    def visit_DefNode(self, node: DefNode) -> None:  # noqa: N802
        """Scan a @def span (a function body may hold rule keywords)."""
        self._scan(node.span)


def find_deprecated_keywords(root: Block) -> list[Finding]:
    """
    Report every deprecated keyword the config uses (info tier).

    Coverage is exactly the keys of parser.DEPRECATED_KEYWORDS (today a
    single entry, realgoto -> goto); the bare ``hook`` deprecation lives
    inline in the parser outside the mapping and is not detected. The
    replacement hint comes from the mapping value. One finding per
    keyword, however many times it occurs. The scan is token-membership
    over rule/def spans, not keyword-position dispatch, so a chain
    literally NAMED after a deprecated keyword (``jump realgoto``)
    false-fires -- a pinned false positive.
    """
    collector = _DeprecatedKeywordCollector()
    _walk_all(root, collector)
    return [
        Finding(
            Severity.INFO,
            "deprecated-keyword",
            f"deprecated keyword: {kw} (use {DEPRECATED_KEYWORDS[kw]})",
        )
        for kw in sorted(collector.hits)
    ]


class Severity(enum.IntEnum):
    """Finding importance; the IntEnum order is the output/gating order."""

    ERROR = 0
    WARNING = 1
    INFO = 2


@dataclass(frozen=True)
class Finding:
    """
    One lint finding: a severity tier, a stable code, and the message.

    ``message`` is the raw (unescaped) text after ``<severity>: ``; it is
    also the dedup/sort key -- control-char escaping happens at print
    time in the CLI, which is byte-equivalent (the substitution is
    position-independent) and keeps slice-1 ordering exact.
    """

    severity: Severity
    code: str
    message: str


def _unused_definition_findings(root: Block) -> list[Finding]:
    """Adapt find_unused_defs to the Finding model (message text pinned)."""
    return [
        Finding(
            Severity.WARNING,
            "unused-definition",
            f"unused definition: {name}",
        )
        for name in find_unused_defs(root)
    ]


def _undefined_jump_findings(root: Block) -> list[Finding]:
    """Adapt find_undefined_chain_jumps to the Finding model."""
    return [
        Finding(
            Severity.WARNING,
            "undefined-jump",
            f"jump to undefined chain: {name}",
        )
        for name in find_undefined_chain_jumps(root)
    ]


def find_unreachable_chains(root: Block) -> list[Finding]:
    """
    Report declared user chains with no incoming jump edge (warning).

    A chain is "reached" by a literal jump/goto/realgoto target or by
    an @subchain declaration (whose jump is implicit in the carrying
    rule). Built-in chains are entry points, not targets: filtered via
    rules.is_netfilter_builtin_chain (all six names, incl. ebtables
    BROUTING). The check is in-degree, not reachability from entry
    points, so a dead A<->B island or a self-looping chain has an
    incoming edge and is NOT reported (jump-cycle covers the island,
    unless its edges route through a function call -- see
    find_jump_cycles); a chain reached only through ``jump $var`` is a
    documented false positive (literal-name contract).
    """
    collector = _ChainCollector()
    _walk_all(root, collector)
    reached = set(collector.jumps) | collector.subchains
    return [
        Finding(
            Severity.WARNING,
            "unreachable-chain",
            f"unreachable chain: {name}",
        )
        for name in sorted(collector.declared)
        if name not in reached and not is_netfilter_builtin_chain("", name)
    ]


def _collect_edges(
    block: Block,
    sources: tuple[str, ...],
    edges: set[tuple[str, str]],
    depth: int = 0,
) -> None:
    """
    Collect directed jump edges attributed to the enclosing chain(s).

    ``sources`` is the chain-name context: the names the nearest
    enclosing chain header declares (several for a ``chain (A B)``
    array). Explicit jump/goto/realgoto targets and implicit @subchain
    jumps in rule/def/subchain spans become (source, target) edges;
    statements outside any chain contribute none (a TOP-LEVEL @def body
    therefore adds no edges), while a @def nested inside a chain block
    is attributed to that chain even if the function is never called --
    a lexical, not call-graph, attribution. An @subchain BODY is
    attributed to the OUTER chain (the structural tree keeps the body a
    sibling block) -- a reachability-preserving approximation: it can
    SHORTEN a reported cycle's printed path (the subchain hop is
    elided) but never fabricates an edge to an unreachable target.
    """
    if depth > MAX_BLOCK_DEPTH:
        return
    for node in block.statements:
        node_sources = sources
        if isinstance(node, HeaderNode):
            declared = tuple(
                _declared_chains((node.keyword, *node.value_span))
            )
            if declared:
                node_sources = declared
        if isinstance(node, (RuleNode, SubchainNode, DefNode)):
            targets = list(_jump_targets(node.span))
            targets.extend(_subchain_names(node.span))
            edges.update(
                (source, target)
                for source in node_sources
                for target in targets
            )
        for child in _child_blocks(node):
            _collect_edges(child, node_sources, edges, depth + 1)


def _canonical_cycle(cycle: tuple[str, ...]) -> tuple[str, ...]:
    """
    Rotate a cycle to start at its lexicographically-least node.

    So the same loop discovered from different DFS starts dedups to one.
    """
    pivot = cycle.index(min(cycle))
    return cycle[pivot:] + cycle[:pivot]


def _find_cycles(
    adjacency: dict[str, tuple[str, ...]],
) -> set[tuple[str, ...]]:
    """
    Find cycles in the jump graph with an ITERATIVE depth-first search.

    Iterative on purpose: the recursion axis is the LENGTH of a jump
    path (the number of chains), which MAX_BLOCK_DEPTH does not bound,
    and --lint is advertised for untrusted input. One DFS per start
    node with a per-start visited set keeps the walk polynomial --
    O(V*(V+E)), i.e. quadratic on a linear jump chain (about two
    seconds at 3000 chains), an accepted bound for config-file input;
    overlapping cycles sharing visited nodes may be summarized rather
    than enumerated exhaustively -- at least one cycle per loop is
    always found.
    """
    cycles: set[tuple[str, ...]] = set()
    for start in adjacency:
        path = [start]
        on_path = {start}
        visited = {start}
        pending = [iter(adjacency.get(start, ()))]
        while pending:
            successor = next(pending[-1], None)
            if successor is None:
                pending.pop()
                on_path.discard(path.pop())
                continue
            if successor in on_path:
                cycles.add(
                    _canonical_cycle(tuple(path[path.index(successor) :]))
                )
                continue
            if successor in visited:
                continue
            visited.add(successor)
            path.append(successor)
            on_path.add(successor)
            pending.append(iter(adjacency.get(successor, ())))
    return cycles


def find_jump_cycles(root: Block) -> list[Finding]:
    """
    Report each cycle in the jump/goto/realgoto graph (error tier).

    A real chain loop is rejected by the kernel at load time, hence the
    error tier. KNOWN FALSE-POSITIVE CLASSES (test-pinned): the graph
    flattens (domain, table) namespaces and walks BOTH @if branches, so
    an A->B edge in one table or branch plus a B->A edge in another
    reports a cycle no single generated ruleset contains; a @def nested
    in a chain block contributes its body's edges to that chain even
    when the function is never called. The conservatism direction FLIPS
    here versus the other analyzers: extra edges over-report instead of
    under-reporting -- with ONE pinned false-negative gap: a loop
    routed through a function CALL is invisible (a top-level @def body
    has no chain context and a call site is not a jump edge).
    """
    edges: set[tuple[str, str]] = set()
    _collect_edges(root, (), edges)
    adjacency: dict[str, tuple[str, ...]] = {}
    for source, target in sorted(edges):
        adjacency[source] = (*adjacency.get(source, ()), target)
    return [
        Finding(
            Severity.ERROR,
            "jump-cycle",
            "jump cycle: " + " -> ".join((*cycle, cycle[0])),
        )
        for cycle in sorted(_find_cycles(adjacency))
    ]


def _declared_def_name(span: Sequence[object]) -> str | None:
    """Return the name a @def span declares ($var or &function)."""
    eq_index = _index_of(span, "=")
    if "&" in span[:eq_index]:
        return _function_def_name(span)
    return next(_iter_var_refs(span), None)


def _collect_duplicate_defs(
    block: Block, duplicates: set[str], depth: int = 0
) -> None:
    """
    Record @def names declared twice within ONE immediate parent Block.

    Each Block gets its own ``seen`` registry, so a redefinition in a
    NESTED block is genuine shadowing (a fresh oracle stack frame per
    "{"; the value does not survive the "}") and never counts. A
    braceless ``@if $c @def $x = 2;`` is swallowed into the IfNode
    condition span by the structural parser (then_body stays empty), so
    such a guarded def is invisible here -- a documented blind spot.
    """
    if depth > MAX_BLOCK_DEPTH:
        return
    seen: set[str] = set()
    for node in block.statements:
        if isinstance(node, DefNode):
            name = _declared_def_name(node.span)
            if name is not None:
                if name in seen:
                    duplicates.add(name)
                seen.add(name)
        for child in _child_blocks(node):
            _collect_duplicate_defs(child, duplicates, depth + 1)


def find_duplicate_definitions(root: Block) -> list[Finding]:
    """
    Report a @def name declared twice in one scope (warning tier).

    "One scope" is one immediate parent Block of the parse_to_block
    tree. In ferm a same-frame re-@def silently last-wins (legal but
    pointless), so this is a style warning, not a language error. One
    finding per name however many repeats or scopes: messages carry no
    positions, so duplicates of one name in two different scopes
    collapse into one line (documented trade-off). A CLI ``--def``
    override is a separate axis (it wins over any script @def) and is
    not considered here.
    """
    duplicates: set[str] = set()
    _collect_duplicate_defs(root, duplicates)
    return [
        Finding(
            Severity.WARNING,
            "duplicate-definition",
            f"duplicate definition: {name}",
        )
        for name in sorted(duplicates)
    ]


#: Ordered analyzer registry: (code, severity, callable). Registration
#: order is the secondary output sort key (after severity), so the two
#: legacy analyzers keep their relative block order from the first slice.
ANALYZERS: Final[
    tuple[tuple[str, Severity, Callable[[Block], list[Finding]]], ...]
] = (
    ("jump-cycle", Severity.ERROR, find_jump_cycles),
    ("unused-definition", Severity.WARNING, _unused_definition_findings),
    ("undefined-jump", Severity.WARNING, _undefined_jump_findings),
    ("unreachable-chain", Severity.WARNING, find_unreachable_chains),
    ("duplicate-definition", Severity.WARNING, find_duplicate_definitions),
    ("deprecated-keyword", Severity.INFO, find_deprecated_keywords),
)


def run_analysis(root: Block) -> list[Finding]:
    """
    Run every registered analyzer; return deduplicated, ordered findings.

    Order: ``(severity, registration index, message)`` -- errors first,
    then warnings, then info; within a tier each analyzer's block stays
    contiguous, and messages sort lexicographically inside a block.
    Identical (severity, code, message) triples collapse to one finding:
    messages carry no positions, so two real same-name findings from
    different scopes print once (a documented trade-off).
    """
    registration_index = {
        code: index for index, (code, _, _) in enumerate(ANALYZERS)
    }
    findings: set[Finding] = set()
    for _code, _severity, analyzer in ANALYZERS:
        findings.update(analyzer(root))
    # A KeyError on a foreign f.code is intentional: every emitted code
    # must be a registered analyzer code.
    return sorted(
        findings,
        key=lambda f: (f.severity, registration_index[f.code], f.message),
    )
