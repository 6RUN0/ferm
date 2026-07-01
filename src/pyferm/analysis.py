"""
Two internal AST proofs over the eval-free parse_to_block tree.

NOT a linter: no CLI, no severity, no user output -- these are called only
from tests, as the layer-6 acceptance criterion that the structural tree is
fit for name- and graph-analysis. They consume the Parser.parse_to_block tree
(both @if branches structured), never the ephemeral walk tree.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from .tree import Block, NodeVisitor

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from .tree import (
        DefNode,
        HeaderNode,
        IfNode,
        Node,
        RuleNode,
        SetNode,
        SubchainNode,
    )

_NAME_RE = re.compile(r"\w+")


def _iter_var_refs(span: Sequence[object]) -> Iterator[str]:
    """
    Yield the $-variable names ($name) mentioned in a raw token span.

    The tokenizer lexes "$" as its own single-char token, so a variable
    reference is ALWAYS the token pair ("$", name) -- never a glued "$name".
    Line sentinels and other non-str tokens are skipped. A "$x" inside a
    double-quoted token is a single quoted token, so it is NOT matched here
    (the pinned interpolation limitation).
    """
    for i, tok in enumerate(span):
        if tok == "$" and i + 1 < len(span):
            nxt = span[i + 1]
            if isinstance(nxt, str) and _NAME_RE.fullmatch(nxt):
                yield "$" + nxt


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
        """Record the declared @def name (LHS) and RHS var mentions."""
        refs = list(_iter_var_refs(node.span))
        if refs:
            # the first $-pair is the declared name (LHS of @def); the rest
            # are mentions of other vars on the RHS.
            self.declared.setdefault(refs[0], node)
            self.mentioned.update(refs[1:])

    def visit_SetNode(self, node: SetNode) -> None:  # noqa: N802
        """Record var mentions in an @set span."""
        self.mentioned.update(_iter_var_refs(node.span))

    def visit_RuleNode(self, node: RuleNode) -> None:  # noqa: N802
        """Record var mentions in a rule span."""
        self.mentioned.update(_iter_var_refs(node.span))

    def visit_IfNode(self, node: IfNode) -> None:  # noqa: N802
        """Record var mentions in an @if condition; branches via _walk_all."""
        self.mentioned.update(_iter_var_refs(node.cond_span))


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


def _walk_all(block: Block, visitor: NodeVisitor) -> None:
    """Visit every statement of a block and recurse into its sub-Blocks."""
    for node in block.statements:
        visitor.visit(node)
        for child in _child_blocks(node):
            _walk_all(child, visitor)


def find_unused_defs(root: Block) -> list[str]:
    """
    Return declared @def names never mentioned in any leaf span.

    Consumes a Parser.parse_to_block tree. The contract is narrowed to
    SYNTACTIC references; a name used only through string interpolation
    ("prefix $x", one double-quoted token) yields a false unused -- a known
    limitation pinned by a test.
    """
    collector = _DefCollector()
    _walk_all(root, collector)
    return sorted(
        name for name in collector.declared if name not in collector.mentioned
    )


#: Subchain declaration keywords -- each names a chain.
_SUBCHAIN_KW = frozenset({"@subchain", "subchain", "@gotosubchain"})

#: A quoted token needs at least an opening and a closing quote.
_QUOTE_PAIR_MIN_LEN = 2

#: Tokens that end a run of chain names after a ``chain`` keyword: a block or
#: statement boundary, or the start of a new header context. Parens are NOT
#: here -- they wrap a ``chain (A B)`` array whose names are still collected.
_CHAIN_NAME_STOP = frozenset(
    {"{", "}", ";", "policy", "priority", "chain", "table", "domain"}
)


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
    header. Also yields a quoted ``@subchain "NAME"`` declaration. $var names
    are skipped (the literal-only contract).
    """
    toks = list(_str_tokens(span))
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "chain":
            i += 1
            while i < len(toks) and toks[i] not in _CHAIN_NAME_STOP:
                name = toks[i]
                i += 1
                if name in ("(", ")") or name.startswith("$"):
                    continue  # array delimiters / $var (not a literal name)
                yield _unquote(name)
            continue
        if tok in _SUBCHAIN_KW:
            i += 1
            if i < len(toks) and _is_quoted(toks[i]):
                yield _unquote(toks[i])
            continue
        i += 1


def _jump_targets(span: Sequence[object]) -> Iterator[str]:
    """Yield the literal jump/goto targets in a token span ($var skipped)."""
    toks = list(_str_tokens(span))
    for i, tok in enumerate(toks):
        if tok in ("jump", "goto") and i + 1 < len(toks):
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
        """Start with empty chain and jump registries."""
        self.declared: set[str] = set()
        self.jumps: list[str] = []

    def visit_HeaderNode(self, node: HeaderNode) -> None:  # noqa: N802
        """Harvest chain names embedded in a header's keyword + value span."""
        self.declared.update(
            _declared_chains((node.keyword, *node.value_span))
        )

    def visit_RuleNode(self, node: RuleNode) -> None:  # noqa: N802
        """Collect jumps, plus a mid-rule @subchain chain declaration."""
        self.declared.update(_declared_chains(node.span))
        self.jumps.extend(_jump_targets(node.span))

    def visit_SubchainNode(self, node: SubchainNode) -> None:  # noqa: N802
        """Harvest a leading @subchain chain declaration."""
        self.declared.update(_declared_chains(node.span))


def find_undefined_chain_jumps(root: Block) -> list[str]:
    """
    Return jump/goto targets whose chain is declared nowhere.

    Consumes a Parser.parse_to_block tree. Harvests chain names from all
    literal declaration sites (embedded ``chain <NAME>`` in a header, quoted
    @subchain). The contract is narrowed to literal (syntactic) names; $var
    targets/names and @include-file chains are pinned known limitations.
    """
    collector = _ChainCollector()
    _walk_all(root, collector)
    return sorted({t for t in collector.jumps if t not in collector.declared})
