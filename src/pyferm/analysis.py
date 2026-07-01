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

    from .tree import DefNode, IfNode, Node, RuleNode, SetNode

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
