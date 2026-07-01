"""
Structural (pre-eval) AST for the ferm parser.

The tree fixes the SHAPE of the source: both @if branches, @def/@include/
@set as nodes, variables NOT substituted. Leaves hold raw token spans
(with Line sentinels preserved) rather than parsed expression subtrees --
the deliberate forward seam. A separate Walker replays the semantics byte
for byte. Node kind for block headers (domain/table/chain) is
runtime-emergent, so those are captured as HeaderNode only on walk.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scope import SourcePosition
    from .tokenizer import Token


@dataclass(frozen=True)
class Node:
    """Base for every AST node; carries its source position."""

    source_pos: SourcePosition


@dataclass(frozen=True)
class Block(Node):
    """An ordered statement list ({ ... } body or the file root)."""

    statements: tuple[Node, ...] = ()


@dataclass(frozen=True)
class KeywordArg(Node):
    """One keyword plus its raw value span; filled on walk."""

    keyword: str
    negated: bool
    value_span: tuple[Token, ...]


@dataclass(frozen=True)
class RuleNode(Node):
    """A rule statement captured as a raw span up to ';' (sliced on walk)."""

    span: tuple[Token, ...]


@dataclass(frozen=True)
class BlockNode(Node):
    """
    A nested { ... } block.

    On the walk path body stays None: the nested statements stream through a
    recursive enter() with their own Walker, so the walk never needs the
    body captured. Parser.parse_to_block is the only builder that fills body
    (for the structural analyzers).
    """

    body: Block | None = None


@dataclass(frozen=True)
class IfNode(Node):
    """
    @if node: condition span plus optional structured branch bodies.

    The condition is a raw token span, evaluated BEFORE either branch is
    sliced. On the WALK path both branch bodies stay None: branches are
    handled live via collect_tokens after the condition eval, never
    stored, and the untaken branch is never structured -- so byte-parity
    does not depend on these fields. The eval-free analyzer pass
    (Parser.parse_to_block) is the ONLY builder that populates
    then_body/else_body, making both branches visible to the structural
    analyzers. None encodes "not captured on this path", distinctly from
    an empty branch.
    """

    cond_span: tuple[Token, ...]
    then_body: Block | None = None
    else_body: Block | None = None


@dataclass(frozen=True)
class IncludeNode(Node):
    """@include: raw span resolved to a file (or glob/pipe) at runtime."""

    span: tuple[Token, ...]


@dataclass(frozen=True)
class PreserveNode(Node):
    """@preserve: raw span of a rule-preservation directive."""

    span: tuple[Token, ...]


@dataclass(frozen=True)
class HookNode(Node):
    """@hook: raw span of a pre/post/flush shell hook."""

    span: tuple[Token, ...]


@dataclass(frozen=True)
class HeaderNode(Node):
    """
    A domain/table/chain/priority/policy header.

    The boundary is ONE getvalues() expression, not ';'. The node kind
    (array-replay vs scalar header plus block) is a walk-time branch on
    isinstance(value, list).
    """

    keyword: str
    value_span: tuple[Token, ...]
    body: Block | None


@dataclass(frozen=True)
class FunctionCallNode(Node):
    """
    A block-form function call: &name(...) { ... };.

    BLOCK form only (a standalone statement waiting on ';'). An inline
    &name is NOT a node -- it preps into the current rule's span.
    """

    span: tuple[Token, ...]


@dataclass(frozen=True)
class SubchainNode(Node):
    """@subchain/@gotosubchain: chain declaration plus jump/goto."""

    span: tuple[Token, ...]


@dataclass(frozen=True)
class ArrayReplayNode(Node):
    """A domain/table/chain (a b) { ... } block replayed per array item."""

    header_keyword: str
    value_span: tuple[Token, ...]
    body_span: tuple[Token, ...]


@dataclass(frozen=True)
class DefNode(Node):
    """@def: raw span of a variable or function definition."""

    span: tuple[Token, ...]


@dataclass(frozen=True)
class SetNode(Node):
    """@set: raw span of an option assignment."""

    span: tuple[Token, ...]


@dataclass(frozen=True)
class RawShimNode(Node):
    """
    An un-promoted statement carried by the strangler shim.

    Holds the leading (keyword, negated) plus a raw span; replayed through
    the old streaming dispatch. Removed once every kind is promoted to a
    typed node.
    """

    keyword: object
    negated: bool
    span: tuple[Token, ...]


class NodeVisitor:
    """
    Dispatch visitor: visit_<ClassName>, no-op fallback.

    Walker (evaluation), find_unused_defs and find_undefined_chain_jumps
    are all NodeVisitors over the same tree.
    """

    def visit(self, node: Node) -> object:
        """Dispatch to visit_<ClassName>, or None when none is defined."""
        method = getattr(self, f"visit_{type(node).__name__}", None)
        if method is None:
            return None
        return method(node)
