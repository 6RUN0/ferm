"""
Walk-driven evaluator over the structural AST (strangler facade).

Skeleton layer: every statement is a RawShimNode; the walker replays it
through the existing streaming dispatch bound on the parser for the current
block. This is a pure pass-through over streaming -- the dispatch reads each
statement's operands live from the tokenizer exactly as before -- so golden
stays byte-identical. Later layers replace RawShimNode kinds with typed nodes
and real visit_* methods that read captured spans through a script.tokens swap.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .tree import NodeVisitor

if TYPE_CHECKING:
    from collections.abc import Callable

    from .parser import NegatedFlag, Parser
    from .tree import RawShimNode


class Walker(NodeVisitor):
    """
    Drives evaluation over the AST by delegating to the parser.

    Bound per block to that block's streaming dispatch (handle), so the
    mutable per-statement state (the pending rule, the scope) stays where it
    always lived -- inside the parser -- while this facade owns statement
    order.
    """

    def __init__(
        self,
        parser: Parser,
        dispatch: Callable[[object, NegatedFlag], str],
    ) -> None:
        """Bind the walker to a parser and the current block's dispatch."""
        self.parser = parser
        self._dispatch = dispatch

    def replay_shim(self, node: RawShimNode, negated: NegatedFlag) -> str:
        """
        Replay an un-promoted statement through the streaming dispatch.

        The dispatch consumes this statement's operands live from the
        tokenizer. The live NegatedFlag -- which a handler may clear when it
        legitimately consumes the negation, and the caller re-checks
        afterwards -- is threaded as an argument because a frozen node cannot
        carry mutable state.
        """
        return self._dispatch(node.keyword, negated)
