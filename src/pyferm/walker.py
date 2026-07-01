"""
Walk-driven evaluator over the structural AST (strangler facade).

The per-block Walker owns statement order and the mutable dispatch state of
one block -- the pending rule and the last-seen keyword -- which used to be
_enter_body closure cells. Both the RawShimNode shim and the typed visit_*
methods mutate that ONE rule, so a promoted { or @if cannot desync from
matches that a preceding shim statement accumulated -- e.g. the saddr in
``saddr 1.2.3.4 { ACCEPT; }`` must reach the nested rule.

Un-promoted statements are RawShimNodes replayed through the block's streaming
dispatch (handle); the dispatch reads their operands live from the tokenizer,
a pure pass-through that keeps golden byte-identical. Later layers replace more
RawShimNode kinds with typed nodes and real visit_* methods.
"""

# The Walker is the evaluator half of the split parser: it drives the
# Parser's own parse helpers (_parse_def, _include_file, ...) by design, so
# pyright's private-usage rule is off here (mirrors the ruff SLF001 ignore).
# pyright: reportPrivateUsage=false
from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from .errors import error, internal_error
from .scope import Frame, new_level
from .tokenizer import make_line_token
from .tree import NodeVisitor
from .values import eval_bool

if TYPE_CHECKING:
    from collections.abc import Callable

    from .parser import NegatedFlag, Parser
    from .scope import Rule
    from .tree import (
        BlockNode,
        DefNode,
        IfNode,
        RawShimNode,
        RuleNode,
        SetNode,
    )


class Walker(NodeVisitor):
    """
    Drives evaluation over one block's AST, holding its dispatch state.

    Bound per _enter_body call to that block's context (level/prev/base_level)
    and its streaming dispatch (handle). The pending ``rule`` and
    ``shown_keyword`` live here -- not on the parser -- because each nested
    block has its own, and both the shim and the typed visit_* methods must
    share the block's single rule.
    """

    def __init__(
        self,
        parser: Parser,
        level: int,
        prev: Rule | None,
        base_level: int,
    ) -> None:
        """Open a fresh per-block dispatch context for _enter_body."""
        self.parser = parser
        self.level = level
        self.prev = prev
        self.base_level = base_level
        self.rule: Rule = new_level(prev)
        self.shown_keyword: object = ""
        #: Bound to this block's handle() right after it is defined.
        self.dispatch: Callable[[object, NegatedFlag], str] | None = None
        #: Bound to Parser._resolve_keyword: negation + deprecated remap of a
        #: leading token (kept off the Walker to avoid a parser import cycle).
        self.resolve: Callable[[object], tuple[object, NegatedFlag]] | None = (
            None
        )
        #: Bound to Parser._dispatch_leading: routes a promoted non-rule
        #: leading token to its typed node, or returns None for a rule keyword
        #: / control token. Shared by the read loop and visit_RuleNode so an
        #: over-captured promoted keyword never bypasses its typed path.
        self.route: Callable[[object], object | None] | None = None

    def replay_shim(self, node: RawShimNode, negated: NegatedFlag) -> str:
        """
        Replay an un-promoted statement through the streaming dispatch.

        The dispatch consumes this statement's operands live from the
        tokenizer. The live NegatedFlag -- which a handler may clear when it
        legitimately consumes the negation, and the caller re-checks
        afterwards -- is threaded as an argument because a frozen node cannot
        carry mutable state.
        """
        assert self.dispatch is not None
        return self.dispatch(node.keyword, negated)

    def visit_BlockNode(self, node: BlockNode) -> str:  # noqa: ARG002
        """
        Enter a nested block, inheriting the current pending rule as context.

        Mirrors the streaming ``{`` handler: push a scope frame, recurse into
        enter() at the next level with self.rule as prev (so matches
        accumulated before the brace reach the nested rules), pop, then reset
        the pending rule to a fresh level. node.body is unused on the walk
        path -- the nested statements stream through the recursion.
        """
        parser = self.parser
        old_depth = len(parser.scope.stack)
        parser.scope.push(Frame(auto=dict(parser.scope.top.auto)))
        parser.enter(self.level + 1, self.rule)
        parser.scope.pop()
        if len(parser.scope.stack) != old_depth:
            raise internal_error()
        self.rule = new_level(self.prev)
        return "next"

    def visit_IfNode(self, node: IfNode) -> str:  # noqa: ARG002
        """
        Evaluate an @if condition first, then stream the taken branch.

        Mirrors the streaming ``@if`` handler: the condition is read live and
        evaluated BEFORE either branch is sliced (window B2). On true, nothing
        is touched -- the taken then-branch streams as the next BlockNode and
        any trailing ``@else`` body is swallowed by the @else shim. On false,
        the then-block is swallowed via collect_tokens; a following ``@else``
        is consumed so its block streams as the taken branch, otherwise the
        pending rule is reset. node.cond_span is unused here: the condition is
        read live, exactly as the streaming handler did.
        """
        parser = self.parser
        if not eval_bool(parser.evaluator.getvalues()):
            parser.evaluator.collect_tokens()
            token = parser.tokenizer.peek_token()
            if token is not None and token == "@else":
                parser.tokenizer.require_next_token()
            else:
                self.rule = new_level(self.prev)
        return "next"

    def visit_RuleNode(self, node: RuleNode) -> str:
        """
        Slice a captured rule span into keyword args on the walk.

        The raw span (up to ';', modules NOT yet loaded) is swapped into
        script.tokens and replayed through the streaming dispatch, mirroring
        _replay_array: detach the live handle, re-emit a line sentinel so the
        following statement's line stays correct, and restore in finally. The
        per-keyword cycle -- resolve (negation via getvar, deprecated remap),
        dispatch (arity slicing + mkrules on ';'), then the leftover-negation
        check -- is exactly the streaming loop, so both negation forms (value
        ``! v`` and keyword ``! $var``) produce the oracle's token stream. The
        shared self.rule carries any unfinished state (a missing ';') to the
        enclosing block's '}' handler.
        """
        assert self.dispatch is not None
        assert self.resolve is not None
        tokenizer = self.parser.tokenizer
        script = tokenizer.script
        old_tokens = script.tokens
        old_line = script.line
        old_handle = script.handle
        old_tokens.appendleft(make_line_token(script.line))
        script.handle = None
        assert self.route is not None
        try:
            script.tokens = deque(node.span)
            while True:
                # A promoted kind (a { or @if from inline &function expansion,
                # or a header/@def/... over-captured by the subchain over-read)
                # is routed to its typed node via the SAME router the read loop
                # uses, so it never bypasses its typed path. A rule keyword or
                # control token (route returns None) goes to the leaf dispatch.
                lead = tokenizer.peek_token()
                if lead is None:
                    break
                result = self.route(lead)
                if result is None:
                    keyword, negated = self.resolve(tokenizer.next_token())
                    result = self.dispatch(keyword, negated)
                    if negated.active:
                        error(
                            f"Doesn't support negation: {self.shown_keyword}"
                        )
                if result == "return":
                    return "return"
        finally:
            script.tokens = old_tokens
            script.handle = old_handle
            script.line = old_line
        return "next"

    def visit_DefNode(self, node: DefNode) -> str:  # noqa: ARG002
        """Define a variable or function (@def), reading operands live."""
        self.parser._parse_def(self.rule)
        return "next"

    def visit_SetNode(self, node: SetNode) -> str:  # noqa: ARG002
        """Declare a named nft set (@set), reading operands live."""
        self.parser._parse_set(self.rule)
        return "next"
