"""
Walk-driven evaluator over the structural AST (strangler facade).

The per-block Walker owns statement order and the mutable dispatch state of
one block -- the pending rule and the last-seen keyword -- which used to be
_enter_body closure cells. Every typed visit_* method mutates that ONE rule,
so a promoted { or @if cannot desync from matches a preceding statement
accumulated -- e.g. the saddr in ``saddr 1.2.3.4 { ACCEPT; }`` must reach the
nested rule.

Each statement is a typed node visited here; the leaf rule keywords and the
bare control tokens (; } @else) that are not promoted stay in the parser's
residual handle(), bound as self.dispatch and self.route. visit_RuleNode swaps
a captured rule span into the tokenizer and replays it through the same router
and leaf dispatch, so an over-captured promoted keyword never bypasses its
typed path.
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
        HeaderNode,
        HookNode,
        IfNode,
        IncludeNode,
        PreserveNode,
        RuleNode,
        SetNode,
        SubchainNode,
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
        #: Bound to Parser._visit_stmt_node: routes an already-consumed
        #: statement keyword to its typed node. Used when a leading ``!``
        #: resolves to a promoted keyword (``! def``), so the resolved keyword
        #: reaches its typed path instead of the (now def-less) leaf handle.
        self.route_resolved: Callable[[object], object | None] | None = None

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
        assert self.route is not None
        assert self.route_resolved is not None
        tokenizer = self.parser.tokenizer
        script = tokenizer.script
        old_tokens = script.tokens
        old_line = script.line
        old_handle = script.handle
        old_tokens.appendleft(make_line_token(script.line))
        script.handle = None
        try:
            script.tokens = deque(node.span)
            while True:
                # A promoted kind (a { or @if from inline &function expansion,
                # or a header/@def/... over-captured by the subchain over-read)
                # is routed to its typed node via the SAME router the read loop
                # uses, so it never bypasses its typed path.
                lead = tokenizer.peek_token()
                if lead is None:
                    break
                result = self.route(lead)
                if result is None:
                    keyword, negated = self.resolve(tokenizer.next_token())
                    self.shown_keyword = keyword
                    # A leading ``!`` resolves to a promoted keyword
                    # (``! def``) only here, after the raw-lead router passed;
                    # route the resolved keyword to its typed node so it is not
                    # lost to the leaf handle, then report a leftover negation.
                    result = self.route_resolved(keyword)
                    if result is None:
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

    def visit_IncludeNode(self, node: IncludeNode) -> str:  # noqa: ARG002
        """Include another file/glob/pipe (@include), resolved at runtime."""
        self.parser._parse_include(self.rule, self.level)
        return "next"

    def visit_PreserveNode(self, node: PreserveNode) -> str:  # noqa: ARG002
        """Preserve matching live rules (@preserve), then reset the level."""
        self.parser._parse_preserve(self.rule)
        self.rule = new_level(self.prev)
        return "next"

    def visit_HookNode(self, node: HookNode) -> str:  # noqa: ARG002
        """Register a pre/post/flush shell hook (@hook)."""
        self.parser._parse_hook(self.rule)
        return "next"

    def visit_HeaderNode(self, node: HeaderNode) -> str:
        """
        Enter a domain/table/chain/policy/priority header.

        The value is read live; _parse_header branches on the runtime type
        (an array replays the block per item, a scalar sets the context) and
        returns the resulting pending rule.
        """
        self.rule = self.parser._parse_header(
            node.keyword, self.rule, self.prev
        )
        return "next"

    def visit_SubchainNode(self, node: SubchainNode) -> str:
        """Declare and enter an inline subchain (@subchain/@gotosubchain)."""
        self.rule.non_empty = True
        self.rule = self.parser._parse_subchain(
            node.keyword, self.rule, self.prev, self.level
        )
        return "next"
