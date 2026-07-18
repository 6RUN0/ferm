"""
Structural coverage for the eval-free Parser.parse_to_block.

parse_to_block builds a retained tree over BOTH @if branches without
evaluating conditions, substituting variables, loading modules or resolving
@include. It is off the golden/parity path -- these tests pin the structure
the analyzers consume.
"""

from __future__ import annotations

from pyferm.parser import MAX_BLOCK_DEPTH, Parser
from pyferm.tree import Block, BlockNode, DefNode, HeaderNode, IfNode, RuleNode


def _block(config: str) -> Block:
    return Parser.parse_to_block(config)


def test_match_block_nests_as_structured_block() -> None:
    # `saddr $x { ... }` must nest the block body as a BlockNode the analyzers
    # descend into -- NOT be lumped into one RuleNode span (the arity-blind
    # capture used to do that, hiding inner decls/jumps/$vars).
    root = _block("saddr $x { table filter chain FOO { jump BAR; } }\n")
    kinds = [type(n).__name__ for n in root.statements]
    assert kinds == ["RuleNode", "BlockNode"]
    rule, block = root.statements
    assert isinstance(rule, RuleNode)
    assert rule.span == ("saddr", "$", "x")  # $x still visible for unused-defs
    assert isinstance(block, BlockNode)
    assert isinstance(block.body, Block)
    header = block.body.statements[0]
    assert isinstance(header, HeaderNode)  # chain FOO now a HeaderNode
    assert isinstance(header.body, Block)
    inner_rule = header.body.statements[0]
    assert isinstance(inner_rule, RuleNode)
    assert inner_rule.span == ("jump", "BAR", ";")  # inner jump visible


def test_directive_block_body_is_not_split() -> None:
    # A @def with a { } body keeps the whole body in its span (stop_at_brace is
    # off for directives), so it is one DefNode, not a Def + a stray block.
    root = _block("@def &svc($p) = { proto tcp dport $p ACCEPT; }\n")
    assert [type(n).__name__ for n in root.statements] == ["DefNode"]
    defn = root.statements[0]
    assert isinstance(defn, DefNode)
    assert defn.span[-1] == "}"  # body retained through the closing brace


def test_if_captures_both_branch_bodies() -> None:
    root = _block("@if 1 { A; } @else { B; }\n")
    ifs = [n for n in root.statements if isinstance(n, IfNode)]
    assert len(ifs) == 1
    node = ifs[0]
    # BOTH branches are structured Blocks -- the key capability the walk lacks.
    assert isinstance(node.then_body, Block)
    assert isinstance(node.else_body, Block)


def test_untaken_branch_is_structured_without_eval() -> None:
    # @if 0 does NOT evaluate to skip structuring -- parse_to_block sees the
    # body.
    root = _block("@if 0 { table filter chain INPUT { saddr $x ACCEPT; } }\n")
    ifs = [n for n in root.statements if isinstance(n, IfNode)]
    assert len(ifs) == 1
    then_body = ifs[0].then_body
    assert isinstance(then_body, Block)
    # non-empty: the untaken body is present
    assert then_body.statements


def test_long_else_if_chain_does_not_recursion_error() -> None:
    # @else @if used to recurse directly, bypassing the depth guard
    # parse_block enforces for ordinary nesting -- a long else-if chain blew
    # the Python recursion limit instead of being handled like any other
    # input.
    link_count = 2000
    cfg = "@if 1 {} @else " * link_count + "{}\n"

    root = _block(cfg)  # must not raise RecursionError

    node = root.statements[0]
    assert isinstance(node, IfNode)
    seen = 0
    while True:
        seen += 1
        else_body = node.else_body
        assert isinstance(else_body, Block)
        if len(else_body.statements) == 1 and isinstance(
            else_body.statements[0], IfNode
        ):
            node = else_body.statements[0]
            continue
        # the final plain @else block: the chain is fully represented, not
        # truncated by an early depth cutoff.
        assert else_body.statements == ()
        break
    assert seen == link_count


# -- structural shape asserts (mutation-hardening) -------------------------
#
# The tests above pin node *types*; these pin the retained tree's SHAPE --
# source positions, header terminators, nesting depth bookkeeping and the
# over-deep skip -- the seams the arity-blind capture used to blur.


def test_every_node_carries_a_source_position() -> None:
    """
    Each structured node keeps a non-null ``source_pos`` (its file:line).

    The eval-free build threads ``self._pos()`` into every node; a dropped
    position would surface as ``None`` and break the analyzers' locating.
    """
    root = _block(
        "chain INPUT ACCEPT;\ntable nat chain POSTROUTING MASQUERADE;\n"
    )
    # the returned Block itself carries a position (parse_block's own pos,
    # captured before the first line sentinel, so line 0)
    assert root.source_pos is not None
    assert root.source_pos.line == 0
    header, rule_or_header = root.statements
    assert isinstance(header, HeaderNode)
    assert header.source_pos is not None
    assert header.source_pos.line == 1
    assert rule_or_header.source_pos is not None


def test_nested_block_carries_a_source_position() -> None:
    """A nested block (recursive parse_block) keeps its own ``source_pos``."""
    root = _block("chain INPUT { jump X; }\n")
    header = root.statements[0]
    assert isinstance(header, HeaderNode)
    # the header itself, not just its nested body -- _parse_header's
    # terminator == "{" branch builds the HeaderNode with its own pos.
    assert header.source_pos is not None
    assert header.body is not None
    assert header.body.source_pos is not None


def test_bare_rule_statement_carries_a_source_position() -> None:
    """
    A plain rule (not a header/directive/@if/block) keeps its own position.

    ``_parse_statement``'s final fallback builds the ``RuleNode`` from the
    same ``pos`` captured at entry; a dropped ``pos`` there would only show
    up on this bare-rule path (headers, directives and blocks each pass
    their own position through a different branch).
    """
    root = _block("chain INPUT { jump X; }\n")
    header = root.statements[0]
    assert isinstance(header, HeaderNode)
    assert header.body is not None
    rule = header.body.statements[0]
    assert isinstance(rule, RuleNode)
    assert rule.source_pos is not None
    assert rule.source_pos.line == 1


def test_if_node_carries_a_source_position() -> None:
    """
    Both the outer ``IfNode`` and each ``@else @if`` link keep a real
    ``source_pos`` -- ``_parse_statement`` threads its own ``pos`` into
    ``_parse_if``, which in turn seeds ``current_pos`` from it for the first
    link (subsequent links re-derive their own position at each ``@else``).
    """
    root = _block("@if 1 {} @else {}\n")
    node = root.statements[0]
    assert isinstance(node, IfNode)
    assert node.source_pos is not None
    assert node.source_pos.line == 1


def test_malformed_if_then_branch_without_brace_keeps_a_position() -> None:
    """
    A "then" branch missing its ``{ ... }`` still gets an (empty) ``Block``
    that carries the ``@if``'s own position, not ``None``.

    A condition terminated by ``;`` instead of ``{`` (malformed input) makes
    ``_parse_branch_block`` take its no-brace fallback.
    """
    root = _block("@if 1 ;\n")
    node = root.statements[0]
    assert isinstance(node, IfNode)
    assert node.then_body is not None
    assert node.then_body.statements == ()
    assert node.then_body.source_pos is not None


def test_malformed_final_else_branch_without_brace_keeps_a_position() -> None:
    """
    A final ``@else`` not followed by ``{`` still gets an (empty) ``Block``
    carrying the current position, not ``None``.
    """
    root = _block("@if 1 {} @else 2;\n")
    node = root.statements[0]
    assert isinstance(node, IfNode)
    assert node.else_body is not None
    assert node.else_body.statements == ()
    assert node.else_body.source_pos is not None


def test_directive_node_keeps_its_position() -> None:
    """A @def directive keeps a real ``source_pos`` (a dropped pos is None)."""
    root = _block("@def $x = 1;\n")
    directive = root.statements[0]
    assert isinstance(directive, DefNode)
    assert directive.source_pos is not None
    assert directive.source_pos.line == 1


def test_semicolon_header_terminator_is_consumed() -> None:
    """
    A ``;``-terminated header consumes the ``;`` and yields exactly one
    body-less HeaderNode, so a following statement stands on its own.

    The terminator test (``terminator == ";"``) and the ``self._i += 1`` that
    swallows it are both load-bearing: mis-flipping either leaves the ``;`` in
    the stream as a stray statement.
    """
    root = _block("domain ip;\nchain INPUT ACCEPT;\n")
    assert [type(n).__name__ for n in root.statements] == [
        "HeaderNode",
        "HeaderNode",
    ]
    first, second = root.statements
    assert isinstance(first, HeaderNode)
    assert isinstance(second, HeaderNode)
    assert (first.keyword, first.body) == ("domain", None)
    assert (second.keyword, second.body) == ("chain", None)


def test_header_value_scan_stops_at_close_brace() -> None:
    """
    A body-less header inside a block ends its value scan at the block's ``}``.

    ``_scan_header_value`` must treat a top-level ``}`` as a value terminator;
    losing it would swallow the block's close and mis-nest the tree.
    """
    root = _block("{ table filter }\n")
    outer = root.statements[0]
    assert isinstance(outer, BlockNode)
    assert outer.body is not None
    inner = outer.body.statements[0]
    assert isinstance(inner, HeaderNode)
    assert inner.keyword == "table"
    assert inner.value_span == ("filter",)
    assert inner.body is None


def test_header_value_scan_keeps_parenthesised_array() -> None:
    """A parenthesised header value is captured whole, parens included."""
    root = _block("chain (A B) { jump X; }\n")
    header = root.statements[0]
    assert isinstance(header, HeaderNode)
    assert header.value_span == ("(", "A", "B", ")")
    assert header.body is not None
    assert len(header.body.statements) == 1


def test_directive_span_retains_nested_braces() -> None:
    """
    A directive body with nested ``{ }`` keeps every brace in its span.

    ``_capture_statement_span`` tracks brace depth so a directive's own body
    (``stop_at_brace`` off) is not cut at the first inner ``}``; a broken
    depth counter would truncate the span there.
    """
    root = _block("@def &f() = { proto tcp { dport 22 ACCEPT; } }\n")
    directive = root.statements[0]
    assert isinstance(directive, DefNode)
    assert directive.span == (
        "@def",
        "&",
        "f",
        "(",
        ")",
        "=",
        "{",
        "proto",
        "tcp",
        "{",
        "dport",
        "22",
        "ACCEPT",
        ";",
        "}",
        "}",
    )


def test_directive_span_ends_at_top_level_semicolon_after_block() -> None:
    """
    A directive's span tracks brace depth so a ``;`` inside its ``{ }`` body
    does not end it, but the first ``;`` back at top level does.

    ``_capture_statement_span`` bumps depth on ``{`` and drops it on ``}``; a
    broken brace counter would either cut the span inside the body or run past
    the terminating ``;`` and swallow the following statement.
    """
    root = _block("@def &f() = { proto tcp; } ; chain INPUT ACCEPT;\n")
    assert [type(n).__name__ for n in root.statements] == [
        "DefNode",
        "HeaderNode",
    ]
    directive, header = root.statements
    assert isinstance(directive, DefNode)
    # the body's inner ';' stayed inside the span; the top-level ';' closed it
    assert directive.span[-1] == ";"
    assert directive.span.count(";") == 2
    assert isinstance(header, HeaderNode)
    assert header.keyword == "chain"


def test_sequential_blocks_do_not_exhaust_the_depth_counter() -> None:
    """
    Many *sequential* blocks all structure -- depth is decremented on exit.

    ``parse_block`` bumps ``self._depth`` on entry and drops it on exit; if the
    finally-decrement were wrong, a long run of sibling blocks would climb past
    MAX_BLOCK_DEPTH and start getting skipped instead of structured.
    """
    count = MAX_BLOCK_DEPTH + 50
    root = _block("{ jump A; } " * count)
    assert len(root.statements) == count
    assert all(
        isinstance(n, BlockNode) and n.body is not None and n.body.statements
        for n in root.statements
    )


def test_over_deep_nesting_skips_subtree_and_recovers_sibling() -> None:
    """
    Nesting past MAX_BLOCK_DEPTH skips the subtree but recovers the next
    sibling.

    The depth cap routes the pathological subtree through
    ``_skip_to_block_end``, which must consume EXACTLY the matching ``}`` run
    so a trailing top-level statement is still structured. A mis-counted skip
    would eat (or leak) a brace and lose the sibling.
    """
    depth = MAX_BLOCK_DEPTH + 2
    config = (
        "chain INPUT "
        + "{ " * depth
        + "jump X; "
        + "} " * depth
        + "table nat chain P MASQUERADE;\n"
    )
    root = _block(config)
    assert [type(n).__name__ for n in root.statements] == [
        "HeaderNode",
        "HeaderNode",
    ]
    deep_header, sibling = root.statements
    assert isinstance(deep_header, HeaderNode)
    assert deep_header.keyword == "chain"
    assert isinstance(sibling, HeaderNode)
    assert sibling.keyword == "table"
