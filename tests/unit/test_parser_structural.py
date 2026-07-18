"""
Mutation-hardening for the span/replay/structural parser seam (cluster C).

Every test here pins a real, observable gap: baseline passes and the named
mutant fails. Assertions read parser state -- the eval-free structural tree
behind ``Parser.parse_to_block`` (``--lint``/``--graph``), one unfolded chain
list, or located error output -- never golden emission.

The eval-path span/replay mutants (``_capture_rule_span`` boundary moves,
``_replay_array`` handle/line/base-level restores, ``mkrules2`` domain) are
deliberately absent: ``visit_RuleNode`` re-splits an over-captured span at
each ``;``/``}`` and streaming rule accumulation spans line sentinels, so
those mutations leave the emitted rules byte-identical (equivalent, verified).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.config import Options
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.parser import Parser
from pyferm.scope import OptionKind
from pyferm.tree import Block, HeaderNode, IfNode
from tests.unit._parse import parse_source

if TYPE_CHECKING:
    from pyferm.rules import RenderedRule


def _parse(source: str, *, options: Options | None = None) -> Parser:
    """Parse *source* through ``Parser.enter`` and return the parser."""
    return parse_source(source, options=options)


def _block(config: str) -> Block:
    """Structure *config* through the eval-free ``Parser.parse_to_block``."""
    return Parser.parse_to_block(config)


def _opts(rule: RenderedRule) -> list[tuple[str, object, OptionKind]]:
    """Return a rendered rule's options as ``(name, value, kind)`` tuples."""
    return [(o.name, o.value, o.kind) for o in rule.options]


# -- _capture_rule_span: the seed line sentinel ----------------------------


def test_capture_rule_span_seeds_the_line_for_a_single_line_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    The seed line sentinel carries a single-line rule's line into its error.

    A one-line rule has only the seed to locate it on replay; seeding a null
    line reports ``line None`` instead of ``line 1`` when the replay errors.
    """
    with pytest.raises(FermError):
        _parse("chain INPUT proto tcp;\n")
    assert "line 1" in capsys.readouterr().err


# -- _replay_array ---------------------------------------------------------


def test_replay_array_continues_past_a_filtered_domain() -> None:
    """
    A filtered-out array element is skipped, not the whole replay aborted.

    With a ``--domain ip`` filter the leading ``ip6`` builds to None; the
    per-element loop must ``continue`` to reach ``ip``, not ``break`` and
    drop it, so the ``ip`` INPUT chain still gets its rule.
    """
    parser = _parse(
        "domain (ip6 ip) { chain INPUT ACCEPT; }\n",
        options=Options(test=True, domain="ip"),
    )
    assert "ip6" not in parser.domains
    inp = parser.domains[Family.IP].tables["filter"].chains["INPUT"].rules
    assert len(inp) == 1
    assert _opts(inp[0]) == [("jump", "ACCEPT", OptionKind.TARGET)]


# -- _StructuralParser (Parser.parse_to_block) -----------------------------


def test_parse_to_block_threads_the_filename_into_positions() -> None:
    """
    Every structured node carries the ``<parse_to_block>`` file in its pos.

    The filename flows literal -> ``Script`` -> ``_StructuralParser`` ->
    ``self._filename`` -> ``_pos``; nulling or garbling it at any hop surfaces
    as an altered ``source_pos.filename`` on the nodes.
    """
    root = _block("chain INPUT ACCEPT;\n")
    assert root.source_pos.filename == "<parse_to_block>"
    header = root.statements[0]
    assert header.source_pos.filename == "<parse_to_block>"


def test_parse_to_block_if_without_else_keeps_else_body_none() -> None:
    """
    An ``@if`` with no ``@else`` leaves ``else_body`` as None, not a stub.

    Seeding ``final_else`` to anything but None hands the innermost link a
    truthy placeholder in place of the "no else branch" sentinel.
    """
    root = _block("@if 1 { A; }\n")
    node = root.statements[0]
    assert isinstance(node, IfNode)
    assert node.else_body is None


def test_parse_to_block_if_condition_excludes_the_if_keyword() -> None:
    """
    The captured condition span starts after ``@if``, not at the file head.

    Nulling ``cond_start`` slices from index 0, pulling ``@if`` (and the
    leading line sentinel) into the condition span.
    """
    root = _block("@if 1 { A; }\n")
    node = root.statements[0]
    assert isinstance(node, IfNode)
    assert "@if" not in node.cond_span
    assert "1" in node.cond_span


def test_parse_to_block_else_if_link_keeps_a_position() -> None:
    """
    A chained ``@else @if`` link re-derives a real position per link.

    The nested ``IfNode`` and its wrapping else ``Block`` both carry a
    non-null ``source_pos``; nulling the per-link ``current_pos`` or the
    wrapper block's position drops it.
    """
    root = _block("@if 1 {} @else @if 2 {}\n")
    node = root.statements[0]
    assert isinstance(node, IfNode)
    assert node.else_body is not None
    assert node.else_body.source_pos is not None
    inner = node.else_body.statements[0]
    assert inner.source_pos is not None


def test_parse_to_block_bare_block_keeps_a_position() -> None:
    """
    A bare ``{ ... }`` block node carries its own ``source_pos``.

    ``_parse_statement`` threads its entry ``pos`` into the ``BlockNode``;
    nulling it drops the block's location.
    """
    root = _block("{ jump X; }\n")
    node = root.statements[0]
    assert node.source_pos is not None
    assert node.source_pos.line == 1


def test_parse_to_block_header_without_terminator_stops_at_eof() -> None:
    """
    A header value scan that reaches EOF stops instead of over-running.

    The ``self._i < len(tokens)`` bound must be strict; a ``<=`` bound runs
    one iteration past the token list at end of input and indexes out of it.
    """
    root = _block("chain INPUT")
    header = root.statements[0]
    assert isinstance(header, HeaderNode)
    assert header.keyword == "chain"
