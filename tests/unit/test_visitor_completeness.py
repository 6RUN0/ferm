"""
Completeness gates for the two dispatch-by-name mechanisms over the AST.

Both `NodeVisitor.visit` (pyferm.tree) and `Parser._visit_stmt_node`
(pyferm.parser) route by name (`getattr`/if-elif) with a silent no-op /
None fallback on a miss -- neither raises when a node kind or keyword is
forgotten. These tests turn that silent fallback into a hard failure by
enumerating the source of truth (`Node.__subclasses__()`, `_STMT_NODES`)
dynamically, so a future node kind or keyword forces either a matching
`visit_*` method or a conscious addition to an explicit ignore list.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING, Final

import pytest

from pyferm.analysis import _ChainCollector, _DefCollector
from pyferm.config import Options
from pyferm.functions import Evaluator
from pyferm.parser import _STMT_NODES, Parser
from pyferm.scope import Frame, Scope
from pyferm.tokenizer import Script, Tokenizer
from pyferm.tree import Node
from pyferm.walker import Walker

if TYPE_CHECKING:
    from collections.abc import Iterable


def _all_node_subclasses(base: type[Node]) -> set[type[Node]]:
    """Collect every (transitively nested) subclass of ``base``."""
    found: set[type[Node]] = set()
    frontier: list[type[Node]] = [base]
    while frontier:
        cls = frontier.pop()
        for sub in cls.__subclasses__():
            if sub not in found:
                found.add(sub)
                frontier.append(sub)
    return found


_NODE_CLASSES: Final[set[type[Node]]] = _all_node_subclasses(Node)


def _missing_visit_methods(
    visitor_cls: type, classes: Iterable[type[Node]]
) -> set[str]:
    """Return the names of node classes ``visitor_cls`` has no visit_* for."""
    return {
        cls.__name__
        for cls in classes
        if not hasattr(visitor_cls, f"visit_{cls.__name__}")
    }


# -- GATE: NodeVisitor.visit completeness (Walker + structural analyzers) --

#: Block is iterated via its own .statements by every visitor here, never
#: visited itself -- so it is not a coverage gap.
_WALKER_IGNORED: Final = frozenset({"Block"})

#: _DefCollector only cares about declarations (@def) and leaf token spans
#: that can mention a $var (@set, a rule, an @if condition); the other node
#: kinds carry no var reference of their own.
_DEF_COLLECTOR_IGNORED: Final = frozenset(
    {
        "Block",
        "BlockNode",
        "HeaderNode",
        "HookNode",
        "IncludeNode",
        "PreserveNode",
        "SubchainNode",
    }
)

#: _ChainCollector only cares about chain-declaration sites (a header, a
#: subchain) and jump/goto targets (a rule); the other node kinds declare no
#: chain and issue no jump.
_CHAIN_COLLECTOR_IGNORED: Final = frozenset(
    {
        "Block",
        "BlockNode",
        "DefNode",
        "HookNode",
        "IfNode",
        "IncludeNode",
        "PreserveNode",
        "SetNode",
    }
)


def test_walker_covers_every_node_class_but_block() -> None:
    # A missing set that grows beyond {"Block"} means some node kind
    # silently no-ops on the walk path (NodeVisitor.visit's getattr
    # fallback) instead of being evaluated.
    assert _missing_visit_methods(Walker, _NODE_CLASSES) == _WALKER_IGNORED


def test_def_collector_covers_or_ignores_every_node_class() -> None:
    assert (
        _missing_visit_methods(_DefCollector, _NODE_CLASSES)
        == _DEF_COLLECTOR_IGNORED
    )


def test_chain_collector_covers_or_ignores_every_node_class() -> None:
    assert (
        _missing_visit_methods(_ChainCollector, _NODE_CLASSES)
        == _CHAIN_COLLECTOR_IGNORED
    )


# -- GATE: _visit_stmt_node routes every _STMT_NODES key --------------------

#: Sentinel returned by _RecordingWalker.visit, distinct from any real
#: visit_* return value (a "next"/"return" str), so a stray string match
#: cannot pass the routed-through assertion by accident.
_ROUTED: Final = object()


class _RecordingWalker(Walker):
    """
    A Walker stand-in that records the node routed to it instead of
    dispatching to a typed visit_* handler.

    Subclassing Walker (rather than duck-typing) keeps this a legitimate
    argument for `Parser._visit_stmt_node(walker: Walker, ...)` while
    overriding only `visit`, the single method `_visit_stmt_node` calls.
    """

    def __init__(self, parser: Parser) -> None:
        """Open a Walker with no real block context; only visit() is used."""
        super().__init__(parser, level=0, prev=None, base_level=0)
        self.routed: Node | None = None

    def visit(self, node: Node) -> object:
        """Record ``node`` and return a sentinel instead of dispatching."""
        self.routed = node
        return _ROUTED


def _make_parser() -> Parser:
    """Build a Parser wired to an empty script -- enough state for routing."""
    script = Script(filename="<test>", handle=io.StringIO(""))
    tokenizer = Tokenizer(script)
    scope = Scope()
    scope.push(Frame())
    evaluator = Evaluator(tokenizer, scope)
    return Parser(evaluator, {}, Options(test=True))


@pytest.mark.parametrize("keyword", sorted(_STMT_NODES))
def test_visit_stmt_node_routes_every_stmt_node_key(keyword: str) -> None:
    """
    Every `_STMT_NODES` key must reach its typed node via `_visit_stmt_node`.

    `_dispatch_leading` consumes the leading token before `_visit_stmt_node`
    confirms it can route it (see test_routing_sets.py's set-equality gate).
    If a future keyword were added to `_STMT_NODES` (and `_STMT_KEYWORDS`)
    without a matching branch in `_visit_stmt_node`'s hand-written if/elif
    chain, the token would already be consumed and the routing call would
    return None, silently producing a headless rule. Parametrizing over
    `_STMT_NODES` (not a hardcoded keyword list) keeps this test aligned as
    the dict grows.
    """
    parser = _make_parser()
    walker = _RecordingWalker(parser)
    result = parser._visit_stmt_node(walker, keyword)
    assert result is _ROUTED
    assert type(walker.routed) is _STMT_NODES[keyword]
