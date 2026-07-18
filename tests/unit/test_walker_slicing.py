"""
Per-keyword rule slicing parity (both negation forms), vs the oracle.

These are differential cases pinned before RuleNode is promoted: the raw rule
span is sliced into keyword arguments on the walk, after modules load, so arity
depends on runtime-loaded modules (mod $var) and a negated keyword identity
must resolve via getvar BEFORE its arity is known (! $var).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.domains import Family
from pyferm.scope import OptionKind
from tests.property.differential_cli import assert_cli_parity
from tests.unit._parse import parse_source

if TYPE_CHECKING:
    from pyferm.parser import Parser
    from pyferm.rules import RenderedRule


def _rules(
    parser: Parser, domain: Family, table: str, chain: str
) -> list[RenderedRule]:
    """Return the unfolded rules of one chain."""
    return parser.domains[domain].tables[table].chains[chain].rules


def _options(rule: RenderedRule) -> list[tuple[str, object, OptionKind]]:
    """Return a rule's options as ``(name, value, kind)`` tuples."""
    return [(opt.name, opt.value, opt.kind) for opt in rule.options]


@pytest.mark.usefixtures("require_perl")
def test_mod_var_gates_keyword_arity() -> None:
    # ctstate becomes a valid keyword only after `mod conntrack` -- arity of
    # the sliced arg depends on the runtime-loaded module.
    assert_cli_parity(
        "@def $m = conntrack;\n"
        "table filter chain INPUT { "
        "mod $m ctstate (NEW ESTABLISHED) ACCEPT; }\n"
    )


@pytest.mark.usefixtures("require_perl")
def test_value_negation() -> None:
    assert_cli_parity(
        "table filter chain INPUT { proto tcp dport ! 22 ACCEPT; }\n"
    )


@pytest.mark.usefixtures("require_perl")
def test_keyword_negation_via_var() -> None:
    # `! $k` -- the KEYWORD itself (and its arity) is resolved from the
    # variable at runtime via getvar(); slicing must resolve the negated
    # keyword position BEFORE determining arity. ctstate is negatable with a
    # comma-array arity>=1, so the (NEW ESTABLISHED) argument is only sliced
    # correctly if the negated keyword identity resolves first.
    assert_cli_parity(
        "@def $k = ctstate;\n"
        "table filter chain INPUT { "
        "mod conntrack ! $k (NEW ESTABLISHED) ACCEPT; }\n"
    )


# -- Walker.visit_BlockNode: must return False and reseed from self.prev ----
#
# A nested { } block must never end the ENCLOSING block's statement loop
# (visit_BlockNode's return value is checked by the read loop in
# Parser._enter_body: a truthy result ends the whole level early), and the
# pending rule it resets to afterwards must inherit context from the
# BLOCK's own prev -- not from whatever leaked onto self.rule while parsing
# the nested block's own leading tokens.


def test_block_node_does_not_end_the_enclosing_level() -> None:
    # Two sibling nested blocks in one chain: if visit_BlockNode returned
    # True (instead of False) after the first, the second would never be
    # read, and only one rule would come out.
    parser = parse_source(
        "chain INPUT { proto tcp { ACCEPT; } proto udp { ACCEPT; } }"
    )
    rules = _rules(parser, Family.IP, "filter", "INPUT")
    assert [_options(r) for r in rules] == [
        [
            ("protocol", "tcp", OptionKind.PROTO),
            ("jump", "ACCEPT", OptionKind.TARGET),
        ],
        [
            ("protocol", "udp", OptionKind.PROTO),
            ("jump", "ACCEPT", OptionKind.TARGET),
        ],
    ]


def test_block_node_reseeds_trailing_rule_from_its_own_prev() -> None:
    # After the nested "proto tcp { ACCEPT; }" block, a trailing rule in the
    # SAME enclosing block must inherit the chain (INPUT) from the block's
    # own prev, and must NOT carry over "proto tcp" (which only applied to
    # the nested rule) -- reseeding from None would lose the chain entirely
    # and error "Chain must be specified".
    parser = parse_source("chain INPUT { proto tcp { ACCEPT; } DROP; }")
    rules = _rules(parser, Family.IP, "filter", "INPUT")
    assert [_options(r) for r in rules] == [
        [
            ("protocol", "tcp", OptionKind.PROTO),
            ("jump", "ACCEPT", OptionKind.TARGET),
        ],
        [("jump", "DROP", OptionKind.TARGET)],
    ]


# -- Walker.visit_HeaderNode: an array-valued header must reseed from prev --


def test_header_array_replay_reseeds_trailing_rule_from_prev() -> None:
    # "table (filter nat)" is an array-valued header inside a nested chain
    # block: per _parse_header, each array item replays its own rule (so
    # ACCEPT lands in both filter/INPUT and nat/INPUT), but the pending rule
    # returned afterwards must reseed via new_level(self.prev) -- passing
    # None instead would drop the inherited chain and the trailing DROP
    # would error "Chain must be specified".
    parser = parse_source("chain INPUT { table (filter nat) ACCEPT; DROP; }")
    filter_rules = _rules(parser, Family.IP, "filter", "INPUT")
    nat_rules = _rules(parser, Family.IP, "nat", "INPUT")
    assert [_options(r) for r in filter_rules] == [
        [("jump", "ACCEPT", OptionKind.TARGET)],
        [("jump", "DROP", OptionKind.TARGET)],
    ]
    assert [_options(r) for r in nat_rules] == [
        [("jump", "ACCEPT", OptionKind.TARGET)],
    ]
