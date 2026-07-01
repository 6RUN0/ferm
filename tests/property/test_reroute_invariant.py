"""Re-route invariant: a promoted keyword over-captured into a rule span.

The subchain over-read in _capture_rule_span can absorb the statements that
follow a block-terminated subchain (no trailing ';') into the SAME rule span.
visit_RuleNode must route each such over-captured promoted keyword to its typed
node -- never replay it via the raw leaf dispatch -- or it would silently
bypass its typed path once handle() is gone. These pin byte-parity with the
Perl oracle for those over-read shapes.
"""

from tests.property.differential_cli import assert_cli_parity


def test_subchain_then_plain_rule() -> None:
    assert_cli_parity(
        "table filter chain INPUT { "
        "proto tcp @subchain { ACCEPT; } saddr 1.2.3.4 DROP; }\n"
    )


def test_two_subchains_same_block() -> None:
    assert_cli_parity(
        "table filter chain INPUT { "
        "proto tcp @subchain { ACCEPT; } proto udp @subchain { DROP; } }\n"
    )


def test_nested_subchain_in_subchain() -> None:
    assert_cli_parity(
        "table filter chain INPUT { interface eth1 @subchain { "
        "proto tcp @subchain { dport 22 ACCEPT; } } }\n"
    )


def test_def_after_subchain_same_block() -> None:
    # @def is over-captured after the block-terminated subchain; it must reach
    # visit_DefNode, not the leaf dispatch.
    assert_cli_parity(
        "table filter chain INPUT { "
        "proto tcp @subchain { ACCEPT; } @def $z = 1; saddr $z DROP; }\n"
    )


def test_negated_promoted_keyword_reaches_typed_path() -> None:
    # `! def` (leading `@!def` lexes to `!`, `def`): the negation resolves the
    # keyword only in visit_RuleNode, AFTER the raw-lead router; it must still
    # reach visit_DefNode, then report the leftover negation like the oracle.
    assert_cli_parity(
        "@!def $addr = 0.0.0.0;\ntable filter chain INPUT { ACCEPT; }\n"
    )


def test_negated_header_keyword() -> None:
    assert_cli_parity("! domain ip;\ntable filter chain INPUT { ACCEPT; }\n")


def test_bare_negation_before_brace() -> None:
    # `!`/`&`/jump/goto consume the next token; a top-level } right after is
    # that operand, so the replay must diagnose it, not hit end-of-file.
    assert_cli_parity("domain ip { table filter { chain extra { } } !}\n")


def test_inline_amp_before_brace() -> None:
    assert_cli_parity("domain ip { table filter { chain extra { } } &}\n")


def test_negated_header_operand_is_brace() -> None:
    assert_cli_parity("table filter chain INPUT { ! policy }\n")
