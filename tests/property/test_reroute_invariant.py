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
