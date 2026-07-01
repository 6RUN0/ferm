"""Arity-agnostic rule-span capture: boundary parity with the oracle.

_capture_rule_span never decides operand-vs-block; it keeps every top-level
{...} block in the span and lets the replay (visit_RuleNode) decide token by
token, exactly as the streaming oracle does. A keyword still awaiting a value
reads a `{`/`}` and its value-reader rejects it ("'{' not allowed here"),
while between keywords a `{` re-routes to a nested block. These pin byte-parity
(stderr + exit verdict) for the whole boundary class the capture used to miss.
"""

from tests.property.differential_cli import assert_cli_parity


def test_proto_operand_is_brace() -> None:
    assert_cli_parity("table filter chain INPUT { proto { }\n")


def test_saddr_operand_is_brace() -> None:
    assert_cli_parity("table filter chain INPUT { saddr { }\n")


def test_dport_operand_is_brace() -> None:
    assert_cli_parity("table filter chain INPUT { proto tcp dport { }\n")


def test_mod_operand_is_brace() -> None:
    assert_cli_parity("table filter chain INPUT { mod { }\n")


def test_negated_def_operand_is_brace() -> None:
    assert_cli_parity("! def {\n")


def test_negated_port_only_priority_falls_to_leaf() -> None:
    # priority is port-only; a negated `! priority` must be unrecognized like
    # the oracle, not run the port feature (route_resolved excludes it).
    assert_cli_parity("table filter chain INPUT { ! priority ; }\n")
    assert_cli_parity("table filter chain INPUT { ! priority }\n")


def test_negated_recognized_header_runs_then_negation() -> None:
    assert_cli_parity("! domain ip;\ntable filter chain INPUT { ACCEPT; }\n")


def test_match_block_still_streams() -> None:
    assert_cli_parity("chain INPUT { saddr 1.2.3.4 { ACCEPT; } }\n")


def test_missing_semicolon_before_brace() -> None:
    assert_cli_parity("table filter chain INPUT { proto tcp ACCEPT }\n")
