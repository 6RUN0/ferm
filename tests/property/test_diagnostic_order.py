"""Targeted differential cases for diagnostic ordering.

These are NOT fuzz cases: they pin the exact stderr ordering the streaming
oracle produces when an eval error precedes a structural one (and vice versa),
and the @if branch-swallow window (eval error in a condition over a brace
imbalance in the branch). Runs port vs Perl oracle, not a self-snapshot.
"""

from tests.property.differential_cli import assert_cli_parity


def test_eval_error_before_structural_error() -> None:
    # eval error on line 1 must stop BEFORE the structural error on line 2.
    assert_cli_parity("@def $x = $undef;\ndomain ip { ;\n")


def test_structural_error_before_eval_error() -> None:
    # symmetric: a structural problem earlier stops before a later eval error.
    assert_cli_parity("domain ip {\ntable filter chain INPUT { proto ;\n")


def test_if_false_swallows_broken_untaken_branch() -> None:
    # oracle swallows a broken untaken branch (missing ';') -- no diagnostic.
    assert_cli_parity("@if 0 { proto tcp ACCEPT }\n")


def test_if_true_swallows_broken_else() -> None:
    # @if 1 takes a valid then-branch and swallows the broken @else body
    # (a rule with no ';' and no chain context) without any diagnostic.
    assert_cli_parity("@if 1 { @def $y = 1; } @else { proto udp }\n")


def test_b2_eval_error_condition_over_brace_imbalance_then() -> None:
    # eval error in the CONDITION must be reported (no such variable), NOT
    # the brace imbalance in the then-branch. Constant @if 0/1 does NOT
    # cover this -- it needs an actual eval error in the condition.
    assert_cli_parity("@if $undef { foo\n")


def test_b2_eval_error_condition_over_brace_imbalance_else() -> None:
    assert_cli_parity("@if $undef { ok; } @else { foo\n")
