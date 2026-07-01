"""Per-keyword rule slicing parity (both negation forms), vs the oracle.

These are differential cases pinned before RuleNode is promoted: the raw rule
span is sliced into keyword arguments on the walk, after modules load, so arity
depends on runtime-loaded modules (mod $var) and a negated keyword identity
must resolve via getvar BEFORE its arity is known (! $var).
"""

from tests.property.differential_cli import assert_cli_parity


def test_mod_var_gates_keyword_arity() -> None:
    # ctstate becomes a valid keyword only after `mod conntrack` -- arity of
    # the sliced arg depends on the runtime-loaded module.
    assert_cli_parity(
        "@def $m = conntrack;\n"
        "table filter chain INPUT { "
        "mod $m ctstate (NEW ESTABLISHED) ACCEPT; }\n"
    )


def test_value_negation() -> None:
    assert_cli_parity(
        "table filter chain INPUT { proto tcp dport ! 22 ACCEPT; }\n"
    )


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
