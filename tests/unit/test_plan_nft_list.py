"""Unit tests for parse_nft_list: the parser for the current-side nft snapshot.

The current side is the output of ``nft list table <fam> ferm`` -- a
brace-delimited block.  parse_nft_list returns the same {table: ParsedTable}
model as parse_nft_script, so diff_tables consumes both sides identically.
"""

import pytest

from pyferm.errors import FermError
from pyferm.plan import parse_nft_list

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_MULTI_CHAIN_LIST = """\
table ip ferm {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		ct state related,established accept
		tcp dport 22 accept
	}

	chain mychain {
		ip saddr 10.0.0.0/8 accept
	}
}
"""


# ---------------------------------------------------------------------------
# Happy-path: structure
# ---------------------------------------------------------------------------


def test_multi_chain_parses_structure() -> None:
    """Base chain and user chain are both present in the ferm table."""
    tables = parse_nft_list(_MULTI_CHAIN_LIST, family="ip")
    assert set(tables) == {"ferm"}
    chains = tables["ferm"].chains
    assert set(chains) == {"INPUT", "mychain"}


def test_base_chain_policy_is_canon_header() -> None:
    """The base-chain policy field is the canonicalized nft header string."""
    tables = parse_nft_list(_MULTI_CHAIN_LIST, family="ip")
    policy = tables["ferm"].chains["INPUT"].policy
    # canonicalize_nft_header maps 'filter' -> '0', strips semicolons
    assert policy == "type filter hook input priority 0 policy accept"


def test_user_chain_policy_is_dash() -> None:
    """A chain whose first body line is a rule gets policy '-'."""
    tables = parse_nft_list(_MULTI_CHAIN_LIST, family="ip")
    assert tables["ferm"].chains["mychain"].policy == "-"


def test_rules_appended_in_order_and_canonicalized() -> None:
    """Rules are in emission order; ct state members are reordered on parse."""
    tables = parse_nft_list(_MULTI_CHAIN_LIST, family="ip")
    rules = tables["ferm"].chains["INPUT"].rules
    # 'related,established' -> 'established,related' (bitmask order)
    assert rules[0] == "ct state established,related accept"
    assert rules[1] == "tcp dport 22 accept"


def test_user_chain_rules_appended() -> None:
    """User chain body lines are canonicalized and appended as rules."""
    tables = parse_nft_list(_MULTI_CHAIN_LIST, family="ip")
    assert tables["ferm"].chains["mychain"].rules == [
        "ip saddr 10.0.0.0/8 accept"
    ]


# ---------------------------------------------------------------------------
# Happy-path: empty / trivial inputs
# ---------------------------------------------------------------------------


def test_empty_input_returns_empty_dict() -> None:
    """Empty string (first-run, no table) -> {}."""
    assert parse_nft_list("", family="ip") == {}


def test_blank_and_comment_only_input_returns_empty_dict() -> None:
    """Input with only blank lines and comments -> {}."""
    assert parse_nft_list("# comment\n\n# another\n", family="ip") == {}


def test_empty_table_block_returns_empty_chains() -> None:
    """A table with no chains produces an empty ParsedTable."""
    text = "table ip ferm {\n}\n"
    tables = parse_nft_list(text, family="ip")
    assert set(tables) == {"ferm"}
    assert tables["ferm"].chains == {}


def test_empty_chain_block_produces_empty_rules() -> None:
    """A chain with no body lines produces [] rules and policy '-'."""
    text = "table ip ferm {\n\tchain mychain {\n\t}\n}\n"
    tables = parse_nft_list(text, family="ip")
    chain = tables["ferm"].chains["mychain"]
    assert chain.policy == "-"
    assert chain.rules == []


# ---------------------------------------------------------------------------
# Base vs user chain detection
# ---------------------------------------------------------------------------


def test_base_chain_detected_by_type_hook_priority_line() -> None:
    """A chain whose first line starts with 'type' is a base chain."""
    text = (
        "table ip ferm {\n"
        "\tchain FORWARD {\n"
        "\t\ttype filter hook forward priority 0; policy drop;\n"
        "\t\tip saddr 10.0.0.0/8 accept\n"
        "\t}\n"
        "}\n"
    )
    tables = parse_nft_list(text, family="ip")
    chain = tables["ferm"].chains["FORWARD"]
    assert chain.policy == "type filter hook forward priority 0 policy drop"
    assert chain.rules == ["ip saddr 10.0.0.0/8 accept"]


def test_user_chain_first_line_becomes_rule() -> None:
    """A chain whose first line is a rule (not a type/hook/priority header)
    is a user chain; that first line is itself canonicalized as a rule."""
    text = "table ip ferm {\n\tchain logdrop {\n\t\tlog drop\n\t}\n}\n"
    tables = parse_nft_list(text, family="ip")
    chain = tables["ferm"].chains["logdrop"]
    assert chain.policy == "-"
    assert chain.rules == ["log drop"]


def test_base_chain_header_without_policy_gets_policy_accept() -> None:
    """A base-chain header that omits 'policy' has 'policy accept' appended."""
    text = (
        "table ip ferm {\n"
        "\tchain INPUT {\n"
        "\t\ttype filter hook input priority filter;\n"
        "\t\ttcp dport 80 accept\n"
        "\t}\n"
        "}\n"
    )
    tables = parse_nft_list(text, family="ip")
    policy = tables["ferm"].chains["INPUT"].policy
    assert "policy accept" in policy


# ---------------------------------------------------------------------------
# Inline family validation
# ---------------------------------------------------------------------------


def test_inline_family_mismatch_raises() -> None:
    """The family token in the table header must match the 'family' kwarg."""
    with pytest.raises(FermError):
        parse_nft_list("table ip6 ferm {\n}\n", family="ip")


def test_inline_family_matches_kwarg_ok() -> None:
    """Matching family token passes without error."""
    tables = parse_nft_list("table ip6 ferm {\n}\n", family="ip6")
    assert set(tables) == {"ferm"}


# ---------------------------------------------------------------------------
# Anonymous set in rule body does NOT break brace depth
# ---------------------------------------------------------------------------


def test_anonymous_set_in_rule_body_does_not_break_depth() -> None:
    """An anonymous set '{22, 80}' inside a rule body is NOT a block opener.

    The chain must contain exactly one rule, not be prematurely closed.
    """
    text = (
        "table ip ferm {\n"
        "\tchain INPUT {\n"
        "\t\ttcp dport { 22, 80 } accept\n"
        "\t}\n"
        "}\n"
    )
    tables = parse_nft_list(text, family="ip")
    chain = tables["ferm"].chains["INPUT"]
    assert chain.policy == "-"
    assert len(chain.rules) == 1
    assert "accept" in chain.rules[0]


def test_multiple_rules_with_anon_set_stay_in_chain() -> None:
    """Multiple rules including one with an anon set stay in the chain."""
    text = (
        "table ip ferm {\n"
        "\tchain INPUT {\n"
        "\t\ttcp dport { 22, 80 } accept\n"
        "\t\tudp dport 53 accept\n"
        "\t}\n"
        "}\n"
    )
    tables = parse_nft_list(text, family="ip")
    assert len(tables["ferm"].chains["INPUT"].rules) == 2


# ---------------------------------------------------------------------------
# Comments and blank lines between chains
# ---------------------------------------------------------------------------


def test_comments_and_blanks_between_chains_are_skipped() -> None:
    """Comment and blank lines between chains do not cause parse errors."""
    text = (
        "table ip ferm {\n"
        "\t# first chain\n"
        "\tchain A {\n"
        "\t\taccept\n"
        "\t}\n"
        "\n"
        "\t# second chain\n"
        "\tchain B {\n"
        "\t\tdrop\n"
        "\t}\n"
        "}\n"
    )
    tables = parse_nft_list(text, family="ip")
    assert set(tables["ferm"].chains) == {"A", "B"}


# ---------------------------------------------------------------------------
# Structural parse errors (fail-loud)
# ---------------------------------------------------------------------------


def test_unterminated_table_brace_at_eof_raises() -> None:
    """A '{' for the table that is never closed raises FermError."""
    with pytest.raises(FermError):
        parse_nft_list("table ip ferm {\n", family="ip")


def test_unterminated_chain_brace_at_eof_raises() -> None:
    """A '{' for a chain that is never closed raises FermError."""
    text = "table ip ferm {\n\tchain INPUT {\n\t\taccept\n"
    with pytest.raises(FermError):
        parse_nft_list(text, family="ip")


def test_stray_close_brace_raises() -> None:
    """A '}' with no matching open block is a parse error."""
    with pytest.raises(FermError):
        parse_nft_list("}\n", family="ip")


def test_line_before_table_raises() -> None:
    """A non-blank, non-comment line before the table block raises."""
    with pytest.raises(FermError):
        parse_nft_list("chain INPUT {\n}\n", family="ip")


def test_chain_line_outside_table_raises() -> None:
    """A 'chain' line that appears outside any table block is a parse error."""
    with pytest.raises(FermError):
        parse_nft_list("table ip ferm {\n}\nchain X {\n}\n", family="ip")
