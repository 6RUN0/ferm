"""Unit tests for parse_nft_script: the parser for the desired-side nft script.

The desired side is the output of NftBackend.render().save -- an nft -f
script produced by serialize_table.  parse_nft_script returns a
{table: ParsedTable} model identical in shape to the one parse_save returns
for iptables, so diff_tables and render_plan consume it unchanged.
"""

import pytest

from pyferm.errors import FermError
from pyferm.plan import parse_nft_script

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MULTI_CHAIN_SCRIPT = """\
add table ip ferm
flush table ip ferm
add chain ip ferm INPUT \
{ type filter hook input priority filter; policy accept; }
add chain ip ferm mychain
add rule ip ferm INPUT ct state related,established accept
add rule ip ferm INPUT tcp dport 22 accept
add rule ip ferm mychain ip daddr 10.0.0.1 drop
"""


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


def test_multi_chain_parses_structure() -> None:
    """Base chain and user chain are both present in the ferm table."""
    tables = parse_nft_script(_MULTI_CHAIN_SCRIPT)
    assert set(tables) == {"ferm"}
    chains = tables["ferm"].chains
    assert set(chains) == {"INPUT", "mychain"}


def test_base_chain_policy_is_canon_header() -> None:
    """The base-chain policy field is the canonicalized nft header string."""
    tables = parse_nft_script(_MULTI_CHAIN_SCRIPT)
    policy = tables["ferm"].chains["INPUT"].policy
    # canonicalize_nft_header maps 'filter' -> '0', strips semicolons
    assert policy == "type filter hook input priority 0 policy accept"


def test_user_chain_policy_is_dash() -> None:
    tables = parse_nft_script(_MULTI_CHAIN_SCRIPT)
    assert tables["ferm"].chains["mychain"].policy == "-"


def test_rules_appended_in_order_and_canonicalized() -> None:
    """Rules are in emission order; ct state members are reordered on parse."""
    tables = parse_nft_script(_MULTI_CHAIN_SCRIPT)
    rules = tables["ferm"].chains["INPUT"].rules
    # 'related,established' -> 'established,related' (bitmask order)
    assert rules[0] == "ct state established,related accept"
    assert rules[1] == "tcp dport 22 accept"


def test_user_chain_rules_appended() -> None:
    tables = parse_nft_script(_MULTI_CHAIN_SCRIPT)
    assert tables["ferm"].chains["mychain"].rules == ["ip daddr 10.0.0.1 drop"]


def test_add_table_and_flush_table_ignored() -> None:
    """add table / flush table lines are structural envelope -- ignored."""
    text = "add table ip ferm\nflush table ip ferm\n"
    tables = parse_nft_script(text)
    assert tables == {}


def test_empty_input_returns_empty_dict() -> None:
    assert parse_nft_script("") == {}


def test_blank_lines_and_comments_ignored() -> None:
    text = (
        "# a comment\n"
        "\n"
        "add table ip ferm\n"
        "\n"
        "add chain ip ferm INPUT"
        " { type filter hook input priority 0; policy drop; }\n"
        "# another comment\n"
        "\n"
    )
    tables = parse_nft_script(text)
    assert set(tables) == {"ferm"}
    assert "INPUT" in tables["ferm"].chains


def test_family_taken_from_script() -> None:
    """Family ip6 is correctly inferred; priority names map per ip6 table."""
    text = (
        "add table ip6 ferm\n"
        "add chain ip6 ferm INPUT"
        " { type filter hook input priority filter; policy accept; }\n"
        "add rule ip6 ferm INPUT ct state related,established accept\n"
    )
    tables = parse_nft_script(text)
    policy = tables["ferm"].chains["INPUT"].policy
    # ip6 maps 'filter' -> 0 (same landmark table as ip)
    assert "priority 0" in policy


def test_base_vs_user_distinction() -> None:
    """A chain line with braces is base; without braces is user."""
    text = (
        "add table ip ferm\n"
        "add chain ip ferm INPUT"
        " { type filter hook input priority 0; policy accept; }\n"
        "add chain ip ferm mychain\n"
    )
    tables = parse_nft_script(text)
    assert tables["ferm"].chains["INPUT"].policy != "-"
    assert tables["ferm"].chains["mychain"].policy == "-"


# ---------------------------------------------------------------------------
# Family-mismatch error
# ---------------------------------------------------------------------------


def test_family_mismatch_raises() -> None:
    """All lines must carry the same family; a mismatch is a parse error."""
    text = (
        "add table ip ferm\n"
        "add chain ip6 ferm INPUT"
        " { type filter hook input priority 0; policy accept; }\n"
    )
    with pytest.raises(FermError):
        parse_nft_script(text)


def test_family_mismatch_rule_raises() -> None:
    text = (
        "add table ip ferm\n"
        "add chain ip ferm INPUT"
        " { type filter hook input priority 0; policy accept; }\n"
        "add rule ip6 ferm INPUT ct state established accept\n"
    )
    with pytest.raises(FermError):
        parse_nft_script(text)


# ---------------------------------------------------------------------------
# Structural parse errors (fail-loud)
# ---------------------------------------------------------------------------


def test_garbage_line_raises() -> None:
    """A line matching none of the 5 productions must raise FermError."""
    text = "add table ip ferm\ngarbage line\n"
    with pytest.raises(FermError):
        parse_nft_script(text)


def test_add_rule_undeclared_chain_raises() -> None:
    """A rule naming an undeclared chain is malformed -- parse error."""
    text = (
        "add table ip ferm\n"
        "add rule ip ferm UNDECLARED ct state established accept\n"
    )
    with pytest.raises(FermError):
        parse_nft_script(text)


def test_add_chain_unterminated_brace_raises() -> None:
    """add chain with '{' but no closing '}' on the line is malformed."""
    text = (
        "add table ip ferm\nadd chain ip ferm INPUT { type filter hook input\n"
    )
    with pytest.raises(FermError):
        parse_nft_script(text)


def test_wrong_table_name_raises() -> None:
    """The table name must be 'ferm'; any other name is a parse error."""
    text = (
        "add table ip nat\n"
        "add chain ip nat INPUT"
        " { type filter hook input priority 0; policy accept; }\n"
    )
    with pytest.raises(FermError):
        parse_nft_script(text)
