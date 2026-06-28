"""Unit tests for parse_nft_script: the parser for the desired-side nft script.

The desired side is the output of NftBackend.render().save -- an nft -f
script produced by serialize_table.  parse_nft_script returns a
{table: ParsedTable} model identical in shape to the one parse_save returns
for iptables, so diff_tables and render_plan consume it unchanged.
"""

import pytest

from pyferm.errors import FermError
from pyferm.plan import (
    ParsedChain,
    ParsedSet,
    ParsedTable,
    build_nft_delta,
    diff_tables,
    parse_nft_script,
)

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


def test_add_table_and_flush_table_materialize_empty_table() -> None:
    """add table / flush table carry no rules but declare the ferm table.

    The envelope lines produce no chains or sets, yet declaring the table
    materializes a present-but-empty ferm entry.  diff_tables iterates desired
    tables, so an absent ferm table would skip the diff entirely and let
    foreign chains in the live kernel table pass silently as "No changes".
    """
    text = "add table ip ferm\nflush table ip ferm\n"
    tables = parse_nft_script(text)
    assert set(tables) == {"ferm"}
    assert tables["ferm"].chains == {}
    assert tables["ferm"].sets == {}


def test_flush_table_bridge_materializes_empty_table() -> None:
    """flush table accepts any nft family and declares the ferm table."""
    text = "flush table bridge ferm\n"
    tables = parse_nft_script(text)
    assert set(tables) == {"ferm"}
    assert tables["ferm"].chains == {}


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
    # ip6 maps 'filter' -> 0 (same landmark table as ip); full equality check
    assert policy == "type filter hook input priority 0 policy accept"


def test_base_vs_user_distinction() -> None:
    """A chain line with braces is base; without braces is user."""
    text = (
        "add table ip ferm\n"
        "add chain ip ferm INPUT"
        " { type filter hook input priority 0; policy accept; }\n"
        "add chain ip ferm mychain\n"
    )
    tables = parse_nft_script(text)
    # base chain: full canonical header string (not just "not -")
    assert tables["ferm"].chains["INPUT"].policy == (
        "type filter hook input priority 0 policy accept"
    )
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


def test_add_table_extra_token_raises() -> None:
    """add table with an extra token beyond the 4-token production raises."""
    with pytest.raises(FermError):
        parse_nft_script("add table ip ferm extra\n")


def test_flush_table_extra_token_raises() -> None:
    """flush table with an extra token beyond the 4-token production raises."""
    with pytest.raises(FermError):
        parse_nft_script("flush table ip ferm extra\n")


def test_add_chain_extra_token_before_brace_raises() -> None:
    """Extra token between chain name and '{' is invalid -- parse error."""
    text = (
        "add table ip ferm\n"
        "add chain ip ferm INPUT extra"
        " { type filter hook input priority 0; policy accept; }\n"
    )
    with pytest.raises(FermError):
        parse_nft_script(text)


def test_envelope_only_desired_surfaces_live_foreign_chain() -> None:
    """The end-to-end payoff of materializing the envelope-only table.

    A chainless config diffed against a live ferm table that still holds a
    user chain reports that chain as foreign (an apply would flush it) rather
    than reporting "No changes".  Before the fix the desired ferm table was
    absent, diff_tables skipped it, and the foreign chain was lost.
    """
    desired = parse_nft_script("add table ip ferm\nflush table ip ferm\n")
    current = {"ferm": ParsedTable(chains={"oldchain": ParsedChain("-")})}
    diff = diff_tables(current, desired, noflush=False)
    assert [fc.chain for fc in diff.foreign_chains] == ["oldchain"]
    assert diff.has_changes()


def test_envelope_only_desired_surfaces_live_foreign_set() -> None:
    """The set path is the symmetric payoff of materializing the envelope.

    diff_tables iterates the desired table's sets the same way it iterates its
    chains, so a chainless, setless config diffed against a live ferm table
    holding a named set reports that set as a removal.  Without the empty-table
    materialization the desired ferm table is absent and the foreign set is
    lost exactly as the foreign chain would be.
    """
    desired = parse_nft_script("add table ip ferm\nflush table ip ferm\n")
    current = {
        "ferm": ParsedTable(
            sets={"oldset": ParsedSet("oldset", elements=["10.0.0.1"])}
        )
    }
    diff = diff_tables(current, desired, noflush=False)
    assert [(sc.name, sc.kind) for sc in diff.set_changes] == [
        ("oldset", "remove")
    ]
    assert diff.has_changes()


def test_envelope_only_desired_emits_delete_chain_delta() -> None:
    """build_nft_delta also consumes parse_nft_script, so the materialized
    empty table propagates to the apply path: an envelope-only config against a
    live ferm table holding a user chain emits a `delete chain` delta instead
    of an empty (no-op) delta.  This locks the apply-path reachability of the
    fix, not just the read-only diff.
    """
    previous = "table ip ferm {\n\tchain oldchain {\n\t}\n}\n"
    desired_save = "add table ip ferm\nflush table ip ferm\n"
    delta = build_nft_delta(previous, desired_save, family="ip")
    assert delta is not None
    assert "delete chain ip ferm oldchain" in delta
