"""Unit tests for the nft delta-apply emitter and its preconditions."""

from __future__ import annotations

import pytest

from pyferm.errors import FermError
from pyferm.plan import (
    ParsedChain,
    ParsedSet,
    ParsedTable,
    _build_desired_index,
    _DesiredIndex,
    _emit_chain_changes,
    _emit_set_changes,
    build_nft_delta,
    diff_tables,
    emit_delta_script,
    needs_full_reload,
    parse_nft_list,
    parse_nft_script,
)


def _table_with_set(name: str, set_obj: ParsedSet) -> dict[str, ParsedTable]:
    table = ParsedTable()
    table.sets[name] = set_obj
    return {"ferm": table}


def test_parsed_set_defaults() -> None:
    ps = ParsedSet("hosts")
    assert ps.type_ is None
    assert ps.flags == ()


def test_parse_nft_script_reads_set_type_and_flags() -> None:
    script = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add set ip ferm hosts { type ipv4_addr; flags interval; }\n"
        "add element ip ferm hosts { 10.0.0.0/24 }\n"
    )
    tables = parse_nft_script(script)
    s = tables["ferm"].sets["hosts"]
    assert s.type_ == "ipv4_addr"
    assert s.flags == ("interval",)
    assert s.elements == ["10.0.0.0/24"]


def test_parse_nft_script_set_without_flags() -> None:
    script = (
        "add table ip ferm\n"
        "add set ip ferm ports { type inet_service; }\n"
        "add element ip ferm ports { 22, 80 }\n"
    )
    s = parse_nft_script(script)["ferm"].sets["ports"]
    assert s.type_ == "inet_service"
    assert s.flags == ()


def test_parse_nft_list_reads_set_type_and_flags() -> None:
    text = (
        "table ip ferm {\n"
        "\tset hosts {\n"
        "\t\ttype ipv4_addr\n"
        "\t\tflags interval\n"
        "\t\telements = { 10.0.0.0/24 }\n"
        "\t}\n"
        "}\n"
    )
    s = parse_nft_list(text, family="ip")["ferm"].sets["hosts"]
    assert s.type_ == "ipv4_addr"
    assert s.flags == ("interval",)
    assert s.elements == ["10.0.0.0/24"]


def test_parse_nft_list_rejects_bad_chain_name() -> None:
    text = "table ip ferm {\n\tchain bad;name {\n\t}\n}\n"
    with pytest.raises(FermError):
        parse_nft_list(text, family="ip")


def test_parse_nft_list_rejects_bad_set_name() -> None:
    text = "table ip ferm {\n\tset bad-name {\n\t}\n}\n"
    with pytest.raises(FermError):
        parse_nft_list(text, family="ip")


def test_diff_set_type_change_is_remove_plus_add() -> None:
    current = _table_with_set(
        "s", ParsedSet("s", ["22"], type_="inet_service")
    )
    desired = _table_with_set(
        "s", ParsedSet("s", ["10.0.0.1"], type_="ipv4_addr")
    )
    diff = diff_tables(current, desired, noflush=False)
    kinds = sorted(sc.kind for sc in diff.set_changes)
    assert kinds == ["add", "remove"]
    add = next(sc for sc in diff.set_changes if sc.kind == "add")
    assert add.elements == ["10.0.0.1"]


def test_diff_set_flags_change_is_remove_plus_add() -> None:
    current = _table_with_set(
        "s", ParsedSet("s", ["10.0.0.1"], type_="ipv4_addr")
    )
    desired = _table_with_set(
        "s",
        ParsedSet(
            "s", ["10.0.0.0/24"], type_="ipv4_addr", flags=("interval",)
        ),
    )
    diff = diff_tables(current, desired, noflush=False)
    assert sorted(sc.kind for sc in diff.set_changes) == ["add", "remove"]


def test_diff_set_elements_only_is_modify() -> None:
    current = _table_with_set(
        "s", ParsedSet("s", ["10.0.0.1"], type_="ipv4_addr")
    )
    desired = _table_with_set(
        "s", ParsedSet("s", ["10.0.0.1", "10.0.0.2"], type_="ipv4_addr")
    )
    diff = diff_tables(current, desired, noflush=False)
    assert [sc.kind for sc in diff.set_changes] == ["modify"]


def test_build_desired_index_extracts_verbatim_lines() -> None:
    save = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add set ip ferm hosts { type ipv4_addr; }\n"
        "add element ip ferm hosts { 10.0.0.1, 10.0.0.2 }\n"
        "add chain ip ferm INPUT { type filter hook input priority 0;"
        " policy accept; }\n"
        "add chain ip ferm sub\n"
        "add rule ip ferm INPUT tcp dport 22 accept\n"
        "add rule ip ferm INPUT ip saddr 10.0.0.1 accept\n"
    )
    index = _build_desired_index(save)
    assert (
        index.set_decl["hosts"] == "add set ip ferm hosts { type ipv4_addr; }"
    )
    assert (
        index.set_elements["hosts"]
        == "add element ip ferm hosts { 10.0.0.1, 10.0.0.2 }"
    )
    assert index.chain_decl["INPUT"].endswith("policy accept; }")
    assert index.chain_decl["sub"] == "add chain ip ferm sub"
    assert index.chain_rules["INPUT"] == [
        "add rule ip ferm INPUT tcp dport 22 accept",
        "add rule ip ferm INPUT ip saddr 10.0.0.1 accept",
    ]
    assert "sub" not in index.chain_rules


def test_emit_set_add() -> None:
    diff = diff_tables(
        {"ferm": ParsedTable()},
        _table_with_set(
            "hosts", ParsedSet("hosts", ["10.0.0.1"], "ipv4_addr")
        ),
        noflush=False,
    )
    index = _build_desired_index(
        "add set ip ferm hosts { type ipv4_addr; }\n"
        "add element ip ferm hosts { 10.0.0.1 }\n"
    )
    lines = _emit_set_changes(
        diff, {"ferm": ParsedTable()}, index, family="ip"
    )
    assert lines == [
        "add set ip ferm hosts { type ipv4_addr; }",
        "add element ip ferm hosts { 10.0.0.1 }",
    ]


def test_emit_set_modify_element_delta() -> None:
    current = _table_with_set(
        "h", ParsedSet("h", ["10.0.0.1", "10.0.0.2"], "ipv4_addr")
    )
    desired = _table_with_set(
        "h", ParsedSet("h", ["10.0.0.2", "10.0.0.3"], "ipv4_addr")
    )
    diff = diff_tables(current, desired, noflush=False)
    index = _build_desired_index(
        "add set ip ferm h { type ipv4_addr; }\n"
        "add element ip ferm h { 10.0.0.2, 10.0.0.3 }\n"
    )
    lines = _emit_set_changes(diff, current, index, family="ip")
    assert "delete element ip ferm h { 10.0.0.1 }" in lines
    assert "add element ip ferm h { 10.0.0.3 }" in lines


def test_emit_set_remove_is_internal_error() -> None:
    # A set 'remove' must be filtered out by build_nft_delta (-> full reload)
    # BEFORE the emitter runs.  If one reaches the emitter the delta contract
    # is broken: fail loud rather than emit a refcount-unsafe 'delete set'.
    import pytest

    from pyferm.errors import FermError

    current = _table_with_set("h", ParsedSet("h", ["10.0.0.1"], "ipv4_addr"))
    diff = diff_tables(current, {"ferm": ParsedTable()}, noflush=False)
    with pytest.raises(FermError):
        _emit_set_changes(diff, current, _DesiredIndex(), family="ip")


def _tbl(chains: dict[str, ParsedChain]) -> dict[str, ParsedTable]:
    t = ParsedTable()
    t.chains.update(chains)
    return {"ferm": t}


def test_emit_chain_new() -> None:
    current = {"ferm": ParsedTable()}
    desired = _tbl({"sub": ParsedChain("-", ["add"])})
    diff = diff_tables(current, desired, noflush=False)
    index = _build_desired_index(
        "add chain ip ferm sub\nadd rule ip ferm sub tcp dport 22 accept\n"
    )
    lines = _emit_chain_changes(diff, current, index, family="ip")
    assert lines == [
        "add chain ip ferm sub",
        "add rule ip ferm sub tcp dport 22 accept",
    ]


def test_emit_chain_changed_flushes_and_rebuilds() -> None:
    current = _tbl({"INPUT": ParsedChain("policy accept", ["old rule"])})
    desired = _tbl({"INPUT": ParsedChain("policy accept", ["new rule"])})
    diff = diff_tables(current, desired, noflush=False)
    index = _build_desired_index(
        "add chain ip ferm INPUT { type filter hook input priority 0;"
        " policy accept; }\nadd rule ip ferm INPUT new rule\n"
    )
    lines = _emit_chain_changes(diff, current, index, family="ip")
    assert "flush chain ip ferm INPUT" in lines
    assert "add rule ip ferm INPUT new rule" in lines
    assert lines.index("flush chain ip ferm INPUT") < lines.index(
        "add rule ip ferm INPUT new rule"
    )


def test_emit_chain_policy_only_no_flush() -> None:
    current = _tbl(
        {
            "INPUT": ParsedChain(
                "type filter hook input priority 0 policy accept", ["r"]
            )
        }
    )
    desired = _tbl(
        {
            "INPUT": ParsedChain(
                "type filter hook input priority 0 policy drop", ["r"]
            )
        }
    )
    diff = diff_tables(current, desired, noflush=False)
    index = _build_desired_index(
        "add chain ip ferm INPUT { type filter hook input priority 0;"
        " policy drop; }\nadd rule ip ferm INPUT r\n"
    )
    lines = _emit_chain_changes(diff, current, index, family="ip")
    assert any(line.startswith("add chain ip ferm INPUT") for line in lines)
    assert not any(line.startswith("flush chain") for line in lines)


def test_emit_chain_unchanged_skipped() -> None:
    current = _tbl({"INPUT": ParsedChain("policy accept", ["r"])})
    desired = _tbl({"INPUT": ParsedChain("policy accept", ["r"])})
    diff = diff_tables(current, desired, noflush=False)
    index = _build_desired_index(
        "add chain ip ferm INPUT { type filter hook input priority 0;"
        " policy accept; }\nadd rule ip ferm INPUT r\n"
    )
    assert _emit_chain_changes(diff, current, index, family="ip") == []


def test_emit_chain_desuet_and_foreign_deleted() -> None:
    current = _tbl(
        {
            "OLDBASE": ParsedChain("policy accept"),
            "olduser": ParsedChain("-"),
        }
    )
    desired = {"ferm": ParsedTable()}
    diff = diff_tables(current, desired, noflush=False)
    lines = _emit_chain_changes(diff, current, _DesiredIndex(), family="ip")
    assert "delete chain ip ferm OLDBASE" in lines
    assert "delete chain ip ferm olduser" in lines


def test_emit_chain_delete_follows_every_flush() -> None:
    # Ordering invariant: a 'delete chain' (desuet/foreign) must come AFTER
    # every 'flush chain' in the same pass, so a jump/goto from a chain that
    # is being rebuilt has already been cleared before its target is removed.
    current = _tbl(
        {
            "INPUT": ParsedChain("policy accept", ["jump gone"]),
            "gone": ParsedChain("-", ["r"]),
        }
    )
    desired = _tbl({"INPUT": ParsedChain("policy accept", ["new rule"])})
    diff = diff_tables(current, desired, noflush=False)
    index = _build_desired_index(
        "add chain ip ferm INPUT { type filter hook input priority 0;"
        " policy accept; }\nadd rule ip ferm INPUT new rule\n"
    )
    lines = _emit_chain_changes(diff, current, index, family="ip")
    flush_positions = [
        i for i, ln in enumerate(lines) if ln.startswith("flush ")
    ]
    delete_positions = [
        i for i, ln in enumerate(lines) if ln.startswith("delete chain ")
    ]
    assert flush_positions
    assert delete_positions
    assert max(flush_positions) < min(delete_positions)


def test_emit_delta_empty_when_no_changes() -> None:
    t = _tbl({"INPUT": ParsedChain("policy accept", ["r"])})
    diff = diff_tables(t, t, noflush=False)
    index = _build_desired_index(
        "add chain ip ferm INPUT { type filter hook input priority 0;"
        " policy accept; }\nadd rule ip ferm INPUT r\n"
    )
    assert emit_delta_script(diff, t, index, family="ip") == ""


def test_emit_delta_starts_with_add_table_and_orders_sets_before_chains() -> (
    None
):
    current = {"ferm": ParsedTable()}
    desired_save = (
        "add table ip ferm\n"
        "add set ip ferm h { type ipv4_addr; }\n"
        "add element ip ferm h { 10.0.0.1 }\n"
        "add chain ip ferm sub\n"
        "add rule ip ferm sub ip saddr @h accept\n"
    )
    desired = parse_nft_script(desired_save)
    diff = diff_tables(current, desired, noflush=False)
    index = _build_desired_index(desired_save)
    out = emit_delta_script(diff, current, index, family="ip")
    assert out.startswith("add table ip ferm\n")
    assert out.index("add set ip ferm h") < out.index("add chain ip ferm sub")
    assert out.endswith("\n")


def test_needs_full_reload_predicate() -> None:
    assert needs_full_reload(None) is True
    assert needs_full_reload("") is True
    assert needs_full_reload("   \n") is True
    assert needs_full_reload("table ip ferm {\n}\n") is False


def test_build_nft_delta_add_one_rule() -> None:
    previous = (
        "table ip ferm {\n"
        "\tchain INPUT {\n"
        "\t\ttype filter hook input priority 0; policy accept;\n"
        "\t\ttcp dport 22 accept\n"
        "\t}\n"
        "}\n"
    )
    desired = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add chain ip ferm INPUT { type filter hook input priority 0;"
        " policy accept; }\n"
        "add rule ip ferm INPUT tcp dport 22 accept\n"
        "add rule ip ferm INPUT tcp dport 80 accept\n"
    )
    delta = build_nft_delta(previous, desired, family="ip")
    assert delta is not None
    assert "flush chain ip ferm INPUT" in delta
    assert "add rule ip ferm INPUT tcp dport 80 accept" in delta
    assert "flush table ip ferm" not in delta  # delta never flushes the table


def test_build_nft_delta_identical_is_empty() -> None:
    previous = (
        "table ip ferm {\n"
        "\tchain INPUT {\n"
        "\t\ttype filter hook input priority 0; policy accept;\n"
        "\t\ttcp dport 22 accept\n"
        "\t}\n"
        "}\n"
    )
    desired = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add chain ip ferm INPUT { type filter hook input priority 0;"
        " policy accept; }\n"
        "add rule ip ferm INPUT tcp dport 22 accept\n"
    )
    assert build_nft_delta(previous, desired, family="ip") == ""


def test_build_nft_delta_set_retype_falls_back_to_none() -> None:
    # A flags-only retype keeps the referencing rule text identical, so the
    # chain is NOT flushed -> a 'delete set' would orphan a live reference.
    # build_nft_delta must signal full-reload (None), never emit the delta.
    previous = (
        "table ip ferm {\n"
        "\tset s {\n"
        "\t\ttype ipv4_addr\n"
        "\t\telements = { 10.0.0.1 }\n"
        "\t}\n"
        "\tchain INPUT {\n"
        "\t\ttype filter hook input priority 0; policy accept;\n"
        "\t\tip saddr @s accept\n"
        "\t}\n"
        "}\n"
    )
    desired = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add set ip ferm s { type ipv4_addr; flags interval; }\n"
        "add element ip ferm s { 10.0.0.0/24 }\n"
        "add chain ip ferm INPUT { type filter hook input priority 0;"
        " policy accept; }\n"
        "add rule ip ferm INPUT ip saddr @s accept\n"
    )
    assert build_nft_delta(previous, desired, family="ip") is None


def test_set_removal_forces_full_reload_via_delta_none() -> None:
    # previous has a named set; desired drops it -> the delta is refcount-
    # unsafe (`delete set` aborts if a live rule still references it), so
    # build_nft_delta returns None and the caller falls back to full reload.
    # NB: this invariant lives in build_nft_delta (set_changes kind=="remove"
    # -> None), NOT in needs_full_reload (which only sees the snapshot side).
    previous = "table ip ferm {\n\tset x {\n\t\ttype ipv4_addr\n\t}\n}\n"
    desired = (  # render().save with a chain but no set x
        "add table ip ferm\n"
        "add chain ip ferm INPUT "
        "{ type filter hook input priority 0; policy accept; }\n"
    )
    assert build_nft_delta(previous, desired, family="ip") is None


def test_needs_full_reload_contract() -> None:
    # needs_full_reload only branches on the snapshot: no prior table (None)
    # or an empty snapshot -> nothing to preserve -> reload; otherwise delta.
    assert needs_full_reload(None) is True
    assert needs_full_reload("") is True
    assert needs_full_reload("table ip ferm {\n}\n") is False
