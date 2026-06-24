"""Unit tests for the nft delta-apply emitter and its preconditions."""

from __future__ import annotations

import pytest

from pyferm.errors import FermError
from pyferm.plan import (
    ParsedSet,
    ParsedTable,
    diff_tables,
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
