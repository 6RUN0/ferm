"""SetChange arm in diff_tables + iptables no-op invariant."""

from pyferm.plan import (
    ParsedSet,
    ParsedTable,
    Plan,
    PlanDiff,
    SetChange,
    diff_tables,
    render_structured,
)


def _table_with_set(name: str, elements: list[str]) -> dict[str, ParsedTable]:
    t = ParsedTable()
    t.sets[name] = ParsedSet(name, elements)
    return {"ferm": t}


def test_set_added_is_a_change() -> None:
    diff = diff_tables(
        current={"ferm": ParsedTable()},
        desired=_table_with_set("ssh", ["22"]),
        noflush=False,
    )
    assert diff.has_changes()
    assert any(c.name == "ssh" for c in diff.set_changes)


def test_set_added_kind_is_add() -> None:
    diff = diff_tables(
        current={"ferm": ParsedTable()},
        desired=_table_with_set("ssh", ["22"]),
        noflush=False,
    )
    sc = next(c for c in diff.set_changes if c.name == "ssh")
    assert sc.kind == "add"
    assert sc.elements == ["22"]
    assert sc.table == "ferm"


def test_empty_sets_is_noop() -> None:
    # No sets on either side -> identical behavior to before this arm.
    diff = diff_tables(
        current={"ferm": ParsedTable()},
        desired={"ferm": ParsedTable()},
        noflush=False,
    )
    assert not diff.has_changes()
    assert diff.set_changes == []


def test_set_removed() -> None:
    diff = diff_tables(
        current=_table_with_set("ssh", ["22"]),
        desired={"ferm": ParsedTable()},
        noflush=False,
    )
    assert diff.has_changes()
    sc = next(c for c in diff.set_changes if c.name == "ssh")
    assert sc.kind == "remove"
    assert sc.elements == []


def test_set_modified() -> None:
    diff = diff_tables(
        current=_table_with_set("ssh", ["22"]),
        desired=_table_with_set("ssh", ["22", "2222"]),
        noflush=False,
    )
    assert diff.has_changes()
    sc = next(c for c in diff.set_changes if c.name == "ssh")
    assert sc.kind == "modify"
    assert sc.elements == ["22", "2222"]


def test_set_unchanged_is_noop() -> None:
    diff = diff_tables(
        current=_table_with_set("ssh", ["22"]),
        desired=_table_with_set("ssh", ["22"]),
        noflush=False,
    )
    assert not diff.has_changes()
    assert diff.set_changes == []


def test_render_structured_set_only_change_is_visible() -> None:
    # A set-only change must produce a visible +/- set line in
    # render_structured (the default human renderer).  Without explicit
    # wiring, has_changes() would flip the exit code but the structured
    # output would show no set lines.
    diff = PlanDiff(
        set_changes=[
            SetChange(table="ferm", name="ssh", kind="add", elements=["22"])
        ],
    )
    plan = Plan(families={"ip": diff})
    out = render_structured(plan)
    assert "ssh" in out
    # At minimum a '+' or '-' set marker must appear
    assert "+" in out or "-" in out
    # Must not fall through to "No changes"
    assert "No changes" not in out
