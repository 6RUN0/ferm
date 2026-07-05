from pyferm.plan import (
    ChainRebuild,
    DesuetChain,
    ForeignChain,
    ParsedChain,
    ParsedTable,
    Plan,
    PlanDiff,
    PolicyChange,
    RuleChange,
    SetChange,
    SetChangeKind,
    _diff_blob,
    diff_tables,
    render_structured,
    summary_line,
)


def _tbl(chains: dict[str, ParsedChain]) -> dict[str, ParsedTable]:
    return {"filter": ParsedTable(chains=chains)}


def test_no_change_is_empty() -> None:
    cur = _tbl({"INPUT": ParsedChain("ACCEPT", ["-p tcp -j ACCEPT"])})
    des = _tbl({"INPUT": ParsedChain("ACCEPT", ["-p tcp -j ACCEPT"])})
    diff = diff_tables(cur, des, noflush=False)
    assert not diff.has_changes()


def test_added_and_removed_rules() -> None:
    cur = _tbl({"INPUT": ParsedChain("ACCEPT", ["-p tcp -j ACCEPT"])})
    des = _tbl({"INPUT": ParsedChain("ACCEPT", ["-p udp -j DROP"])})
    diff = diff_tables(cur, des, noflush=False)
    assert [r.rule for r in diff.rules_added] == ["-p udp -j DROP"]
    assert [r.rule for r in diff.rules_removed] == ["-p tcp -j ACCEPT"]
    assert diff.has_changes()


def test_duplicate_rule_not_collapsed() -> None:
    # current has two identical rules; desired has one -> one removal
    cur = _tbl({"INPUT": ParsedChain("ACCEPT", ["-j A", "-j A"])})
    des = _tbl({"INPUT": ParsedChain("ACCEPT", ["-j A"])})
    diff = diff_tables(cur, des, noflush=False)
    assert [r.rule for r in diff.rules_removed] == ["-j A"]


def test_policy_change() -> None:
    cur = _tbl({"INPUT": ParsedChain("ACCEPT", [])})
    des = _tbl({"INPUT": ParsedChain("DROP", [])})
    diff = diff_tables(cur, des, noflush=False)
    assert diff.policy_changes[0].old == "ACCEPT"
    assert diff.policy_changes[0].new == "DROP"


def test_foreign_chain_in_managed_table() -> None:
    cur = _tbl(
        {
            "INPUT": ParsedChain("ACCEPT", []),
            "DOCKER": ParsedChain("-", ["-j RETURN"]),
        }
    )
    des = _tbl({"INPUT": ParsedChain("ACCEPT", [])})
    diff = diff_tables(cur, des, noflush=False)
    assert [f.chain for f in diff.foreign_chains] == ["DOCKER"]
    assert diff.has_changes()


def test_kernel_table_without_config_rules_is_full_removal() -> None:
    # rules_to_save seeds every kernel table into desired as an empty skeleton
    # (domains.read_previous pollutes domain_info.tables), so an unmanaged
    # kernel table such as nat is rewritten -> its live rules show as `-`.
    # There is no "foreign table info-only" model.
    cur = {
        "filter": ParsedTable(chains={"INPUT": ParsedChain("ACCEPT", [])}),
        "nat": ParsedTable(
            chains={"POSTROUTING": ParsedChain("ACCEPT", ["-j MASQUERADE"])}
        ),
    }
    des = {
        "filter": ParsedTable(chains={"INPUT": ParsedChain("ACCEPT", [])}),
        "nat": ParsedTable(chains={"POSTROUTING": ParsedChain("ACCEPT", [])}),
    }
    diff = diff_tables(cur, des, noflush=False)
    assert [r.rule for r in diff.rules_removed] == ["-j MASQUERADE"]
    assert diff.has_changes()


def test_noflush_suppresses_builtin_rule_removal() -> None:
    # a current-only rule in a built-in chain is NOT removed under --noflush
    cur = _tbl({"INPUT": ParsedChain("ACCEPT", ["-j EXISTING"])})
    des = _tbl({"INPUT": ParsedChain("ACCEPT", [])})
    diff = diff_tables(cur, des, noflush=True)
    assert diff.rules_removed == []
    assert not diff.has_changes()


def test_noflush_shows_declared_user_chain_removal() -> None:
    # a declared user chain IS flushed under --noflush -> show removal
    cur = _tbl({"mychain": ParsedChain("-", ["-j OLD"])})
    des = _tbl({"mychain": ParsedChain("-", [])})
    diff = diff_tables(cur, des, noflush=True)
    assert [r.rule for r in diff.rules_removed] == ["-j OLD"]


def test_noflush_keeps_policy_change_visible() -> None:
    cur = _tbl({"INPUT": ParsedChain("ACCEPT", [])})
    des = _tbl({"INPUT": ParsedChain("DROP", [])})
    diff = diff_tables(cur, des, noflush=True)
    assert diff.policy_changes[0].old == "ACCEPT"
    assert diff.policy_changes[0].new == "DROP"
    assert diff.has_changes()


def test_noflush_new_chain_rules_show_as_added() -> None:
    cur = _tbl({"INPUT": ParsedChain("ACCEPT", [])})
    des = _tbl(
        {
            "INPUT": ParsedChain("ACCEPT", []),
            "mychain": ParsedChain("-", ["-j NEW"]),
        }
    )
    diff = diff_tables(cur, des, noflush=True)
    assert [r.rule for r in diff.rules_added] == ["-j NEW"]
    assert diff.has_changes()


def test_current_empty_flag() -> None:
    des = _tbl({"INPUT": ParsedChain("ACCEPT", ["-j A"])})
    diff = diff_tables({}, des, noflush=False)
    assert diff.current_empty
    assert [r.rule for r in diff.rules_added] == ["-j A"]


def test_noflush_suppresses_undeclared_user_chain() -> None:
    # Under --noflush, a user chain present in the kernel but absent from
    # config is NOT reported as foreign and does not trigger has_changes().
    cur = _tbl(
        {
            "INPUT": ParsedChain("ACCEPT", []),
            "orphan": ParsedChain("-", ["-j RETURN"]),
        }
    )
    des = _tbl({"INPUT": ParsedChain("ACCEPT", [])})
    diff = diff_tables(cur, des, noflush=True)
    assert [f.chain for f in diff.foreign_chains] == []
    assert not diff.has_changes()


def test_noflush_false_reports_undeclared_user_chain_as_foreign() -> None:
    # Without --noflush, the same undeclared user chain IS reported as foreign
    # and causes has_changes() to return True.
    cur = _tbl(
        {
            "INPUT": ParsedChain("ACCEPT", []),
            "orphan": ParsedChain("-", ["-j RETURN"]),
        }
    )
    des = _tbl({"INPUT": ParsedChain("ACCEPT", [])})
    diff = diff_tables(cur, des, noflush=False)
    assert [f.chain for f in diff.foreign_chains] == ["orphan"]
    assert diff.has_changes()


def _rule(chain: str = "INPUT") -> RuleChange:
    return RuleChange("filter", chain, "-j ACCEPT")


def test_summary_line_singular_forms() -> None:
    # Exactly one of every category exercises the singular word for each
    # clause and the "N policy change" (not "changes") branch.
    diff = PlanDiff(
        rules_added=[_rule()],
        rules_removed=[_rule()],
        policy_changes=[PolicyChange("filter", "INPUT", "ACCEPT", "DROP")],
        desuet_chains=[DesuetChain("filter", "base")],
        chain_rebuilds=[ChainRebuild("filter", "base", "0", "1")],
        set_changes=[SetChange("filter", "s", SetChangeKind.ADD, ["1"])],
    )
    assert summary_line(diff) == (
        "Plan: 1 to add, 1 to remove, 1 policy change,"
        " 1 chain removed, 1 chain rebuilt, 1 set changed"
    )


def test_summary_line_plural_forms() -> None:
    # Two of every optional category exercises every plural word.
    diff = PlanDiff(
        policy_changes=[
            PolicyChange("filter", "INPUT", "ACCEPT", "DROP"),
            PolicyChange("filter", "OUTPUT", "ACCEPT", "DROP"),
        ],
        desuet_chains=[
            DesuetChain("filter", "a"),
            DesuetChain("filter", "b"),
        ],
        chain_rebuilds=[
            ChainRebuild("filter", "a", "0", "1"),
            ChainRebuild("filter", "b", "0", "1"),
        ],
        set_changes=[
            SetChange("filter", "s", SetChangeKind.ADD, ["1"]),
            SetChange("filter", "t", SetChangeKind.ADD, ["1"]),
        ],
    )
    assert summary_line(diff) == (
        "Plan: 0 to add, 0 to remove, 2 policy changes,"
        " 2 chains removed, 2 chains rebuilt, 2 sets changed"
    )


def test_summary_line_chains_removed_sums_desuet_and_foreign() -> None:
    # chains_removed is desuet + foreign; one of each must total two, so a
    # dropped or subtracted term would omit or miscount the clause.
    diff = PlanDiff(
        desuet_chains=[DesuetChain("filter", "base")],
        foreign_chains=[ForeignChain("filter", "orphan")],
    )
    assert summary_line(diff) == (
        "Plan: 0 to add, 0 to remove, 0 policy changes, 2 chains removed"
    )


def test_summary_line_sets_only_clause() -> None:
    # A set-only diff pins the appended (not overwritten) sets clause.
    diff = PlanDiff(
        set_changes=[SetChange("filter", "s", SetChangeKind.ADD, ["1"])],
    )
    assert summary_line(diff) == (
        "Plan: 0 to add, 0 to remove, 0 policy changes, 1 set changed"
    )


def test_diff_tables_change_records_carry_table_and_chain() -> None:
    # Every emitted change (added/removed rule, policy, foreign chain) must
    # carry the real table -- and rules their chain -- so the rendered
    # *table / chain path is never None.
    cur = _tbl(
        {
            "INPUT": ParsedChain("ACCEPT", ["-j OLD"]),
            "DOCKER": ParsedChain("-", ["-j R"]),
        }
    )
    des = _tbl({"INPUT": ParsedChain("DROP", ["-j NEW"])})
    diff = diff_tables(cur, des, noflush=False)
    assert [(r.table, r.chain, r.rule) for r in diff.rules_added] == [
        ("filter", "INPUT", "-j NEW")
    ]
    assert [(r.table, r.chain, r.rule) for r in diff.rules_removed] == [
        ("filter", "INPUT", "-j OLD")
    ]
    assert [p.table for p in diff.policy_changes] == ["filter"]
    assert [f.table for f in diff.foreign_chains] == ["filter"]


def test_diff_tables_records_noflush_flag() -> None:
    cur = _tbl({"my": ParsedChain("-", ["-j OLD"])})
    des = _tbl({"my": ParsedChain("-", [])})
    assert diff_tables(cur, des, noflush=True).noflush is True
    assert diff_tables(cur, des, noflush=False).noflush is False


def _render(
    cur: dict[str, ParsedTable], des: dict[str, ParsedTable], *, noflush: bool
) -> str:
    diff = diff_tables(cur, des, noflush=noflush)
    return render_structured(Plan(families={"ip": diff}))


def test_render_structured_no_changes_message() -> None:
    out = _render(
        _tbl({"INPUT": ParsedChain("ACCEPT", [])}),
        _tbl({"INPUT": ParsedChain("ACCEPT", [])}),
        noflush=False,
    )
    assert out == "No changes. Live ruleset matches the configuration.\n"


def test_render_structured_foreign_chain_warning() -> None:
    out = _render(
        _tbl(
            {
                "INPUT": ParsedChain("ACCEPT", []),
                "DOCKER": ParsedChain("-", ["-j R"]),
            }
        ),
        _tbl({"INPUT": ParsedChain("ACCEPT", [])}),
        noflush=False,
    )
    assert out == (
        "family ip\n"
        "  warning: chain filter/DOCKER is not in the config"
        " and will be flushed\n"
        "  Plan: 0 to add, 0 to remove, 0 policy changes, 1 chain removed\n"
    )


def test_render_structured_noflush_notes_and_summary() -> None:
    out = _render(
        _tbl({"my": ParsedChain("-", ["-j OLD"])}),
        _tbl({"my": ParsedChain("-", [])}),
        noflush=True,
    )
    assert out == (
        "family ip\n"
        "  note: noflush -- existing built-in/undeclared rules kept;"
        " declared user chains overwritten; policies applied\n"
        "  note: noflush -- counts are the net positional diff;"
        " apply re-appends listed rules to unflushed chains, so"
        " live rules overlapping the config are duplicated\n"
        "  - -j OLD\n"
        "  Plan: 0 to add, 1 to remove, 0 policy changes\n"
    )


def test_diff_blob_sorts_every_category_and_renders_set_removals() -> None:
    # Each category holds two entries in DESCENDING chain order so the inner
    # by-chain/by-name sorts must reorder them (a no-op sort would crash on
    # equal keys or leak the input order); set removals with and without
    # current elements pin both render branches.
    diff = PlanDiff(
        policy_changes=[
            PolicyChange("filter", "zzz", "A", "D"),
            PolicyChange("filter", "aaa", "A", "D"),
        ],
        chain_rebuilds=[
            ChainRebuild("filter", "zzz", "0", "1"),
            ChainRebuild("filter", "aaa", "0", "1"),
        ],
        foreign_chains=[
            ForeignChain("filter", "zforeign"),
            ForeignChain("filter", "aforeign"),
        ],
        desuet_chains=[
            DesuetChain("filter", "zdes"),
            DesuetChain("filter", "ades"),
        ],
        rules_removed=[
            RuleChange("filter", "zzz", "-j R"),
            RuleChange("filter", "aaa", "-j R"),
        ],
        rules_added=[
            RuleChange("filter", "zzz", "-j A"),
            RuleChange("filter", "aaa", "-j A"),
        ],
        set_changes=[
            SetChange(
                "filter",
                "zset",
                SetChangeKind.REMOVE,
                [],
                ["1.1.1.1", "2.2.2.2"],
            ),
            SetChange("filter", "aset", SetChangeKind.REMOVE, [], []),
        ],
    )
    current, desired = _diff_blob(diff)
    assert current == [
        "*filter",
        ":aaa A",
        ":zzz A",
        ":aaa priority 0",
        ":zzz priority 0",
        "# foreign chain aforeign will be flushed",
        "# foreign chain zforeign will be flushed",
        "# base chain ades removed (no longer declared)",
        "# base chain zdes removed (no longer declared)",
        "-A aaa -j R",
        "-A zzz -j R",
        "add set filter aset",
        "add set filter zset { 1.1.1.1, 2.2.2.2 }",
    ]
    assert desired == [
        "*filter",
        ":aaa D",
        ":zzz D",
        ":aaa priority 1",
        ":zzz priority 1",
        "-A aaa -j A",
        "-A zzz -j A",
    ]
