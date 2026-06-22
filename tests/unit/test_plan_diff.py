from pyferm.plan import ParsedChain, ParsedTable, diff_tables


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
