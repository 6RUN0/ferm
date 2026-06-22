from pyferm.plan import (
    ForeignChain,
    Plan,
    PlanDiff,
    PolicyChange,
    RuleChange,
    render_plan,
    render_structured,
    render_unified,
)


def test_no_changes_message() -> None:
    plan = Plan(families={"ip": PlanDiff()})
    out = render_structured(plan)
    assert "No changes" in out


def test_structured_lists_changes_deterministically() -> None:
    diff = PlanDiff(
        policy_changes=[PolicyChange("filter", "INPUT", "ACCEPT", "DROP")],
        rules_added=[RuleChange("filter", "INPUT", "-p udp -j DROP")],
        rules_removed=[RuleChange("filter", "INPUT", "-p tcp -j ACCEPT")],
        foreign_chains=[ForeignChain("filter", "DOCKER")],
    )
    out = render_structured(Plan(families={"ip": diff}))
    assert "~ policy filter/INPUT: ACCEPT -> DROP" in out
    assert "+ -p udp -j DROP" in out
    assert "- -p tcp -j ACCEPT" in out
    assert "DOCKER" in out
    assert "warning" in out.lower()
    assert "Plan: 1 to add, 1 to remove, 1 policy change" in out


def test_structured_is_stable_across_family_order() -> None:
    a = Plan(
        families={
            "ip6": PlanDiff(
                rules_added=[RuleChange("filter", "INPUT", "-j A")]
            ),
            "ip": PlanDiff(
                rules_added=[RuleChange("filter", "INPUT", "-j B")]
            ),
        }
    )
    # families render sorted by name regardless of dict insertion order
    assert render_structured(a).index("family ip\n") < render_structured(
        a
    ).index("family ip6\n")


def test_unsupported_family_noted() -> None:
    plan = Plan(families={}, unsupported=["eb"])
    out = render_structured(plan)
    assert "eb" in out
    assert "not supported" in out.lower()


def test_render_plan_dispatch() -> None:
    diff = PlanDiff(rules_added=[RuleChange("filter", "INPUT", "-j A")])
    plan = Plan(families={"ip": diff})
    assert render_plan(plan, fmt="structured") == render_structured(plan)
    # diff format produces unified-diff markers
    result = render_plan(plan, fmt="diff")
    assert "---" in result
    assert "+++" in result
    assert "@@" in result


def test_unified_shows_policy_change_no_hidden_lockout() -> None:
    # A policy-only diff must NOT be invisible in the unified format --
    # hiding INPUT ACCEPT -> DROP would be a lock-out hidden from
    # --plan-format=diff.
    diff = PlanDiff(
        policy_changes=[PolicyChange("filter", "INPUT", "ACCEPT", "DROP")]
    )
    out = render_unified(Plan(families={"ip": diff}))
    assert "No changes" not in out
    assert "INPUT" in out
    assert "DROP" in out


def test_unified_shows_foreign_chain() -> None:
    # A foreign chain (will be flushed) must appear in the unified format too.
    diff = PlanDiff(foreign_chains=[ForeignChain("filter", "DOCKER")])
    out = render_unified(Plan(families={"ip": diff}))
    assert "DOCKER" in out


def test_unified_preserves_duplicate_removals() -> None:
    # Two identical removed rules must produce two `-` lines, not one
    # (the multiset principle: never use set to collapse duplicates).
    diff = PlanDiff(
        rules_removed=[
            RuleChange("filter", "INPUT", "-j A"),
            RuleChange("filter", "INPUT", "-j A"),
        ]
    )
    out = render_unified(Plan(families={"ip": diff}))
    assert out.count("-A INPUT -j A") == 2


def test_structured_skips_clean_family_with_unsupported() -> None:
    plan = Plan(families={"ip": PlanDiff()}, unsupported=["eb"])
    out = render_structured(plan)
    assert "not supported" in out.lower()
    assert "family ip\n" not in out
    assert "0 to add" not in out
