import pytest

from pyferm.config import PlanFormat
from pyferm.plan import (
    ChainRebuild,
    DesuetChain,
    ForeignChain,
    Plan,
    PlanDiff,
    PolicyChange,
    RuleChange,
    SetChange,
    SetChangeKind,
    render_plan,
    render_structured,
    render_unified,
)
from tests.unit._plan import plan_ip


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
    out = render_structured(plan_ip(diff))
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
    plan = plan_ip(diff)
    assert render_plan(plan, fmt=PlanFormat.STRUCTURED) == render_structured(
        plan
    )
    # diff format produces unified-diff markers
    result = render_plan(plan, fmt=PlanFormat.DIFF)
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
    out = render_unified(plan_ip(diff))
    assert "No changes" not in out
    assert "INPUT" in out
    assert "DROP" in out


def test_unified_shows_foreign_chain() -> None:
    # A foreign chain (will be flushed) must appear in the unified format too.
    diff = PlanDiff(foreign_chains=[ForeignChain("filter", "DOCKER")])
    out = render_unified(plan_ip(diff))
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
    out = render_unified(plan_ip(diff))
    assert out.count("-A INPUT -j A") == 2


def test_structured_skips_clean_family_with_unsupported() -> None:
    plan = Plan(families={"ip": PlanDiff()}, unsupported=["eb"])
    out = render_structured(plan)
    assert "not supported" in out.lower()
    assert "family ip\n" not in out
    assert "0 to add" not in out


def test_structured_noflush_note_warns_about_reappend_undercount() -> None:
    # Under --noflush the structured banner must carry two notes: the
    # survives/flushed split AND the re-append caveat. The second is the point
    # of the ticket -- the counts are a net positional diff, but an apply
    # appends the listed rules to unflushed chains, so live rules overlapping
    # the config are duplicated and never appear in the counts.
    diff = PlanDiff(
        noflush=True,
        rules_added=[
            RuleChange("filter", "INPUT", "-p tcp --dport 80 -j ACCEPT")
        ],
    )
    out = render_structured(plan_ip(diff))
    assert "note: noflush -- existing built-in/undeclared rules kept" in out
    assert "note: noflush -- counts are the net positional diff" in out
    assert "duplicated" in out


@pytest.mark.parametrize(
    ("diff", "first", "second"),
    [
        pytest.param(
            # Policy changes given out of order render sorted by chain, and
            # the sort key must be present (an absent key raises on the
            # dataclass).
            PlanDiff(
                policy_changes=[
                    PolicyChange("filter", "OUTPUT", "ACCEPT", "DROP"),
                    PolicyChange("filter", "INPUT", "ACCEPT", "DROP"),
                ]
            ),
            "policy filter/INPUT",
            "policy filter/OUTPUT",
            id="policy-changes",
        ),
        pytest.param(
            PlanDiff(
                rules_removed=[
                    RuleChange("filter", "OUTPUT", "-j A"),
                    RuleChange("filter", "INPUT", "-j B"),
                ]
            ),
            "-j B",
            "-j A",
            id="rules-removed",
        ),
        pytest.param(
            PlanDiff(
                rules_added=[
                    RuleChange("filter", "OUTPUT", "-j A"),
                    RuleChange("filter", "INPUT", "-j B"),
                ]
            ),
            "-j B",
            "-j A",
            id="rules-added",
        ),
        pytest.param(
            PlanDiff(
                foreign_chains=[
                    ForeignChain("filter", "ZULU"),
                    ForeignChain("filter", "ALFA"),
                ]
            ),
            "ALFA",
            "ZULU",
            id="foreign-chains",
        ),
        pytest.param(
            PlanDiff(
                desuet_chains=[
                    DesuetChain("filter", "ZULU"),
                    DesuetChain("filter", "ALFA"),
                ]
            ),
            "ALFA",
            "ZULU",
            id="desuet-chains",
        ),
        pytest.param(
            PlanDiff(
                chain_rebuilds=[
                    ChainRebuild("filter", "ZULU", "0", "10"),
                    ChainRebuild("filter", "ALFA", "0", "10"),
                ]
            ),
            "ALFA",
            "ZULU",
            id="chain-rebuilds",
        ),
    ],
)
def test_structured_sorts_by_chain(
    diff: PlanDiff, first: str, second: str
) -> None:
    out = render_structured(plan_ip(diff))
    assert out.index(first) < out.index(second)


def test_structured_set_changes_sorted_by_name() -> None:
    diff = PlanDiff(
        set_changes=[
            SetChange("filter", "zeta", SetChangeKind.ADD, ["1"]),
            SetChange("filter", "alfa", SetChangeKind.ADD, ["2"]),
        ]
    )
    out = render_structured(plan_ip(diff))
    assert out.index("alfa") < out.index("zeta")


def test_structured_set_add_lists_elements_joined_by_comma() -> None:
    diff = PlanDiff(
        set_changes=[
            SetChange("filter", "ssh", SetChangeKind.ADD, ["80", "22"])
        ]
    )
    out = render_structured(plan_ip(diff))
    assert "+ set filter/ssh { 80, 22 }" in out


def test_structured_set_modify_lists_elements_joined_by_comma() -> None:
    diff = PlanDiff(
        set_changes=[
            SetChange("filter", "ssh", SetChangeKind.MODIFY, ["80", "22"])
        ]
    )
    out = render_structured(plan_ip(diff))
    assert "~ set filter/ssh { 80, 22 }" in out


def test_structured_set_remove_renders_minus_line() -> None:
    # A removed set renders as a bare '- set' line, never the '~ set { ... }'
    # modify form.
    diff = PlanDiff(
        set_changes=[SetChange("filter", "ssh", SetChangeKind.REMOVE, [])]
    )
    out = render_structured(plan_ip(diff))
    assert "- set filter/ssh" in out
    assert "~ set filter/ssh" not in out


def test_unified_includes_desuet_chain_in_its_table() -> None:
    # A desuet (removed base) chain must appear in the unified current side
    # under its own table, never filtered out by a table mismatch.
    diff = PlanDiff(desuet_chains=[DesuetChain("filter", "INPUT")])
    out = render_unified(plan_ip(diff))
    assert "base chain INPUT removed" in out


def test_unified_includes_set_change_in_its_table() -> None:
    # A set change must be emitted under its own table in the unified diff.
    diff = PlanDiff(
        set_changes=[SetChange("filter", "ssh", SetChangeKind.ADD, ["22"])]
    )
    out = render_unified(plan_ip(diff))
    assert "add set filter ssh" in out
