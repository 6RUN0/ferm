"""SetChange arm in diff_tables + iptables no-op invariant."""

from pyferm.plan import (
    ParsedSet,
    ParsedTable,
    Plan,
    PlanDiff,
    SetChange,
    SetChangeKind,
    canonicalize_nft_rule,
    diff_tables,
    parse_nft_list,
    parse_nft_script,
    render_structured,
    render_unified,
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
    assert sc.kind == SetChangeKind.ADD
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
    assert sc.kind == SetChangeKind.REMOVE
    assert sc.elements == []


def test_set_modified() -> None:
    diff = diff_tables(
        current=_table_with_set("ssh", ["22"]),
        desired=_table_with_set("ssh", ["22", "2222"]),
        noflush=False,
    )
    assert diff.has_changes()
    sc = next(c for c in diff.set_changes if c.name == "ssh")
    assert sc.kind == SetChangeKind.MODIFY
    assert sc.elements == ["22", "2222"]
    # the live side travels with the change so the diff can show what the
    # elements change FROM.
    assert sc.current_elements == ["22"]


def test_modified_set_diff_shows_current_elements() -> None:
    # A MODIFY used to render the current side as a bare `add set` line,
    # hiding WHICH elements disappear; both sides must show elements.
    diff = diff_tables(
        current=_table_with_set("ssh", ["22"]),
        desired=_table_with_set("ssh", ["22", "2222"]),
        noflush=False,
    )
    out = render_unified(Plan(families={"ip": diff}))
    assert "-add set ferm ssh { 22 }" in out
    assert "+add set ferm ssh { 22, 2222 }" in out


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
            SetChange(
                table="ferm",
                name="ssh",
                kind=SetChangeKind.ADD,
                elements=["22"],
            )
        ],
    )
    plan = Plan(families={"ip": diff})
    out = render_structured(plan)
    assert "ssh" in out
    # At minimum a '+' or '-' set marker must appear
    assert "+" in out or "-" in out
    # Must not fall through to "No changes"
    assert "No changes" not in out


def test_prefix_aligned_range_set_converges_round_trip() -> None:
    # An interval set written as a prefix-aligned address range converges:
    # ferm emits the range, the kernel reads it back as the equivalent CIDR,
    # and canonicalization on both diff sides must make them compare equal --
    # otherwise an unchanged set shows a perpetual phantom "modify".
    desired = parse_nft_script(
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add set ip ferm r { type ipv4_addr; flags interval; }\n"
        "add element ip ferm r { 10.0.0.0-10.0.0.255, 172.16.0.5 }\n"
    )
    current = parse_nft_list(
        "table ip ferm {\n"
        "\tset r {\n"
        "\t\ttype ipv4_addr\n"
        "\t\tflags interval\n"
        "\t\telements = { 10.0.0.0/24, 172.16.0.5 }\n"
        "\t}\n"
        "}\n",
        family="ip",
    )
    assert desired["ferm"].sets["r"].elements == ["10.0.0.0/24", "172.16.0.5"]
    diff = diff_tables(current=current, desired=desired, noflush=False)
    assert diff.set_changes == []


def test_inline_anonymous_range_set_normalizes_to_cidr() -> None:
    # The inline `{ ... }` rule-text path (plan.py _normalize_sets) must
    # canonicalize an aligned range to the CIDR the kernel reads back, so a
    # rule carrying an anonymous interval set converges on both diff sides.
    desired = canonicalize_nft_rule(
        "ip saddr { 10.0.0.0-10.0.0.255 } accept", family="ip"
    )
    current = canonicalize_nft_rule(
        "ip saddr { 10.0.0.0/24 } accept", family="ip"
    )
    assert desired == current
    assert "{ 10.0.0.0/24 }" in desired


def test_ifname_named_set_same_membership_different_order_is_noop() -> None:
    # A named ifname set desired in config order vs the kernel's lexical
    # readback order must canonicalize equal, or an unchanged set shows a
    # perpetual phantom "modify" (see nftset.RANK_QUOTED).
    desired = parse_nft_script(
        "add table ip ferm\n"
        "flush table ip ferm\n"
        "add set ip ferm ifaces { type ifname; }\n"
        'add element ip ferm ifaces { "wlan0", "eth1", "eth0", "ppp1" }\n'
    )
    current = parse_nft_list(
        "table ip ferm {\n"
        "\tset ifaces {\n"
        "\t\ttype ifname\n"
        '\t\telements = { "eth0", "eth1", "ppp1", "wlan0" }\n'
        "\t}\n"
        "}\n",
        family="ip",
    )
    assert desired["ferm"].sets["ifaces"].elements == [
        '"eth0"',
        '"eth1"',
        '"ppp1"',
        '"wlan0"',
    ]
    diff = diff_tables(current=current, desired=desired, noflush=False)
    assert diff.set_changes == []


def test_inline_l4proto_set_orders_by_protocol_number() -> None:
    # A folded `meta l4proto { ... }` carries protocol names; nft reads the
    # set back ordered by protocol *number* while keeping the names.  Both diff
    # sides must canonicalize to that order or two adjacent protocol-only
    # rules folding into a set show a perpetual phantom "change".
    #
    # esp (50) and ah (51) are chosen deliberately: their alphabetical order
    # (ah, esp) is the reverse of their protocol-number order (esp, ah), so a
    # regression to a plain alphabetical sort fails this test.  A tcp/udp pair
    # would not -- its two orderings coincide, hiding the bug.
    desired = canonicalize_nft_rule(
        "meta l4proto { ah, esp } accept", family="ip"
    )
    current = canonicalize_nft_rule(
        "meta l4proto { esp, ah } accept", family="ip"
    )
    assert desired == current
    assert "{ esp, ah }" in desired
    assert "{ ah, esp }" not in desired
