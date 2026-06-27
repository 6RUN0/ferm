"""
Unit tests for the base-chain priority knob (``chain FORWARD priority -1``).

The knob lets a config override the hardcoded ``_BASE_CHAIN_MAP``
priority of a built-in nft chain so ferm can order its own table
deterministically against a coexisting one (docker's forward chain sits
on ``priority filter`` = 0, the same slot as ferm's default).  These
tests pin the four seams: the parser stores the integer, the nft backend
emits it (and rejects it on a non-base chain), and the iptables backend
rejects it outright (chains have no priority there).
"""

from __future__ import annotations

import io
import re
import shutil
import subprocess

import pytest

from pyferm.backend.iptables import validate_names
from pyferm.backend.nft import NftBackend, NftBaseChain, build_chains
from pyferm.config import Options
from pyferm.domains import (
    ChainInfo,
    DomainInfo,
    TableInfo,
    resolve_chain_priority,
)
from pyferm.errors import FermError
from pyferm.functions import Evaluator
from pyferm.parser import Parser
from pyferm.plan import (
    build_nft_delta,
    canonicalize_nft_header,
    diff_tables,
    parse_nft_list,
    parse_nft_script,
)
from pyferm.scope import Frame, Scope
from pyferm.tokenizer import Script, Tokenizer

#: A live ``nft list table`` snapshot of FORWARD at a given priority.
_SNAPSHOT = (
    "table ip ferm {{\n"
    "\tchain FORWARD {{\n"
    "\t\ttype filter hook forward priority {priority}; policy accept;\n"
    "\t\tip saddr 10.0.0.1 drop\n"
    "\t}}\n"
    "}}\n"
)

#: The desired ``render().save`` of FORWARD at a given priority.
_DESIRED = (
    "add table ip ferm\n"
    "flush table ip ferm\n"
    "add chain ip ferm FORWARD {{ type filter hook forward "
    "priority {priority}; policy accept; }}\n"
    "add rule ip ferm FORWARD ip saddr 10.0.0.1 drop\n"
)


def _parse(source: str, *, options: Options | None = None) -> Parser:
    options = options if options is not None else Options(test=True)
    script = Script(filename="<test>", handle=io.StringIO(source))
    scope = Scope()
    scope.push(Frame())
    parser = Parser(Evaluator(Tokenizer(script), scope), {}, options)
    parser.enter(0, None)
    return parser


# --- parser: store the integer (form A: `priority -N` before `{`) ----------


def test_parser_stores_negative_priority() -> None:
    parser = _parse(
        "domain ip table filter chain FORWARD priority -1 {\n"
        "    policy ACCEPT;\n"
        "}\n"
    )
    chain = parser.domains["ip"].tables["filter"].chains["FORWARD"]
    assert chain.priority == -1
    # the chain attributes coexist: priority does not eat the policy.
    assert chain.policy == "ACCEPT"


def test_parser_stores_explicit_positive_priority() -> None:
    parser = _parse(
        "domain ip table filter chain INPUT priority 10 { policy DROP; }\n"
    )
    assert parser.domains["ip"].tables["filter"].chains["INPUT"].priority == 10


def test_parser_default_priority_is_none() -> None:
    parser = _parse("domain ip table filter chain INPUT { policy DROP; }\n")
    chain = parser.domains["ip"].tables["filter"].chains["INPUT"]
    assert chain.priority is None


def test_parser_rejects_non_integer_priority() -> None:
    with pytest.raises(FermError, match="priority"):
        _parse("domain ip table filter chain FORWARD priority foo { }\n")


# --- nft backend: emit the override, reject on a non-base chain ------------


def test_render_emits_overridden_priority() -> None:
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    table.chains.setdefault("FORWARD", ChainInfo(policy="ACCEPT", priority=-1))
    save = NftBackend().render("ip", info, Options(test=True)).save
    assert save is not None
    assert (
        "add chain ip ferm FORWARD "
        "{ type filter hook forward priority -1; policy accept; }\n"
    ) in save


def test_render_without_override_keeps_default_priority() -> None:
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    table.chains.setdefault("FORWARD", ChainInfo(policy="ACCEPT"))
    save = NftBackend().render("ip", info, Options(test=True)).save
    assert save is not None
    assert "hook forward priority 0;" in save


def test_build_chains_overrides_base_priority() -> None:
    table = TableInfo()
    table.chains["FORWARD"] = ChainInfo(priority=-1)
    chains = build_chains("ip", "filter", table)
    base = next(c for c in chains if isinstance(c, NftBaseChain))
    assert base.priority == -1


def test_build_chains_rejects_priority_on_user_chain() -> None:
    table = TableInfo()
    table.chains["mychain"] = ChainInfo(priority=-1)
    with pytest.raises(FermError, match="priority"):
        build_chains("ip", "filter", table)


# --- iptables backend: no chain priority exists; reject fail-closed --------


def test_iptables_rejects_priority() -> None:
    info = DomainInfo()
    table = info.tables.setdefault("filter", TableInfo())
    table.chains.setdefault("FORWARD", ChainInfo(policy="ACCEPT", priority=-1))
    with pytest.raises(FermError, match="priority"):
        validate_names(info)


# --- delta-apply (Fix A): a priority change rebuilds the chain ------------


def test_priority_change_rebuilds_chain_in_delta() -> None:
    # A priority change cannot be a bare redeclare: nft rejects "already
    # exists with different declaration".  The delta must delete + recreate
    # + re-emit the chain's rules, in one transaction, delete first.
    delta = build_nft_delta(
        _SNAPSHOT.format(priority="0"),
        _DESIRED.format(priority="-1"),
        family="ip",
    )
    assert delta is not None
    assert "delete chain ip ferm FORWARD" in delta
    assert (
        "add chain ip ferm FORWARD { type filter hook forward "
        "priority -1; policy accept; }" in delta
    )
    assert "add rule ip ferm FORWARD ip saddr 10.0.0.1 drop" in delta
    assert delta.index("delete chain ip ferm FORWARD") < delta.index(
        "add chain ip ferm FORWARD {"
    )


def test_priority_unchanged_delta_is_empty() -> None:
    # Same priority + same rules -> no delta at all (counters survive).
    delta = build_nft_delta(
        _SNAPSHOT.format(priority="-1"),
        _DESIRED.format(priority="-1"),
        family="ip",
    )
    assert delta == ""


def test_priority_change_is_rebuild_not_policy_change() -> None:
    current = parse_nft_list(_SNAPSHOT.format(priority="0"), family="ip")
    desired = parse_nft_script(_DESIRED.format(priority="-1"))
    diff = diff_tables(current, desired, noflush=False)
    assert [cr.chain for cr in diff.chain_rebuilds] == ["FORWARD"]
    assert diff.policy_changes == []
    assert diff.has_changes()


def test_policy_only_change_is_not_a_rebuild() -> None:
    # Priority equal, only the policy word flips: stays a policy change
    # (bare redeclare, counters survive) -- not a rebuild.
    current = parse_nft_list(
        "table ip ferm {\n\tchain FORWARD {\n"
        "\t\ttype filter hook forward priority 0; policy accept;\n"
        "\t}\n}\n",
        family="ip",
    )
    desired = parse_nft_script(
        "add table ip ferm\nflush table ip ferm\n"
        "add chain ip ferm FORWARD { type filter hook forward "
        "priority 0; policy drop; }\n"
    )
    diff = diff_tables(current, desired, noflush=False)
    assert diff.chain_rebuilds == []
    assert [pc.chain for pc in diff.policy_changes] == ["FORWARD"]


def test_plan_output_reports_priority_rebuild() -> None:
    # --plan must not silently drop a priority change: it surfaces as a
    # rebuild line and a summary clause, not as a (misleading) policy change.
    from pyferm.plan import Plan, render_structured

    current = parse_nft_list(_SNAPSHOT.format(priority="0"), family="ip")
    desired = parse_nft_script(_DESIRED.format(priority="-1"))
    diff = diff_tables(current, desired, noflush=False)
    out = render_structured(Plan(families={"ip": diff}))
    assert "chain ferm/FORWARD priority 0 -> -1 (rebuilt" in out
    assert "1 chain rebuilt" in out


# --- canonicalization: nft's offset display resolves to numeric -----------


@pytest.mark.parametrize(
    ("display", "numeric"),
    [
        ("filter - 1", "-1"),
        ("filter + 5", "5"),
        ("security - 1", "49"),
        ("mangle - 1", "-151"),
        ("raw - 1", "-301"),
        ("mangle", "-150"),
        ("-200", "-200"),
    ],
)
def test_canon_resolves_priority_display(display: str, numeric: str) -> None:
    # nft pretty-prints a priority near a landmark as an offset
    # (empirically verified on nft v1.1.6).  Canon must resolve it to the
    # integer so the config side (always numeric) matches.
    canon = canonicalize_nft_header(
        f"type filter hook forward priority {display}", family="ip"
    )
    assert f"priority {numeric} " in f"{canon} "


def test_priority_offset_kernel_form_is_idempotent_delta() -> None:
    # The kernel reports -1 as 'filter - 1'; re-applying the same config must
    # produce no delta -- no spurious rebuild that would reset counters.
    kernel_snapshot = (
        "table ip ferm {\n\tchain FORWARD {\n"
        "\t\ttype filter hook forward priority filter - 1; policy accept;\n"
        "\t\tip saddr 10.0.0.1 drop\n"
        "\t}\n}\n"
    )
    delta = build_nft_delta(
        kernel_snapshot, _DESIRED.format(priority="-1"), family="ip"
    )
    assert delta == ""


# --- parser: nft landmark-name priorities resolve to integers --------------


@pytest.mark.parametrize(
    ("syntax", "expected"),
    [
        ("filter", 0),
        ("dstnat", -100),
        ("security", 50),
        ("srcnat", 100),
        ("raw", -300),
        ("dstnat - 10", -110),  # spaced offset
        ("filter + 5", 5),
        ("filter+5", 5),  # joined offset, a single token
        ("mangle - 1", -151),
    ],
)
def test_parser_resolves_landmark_priority(syntax: str, expected: int) -> None:
    # nft displays priorities by landmark name; ferm must accept the same
    # spelling on input and resolve it to the integer netfilter stores.
    parser = _parse(
        f"domain ip table filter chain FORWARD priority {syntax} {{\n"
        "    policy ACCEPT;\n"
        "}\n"
    )
    chain = parser.domains["ip"].tables["filter"].chains["FORWARD"]
    assert chain.priority == expected


def test_parser_resolves_landmark_per_family() -> None:
    # bridge landmarks differ from inet: `filter` is -200 there, 0 for ip.
    # The resolver keys off the ferm domain, so each family gets its own value.
    parser = _parse(
        "domain eb table filter chain FORWARD priority filter { }\n"
    )
    chain = parser.domains["eb"].tables["filter"].chains["FORWARD"]
    assert chain.priority == -200


def test_parser_rejects_unknown_landmark() -> None:
    with pytest.raises(FermError, match="Invalid chain priority: bogus"):
        _parse("domain ip table filter chain FORWARD priority bogus { }\n")


# --- hardening: priority distributes over chain arrays and dual-stack -------


def test_priority_applies_to_each_chain_in_array() -> None:
    parser = _parse(
        "domain ip table filter chain (FORWARD OUTPUT) priority -1 {\n"
        "    policy ACCEPT;\n"
        "}\n"
    )
    chains = parser.domains["ip"].tables["filter"].chains
    assert chains["FORWARD"].priority == -1
    assert chains["OUTPUT"].priority == -1


def test_priority_applies_to_each_family_in_dual_stack() -> None:
    parser = _parse(
        "domain (ip ip6) table filter chain FORWARD priority -1 {\n"
        "    policy ACCEPT;\n"
        "}\n"
    )
    ip = parser.domains["ip"].tables["filter"].chains["FORWARD"]
    ip6 = parser.domains["ip6"].tables["filter"].chains["FORWARD"]
    assert ip.priority == -1
    assert ip6.priority == -1


def test_dual_stack_landmark_resolves_per_family() -> None:
    # ip and ip6 share inet landmarks, so `filter - 1` is -1 on both.
    parser = _parse(
        "domain (ip ip6) table filter chain FORWARD priority filter - 1 {\n"
        "    policy ACCEPT;\n"
        "}\n"
    )
    ip = parser.domains["ip"].tables["filter"].chains["FORWARD"]
    ip6 = parser.domains["ip6"].tables["filter"].chains["FORWARD"]
    assert ip.priority == -1
    assert ip6.priority == -1


# --- diff-format surfaces the priority rebuild -----------------------------


def test_diff_format_reports_priority_rebuild() -> None:
    # --plan-format=diff must show a priority change as a rebuild, with the
    # old priority removed and the new one added -- never silently dropped.
    from pyferm.plan import Plan, render_plan

    current = parse_nft_list(_SNAPSHOT.format(priority="0"), family="ip")
    desired = parse_nft_script(_DESIRED.format(priority="-1"))
    diff = diff_tables(current, desired, noflush=False)
    out = render_plan(Plan(families={"ip": diff}), fmt="diff")
    assert "-:FORWARD priority 0" in out
    assert "+:FORWARD priority -1" in out


# --- review follow-ups ------------------------------------------------------

#: A live snapshot of FORWARD at priority 0 carrying a {rule}.
_SNAPSHOT_RULE = (
    "table ip ferm {{\n"
    "\tchain FORWARD {{\n"
    "\t\ttype filter hook forward priority 0; policy accept;\n"
    "\t\t{rule}\n"
    "\t}}\n"
    "}}\n"
)

#: The desired save of FORWARD at priority -1 carrying a {rule}.
_DESIRED_PRIO_RULE = (
    "add table ip ferm\n"
    "flush table ip ferm\n"
    "add chain ip ferm FORWARD {{ type filter hook forward "
    "priority -1; policy accept; }}\n"
    "add rule ip ferm FORWARD {rule}\n"
)


# Fix 1: a coincident priority + rule change reports ONLY the rebuild ---------


def test_priority_plus_rule_change_suppresses_rule_diff() -> None:
    # When priority AND the rule set change together, the rebuild re-emits all
    # desired rules, so --plan must report the chain once (as a rebuild) and
    # NOT also as N rules added/removed (which would double-count).
    current = parse_nft_list(
        _SNAPSHOT_RULE.format(rule="ip saddr 10.0.0.1 drop"), family="ip"
    )
    desired = parse_nft_script(
        _DESIRED_PRIO_RULE.format(rule="ip saddr 10.0.0.2 drop")
    )
    diff = diff_tables(current, desired, noflush=False)
    assert [cr.chain for cr in diff.chain_rebuilds] == ["FORWARD"]
    assert diff.rules_added == []
    assert diff.rules_removed == []


def test_priority_plus_rule_change_summary_counts_only_rebuild() -> None:
    from pyferm.plan import Plan, render_structured

    current = parse_nft_list(
        _SNAPSHOT_RULE.format(rule="ip saddr 10.0.0.1 drop"), family="ip"
    )
    desired = parse_nft_script(
        _DESIRED_PRIO_RULE.format(rule="ip saddr 10.0.0.2 drop")
    )
    diff = diff_tables(current, desired, noflush=False)
    out = render_structured(Plan(families={"ip": diff}))
    assert (
        "Plan: 0 to add, 0 to remove, 0 policy changes, 1 chain rebuilt"
        in (out)
    )
    # the chain surfaces once, as the rebuild line -- no stray rule +/- lines.
    assert "10.0.0.1" not in out
    assert "10.0.0.2" not in out


def test_priority_plus_rule_change_apply_reemits_new_rule() -> None:
    # The rebuild still installs the new rule and drops the old one at apply,
    # even though the per-rule diff is suppressed for the --plan view.
    delta = build_nft_delta(
        _SNAPSHOT_RULE.format(rule="ip saddr 10.0.0.1 drop"),
        _DESIRED_PRIO_RULE.format(rule="ip saddr 10.0.0.2 drop"),
        family="ip",
    )
    assert delta is not None
    assert "ip saddr 10.0.0.2 drop" in delta
    assert "10.0.0.1" not in delta


# Fix 2: a sign glued to the number after a landmark is accepted -------------


@pytest.mark.parametrize(
    ("syntax", "expected"),
    [
        ("filter -1", -1),
        ("filter +5", 5),
        ("security -1", 49),
        ("dstnat -10", -110),
    ],
)
def test_parser_accepts_glued_sign_after_landmark(
    syntax: str, expected: int
) -> None:
    # nft pretty-prints `filter - 1`, but a user may glue the sign to the
    # number (`filter -1`); accept it rather than failing with a confusing
    # "Unrecognized keyword: -1".
    parser = _parse(
        f"domain ip table filter chain FORWARD priority {syntax} {{\n"
        "    policy ACCEPT;\n"
        "}\n"
    )
    chain = parser.domains["ip"].tables["filter"].chains["FORWARD"]
    assert chain.priority == expected


# Fix 3: arp accepts only the `filter` landmark (nft rejects the rest) -------


def test_parser_accepts_filter_landmark_on_arp() -> None:
    parser = _parse(
        "domain arp table filter chain INPUT priority filter { }\n"
    )
    assert parser.domains["arp"].tables["filter"].chains["INPUT"].priority == 0


@pytest.mark.parametrize("landmark", ["srcnat", "dstnat", "raw", "security"])
def test_parser_rejects_inet_landmark_on_arp(landmark: str) -> None:
    # nft accepts only `filter` priority for the arp family; the other inet
    # landmarks are meaningless there (nft: "invalid priority expression
    # value in this context"), so ferm rejects them at the border.
    with pytest.raises(FermError, match="Invalid chain priority"):
        _parse(
            f"domain arp table filter chain INPUT priority {landmark} {{ }}\n"
        )


# Fix 4: resolve_chain_priority validates int32 range and rejects exotica ----


@pytest.mark.parametrize(
    "text",
    ["2147483648", "-2147483649", "1_000", "١٢٣", "0x10"],
)
def test_resolve_priority_rejects_out_of_range_or_nonascii(text: str) -> None:
    # nft chain priority is a signed 32-bit integer; reject overflow and the
    # forms Python's lenient int() would otherwise accept (underscores,
    # non-ASCII digits) so the border error is clear, not a kernel reject.
    # The rejected token is always echoed in the ValueError message.
    with pytest.raises(ValueError, match=re.escape(text)):
        resolve_chain_priority("ip", text)


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("2147483647", 2147483647),
        ("-2147483648", -2147483648),
        ("+5", 5),
        (" -1 ", -1),
        ("0", 0),
    ],
)
def test_resolve_priority_accepts_valid_int32(text: str, value: int) -> None:
    assert resolve_chain_priority("ip", text) == value


def test_resolve_priority_offset_overflow_rejected() -> None:
    # A landmark offset can also overflow int32; the range check runs on the
    # resolved value, not just on a plain integer literal.
    with pytest.raises(ValueError, match="out of range"):
        resolve_chain_priority("ip", "filter + 9999999999")


# Fix 7: a duplicate priority on one chain warns (last wins) -----------------


def test_duplicate_priority_warns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = _parse(
        "domain ip table filter chain FORWARD priority -1 priority -2 {\n"
        "    policy ACCEPT;\n"
        "}\n"
    )
    chain = parser.domains["ip"].tables["filter"].chains["FORWARD"]
    assert chain.priority == -2  # last wins
    assert "priority is already specified" in capsys.readouterr().err.lower()


# Fix 8 (MAJOR): kernel-coupled guard for the landmark table -----------------
#
# The unit tests above prove the canonicalizer against a hardcoded model of
# nft's offset display.  This test closes that self-referential gap: it asks a
# LIVE nft how it displays each landmark's integer and asserts the
# canonicalizer resolves that display back to the same integer.  If a future
# nft renames a landmark or shifts its value, this fails -- the model and the
# kernel have drifted.  Runs in a rootless network namespace so the host
# firewall is never touched; auto-skips where rootless nft is unavailable
# (e.g. constrained CI), so it is opportunistic, not a hard dependency.


def _rootless_nft_available() -> bool:
    if shutil.which("nft") is None or shutil.which("unshare") is None:
        return False
    try:
        probe = subprocess.run(
            ["unshare", "-rn", "nft", "list", "ruleset"],
            capture_output=True,
            encoding="utf-8",
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


def _nft_priority_display(value: int) -> str | None:
    """Ask live rootless nft how it displays a forward chain at ``value``."""
    script = (
        "add table ip ferm_probe; "
        "add chain ip ferm_probe c { type filter hook forward "
        f"priority {value} ; }}; "
        "list chain ip ferm_probe c"
    )
    proc = subprocess.run(
        ["unshare", "-rn", "nft", "-f", "-"],
        input=script,
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=15,
    )
    if proc.returncode != 0:
        return None
    match = re.search(r"priority\s+(?P<token>[^;]+?)\s*;", proc.stdout)
    return match.group("token") if match else None


@pytest.mark.skipif(
    not _rootless_nft_available(),
    reason="needs a working rootless `unshare -rn nft`",
)
@pytest.mark.parametrize(
    "value", [-300, -150, -100, -1, 0, 5, 49, 50, 100, 150]
)
def test_landmark_table_matches_live_nft_display(value: int) -> None:
    display = _nft_priority_display(value)
    assert display is not None, f"live nft refused priority {value}"
    canon = canonicalize_nft_header(
        f"type filter hook forward priority {display}", family="ip"
    )
    assert f"priority {value} " in f"{canon} ", (
        f"nft displays priority {value} as {display!r}, but the canonicalizer "
        f"resolved it to {canon!r} -- landmark table has drifted from the "
        "kernel"
    )
