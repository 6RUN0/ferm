"""Plan renderers: structured, unified and summary output."""

from __future__ import annotations

import difflib

from ..config import PlanFormat
from .model import Plan, PlanDiff, SetChangeKind


def _clause(count: int, noun: str, verb: str) -> str:
    """Build one ``, N noun(s) verb`` summary_line clause."""
    plural = noun if count == 1 else noun + "s"
    return f", {count} {plural} {verb}"


def summary_line(diff: PlanDiff) -> str:
    """
    Build the ``Plan: N to add, M to remove, K policy changes`` tail.

    When desuet or foreign chains are present an extra
    ``, C chain(s) removed`` clause is appended so the summary reflects
    every change that will be applied -- not just rule-level deltas.
    """
    adds = len(diff.rules_added)
    removes = len(diff.rules_removed)
    policies = len(diff.policy_changes)
    chains_removed = len(diff.desuet_chains) + len(diff.foreign_chains)
    pol_word = "change" if policies == 1 else "changes"
    summary = (
        f"Plan: {adds} to add, {removes} to remove,"
        f" {policies} policy {pol_word}"
    )
    if chains_removed:
        summary += _clause(chains_removed, "chain", "removed")
    if rebuilt := len(diff.chain_rebuilds):
        summary += _clause(rebuilt, "chain", "rebuilt")
    if sets_changed := len(diff.set_changes):
        summary += _clause(sets_changed, "set", "changed")
    if objects_changed := len(diff.object_changes):
        summary += _clause(objects_changed, "object", "changed")
    return summary


def render_structured(plan: Plan) -> str:
    """Render the default human-readable plan, deterministic by sort order."""
    lines: list[str] = [
        f"family {f}: plan not supported for this family"
        for f in plan.unsupported
    ]

    if not plan.has_changes() and not plan.unsupported:
        return "No changes. Live ruleset matches the configuration.\n"

    for family in sorted(plan.families):
        diff = plan.families[family]
        if not diff.has_changes():
            continue
        lines.append(f"family {family}")
        if diff.current_empty:
            lines.append("  note: current ruleset is empty")
        if diff.noflush:
            lines.append(
                "  note: noflush -- existing built-in/undeclared rules"
                " kept; declared user chains overwritten; policies applied"
            )
            lines.append(
                "  note: noflush -- counts are the net positional diff;"
                " apply re-appends listed rules to unflushed chains, so"
                " live rules overlapping the config are duplicated"
            )
        lines.extend(
            f"  ~ policy {c.table}/{c.chain}: {c.old} -> {c.new}"
            for c in sorted(
                diff.policy_changes, key=lambda c: (c.table, c.chain)
            )
        )
        lines.extend(
            f"  - {r.rule}"
            for r in sorted(
                diff.rules_removed, key=lambda r: (r.table, r.chain)
            )
        )
        lines.extend(
            f"  + {r.rule}"
            for r in sorted(diff.rules_added, key=lambda r: (r.table, r.chain))
        )
        lines.extend(
            f"  warning: chain {fchain.table}/{fchain.chain} is not in"
            " the config and will be flushed"
            for fchain in sorted(
                diff.foreign_chains,
                key=lambda fchain: (fchain.table, fchain.chain),
            )
        )
        lines.extend(
            f"  ~ chain {dchain.table}/{dchain.chain} removed"
            " (base chain no longer declared)"
            for dchain in sorted(
                diff.desuet_chains,
                key=lambda dchain: (dchain.table, dchain.chain),
            )
        )
        lines.extend(
            f"  ~ chain {cr.table}/{cr.chain} priority {cr.old} -> {cr.new}"
            " (rebuilt; counters reset)"
            for cr in sorted(
                diff.chain_rebuilds,
                key=lambda cr: (cr.table, cr.chain),
            )
        )
        for sc in sorted(diff.set_changes, key=lambda s: (s.table, s.name)):
            if sc.kind == SetChangeKind.REMOVE:
                lines.append(f"  - set {sc.table}/{sc.name}")
            else:
                sign = "+" if sc.kind == SetChangeKind.ADD else "~"
                elems = ", ".join(sc.elements)
                lines.append(
                    f"  {sign} set {sc.table}/{sc.name} {{ {elems} }}"
                )
        for oc in sorted(diff.object_changes, key=lambda o: (o.table, o.name)):
            sign = "+" if oc.added else "-"
            lines.append(f"  {sign} {oc.kind} {oc.table}/{oc.name}")
        lines.append(f"  {summary_line(diff)}")

    return "\n".join(lines) + "\n"


def _diff_blob(diff: PlanDiff) -> tuple[list[str], list[str]]:
    """
    Build current/desired line lists for one family, for the unified diff.

    Multiset-preserving (ordered lists, never ``set`` -- two identical removed
    rules must stay two lines) and complete: policy changes (``:CHAIN POLICY``
    on both sides) and foreign chains are emitted too, so a lock-out via a
    policy flip or a flushed foreign chain is never hidden from
    ``--plan-format=diff``.  Sorts are by table first, then chain within each
    table, so duplicate rule bodies within the same table keep their relative
    order and stay distinct lines.
    """
    tables = sorted(
        {c.table for c in diff.policy_changes}
        | {r.table for r in diff.rules_removed}
        | {r.table for r in diff.rules_added}
        | {f.table for f in diff.foreign_chains}
        | {d.table for d in diff.desuet_chains}
        | {cr.table for cr in diff.chain_rebuilds}
        | {s.table for s in diff.set_changes}
        | {o.table for o in diff.object_changes}
    )
    current: list[str] = []
    desired: list[str] = []
    for table in tables:
        current.append(f"*{table}")
        desired.append(f"*{table}")
        for change in sorted(
            (c for c in diff.policy_changes if c.table == table),
            key=lambda c: c.chain,
        ):
            current.append(f":{change.chain} {change.old}")
            desired.append(f":{change.chain} {change.new}")
        for rebuild in sorted(
            (cr for cr in diff.chain_rebuilds if cr.table == table),
            key=lambda cr: cr.chain,
        ):
            current.append(f":{rebuild.chain} priority {rebuild.old}")
            desired.append(f":{rebuild.chain} priority {rebuild.new}")
        current.extend(
            f"# foreign chain {fchain.chain} will be flushed"
            for fchain in sorted(
                (fc for fc in diff.foreign_chains if fc.table == table),
                key=lambda fchain: fchain.chain,
            )
        )
        current.extend(
            f"# base chain {dchain.chain} removed (no longer declared)"
            for dchain in sorted(
                (dc for dc in diff.desuet_chains if dc.table == table),
                key=lambda dchain: dchain.chain,
            )
        )
        current.extend(
            f"-A {r.chain} {r.rule}"
            for r in sorted(
                (r for r in diff.rules_removed if r.table == table),
                key=lambda r: r.chain,
            )
        )
        desired.extend(
            f"-A {r.chain} {r.rule}"
            for r in sorted(
                (r for r in diff.rules_added if r.table == table),
                key=lambda r: r.chain,
            )
        )
        for sc in sorted(
            (s for s in diff.set_changes if s.table == table),
            key=lambda s: s.name,
        ):
            if sc.kind.touches_elements:
                elems = ", ".join(sc.elements)
                desired.append(f"add set {table} {sc.name} {{ {elems} }}")
            if sc.kind.is_removal:
                if sc.current_elements:
                    elems = ", ".join(sc.current_elements)
                    current.append(f"add set {table} {sc.name} {{ {elems} }}")
                else:
                    current.append(f"add set {table} {sc.name}")
        for oc in sorted(
            (o for o in diff.object_changes if o.table == table),
            key=lambda o: o.name,
        ):
            side = desired if oc.added else current
            side.append(f"add {oc.kind} {table} {oc.name}")
    return current, desired


def render_unified(plan: Plan) -> str:
    """Render a unified diff of the canonicalized save sections per family."""
    out: list[str] = [
        f"family {f}: plan not supported for this family"
        for f in plan.unsupported
    ]
    for family in sorted(plan.families):
        current, desired = _diff_blob(plan.families[family])
        out.extend(
            difflib.unified_diff(
                current,
                desired,
                fromfile=f"{family} (current)",
                tofile=f"{family} (desired)",
                lineterm="",
            )
        )
    if not out:
        return "No changes. Live ruleset matches the configuration.\n"
    return "\n".join(out) + "\n"


def render_plan(plan: Plan, *, fmt: PlanFormat) -> str:
    """Dispatch to the structured (default) or unified renderer."""
    if fmt == PlanFormat.DIFF:
        return render_unified(plan)
    return render_structured(plan)
