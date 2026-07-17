"""Plan renderers: structured, unified and summary output."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

from ..config import PlanFormat
from .model import Plan, PlanDiff, SetChangeKind

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


def _plural(count: int, noun: str) -> str:
    """Naive plural: append ``s`` unless the count is exactly one."""
    return noun if count == 1 else noun + "s"


def _clause(count: int, noun: str, verb: str) -> str:
    """Build one ``, N noun(s) verb`` summary_line clause."""
    return f", {count} {_plural(count, noun)} {verb}"


@dataclass(frozen=True)
class DeltaCounts:
    """
    The per-category change counts of one diff (or a summed plan).

    The single counting authority behind both the commit-subject tail
    (:func:`delta_phrase`) and the body summary (:func:`summary_line`),
    so the two can never disagree.
    """

    rules_added: int = 0
    rules_removed: int = 0
    policies: int = 0
    chains_removed: int = 0
    chains_rebuilt: int = 0
    sets_changed: int = 0
    objects_changed: int = 0

    def __add__(self, other: DeltaCounts) -> DeltaCounts:
        """Per-field sum -- fold a plan's families into one delta."""
        return DeltaCounts(
            rules_added=self.rules_added + other.rules_added,
            rules_removed=self.rules_removed + other.rules_removed,
            policies=self.policies + other.policies,
            chains_removed=self.chains_removed + other.chains_removed,
            chains_rebuilt=self.chains_rebuilt + other.chains_rebuilt,
            sets_changed=self.sets_changed + other.sets_changed,
            objects_changed=self.objects_changed + other.objects_changed,
        )


def count_changes(diff: PlanDiff) -> DeltaCounts:
    """Count one diff's changes per category (desuet+foreign fold)."""
    return DeltaCounts(
        rules_added=len(diff.rules_added),
        rules_removed=len(diff.rules_removed),
        policies=len(diff.policy_changes),
        chains_removed=len(diff.desuet_chains) + len(diff.foreign_chains),
        chains_rebuilt=len(diff.chain_rebuilds),
        sets_changed=len(diff.set_changes),
        objects_changed=len(diff.object_changes),
    )


def delta_phrase(counts: DeltaCounts) -> str:
    """
    Render the commit-subject delta tail: ``+12/-3 rules, 1 policy``.

    Zero categories are suppressed entirely (the rules segment drops a
    zero side: ``+12 rules``, ``-42 rules``; at 0/0 the whole segment is
    omitted); an all-zero delta reads ``no changes``.
    """
    clauses: list[str] = []
    adds, removes = counts.rules_added, counts.rules_removed
    if adds and removes:
        clauses.append(f"+{adds}/-{removes} rules")
    elif adds:
        clauses.append(f"+{adds} {_plural(adds, 'rule')}")
    elif removes:
        clauses.append(f"-{removes} {_plural(removes, 'rule')}")
    if counts.policies:
        word = "policy" if counts.policies == 1 else "policies"
        clauses.append(f"{counts.policies} {word}")
    if counts.chains_removed:
        chains = _plural(counts.chains_removed, "chain")
        clauses.append(f"{counts.chains_removed} {chains} removed")
    if counts.chains_rebuilt:
        chains = _plural(counts.chains_rebuilt, "chain")
        clauses.append(f"{counts.chains_rebuilt} {chains} rebuilt")
    if counts.sets_changed:
        clauses.append(
            f"{counts.sets_changed} {_plural(counts.sets_changed, 'set')}"
        )
    if counts.objects_changed:
        objects = _plural(counts.objects_changed, "object")
        clauses.append(f"{counts.objects_changed} {objects}")
    return ", ".join(clauses) if clauses else "no changes"


def summary_line(diff: PlanDiff) -> str:
    """
    Build the ``Plan: N to add, M to remove, K policy changes`` tail.

    When desuet or foreign chains are present an extra
    ``, C chain(s) removed`` clause is appended so the summary reflects
    every change that will be applied -- not just rule-level deltas.
    """
    counts = count_changes(diff)
    pol_word = "change" if counts.policies == 1 else "changes"
    summary = (
        f"Plan: {counts.rules_added} to add,"
        f" {counts.rules_removed} to remove,"
        f" {counts.policies} policy {pol_word}"
    )
    if counts.chains_removed:
        summary += _clause(counts.chains_removed, "chain", "removed")
    if counts.chains_rebuilt:
        summary += _clause(counts.chains_rebuilt, "chain", "rebuilt")
    if counts.sets_changed:
        summary += _clause(counts.sets_changed, "set", "changed")
    if counts.objects_changed:
        summary += _clause(counts.objects_changed, "object", "changed")
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


class _TableKeyed(Protocol):
    """Structural type for diff items exposing a ``table`` field."""

    table: str


_ItemT = TypeVar("_ItemT", bound=_TableKeyed)


def _in_table(
    items: Iterable[_ItemT], table: str, key: Callable[[_ItemT], Any]
) -> list[_ItemT]:
    """Return ``items`` for ``table`` sorted by ``key`` (stable)."""
    return sorted((x for x in items if x.table == table), key=key)


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
        for change in _in_table(
            diff.policy_changes, table, key=lambda c: c.chain
        ):
            current.append(f":{change.chain} {change.old}")
            desired.append(f":{change.chain} {change.new}")
        for rebuild in _in_table(
            diff.chain_rebuilds, table, key=lambda cr: cr.chain
        ):
            current.append(f":{rebuild.chain} priority {rebuild.old}")
            desired.append(f":{rebuild.chain} priority {rebuild.new}")
        current.extend(
            f"# foreign chain {fchain.chain} will be flushed"
            for fchain in _in_table(
                diff.foreign_chains, table, key=lambda fchain: fchain.chain
            )
        )
        current.extend(
            f"# base chain {dchain.chain} removed (no longer declared)"
            for dchain in _in_table(
                diff.desuet_chains, table, key=lambda dchain: dchain.chain
            )
        )
        current.extend(
            f"-A {r.chain} {r.rule}"
            for r in _in_table(
                diff.rules_removed, table, key=lambda r: r.chain
            )
        )
        desired.extend(
            f"-A {r.chain} {r.rule}"
            for r in _in_table(diff.rules_added, table, key=lambda r: r.chain)
        )
        for sc in _in_table(diff.set_changes, table, key=lambda s: s.name):
            if sc.kind.touches_elements:
                elems = ", ".join(sc.elements)
                desired.append(f"add set {table} {sc.name} {{ {elems} }}")
            if sc.kind.is_removal:
                if sc.current_elements:
                    elems = ", ".join(sc.current_elements)
                    current.append(f"add set {table} {sc.name} {{ {elems} }}")
                else:
                    current.append(f"add set {table} {sc.name}")
        for oc in _in_table(diff.object_changes, table, key=lambda o: o.name):
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
