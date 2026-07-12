"""The table differ: diff_tables over parsed current/desired state."""

from __future__ import annotations

import difflib

from .model import (
    ChainRebuild,
    DesuetChain,
    ForeignChain,
    ObjectChange,
    ParsedChain,
    ParsedTable,
    PlanDiff,
    PolicyChange,
    RuleChange,
    SetChange,
    SetChangeKind,
)
from .readback import _header_priority


def _is_builtin(chain: ParsedChain) -> bool:
    """
    Return True when the chain is built-in (carries a real policy).

    User chains carry ``-`` as their policy placeholder.
    """
    return chain.policy != "-"


def _diff_rules(
    current: list[str], desired: list[str]
) -> tuple[list[str], list[str]]:
    """
    Compute a positional multiset diff of two ordered rule lists.

    Uses :class:`difflib.SequenceMatcher` so order is significant and a
    duplicated rule body is not collapsed (a set-diff would silently
    under-count a removed copy).  Returns ``(added, removed)``.
    """
    added: list[str] = []
    removed: list[str] = []
    matcher = difflib.SequenceMatcher(a=current, b=desired, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            removed.extend(current[i1:i2])
        if tag in ("replace", "insert"):
            added.extend(desired[j1:j2])
    return added, removed


def diff_tables(
    current: dict[str, ParsedTable],
    desired: dict[str, ParsedTable],
    *,
    noflush: bool,
) -> PlanDiff:
    """
    Diff one family's current (kernel) model against the desired (config).

    Tables present in ``desired`` are diffed.  ferm's save text carries every
    table it read from the kernel (``rules_to_save`` iterates the dump-seeded
    ``domain_info.tables``), so an unmanaged kernel table (nat/mangle) appears
    in ``desired`` as an empty skeleton and its live rules diff as removals --
    there is no "untouched foreign table" case.  A table only in ``current``
    would genuinely not be in ferm's restore input, so it is not touched and
    produces no diff.  Within a table: built-in policies diff by chain name;
    rules diff positionally; a user chain only in ``current`` is a foreign
    chain (warning, flushed unless ``--noflush``).

    Under ``--noflush``: rule removals are suppressed for built-in and
    undeclared chains (their rules survive) but kept for declared user chains
    (those are flushed); policy changes and foreign-chain warnings follow the
    same survives/flushed split.
    """
    diff = PlanDiff(noflush=noflush, current_empty=not current)

    for table_name, desired_table in desired.items():
        current_table = current.get(table_name)
        current_chains = current_table.chains if current_table else {}

        for chain_name, desired_chain in desired_table.chains.items():
            current_chain = current_chains.get(chain_name)
            current_rules = current_chain.rules if current_chain else []
            chain_rebuilt = False

            if (
                current_chain is not None
                and _is_builtin(current_chain)
                and desired_chain.policy != current_chain.policy
            ):
                old_priority = _header_priority(current_chain.policy)
                new_priority = _header_priority(desired_chain.policy)
                if old_priority != new_priority:
                    # Priority is baked into the chain declaration; nft
                    # rejects an in-place redeclare with a different priority,
                    # so rebuild (delete + recreate + re-emit rules).  A
                    # coincident policy change rides along in the new decl.
                    chain_rebuilt = True
                    diff.chain_rebuilds.append(
                        ChainRebuild(
                            table_name,
                            chain_name,
                            old_priority or "",
                            new_priority or "",
                        )
                    )
                else:
                    diff.policy_changes.append(
                        PolicyChange(
                            table_name,
                            chain_name,
                            current_chain.policy,
                            desired_chain.policy,
                        )
                    )

            if chain_rebuilt:
                # The rebuild re-emits all desired rules verbatim (it deletes
                # and recreates the chain), so a coincident rule delta is
                # subsumed.  Skip the per-rule diff to avoid double-counting
                # the same chain as both "rebuilt" and "N rules added/removed".
                continue

            added, removed = _diff_rules(current_rules, desired_chain.rules)
            diff.rules_added.extend(
                RuleChange(table_name, chain_name, r) for r in added
            )
            # --noflush: only a declared user chain is flushed; built-in and
            # undeclared chains keep their rules, so suppress their removals.
            builtin = current_chain is not None and _is_builtin(current_chain)
            declared_user = current_chain is not None and not builtin
            # Always emit the removal, unless --noflush keeps the rules of a
            # chain that is not a declared user chain (built-in/undeclared
            # chains survive).
            emit_removal = not noflush or declared_user
            if emit_removal:
                diff.rules_removed.extend(
                    RuleChange(table_name, chain_name, r) for r in removed
                )

        # named set diff: sets added, modified, or removed
        current_sets = current_table.sets if current_table else {}
        for set_name, desired_set in desired_table.sets.items():
            current_set = current_sets.get(set_name)
            if current_set is None:
                diff.set_changes.append(
                    SetChange(
                        table_name,
                        set_name,
                        SetChangeKind.ADD,
                        desired_set.elements,
                    )
                )
            elif (current_set.type_, current_set.flags) != (
                desired_set.type_,
                desired_set.flags,
            ):
                # Type/flags cannot be altered in place: drop the set and
                # recreate it (the elements are lawfully lost -- the type
                # changed).  Remove precedes add so one transaction reuses
                # the name.
                diff.set_changes.append(
                    SetChange(table_name, set_name, SetChangeKind.REMOVE, [])
                )
                diff.set_changes.append(
                    SetChange(
                        table_name,
                        set_name,
                        SetChangeKind.ADD,
                        desired_set.elements,
                    )
                )
            elif (
                not desired_set.is_dynamic
                and current_set.elements != desired_set.elements
            ):
                # A dynamic set never reaches MODIFY: past the type/flags
                # gate above both sides are dynamic, and its elements are
                # kernel-accrued runtime state (see ParsedSet).
                diff.set_changes.append(
                    SetChange(
                        table_name,
                        set_name,
                        SetChangeKind.MODIFY,
                        desired_set.elements,
                        current_elements=current_set.elements,
                    )
                )
        for set_name in current_sets:
            if set_name not in desired_table.sets:
                diff.set_changes.append(
                    SetChange(table_name, set_name, SetChangeKind.REMOVE, [])
                )

        # table object diff: objects are content-addressed (the name fixes the
        # body), so this is a pure name-set diff -- an add for a desired-only
        # name, a remove for a current-only one, never an in-place modify.
        current_objects = current_table.objects if current_table else {}
        for obj_name, desired_obj in desired_table.objects.items():
            if obj_name not in current_objects:
                diff.object_changes.append(
                    ObjectChange(
                        table_name, obj_name, desired_obj.kind, added=True
                    )
                )
        for obj_name, current_obj in current_objects.items():
            if obj_name not in desired_table.objects:
                diff.object_changes.append(
                    ObjectChange(
                        table_name, obj_name, current_obj.kind, added=False
                    )
                )

        # foreign chains: user chains in the managed table absent from config
        for chain_name, current_chain in current_chains.items():
            if chain_name in desired_table.chains:
                continue
            if _is_builtin(current_chain):
                diff.desuet_chains.append(DesuetChain(table_name, chain_name))
                continue
            if noflush:
                continue  # undeclared user chains survive under --noflush
            diff.foreign_chains.append(ForeignChain(table_name, chain_name))

    return diff
