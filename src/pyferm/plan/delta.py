"""Incremental nft delta: emit_delta_script and the full-reload decision."""

from __future__ import annotations

from ..domains import (
    NFT_TABLE_NAME,
)
from ..errors import internal_error
from .diff import diff_tables
from .model import (
    _DESIRED_NAME_INDEX,
    ParsedTable,
    PlanDiff,
    SetChangeKind,
    _DesiredIndex,
)
from .readback import (
    _NFT_OBJ_CHAIN,
    _NFT_OBJ_ELEMENT,
    _NFT_OBJ_RULE,
    _NFT_OBJ_SECMARK,
    _NFT_OBJ_SET,
    parse_nft_list,
    parse_nft_script,
)


def _build_desired_index(desired_save: str) -> _DesiredIndex:
    """
    Index a ``render().save`` script into verbatim lines keyed by object name.

    Productions mirror :func:`parse_nft_script`; ``add table``/``flush table``
    carry no per-object content and are skipped, and ``delete table`` (the
    whole-table replace a full reload applies) resets the index so only
    objects after it count.  An unrecognized line is a render-contract
    violation (render produced it), so it raises :func:`internal_error` rather
    than being silently dropped.
    """
    index = _DesiredIndex()
    for line in desired_save.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if parts[:2] == ["delete", "table"]:
            index = _DesiredIndex()  # whole-table replace: drop anything prior
            continue
        if parts[:2] in (["add", "table"], ["flush", "table"]):
            continue
        if len(parts) <= _DESIRED_NAME_INDEX or parts[0] != "add":
            raise internal_error(f"unexpected render line: {stripped!r}")
        sub, name = parts[1], parts[_DESIRED_NAME_INDEX]
        if sub == _NFT_OBJ_CHAIN:
            index.chain_decl[name] = stripped
        elif sub == _NFT_OBJ_RULE:
            index.chain_rules.setdefault(name, []).append(stripped)
        elif sub == _NFT_OBJ_SET:
            index.set_decl[name] = stripped
        elif sub == _NFT_OBJ_ELEMENT:
            index.set_elements[name] = stripped
        elif sub == _NFT_OBJ_SECMARK:
            # A table object rides its own index slot; a real object change
            # diverts the whole family to a full reload (build_nft_delta), so
            # the delta emitter never consults this -- but the index must still
            # recognize the line (it is present on every unchanged reconcile).
            index.object_decl[name] = stripped
        else:
            raise internal_error(f"unexpected render line: {stripped!r}")
    return index


def _emit_set_changes(
    diff: PlanDiff,
    current: dict[str, ParsedTable],
    index: _DesiredIndex,
    *,
    family: str,
) -> list[str]:
    """
    Emit the set BUILD-UP phase of a delta: adds and element-modifies only.

    A delta never emits ``delete set``: ``build_nft_delta`` diverts
    any set ``remove`` (pure removal OR retype remove+add) to a full reload,
    because ``delete set`` is refcount-unsafe inside a transaction when a live
    rule still references the set.  So this phase only adds new sets (verbatim
    render declaration + elements) and applies element deltas to modified sets
    (this is what spares unchanged elements from churn).  A ``remove`` reaching
    here is a broken contract -> ``internal_error``.
    """
    prefix = f"{family} ferm"
    current_sets = (
        current[NFT_TABLE_NAME].sets if NFT_TABLE_NAME in current else {}
    )
    out: list[str] = []
    for sc in sorted(diff.set_changes, key=lambda s: s.name):
        if sc.kind == SetChangeKind.REMOVE:
            raise internal_error(
                "set remove reached the emitter"
                f" (should full-reload): {sc.name!r}"
            )
        if sc.kind == SetChangeKind.ADD:
            decl = index.set_decl.get(sc.name)
            if decl is None:
                raise internal_error(f"no desired decl for set {sc.name!r}")
            out.append(decl)
            elements = index.set_elements.get(sc.name)
            if elements is not None:
                out.append(elements)
        elif sc.kind == SetChangeKind.MODIFY:
            live = current_sets[sc.name].elements
            desired_elements = sc.elements
            desired_membership = set(desired_elements)
            live_membership = set(live)
            removed = [e for e in live if e not in desired_membership]
            added = [e for e in desired_elements if e not in live_membership]
            if removed:
                out.append(
                    f"delete element {prefix} {sc.name} "
                    f"{{ {', '.join(removed)} }}"
                )
            if added:
                out.append(
                    f"add element {prefix} {sc.name} {{ {', '.join(added)} }}"
                )
    return out


def _emit_chain_changes(
    diff: PlanDiff,
    current: dict[str, ParsedTable],
    index: _DesiredIndex,
    *,
    family: str,
) -> list[str]:
    """
    Emit the chain phase of a delta.

    Per desired chain: a new chain is declared and filled; a chain with a rule
    delta is redeclared (idempotent -- updates a base chain's policy),
    flushed, and rebuilt from the verbatim desired rules (its counters are
    lost, it changed); a base chain with ONLY a policy change is redeclared
    without a flush (policy updates, counters survive); an unchanged chain is
    left untouched (the whole point -- its counters survive).  Desuet base
    chains and foreign user chains are deleted (convergence to desired).
    """
    prefix = f"{family} ferm"
    current_chains = (
        current[NFT_TABLE_NAME].chains if NFT_TABLE_NAME in current else {}
    )
    rule_changed = {rc.chain for rc in diff.rules_added} | {
        rc.chain for rc in diff.rules_removed
    }
    policy_changed = {pc.chain for pc in diff.policy_changes}
    rebuilt = {cr.chain for cr in diff.chain_rebuilds}
    out: list[str] = []
    for name in sorted(index.chain_decl):
        decl = index.chain_decl[name]
        rules = index.chain_rules.get(name, [])
        if name not in current_chains:
            out.append(decl)
            out.extend(rules)
        elif name in rebuilt:
            # Priority changed: nft cannot redeclare in place.  Delete first,
            # then recreate and re-emit rules in the same transaction.  This
            # subsumes any coincident policy/rule change.
            out.append(f"delete chain {prefix} {name}")
            out.append(decl)
            out.extend(rules)
        elif name in rule_changed:
            out.append(decl)
            out.append(f"flush chain {prefix} {name}")
            out.extend(rules)
        elif name in policy_changed:
            out.append(decl)
        # else: unchanged -- skip so its counters survive.
    out.extend(
        f"delete chain {prefix} {dchain.chain}"
        for dchain in sorted(diff.desuet_chains, key=lambda d: d.chain)
    )
    out.extend(
        f"delete chain {prefix} {fchain.chain}"
        for fchain in sorted(diff.foreign_chains, key=lambda f: f.chain)
    )
    return out


def emit_delta_script(
    diff: PlanDiff,
    current: dict[str, ParsedTable],
    index: _DesiredIndex,
    *,
    family: str,
) -> str:
    """
    Build an applicable nft delta script from a diff (mirror of render_plan).

    Returns ``""`` when nothing changed -- the caller skips ``nft -f``
    entirely (idempotency).  Otherwise: an idempotent ``add table`` envelope,
    the set phase, then the chain phase.  The whole script is one ``nft -f``
    transaction, so it stays atomic; ``@set`` references resolve because a set
    is declared before any rule that uses it.
    """
    if not diff.has_changes():
        return ""
    prefix = f"{family} ferm"
    lines = [f"add table {prefix}"]
    lines.extend(_emit_set_changes(diff, current, index, family=family))
    lines.extend(_emit_chain_changes(diff, current, index, family=family))
    return "\n".join(lines) + "\n"


def needs_full_reload(previous: str | None) -> bool:
    """
    Return True when a delta is impossible/pointless -> fall back to reload.

    A delta diffs a captured snapshot against the desired ruleset; with no
    prior table (first run / ENOENT -> ``None``) or an empty snapshot there is
    nothing to preserve, so the deterministic, safe choice is the existing
    ``flush table`` + full rebuild from ``render().save``.
    """
    if previous is None:
        return True
    return previous.strip() == ""


def build_nft_delta(
    previous: str, desired_save: str, *, family: str
) -> str | None:
    """
    Orchestrate one family's delta: parse both sides, diff, emit.

    ``previous`` is a ``nft list table`` snapshot (the captured live side);
    ``desired_save`` is ``render().save`` (valid by construction).  Returns the
    applicable delta script, ``""`` when nothing changed, or ``None`` when the
    delta is refcount-unsafe and the caller must fall back to a full reload.

    The unsafe cases are any set ``remove`` (a pure removal or a retype
    modelled as remove+add) and any table-object add/remove: ``delete set`` /
    ``delete secmark`` aborts the whole transaction if a live rule still
    references the object, and a flags-only retype keeps the referencing rule
    unchanged (so its chain is never flushed to clear the reference).
    Diverting that family to ``render().save`` keeps it correct; counter
    preservation is lost only for that rare reload.  The caller must have
    ruled out the snapshot-based full-reload cases via
    :func:`needs_full_reload` first.
    """
    current = parse_nft_list(previous, family=family)
    desired = parse_nft_script(desired_save)
    diff = diff_tables(current, desired, noflush=False)
    if any(sc.kind == SetChangeKind.REMOVE for sc in diff.set_changes):
        return None
    if diff.object_changes:
        # Any table-object add/remove diverts to a full reload: an object is
        # declared-once and rarely changes, and `delete secmark`/`delete ct
        # helper` is refcount-unsafe while a live rule still references it (the
        # set-REMOVE precedent).  Counter preservation is lost only for that
        # rare reload; an unchanged object never reaches here.
        return None
    index = _build_desired_index(desired_save)
    return emit_delta_script(diff, current, index, family=family)
