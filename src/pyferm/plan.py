"""
Read-only diff preview for ``ferm --plan`` (iptables backend).

Parses an ``iptables-save`` dump into a structural model, canonicalizes
both the desired (ferm ``rules_to_save``, long-form options) and the current
(kernel ``iptables-save``, short-form) sides through a whitelist of
proven-equivalent transforms, diffs them, and renders the result.  The diff
engine is backend-agnostic; the parser is specific to the ``iptables-save``
grammar.  Read-only by construction: this module never
runs a command -- the cli hands it text.
"""

from __future__ import annotations

import difflib
import shlex
from dataclasses import dataclass, field

from pyferm.errors import FermError

# ``:chain policy [pkts:bytes]`` has exactly 2 required fields + 1 optional.
_CHAIN_PARTS_MIN = 2
_CHAIN_PARTS_MAX = 3

# ``-c pkts bytes`` occupies the first 3 tokens of a rule body.
_COUNTER_TOKENS = 3


@dataclass
class ParsedChain:
    """One parsed chain: its policy field and its ordered rule bodies."""

    policy: str
    rules: list[str] = field(default_factory=list[str])


@dataclass
class ParsedTable:
    """One parsed table: its chains keyed by name, insertion-ordered."""

    chains: dict[str, ParsedChain] = field(
        default_factory=dict[str, ParsedChain]
    )


def _parse_error(lineno: int, line: str) -> FermError:
    """
    Build a sanitized parse error: line number + cleaned, truncated text.

    The dump is a trusted source (live kernel/mock), but it can carry
    comment text, log prefixes and internal addresses; the excerpt is
    length-capped and stripped of control bytes so a malformed line never
    dumps raw bytes (latin-1) to a terminal.
    """
    excerpt = "".join(c for c in line.rstrip("\n")[:80] if c.isprintable())
    return FermError(f"cannot parse save line {lineno}: {excerpt!r}")


def parse_save(text: str, *, host_mask: str) -> dict[str, ParsedTable]:
    """
    Parse one family's ``iptables-save`` dump into ``{table: ParsedTable}``.

    Fail-loud: every non-comment, non-blank line must match exactly one
    production (``*table`` / ``:chain policy`` / ``-A rule`` / ``COMMIT``);
    anything else raises :class:`FermError`.  Counters (``[pkts:bytes]`` on
    chain lines, ``-c pkts bytes`` on rule lines) are stripped.
    ``host_mask`` selects the family's host mask for rule canonicalization
    (added by the canonicalization pass).
    """
    tables: dict[str, ParsedTable] = {}
    current: ParsedTable | None = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("*"):
            if current is not None:
                raise _parse_error(lineno, raw)  # previous table not COMMITted
            name = line[1:]
            if not name or " " in name or name in tables:
                raise _parse_error(lineno, raw)
            current = ParsedTable()
            tables[name] = current
            continue

        if line == "COMMIT":
            if current is None:
                raise _parse_error(lineno, raw)
            current = None
            continue

        if current is None:
            raise _parse_error(lineno, raw)  # :chain / -A outside a table

        if line.startswith(":"):
            parts = line[1:].split()
            # chain + policy are required; [pkts:bytes] counter is optional
            if len(parts) < _CHAIN_PARTS_MIN or len(parts) > _CHAIN_PARTS_MAX:
                raise _parse_error(lineno, raw)
            chain, policy = parts[0], parts[1]
            current.chains[chain] = ParsedChain(policy=policy)
            continue

        if line.startswith("-A "):
            body = line[len("-A ") :]
            chain, _, rest = body.partition(" ")
            if not chain or chain not in current.chains:
                # -A for an undeclared chain is malformed iptables-save
                raise _parse_error(lineno, raw)
            current.chains[chain].rules.append(
                _canonicalize_rule(rest, host_mask)
            )
            continue

        raise _parse_error(lineno, raw)

    if current is not None:
        raise _parse_error(len(text.splitlines()), "<EOF: missing COMMIT>")

    return tables


#: Whole-token option aliases (source of truth: Makefile RESULT_SED, plus the
#: multiport long->short pair).  Matched as whole tokens, never as prefixes.
_OPTION_ALIASES = {
    "--protocol": "-p",
    "--source": "-s",
    "--destination": "-d",
    "--match": "-m",
    "--jump": "-j",
    "--goto": "-g",
    "--in-interface": "-i",
    "--out-interface": "-o",
    "--fragment": "-f",
    "--destination-ports": "--dports",
    "--source-ports": "--sports",
}
#: ``-m <proto>`` matches the kernel injects as implied by ``-p <proto>``.
_IMPLIED_MATCHES = frozenset({"tcp", "udp", "icmp", "icmpv6"})


def _tokenize_rule(body: str) -> list[str]:
    """
    Split a rule body into tokens, keeping quoted comments intact.

    Safe bias: if the body cannot be lexed (unbalanced quote), fall back to
    a whitespace split.  Worst case is a phantom diff, never a hidden one.
    """
    try:
        return shlex.split(body, posix=False)
    except ValueError:
        return body.split()


def _proto_of(tokens: list[str]) -> str | None:
    """Return the value following ``-p`` (already alias-normalized), if any."""
    for index, token in enumerate(tokens):
        if token == "-p" and index + 1 < len(tokens):
            return tokens[index + 1]
    return None


def _strip_host_mask(operand: str, host_mask: str) -> str:
    """Strip the family host mask (``/32`` or ``/128``) from an address."""
    if operand.endswith(host_mask):
        return operand[: -len(host_mask)]
    return operand


def _canonicalize_rule(body: str, host_mask: str) -> str:
    """
    Normalize one rule body to canonical form via whitelisted transforms.

    Strips a leading ``-c pkts bytes`` counter, normalizes option aliases to
    their short form, collapses a repeated ``-m <module>`` to one, drops an
    injected ``-m <proto>`` implied by ``-p <proto>``, and strips the family
    host mask from ``-s``/``-d`` operands only.  Anything outside the
    whitelist is left untouched (safe bias).
    """
    tokens = _tokenize_rule(body)
    if tokens[:1] == ["-c"] and len(tokens) >= _COUNTER_TOKENS:
        tokens = tokens[_COUNTER_TOKENS:]
    tokens = [_OPTION_ALIASES.get(token, token) for token in tokens]

    proto = _proto_of(tokens)
    seen_modules: set[str] = set()
    out: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-m" and index + 1 < len(tokens):
            module = tokens[index + 1]
            if module in _IMPLIED_MATCHES and module == proto:
                index += 2
                continue
            if module in seen_modules:
                index += 2
                continue
            seen_modules.add(module)
            out.append(token)
            out.append(module)
            index += 2
            continue
        if token in ("-s", "-d") and index + 1 < len(tokens):
            out.append(token)
            out.append(_strip_host_mask(tokens[index + 1], host_mask))
            index += 2
            continue
        out.append(token)
        index += 1
    return " ".join(out)


@dataclass
class PolicyChange:
    """A built-in chain's default policy changed (``old`` -> ``new``)."""

    table: str
    chain: str
    old: str
    new: str


@dataclass
class RuleChange:
    """One rule added to (or removed from) a chain."""

    table: str
    chain: str
    rule: str


@dataclass
class ForeignChain:
    """A user chain present in the kernel but absent from the config."""

    table: str
    chain: str


@dataclass
class PlanDiff:
    """The diff for one family: what applying the config would change."""

    policy_changes: list[PolicyChange] = field(
        default_factory=list[PolicyChange]
    )
    rules_added: list[RuleChange] = field(default_factory=list[RuleChange])
    rules_removed: list[RuleChange] = field(default_factory=list[RuleChange])
    foreign_chains: list[ForeignChain] = field(
        default_factory=list[ForeignChain]
    )
    noflush: bool = False
    current_empty: bool = False

    def has_changes(self) -> bool:
        """Return True if applying the config would change the kernel."""
        return bool(
            self.policy_changes
            or self.rules_added
            or self.rules_removed
            or self.foreign_chains
        )


@dataclass
class Plan:
    """The whole plan: a per-family diff plus any unsupported families."""

    families: dict[str, PlanDiff] = field(default_factory=dict[str, PlanDiff])
    unsupported: list[str] = field(default_factory=list[str])

    def has_changes(self) -> bool:
        """Return True if any family's diff carries a change."""
        return any(diff.has_changes() for diff in self.families.values())


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

            if (
                current_chain is not None
                and _is_builtin(current_chain)
                and desired_chain.policy != current_chain.policy
            ):
                diff.policy_changes.append(
                    PolicyChange(
                        table_name,
                        chain_name,
                        current_chain.policy,
                        desired_chain.policy,
                    )
                )

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

        # foreign chains: user chains in the managed table absent from config
        for chain_name, current_chain in current_chains.items():
            if chain_name in desired_table.chains:
                continue
            if _is_builtin(current_chain):
                continue  # an undeclared built-in is not a foreign user chain
            if noflush:
                continue  # undeclared user chains survive under --noflush
            diff.foreign_chains.append(ForeignChain(table_name, chain_name))

    return diff


def _summary_line(diff: PlanDiff) -> str:
    """Build the ``Plan: N to add, M to remove, K policy changes`` tail."""
    adds = len(diff.rules_added)
    removes = len(diff.rules_removed)
    policies = len(diff.policy_changes)
    pol_word = "change" if policies == 1 else "changes"
    return (
        f"Plan: {adds} to add, {removes} to remove,"
        f" {policies} policy {pol_word}"
    )


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
        lines.append(f"  {_summary_line(diff)}")

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
        current.extend(
            f"# foreign chain {fchain.chain} will be flushed"
            for fchain in sorted(
                (fc for fc in diff.foreign_chains if fc.table == table),
                key=lambda fchain: fchain.chain,
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


def render_plan(plan: Plan, *, fmt: str) -> str:
    """Dispatch to the structured (default) or unified renderer."""
    if fmt == "diff":
        return render_unified(plan)
    return render_structured(plan)
