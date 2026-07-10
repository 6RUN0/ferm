"""Parsed-state and change-record dataclasses shared by every plan stage."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Final


@dataclass
class ParsedChain:
    """One parsed chain: its policy field and its ordered rule bodies."""

    policy: str
    rules: list[str] = field(default_factory=list[str])


@dataclass
class ParsedSet:
    """
    One parsed named set: its elements plus its nft type and flags.

    ``type_`` and ``flags`` are diff-relevant: a set whose elements are
    unchanged but whose type or flags differ is NOT a no-op -- an element
    delta applied to a wrongly-typed live set fails the transaction.  Both
    parsers populate them; ``diff_tables`` models a type/flags divergence as
    remove+add (the elements are lawfully lost when the type changes).

    A ``dynamic`` set's elements are runtime state the kernel accrues
    (``update @set``), not configuration: the desired side declares no
    elements while a live snapshot may carry any number, so
    ``diff_tables`` compares dynamic sets on ``(type_, flags)`` only.
    Diffing their elements would report a phantom MODIFY forever and a
    delta apply would wipe the tracked state on every reconcile.
    """

    name: str
    elements: list[str] = field(default_factory=list[str])
    type_: str | None = None
    flags: tuple[str, ...] = ()

    @property
    def is_dynamic(self) -> bool:
        """True when the set carries the ``dynamic`` flag."""
        # ``nft list`` prints ``flags dynamic,timeout`` as one whitespace
        # token, so a flags entry may hold several comma-joined flags.
        return any("dynamic" in flag.split(",") for flag in self.flags)


@dataclass
class ParsedTable:
    """One parsed table: its chains and named sets, insertion-ordered."""

    chains: dict[str, ParsedChain] = field(
        default_factory=dict[str, ParsedChain]
    )
    sets: dict[str, ParsedSet] = field(default_factory=dict[str, ParsedSet])


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
class DesuetChain:
    """A base chain present in the kernel but absent from the config."""

    table: str
    chain: str


@dataclass
class ChainRebuild:
    """
    A built-in chain whose nft priority changed (``old`` -> ``new``).

    A base chain's priority is part of its declaration, and nft refuses to
    redeclare an existing chain with a different priority ("already exists
    with different declaration").  The delta must therefore delete and
    recreate the chain, re-emitting its rules in the same transaction; its
    counters reset (it changed).  The delete is safe precisely because the
    knob is base-chain-only: nothing ``jump``s to a hook chain.
    """

    table: str
    chain: str
    old: str
    new: str


class SetChangeKind(enum.StrEnum):
    """The kinds a diff can record for a named set (see SetChange)."""

    ADD = "add"
    REMOVE = "remove"
    MODIFY = "modify"

    @property
    def touches_elements(self) -> bool:
        """True for add/modify: the change carries a desired-side set."""
        return self in (SetChangeKind.ADD, SetChangeKind.MODIFY)

    @property
    def is_removal(self) -> bool:
        """True for remove/modify: the change carries a current-side set."""
        return self in (SetChangeKind.REMOVE, SetChangeKind.MODIFY)


@dataclass
class SetChange:
    """
    A named set added, removed, or with changed elements.

    ``elements`` is the desired side; ``current_elements`` is the live
    side, carried for MODIFY so the diff can show what the elements
    change FROM, not just what they change to.
    """

    table: str
    name: str
    kind: SetChangeKind
    elements: list[str]
    current_elements: list[str] = field(default_factory=list[str])


@dataclass
class _DesiredIndex:
    """
    Verbatim render lines keyed by object name, for the delta emitter.

    The delta DECIDES what to touch from the diff, but the content it ADDS is
    copied byte-for-byte from ``render().save`` (already past every validate
    border, valid as ``nft -f`` input by construction).  This index is that
    lookup: each value is one render line with its trailing newline stripped.
    """

    chain_decl: dict[str, str] = field(default_factory=dict[str, str])
    chain_rules: dict[str, list[str]] = field(
        default_factory=dict[str, list[str]]
    )
    set_decl: dict[str, str] = field(default_factory=dict[str, str])
    set_elements: dict[str, str] = field(default_factory=dict[str, str])


# Index of a render line: 'add <sub> <fam> ferm <name> ...'
# -> name at parts[4].
_DESIRED_NAME_INDEX: Final[int] = 4


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
    desuet_chains: list[DesuetChain] = field(default_factory=list[DesuetChain])
    chain_rebuilds: list[ChainRebuild] = field(
        default_factory=list[ChainRebuild]
    )
    set_changes: list[SetChange] = field(default_factory=list[SetChange])
    noflush: bool = False
    current_empty: bool = False

    def has_changes(self) -> bool:
        """Return True if applying the config would change the kernel."""
        return bool(
            self.policy_changes
            or self.rules_added
            or self.rules_removed
            or self.foreign_chains
            or self.desuet_chains
            or self.chain_rebuilds
            or self.set_changes
        )


@dataclass
class Plan:
    """The whole plan: a per-family diff plus any unsupported families."""

    families: dict[str, PlanDiff] = field(default_factory=dict[str, PlanDiff])
    unsupported: list[str] = field(default_factory=list[str])

    def has_changes(self) -> bool:
        """Return True if any family's diff carries a change."""
        return any(diff.has_changes() for diff in self.families.values())
