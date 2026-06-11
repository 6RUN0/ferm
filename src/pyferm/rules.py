"""
Rule assembly and array unfolding (formatting lives in the backend).

Faithful port of ferm's rule-assembly layer from ``reference/src/ferm``: the
netfilter predicates ``is_netfilter_core_target``,
``is_netfilter_module_target`` and ``is_netfilter_builtin_chain``, the protocol
helpers ``netfilter_canonical_protocol``/``netfilter_protocol_module``
(``:1766-1803``), plus ``append_rule``/``unfold_rule``/``mkrules2``
(``:1885-1920``).

**Render/commit split (sanctioned deviation #1, design §"Ключевое
архитектурное решение").**  In the oracle the array unfold and
``format_option`` are *fused* inside one recursion: ``unfold_rule`` writes the
formatted string into the option's slot ``$option->[2]`` (``:1902``) and
``append_rule`` joins those slots into the final ``-A ...`` command
(``:1888``).  This port keeps the unfold in the kernel but no longer formats:
``unfold_rule``/``mkrules2`` record the *selected value* for each option (array
expanded, deferred realized -- still a value, not a string) on
:attr:`pyferm.scope.Option.chosen`, and ``append_rule`` snapshots those values
into a structural :class:`RenderedRule`.  ``format_option`` -- the only place
that turns one value into text -- moves to ``backend/iptables.py``.  Without
this split, ``rules`` would import the backend, creating a ``rules -> backend``
cycle.  The unfold itself stays here because expanding the cartesian product is
kernel-agnostic; only per-value formatting is backend-specific.

``mkrules`` itself (``:1924``, the tables x chains walk that seeds
``chain_rules`` in ``%domains``) is deliberately *not* here: it mutates the
per-domain state owned by ``domains.py``, so it is ported alongside that module
(implementation plan §4, which scopes this step to ``mkrules2``,
``unfold_rule`` and ``append_rule`` only).

``realize_deferred`` is imported from :mod:`pyferm.values` (its home; see that
module and plan §3) -- it is interleaved with the unfold here exactly as in the
oracle, so the expansion order (outer loop over options x inner loop over
realized values) is preserved and multi-valued deferred rules emit their lines
in the same order as Perl.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pyferm.errors import internal_error
from pyferm.values import Value, realize_deferred

if TYPE_CHECKING:
    from pyferm.modules import ModuleDef, Registry
    from pyferm.scope import Option, Rule, SourcePosition

#: Targets understood by netfilter itself, no ``-m`` module (``:1769``).
_CORE_TARGETS = ("ACCEPT", "DROP", "RETURN", "QUEUE")

#: The built-in chains across all tables/families (``:1785``); the table
#: argument is ignored, exactly as in the oracle.
_BUILTIN_CHAINS = (
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
    "BROUTING",
)


def is_netfilter_core_target(target: str | None) -> bool:
    """
    Whether ``target`` is a built-in netfilter target (Perl ``:1766``).

    Mirrors ``die unless defined $target and length $target`` before the
    membership test; the Perl ``grep`` is used in boolean context, so this
    returns a plain ``bool``.
    """
    if target is None or target == "":
        raise internal_error("undefined or empty target")
    return target in _CORE_TARGETS


def is_netfilter_module_target(
    target_defs: Registry, domain_family: str | None, target: str | None
) -> ModuleDef | None:
    """
    Return the target-module def for ``target``, else ``None`` (``:1772``).

    The oracle reads the global ``%target_defs``; this port takes the registry
    explicitly (``target_defs`` from :mod:`pyferm.modules`).  Returns the def
    hash (truthy) when ``domain_family`` is known and defines ``target``, so
    callers can write ``if defs := is_netfilter_module_target(...)`` just like
    Perl's ``if (my $defs = ...)``.
    """
    if target is None or target == "":
        raise internal_error("undefined or empty target")
    if domain_family is None:
        return None
    return target_defs.get(domain_family, {}).get(target)


def is_netfilter_builtin_chain(table: str, chain: str) -> bool:
    """
    Whether ``chain`` is a built-in chain (Perl ``:1781``).

    ``table`` is part of the faithful signature but unused -- the oracle
    ignores it and tests the chain name against a fixed set across all tables.
    """
    del table  # unused, mirrors the oracle
    return chain in _BUILTIN_CHAINS


def netfilter_canonical_protocol(proto: str) -> str:
    """
    Canonicalize a protocol name for matching (Perl ``:1788``).

    Folds the IPv6 spellings ``ipv6-icmp``/``icmpv6`` to ``icmp`` and
    ``ipv6-mh`` to ``mh`` so auto-protocol lookups hit one canonical key.
    """
    if proto in ("ipv6-icmp", "icmpv6"):
        return "icmp"
    if proto == "ipv6-mh":
        return "mh"
    return proto


def netfilter_protocol_module(proto: str | None) -> str | None:
    """
    Map a protocol to its match-module name, if any (Perl ``:1797``).

    Returns ``None`` for an undefined protocol (Perl ``return unless
    defined``); rewrites ``icmpv6`` to the ``icmp6`` module name, leaving every
    other protocol unchanged.
    """
    if proto is None:
        return None
    if proto == "icmpv6":
        return "icmp6"
    return proto


@dataclass
class RenderedOption:
    """
    One option of an unfolded rule, ready for the backend to format.

    The kernel->backend contract element ``(name, value, kind, module)``
    (design §"Контракт правила").  ``value`` is the single value selected for
    this option in this leaf rule (no arrays, deferred already realized);
    negation survives as a ``Negated``/``PreNegated`` tag on ``value``, not as
    a field.  ``kind``/``module`` are the port-only fields carried over from
    :class:`pyferm.scope.Option` (no Phase 1 consumer).
    """

    name: str
    value: Value
    kind: str
    module: str | None


@dataclass
class RenderedRule:
    """
    One fully unfolded rule (Perl's ``chain_rules`` entry, ``:1889``).

    The oracle stores a rendered ``rule`` string plus ``script``; this port
    stores the structural :attr:`options` list instead and defers string
    rendering to the backend (see the module docstring).  :attr:`script`
    carries the source position verbatim for later error/rollback messages.
    """

    options: list[RenderedOption]
    script: SourcePosition | None


def append_rule(chain_rules: list[RenderedRule], rule: Rule) -> None:
    """
    Emit one finished rule into ``chain_rules`` (Perl ``:1885``).

    Snapshots the value currently selected on every option
    (:attr:`pyferm.scope.Option.chosen`, the analog of Perl's joined
    ``$option->[2]`` slots) into a :class:`RenderedRule`, preserving the
    original option order.  Formatting happens later in the backend.
    """
    options = [
        RenderedOption(option.name, option.chosen, option.kind, option.module)
        for option in rule.options
    ]
    chain_rules.append(RenderedRule(options=options, script=rule.script))


def unfold_rule(
    domain: str,
    chain_rules: list[RenderedRule],
    rule: Rule,
    options: list[Option],
) -> None:
    """
    Recursively unfold array options into concrete rules (``:1894``).

    With no array options left, the rule is complete -> :func:`append_rule`.
    Otherwise the first remaining array option is expanded: each value from
    ``realize_deferred`` (deferred calls expanded inline, exactly as in the
    oracle) is recorded on the option and the rest are unfolded under it,
    producing the cartesian product.  The expansion order is preserved -- outer
    loop over options, inner loop over realized values -- so multi-valued
    deferred rules emit lines in Perl's order.
    """
    if not options:
        append_rule(chain_rules, rule)
        return

    option = options[0]
    rest = options[1:]
    assert isinstance(option.value, list)
    for value in realize_deferred(domain, *option.value):
        option.chosen = value
        unfold_rule(domain, chain_rules, rule, rest)


def mkrules2(domain: str, chain_rules: list[RenderedRule], rule: Rule) -> None:
    """
    Split options into scalar/array and unfold (Perl ``:1907``).

    Array options (plain Python ``list`` == Perl ``ARRAY`` ref) are collected
    for :func:`unfold_rule`; every other value -- scalars and the non-array
    refs ``params``/``multi``/``negated``/``deferred`` -- is its own selected
    value and recorded directly (the oracle formats these via ``format_option``
    here; this port defers that to the backend, recording the value instead).
    """
    unfold: list[Option] = []
    for option in rule.options:
        if isinstance(option.value, list):
            unfold.append(option)
        else:
            option.chosen = option.value

    unfold_rule(domain, chain_rules, rule, unfold)
