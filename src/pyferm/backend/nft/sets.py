"""Named-set declarations: collection, conflict identity, serialization."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ...domains import (
    NFT_TABLE_NAME,
    Family,
)
from ...errors import FermError, internal_error
from ...nftset import (
    RANK_ADDRESS,
    RANK_INTERVAL,
    classify,
    set_body,
    sort_set_elements,
)
from ...scope import OptionKind
from ...values import (
    SetRef,
    iter_setrefs,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ...rules import (
        RenderedRule,
    )


from .model import (
    NftBaseChain,
    NftMatch,
    NftRegularChain,
    NftRule,
    NftSetUpdate,
    NftTable,
    _chain_header,
    _nft_ifname,
    _validate_address,
    _validate_port,
    _validate_set_name,
    first_scalar,
    render_comment,
)

#: A numeric port or a closed numeric range; service/protocol NAMES are
#: rejected because their nft type and sort order cannot be inferred here.
_SET_PORT_NUMERIC_RE: Final[re.Pattern[str]] = re.compile(r"\A\d+([-:]\d+)?\Z")


class NftSetType(enum.StrEnum):
    """nft named-set element type keyword (emitted verbatim into scripts)."""

    INET_SERVICE = "inet_service"
    IPV4_ADDR = "ipv4_addr"
    IPV6_ADDR = "ipv6_addr"
    IFNAME = "ifname"


@dataclass
class _SetDecl:
    """A named-set declaration: type plus ordered, validated elements."""

    type_: NftSetType
    flags_interval: bool
    elements: list[str]


#: The kernel injects ``size 65535`` into an implicit dynamic set; emit it
#: explicitly so ``--plan`` converges against the readback.
_DYN_SET_SIZE: Final[int] = 65535

#: Placeholder set name a connlimit ``NftSetUpdate`` carries until the
#: per-chain post-pass assigns its content-hash name (the final name depends
#: on the fully rendered rule text, unavailable inside ``translate_rule``).
_CONNLIMIT_SENTINEL: Final[str] = "?"


def _conflicting_set(name: str) -> FermError:
    """Build the shared error for a set name with two incompatible uses."""
    return FermError(
        f"set '{name}' has conflicting declarations for the nft backend"
    )


@dataclass
class _DynSetDecl:
    """
    A dynamic (stateful) named-set declaration for recent/hashlimit.

    Unlike :class:`_SetDecl`, it carries no config elements (the kernel
    accrues them at runtime via ``update @set``) and always prints an explicit
    ``size 65535``.  ``type_`` is the full nft type expression, a single
    keyword (``ipv4_addr``) or a concatenation (``ipv4_addr . inet_service``).

    Beyond ``type_``, the fields exist for the collector's conflict
    equality, not for emission: a dynamic element's stateful expression is
    fixed at creation and every touching rule consumes from it, so one name
    MUST mean one element spec.  Same nft type is not enough -- ``srcip``
    and ``dstip`` keys, or two different rates, share a type yet mean
    different buckets.
    """

    type_: str
    key_expr: str
    timeout: str | None
    limit: str | None
    #: Mirrors :attr:`NftSetUpdate.owned`: an owned declaration compares by
    #: the full element spec; a user (SET-target) declaration merges by
    #: ``type_`` alone, OR-ing the timeout flag across the touching rules.
    owned: bool = True

    @property
    def with_timeout(self) -> bool:
        """True when the elements bear a timeout (``,timeout`` flag)."""
        return self.timeout is not None


def _set_type_and_elements(
    domain: Family, selector: str, setref: SetRef
) -> tuple[NftSetType, bool, list[str]]:
    """
    Infer (nft type, flags-interval, validated sorted elements) for a set.

    The type comes from the use-site *selector* (a port match needs
    ``inet_service``, an address match ``ipv4_addr``/``ipv6_addr``, an
    interface match ``ifname``); the elements are validated with the very
    same validators the corresponding single-operand match uses, so a set
    cannot smuggle an operand a literal match would reject.

    Port elements must be numeric ports or numeric ranges.  A service or
    protocol NAME would land in the unparsable sort bucket whose order is
    not stable against a kernel readback, producing a never-converging
    phantom diff, so it is rejected outright (fail-closed).
    """
    raw = [str(element) for element in setref.elements]
    if selector.endswith(("dport", "sport")):
        for element in raw:
            if not _SET_PORT_NUMERIC_RE.match(element):
                raise FermError(
                    f"named set element '{element}' must be a numeric port "
                    "or range; service/protocol names are not supported"
                )
        elements = [_validate_port(element) for element in raw]
        type_ = NftSetType.INET_SERVICE
    elif "saddr" in selector or "daddr" in selector:
        elements = [_validate_address(element) for element in raw]
        type_ = (
            NftSetType.IPV4_ADDR if domain == "ip" else NftSetType.IPV6_ADDR
        )
    elif selector.endswith(("iifname", "oifname")):
        elements = [_nft_ifname(element) for element in raw]
        type_ = NftSetType.IFNAME
    else:
        raise FermError(f"named set selector '{selector}' not supported")
    flags_interval = any(
        (rank := classify(element)[0]) == RANK_INTERVAL
        or (rank == RANK_ADDRESS and "/" in element)
        for element in elements
    ) or (
        # nft treats a trailing `*` in a NAMED ifname set element as a
        # prefix and rejects the declaration without `flags interval`
        # (anonymous sets and vmaps need no flag; verified on nft v1.1.6).
        type_ is NftSetType.IFNAME
        and any(element.endswith('*"') for element in elements)
    )
    return type_, flags_interval, sort_set_elements(elements)


def _merge_dynamic_decl(
    decls: dict[str, _SetDecl | _DynSetDecl], stmt: NftSetUpdate
) -> None:
    """
    Merge one :class:`NftSetUpdate` sighting into ``decls``.

    Dynamic-set arm of :func:`_collect_set_declarations`: see that
    docstring for the collision-namespace rationale.
    """
    if stmt.name == _CONNLIMIT_SENTINEL:
        # The connlimit post-pass runs in render() before the
        # collapse pass and MUST have renamed every sentinel;
        # one surviving here is a wiring bug, not config error.
        raise internal_error(
            "connlimit set reached declaration collection "
            "with an unfinalized name"
        )
    dyn = _DynSetDecl(
        stmt.set_type,
        stmt.key_expr,
        stmt.timeout,
        stmt.limit,
        owned=stmt.owned,
    )
    existing = decls.get(stmt.name)
    if stmt.owned:
        if existing is not None and existing != dyn:
            raise _conflicting_set(stmt.name)
        decls[stmt.name] = dyn
        return
    # A user @set mutated by the SET target: several rules
    # (differing keys or timeouts) legally share one set, so
    # the identity is the nft type alone and the timeout
    # flag ORs across uses.  A prior static declaration can
    # only be the elementless match-set arm of the same set
    # (a SET-targeted set with config elements refuses at
    # translate time) -- upgrade it to the dynamic form.
    if existing is None:
        decls[stmt.name] = dyn
        return
    if isinstance(existing, _SetDecl):
        # A port-selector use (`dport $x`) would need an
        # inet_service set the addr-keyed SET target cannot
        # share -- conflict, never a silent overwrite.
        if existing.type_ != dyn.type_:
            raise _conflicting_set(stmt.name)
        decls[stmt.name] = dyn
        return
    if existing.owned or existing.type_ != dyn.type_:
        raise _conflicting_set(stmt.name)
    if existing.timeout is None:
        existing.timeout = dyn.timeout


def _merge_static_decl(
    decls: dict[str, _SetDecl | _DynSetDecl],
    selectors: dict[str, str],
    domain: Family,
    stmt: NftMatch,
) -> None:
    """
    Merge one :class:`NftMatch` setref sighting into ``decls``.

    Static-set arm of :func:`_collect_set_declarations`; the caller has
    already confirmed ``stmt.setref is not None``.
    """
    setref = stmt.setref
    if setref is None:
        raise internal_error()  # structural; caller narrows this
    name = _validate_set_name(setref.name)
    if stmt.set_selector is None:
        raise internal_error()  # structural; -O would void assert
    selector = stmt.set_selector
    type_, flags_interval, elements = _set_type_and_elements(
        domain, selector, setref
    )
    prior = decls.get(name)
    if isinstance(prior, _DynSetDecl):
        if prior.owned or prior.type_ != type_:
            raise FermError(
                f"named set '{name}' collides with a stateful "
                "set of the same name for the nft backend"
            )
        # A lookup on a SET-target set (the ban-list pattern):
        # the dynamic declaration stands, and the selectors
        # guard below is skipped -- matching saddr while adding
        # daddr (or vice versa) into one addr-typed set is
        # legal nft, unlike two static element interpretations.
        return
    if name in selectors and selectors[name] != selector:
        raise FermError(
            f"named set '{name}' used with conflicting selectors "
            f"'{selectors[name]}' and '{selector}'"
        )
    if prior is not None and prior.elements != elements:
        raise FermError(f"named set '{name}' has conflicting element sets")
    selectors[name] = selector
    decls[name] = _SetDecl(type_, flags_interval, elements)


def _collect_set_declarations(
    domain: Family, rules: dict[str, list[NftRule]]
) -> dict[str, _SetDecl | _DynSetDecl]:
    """
    Aggregate named-set declarations over one family's rules.

    Keyed by name within this ``render()``: every ferm table merges into one
    ``table <family> ferm``, so a name is family-scoped.  Two arms feed the
    single dict -- static sets read structurally from :attr:`NftMatch.setref`
    (never reverse-parsed out of the rendered text) and dynamic sets from
    :class:`NftSetUpdate` (recent/hashlimit).  A name reused with a differing
    selector or element set, or across the static/dynamic kinds, is a conflict
    (error); the same name across several chains or tables of one family is one
    object (dedup).  The unified namespace is the collision guard the spec
    requires: an implicit ``recent_<x>``/``hashlimit_<x>`` set cannot silently
    shadow a user ``@set`` of the same name.
    """
    decls: dict[str, _SetDecl | _DynSetDecl] = {}
    selectors: dict[str, str] = {}
    for chain_rules in rules.values():
        for rule in chain_rules:
            for stmt in rule.statements:
                if isinstance(stmt, NftSetUpdate):
                    _merge_dynamic_decl(decls, stmt)
                elif isinstance(stmt, NftMatch) and stmt.setref is not None:
                    _merge_static_decl(decls, selectors, domain, stmt)
    return decls


def serialize_table(
    table: NftTable,
    chains: list[NftBaseChain | NftRegularChain],
    rules: dict[str, list[NftRule]],
    decls: dict[str, _SetDecl | _DynSetDecl],
    *,
    noflush: bool,
) -> str:
    """
    Serialize one family's table as an atomic ``nft -f`` script.

    Emits ``add table`` (idempotent), then ``flush table`` unless
    ``noflush`` (the ``--noflush`` decision lives HERE, not in the
    applier), then every named-set declaration, then every
    chain, then every rule.  ``chains`` is pre-sorted by the caller for
    deterministic golden output; ``decls`` is emitted by sorted name.
    """
    prefix = f"{table.family} {table.name}"
    lines = [f"add table {prefix}\n"]
    if not noflush:
        lines.append(f"flush table {prefix}\n")
    for name in sorted(decls):
        decl = decls[name]
        if isinstance(decl, _DynSetDecl):
            dyn_flags = "dynamic,timeout" if decl.with_timeout else "dynamic"
            lines.append(
                f"add set {prefix} {name} {{ type {decl.type_}; "
                f"size {_DYN_SET_SIZE}; flags {dyn_flags}; }}\n"
            )
            continue
        flags = " flags interval;" if decl.flags_interval else ""
        lines.append(
            f"add set {prefix} {name} {{ type {decl.type_};{flags} }}\n"
        )
        if decl.elements:
            lines.append(
                f"add element {prefix} {name} {set_body(decl.elements)}\n"
            )
    for chain in chains:
        header = _chain_header(chain)
        suffix = f" {header}" if header else ""
        lines.append(f"add chain {prefix} {chain.name}{suffix}\n")
    for chain in chains:
        for rule in rules.get(chain.name, []):
            parts = [stmt.to_text() for stmt in rule.statements]
            if rule.comment is not None:
                parts.append(render_comment(rule.comment))
            tail = " ".join(parts)
            sep = " " if tail else ""
            lines.append(f"add rule {prefix} {chain.name}{sep}{tail}\n")
    return "".join(lines)


def _full_reload_text(save: str, family: str) -> str:
    """
    Convert a flush-form save into an atomic whole-table replace.

    ``flush table`` empties chains of rules but keeps their declarations, so a
    base chain dropped from the config survives empty-but-hooked (still
    enforcing its policy) and a removed named set keeps its definition.
    Replacing the single ``flush table`` line with ``delete table`` +
    ``add table`` drops every leftover chain/set and rebuilds from scratch,
    converging like ``iptables-restore``.  The leading ``add table`` already in
    ``save`` makes the ``delete`` safe on a first run, and the whole script
    stays one atomic ``nft -f`` transaction.

    The transform is applied only to the apply text, never to ``save`` itself:
    ``save`` is also parsed by :func:`build_nft_delta` and backs the ``.nft``
    goldens, and by contract carries only ``add``/``flush`` table verbs -- the
    ``delete table`` reset is introduced here, into the apply text alone, which
    is fed straight to ``nft -f`` and never re-parsed.
    """
    prefix = f"{family} {NFT_TABLE_NAME}"
    flush_line = f"flush table {prefix}\n"
    replacement = f"delete table {prefix}\nadd table {prefix}\n"
    # No flush line (e.g. a save with nothing to flush) -> nothing to rewrite,
    # so this is a no-op; the leftover-chain hazard only exists where a flush
    # would have kept declarations alive.
    return save.replace(flush_line, replacement, 1)


def _collect_set_target_names(rules: Iterable[RenderedRule]) -> frozenset[str]:
    """
    Collect the set names some SET target of the family mutates.

    A whole-family pre-pass (the ``recent_specs`` precedent): the names feed
    :func:`_references_empty_named_set` so the empty runtime buckets --
    which MUST start empty -- keep both their mutating rules and any
    lookups on them (the ban-list pattern), instead of being dropped as
    dead empty-set references.
    """
    names: set[str] = set()
    for rule in rules:
        if not any(
            o.kind is OptionKind.TARGET and first_scalar(o.value) == "SET"
            for o in rule.options
        ):
            continue
        for option in rule.options:
            if option.name in ("add-set", "del-set"):
                for setref in iter_setrefs(option.value):
                    names.add(setref.name)
    return frozenset(names)


def _references_empty_named_set(
    rule: RenderedRule, set_targets: frozenset[str] = frozenset()
) -> bool:
    """
    Whether *rule* matches on a named set that filtered empty for its family.

    A v4-only set on the ip6 pass of a dual-stack rule (or a ``@set $x = ()``)
    matches nothing.  The caller drops such a rule before translation, exactly
    as an empty inline address list drops one under the iptables backend and
    the Perl oracle -- otherwise the family would emit a dangling ``@name``
    reference plus an empty ``add set`` declaration.

    ``set_targets`` exempts the sets some rule of the family mutates via the
    SET target: those are runtime buckets that MUST start empty, so both the
    mutating rule and a lookup on the set stay (an empty dynamic set matches
    nothing until the kernel fills it -- the ban-list semantics).  Under the
    iptables backend the same config unfolds the empty ``@set`` to zero
    rules; ``@set`` is a port invention with no oracle counterpart, and the
    nft backend already diverges the same way for recent/hashlimit.
    """
    return any(
        not setref.elements and setref.name not in set_targets
        for o in rule.options
        for setref in iter_setrefs(o.value)
    )
