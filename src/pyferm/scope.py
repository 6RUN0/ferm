"""
Parser state: the rule structure, scope stack and copy-on-write helpers.

Faithful port of ferm's scoping machinery from ``reference/src/ferm``:
``copy_on_write``/``new_level``/``merge_keywords`` (``:2033-2068``) plus the
global parser stack ``@stack`` and the auto-chain counter ``$auto_chain``
(``:65-67``).

The central data structure is :class:`Rule` -- the Perl ``%rule`` hash that
``enter()`` threads through the recursive descent.  Perl tracks presence of
its scalar keys with ``exists``/``delete``; this port maps that to ``None``
(or ``False`` for the flag keys), because no scalar is ever stored with a
falsy-but-meaningful value, so ``exists`` collapses to ``is not None`` and
``new_level``'s "copy if exists" collapses to an unconditional copy.  The one
caveat is ``domain``: an empty ``domain ()`` is the empty list ``[]`` (present
yet falsy), so its presence test must be ``is not None``, never truthiness.

Two Perl rule keys are intentionally not fields here: ``rule`` (the rendered
``-A ...`` string) lives on the ``chain_rules`` entries built by
``append_rule``, not on ``%rule``; and ``$inner{auto}`` (``:2716``) is a dead
write -- ``variable_value`` reads ``auto`` only from stack frames, never from
a rule -- so reproducing it would change nothing observable.

``new_level`` returns a fresh :class:`Rule` rather than clearing one in place
(Perl's ``%$rule = ()``): ``%rule`` is a lexical that is never aliased across
a ``new_level`` call, so rebuilding and reassigning is equivalent.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Protocol

# Runtime imports, not TYPE_CHECKING: the parametrized default_factory
# expressions below (``dict[str, Keyword]`` etc.) evaluate at class-body
# time.
from .modules import Keyword
from .values import Value

if TYPE_CHECKING:
    # Type-only: tokenizer sits below scope in the import layering, so this
    # edge is allowed, but nothing here needs Token at runtime -- deferred
    # annotations (``from __future__ import annotations``) keep it that way.
    from .tokenizer import Token


@dataclass(frozen=True)
class SourcePosition:
    """
    Where a rule was defined (Perl's ``$rule{script}`` hash, ``:2174``).

    Carried verbatim onto the emitted ``chain_rules`` entry by
    ``append_rule`` so later error/rollback messages can locate the rule.
    """

    filename: str
    line: int
    #: Reserved forward seam for AST nodes; the tokenizer tracks only
    #: line, so this stays None until a column-aware pass fills it.
    column: int | None = None


class OptionKind(enum.StrEnum):
    """
    The closed set of synthesized option kinds (see :data:`_OPTION_KINDS`).

    Consumed by the nft backend's rule translator, so it is a live contract,
    not a dead field -- keep the spellings byte-stable.
    """

    OPTION = "option"
    MATCH_MODULE = "match_module"
    PROTO = "proto"
    TARGET = "target"


@dataclass
class Option:
    """
    One pending iptables option: Perl's ``[ $name, $value ]`` (``:2022``).

    ``append_option`` pushes these onto :attr:`Rule.options`; the backend
    later turns each into concrete ``--name value`` text, expanding an array
    ``value`` into the cartesian product of rules (Perl ``unfold_rule``).

    :attr:`kind` and :attr:`module` are **synthesized by the port** -- they
    have no counterpart in the oracle, which distinguishes match/proto/target
    by the option ``name`` alone (a sanctioned deviation, a seed for the
    Phase 2 nft backend).  ``kind`` is derived
    from ``name`` in :func:`append_option`; ``module`` is the name of the
    module that introduced a sub-option's keyword, recorded by
    :func:`merge_keywords` on :attr:`Rule.keyword_module` and passed in by
    ``parse_option`` (``None`` for non-module options).  The iptables backend
    emits positionally and ignores both, but the nft backend's rule translator
    branches on :attr:`kind` (``proto``/``match_module``/``target``), so it is
    a live contract field -- keep the spellings stable.

    :attr:`chosen` is the deferred analog of Perl's formatted slot
    ``$option->[2]`` (``:1888``): :func:`pyferm.rules.unfold_rule` records the
    *value* selected for this option in the current leaf rule (array expanded,
    deferred realized) rather than a rendered string, because formatting moved
    to the backend (a sanctioned deviation).
    """

    name: str
    value: Value
    kind: OptionKind = OptionKind.OPTION
    module: str | None = None
    chosen: Value = None


@dataclass
class Rule:
    """
    The parser's working rule -- Perl's ``%rule`` hash (``:2135``).

    ``keywords`` is shared with the parent level until mutated (guarded by
    :attr:`cow`); ``match`` and ``options`` are always copied by
    :func:`new_level`.  ``match`` records which match modules have already
    emitted their ``-m module`` (Perl's ``$rule{match}{$module}`` set).
    """

    cow: set[str] = field(default_factory=set[str])
    keywords: dict[str, Keyword] = field(default_factory=dict[str, Keyword])
    #: Which module's ``merge_keywords`` introduced each keyword (the
    #: parse-time link the oracle discards, kept for :attr:`Option.module`);
    #: travels with ``keywords`` under the same copy-on-write guard.
    keyword_module: dict[str, str] = field(default_factory=dict[str, str])
    match: set[str] = field(default_factory=set[str])
    options: list[Option] = field(default_factory=list[Option])
    domain: Value = None
    #: The folded family this rule is pinned to (a family string, the sentinel
    #: ``"none"`` for empty ``domain ()``, or ``None`` when unset).  Typed
    #: ``str`` rather than ``Family`` because ``scope`` sits below ``domains``
    #: in the import layering; the parser assigns a validated ``Family`` here.
    domain_family: str | None = None
    domain_both: bool = False
    table: Value = None
    chain: Value = None
    protocol: Value = None
    auto_protocol: Value = None
    has_rule: bool = False
    has_action: bool = False
    non_empty: bool = False
    script: SourcePosition | None = None


def copy_on_write(rule: Rule, key: str) -> None:
    """
    Detach a shared dict before mutating it (Perl ``:2033``).

    A no-op unless ``key`` is still marked copy-on-write in :attr:`Rule.cow`.
    Only ``"keywords"`` is ever guarded this way (``new_level``/``set_domain``
    are the sole writers of ``cow``), so this copies just that dict.
    """
    if key not in rule.cow:
        return
    if key == "keywords":
        rule.keywords = dict(rule.keywords)
        rule.keyword_module = dict(rule.keyword_module)
    rule.cow.discard(key)


def new_level(prev: Rule | None) -> Rule:
    """
    Open a fresh rule level (Perl ``new_level``, ``:2040``).

    With no parent, returns an empty :class:`Rule`.  Otherwise inherits the
    parent's context: ``keywords`` is shared copy-on-write, ``match`` and
    ``options`` are copied, and the scalar/flag keys are carried over (Perl's
    "copy if exists", here unconditional -- see the module docstring).  The
    transient keys ``non_empty``/``script`` are deliberately not inherited.
    """
    if prev is None:
        return Rule()
    rule = Rule()
    rule.cow = {"keywords"}
    rule.keywords = prev.keywords
    rule.keyword_module = prev.keyword_module
    rule.match = set(prev.match)
    rule.options = list(prev.options)
    rule.domain = prev.domain
    rule.domain_family = prev.domain_family
    rule.domain_both = prev.domain_both
    rule.table = prev.table
    rule.chain = prev.chain
    rule.protocol = prev.protocol
    rule.auto_protocol = prev.auto_protocol
    rule.has_rule = prev.has_rule
    rule.has_action = prev.has_action
    return rule


def merge_keywords(
    rule: Rule, keywords: dict[str, Keyword], module: str | None = None
) -> None:
    """
    Add a module's keywords to the rule (Perl ``:2062``).

    Detaches the shared ``keywords`` dict first so the parent level is not
    affected, then merges ``keywords`` in (later definitions win).
    ``module`` is the introducing module's name; it is recorded per keyword
    so ``parse_option`` can fill :attr:`Option.module` (the parse-time link
    the oracle discards -- a sanctioned deviation).
    """
    copy_on_write(rule, "keywords")
    rule.keywords.update(keywords)
    if module is not None:
        for name in keywords:
            rule.keyword_module[name] = module


#: Map an option ``name`` to its synthesized :attr:`Option.kind`:
#: ``match``->``match_module``, ``protocol``->``proto``,
#: ``jump``/``goto``->``target``, everything else->``option``.
_OPTION_KINDS: Final[dict[str, OptionKind]] = {
    "match": OptionKind.MATCH_MODULE,
    "protocol": OptionKind.PROTO,
    "jump": OptionKind.TARGET,
    "goto": OptionKind.TARGET,
}


def append_option(
    rule: Rule, name: str, value: Value, module: str | None = None
) -> None:
    """
    Queue one iptables option on the rule (Perl ``:2020``).

    Lives here (with :class:`Rule`/:class:`Option`) rather than in the parser
    so the protocol/param helpers in ``functions`` and the parser can both
    emit options without an import cycle.

    ``kind`` is synthesized from ``name`` via :data:`_OPTION_KINDS`; ``module``
    (the introducing module for a sub-option) is passed through from the
    call-site.  ``kind`` is consumed by the nft backend's rule translator (see
    :class:`Option`); ``module`` is currently unused by either backend.
    """
    kind = _OPTION_KINDS.get(name, OptionKind.OPTION)
    rule.options.append(Option(name, value, kind, module))


class FunctionLike(Protocol):
    """
    The structural shape a user-defined ``@def &name`` function must have.

    ``scope`` sits below ``parser`` in the import layering, so it cannot name
    the parser's ``Function`` dataclass; this Protocol names exactly the
    members :attr:`Frame.functions` stores and the parser reads back
    (``params``/``tokens``/``block``, matching ``Function``'s fields),
    letting both sides stay honestly typed without an import cycle.
    """

    params: list[str]
    tokens: list[Token]
    block: bool


@dataclass
class Frame:
    """
    One scope-stack frame (an element of Perl's ``@stack``).

    ``vars``/``functions`` hold the variables and functions visible at this
    level; ``auto`` holds the built-in pseudo-variables (``DOMAIN``,
    ``TABLE``, ``CHAIN``, ``FILENAME`` ...).  Frames may share their ``vars``
    or ``functions`` dict with another frame (Perl's ``||=`` aliasing); the
    parser builds them with the right sharing, so a shared dict is just the
    same object assigned to two frames.
    """

    vars: dict[str, Value] = field(default_factory=dict[str, Value])
    #: User-defined ``@function`` bodies (parser ``Function`` objects,
    #: structurally typed here as :class:`FunctionLike`; see its docstring
    #: for why ``scope`` cannot name ``Function`` directly).
    functions: dict[str, FunctionLike] = field(
        default_factory=dict[str, FunctionLike]
    )
    auto: dict[str, Value] = field(default_factory=dict[str, Value])


class Scope:
    """
    The parser's scope stack and auto-chain counter (Perl globals).

    Mirrors ``@stack``, but top-at-end: index ``-1`` is the innermost level
    and ``0`` the global one (Perl ``unshift``/``shift`` at the front, so
    its notation is inverted -- Perl ``$stack[0]`` is ``stack[-1]`` here).
    Name and function lookups walk :attr:`stack` from the top;
    ``functions.py`` owns that traversal, this class only owns the storage
    and frame churn.
    """

    def __init__(self) -> None:
        """Start with an empty stack and a zeroed auto-chain counter."""
        self.stack: list[Frame] = []
        self.auto_chain: int = 0

    @property
    def top(self) -> Frame:
        """The innermost frame (Perl ``$stack[0]``, inverted here)."""
        return self.stack[-1]

    @property
    def globals(self) -> Frame:
        """The outermost/global frame (Perl ``$stack[-1]``, inverted here)."""
        return self.stack[0]

    def push(self, frame: Frame) -> None:
        """Enter a new scope level (Perl ``unshift @stack, $frame``)."""
        self.stack.append(frame)

    def pop(self) -> Frame:
        """Leave the innermost scope level (Perl ``shift @stack``)."""
        return self.stack.pop()

    def next_auto_chain(self) -> str:
        """
        Mint the next auto-generated chain name (Perl ``:2687``).

        Pre-increments the counter, matching ``'ferm_auto_' . ++$auto_chain``.
        """
        self.auto_chain += 1
        return f"ferm_auto_{self.auto_chain}"
