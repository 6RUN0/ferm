"""Parser state: the rule structure, scope stack and copy-on-write helpers.

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

from dataclasses import dataclass, field

from pyferm.modules import Keyword
from pyferm.values import Value


@dataclass(frozen=True)
class SourcePosition:
    """Where a rule was defined (Perl's ``$rule{script}`` hash, ``:2174``).

    Carried verbatim onto the emitted ``chain_rules`` entry by
    ``append_rule`` so later error/rollback messages can locate the rule.
    """

    filename: str
    line: int


@dataclass
class Option:
    """One pending iptables option: Perl's ``[ $name, $value ]`` (``:2022``).

    ``append_option`` pushes these onto :attr:`Rule.options`; the backend
    later turns each into concrete ``--name value`` text, expanding an array
    ``value`` into the cartesian product of rules (Perl ``unfold_rule``).
    """

    name: str
    value: Value


@dataclass
class Rule:
    """The parser's working rule -- Perl's ``%rule`` hash (``:2135``).

    ``keywords`` is shared with the parent level until mutated (guarded by
    :attr:`cow`); ``match`` and ``options`` are always copied by
    :func:`new_level`.  ``match`` records which match modules have already
    emitted their ``-m module`` (Perl's ``$rule{match}{$module}`` set).
    """

    cow: set[str] = field(default_factory=set)
    keywords: dict[str, Keyword] = field(default_factory=dict)
    match: set[str] = field(default_factory=set)
    options: list[Option] = field(default_factory=list)
    domain: Value = None
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
    """Detach a shared dict before mutating it (Perl ``:2033``).

    A no-op unless ``key`` is still marked copy-on-write in :attr:`Rule.cow`.
    Only ``"keywords"`` is ever guarded this way (``new_level``/``set_domain``
    are the sole writers of ``cow``), so this copies just that dict.
    """
    if key not in rule.cow:
        return
    if key == "keywords":
        rule.keywords = dict(rule.keywords)
    rule.cow.discard(key)


def new_level(prev: Rule | None) -> Rule:
    """Open a fresh rule level (Perl ``new_level``, ``:2040``).

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


def merge_keywords(rule: Rule, keywords: dict[str, Keyword]) -> None:
    """Add a module's keywords to the rule (Perl ``:2062``).

    Detaches the shared ``keywords`` dict first so the parent level is not
    affected, then merges ``keywords`` in (later definitions win).
    """
    copy_on_write(rule, "keywords")
    rule.keywords.update(keywords)


@dataclass
class Frame:
    """One scope-stack frame (an element of Perl's ``@stack``).

    ``vars``/``functions`` hold the variables and functions visible at this
    level; ``auto`` holds the built-in pseudo-variables (``DOMAIN``,
    ``TABLE``, ``CHAIN``, ``FILENAME`` ...).  Frames may share their ``vars``
    or ``functions`` dict with another frame (Perl's ``||=`` aliasing); the
    parser builds them with the right sharing, so a shared dict is just the
    same object assigned to two frames.
    """

    vars: dict[str, Value] = field(default_factory=dict)
    functions: dict[str, object] = field(default_factory=dict)
    auto: dict[str, Value] = field(default_factory=dict)


class Scope:
    """The parser's scope stack and auto-chain counter (Perl globals).

    Mirrors ``@stack`` (``unshift``/``shift`` at the front, so index ``0`` is
    the innermost level and ``-1`` the global one) and ``$auto_chain``.  Name
    and function lookups walk :attr:`stack` from the top; ``functions.py``
    owns that traversal, this class only owns the storage and frame churn.
    """

    def __init__(self) -> None:
        """Start with an empty stack and a zeroed auto-chain counter."""
        self.stack: list[Frame] = []
        self.auto_chain: int = 0

    @property
    def top(self) -> Frame:
        """The innermost frame (Perl ``$stack[0]``)."""
        return self.stack[0]

    @property
    def globals(self) -> Frame:
        """The outermost/global frame (Perl ``$stack[-1]``)."""
        return self.stack[-1]

    def push(self, frame: Frame) -> None:
        """Enter a new scope level (Perl ``unshift @stack, $frame``)."""
        self.stack.insert(0, frame)

    def pop(self) -> Frame:
        """Leave the innermost scope level (Perl ``shift @stack``)."""
        return self.stack.pop(0)

    def next_auto_chain(self) -> str:
        """Mint the next auto-generated chain name (Perl ``:2687``).

        Pre-increments the counter, matching ``'ferm_auto_' . ++$auto_chain``.
        """
        self.auto_chain += 1
        return f"ferm_auto_{self.auto_chain}"
