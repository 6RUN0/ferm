"""
Value model: bless-tag value types and deferred realization.

Faithful port of ferm's value layer (``reference/src/ferm``).  Perl
represents parsed values as either plain scalars or *blessed* references
whose package name acts as a tag.  The tags and their Python forms:

==============  ==================  ===============================
Perl ``ref``    Python form         meaning
==============  ==================  ===============================
(none)          ``str`` / ``None``  a scalar, or a flag with no arg
``ARRAY``       ``list``            a ferm array (unfolds to a rule
                                    per element)
``negated``     :class:`Negated`    ``! --keyword value``
``pre_negated`` :class:`PreNegated` negation consumed before the
                                    keyword's parameters
``params``      :class:`Params`     several arguments to one option
``multi``       :class:`Multi`      one option repeated per value
``deferred``    :class:`Deferred`   a late-evaluated call
==============  ==================  ===============================

``realize_deferred`` lives here (not in ``rules``) because parser,
functions and values all call it; ``values`` has no upward dependency, so
keeping it here avoids import cycles.
The deferred *callable* is injected when the :class:`Deferred` is built
(by ``functions``/``parser``), so this module never imports them back.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeAlias

from pyferm.errors import error, internal_error

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass
class Negated:
    """A negated value: rendered ``! --keyword value`` (Perl ``negated``)."""

    value: Value


@dataclass
class PreNegated:
    """
    Negation consumed before the parameters (Perl ``pre_negated``).

    Renders identically to :class:`Negated` (``shell_format_option``,
    ``:1837``); the distinction is where the ``!`` was parsed, and both
    are rejected as double negation by :func:`negate_value`.
    """

    value: Value


@dataclass
class Params:
    """Several arguments to one option: ``--k a b c`` (Perl ``params``)."""

    values: list[Value]


@dataclass
class Multi:
    """One option repeated per value: ``--k a --k b`` (Perl ``multi``)."""

    values: list[Value]


@dataclass
class Deferred:
    """
    A late-evaluated call (Perl ``deferred``: ``[fn, *params]``).

    ``function`` is invoked as ``function(domain, *realized_params)`` and
    must return a list mirroring its Perl list-context return (so
    :func:`realize_deferred` can splice it in uniformly).
    """

    function: Callable[..., list[Value]]
    params: list[Value]


@dataclass
class SetRef:
    """
    A named nft set: stable identity ``name`` plus its ``elements``.

    Identity is ``(family, name)`` -- the element list is family-specific
    after per-family filtering; the family dimension lives in the declaration
    registry, not here.  Under ``--nft`` a SetRef travels scalar to the
    backend (rendered ``@name`` plus declaration); under iptables a
    parse-phase pre-pass expands it back to its elements.
    """

    name: str
    elements: list[Value]


#: Any parsed value.  Recursive: arrays nest, deferred params hold values.
Value: TypeAlias = (
    str
    | None
    | list["Value"]
    | Negated
    | PreNegated
    | Params
    | Multi
    | Deferred
    | SetRef
)

_REF_TYPES = (list, Negated, PreNegated, Params, Multi, Deferred, SetRef)


def _is_ref(value: object) -> bool:
    """Whether ``value`` is a reference in Perl's sense (``ref $value``)."""
    return isinstance(value, _REF_TYPES)


def stringify(value: object) -> str:
    """Coerce a value to text the way Perl stringifies it (undef -> "")."""
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def perl_true(value: object) -> bool:
    """
    Apply Perl's truthiness, which differs from Python's.

    Perl treats ``undef``, the number 0, the empty string and the string
    ``"0"`` as false; everything else (including ``"0.0"`` and ``"00"``)
    is true.  ferm values are strings, so this matters for ``@if``/``@eq``.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value not in ("", "0")
    return True


def flatten(*values: Value) -> list[Value]:
    """
    Recursively flatten ferm arrays, leaving other refs intact (``:1384``).

    Only plain arrays (Python ``list``) are descended into; blessed values
    (negated, deferred, ...) pass through unchanged, exactly as Perl's
    ``ref $_ eq 'ARRAY'`` test does.
    """
    result: list[Value] = []
    for value in values:
        if isinstance(value, list):
            result.extend(flatten(*value))
        else:
            result.append(value)
    return result


def cat(*values: Value) -> str:
    """Concatenate flattened scalars; error on a stray ref (``@cat``)."""
    result = ""
    for item in flatten(*values):
        if item is None:
            continue
        if isinstance(item, SetRef):
            error("a named set cannot appear in a string context")
        if not isinstance(item, str):
            error("String expected")
        result += item
    return result


def deferred_cat(domain: str, *values: Value) -> list[Value]:
    """
    ``@cat`` with deferred params (``:1405``).

    Returns a one-element list (Perl returns the scalar; the single-element
    list lets :func:`realize_deferred` splice it like any other result).
    """
    return [cat(*realize_deferred(domain, *values))]


def join_value(expr: str, value: Value) -> Value:
    """Join an array value with ``expr``, preserving negation (``:1252``)."""
    if not _is_ref(value):
        return value
    if isinstance(value, list):
        return expr.join(str(item) for item in value)
    if isinstance(value, Negated):
        return Negated(join_value(expr, value.value))
    if isinstance(value, SetRef):
        error("a named set cannot be joined as an array")
    raise internal_error()


def negate_value(
    value: Value, klass: str | None = None, allow_array: bool = False
) -> Negated | PreNegated:
    """
    Wrap ``value`` as negated, rejecting double/array negation (``:1268``).

    ``klass`` selects the tag (``"pre_negated"`` or the default
    ``"negated"``), mirroring Perl's ``$class || 'negated'``.
    """
    if _is_ref(value):
        if isinstance(value, (Negated, PreNegated)):
            error("double negation is not allowed")
        if isinstance(value, list) and not allow_array:
            error("it is not possible to negate an array")
        if isinstance(value, SetRef):
            error("cannot negate a named set")
    if (klass or "negated") == "pre_negated":
        return PreNegated(value)
    return Negated(value)


def format_bool(value: object) -> str:
    """Return ``"1"``/``"0"`` for a (Perl-truthy) value (``:1282``)."""
    return "1" if perl_true(value) else "0"


def to_array(value: Value) -> list[Value]:
    """
    Expand a value to a list (Perl list-context ``to_array``, ``:1710``).

    Scalars and deferred values become a one-element list; arrays expand to
    their elements; anything else is an internal error (bare ``die``).
    """
    if not _is_ref(value) or isinstance(value, Deferred):
        return [value]
    if isinstance(value, list):
        return list(value)
    if isinstance(value, SetRef):
        return [value]
    raise internal_error()


def eval_bool(value: Value) -> bool:
    """
    Evaluate a value as a Perl boolean (``:1724``).

    A scalar uses Perl truthiness; an array is true when non-empty.
    """
    if not _is_ref(value):
        return perl_true(value)
    if isinstance(value, list):
        return len(value) > 0
    if isinstance(value, SetRef):
        return len(value.elements) > 0
    raise internal_error()


def contains_deferred(*values: Value) -> bool:
    """Whether any value (recursively) is deferred (``:1737``)."""
    for value in values:
        if isinstance(value, Deferred):
            return True
        if isinstance(value, list) and contains_deferred(*value):
            return True
    return False


def realize_deferred(domain: str, *values: Value) -> list[Value]:
    """
    Evaluate every deferred value, recursing into nested calls (``:1746``).

    Each deferred ``function`` returns a list mirroring its Perl
    list-context return, which is spliced into the result; non-deferred
    values pass through.  A function returning the empty list (e.g. an
    unresolvable ``@resolve``) splices nothing, so the surrounding value
    shrinks -- matching Perl's list-context splice.
    """
    result: list[Value] = []
    for value in values:
        if isinstance(value, Deferred):
            args = realize_deferred(domain, *value.params)
            result.extend(value.function(domain, *args))
        else:
            result.append(value)
    return result
