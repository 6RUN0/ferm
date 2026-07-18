"""
Mutation-killing unit tests for the parser keyword-dispatch cluster.

Targets survivors in ``parse_keyword``, ``_resolve_keyword`` and
``_route_resolved_keyword`` -- the negation/deprecation resolution and the
per-``params`` argument reader.  Each test drives a real ferm source string
and asserts on the resulting ``%domains`` state or the located error, chosen
so the original passes while its target mutant fails.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.values import PreNegated
from tests.unit._parse import parse_source

if TYPE_CHECKING:
    from pyferm.parser import Parser


def _parse(source: str) -> Parser:
    """Parse ``source`` through ``Parser.enter`` and return the parser."""
    return parse_source(source)


def _values(parser: Parser, chain: str = "INPUT") -> dict[str, object]:
    """Map the first ``filter``/``chain`` rule's option names to values."""
    rules = parser.domains[Family.IP].tables["filter"].chains[chain].rules
    return {opt.name: opt.value for opt in rules[0].options}


def test_parse_keyword_bare_flag_keeps_none_value() -> None:
    """
    A no-argument option (``params is None``) stores ``None``, not ``""``.

    ``fragment`` takes no value; the empty-string mutant of the bare-flag
    branch would substitute ``""`` for the sentinel ``None``.
    """
    parser = _parse("chain INPUT { protocol tcp fragment ACCEPT; }")
    values = _values(parser)
    assert "fragment" in values
    assert values["fragment"] is None


def test_parse_keyword_pre_negation_scalar_wraps_value() -> None:
    """
    A pre-negated scalar option keeps its :class:`PreNegated` wrapper.

    ``! ctproto tcp`` consumes the leading ``!`` as a pre-negation; dropping
    the consumed flag in the ``params == 1`` branch would leave the value a
    bare string instead of ``PreNegated``.
    """
    parser = _parse("chain INPUT { mod conntrack ! ctproto tcp ACCEPT; }")
    values = _values(parser)
    assert isinstance(values["ctproto"], PreNegated)


def test_parse_keyword_comma_code_rejects_empty_array() -> None:
    """
    A comma-joined option (``c`` code) forbids an empty ``()`` value.

    The ``c`` branch reads with ``non_empty=True``; flipping that flag to
    ``False``/``None`` would silently accept the empty array instead of
    raising.
    """
    with pytest.raises(FermError, match="empty array not allowed here"):
        _parse("chain INPUT { mod conntrack ctstate () ACCEPT; }")


def test_resolve_keyword_deprecated_alias_warns_with_replacement(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    A deprecated keyword warns naming both the old and the new spelling.

    ``realgoto`` remaps to ``goto``; blanking the warning argument would emit
    ``None`` instead of the guidance text.
    """
    _parse("chain INPUT { protocol tcp realgoto FOO; }")
    assert (
        "'realgoto' is deprecated, please use 'goto' instead"
        in capsys.readouterr().err
    )


def test_route_resolved_keyword_negated_priority_falls_through() -> None:
    """
    A negated ``priority`` routes to the leaf, not the priority header.

    ``priority`` is a port-only keyword the oracle lacks, so ``! priority``
    must reach the leaf ("Unrecognized keyword: priority"); changing the
    guard literal would run the header path instead.
    """
    with pytest.raises(FermError, match="Unrecognized keyword: priority"):
        _parse("domain ip table filter chain INPUT { ! priority 0; }")
