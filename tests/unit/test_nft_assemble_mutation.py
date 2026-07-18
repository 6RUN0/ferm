"""
Mutation-survivor kills for :mod:`pyferm.backend.nft.assemble`.

Each test pins one behaviour a surviving mutant would break: the
``has_implied_l4proto`` suppression table (a mutated keyword literal
would re-emit a spurious ``meta l4proto`` prefix), the socket-match
latch (a broken latch double-emits the socket match), the empty
named-set guard (its exact internal-error text), and the collapse
pass's ``changed`` report (``False`` identity, not merely falsy).
The emitted nft ruleset text is the observable; assertions read it
straight off ``translate_rule`` before any collapse pass runs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.backend.nft import translate_rule
from pyferm.backend.nft.assemble import _collapse_one_pass
from pyferm.backend.nft.model import NftRule, NftVerdict
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.scope import OptionKind
from pyferm.values import SetRef
from tests.unit._nftrule import _exact, _opt, _rule, _target

if TYPE_CHECKING:
    from pyferm.rules import RenderedOption


def _marker(module: str) -> RenderedOption:
    """Build a bare ``mod <module>`` match-module marker option."""
    return _opt("match", module, kind=OptionKind.MATCH_MODULE)


def _texts(domain: Family, *options: RenderedOption) -> list[str]:
    """Translate a hand-built rule and return its statement texts."""
    nft = translate_rule(domain, "filter", _rule(*options))
    return [statement.to_text() for statement in nft.statements]


# -- has_implied_l4proto suppression table --------------------------------
#
# A rule carrying a match that already implies its l4proto (ecn tcp-flag
# forms, the tcp-option match) must NOT also emit `meta l4proto tcp` for
# a `protocol tcp` option -- the kernel readback omits the prefix, so
# emitting it would leave --plan diffing forever.  A mutant that corrupts
# a keyword literal in the table drops that suppression and re-emits the
# prefix; asserting its absence kills the literal mutants.


def test_ecn_tcp_cwr_suppresses_the_l4proto_prefix() -> None:
    """``ecn-tcp-cwr`` implies tcp, so no ``meta l4proto`` prefix emits."""
    texts = _texts(
        Family.IP,
        _opt("protocol", "tcp", kind=OptionKind.PROTO),
        _opt("ecn-tcp-cwr", None, module="ecn"),
    )
    assert texts == ["tcp flags cwr"]
    assert "meta l4proto tcp" not in texts


def test_ecn_tcp_ece_suppresses_the_l4proto_prefix() -> None:
    """``ecn-tcp-ece`` implies tcp, so no ``meta l4proto`` prefix emits."""
    texts = _texts(
        Family.IP,
        _opt("protocol", "tcp", kind=OptionKind.PROTO),
        _opt("ecn-tcp-ece", None, module="ecn"),
    )
    assert texts == ["tcp flags ece"]
    assert "meta l4proto tcp" not in texts


def test_tcp_option_match_suppresses_the_l4proto_prefix() -> None:
    """The ``tcp-option`` match implies tcp, so the prefix is dropped."""
    texts = _texts(
        Family.IP,
        _opt("protocol", "tcp", kind=OptionKind.PROTO),
        _opt("tcp-option", "4", module="tcp"),
    )
    assert texts == ["tcp option sack-perm exists"]
    assert "meta l4proto tcp" not in texts


# -- socket-match latch ---------------------------------------------------


def test_socket_marker_then_flag_emits_the_match_once() -> None:
    """
    The ``socket_emitted`` latch fires once across marker and flag.

    A rule with the ``mod socket`` marker AND a socket flag option hits
    the marker dispatch (which emits and latches) and then the flag's
    own dispatch; a broken latch re-emits the socket match a second
    time.  One ``socket wildcard 0`` proves the latch held.
    """
    texts = _texts(
        Family.IP,
        _marker("socket"),
        _opt("transparent", None, module="socket"),
        _target("ACCEPT"),
    )
    assert texts == [
        "socket wildcard 0",
        "socket transparent 1",
        "accept",
    ]


def test_marker_less_socket_flags_emit_the_match_once() -> None:
    """
    The marker-less socket dispatch latches across several flags.

    A hand-built rule whose socket flags carry no ``mod socket`` marker
    (the parser always synthesizes one, but nothing structurally
    requires it) reaches the second socket dispatch; its latch must
    still emit the socket match exactly once, not once per flag.
    """
    texts = _texts(
        Family.IP,
        _opt("transparent", None, module="socket"),
        _opt("restore-skmark", None, module="socket"),
        _target("ACCEPT"),
    )
    assert texts == [
        "socket wildcard 0",
        "socket transparent 1",
        "meta mark set socket mark",
        "accept",
    ]


# -- empty named-set guard ------------------------------------------------


def test_empty_named_set_reaching_translate_rule_is_internal_error() -> None:
    """
    A family-filtered empty named set must never reach translate_rule.

    The caller drops such a rule first; reaching translate_rule is a
    wiring bug surfaced as an internal error with an exact message.
    """
    message = _exact(
        "internal error: a rule over a family-filtered empty named set "
        "reached translate_rule; the caller must drop it first"
    )
    with pytest.raises(FermError, match=message):
        translate_rule(
            Family.IP, "filter", _rule(_opt("saddr", SetRef("empty", [])))
        )


# -- collapse-pass change report ------------------------------------------


def test_collapse_one_pass_reports_false_when_nothing_merges() -> None:
    """
    ``_collapse_one_pass`` returns ``False`` (not a truthy/None proxy).

    A single rule cannot merge, so the pass reports no change; the
    report is the literal ``False``, which the fixpoint loop and any
    caller may compare by identity.
    """
    rules = [NftRule(statements=[NftVerdict("accept")])]
    out, changed = _collapse_one_pass(rules)
    assert out == rules
    assert changed is False
