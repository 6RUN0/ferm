"""
Mutation-killing unit tests for ``pyferm.backend.nft.matches``.

Each test pins a spelling or a refusal message that a surviving mutant in
``_translate_match_parts`` and its helpers would perturb: a dropped family
prefix, a port selector that no longer reads its protocol, or a refusal
message whose option name has been replaced by ``None``.  The emitted nft
expression (and the option-named refusal text) is a unit-inspectable value,
which is exactly how these mutants are distinguished from the original.
"""

from __future__ import annotations

import pytest

from pyferm.backend.nft.matches import translate_match
from pyferm.domains import Family
from pyferm.errors import FermError
from tests.unit._nftrule import _exact, _opt


def test_address_selector_carries_the_family_prefix() -> None:
    """The address arm prefixes its selector with the rule family, not None."""
    assert (
        translate_match(Family.IP, _opt("source", "1.2.3.4"), None)
        == "ip saddr 1.2.3.4"
    )
    assert (
        translate_match(Family.IP6, _opt("destination", "2001:db8::1"), None)
        == "ip6 daddr 2001:db8::1"
    )


def test_port_selector_derives_from_the_protocol() -> None:
    """The port arm builds its selector from the protocol argument."""
    assert (
        translate_match(Family.IP, _opt("sport", "80"), "tcp")
        == "tcp sport 80"
    )
    assert (
        translate_match(Family.IP, _opt("dport", "22"), "udp")
        == "udp dport 22"
    )


def test_espspi_refusal_names_the_option() -> None:
    """An invalid espspi refusal is phrased with the option name, not None."""
    with pytest.raises(
        FermError,
        match=_exact("invalid espspi 'oops' for nft backend"),
    ):
        translate_match(Family.IP, _opt("espspi", "oops"), None)


def test_ahspi_refusal_names_the_option() -> None:
    """An invalid ahspi refusal is phrased with the option name, not None."""
    with pytest.raises(
        FermError,
        match=_exact("invalid ahspi 'oops' for nft backend"),
    ):
        translate_match(Family.IP, _opt("ahspi", "oops"), None)


def test_state_mixed_list_refusal_names_the_option() -> None:
    """The mixed state/status refusal is phrased with the option name."""
    with pytest.raises(FermError, match=r"option 'state': a list mixing"):
        translate_match(
            Family.IP, _opt("state", "established,snat", module="state"), None
        )
