"""iptables option formatting: ip6 substitutions and the SetRef guard."""

from __future__ import annotations

import pytest

from pyferm.backend.iptables import format_option, shell_format_option
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.values import SetRef


def test_format_option_ip6_protocol_icmp_becomes_icmpv6() -> None:
    """Under ip6 the ``icmp`` protocol is rewritten to ``icmpv6``."""
    assert (
        format_option(Family.IP6, "protocol", "icmp", fast=True)
        == " --protocol icmpv6"
    )


def test_format_option_ip6_protocol_non_icmp_passes_through() -> None:
    """
    A non-icmp protocol under ip6 is left untouched.

    The rewrite is gated on both the ``protocol`` keyword and the
    ``icmp`` value; a plain ``tcp`` must not be coerced to ``icmpv6``.
    """
    assert (
        format_option(Family.IP6, "protocol", "tcp", fast=True)
        == " --protocol tcp"
    )


def test_format_option_ip6_reject_map_only_for_reject_with() -> None:
    """
    The ip6 reject map is consulted only for the ``reject-with`` keyword.

    A reject-with value carried by any other keyword must pass through
    verbatim; the mapping is not a blanket value rewrite.
    """
    assert (
        format_option(
            Family.IP6, "comment", "icmp-port-unreachable", fast=True
        )
        == " --comment icmp-port-unreachable"
    )


def test_shell_format_option_setref_is_internal_error() -> None:
    """
    A named set reaching the iptables backend is an internal error.

    Sets are expanded upstream for iptables; one arriving here is a bug,
    reported with the exact internal-error text.
    """
    with pytest.raises(
        FermError,
        match=r"^internal: a named set reached the iptables "
        r"backend unexpanded$",
    ):
        shell_format_option("source", SetRef("x", ["1"]), fast=True)
