"""
Unit matrix for the ebtables NAT translation (eb snat/dnat).

Every emitted spelling was captured from a live ``nft list ruleset``
readback (nft v1.1.6): the kernel prints MACs lowercase with octets
zero-padded to two hex digits (ebtables-translate emits them unpadded --
a phantom ``--plan`` diff), so the emission MUST equal the padded form.
The placement refusals pin what the legacy kernel enforces with hook
masks at insert time (man ebtables: snat only in nat/POSTROUTING, dnat
only in nat/PREROUTING|OUTPUT) -- translating a rule the ebtables path
could never apply would be fail-open.  The chain-map cases pin the
bridge-family facts: no ``nat``/``route`` chain types (the kernel
rejects both), ebtables-nft's hooks and priorities for filter/nat, and
the deliberate raw/mangle refusal (stock ebtables has no such tables
and both implementations crash on them on the ebtables path).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.backend.nft import translate_rule
from pyferm.backend.nft.assemble import _is_vmap_verdict
from pyferm.backend.nft.chains import BaseChainSpec, map_base_chain
from pyferm.backend.nft.verdicts import (
    _EB_NAT_TARGETS,
    _EB_REFUSED_TARGETS,
    _mac_canon,
)
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.modules import TARGET_DEFS
from tests.unit._nftrule import _opt, _rule, _target

if TYPE_CHECKING:
    from pyferm.rules import RenderedOption


def _eb_nat_text(
    *options: RenderedOption,
    table: str = "nat",
    chain: str | None = "POSTROUTING",
) -> str:
    # End-to-end through translate_rule, NOT _eb_nat_statement in
    # isolation: this seam pins the companion registration in assemble.py
    # (an unregistered snat-target would refuse in the match path before
    # the eb NAT translation ever ran).
    nft = translate_rule(Family.EB, table, _rule(*options), chain=chain)
    return " | ".join(s.to_text() for s in nft.statements)


def _snat(mac: str, *extra: RenderedOption) -> tuple[RenderedOption, ...]:
    return (_target("snat"), _opt("to-source", mac, module="snat"), *extra)


# -- chain map -----------------------------------------------------------


def test_eb_chain_map_matches_ebtables_nft() -> None:
    # Hooks and priorities captured live from the ebtables-nft readback;
    # everything is type filter -- the bridge family has no nat type.
    expected = {
        ("filter", "INPUT"): BaseChainSpec("filter", "input", -200),
        ("filter", "FORWARD"): BaseChainSpec("filter", "forward", -200),
        ("filter", "OUTPUT"): BaseChainSpec("filter", "output", -200),
        ("nat", "PREROUTING"): BaseChainSpec("filter", "prerouting", -300),
        ("nat", "OUTPUT"): BaseChainSpec("filter", "output", 100),
        ("nat", "POSTROUTING"): BaseChainSpec("filter", "postrouting", 300),
    }
    for (table, chain), spec in expected.items():
        assert map_base_chain(Family.EB, table, chain) == spec


@pytest.mark.parametrize(
    ("table", "chain"),
    [
        ("broute", "BROUTING"),
        ("nat", "INPUT"),
        ("raw", "PREROUTING"),
        ("raw", "OUTPUT"),
        ("mangle", "PREROUTING"),
        ("mangle", "OUTPUT"),
    ],
)
def test_eb_chain_map_refuses_unmappable(table: str, chain: str) -> None:
    with pytest.raises(FermError, match=rf"\Achain '{table}/{chain}' not"):
        map_base_chain(Family.EB, table, chain)


# -- MAC canon -----------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "canon"),
    [
        ("aa:bb:cc:00:11:22", "aa:bb:cc:00:11:22"),
        ("AA:BB:CC:0:11:22", "aa:bb:cc:00:11:22"),
        ("0:1:2:3:4:5", "00:01:02:03:04:05"),
    ],
)
def test_mac_canon_pads_and_lowercases(raw: str, canon: str) -> None:
    assert _mac_canon(raw) == canon


@pytest.mark.parametrize(
    "raw",
    [
        "aa:bb:cc:00:11",  # 5 octets
        "aa:bb:cc:00:11:22:33",  # 7 octets
        "aa:bb:cc::11:22",  # empty octet
        "aa:bb:cc:00:11:2g",  # non-hex
        "aaa:bb:cc:00:11:22",  # 3-digit octet
        "aa-bb-cc-00-11-22",  # dash separator (nft would swallow it)
        "aa:bb:cc:00:11:22/ff:ff:ff:ff:ff:ff",  # mask
        "aa:bb:cc:00:11:22\n",  # trailing newline (the ^...$ trap)
        " aa:bb:cc:00:11:22",  # stray whitespace
    ],
)
def test_mac_canon_refuses(raw: str) -> None:
    with pytest.raises(FermError, match=r"\Ainvalid mac "):
        _mac_canon(raw)


# -- translation ---------------------------------------------------------


def test_eb_snat_translates_with_default_accept() -> None:
    assert (
        _eb_nat_text(*_snat("AA:BB:CC:0:11:22"))
        == "ether saddr set aa:bb:cc:00:11:22 accept"
    )


def test_eb_snat_target_picks_the_verdict() -> None:
    # The whitelist emits the dict VALUE (canonical constant), never a
    # transform of the config string.
    for operand, verdict in (
        ("ACCEPT", "accept"),
        ("DROP", "drop"),
        ("CONTINUE", "continue"),
        ("RETURN", "return"),
    ):
        assert (
            _eb_nat_text(
                *_snat(
                    "aa:bb:cc:00:11:22",
                    _opt("snat-target", operand, module="snat"),
                )
            )
            == f"ether saddr set aa:bb:cc:00:11:22 {verdict}"
        )


@pytest.mark.parametrize(
    ("chain", "expected"),
    [
        ("PREROUTING", "ether daddr set 00:01:02:03:04:05 accept"),
        ("OUTPUT", "ether daddr set 00:01:02:03:04:05 accept"),
    ],
)
def test_eb_dnat_translates_in_both_hooks(chain: str, expected: str) -> None:
    assert (
        _eb_nat_text(
            _target("dnat"),
            _opt("to-destination", "0:1:2:3:4:5", module="dnat"),
            chain=chain,
        )
        == expected
    )


def test_eb_dnat_target_maps_verdict() -> None:
    assert (
        _eb_nat_text(
            _target("dnat"),
            _opt("to-destination", "aa:bb:cc:00:11:22", module="dnat"),
            _opt("dnat-target", "DROP", module="dnat"),
            chain="OUTPUT",
        )
        == "ether daddr set aa:bb:cc:00:11:22 drop"
    )


@pytest.mark.parametrize("operand", ["NFQUEUE", "accept", " ACCEPT", "jump x"])
def test_eb_nat_target_refuses_off_whitelist(operand: str) -> None:
    with pytest.raises(FermError, match=r"\Ainvalid snat-target "):
        _eb_nat_text(
            *_snat(
                "aa:bb:cc:00:11:22",
                _opt("snat-target", operand, module="snat"),
            )
        )


# -- refusals ------------------------------------------------------------


@pytest.mark.parametrize(
    ("table", "chain"),
    [
        ("filter", "INPUT"),
        ("nat", "PREROUTING"),
        ("nat", "OUTPUT"),
        ("nat", "mychain"),  # user chain: hook side statically unknown
        ("nat", None),
    ],
)
def test_eb_snat_refuses_outside_nat_postrouting(
    table: str, chain: str | None
) -> None:
    with pytest.raises(
        FermError,
        match=r"\Aeb snat translates only inside the built-in "
        r"nat/POSTROUTING chain",
    ):
        _eb_nat_text(*_snat("aa:bb:cc:00:11:22"), table=table, chain=chain)


def test_eb_dnat_refuses_in_postrouting() -> None:
    with pytest.raises(
        FermError,
        match=r"\Aeb dnat translates only inside the built-in "
        r"nat/PREROUTING or nat/OUTPUT chain",
    ):
        _eb_nat_text(
            _target("dnat"),
            _opt("to-destination", "aa:bb:cc:00:11:22", module="dnat"),
            chain="POSTROUTING",
        )


def test_eb_snat_arp_refuses_on_key_presence() -> None:
    # snat-arp is a zero-arg flag; the refusal keys on presence, not on
    # the (empty/sentinel) value -- silently dropping the ARP rewrite
    # would make the rule do less than the config asked.
    with pytest.raises(FermError, match=r"\Aoption 'snat-arp' has no nft"):
        _eb_nat_text(
            *_snat(
                "aa:bb:cc:00:11:22",
                _opt("snat-arp", None, module="snat"),
            )
        )


def test_eb_snat_without_to_source_refuses() -> None:
    with pytest.raises(FermError, match=r"\Aeb snat needs 'to-source'"):
        _eb_nat_text(_target("snat"))


# -- registry partition and folding --------------------------------------


def test_eb_target_partition_covers_the_registry() -> None:
    # A future eb target must land in exactly one of the two sets or it
    # would fall through to the user-chain jump branch -- fail-open.
    # The parser remaps the registry's MARK keyword to ebtables' `mark`
    # spelling before the backend sees it, so both forms are guarded.
    registry = set(TARGET_DEFS["eb"]) | {"mark"}
    assert registry == _EB_NAT_TARGETS | _EB_REFUSED_TARGETS
    assert not _EB_NAT_TARGETS & _EB_REFUSED_TARGETS


def test_eb_nat_statement_is_not_a_vmap_verdict() -> None:
    # The compound `ether ... set ... accept` text must stay linear: the
    # vmap pass folds only pure verdicts, and folding two MAC rewrites
    # onto one vmap entry would drop a rewrite.
    nft = translate_rule(
        Family.EB,
        "nat",
        _rule(*_snat("aa:bb:cc:00:11:22")),
        chain="POSTROUTING",
    )
    (statement,) = nft.statements
    assert not _is_vmap_verdict(statement)
