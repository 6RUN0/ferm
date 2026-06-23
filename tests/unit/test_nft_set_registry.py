"""Named-set declaration registry: emit and conflict detection.

Drives the nft backend through the real CLI so the assertions exercise the
whole render path (translate -> collect declarations -> serialize).  A
declaration is emitted only when a ``@set`` is actually referenced, so the
type can be inferred from the use-site selector.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from pyferm.backend.nft import (
    NftMatch,
    NftRule,
    _collect_set_declarations,
    _set_type_and_elements,
)
from pyferm.errors import FermError
from pyferm.values import SetRef


def _run_nft(src: str) -> subprocess.CompletedProcess[str]:
    """Run the nft backend on *src* via the hermetic ``--test`` path."""
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pyferm",
            "--nft",
            "--test",
            "--noexec",
            "--lines",
            "-",
        ],
        input=src,
        capture_output=True,
        text=True,
        check=False,
    )


def test_emit_add_set_and_element() -> None:
    proc = _run_nft(
        "@set $ssh = (22 2222);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport $ssh ACCEPT; }\n"
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "add set ip ferm ssh { type inet_service; }" in out
    assert "add element ip ferm ssh { 22, 2222 }" in out
    assert "tcp dport @ssh accept" in out


def test_emit_address_set() -> None:
    proc = _run_nft(
        "@set $hosts = (10.0.0.1 10.0.0.2);\n"
        "domain ip table filter chain INPUT "
        "{ saddr $hosts ACCEPT; }\n"
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert "add set ip ferm hosts { type ipv4_addr; }" in out
    assert "add element ip ferm hosts { 10.0.0.1, 10.0.0.2 }" in out
    assert "ip saddr @hosts accept" in out


def test_emit_interval_flag_for_range() -> None:
    proc = _run_nft(
        "@set $ports = (1024-2048);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport $ports ACCEPT; }\n"
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert (
        "add set ip ferm ports { type inet_service; flags interval; }" in out
    )
    assert "add element ip ferm ports { 1024-2048 }" in out


def test_phantom_service_name_rejected() -> None:
    proc = _run_nft(
        "@set $ssh = (ssh 2222);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport $ssh ACCEPT; }\n"
    )
    assert proc.returncode != 0
    assert "numeric port or range" in proc.stderr


def test_element_conflict_errors() -> None:
    proc = _run_nft(
        "domain ip table filter {\n"
        "  chain INPUT { @set $x = (22); proto tcp dport $x ACCEPT; }\n"
        "  chain OUTPUT { @set $x = (80); proto tcp dport $x ACCEPT; }\n"
        "}\n"
    )
    assert proc.returncode != 0
    assert "conflicting" in proc.stderr


def test_selector_conflict_errors() -> None:
    proc = _run_nft(
        "@set $x = (22);\n"
        "domain ip table filter chain INPUT {\n"
        "  proto tcp dport $x ACCEPT;\n"
        "  saddr $x ACCEPT;\n"
        "}\n"
    )
    assert proc.returncode != 0
    assert "conflicting" in proc.stderr
    assert "selector" in proc.stderr


def test_dedup_same_name_across_chains() -> None:
    proc = _run_nft(
        "@set $ssh = (22 2222);\n"
        "domain ip table filter {\n"
        "  chain INPUT { proto tcp dport $ssh ACCEPT; }\n"
        "  chain OUTPUT { proto tcp dport $ssh ACCEPT; }\n"
        "}\n"
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    assert out.count("add set ip ferm ssh { type inet_service; }") == 1
    assert out.count("add element ip ferm ssh { 22, 2222 }") == 1


# ---------------------------------------------------------------------------
# In-process unit mirrors.  The subprocess cases above import the unmutated
# venv install in the child, so a mutation sweep cannot kill a mutant in the
# type-inference and aggregation helpers through them; these call the helpers
# directly so those code paths are in the kill set.
# ---------------------------------------------------------------------------


def _match(name: str, selector: str, elements: list[str]) -> NftMatch:
    """Build a set-bearing NftMatch the aggregator reads structurally."""
    return NftMatch(
        expr="",
        setref=SetRef(name, list(elements)),
        set_selector=selector,
    )


def test_set_type_and_elements_port() -> None:
    """A dport selector yields ``inet_service`` and validated ports."""
    type_, flags_interval, elements = _set_type_and_elements(
        "ip", "tcp dport", SetRef("p", ["2222", "22"])
    )
    assert type_ == "inet_service"
    assert flags_interval is False
    assert elements == ["22", "2222"]


def test_set_type_and_elements_address_family() -> None:
    """The address type follows the family (ip -> v4, ip6 -> v6)."""
    type_v4, _, _ = _set_type_and_elements(
        "ip", "ip saddr", SetRef("h", ["10.0.0.1"])
    )
    type_v6, _, _ = _set_type_and_elements(
        "ip6", "ip6 saddr", SetRef("h", ["2001:db8::1"])
    )
    assert type_v4 == "ipv4_addr"
    assert type_v6 == "ipv6_addr"


def test_set_type_and_elements_interval_flag() -> None:
    """A range element forces the interval flag on."""
    _, flags_interval, _ = _set_type_and_elements(
        "ip", "tcp dport", SetRef("r", ["1024-2048"])
    )
    assert flags_interval is True


def test_set_type_and_elements_rejects_service_name() -> None:
    """A service name in a port set is rejected (fail-closed)."""
    with pytest.raises(FermError, match="numeric port or range"):
        _set_type_and_elements("ip", "tcp dport", SetRef("s", ["ssh"]))


def test_set_type_and_elements_rejects_iface_selector() -> None:
    """An unsupported selector raises rather than emitting a bad type."""
    with pytest.raises(FermError, match="not supported"):
        _set_type_and_elements("ip", "meta mark", SetRef("m", ["1"]))


def test_collect_declarations_dedups_same_name() -> None:
    """The same name across chains collapses to one declaration."""
    rules = {
        "INPUT": [NftRule([_match("ssh", "tcp dport", ["22", "2222"])])],
        "OUTPUT": [NftRule([_match("ssh", "tcp dport", ["2222", "22"])])],
    }
    decls = _collect_set_declarations("ip", rules)
    assert set(decls) == {"ssh"}
    assert decls["ssh"].elements == ["22", "2222"]


def test_collect_declarations_conflicting_elements_raise() -> None:
    """A name reused with differing elements is a conflict (error)."""
    rules = {
        "INPUT": [NftRule([_match("x", "tcp dport", ["22"])])],
        "OUTPUT": [NftRule([_match("x", "tcp dport", ["80"])])],
    }
    with pytest.raises(FermError, match="conflicting element sets"):
        _collect_set_declarations("ip", rules)


def test_collect_declarations_conflicting_selectors_raise() -> None:
    """A name reused with differing selectors is a conflict (error)."""
    rules = {
        "INPUT": [NftRule([_match("x", "tcp dport", ["22"])])],
        "OUTPUT": [NftRule([_match("x", "ip saddr", ["22"])])],
    }
    with pytest.raises(FermError, match="conflicting selectors"):
        _collect_set_declarations("ip", rules)
