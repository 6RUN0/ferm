"""nft SetRef translation + name validator."""

from __future__ import annotations

import pytest

from pyferm.backend.nft import _validate_set_name
from pyferm.errors import FermError
from tests.unit._cli import run_pyferm


def test_validate_set_name_accepts_plain() -> None:
    """A plain identifier is returned unchanged."""
    assert _validate_set_name("ssh_ports") == "ssh_ports"


def test_validate_set_name_rejects_leading_digit() -> None:
    """An identifier that starts with a digit is rejected."""
    with pytest.raises(FermError, match="invalid set name"):
        _validate_set_name("22ports")


def test_validate_set_name_rejects_injection() -> None:
    """A value containing shell-injection characters is rejected."""
    with pytest.raises(FermError, match="invalid set name"):
        _validate_set_name("evil; add rule")


def test_validate_set_name_rejects_too_long() -> None:
    """A name of 256 chars (the first rejected length) is rejected."""
    with pytest.raises(FermError, match="invalid set name"):
        _validate_set_name("a" * 256)


def test_validate_set_name_accepts_maxlen_minus_one() -> None:
    """A name of 255 chars (the last usable length) is accepted."""
    name = "a" * 255
    assert _validate_set_name(name) == name


# ---------------------------------------------------------------------------
# Integration: translate a rule through the nft backend.
# ---------------------------------------------------------------------------


def test_nft_setref_renders_at_name_reference() -> None:
    """Under --nft a named set is rendered as @name, not expanded."""
    proc = run_pyferm(
        "@set $p = (22 80);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport $p ACCEPT; }\n",
        "--nft",
    )
    assert proc.returncode == 0, (
        f"nft SetRef translation failed:\n{proc.stderr}"
    )
    assert "@p" in proc.stdout, (
        f"expected @p reference in nft output, got:\n{proc.stdout}"
    )


def test_nft_setref_two_sets_per_rule_rejected() -> None:
    """Two SetRef options on one rule is rejected under --nft."""
    proc = run_pyferm(
        "@set $a = (10.0.0.1);\n"
        "@set $b = (10.0.0.2);\n"
        "domain ip table filter chain INPUT "
        "{ source $a destination $b ACCEPT; }\n",
        "--nft",
    )
    assert proc.returncode != 0, (
        "expected rejection of two SetRefs on one nft rule"
    )
    assert "at most one named set per rule" in proc.stderr, (
        "expected 'at most one named set per rule' in stderr, got:"
        f"\n{proc.stderr}"
    )


# ---------------------------------------------------------------------------
# mod set match-set -> @set reference (nft)
# ---------------------------------------------------------------------------


def test_nft_match_set_src_renders_saddr_reference() -> None:
    """`match-set $s src` becomes `ip saddr @s`."""
    proc = run_pyferm(
        "@set $badguys = (10.1.2.3 192.168.0.0/24);\n"
        "domain ip table filter chain INPUT "
        "{ mod set match-set $badguys src DROP; }\n",
        "--nft",
    )
    assert proc.returncode == 0, f"match-set src failed:\n{proc.stderr}"
    assert "ip saddr @badguys drop" in proc.stdout, (
        f"expected `ip saddr @badguys drop`, got:\n{proc.stdout}"
    )


def test_nft_match_set_negated_dst_renders_inequality() -> None:
    """`mod set ! match-set $s dst` becomes `ip daddr != @s`."""
    proc = run_pyferm(
        "@set $friends = (172.16.0.1);\n"
        "domain ip table filter chain INPUT "
        "{ mod set ! match-set $friends dst DROP; }\n",
        "--nft",
    )
    assert proc.returncode == 0, f"negated match-set failed:\n{proc.stderr}"
    assert "ip daddr != @friends drop" in proc.stdout, (
        f"expected `ip daddr != @friends drop`, got:\n{proc.stdout}"
    )


def test_nft_match_set_external_ipset_refused() -> None:
    """A bare (non-$var) set name is an external ipset and refuses."""
    proc = run_pyferm(
        "domain ip table filter chain INPUT "
        "{ mod set match-set blocklist src DROP; }\n",
        "--nft",
    )
    assert proc.returncode != 0, "expected external-ipset refusal"
    assert (
        "external ipset 'blocklist' cannot be referenced from nftables"
        in proc.stderr
    ), f"expected external-ipset message, got:\n{proc.stderr}"


def test_nft_match_set_multi_flag_refused() -> None:
    """`(src dst)` needs a concatenated set type @set does not declare."""
    proc = run_pyferm(
        "@set $x = (10.1.2.3);\n"
        "domain ip table filter chain INPUT "
        "{ mod set match-set $x (src dst) DROP; }\n",
        "--nft",
    )
    assert proc.returncode != 0, "expected multi-flag refusal"
    assert "multiple set-match flags need" in proc.stderr, (
        f"expected multi-flag message, got:\n{proc.stderr}"
    )


def test_nft_match_set_dual_stack_filters_per_family() -> None:
    """A mixed-family set emits only its own family's elements per pass."""
    proc = run_pyferm(
        "@set $mixed = (10.1.2.3 fe80::1 192.168.0.0/24 2001:db8::/32);\n"
        "domain (ip ip6) table filter chain INPUT "
        "{ mod set match-set $mixed src DROP; }\n",
        "--nft",
    )
    assert proc.returncode == 0, f"dual-stack match-set failed:\n{proc.stderr}"
    out = proc.stdout
    # ip table: only v4 elements; ip6 table: only v6 elements.
    assert "add element ip ferm mixed { 10.1.2.3, 192.168.0.0/24 }" in out, out
    assert "add element ip6 ferm mixed { 2001:db8::/32, fe80::1 }" in out, out
    # No cross-family leakage.
    assert "add element ip ferm mixed { 10.1.2.3, fe80::1" not in out
    assert "fe80::1" not in out.split("add table ip6")[0]


def test_nft_match_set_one_family_set_drops_other_family_rule() -> None:
    """A v4-only set under dual-stack drops (does not crash) the ip6 rule."""
    proc = run_pyferm(
        "@set $v4only = (10.1.2.3 192.168.0.0/24);\n"
        "domain (ip ip6) table filter chain INPUT "
        "{ mod set match-set $v4only src DROP; }\n",
        "--nft",
    )
    assert proc.returncode == 0, f"one-family match-set failed:\n{proc.stderr}"
    out = proc.stdout
    assert "add rule ip ferm INPUT ip saddr @v4only drop" in out, out
    # The ip6 pass filters the set empty: no dangling @v4only rule, no
    # empty `add set` declaration in the ip6 table.
    ip6_section = out.split("add table ip6 ferm")[1]
    assert "@v4only" not in ip6_section, ip6_section
    assert "add set ip6 ferm v4only" not in ip6_section, ip6_section
