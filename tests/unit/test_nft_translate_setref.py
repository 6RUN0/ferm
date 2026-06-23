"""nft SetRef translation + name validator."""

from __future__ import annotations

import subprocess
import sys

import pytest

from pyferm.backend.nft import _validate_set_name
from pyferm.errors import FermError


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


def _run(
    src: str, extra_flags: list[str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run pyferm in --test --noexec --lines mode on *src* via stdin."""
    flags = extra_flags or []
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pyferm",
            "--test",
            "--noexec",
            "--lines",
            *flags,
            "-",
        ],
        input=src,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def test_nft_setref_renders_at_name_reference() -> None:
    """Under --nft a named set is rendered as @name, not expanded."""
    proc = _run(
        "@set $p = (22 80);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport $p ACCEPT; }\n",
        extra_flags=["--nft"],
    )
    assert proc.returncode == 0, (
        f"nft SetRef translation failed:\n{proc.stderr}"
    )
    assert "@p" in proc.stdout, (
        f"expected @p reference in nft output, got:\n{proc.stdout}"
    )


def test_nft_setref_two_sets_per_rule_rejected() -> None:
    """Two SetRef options on one rule is rejected under --nft."""
    proc = _run(
        "@set $a = (10.0.0.1);\n"
        "@set $b = (10.0.0.2);\n"
        "domain ip table filter chain INPUT "
        "{ source $a destination $b ACCEPT; }\n",
        extra_flags=["--nft"],
    )
    assert proc.returncode != 0, (
        "expected rejection of two SetRefs on one nft rule"
    )
    assert "at most one named set per rule" in proc.stderr, (
        "expected 'at most one named set per rule' in stderr, got:"
        f"\n{proc.stderr}"
    )
