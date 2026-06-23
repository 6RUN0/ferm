"""SetRef expands to cartesian product under the iptables backend."""

from __future__ import annotations

import subprocess
import sys


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
        text=True,
        check=False,
    )


def test_setref_expands_like_literal_list() -> None:
    """A named set as a selector expands identically to a literal list."""
    with_set = _run(
        "@set $p = (22 80);\n"
        "domain ip table filter chain INPUT { proto tcp dport $p ACCEPT; }\n"
    )
    literal = _run(
        "domain ip table filter chain INPUT "
        "{ proto tcp dport (22 80) ACCEPT; }\n"
    )
    assert with_set.returncode == 0, f"set variant failed:\n{with_set.stderr}"
    assert literal.returncode == 0, (
        f"literal variant failed:\n{literal.stderr}"
    )
    assert with_set.stdout == literal.stdout, (
        "set variant output differs from literal:\n"
        f"--- set variant ---\n{with_set.stdout}"
        f"--- literal ---\n{literal.stdout}"
    )


def test_lone_parenthesised_set_ok() -> None:
    """Lone ``($p)`` is accepted and equals bare ``$p`` output."""
    with_parens = _run(
        "@set $p = (22 80);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport ($p) ACCEPT; }\n"
    )
    without_parens = _run(
        "@set $p = (22 80);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport $p ACCEPT; }\n"
    )
    assert with_parens.returncode == 0, (
        f"lone parenthesised set failed:\n{with_parens.stderr}"
    )
    assert without_parens.returncode == 0, (
        f"bare set failed:\n{without_parens.stderr}"
    )
    assert with_parens.stdout == without_parens.stdout, (
        "($p) and $p produce different output:\n"
        f"--- with parens ---\n{with_parens.stdout}"
        f"--- without parens ---\n{without_parens.stdout}"
    )


def test_mixed_literal_before_set_rejected() -> None:
    """Literal before a set in one selector is rejected at parse time."""
    proc = _run(
        "@set $p = (80);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport (22 $p) ACCEPT; }\n"
    )
    assert proc.returncode != 0, "expected rejection of mixed literal+set"
    assert "mixed with other values" in proc.stderr, (
        f"expected 'mixed with other values' in stderr, got:\n{proc.stderr}"
    )


def test_mixed_set_before_literal_rejected() -> None:
    """Set before a literal in one selector is rejected at parse time."""
    proc = _run(
        "@set $p = (80);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport ($p 22) ACCEPT; }\n"
    )
    assert proc.returncode != 0, "expected rejection of set+literal mix"
    assert "mixed with other values" in proc.stderr, (
        f"expected 'mixed with other values' in stderr, got:\n{proc.stderr}"
    )


def test_mixed_set_before_literal_rejected_under_nft() -> None:
    """The mixed-selector guard fires under --nft (backend-agnostic gate)."""
    proc = _run(
        "@set $p = (80);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport ($p 22) ACCEPT; }\n",
        extra_flags=["--nft"],
    )
    assert proc.returncode != 0, (
        "expected rejection of set+literal mix under --nft"
    )
    assert "mixed with other values" in proc.stderr, (
        f"expected 'mixed with other values' in stderr, got:\n{proc.stderr}"
    )


def test_nft_does_not_silently_expand_set() -> None:
    """Under --nft the iptables pre-pass does NOT run.

    The nft backend does not yet render SetRef (that is Task 5 scope), so
    the process exits non-zero with the nft-specific "unsupported value
    shape" error rather than silently producing iptables-style expanded
    rules.  This confirms the ``not self.options.nft`` gate is real.
    """
    proc = _run(
        "@set $p = (22 80);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport $p ACCEPT; }\n",
        extra_flags=["--nft"],
    )
    assert proc.returncode != 0, (
        "expected nft backend to reject unexpanded SetRef"
    )
    assert "unsupported value shape" in proc.stderr, (
        f"expected nft backend error in stderr, got:\n{proc.stderr}"
    )
