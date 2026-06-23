"""SetRef expands to cartesian product under the iptables backend."""

from __future__ import annotations

import subprocess
import sys


def _run(src: str) -> subprocess.CompletedProcess[str]:
    """Run pyferm in --test --noexec --lines mode on *src* via stdin."""
    return subprocess.run(
        [sys.executable, "-m", "pyferm", "--test", "--noexec", "--lines", "-"],
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


def test_mixed_literal_and_set_rejected() -> None:
    """Mixing a literal and a set in one selector is rejected at parse time."""
    proc = _run(
        "@set $p = (80);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport (22 $p) ACCEPT; }\n"
    )
    assert proc.returncode != 0, "expected rejection of mixed literal+set"
    assert "mixed with other values" in proc.stderr, (
        f"expected 'mixed with other values' in stderr, got:\n{proc.stderr}"
    )
