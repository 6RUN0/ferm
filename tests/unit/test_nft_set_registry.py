"""Named-set declaration registry: emit and conflict detection.

Drives the nft backend through the real CLI so the assertions exercise the
whole render path (translate -> collect declarations -> serialize).  A
declaration is emitted only when a ``@set`` is actually referenced, so the
type can be inferred from the use-site selector.
"""

from __future__ import annotations

import subprocess
import sys


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
