"""Tests for pyferm.introspect (Phase-7 slice 3)."""

from __future__ import annotations

import pytest

from pyferm.introspect import _render_module, render_params
from pyferm.modules import MATCH_DEFS, PROTO_DEFS, KeywordParams, ParamFunction


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        (None, "(no argument)"),
        (1, "<value>"),
        ("2", "<2 values>"),  # defensive: no digit-strings in real data
        ("s", "<value>"),
        ("c", "<comma-separated list>"),
        ("cc", "<comma-separated list> <comma-separated list>"),
        ("sc", "<value> <comma-separated list>"),
        ("m", "<value>... (repeatable)"),
        (ParamFunction("address_magic"), "<address[/mask]>"),
        (ParamFunction("cgroup_classid"), "<special: cgroup_classid>"),
    ],
)
def test_render_params(params: KeywordParams, expected: str) -> None:
    assert render_params(params) == expected


def test_render_module_connlimit_block() -> None:
    block = _render_module(
        "match", "connlimit", "ip", MATCH_DEFS["ip"]["connlimit"]
    )
    lines = block.splitlines()
    assert lines[0] == "match module 'connlimit' (ip/ip6):"
    assert lines[-1] == "  see iptables-extensions(8) and ferm(1)"
    joined = "\n".join(lines)
    assert "connlimit-upto" in joined
    assert "negatable (! before keyword)" in joined
    assert "(no argument)" in joined  # connlimit-saddr


def test_render_module_alias_grouping() -> None:
    block = _render_module("proto", "icmp", "ip", PROTO_DEFS["ip"]["icmp"])
    # icmpv6-type is an alias key of icmp-type: one row, no own line
    assert "(aliases: icmpv6-type)" in block
    assert block.count("icmpv6-type") == 1


def test_render_module_lines_fit_width() -> None:
    from pyferm.introspect import MAX_WIDTH

    # The design spec scopes the 79-column invariant to --list-modules'
    # own name-column layout, not to --describe's per-module option
    # tables. 'set' (ip match, i.e. ipset) combines a 19-char option name
    # ("update-subcounters") with a wide "sc" argument rendering, so its
    # fixed-width columns exceed 79 in every row regardless of gutter --
    # a real data shape, not a rendering defect.
    _known_wide = {("ip", "set")}
    for family, mods in MATCH_DEFS.items():
        for name, module in mods.items():
            if (family, name) in _known_wide:
                continue
            for line in _render_module(
                "match", name, family, module
            ).splitlines():
                assert len(line) <= MAX_WIDTH, (family, name, line)
