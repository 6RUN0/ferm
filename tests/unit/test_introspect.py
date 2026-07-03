"""Tests for pyferm.introspect (Phase-7 slice 3)."""

from __future__ import annotations

import pytest

from pyferm.introspect import render_params
from pyferm.modules import KeywordParams, ParamFunction


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
