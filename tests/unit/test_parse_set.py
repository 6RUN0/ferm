"""Tests for ``@set`` named-set parsing and early guards."""

from __future__ import annotations

import io
import subprocess
import sys

import pytest

from pyferm.config import Options
from pyferm.errors import FermError
from pyferm.functions import Evaluator
from pyferm.parser import Parser
from pyferm.scope import Frame, Scope
from pyferm.tokenizer import Script, Tokenizer
from pyferm.values import SetRef


def _parse(source: str, *, options: Options | None = None) -> Parser:
    """Parse ``source`` and return the populated parser."""
    options = options if options is not None else Options(test=True)
    script = Script(filename="<test>", handle=io.StringIO(source))
    tokenizer = Tokenizer(script)
    scope = Scope()
    scope.push(Frame())
    evaluator = Evaluator(tokenizer, scope)
    parser = Parser(evaluator, {}, options)
    parser.enter(0, None)
    return parser


def _set_var(src: str, name: str) -> object:
    p = _parse(src)
    return p.evaluator.scope.top.vars.get(name)


# -- happy-path bindings ------------------------------------------------------


def test_parse_set_binds_setref() -> None:
    v = _set_var("@set $ssh = (22 2222);\n", "ssh")
    assert isinstance(v, SetRef)
    assert v.name == "ssh"
    assert v.elements == ["22", "2222"]


def test_parse_set_scalar_one_element() -> None:
    v = _set_var("@set $x = 22;\n", "x")
    assert isinstance(v, SetRef)
    assert v.elements == ["22"]


def test_parse_set_empty() -> None:
    v = _set_var("@set $x = ();\n", "x")
    assert isinstance(v, SetRef)
    assert v.elements == []


# -- early-guard rejections ---------------------------------------------------


def test_parse_set_rejects_deferred() -> None:
    with pytest.raises(FermError, match=r"deferred|resolve"):
        _set_var("@set $x = (@resolve(localhost));\n", "x")


def test_parse_set_rejects_numeric_name() -> None:
    with pytest.raises(FermError, match=r"set name|identifier"):
        _set_var("@set $22 = (1 2);\n", "22")


def test_parse_set_rejects_hyphenated_name() -> None:
    # nft identifiers may not contain hyphens
    with pytest.raises(FermError, match=r"set name|identifier"):
        _set_var("@set $my-set = (1 2);\n", "my-set")


# -- bareword set regression (ipset match) ------------------------------------

_IPSET_SRC = """\
table filter chain INPUT mod set {
    set foo (src src) ACCEPT;
    match-set foo (src src) ACCEPT;
}
"""


def test_bareword_set_in_mod_set_still_compiles() -> None:
    """ipset ``set`` inside ``mod set {}`` must not be hijacked by ``@set``.

    Confirms the bareword-only dispatch invariant.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pyferm", "--test", "--noexec", "--lines", "-"],
        input=_IPSET_SRC,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"ipset mod set regression failed (rc={proc.returncode}):\n"
        f"{proc.stderr}"
    )
