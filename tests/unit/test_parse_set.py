"""Tests for ``@set`` named-set parsing and early guards."""

from __future__ import annotations

import io
import subprocess
import sys

import pytest

from pyferm.backend.nft import _validate_set_name
from pyferm.config import Options
from pyferm.errors import FermError
from pyferm.functions import Evaluator
from pyferm.parser import Parser
from pyferm.scope import Frame, Scope
from pyferm.tokenizer import Script, Tokenizer
from pyferm.values import SetRef, negate_value


def _run_nft(src: str) -> subprocess.CompletedProcess[str]:
    """Compile *src* through the nft backend; return the finished process.

    Errors raised inside the child do not propagate as :class:`FermError`
    to this parent process, so a rejection is asserted on a non-zero
    ``returncode`` plus a ``stderr`` substring rather than ``pytest.raises``.
    """
    return subprocess.run(  # fixed argv, no shell
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


# -- negative battery: rejected named-set uses --------------------------------


def test_negated_setref_rejected() -> None:
    """A named set cannot be negated (in-process guard)."""
    with pytest.raises(FermError, match="negate a named set"):
        negate_value(SetRef("p", ["22"]))


def test_second_setref_per_rule_rejected() -> None:
    """At most one named set may appear in a single rule."""
    proc = _run_nft(
        "@set $a = (10.0.0.1);\n@set $b = (10.0.0.2);\n"
        "domain ip table filter chain INPUT { saddr $a daddr $b ACCEPT; }\n"
    )
    assert proc.returncode != 0
    assert "at most one named set" in proc.stderr


def test_protocol_name_in_port_set_rejected() -> None:
    """A service/protocol name in a port set is rejected (fail-closed)."""
    proc = _run_nft(
        "@set $s = (ssh http);\n"
        "domain ip table filter chain INPUT { proto tcp dport $s ACCEPT; }\n"
    )
    assert proc.returncode != 0
    assert "numeric port or range" in proc.stderr


def test_setref_in_string_context_rejected() -> None:
    """A named set fed to ``@cat`` is rejected in a string context."""
    proc = _run_nft(
        '@set $s = (22);\n@def $x = @cat($s, "x");\n'
        "domain ip table filter chain INPUT { proto tcp dport $x ACCEPT; }\n"
    )
    assert proc.returncode != 0
    assert "string context" in proc.stderr


def test_mixed_literal_and_setref_in_selector_rejected() -> None:
    """A literal mixed with a named set in one selector is rejected."""
    proc = _run_nft(
        "@set $s = (22);\n"
        "domain ip table filter chain INPUT "
        "{ proto tcp dport (22 $s) ACCEPT; }\n"
    )
    assert proc.returncode != 0
    assert "cannot be mixed with other values" in proc.stderr


def test_deferred_value_in_set_rejected() -> None:
    """A deferred value (``@resolve``) inside a ``@set`` is rejected."""
    proc = _run_nft(
        "@set $s = (@resolve(localhost));\n"
        "domain ip table filter chain INPUT { saddr $s ACCEPT; }\n"
    )
    assert proc.returncode != 0
    assert "deferred values are not allowed in a named set" in proc.stderr


def test_numeric_set_name_rejected() -> None:
    """A digit-leading set name is rejected as a non-identifier."""
    proc = _run_nft(
        "@set $22 = (10.0.0.1);\n"
        "domain ip table filter chain INPUT { saddr $22 ACCEPT; }\n"
    )
    assert proc.returncode != 0
    assert "letter-led identifier" in proc.stderr


def test_overlong_set_name_rejected_by_nft_validator() -> None:
    """A name past the nft length cap is rejected by the backend validator."""
    name = "a" * 300
    with pytest.raises(FermError, match="invalid set name"):
        _validate_set_name(name)


def test_injection_set_name_rejected_by_nft_validator() -> None:
    """A name carrying nft metacharacters is rejected by the validator."""
    with pytest.raises(FermError, match="invalid set name"):
        _validate_set_name("x;drop")
