"""
Mutation-hardening unit tests for :mod:`pyferm.functions`.

Targets survivors of the mutmut run that the baseline suite in
``test_functions.py`` does not kill: the family threading through
``address_magic``/``@resolve``, the ``code`` token-source threading in the
value readers, the ``collect_tokens`` ``@else``/line-sentinel handling, and a
batch of guard messages whose baseline assertions matched only a substring
(so an ``XX``-wrapped or re-cased mutant slipped through).  Each test pins one
observable difference between the original and its mutant.
"""

from __future__ import annotations

import io
import re
import subprocess

import pytest

from pyferm.errors import FermError
from pyferm.functions import (
    Evaluator,
    _split_backtick_output,
    realize_protocol_keyword,
)
from pyferm.resolver import ResolverProvider, ZonefileResolver, resolve
from pyferm.scope import Frame, FunctionLike, Rule, Scope
from pyferm.tokenizer import Script, Tokenizer
from pyferm.values import Deferred, Negated, SetRef, Value, realize_deferred


def _evaluator(
    text: str,
    *,
    variables: dict[str, Value] | None = None,
    functions: dict[str, FunctionLike] | None = None,
    auto: dict[str, Value] | None = None,
    resolver_provider: ResolverProvider | None = None,
) -> Evaluator:
    """Build an :class:`Evaluator` over ``text`` (mirrors test_functions)."""
    tokenizer = Tokenizer(Script(filename="t.ferm", handle=io.StringIO(text)))
    scope = Scope()
    scope.push(
        Frame(
            vars=dict(variables or {}),
            functions=dict(functions or {}),
            auto=dict(auto or {}),
        )
    )
    return Evaluator(tokenizer, scope, resolver_provider=resolver_provider)


def _exact(message: str) -> str:
    """Anchor a ``pytest.raises`` pattern to the whole error message."""
    return r"\A" + re.escape(message) + r"\Z"


# -- _perl_eq: a reference is never equal to a scalar (identity only) --------


def test_perl_eq_ref_vs_scalar_is_never_equal() -> None:
    """A ref compared with a scalar is unequal even if their text collides."""
    # Perl ``eq`` stringifies a ref to its address, so a ref never equals a
    # scalar -- ferm relies on this identity-only rule.  The scalar here is
    # chosen to equal the list's Python ``str`` ("['1', '2']"): a mutant that
    # reaches the stringify branch (``or``->``and`` for the ref arm, or a
    # dropped ``_is_ref(a)`` check) would wrongly report equality.
    variables: dict[str, Value] = {"a": ["1", "2"], "b": "['1', '2']"}
    assert _evaluator("@eq($a, $b)", variables=variables).getvalues() == "0"


def test_perl_eq_scalar_vs_ref_is_never_equal() -> None:
    """Reversed operand order keeps the rule, guarding the ``b`` arm."""
    # Same collision as above but with the scalar first, so a dropped
    # ``_is_ref(b)`` check (comparing text instead of identity) is caught.
    variables: dict[str, Value] = {"a": "['1', '2']", "b": ["1", "2"]}
    assert _evaluator("@eq($a, $b)", variables=variables).getvalues() == "0"


# -- _split_backtick_output: the re.ASCII flag pins byte-mode whitespace -----


def test_split_backtick_output_keeps_ascii_whitespace_flag() -> None:
    """``\\x1c`` splits under a Unicode ``\\s``; the ASCII flag keeps it."""
    # Byte-mode \s (re.ASCII) is [ \t\n\r\f\v] and does not match \x1c, so the
    # word survives whole; a mutant dropping flags=re.ASCII splits on \x1c.
    assert _split_backtick_output("a\x1cb") == ["a\x1cb"]


# -- realize_protocol_keyword: a non-string proto is skipped, not a stop -----


def test_realize_protocol_keyword_skips_non_string_proto() -> None:
    """A non-string auto-protocol is skipped so a later match promotes."""
    # A leading non-string element must ``continue`` (skip) rather than
    # ``break``: the matching "tcp" that follows still promotes.
    rule = Rule(auto_protocol=[SetRef("x", []), "tcp"], domain_family="ip")
    realize_protocol_keyword(rule, "syn")  # syn belongs to tcp
    assert rule.protocol == "tcp"
    assert rule.auto_protocol is None


# -- _builtin_glob: a relative pattern is prefixed with "./", not junk --------


def test_builtin_glob_relative_pattern_uses_dot_slash_prefix(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slashless script filename prefixes a bare pattern with ``./``."""
    import pathlib

    base = pathlib.Path(str(tmp_path))
    (base / "a.conf").write_text("", encoding="utf-8")
    monkeypatch.chdir(base)
    # filename "t.ferm" has no "/", so parent_dir falls back to "./"; a mutant
    # that corrupts that literal globs a non-existent path and returns nothing.
    assert _evaluator("@glob('*.conf')").getvalues() == "./a.conf"


# -- code-source threading: getvalues/_read_name read a "$" name from $code --


def test_read_name_reads_variable_name_from_code_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``$name`` in backtick output resolves via the same $code stream."""

    # The backtick output "$ v" is tokenized and replayed through getvalues
    # with a $code override; reading the name after "$" must use that same
    # override, not fall back to the (exhausted) main tokenizer.
    def fake_run(*_args: object, **_kwargs: object) -> object:
        return subprocess.CompletedProcess("cmd", 0, stdout="$ v")

    monkeypatch.setattr(subprocess, "run", fake_run)
    ev = _evaluator("`cmd`", variables={"v": "hello"})
    assert ev.getvalues() == "hello"


# -- cgroup_classid: a stray reference is an internal error ------------------


def test_cgroup_classid_setref_is_internal_error() -> None:
    """A SetRef value hits the ``_is_ref`` guard and raises internal error."""
    # A named set can never be a classid: the ``elif _is_ref(value)`` arm must
    # fire (a mutant that neutralises it falls through to the decimal parser
    # and reports the wrong diagnostic).
    ev = _evaluator("$ s", variables={"s": SetRef("n", [])})
    with pytest.raises(
        FermError, match=_exact("internal error: unexpected value type")
    ):
        ev.cgroup_classid(Rule())


# -- collect_tokens: include_else default, @else continuation, line sentinel --


def test_collect_tokens_include_else_defaults_false() -> None:
    """The default ``collect_tokens`` stops at the first top-level ``;``."""
    # include_else defaults to False, so a trailing "@else" does not extend
    # the run past the first ";"; flipping the default would swallow it.
    ev = _evaluator("a ; @else b ;")
    tokens = ev.collect_tokens()
    assert [t for t in tokens if isinstance(t, str)] == ["a"]


def test_collect_tokens_include_else_continues_past_else() -> None:
    """With ``include_else`` a ``; @else`` boundary keeps buffering."""
    # peek_token() == "@else" (exact) at a top-level ";" must ``continue`` so
    # the "@else" arm is captured; a mutated literal or ``break`` stops early.
    ev = _evaluator("a ; @else b ;")
    tokens = ev.collect_tokens(include_else=True)
    assert [t for t in tokens if isinstance(t, str)] == ["a", "@else", "b"]


def test_collect_tokens_advances_line_on_sentinel() -> None:
    """A line sentinel in the raw stream advances ``script.line``."""
    # collect_tokens must hand each non-string token to handle_special_token so
    # a Line sentinel bumps script.line; a mutant passing None drops the update
    # and the line counter never leaves its initial 0.
    ev = _evaluator("a\nb ;")
    ev.collect_tokens()
    assert ev.tokenizer.script.line == 2


# -- address_magic / @resolve: the rule family selects the record type -------

_DUAL_ZONE_TEXT: str = (
    "host.example.com. IN A 192.0.2.1\nhost.example.com. IN AAAA 2001:db8::1\n"
)
#: The AAAA answer above in Net::DNS expanded (no-leading-zero) form.
_EXPECTED_AAAA: str = "2001:db8:0:0:0:0:0:1"


def _dual_zone() -> ZonefileResolver:
    """A resolver with an A and an AAAA record for ``host.example.com``."""
    return ZonefileResolver.from_text(_DUAL_ZONE_TEXT)


def test_address_magic_resolve_uses_rule_family() -> None:
    """The plain @resolve arm realizes against the family (ip6 -> AAAA)."""
    zone = _dual_zone()
    ev = _evaluator(
        "@resolve(host.example.com)", resolver_provider=lambda: zone
    )
    # domain="ip6" must select AAAA; passing a wrong/None family would fall
    # back to the A record.
    assert ev.address_magic(Rule(domain="ip6")) == [_EXPECTED_AAAA]


def test_address_magic_negated_resolve_uses_rule_family() -> None:
    """The negated @resolve arm also realizes against the rule's family."""
    zone = _dual_zone()
    ev = _evaluator(
        "! @resolve(host.example.com)", resolver_provider=lambda: zone
    )
    assert ev.address_magic(Rule(domain="ip6")) == Negated([_EXPECTED_AAAA])


def test_address_magic_setref_resolve_uses_rule_family() -> None:
    """A SetRef holding a deferred resolve realizes against the rule family."""
    zone = _dual_zone()

    def resolve_via_zone(domain: str, *args: Value) -> list[Value]:
        return resolve(domain, *args, resolver=zone)

    setref = SetRef(
        "myset", [Deferred(resolve_via_zone, ["host.example.com"])]
    )
    ev = _evaluator("$ s", variables={"s": setref})
    assert ev.address_magic(Rule(domain="ip6")) == SetRef(
        "myset", [_EXPECTED_AAAA]
    )


def test_builtin_resolve_injected_provider_passes_family() -> None:
    """The injected-provider @resolve closure forwards the family."""
    zone = _dual_zone()
    ev = _evaluator(
        "@resolve(host.example.com)", resolver_provider=lambda: zone
    )
    deferred = ev.getvalues()
    assert isinstance(deferred, Deferred)
    # Realizing under ip6 must reach resolve with domain="ip6" (AAAA); a mutant
    # that drops the domain inside the closure yields the A record instead.
    assert realize_deferred("ip6", deferred) == [_EXPECTED_AAAA]


# -- guard messages: anchor the whole string so XX/re-cased mutants die ------


# Guards reachable through a plain ``getvalues()`` call; each row pins the
# exact diagnostic so an XX-wrapped, re-cased, or None-blanked message dies
# (the baseline suite only substring-matched these).
_GETVALUES_MESSAGE_CASES = [
    pytest.param("! x", "negation is not allowed here", id="negation"),
    pytest.param(",", "comma is not allowed here", id="comma"),
    pytest.param(
        "=", 'equals operator ("=") is not allowed here', id="equals"
    ),
    pytest.param(")", "Syntax error", id="syntax"),
    pytest.param(
        "&",
        "function calls are not allowed as keyword parameter",
        id="ampersand",
    ),
    pytest.param(
        "$ (",
        "variable name expected - if you want to concatenate "
        "strings, try using double quotes",
        id="variable-name",
    ),
    pytest.param(
        "(a, b)",
        "Comma is not allowed within arrays, please use only a space",
        id="array-comma",
    ),
]


@pytest.mark.parametrize(("source", "message"), _GETVALUES_MESSAGE_CASES)
def test_getvalues_guard_messages_are_exact(source: str, message: str) -> None:
    """A malformed value reports its guard message verbatim."""
    with pytest.raises(FermError, match=_exact(message)):
        _evaluator(source).getvalues()


def test_getvalues_empty_array_message_is_exact() -> None:
    """The non-empty-array guard reports its message verbatim."""
    with pytest.raises(
        FermError, match=_exact("empty array not allowed here")
    ):
        _evaluator("()").getvalues(non_empty=True)


def test_getvar_array_message_is_exact() -> None:
    """``getvar`` rejects an array with its exact message."""
    with pytest.raises(FermError, match=_exact("array not allowed here")):
        _evaluator("(a b)").getvar()


def test_read_array_unknown_token_message_is_exact() -> None:
    """An unmatched reference kind in an array reports its exact message."""
    # A Negated value (a ref that is not list/Deferred/SetRef) falls to the
    # else arm; the exact match rejects an XX/re-cased text and a None-blanked
    # message (which raises TypeError from the join rather than the FermError).
    ev = _evaluator("($ v)", variables={"v": Negated("x")})
    with pytest.raises(FermError, match=_exact("unknown token type")):
        ev.getvalues()


def test_read_array_named_set_mix_message_is_exact() -> None:
    """Mixing a named set with another value reports its exact message."""
    ev = _evaluator("($ s x)", variables={"s": SetRef("myset", [])})
    with pytest.raises(
        FermError,
        match=_exact(
            "a named set cannot be mixed with other values in one selector"
        ),
    ):
        ev.getvalues()


def test_collect_tokens_eof_message_is_exact() -> None:
    """Hitting EOF mid-declaration reports its exact message."""
    # No terminating ";": the reader runs off the end and must report the
    # unexpected-EOF diagnostic verbatim.
    with pytest.raises(
        FermError,
        match=_exact(
            "unexpected end of file within function/variable declaration"
        ),
    ):
        _evaluator("a b").collect_tokens()
