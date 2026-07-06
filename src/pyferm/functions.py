"""
Value evaluation: ferm's ``@`` built-ins, variable/array reading, helpers.

Faithful port of the expression layer of ``reference/src/ferm``: the
token-consuming readers ``getvalues``/``getvar``/``get_function_params``/
``collect_tokens`` (``:1416-1706``), the stack lookups ``variable_value``/
``string_variable_value``/``lookup_function`` (``:1220-1379``), the protocol
helpers ``realize_protocol``/``realize_protocol_keyword`` (``:455-496``) and
the keyword-parameter parsers ``ipfilter``/``address_magic``/
``cgroup_classid``/``multiport_params`` (``:498-615``).

Perl reaches the tokenizer and the variable stack through globals; this port
gathers them on an :class:`Evaluator` (holding a ``Tokenizer`` and a
``Scope``) so the readers stay testable.  The
``@resolve``/``@ipfilter``/deferred-``@cat`` callables are kept as *free*
functions, not bound methods, because a deferred value is realized later --
during rule assembly -- when the evaluator's token position has moved on;
the callable must depend only on its domain and arguments.
"""

# The evaluator reuses values' own reference predicate (_is_ref) by
# design, so pyright's private-usage rule is off here (mirrors walker.py).
# pyright: reportPrivateUsage=false
from __future__ import annotations

import glob as globlib
import re
import subprocess
from collections import deque
from typing import TYPE_CHECKING, ClassVar, Final, TypeAlias

from pyferm.errors import ERR_STRING_EXPECTED, error, internal_error
from pyferm.modules import PROTO_DEFS
from pyferm.resolver import resolve
from pyferm.scope import FunctionLike, Rule, Scope, append_option
from pyferm.streams import BYTE_ENCODING
from pyferm.tokenizer import Token, Tokenizer, make_line_token
from pyferm.values import (
    Deferred,
    Negated,
    SetRef,
    Value,
    _is_ref,
    cat,
    contains_deferred,
    deferred_cat,
    flatten,
    format_bool,
    join_value,
    negate_value,
    perl_true,
    realize_deferred,
    stringify,
    to_array,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pyferm.resolver import ResolverProvider

_NAME_RE: Final[re.Pattern[str]] = re.compile(r"\w+")
_DVAR_RE: Final[re.Pattern[str]] = re.compile(r"\$(\w+)")
_QUOTED_RE: Final[dict[str, re.Pattern[str]]] = {
    "`": re.compile(r"`(.*)`", re.DOTALL),
    "'": re.compile(r"'(.*)'", re.DOTALL),
    '"': re.compile(r'"(.*)"', re.DOTALL),
}
_CLASSID_RE: Final[re.Pattern[str]] = re.compile(
    r"([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{1,4})"
)
_DECIMAL_RE: Final[re.Pattern[str]] = re.compile(r"-?\d+")
_MULTIPORT_PROTO_RE: Final[re.Pattern[str]] = re.compile(r"tcp|udp|udplite")
#: The crude ipfilter family probes: a ``:hex:`` run looks IPv6, a purely
#: numeric/dot/slash token is IPv4/CIDR.  No re.ASCII -- Perl's patterns
#: here are plain byte-mode literals with no \s/\w classes.
_IPV6_HINT_RE: Final[re.Pattern[str]] = re.compile(r":[0-9a-f]*:")
_IPV4_NUMERIC_RE: Final[re.Pattern[str]] = re.compile(r"[0-9./]+")

#: Cap on value-reader recursion depth (:meth:`Evaluator.getvalues`).
#: Nested arrays ``((( ... )))``, chained negation ``!!! ...`` and nested
#: ``@cat(@cat(...))`` calls all recurse back through ``getvalues``, so one
#: guard there covers them.  A sanctioned deviation, the value-reader twin
#: of :data:`~pyferm.parser.MAX_BLOCK_DEPTH`: Perl recurses until memory runs
#: out (OOM only at ~200k levels), the port fails earlier with a located
#: diagnostic.
MAX_VALUE_DEPTH: Final[int] = 100

#: Largest ``classid`` value: the kernel field is an unsigned 32-bit int.
MAX_CLASSID: Final[int] = 0xFFFFFFFF

#: ``multiport`` match capacity: the kernel accepts at most 15 ports, and a
#: ``a:b`` range counts as two of them.
MAX_MULTIPORT_PORTS: Final[int] = 15


def _perl_eq(a: Value, b: Value) -> bool:
    """
    Compare two values the way Perl ``eq`` does (``:1544``).

    Perl stringifies its operands: a reference becomes its address string,
    so two distinct refs are never equal and a ref never equals a scalar --
    identity is the only way refs compare equal.  Scalars compare as text.
    """
    if _is_ref(a) or _is_ref(b):
        return a is b
    return stringify(a) == stringify(b)


def ipfilter(domain: str, value: Value) -> list[Value]:
    """
    Drop addresses of the wrong family (Perl ``ipfilter``, ``:540``).

    A deliberately crude split: under ``ip`` discard anything that looks
    IPv6 (a ``:hex:`` run), under ``ip6`` discard anything purely numeric
    IPv4/CIDR.  Used both directly and as a deferred ``@ipfilter`` callable.
    """
    ips = to_array(value)
    if domain == "ip":
        return [ip for ip in ips if not _IPV6_HINT_RE.search(stringify(ip))]
    if domain == "ip6":
        return [
            ip for ip in ips if not _IPV4_NUMERIC_RE.fullmatch(stringify(ip))
        ]
    return ips


def realize_protocol(rule: Rule) -> Value:
    """
    Pin down the rule's protocol, emitting it if deferred (Perl ``:458``).

    When no explicit ``protocol`` is set but an ``auto_protocol`` is pending
    (carried into a subchain), promote it now and emit the option so a later
    keyword such as ``dport`` resolves against it.
    """
    proto = rule.protocol
    if proto is None:
        proto = rule.auto_protocol
        if proto is not None:
            rule.protocol = proto
            rule.auto_protocol = None
            append_option(rule, "protocol", proto)
    return proto


def realize_protocol_keyword(rule: Rule, keyword: str) -> None:
    """
    Promote ``auto_protocol`` only if ``keyword`` needs it (Perl ``:477``).

    Scans the pending auto-protocols for one whose module defines ``keyword``
    and, on a match, fixes the protocol and emits it -- the magic behind
    ``proto http @subchain { dport http; }``.
    """
    protos = rule.auto_protocol
    if protos is None:
        return
    domain_family = rule.domain_family
    if domain_family is None:
        return
    defs = PROTO_DEFS.get(domain_family)
    if defs is None:
        return
    for proto in to_array(protos):
        if not isinstance(proto, str):
            continue
        module = defs.get(proto)
        if module is not None and keyword in module.keywords:
            rule.protocol = proto
            rule.auto_protocol = None
            append_option(rule, "protocol", proto)
            return


def _perl_substr(string: str, offset: int, length: int) -> str:
    """
    Reproduce Perl's three-argument ``substr`` (signed offset/length).

    Both endpoints may fall before the string: the start is then clamped
    to 0, and only when the *end* is also negative (or the offset is past
    the string) does Perl return undef -- which ferm later interpolates
    as ``''``.  Model verified empirically against perl 5.42 by the
    differential fuzzer.
    """
    size = len(string)
    if offset > size:
        return ""  # Perl: undef ("substr outside of string")
    start = size + offset if offset < 0 else offset
    end = size + length if length < 0 else start + length
    if start < 0:
        if end < 0:
            return ""  # Perl: undef -- both endpoints before the string
        start = 0
    end = max(start, min(end, size))
    return string[start:end]


#: ``re.ASCII``: Perl numification skips byte-mode ``\s`` only, so a
#: Unicode ``\s`` would accept ``\x1c``-``\x1f`` before the digits.
_NUMERIC_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    r"\s*(?P<sign>[+-]?)(?P<number>\d+(?:\.\d*)?|\.\d+)(?P<exp>[eE][+-]?\d+)?",
    re.ASCII,
)

_UV_MAX: Final[int] = 2**64 - 1
_IV_MIN: Final[int] = -(2**63)


def _perl_substr_index(text: str) -> int:
    """
    Coerce a ``substr`` offset/length the way Perl's ``substr`` reads it.

    ``@substr`` passes its raw string arguments straight to Perl ``substr``
    (``reference/src/ferm:1570``), and ``pp_substr`` reads each through a
    ``SvIsUV``-aware path: a magnitude that fits in a UV stays a large
    *positive* value -- ``substr(s, 0, 2**63)`` keeps the whole string --
    unlike general scalar->IV numification, which reinterprets that same bit
    pattern as a negative IV.  The leading numeric prefix is read and
    truncated toward zero; a non-numeric string is 0.  Saturation matches
    perl 5.42: a magnitude past UV_MAX collapses to UV_MAX read as ``-1``,
    and anything below ``-2**63`` clamps to IV_MIN.
    """
    match = _NUMERIC_PREFIX_RE.match(text)
    if match is None:
        return 0
    number, exponent = match.group("number", "exp")
    negative = match.group("sign") == "-"
    if exponent is None and "." not in number:
        magnitude = int(number)
        if negative:
            return max(-magnitude, _IV_MIN)
        # Keep the full UV magnitude positive (substr's SvIsUV path); only
        # a value past UV_MAX (which Perl stores as an NV) saturates to -1.
        return magnitude if magnitude <= _UV_MAX else -1
    value = float(match.group())
    if _IV_MIN <= value < 2**63:
        return int(value)
    if value > 0:
        return int(value) if value < 2**64 else -1
    return _IV_MIN


def splitpath_file(path: str) -> str:
    """Return the trailing component (``File::Spec->splitpath`` basename)."""
    index = path.rfind("/")
    return path if index < 0 else path[index + 1 :]


def splitpath_dir(path: str) -> str:
    """Return the directory with its trailing slash (``splitpath``)."""
    index = path.rfind("/")
    return "" if index < 0 else path[: index + 1]


def _split_backtick_output(output: str) -> list[str]:
    """
    Strip ``#`` comments and split on whitespace (Perl ``:1470``/``:1473``).

    The word list a backtick command's stdout contributes, before each
    word goes through ``getvalues``.
    """
    stripped = re.sub(r"#.*", "", output)
    # re.ASCII: Perl's byte-mode \s is [ \t\n\r\f\x0B]; a Unicode \s
    # would also split on \x1c-\x1f (found by the differential fuzzer).
    return [
        word for word in re.split(r"\s+", stripped, flags=re.ASCII) if word
    ]


#: The token-source override passed through ``getvalues`` (Perl's ``$code``).
TokenSource: TypeAlias = "Callable[[], Token | None]"


class Evaluator:
    """
    Reads values from the token stream against a variable stack.

    Bundles the :class:`~pyferm.tokenizer.Tokenizer` and
    :class:`~pyferm.scope.Scope` that Perl keeps as the ``$script`` and
    ``@stack`` globals, exposing the readers ``enter`` drives.
    """

    def __init__(
        self,
        tokenizer: Tokenizer,
        scope: Scope,
        *,
        resolver_provider: ResolverProvider | None = None,
    ) -> None:
        """
        Bind the evaluator to a tokenizer and a scope stack.

        ``resolver_provider`` scopes ``@resolve`` lookups to this evaluator;
        ``None`` (the CLI path) falls back to the process-wide provider
        installed with :func:`pyferm.resolver.set_resolver_provider`.
        """
        self.tokenizer = tokenizer
        self.scope = scope
        self._resolver_provider = resolver_provider
        #: Current value-reader recursion depth (see :data:`MAX_VALUE_DEPTH`).
        self._value_depth = 0

    # -- variable / function stack lookups (:1220-1379) ------------------

    def variable_value(self, name: str) -> Value:
        """
        Look up a variable, then a pseudo-variable (Perl ``:1221``).

        ``LINE`` resolves to the current input line; otherwise the stack is
        walked from the top (innermost first, so the stack list reverses),
        falling back to the top frame's ``auto`` pseudo-variables (Perl
        ``$stack[0]{auto}``, ``stack[-1]`` here).  Returns ``None`` when
        undefined.
        """
        if name == "LINE":
            # No script while evaluating --def: fall through to undefined,
            # so the caller reports "no such variable: $LINE" (the oracle's
            # autovivified empty $script behaves the same way).
            script = self.tokenizer.script_if_any
            if script is None:
                return None
            return str(script.line)
        for frame in reversed(self.scope.stack):
            if name in frame.vars:
                return frame.vars[name]
        if self.scope.stack:
            top = self.scope.stack[-1]
            if name in top.auto:
                return top.auto[name]
        return None

    def string_variable_value(self, name: str) -> Value:
        """Like :meth:`variable_value` but reject an array (Perl ``:1240``)."""
        value = self.variable_value(name)
        if _is_ref(value):
            error(f"variable '{name}' must be a string, but it is an array")
        return value

    def lookup_function(self, name: str) -> FunctionLike | None:
        """
        Find a user-defined ``@function`` on the stack (Perl ``:1370``).

        Returns :class:`~pyferm.scope.FunctionLike`, the structural stand-in
        for the parser's ``Function`` -- ``functions`` sits below ``parser``
        in the import layering and cannot name it directly.
        """
        for frame in reversed(self.scope.stack):
            if name in frame.functions:
                return frame.functions[name]
        return None

    # -- value readers (:1416-1657) --------------------------------------

    def getvalues(
        self,
        code: TokenSource | None = None,
        *,
        non_empty: bool = False,
        allow_negation: bool = False,
        comma_allowed: bool = False,
        parenthesis_allowed: bool = False,
        allow_array_negation: bool = False,
    ) -> Value:
        """
        Read one value: scalar, array, function call, ... (Perl ``:1416``).

        Guards the value-reader recursion with :data:`MAX_VALUE_DEPTH` (an
        explicit frame counter); every recursion point -- nested arrays via
        :meth:`_read_array`, chained ``!`` negation, and nested ``@`` calls
        via :meth:`get_function_params` -- re-enters here, so one guard
        covers them all.  Delegates to :meth:`_getvalues_body`.
        """
        if self._value_depth >= MAX_VALUE_DEPTH:
            error(f"values nested too deeply (max {MAX_VALUE_DEPTH})")
        self._value_depth += 1
        try:
            return self._getvalues_body(
                code,
                non_empty=non_empty,
                allow_negation=allow_negation,
                comma_allowed=comma_allowed,
                parenthesis_allowed=parenthesis_allowed,
                allow_array_negation=allow_array_negation,
            )
        finally:
            self._value_depth -= 1

    def _getvalues_body(
        self,
        code: TokenSource | None = None,
        *,
        non_empty: bool = False,
        allow_negation: bool = False,
        comma_allowed: bool = False,
        parenthesis_allowed: bool = False,
        allow_array_negation: bool = False,
    ) -> Value:
        """
        Read one value (Perl ``:1416``); see :meth:`getvalues` for the guard.

        A faithful transcription of ferm's recursive value reader; the
        keyword flags mirror Perl's ``%options`` (``non_empty`` forbids an
        empty array, ``allow_negation`` a leading ``!``, and so on).
        """
        token = self.tokenizer.require_next_token(code)
        if not isinstance(token, str):
            # A deferred value injected into the stream passes straight
            # through (Perl's final "else" branch); a Line sentinel never
            # reaches here because ``next_token`` drops sentinels first.
            assert isinstance(token, Deferred)
            return token

        if token == "(":
            return self._read_array(code, non_empty=non_empty)
        backtick = self._quoted_inside(token, "`")
        if backtick is not None:
            return self._run_shell(backtick)
        single = self._quoted_inside(token, "'")
        if single is not None:
            return single
        double = self._quoted_inside(token, '"')
        if double is not None:
            return _DVAR_RE.sub(
                lambda m: self._interpolate(m.group(1)), double
            )
        if token == "!":
            if not allow_negation:
                error("negation is not allowed here")
            inner = self.getvalues(code)
            return negate_value(inner, None, allow_array_negation)
        if token == ",":
            if comma_allowed:
                return token
            error("comma is not allowed here")
        if token == "=":
            error('equals operator ("=") is not allowed here')
        if token == "$":
            name = self.tokenizer.require_next_token(code)
            if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
                error(
                    "variable name expected - if you want to concatenate "
                    "strings, try using double quotes"
                )
            value = self.variable_value(name)
            if value is None:
                error(f"no such variable: ${name}")
            return value
        if token == "&":
            error("function calls are not allowed as keyword parameter")
        if token == ")" and not parenthesis_allowed:
            error("Syntax error")
        if token.startswith("@"):
            return self._call_builtin(token)
        return token

    def _quoted_inside(self, token: str, quote: str) -> str | None:
        """Return the inside of a ``quote``-delimited token, else ``None``."""
        match = _QUOTED_RE[quote].fullmatch(token)
        return match.group(1) if match is not None else None

    def _interpolate(self, name: str) -> str:
        """Expand ``$name`` inside a double-quoted string (undefined -> "")."""
        return stringify(self.string_variable_value(name))

    def _read_array(
        self, code: TokenSource | None, *, non_empty: bool
    ) -> Value:
        """Read a parenthesised array until ``)`` (Perl ``:1422``)."""
        wordlist: list[Value] = []
        while True:
            token = self.getvalues(
                code, parenthesis_allowed=True, comma_allowed=True
            )
            if not _is_ref(token):
                if token == ")":
                    break
                if token == ",":
                    error(
                        "Comma is not allowed within arrays, please use "
                        "only a space"
                    )
                wordlist.append(token)
            elif isinstance(token, list):
                wordlist.extend(token)
            elif isinstance(token, (Deferred, SetRef)):
                wordlist.append(token)
            else:
                error("unknown token type")
        if not wordlist and non_empty:
            error("empty array not allowed here")
        # A named set is opaque to nft and cannot share a selector with any
        # other value.  This one post-loop invariant covers every element kind
        # and order; guarding inside the per-branch appends left the list and
        # Deferred branches unchecked, so a ``($set $list)`` selector slipped
        # past under --nft (the iptables pre-pass masked it under the default
        # backend) and unfolded into separate rules.
        if (
            any(isinstance(item, SetRef) for item in wordlist)
            and len(wordlist) != 1
        ):
            error(
                "a named set cannot be mixed with other values in one selector"
            )
        return wordlist[0] if len(wordlist) == 1 else wordlist

    def _run_shell(
        self,
        command: str,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> Value:
        """
        Run a backtick command and tokenize its output (Perl ``:1455``).

        Only stdout is captured, as with Perl backticks: the child's
        stderr reaches the terminal, so a failing command's diagnostics
        are not swallowed.  ``runner`` is the spawn seam (the
        ``capture_previous`` convention); ``None`` -- the backtick path --
        binds ``subprocess.run`` late, so monkeypatching still works.
        """
        if runner is None:
            runner = subprocess.run
        try:
            result = runner(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                encoding=BYTE_ENCODING,
                check=False,
            )
        except OSError as exc:
            error(f"failed to execute: {exc.strerror or exc}")
        if result.returncode != 0:
            if result.returncode < 0:
                error(f"child died with signal {-result.returncode}")
            error(f"child exited with status {result.returncode}")

        tokens = deque(_split_backtick_output(result.stdout))
        values: list[Value] = []
        while tokens:
            value = self.getvalues(
                lambda: tokens.popleft() if tokens else None
            )
            values.extend(to_array(value))
        return values[0] if len(values) == 1 else values

    def getvar(self) -> Value:
        """Read one value, forbidding an array (Perl ``getvar``, ``:1624``)."""
        token = self.getvalues()
        if isinstance(token, list):
            error("array not allowed here")
        return token

    def get_function_params(
        self, *, allow_negation: bool = False
    ) -> list[Value]:
        """
        Read a ``(a, b, ...)`` argument list (Perl ``:1633``).

        ``allow_negation`` is threaded into every :meth:`getvalues` call, as
        Perl forwards its ``%options`` (``getvalues(undef, @_)``, ``:1654``);
        the parser passes it when expanding a user ``&function`` call so a
        ``! arg`` is accepted, while the ``@``-builtins leave it off.
        """
        self.tokenizer.expect_token(
            "(", 'function name must be followed by "()"'
        )
        if self.tokenizer.peek_token() == ")":
            self.tokenizer.require_next_token()
            return []
        params: list[Value] = []
        while True:
            if params:
                token = self.tokenizer.require_next_token()
                if token == ")":
                    break
                if token != ",":
                    error('"," expected')
            params.append(self.getvalues(allow_negation=allow_negation))
        return params

    def collect_tokens(
        self, *, include_semicolon: bool = False, include_else: bool = False
    ) -> list[Token]:
        """
        Buffer tokens up to the statement end (Perl ``:1662``).

        Tracks bracket depth so a top-level ``;`` (or a closing ``}``) ends
        the run; used to capture a ``@def`` body or a ``domain (...)`` block
        for replay.  Re-emits a leading line sentinel because the statement's
        first token has already been consumed.
        """
        level: list[str] = []
        tokens: list[Token] = [make_line_token(self.tokenizer.script.line)]
        while True:
            keyword = self.tokenizer.next_raw_token()
            if keyword is None:
                error(
                    "unexpected end of file within function/variable "
                    "declaration"
                )
            if not isinstance(keyword, str):
                self.tokenizer.handle_special_token(keyword)
            elif keyword in ("{", "("):
                level.append(keyword)
            elif keyword in ("}", ")"):
                expected = "{" if keyword == "}" else "("
                opener = level.pop() if level else None
                if opener is None or opener != expected:
                    error(f"unmatched '{keyword}'")
            elif keyword == ";" and not level:
                if include_semicolon:
                    tokens.append(keyword)
                if include_else and self.tokenizer.peek_token() == "@else":
                    continue
                break
            tokens.append(keyword)
            if keyword == "}" and not level:
                break
        return tokens

    # -- @-builtins (:1522-1617) -----------------------------------------

    def _call_builtin(self, token: str) -> Value:
        """Dispatch a ferm ``@`` built-in function (Perl ``:1522``)."""
        handler = self.BUILTIN_FUNCTIONS.get(token)
        if handler is None:
            return error("unknown ferm built-in function")
        return handler(self)

    def _params(self, usage: str, count: int) -> list[Value]:
        """Read a fixed-arity argument list, erroring with ``usage``."""
        params = self.get_function_params()
        if len(params) != count:
            error(f"Usage: {usage}")
        return params

    def _string_param(self, usage: str) -> str:
        """Read the single non-reference argument, stringified."""
        params = self._params(usage, 1)
        if _is_ref(params[0]):
            error(ERR_STRING_EXPECTED)
        return stringify(params[0])

    def _builtin_defined(self) -> Value:
        """``@defined($var)`` / ``@defined(&func)`` (Perl ``:1523``)."""
        self.tokenizer.expect_token(
            "(", 'function name must be followed by "()"'
        )
        kind = self.tokenizer.require_next_token()
        if kind == "$":
            name = self.tokenizer.require_next_token()
            if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
                error("variable name expected")
            self.tokenizer.expect_token(")")
            return "1" if self.variable_value(name) is not None else ""
        if kind == "&":
            name = self.tokenizer.require_next_token()
            if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
                error("function name expected")
            self.tokenizer.expect_token(")")
            return "1" if self.lookup_function(name) is not None else ""
        return error("'$' or '&' expected")

    def _builtin_glob(self) -> Value:
        """``@glob(pattern)`` against the script's dir (Perl ``:1588``)."""
        params = self._params("@glob(string)", 1)
        match = re.match(r"^(.*/)", self.tokenizer.script.filename)
        parent_dir = match.group(1) if match is not None else "./"
        result: list[Value] = []
        for pattern in to_array(params[0]):
            path = stringify(pattern)
            if not path.startswith("/"):
                path = parent_dir + path
            # Perl glob() takes a full shell pattern (possibly absolute);
            # Path.glob needs a split base + relative pattern, so it does
            # not fit a faithful port here.
            result.extend(sorted(globlib.glob(path)))  # noqa: PTH207
        return result[0] if len(result) == 1 else result

    def _builtin_eq(self) -> Value:
        """``@eq(a, b)``: Perl ``eq`` string equality as a ferm bool."""
        params = self._params("@eq(a, b)", 2)
        return format_bool(_perl_eq(params[0], params[1]))

    def _builtin_ne(self) -> Value:
        """``@ne(a, b)``: negated ``@eq``."""
        params = self._params("@ne(a, b)", 2)
        return format_bool(not _perl_eq(params[0], params[1]))

    def _builtin_not(self) -> Value:
        """``@not(a)``: Perl boolean negation as a ferm bool."""
        params = self._params("@not(a)", 1)
        return format_bool(not perl_true(params[0]))

    def _builtin_cat(self) -> Value:
        """``@cat(...)``: concatenate, deferred if any argument is."""
        params = self.get_function_params()
        if contains_deferred(*params):
            return Deferred(deferred_cat, params)
        return cat(*params)

    def _builtin_join(self) -> Value:
        """``@join(sep, ...)``: join the flattened tail with ``sep``."""
        params = self.get_function_params()
        if not params:
            return ""
        separator = stringify(params[0])
        return join_value(separator, flatten(*params[1:]))

    def _builtin_substr(self) -> Value:
        """``@substr(string, offset, length)``: Perl substr semantics."""
        params = self._params("@substr(string, num, num)", 3)
        if any(_is_ref(p) for p in params):
            error(ERR_STRING_EXPECTED)
        return _perl_substr(
            stringify(params[0]),
            _perl_substr_index(stringify(params[1])),
            _perl_substr_index(stringify(params[2])),
        )

    def _builtin_length(self) -> Value:
        """``@length(string)``: string length as a decimal string."""
        return str(len(self._string_param("@length(string)")))

    def _builtin_basename(self) -> Value:
        """``@basename(path)``: the file part of ``path``."""
        return splitpath_file(self._string_param("@basename(path)"))

    def _builtin_dirname(self) -> Value:
        """``@dirname(path)``: the directory part of ``path``."""
        return splitpath_dir(self._string_param("@dirname(path)"))

    def _builtin_resolve(self) -> Value:
        """``@resolve((hostname ...), [type])``: a deferred DNS lookup."""
        params = self.get_function_params()
        if len(params) not in (1, 2):
            error("Usage: @resolve((hostname ...), [type])")
        provider = self._resolver_provider
        if provider is None:
            return Deferred(resolve, params)

        # The closure captures only the injected provider, never the
        # evaluator: a deferred is realized after the token position has
        # moved on (see the module docstring's free-function rule).
        def resolve_with_provider(domain: str, *args: Value) -> list[Value]:
            return resolve(domain, *args, resolver=provider())

        return Deferred(resolve_with_provider, params)

    def _builtin_ipfilter(self) -> Value:
        """``@ipfilter((ip1 ip2 ...))``: a deferred per-family filter."""
        params = self.get_function_params()
        if len(params) != 1:
            error("Usage: @ipfilter((ip1 ip2 ...))")
        return Deferred(ipfilter, params)

    #: ferm ``@`` built-ins: token -> handler (Perl ``:1522-1617``).  The
    #: single source of truth for the built-in function names; the
    #: introspection completeness gate keys off this table.  In-class with
    #: bare names so the private methods stay private to the class.
    BUILTIN_FUNCTIONS: ClassVar[dict[str, Callable[[Evaluator], Value]]] = {
        "@defined": _builtin_defined,
        "@eq": _builtin_eq,
        "@ne": _builtin_ne,
        "@not": _builtin_not,
        "@cat": _builtin_cat,
        "@join": _builtin_join,
        "@substr": _builtin_substr,
        "@length": _builtin_length,
        "@basename": _builtin_basename,
        "@dirname": _builtin_dirname,
        "@glob": _builtin_glob,
        "@resolve": _builtin_resolve,
        "@ipfilter": _builtin_ipfilter,
    }

    # -- keyword-parameter parsers (:498-615) ----------------------------

    def address_magic(self, rule: Rule) -> Value:
        """
        Parse a ``source``/``destination`` address value (Perl ``:552``).

        Realizes any deferred ``@resolve``/``@ipfilter`` against the rule's
        family now, and -- only on a dual-stack ``domain (ip ip6)`` rule
        (``domain_both``) -- filters out addresses of the wrong family.
        """
        family = rule.domain if isinstance(rule.domain, str) else ""
        value = self.getvalues(allow_negation=True)
        negated = False
        ips: list[Value]
        if isinstance(value, list):
            ips = realize_deferred(family, *value)
        elif isinstance(value, Deferred):
            ips = realize_deferred(family, value)
        elif isinstance(value, Negated):
            ips = realize_deferred(family, value.value)
            negated = True
        elif isinstance(value, SetRef):
            filtered = realize_deferred(family, *value.elements)
            if rule.domain_both:
                filtered = ipfilter(family, filtered)
            return SetRef(value.name, filtered)
        elif _is_ref(value):
            raise internal_error()
        else:
            ips = [value]
        if rule.domain_both:
            ips = ipfilter(family, ips)
        if negated and ips:
            return Negated(ips)
        return ips

    def cgroup_classid(self, rule: Rule) -> Value:
        """Parse a cgroup ``classid``: hex:hex or decimal (Perl ``:583``)."""
        del rule  # uniform keyword-parser signature (address_magic & co.)
        value = self.getvalues(allow_negation=True)
        negated = False
        if isinstance(value, list):
            classids: list[Value] = list(value)
        elif isinstance(value, Negated):
            classids = [value.value]
            negated = True
        elif _is_ref(value):
            raise internal_error()
        else:
            classids = [value]

        normalized: list[Value] = []
        for item in classids:
            text = stringify(item)
            pair = _CLASSID_RE.fullmatch(text)
            if pair is not None:
                high = int(pair.group(1), 16)
                number = (high << 16) + int(pair.group(2), 16)
                stored: Value = str(number)
            elif _DECIMAL_RE.fullmatch(text):
                number = int(text)
                stored = text
            else:
                error("classid must be hex:hex or decimal")
            if number < 0:
                error("classid must be non-negative")
            if number > MAX_CLASSID:
                error("classid is too large")
            normalized.append(stored)

        if negated and normalized:
            return Negated(normalized)
        return normalized

    def multiport_params(self, rule: Rule) -> Value:
        """
        Parse ``multiport`` ports, chunked to 15 each (Perl ``:499``).

        multiport accepts at most 15 ports per invocation (a range counts as
        two), so a long list is split into chunks that become array elements
        and unfold into several rules.
        """
        proto = realize_protocol(rule)
        protos = to_array(proto) if proto is not None else []
        if proto is None or not any(
            isinstance(p, str) and _MULTIPORT_PROTO_RE.fullmatch(p)
            for p in protos
        ):
            error(
                'To use multiport, you have to specify "proto tcp" or '
                '"proto udp" first'
            )
        value = self.getvalues(allow_negation=True, allow_array_negation=True)
        if not isinstance(value, list):
            return join_value(",", value)

        params: list[Value] = []
        chunk: list[str] = []
        size = 0
        for ports in value:
            text = stringify(ports)
            increment = 2 if ":" in text else 1
            if size + increment > MAX_MULTIPORT_PORTS:
                params.append(",".join(chunk))
                chunk = []
                size = 0
            chunk.append(text)
            size += increment
        if chunk:
            params.append(",".join(chunk))
        return params[0] if len(params) == 1 else params
