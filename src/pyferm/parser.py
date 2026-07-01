"""
Recursive-descent parser: ``enter()`` and its keyword/option helpers.

Faithful port of the parser core of ``reference/src/ferm``: the ~795-line
``enter()`` recursion (``:2123-2892``, a deliberate monolith) plus
``parse_keyword``/``parse_option`` (``:1943-2031``), ``set_domain``/
``set_target``/``set_module_target`` (``:2070-2119``), ``mkrules`` (``:1924``)
and ``collect_filenames`` (``:1099``).

``enter`` reads tokens one keyword at a time and dispatches on each.  The Perl
source wraps the dispatch in a ``for ($keyword) { ... }`` once-loop whose
``next`` falls through to a trailing ``error("Doesn't support negation")``
check; this port models that with an inner :func:`handle` returning ``"next"``
(fall through to the negation check, then continue the read loop) or
``"return"`` (the ``}`` handler, which exits ``enter`` outright).

State Perl keeps in globals is gathered on the :class:`Parser`: the token
stream and variable stack come from the injected
:class:`pyferm.functions.Evaluator` (its ``Tokenizer`` and ``Scope``), the
per-family ``%domains`` is passed in, and ``%option`` is a typed
:class:`pyferm.config.Options`.  The execution-coupled
:func:`pyferm.domains.initialize_domain` (reached via ``check_domain``) is fed
the same injected ``capture_previous`` closure and ``emit_line`` sink the cli
wires up, so the parser never imports the backend.  The ``@hook`` lists are
parser state, consumed later by the cli's main flow (``:777-794``).

``Option.module`` (the port-only contract field, a sanctioned deviation) is
filled by :meth:`Parser.parse_option` from the keyword-to-module link that
``merge_keywords`` records (the oracle computes the same link at parse time
and discards it); ``kind`` is synthesized from the option name in
:func:`pyferm.scope.append_option`.  Phase 1 has no consumer for either
field -- they exist for the Phase 2 nft translator.
"""

from __future__ import annotations

import io
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

from pyferm.domains import (
    CapturePrevious,
    ChainInfo,
    DomainInfo,
    LineEmitter,
    ShellSnapshotBuilder,
    TableInfo,
    initialize_domain,
    resolve_chain_priority,
)
from pyferm.errors import FermError, error, internal_error, warning
from pyferm.functions import (
    Evaluator,
    realize_protocol,
    realize_protocol_keyword,
    splitpath_dir,
    splitpath_file,
)
from pyferm.modules import (
    MATCH_DEFS,
    PORT_PROTOCOLS,
    PROTO_DEFS,
    SHORTCUTS,
    TARGET_DEFS,
    Keyword,
    ModuleDef,
    ParamFunction,
)
from pyferm.rules import (
    is_netfilter_core_target,
    is_netfilter_module_target,
    mkrules2,
    netfilter_canonical_protocol,
    netfilter_protocol_module,
)
from pyferm.scope import (
    Frame,
    Rule,
    SourcePosition,
    append_option,
    merge_keywords,
    new_level,
)
from pyferm.tokenizer import Line, Script, Token, Tokenizer, make_line_token
from pyferm.tree import (
    Block,
    BlockNode,
    DefNode,
    HeaderNode,
    HookNode,
    IfNode,
    IncludeNode,
    Node,
    PreserveNode,
    RawShimNode,
    RuleNode,
    SetNode,
    SubchainNode,
)
from pyferm.values import (
    Multi,
    Params,
    SetRef,
    Value,
    contains_deferred,
    flatten,
    negate_value,
    realize_deferred,
    stringify,
    to_array,
)
from pyferm.walker import Walker

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from pyferm.config import Options
    from pyferm.scope import Scope

#: ferm 1.1 keywords automatically remapped with a warning (Perl ``:86``).
DEPRECATED_KEYWORDS = {"realgoto": "goto"}

#: Leading keywords the dispatch treats as their own (non-rule) statement,
#: routed to the streaming shim per keyword.  Everything else that leads a
#: statement (a match/target/shortcut, ``!``/``$``/``&``, a deprecated alias)
#: starts a rule, captured whole and sliced on the walk by visit_RuleNode.
#: These never carry a ``!`` prefix, so the shim path needs no negation.
_NON_RULE_LEADING: Final = frozenset(
    {
        ";",
        "}",
        "@else",
        "hook",
        "@hook",
        "include",
        "@include",
        "def",
        "@def",
        "@set",
        "@preserve",
        "domain",
        "table",
        "chain",
        "policy",
        "priority",
        "subchain",
        "@subchain",
        "@gotosubchain",
    }
)

#: Rule keywords that themselves consume a following ``{ ... }`` block, so a
#: top-level ``{`` after one is the subchain body (part of the rule), not a
#: nested match block that would end the rule span.
_SUBCHAIN_KEYWORDS: Final = frozenset(
    {"subchain", "@subchain", "@gotosubchain"}
)

#: Hard ceiling on nested-block recursion in :meth:`Parser.enter`.  Real
#: configs nest below ten levels; 100 is an order of magnitude of headroom
#: yet sits well below the interpreter's own RecursionError point
#: (~150-300 frames at the default recursionlimit).  An explicit counter,
#: NOT the ``level`` parameter: an array ``domain``/``table``/``chain``
#: replays its block with ``enter(0, ...)`` (:meth:`Parser._replay_array`),
#: resetting ``level``.  A sanctioned deviation: Perl recurses until
#: memory runs out, the port fails with a located diagnostic.
MAX_BLOCK_DEPTH = 100

#: iptables chain-name cap, shared by every target that names a chain --
#: chain/subchain/jump/goto (Perl ``:2600``/``:2693``/``:2809``/``:2817``).
MAX_CHAIN_NAME_LENGTH: Final[int] = 29

#: iptables ``log-prefix`` cap; over-long prefixes are truncated, not
#: rejected (Perl ``:1998-1999``).  A distinct limit that happens to match
#: :data:`MAX_CHAIN_NAME_LENGTH`.
MAX_LOG_PREFIX_LENGTH: Final[int] = 29

_NAME_RE = re.compile(r"\w+")
#: nft set identifier: letter-led word chars only, no digit-leading names.
#: Early UX reject; authoritative check is on the nft emit boundary.
_NFT_SET_NAME_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9_]*\Z")
_DVAR_RE = re.compile(r"\$(\w+)")
#: A double-quoted token, for the function-expansion interpolation (``:2484``).
_DQUOTE_RE = re.compile(r'".*"', re.DOTALL)
#: A lower-case lead, distinguishing letter param codes (``s``/``c``) from a
#: numeric count in ``parse_keyword`` (Perl ``$params =~ /^[a-z]/``).
_LOWER_RE = re.compile(r"[a-z]")
#: A ``'...'``/``"..."`` quoted subchain name (Perl ``:2681``).
_QUOTED_SUB_RE = re.compile(r"([\"'])(.*)\1", re.DOTALL)
#: Built-in chain names that must be upper case (Perl ``:2588``).
_LOWER_BUILTIN_RE = re.compile(r"input|forward|output|prerouting|postrouting")
#: A sign glued to a number (``-1``/``+5``) following a chain-priority
#: landmark, e.g. ``priority filter -1`` -- folded into the offset form.
_GLUED_SIGN_RE = re.compile(r"[+-][0-9]+")
#: A relative ``@include`` path / pipe spec (Perl ``:1112``).
_ABS_OR_PIPE_RE = re.compile(r"^/|\|$")
#: dpkg backup files skipped by a directory ``@include`` (Perl ``:1129``).
_DPKG_RE = re.compile(r"\.dpkg-(old|dist|new|tmp)$")


def _check_chain_name(name: str) -> None:
    """Reject a chain name iptables would truncate (shared chain-name cap)."""
    if len(name) > MAX_CHAIN_NAME_LENGTH:
        error(
            "Chain name too long, must be "
            f"{MAX_CHAIN_NAME_LENGTH} characters or less: {name}"
        )


def _domain_key(value: Value) -> str:
    """
    Return a family value as a dict key, requiring a single name.

    ``set_domain`` stores a scalar family (``ip``/``ip6``/...) for every real
    rule, so this is always a ``str`` in practice.  Perl would stringify an
    array ref into a (nonsensical) key for an empty ``domain ()`` carrying
    rules; this port raises instead -- no test exercises that, and a clean
    error beats a misleading key.
    """
    if isinstance(value, str):
        return value
    raise internal_error()


def collect_filenames(
    parent_filename: str, pathnames: list[Value]
) -> list[str]:
    """
    Resolve ``@include`` arguments to a list of files (Perl ``:1099``).

    Non-absolute, non-pipe names are taken relative to ``parent_filename``'s
    directory.  A trailing ``/`` includes every regular file in a directory
    (sorted, skipping dpkg backups and dot/tilde files); a trailing ``|`` is a
    command pipe kept verbatim; a leading ``|`` is rejected.
    """
    match = re.match(r"^(.*/)", parent_filename)
    parent_dir = match.group(1) if match is not None else "./"

    ret: list[str] = []
    for raw in pathnames:
        pathname = stringify(raw)
        if _ABS_OR_PIPE_RE.search(pathname) is None:
            pathname = parent_dir + pathname

        if pathname.endswith("/"):
            directory = Path(pathname)
            if not directory.is_dir():
                error(f"'{pathname}' is not a directory")
            try:
                names = sorted(entry.name for entry in directory.iterdir())
            except OSError as exc:
                error(f"Failed to open directory '{pathname}': {exc.strerror}")
            for name in names:
                if _DPKG_RE.search(name) is not None:
                    continue
                if name.startswith(".") or name.endswith("~"):
                    continue
                filename = pathname + name
                if Path(filename).is_file():
                    ret.append(filename)
        elif pathname.endswith("|"):
            ret.append(pathname)
        elif pathname.startswith("|"):
            error("This kind of pipe is not allowed")
        else:
            if Path(pathname).is_dir():
                error(
                    f"'{pathname}' is a directory; maybe use trailing '/' "
                    "to include a directory?"
                )
            if not Path(pathname).is_file():
                error(f"'{pathname}' is not a file")
            ret.append(pathname)

    return ret


@dataclass
class Function:
    """
    A user-defined ``@def &name`` function (Perl ``%function``, ``:2372``).

    ``params`` are the declared parameter names; ``tokens`` is the captured
    body token list; ``block`` records whether the body contains a ``{`` (so a
    call must be terminated by ``;``, ``:2468``).  Stored on a scope
    :class:`~pyferm.scope.Frame` and found by ``Evaluator.lookup_function``.
    """

    params: list[str]
    tokens: list[Token]
    block: bool


@dataclass
class NegatedFlag:
    r"""
    A mutable negation flag for ``parse_keyword`` (Perl ``\$negated``).

    The oracle passes ``$negated`` by reference so a keyword handler can clear
    it once consumed (``undef $$negated_ref``, ``:1953``); a leftover flag
    after dispatch triggers "Doesn't support negation".  Python has no scalar
    references, so this one-field holder stands in.
    """

    active: bool


#: Block-header keywords whose value runs up to a top-level ``{`` or ``;``.
_HEADER_KEYWORDS: Final = frozenset(
    {"domain", "table", "chain", "policy", "priority"}
)

#: Leading keywords of ``;``-terminated directive statements and the node
#: each becomes; every other leading keyword is a plain rule.
_STMT_NODES: Final[
    dict[str, Callable[[SourcePosition, tuple[Token, ...]], Node]]
] = {
    "@def": DefNode,
    "def": DefNode,
    "@set": SetNode,
    "@include": IncludeNode,
    "include": IncludeNode,
    "@preserve": PreserveNode,
    "@hook": HookNode,
    "hook": HookNode,
    "@subchain": SubchainNode,
    "subchain": SubchainNode,
    "@gotosubchain": SubchainNode,
}


class _StructuralParser:
    """
    Eager, eval-free structural pass over a flat token list.

    Builds the retained tree the structural analyzers consume: BOTH @if
    branches, headers and blocks, and statements as raw spans -- WITHOUT
    evaluating conditions, substituting variables, loading modules or resolving
    @include. Boundaries come from a bracket-aware scan (the eval-free
    mechanics of collect_tokens), never from eval. Error-tolerant: truncated or
    unbalanced input yields the structure captured so far, not a diagnostic.

    Known limitations (pinned): @include content is invisible (resolving it is
    file I/O); ``$var`` is not substituted, so ``mod $var`` is not sliced and
    ``domain $d`` / ``jump $t`` stay literal; and a multi-keyword header line
    such as ``table filter chain INPUT { ... }`` is one HeaderNode, not nested
    ones. Line sentinels are kept in the spans (for file:line); the analyzers
    skip them.
    """

    def __init__(self, tokens: list[Token], filename: str) -> None:
        self._tokens = tokens
        self._filename = filename
        self._i = 0
        self._line = 0

    def _pos(self) -> SourcePosition:
        return SourcePosition(self._filename, self._line)

    def _skip_sentinels(self) -> None:
        """Advance past leading non-string tokens, tracking the line."""
        tokens = self._tokens
        while self._i < len(tokens) and not isinstance(tokens[self._i], str):
            tok = tokens[self._i]
            if isinstance(tok, Line):
                self._line = tok.number
            self._i += 1

    def _peek(self) -> str | None:
        """Return the next string token (sentinels skipped), or None."""
        self._skip_sentinels()
        if self._i < len(self._tokens):
            tok = self._tokens[self._i]
            return tok if isinstance(tok, str) else None
        return None

    def parse_block(self) -> Block:
        """Parse statements until a top-level ``}`` (consumed) or EOF."""
        pos = self._pos()
        statements: list[Node] = []
        while True:
            tok = self._peek()
            if tok is None:
                break
            if tok == "}":
                self._i += 1
                break
            statements.append(self._parse_statement())
        return Block(source_pos=pos, statements=tuple(statements))

    def _parse_statement(self) -> Node:
        pos = self._pos()
        tok = self._tokens[self._i]  # a string: _peek skipped the sentinels
        assert isinstance(tok, str)
        if tok == "@if":
            return self._parse_if(pos)
        if tok == "{":
            self._i += 1
            return BlockNode(source_pos=pos, body=self.parse_block())
        if tok in _HEADER_KEYWORDS:
            return self._parse_header(pos)
        span = self._capture_statement_span()
        node_type = _STMT_NODES.get(tok)
        if node_type is not None:
            return node_type(pos, span)
        return RuleNode(pos, span)

    def _capture_statement_span(self) -> tuple[Token, ...]:
        """Raw span from here to and including the next top-level ``;``."""
        tokens = self._tokens
        start = self._i
        depth = 0
        while self._i < len(tokens):
            tok = tokens[self._i]
            if isinstance(tok, Line):
                self._line = tok.number
            elif tok in ("{", "("):
                depth += 1
            elif tok in ("}", ")"):
                if depth == 0:
                    break  # unbalanced top-level close: stop before it
                depth -= 1
            elif tok == ";" and depth == 0:
                self._i += 1
                return tuple(tokens[start : self._i])
            self._i += 1
        return tuple(tokens[start : self._i])

    def _scan_header_value(self) -> str | None:
        """
        Advance over a header/condition value, tracking parens and the line.

        Stops before (without consuming) the first top-level ``{``, ``;`` or
        ``}`` and returns it, or None at end of input.
        """
        tokens = self._tokens
        depth = 0
        while self._i < len(tokens):
            tok = tokens[self._i]
            if isinstance(tok, Line):
                self._line = tok.number
            elif isinstance(tok, str):
                if tok == "(":
                    depth += 1
                elif tok == ")":
                    depth = max(0, depth - 1)
                elif depth == 0 and tok in ("{", ";", "}"):
                    return tok
            self._i += 1
        return None

    def _parse_header(self, pos: SourcePosition) -> HeaderNode:
        tokens = self._tokens
        keyword = tokens[self._i]
        assert isinstance(keyword, str)
        self._i += 1
        value_start = self._i
        terminator = self._scan_header_value()
        value_span = tuple(tokens[value_start : self._i])
        if terminator == "{":
            self._i += 1
            return HeaderNode(pos, keyword, value_span, self.parse_block())
        if terminator == ";":
            self._i += 1
        # ``}`` or EOF: no block; leave a top-level ``}`` for the caller.
        return HeaderNode(pos, keyword, value_span, None)

    def _parse_if(self, pos: SourcePosition) -> IfNode:
        tokens = self._tokens
        self._i += 1  # consume '@if'
        cond_start = self._i
        self._scan_header_value()  # stop before the top-level '{'
        cond_span = tuple(tokens[cond_start : self._i])
        then_body = self._parse_branch_block(pos)
        else_body: Block | None = None
        if self._peek() == "@else":
            self._i += 1  # consume '@else'
            if self._peek() == "@if":
                inner_pos = self._pos()
                else_body = Block(
                    source_pos=inner_pos,
                    statements=(self._parse_if(inner_pos),),
                )
            else:
                else_body = self._parse_branch_block(pos)
        return IfNode(pos, cond_span, then_body, else_body)

    def _parse_branch_block(self, pos: SourcePosition) -> Block:
        """Parse a ``{ ... }`` branch block, or empty Block if malformed."""
        if self._peek() == "{":
            self._i += 1
            return self.parse_block()
        return Block(source_pos=pos, statements=())


class Parser:
    """The ferm parser: drives ``enter`` over the injected evaluator/scope."""

    @staticmethod
    def parse_to_block(config: str) -> Block:
        """
        Build an eager, eval-free structural tree over a config string.

        Test-facing entry point for the structural analyzers: it tokenizes the
        config and structures BOTH @if branches, headers and blocks WITHOUT
        evaluating conditions, substituting variables, loading modules or
        resolving @include. Off the golden/parity path; see _StructuralParser
        for the pinned limitations.
        """
        filename = "<parse_to_block>"
        script = Script(filename=filename, handle=io.StringIO(config))
        tokenizer = Tokenizer(script)
        tokens: list[Token] = []
        while True:
            tok = tokenizer.next_raw_token()
            if tok is None:
                break
            tokens.append(tok)
        script.close()
        return _StructuralParser(tokens, filename).parse_block()

    def __init__(
        self,
        evaluator: Evaluator,
        domains: dict[str, DomainInfo],
        options: Options,
        *,
        resolve_tools: Callable[[str], dict[str, str]] | None = None,
        capture_previous: CapturePrevious | None = None,
        emit_line: LineEmitter | None = None,
        shell_snapshot: ShellSnapshotBuilder | None = None,
    ) -> None:
        """Bind the parser to its evaluator, domain state and injected I/O."""
        self.evaluator = evaluator
        self.scope: Scope = evaluator.scope
        self.tokenizer: Tokenizer = evaluator.tokenizer
        self.domains = domains
        self.options = options
        self._block_depth = 0
        self._resolve_tools = resolve_tools
        self._capture_previous = capture_previous
        self._emit_line = emit_line
        self._shell_snapshot = shell_snapshot
        self.pre_hooks: list[str] = []
        self.post_hooks: list[str] = []
        self.flush_hooks: list[str] = []

    # -- domain / target helpers (:2070-2119, :976) ----------------------

    def check_domain(self, domain: Value) -> bool:
        """
        Filter by ``--domain`` and initialise the family (Perl ``:976``).

        Returns ``False`` when ``--domain`` is set and ``domain`` differs (the
        family is skipped); otherwise initialises it -- wrapping any
        :class:`FermError` from :func:`initialize_domain` through
        :func:`error` so it gains a ``file:line`` prefix -- and returns
        ``True``.
        """
        if self.options.domain is not None and domain != self.options.domain:
            return False
        try:
            initialize_domain(
                _domain_key(domain),
                self.domains,
                self.options,
                resolve_tools=self._resolve_tools,
                capture_previous=self._capture_previous,
                emit_line=self._emit_line,
                shell_snapshot=self._shell_snapshot,
            )
        except FermError as exc:
            # Perl re-raises ``error($@)``: $@ keeps the die's trailing
            # newline and error() appends its own, so the message prints
            # with a blank line after it.
            error(f"{exc}\n")
        return True

    def set_domain(self, rule: Rule, domain: Value) -> bool:
        """
        Set the rule's family and base keywords (Perl ``:2070``).

        Returns ``False`` when :meth:`check_domain` filtered the family out;
        otherwise derives ``domain_family`` (``ip6`` folds to ``ip``; an empty
        or mixed set is ``none``/an error), installs that family's base match
        keywords copy-on-write, and records the family on the rule and on the
        scope's ``DOMAIN`` pseudo-variable.
        """
        if not self.check_domain(domain):
            return False

        if not isinstance(domain, list):
            family = "ip" if domain == "ip6" else stringify(domain)
        elif len(domain) == 0:
            family = "none"
        elif any(
            not (isinstance(d, str) and re.fullmatch(r"ip6?", d, re.DOTALL))
            for d in domain
        ):
            error("Cannot combine non-IP domains")
        else:
            family = "ip"

        rule.domain_family = family
        base = MATCH_DEFS.get(family, {}).get("")
        rule.keywords = base.keywords if base is not None else {}
        # base keywords come from the family's "" pseudo-module: no -m is
        # ever emitted for them, so they carry no introducing module
        rule.keyword_module = {}
        rule.cow.add("keywords")
        rule.domain = domain
        self.scope.top.auto["DOMAIN"] = domain
        return True

    def set_target(self, rule: Rule, name: str, value: Value) -> None:
        """Record the rule's single action (Perl ``:2093``)."""
        if rule.has_action:
            error("There can only one action per rule")
        rule.has_action = True
        append_option(rule, name, value)

    def set_module_target(
        self, rule: Rule, name: str, defs: ModuleDef
    ) -> None:
        """
        Apply a target module like ``DNAT``/``TCPMSS`` (Perl ``:2101``).

        ``TCPMSS`` requires ``proto tcp``; ``MARK`` becomes ``mark`` under
        ebtables (which has both ``--mark`` and ``-j mark``).  The module's
        keywords are merged so its options parse afterwards.
        """
        if name == "TCPMSS":
            protos = realize_protocol(rule)
            if protos is None:
                error("No protocol specified before TCPMSS")
            for proto in to_array(protos):
                if proto != "tcp":
                    error(f'TCPMSS not available for protocol "{proto}"')
        if name == "MARK" and rule.domain_family == "eb":
            name = "mark"
        self.set_target(rule, "jump", name)
        merge_keywords(rule, defs.keywords, name)

    # -- keyword / option parsing (:1943-2031) ---------------------------

    def _call_param_function(
        self, function: ParamFunction, rule: Rule
    ) -> Value:
        """
        Invoke a ``&name`` option-argument parser on the evaluator.

        Resolves the recorded :class:`ParamFunction` name
        (``address_magic``/``cgroup_classid``/``multiport_params``) to the
        matching :class:`Evaluator` method (Perl's ``&$params($rule)``,
        ``:1959``).
        """
        method = getattr(self.evaluator, function.name, None)
        if method is None:
            raise internal_error()
        return cast("Value", method(rule))

    def parse_keyword(
        self, rule: Rule, keyword: Keyword, negated: NegatedFlag
    ) -> Value:
        """
        Read one keyword's argument per its module def (Perl ``:1943``).

        Dispatches on ``params``: ``None`` (a bare flag), a
        :class:`ParamFunction` (custom parser), ``"m"`` (a repeated ``multi``),
        a letter-code string (``s`` scalar / ``c`` comma-joined, possibly
        several), a count of ``1`` (one value, with optional ``!`` negation),
        or a larger numeric count (that many scalars).  A consumed negation --
        whether the leading ``!`` (pre-negation) or one before the value -- is
        applied to the result.
        """
        params = keyword.params
        local_negated = False
        if negated.active and keyword.pre_negation:
            local_negated = True
            negated.active = False

        value: Value
        if params is None:
            value = None
        elif isinstance(params, ParamFunction):
            value = self._call_param_function(params, rule)
        elif params == "m":
            domain = self.scope.top.auto.get("DOMAIN")
            family = domain if isinstance(domain, str) else ""
            value = Multi(
                realize_deferred(family, *to_array(self.evaluator.getvalues()))
            )
        elif isinstance(params, str) and _LOWER_RE.match(params):
            local_negated = self._maybe_consume_negation(
                keyword, local_negated
            )
            collected: list[Value] = []
            for code in params:
                if code == "s":
                    collected.append(self.evaluator.getvar())
                elif code == "c":
                    items = to_array(self.evaluator.getvalues(non_empty=True))
                    collected.append(
                        ",".join(stringify(item) for item in items)
                    )
                else:
                    raise internal_error()
            value = collected[0] if len(collected) == 1 else Params(collected)
        elif params == 1:
            local_negated = self._maybe_consume_negation(
                keyword, local_negated
            )
            value = self.evaluator.getvalues()
            if (
                keyword.name == "log-prefix"
                and isinstance(value, str)
                and len(value) > MAX_LOG_PREFIX_LENGTH
            ):
                warning(
                    "log-prefix is too long; truncating to "
                    f"{MAX_LOG_PREFIX_LENGTH} characters: "
                    f"'{value[:MAX_LOG_PREFIX_LENGTH]}'"
                )
                value = value[:MAX_LOG_PREFIX_LENGTH]
        else:
            local_negated = self._maybe_consume_negation(
                keyword, local_negated
            )
            value = Params(
                [self.evaluator.getvar() for _ in range(int(params))]
            )

        if local_negated:
            value = negate_value(
                value, "pre_negated" if keyword.pre_negation else None
            )
        return value

    def _maybe_consume_negation(
        self, keyword: Keyword, local_negated: bool
    ) -> bool:
        """
        Consume a value-leading ``!`` if the keyword allows it (``:1964``).

        Returns the (possibly newly set) negation flag; a no-op when the
        keyword is not negatable or negation was already taken.
        """
        if (
            keyword.negation
            and not local_negated
            and self.tokenizer.peek_token() == "!"
        ):
            self.tokenizer.require_next_token()
            return True
        return local_negated

    def parse_option(
        self, keyword: Keyword, rule: Rule, negated: NegatedFlag
    ) -> None:
        """
        Read a module option and queue it on the rule (Perl ``:2026``).

        Fills :attr:`pyferm.scope.Option.module` from the keyword-to-module
        link ``merge_keywords`` recorded (a sanctioned deviation: the
        contract field the Phase 2 nft translator reads).
        """
        append_option(
            rule,
            keyword.name,
            self.parse_keyword(rule, keyword, negated),
            module=rule.keyword_module.get(keyword.name),
        )

    # -- rule emission (:1924) -------------------------------------------

    def mkrules(self, rule: Rule) -> None:
        """
        Seed ``chain_rules`` over the rule's tables/chains (Perl ``:1924``).

        Marks the family enabled, then for every (table, chain) pair unfolds
        the rule into that chain's rule list -- unless ``--flush`` is set or
        the rule carries no match (policy-only), exactly as the oracle.
        """
        domain = _domain_key(rule.domain)
        domain_info = self.domains[domain]
        domain_info.enabled = True

        if not self.options.nft:
            self._expand_setrefs_for_iptables(rule)

        for table in to_array(rule.table):
            table_info = domain_info.tables.setdefault(
                stringify(table), TableInfo()
            )
            for chain in to_array(rule.chain):
                chain_info = table_info.chains.setdefault(
                    stringify(chain), ChainInfo()
                )
                if rule.has_rule and not self.options.flush:
                    mkrules2(domain, chain_info.rules, rule)

    @staticmethod
    def _expand_setrefs_for_iptables(rule: Rule) -> None:
        """
        Replace SetRef option values with their element lists.

        Runs only under the default iptables backend.  Called once per
        completed rule, before the inner table/chain loop hands the rule to
        ``mkrules2``, so the standard ``unfold_rule`` produces the cartesian
        product with the same code that expands ``dport (22 80)``.  A SetRef
        mixed with other values in one selector is an error: expanding it
        would leak a bare SetRef through the unfold path into
        ``shell_escape``.
        """
        if sum(isinstance(o.value, SetRef) for o in rule.options) > 1:
            error("at most one named set per rule in this version")
        for option in rule.options:
            value = option.value
            if isinstance(value, SetRef):
                option.value = list(value.elements)
            elif isinstance(value, list) and any(
                isinstance(item, SetRef) for item in value
            ):
                # Defense-in-depth: unreachable under the current parser
                # because _read_array rejects a mixed literal+set before this
                # point; kept in case a future call path bypasses _read_array.
                error(
                    "a named set cannot be mixed with other values "
                    "in one selector"
                )

    # -- token-stream block replay (domain/table/chain arrays) -----------

    def _replay_array(
        self,
        items: Iterable[Value],
        build_inner: Callable[[Value], Rule | None],
    ) -> None:
        """
        Re-parse a captured block once per array element (Perl ``:2500``).

        ``domain``/``table``/``chain`` with an array value buffer the rest of
        the statement (including its ``;``) and replay it for each element,
        swapping the script's token queue.  The current line is re-emitted as
        a sentinel onto the saved queue so positions stay correct after the
        block, and the live handle is detached during replay so no new input
        is read.
        """
        block = self.evaluator.collect_tokens(
            include_semicolon=True, include_else=True
        )
        script = self.tokenizer.script
        old_line = script.line
        old_handle = script.handle
        old_tokens = script.tokens
        old_base_level = script.base_level
        old_tokens.appendleft(make_line_token(script.line))
        script.handle = None

        # finally: a parse error inside the replay must not lose the
        # detached live handle (the cli closes scripts by walking them).
        try:
            for item in items:
                inner = build_inner(item)
                if inner is None:
                    continue
                script.base_level = 0
                script.tokens = deque(block)
                self.enter(0, inner)
        finally:
            script.base_level = old_base_level
            script.tokens = old_tokens
            script.handle = old_handle
            script.line = old_line

    # -- the core recursion (:2123) --------------------------------------

    def _resolve_keyword(self, token: object) -> tuple[object, NegatedFlag]:
        """
        Resolve a leading token to (keyword, negated) as the read loop does.

        ``!`` reads the negated keyword identity via getvar() BEFORE its arity
        is known (the fifth runtime mechanism); a deprecated alias is remapped
        with a warning. Shared by the streaming loop and Walker.visit_RuleNode
        so both negation forms replay identically.
        """
        keyword = token
        negated = NegatedFlag(keyword == "!")
        if negated.active:
            keyword = self.evaluator.getvar()
            if keyword is None:
                error("unexpected end of file after negation")
        if isinstance(keyword, str) and keyword in DEPRECATED_KEYWORDS:
            new_keyword = DEPRECATED_KEYWORDS[keyword]
            warning(
                f"'{keyword}' is deprecated, please use "
                f"'{new_keyword}' instead"
            )
            keyword = new_keyword
        return keyword, negated

    def _capture_rule_span(self) -> tuple[Token, ...]:
        """
        Capture a rule statement as a raw span up to its top-level ``;``.

        Reads raw tokens (Line sentinels kept, for file:line on replay),
        tracking ``{``/``(`` nesting so only a top-level ``;`` ends the span.
        A top-level ``}`` belongs to the enclosing block, not the rule: it is
        pushed back and the span ends before it (a missing ``;`` is diagnosed
        by that ``}`` handler via the shared rule). Capture is lenient --
        bracket mismatches are diagnosed on the walk, matching the streaming
        oracle -- and the leading token is NOT consumed beforehand.
        """
        script = self.tokenizer.script
        span: list[Token] = [make_line_token(script.line)]
        depth = 0
        saw_subchain = False
        while True:
            tok = self.tokenizer.next_raw_token()
            if tok is None:
                break
            if not isinstance(tok, str):
                self.tokenizer.handle_special_token(tok)
            elif tok == "(":
                depth += 1
            elif tok == "{":
                if depth == 0 and not saw_subchain:
                    # a top-level '{' after matches opens a nested block: the
                    # rule ends here and the block streams separately.
                    script.tokens.appendleft(tok)
                    break
                depth += 1
            elif tok == ")":
                if depth > 0:
                    depth -= 1
            elif tok == "}":
                if depth == 0:
                    script.tokens.appendleft(tok)
                    break
                depth -= 1
            elif tok == ";" and depth == 0:
                span.append(tok)
                break
            if isinstance(tok, str) and tok in _SUBCHAIN_KEYWORDS:
                saw_subchain = True
            span.append(tok)
        return tuple(span)

    def enter(self, level: int, prev: Rule | None) -> None:
        """
        Parse a block of rules at depth ``level`` (Perl ``:2123``).

        Guards the recursion with :data:`MAX_BLOCK_DEPTH` (an explicit
        frame counter -- ``level`` resets to 0 in array-block replays),
        then delegates to :meth:`_enter_body`.  The guard sits after the
        structural ``internal_error`` check so broken bookkeeping cannot
        skew the count; all four recursion points call ``enter``, so one
        guard covers them all.
        """
        base_level = self.tokenizer.script.base_level or 0
        if base_level > level:
            raise internal_error()

        if self._block_depth >= MAX_BLOCK_DEPTH:
            error(f"too many nested blocks (max {MAX_BLOCK_DEPTH})")
        self._block_depth += 1
        try:
            self._enter_body(level, prev, base_level)
        finally:
            self._block_depth -= 1

    def _enter_body(
        self, level: int, prev: Rule | None, base_level: int
    ) -> None:
        """
        Run the body of :meth:`enter` (Perl ``:2123``).

        See the wrapper for the depth guard.
        Reads keywords until end of file or a closing ``}`` and dispatches each
        through :func:`handle`.  ``prev`` seeds the level's inherited context
        (see :func:`pyferm.scope.new_level`); the trailing consistency checks
        reproduce the oracle's "missing ``}``" / "missing ``;``" diagnostics.
        """
        # The per-block Walker owns statement order and this block's mutable
        # dispatch state: the pending rule (walker.rule, seeded from prev) and
        # walker.shown_keyword, the keyword as last seen by the dispatcher.  A
        # handler may remap the keyword (``hook``->``@hook``, a shortcut->its
        # real keyword); the trailing "Doesn't support negation" check must
        # name the remapped form, as Perl's ``for ($keyword)`` aliases the
        # variable (``:2881``).  Sharing this state is why a promoted { or @if
        # cannot desync from a preceding shim statement's matches.
        walker = Walker(self, level, prev, base_level)

        def script_position() -> SourcePosition:
            script = self.tokenizer.script
            return SourcePosition(script.filename, script.line)

        def handle(keyword: object, negated: NegatedFlag) -> str:
            walker.shown_keyword = keyword

            # effectuation operator
            if keyword == ";":
                if not walker.rule.non_empty:
                    error('Empty rule before ";" not allowed')
                if walker.rule.has_rule and not walker.rule.has_action:
                    error('No action defined; did you mean "NOP"?')
                if walker.rule.chain is None:
                    error("No chain defined")
                walker.rule.script = script_position()
                self.mkrules(walker.rule)
                walker.rule = new_level(prev)
                return "next"

            # @if is promoted to a typed IfNode (see Walker.visit_IfNode);
            # only a leftover @else after a true @if still reaches the shim.
            if keyword == "@else":
                # a leftover "else" from a true "if": drop its body
                self.evaluator.collect_tokens()
                return "next"

            # hooks for custom shell commands
            if keyword == "hook":
                warning("'hook' is deprecated, use '@hook'")
                keyword = "@hook"
                walker.shown_keyword = keyword

            if keyword == "@hook":
                if walker.rule.domain is not None:
                    error('"hook" must be the first token in a command')
                position = self.evaluator.getvar()
                if position == "pre":
                    hooks = self.pre_hooks
                elif position == "post":
                    hooks = self.post_hooks
                elif position == "flush":
                    hooks = self.flush_hooks
                else:
                    error(f"Invalid hook position: '{position}'")
                hooks.append(stringify(self.evaluator.getvar()))
                self.tokenizer.expect_token(";")
                return "next"

            # { is promoted to a typed BlockNode (see Walker.visit_BlockNode);
            # the closing } still reaches the shim to end the level.
            if keyword == "}":
                if level <= base_level:
                    error('Unmatched "}"')
                if walker.rule.non_empty:
                    error('Missing semicolon before "}"')
                return "return"

            # include another file
            if keyword in ("@include", "include"):
                if self.tokenizer.peek_token() == "@glob":
                    files = [
                        stringify(name)
                        for name in to_array(self.evaluator.getvalues())
                    ]
                else:
                    files = collect_filenames(
                        self.tokenizer.script.filename,
                        to_array(self.evaluator.getvalues()),
                    )
                if self.tokenizer.next_token() != ";":
                    error(
                        'Missing ";" - "include FILENAME" must be the last '
                        "command in a rule"
                    )
                for filename in files:
                    self._include_file(filename, level, walker.rule)
                return "next"

            # definition of a variable or function
            if keyword in ("@def", "def"):
                self._parse_def(walker.rule)
                return "next"

            # named set declaration -- dispatch ONLY on @set, never bareword
            # "set", which is the live ipset match keyword
            if keyword == "@set":
                self._parse_set(walker.rule)
                return "next"

            if keyword == "@preserve":
                self._parse_preserve(walker.rule)
                walker.rule = new_level(prev)
                return "next"

            # something not inherited by the parent closure
            walker.rule.non_empty = True

            if keyword == "$":
                error(
                    "variable references are only allowed as keyword parameter"
                )

            if keyword == "&":
                self._call_function(walker.rule)
                return "next"

            # where to put the rule?
            if keyword == "domain":
                if walker.rule.domain is not None:
                    error("Domain is already specified")
                domains = self.evaluator.getvalues()
                if isinstance(domains, list):

                    def build_domain(item: Value) -> Rule | None:
                        inner = new_level(walker.rule)
                        if not self.set_domain(inner, item):
                            return None
                        inner.domain_both = True
                        return inner

                    self._replay_array(domains, build_domain)
                    walker.rule = new_level(prev)
                elif not self.set_domain(walker.rule, domains):
                    self.evaluator.collect_tokens()
                    walker.rule = new_level(prev)
                return "next"

            if keyword == "table":
                if walker.rule.table is not None:
                    warning("Table is already specified")
                tables = self.evaluator.getvalues()
                if walker.rule.domain is None:
                    self.set_domain(walker.rule, self.options.domain or "ip")
                if isinstance(tables, list):

                    def build_table(item: Value) -> Rule | None:
                        inner = new_level(walker.rule)
                        inner.table = item
                        self.scope.top.auto["TABLE"] = item
                        return inner

                    self._replay_array(tables, build_table)
                    walker.rule = new_level(prev)
                else:
                    walker.rule.table = tables
                    self.scope.top.auto["TABLE"] = tables
                return "next"

            if keyword == "chain":
                if walker.rule.chain is not None:
                    warning("Chain is already specified")
                chains = self.evaluator.getvalues()
                for chain in to_array(chains):
                    if isinstance(chain, str) and _LOWER_BUILTIN_RE.fullmatch(
                        chain
                    ):
                        error(
                            "Please write built-in chain names in upper case"
                        )
                if walker.rule.domain is None:
                    self.set_domain(walker.rule, self.options.domain or "ip")
                if walker.rule.table is None:
                    walker.rule.table = "filter"
                domain = _domain_key(walker.rule.domain)
                for table in to_array(walker.rule.table):
                    table_info = self.domains[domain].tables.setdefault(
                        stringify(table), TableInfo()
                    )
                    for chain in to_array(chains):
                        name = stringify(chain)
                        _check_chain_name(name)
                        table_info.chains.setdefault(name, ChainInfo())
                if isinstance(chains, list):

                    def build_chain(item: Value) -> Rule | None:
                        inner = new_level(walker.rule)
                        inner.chain = item
                        self.scope.top.auto["CHAIN"] = item
                        return inner

                    self._replay_array(chains, build_chain)
                    walker.rule = new_level(prev)
                else:
                    walker.rule.chain = chains
                    self.scope.top.auto["CHAIN"] = chains
                return "next"

            if walker.rule.chain is None:
                error("Chain must be specified")

            # policy for a built-in chain
            if keyword == "policy":
                if walker.rule.has_rule:
                    error("Cannot specify matches for policy")
                policy = self.evaluator.getvar()
                if not isinstance(policy, str) or not is_netfilter_core_target(
                    policy
                ):
                    error(f"Invalid policy target: {policy}")
                self.tokenizer.expect_token(";")
                domain = _domain_key(walker.rule.domain)
                domain_info = self.domains[domain]
                domain_info.enabled = True
                for table in to_array(walker.rule.table):
                    table_info = domain_info.tables.setdefault(
                        stringify(table), TableInfo()
                    )
                    for chain in to_array(walker.rule.chain):
                        table_info.chains.setdefault(
                            stringify(chain), ChainInfo()
                        ).policy = policy
                walker.rule = new_level(prev)
                return "next"

            # nft base-chain priority override (form A: `priority -N`
            # written after the chain name, before the block -- so unlike
            # `policy` it does NOT consume a trailing `;`).  Stored
            # unconditionally; the backend validates (nft rejects it on a
            # user chain, iptables rejects it outright).
            if keyword == "priority":
                if walker.rule.has_rule:
                    error("Cannot specify matches for priority")
                token = stringify(self.evaluator.getvar())
                # nft landmark offset form (`dstnat - 10`) arrives as three
                # tokens; fold the `+`/`-` and magnitude back in so the
                # resolver sees one string.  A joined `dstnat-10` or a plain
                # `-1` is already a single token and skips this.
                sign = self.tokenizer.peek_token()
                if sign in ("+", "-"):
                    self.tokenizer.next_token()
                    magnitude = stringify(self.evaluator.getvar())
                    token = f"{token} {sign} {magnitude}"
                elif (
                    isinstance(sign, str)
                    and token.isalpha()
                    and _GLUED_SIGN_RE.fullmatch(sign)
                ):
                    # `filter -1` / `filter +5`: the sign is glued to the
                    # number (a single token) right after a landmark name.
                    # Fold it into the offset form so the resolver sees
                    # `filter - 1` rather than leaving a stray `-1` token that
                    # would mis-report as "Unrecognized keyword".
                    self.tokenizer.next_token()
                    token = f"{token} {sign[0]} {sign[1:]}"
                domain = _domain_key(walker.rule.domain)
                try:
                    priority = resolve_chain_priority(domain, token)
                except ValueError:
                    error(f"Invalid chain priority: {token}")
                domain_info = self.domains[domain]
                domain_info.enabled = True
                already_set = False
                for table in to_array(walker.rule.table):
                    table_info = domain_info.tables.setdefault(
                        stringify(table), TableInfo()
                    )
                    for chain in to_array(walker.rule.chain):
                        chain_info = table_info.chains.setdefault(
                            stringify(chain), ChainInfo()
                        )
                        if chain_info.priority is not None:
                            already_set = True
                        chain_info.priority = priority
                if already_set:
                    warning("Priority is already specified")
                # Unlike `policy` (which sits inside the block and resets to
                # a fresh level), `priority` precedes the block at the chain
                # level: leave `rule.chain` intact so the following `{`
                # inherits it.
                return "next"

            if keyword in ("@subchain", "subchain", "@gotosubchain"):
                walker.rule = self._parse_subchain(
                    keyword, walker.rule, prev, level
                )
                return "next"

            # everything else is part of a "real" rule
            walker.rule.has_rule = True

            # extended parameters: module load
            if isinstance(keyword, str) and re.fullmatch(
                r"mod(?:ule)?", keyword
            ):
                for value in to_array(self.evaluator.getvalues()):
                    module = stringify(value)
                    if module in walker.rule.match:
                        continue
                    family_defs = MATCH_DEFS.get(
                        walker.rule.domain_family or "", {}
                    )
                    defs = family_defs.get(module)
                    append_option(walker.rule, "match", module)
                    walker.rule.match.add(module)
                    if defs is not None:
                        merge_keywords(walker.rule, defs.keywords, module)
                return "next"

            # shortcuts
            if (
                isinstance(keyword, str)
                and keyword not in walker.rule.keywords
            ):
                family = walker.rule.domain_family or ""
                shortcut = SHORTCUTS.get(family, {}).get(keyword)
                if shortcut is not None:
                    module = shortcut[0]
                    defs = MATCH_DEFS.get(family, {}).get(module)
                    append_option(walker.rule, "match", module)
                    walker.rule.match.add(module)
                    if defs is not None:
                        merge_keywords(walker.rule, defs.keywords, module)
                    keyword = shortcut[1]
                    walker.shown_keyword = keyword

            # keywords from rule.keywords
            if isinstance(keyword, str) and keyword in walker.rule.keywords:
                realize_protocol_keyword(walker.rule, keyword)
                self.parse_option(
                    walker.rule.keywords[keyword], walker.rule, negated
                )
                return "next"

            # actions
            if keyword in ("jump", "goto"):
                target = self.evaluator.getvar()
                if isinstance(target, str):
                    _check_chain_name(target)
                self.set_target(walker.rule, keyword, target)
                return "next"

            if isinstance(keyword, str) and is_netfilter_core_target(keyword):
                self.set_target(walker.rule, "jump", keyword)
                return "next"

            if keyword == "NOP":
                if walker.rule.has_action:
                    error("There can only one action per rule")
                walker.rule.has_action = True
                return "next"

            if isinstance(keyword, str):
                defs = is_netfilter_module_target(
                    TARGET_DEFS, walker.rule.domain_family, keyword
                )
                if defs is not None:
                    self.set_module_target(walker.rule, keyword, defs)
                    return "next"

            # protocol specific options
            if keyword in ("proto", "protocol"):
                self._parse_protocol(walker.rule, negated)
                return "next"

            # port switches
            if isinstance(keyword, str) and re.fullmatch(r"[sd]port", keyword):
                proto = realize_protocol(walker.rule)
                valid = proto is not None and any(
                    isinstance(p, str) and p in PORT_PROTOCOLS
                    for p in to_array(proto)
                )
                if not valid:
                    error(
                        "To use sport or dport, you have to specify "
                        '"proto tcp" or "proto udp" first'
                    )
                append_option(
                    walker.rule,
                    keyword,
                    self.evaluator.getvalues(allow_negation=True),
                )
                return "next"

            return error(f"Unrecognized keyword: {keyword}")

        # The strangler facade: each statement is materialized as a tree node
        # and dispatched through the Walker, which replays it via the streaming
        # handle() bound above.  Build and walk are interleaved per statement
        # (no parse pre-pass), so diagnostics stay in source order.  At this
        # layer every statement is a RawShimNode and the dispatch reads its
        # operands live -- a pure pass-through, byte-identical to the old call.
        walker.dispatch = handle
        walker.resolve = self._resolve_keyword
        # Route by the RAW leading token (peeked, not consumed): a block or
        # @if to its typed node; a non-rule statement keyword to the streaming
        # shim per keyword; everything else starts a rule captured whole and
        # sliced on the walk.  A rule owns its own negation handling (its
        # leading token may be ``!``); the shim path never negates.
        while True:
            lead = self.tokenizer.peek_token()
            if lead is None:
                break

            node: Node
            if lead == "{":
                self.tokenizer.next_token()
                node = BlockNode(source_pos=script_position())
                result = walker.visit(node)
            elif lead == "@if":
                self.tokenizer.next_token()
                node = IfNode(source_pos=script_position(), cond_span=())
                result = walker.visit(node)
            elif isinstance(lead, str) and lead in _NON_RULE_LEADING:
                token = self.tokenizer.next_token()
                walker.shown_keyword = token
                node = RawShimNode(
                    source_pos=script_position(),
                    keyword=token,
                    negated=False,
                    span=(),
                )
                result = walker.replay_shim(node, NegatedFlag(active=False))
            else:
                node = RuleNode(
                    source_pos=script_position(),
                    span=self._capture_rule_span(),
                )
                result = walker.visit(node)
            if result == "return":
                return

        if level > base_level:
            error('Missing "}" at end of file')
        if walker.rule.non_empty:
            error("Missing semicolon before end of file")

    # -- enter() sub-handlers (kept off the monolith for readability) ----

    def _include_file(self, filename: str, level: int, prev: Rule) -> None:
        """
        Open ``filename`` and parse it as a nested level (Perl ``:2282``).

        Pushes a scope frame that shares the parent's variables/functions
        (so an include can set values for its caller) but has its own
        ``FILENAME``/``FILEBNAME``/``DIRNAME`` pseudo-variables, parses the
        file at ``level + 1`` with a matching ``base_level``, then closes the
        handle and restores the previous script.
        """
        old_script = self.tokenizer.script
        new_script = self.tokenizer.open_script(filename)
        new_script.base_level = level + 1

        old_depth = len(self.scope.stack)
        if self.scope.stack:
            frame = Frame(
                vars=self.scope.top.vars,
                functions=self.scope.top.functions,
                auto=dict(self.scope.top.auto),
            )
        else:
            frame = Frame()
        frame.auto["FILENAME"] = filename
        frame.auto["FILEBNAME"] = splitpath_file(filename)
        frame.auto["DIRNAME"] = splitpath_dir(filename)
        self.scope.push(frame)

        self.enter(level + 1, prev)

        new_script.close()
        if new_script.process is not None and new_script.process.wait() != 0:
            # Perl: close on a piped handle reaps the child and fails on a
            # non-zero exit (:2311) -- a truncated ruleset must not install.
            error(f"'{new_script.filename}': exit status is not 0")
        self.scope.pop()
        if len(self.scope.stack) != old_depth:
            raise internal_error()
        self.tokenizer.script = old_script

    def _parse_def(self, rule: Rule) -> None:
        """
        Define a variable (``$``) or function (``&``) (Perl ``:2325``).

        Both bind on the innermost scope frame unless the global frame already
        carries that name (so a command-line ``-D`` definition wins).
        """
        if rule.non_empty:
            error('"def" must be the first token in a command')
        kind = self.tokenizer.require_next_token()
        if kind == "$":
            name = self.tokenizer.require_next_token()
            if not (isinstance(name, str) and _NAME_RE.fullmatch(name)):
                error("invalid variable name")
            self.tokenizer.expect_token("=")
            value = self.evaluator.getvalues(allow_negation=True)
            self.tokenizer.expect_token(";")
            if name not in self.scope.globals.vars:
                self.scope.top.vars[name] = value
        elif kind == "&":
            name = self.tokenizer.require_next_token()
            if not (isinstance(name, str) and _NAME_RE.fullmatch(name)):
                error("invalid function name")
            self.tokenizer.expect_token(
                "(", 'function parameter list or "()" expected'
            )
            params: list[str] = []
            while True:
                token = self.tokenizer.require_next_token()
                if token == ")":
                    break
                if params:
                    if token != ",":
                        error('"," expected')
                    token = self.tokenizer.require_next_token()
                if token != "$":
                    error('"$" and parameter name expected')
                token = self.tokenizer.require_next_token()
                if not (isinstance(token, str) and _NAME_RE.fullmatch(token)):
                    error("invalid function parameter name")
                params.append(token)
            self.tokenizer.expect_token("=")
            tokens = self.evaluator.collect_tokens()
            block = any(token == "{" for token in tokens)
            if name not in self.scope.globals.functions:
                self.scope.top.functions[name] = Function(
                    params=params, tokens=tokens, block=block
                )
        else:
            error('"$" (variable) or "&" (function) expected')

    def _parse_set(self, rule: Rule) -> None:
        """
        Define a named nft set (``@set $name = (...)``).

        Binds a :class:`~pyferm.values.SetRef` on the innermost scope frame
        (unless the global frame already carries the name, mirroring
        ``_parse_def``).  Rejects deferred elements and non-nft-identifier
        names early with a clean error rather than a late ``nft -f`` crash.
        """
        if rule.non_empty:
            error('"set" must be the first token in a command')
        kind = self.tokenizer.require_next_token()
        if kind != "$":
            error('"$" and set name expected')
        name = self.tokenizer.require_next_token()
        if not (isinstance(name, str) and _NAME_RE.fullmatch(name)):
            error("invalid set name")
        if not _NFT_SET_NAME_RE.match(name):
            error(
                f"invalid nft set name '{name}': "
                "must be a letter-led identifier"
            )
        self.tokenizer.expect_token("=")
        value = self.evaluator.getvalues(allow_negation=False)
        self.tokenizer.expect_token(";")
        if contains_deferred(value):
            error("deferred values are not allowed in a named set")
        elements = (
            flatten(*value) if isinstance(value, list) else flatten(value)
        )
        # A lone ``@set $b = ($a)`` keeps the inner SetRef as an element (the
        # mixing guard permits a single reference); a set nested in a set is
        # supported by neither backend, so reject it here with a clean message
        # rather than leaking an internal error / a ``SetRef(...)`` repr later.
        if any(isinstance(element, SetRef) for element in elements):
            error("a named set cannot contain another named set")
        if name not in self.scope.globals.vars:
            self.scope.top.vars[name] = SetRef(name, elements)

    def _call_function(self, rule: Rule) -> None:
        """
        Expand a user ``&name(...)`` call into the token stream (``:2440``).

        Looks the function up, reads its arguments, binds them to the
        parameter names, then substitutes ``$param`` references (and
        interpolates them inside double-quoted tokens) in the function body
        before unshifting the result -- plus a line sentinel that restores the
        caller's line number -- onto the token queue.
        """
        del rule  # the call is replayed through the token stream
        line_token = make_line_token(self.tokenizer.script.line)
        name = self.tokenizer.require_next_token()
        if not (isinstance(name, str) and _NAME_RE.fullmatch(name)):
            error("function name expected")
        found = self.evaluator.lookup_function(name)
        if found is None:
            error(f"no such function: &{name}")
        function = cast("Function", found)

        params = self.evaluator.get_function_params(allow_negation=True)
        if len(params) != len(function.params):
            error(
                f"Wrong number of parameters for function '&{name}': "
                f"{len(function.params)} expected, {len(params)} given"
            )
        variables = dict(zip(function.params, params, strict=True))

        if function.block:
            self.tokenizer.expect_token(";")

        tokens: list[Token] = list(function.tokens)
        index = 0
        while index < len(tokens):
            token = tokens[index]
            following = tokens[index + 1] if index + 1 < len(tokens) else None
            if (
                token == "$"
                and isinstance(following, str)
                and following in variables
            ):
                expanded = cast(
                    "list[Token]", list(to_array(variables[following]))
                )
                if len(tokens) != 1:
                    expanded = ["(", *expanded, ")"]
                tokens[index : index + 2] = expanded
                index += len(expanded) - 2
            elif isinstance(token, str) and _DQUOTE_RE.fullmatch(token):
                tokens[index] = _DVAR_RE.sub(
                    lambda match: (
                        stringify(variables[match.group(1)])
                        if match.group(1) in variables
                        else f"${match.group(1)}"
                    ),
                    token,
                )
            index += 1

        # extendleft inserts in reverse, so pre-reverse to prepend in order
        self.tokenizer.script.tokens.extendleft(
            reversed([*tokens, line_token])
        )

    def _parse_preserve(self, rule: Rule) -> None:
        """
        Mark chains to keep from the previous ruleset (Perl ``:2391``).

        Only valid in ``--fast`` mode with a chain and no matches.  A literal
        chain name is flagged ``preserve``; a ``/regex/`` name is recorded as a
        table preserve pattern (and dropped from the chains map) so matching
        chains in the live ruleset are kept dynamically.
        """
        if not self.options.fast:
            error("@preserve not implemented for --slow mode")
        if rule.chain is None:
            error("@preserve without chain")
        if rule.has_rule:
            error("Cannot specify matches for @preserve")
        self.tokenizer.expect_token(";")

        domain = _domain_key(rule.domain)
        domain_info = self.domains[domain]
        if not self.options.test and domain_info.previous is None:
            error(f"@preserve not supported on domain {domain}")

        for table in to_array(rule.table):
            table_info = domain_info.tables.setdefault(
                stringify(table), TableInfo()
            )
            for chain in to_array(rule.chain):
                name = stringify(chain)
                chain_info = table_info.chains.setdefault(name, ChainInfo())
                if chain_info.rules:
                    error(
                        f"Cannot @preserve chain {name} because it is "
                        "not empty"
                    )
                regex = re.fullmatch(r"/(.+)/", name)
                if regex is not None:
                    table_info.preserve_regexes.append(
                        re.compile(regex.group(1))
                    )
                    del table_info.chains[name]
                else:
                    chain_info.preserve = True

    def _parse_subchain(
        self, keyword: str, rule: Rule, prev: Rule | None, level: int
    ) -> Rule:
        """
        Create and enter an inline sub-chain (Perl ``:2667``).

        The sub-chain name is a quoted literal, an auto-generated
        ``ferm_auto_N`` (for a bare ``{``), or a bareword.  After registering
        it and emitting the jump/goto into the parent rule, the body is parsed
        in a fresh scope frame; the parent rule is then emitted and a new
        level returned (with ``has_rule`` cleared).
        """
        if rule.chain is None:
            error("Chain must be specified")
        jumptype = "goto" if keyword.startswith("@go") else "jump"
        jumpkey = re.sub(r"^sub", "@sub", keyword)
        if not rule.has_rule:
            error(f"No rule specified before '{jumpkey}'")

        token = self.tokenizer.peek_token()
        quoted = (
            _QUOTED_SUB_RE.fullmatch(token) if isinstance(token, str) else None
        )
        if quoted is not None:
            subchain = quoted.group(2)
            self.tokenizer.next_token()
            keyword = stringify(self.tokenizer.next_token())
        elif token == "{":
            self.tokenizer.next_token()
            subchain = self.scope.next_auto_chain()
            keyword = "{"
        else:
            subchain = stringify(self.evaluator.getvar())
            keyword = stringify(self.tokenizer.next_token())

        _check_chain_name(subchain)

        domain = _domain_key(rule.domain)
        for table in to_array(rule.table):
            chains = (
                self.domains[domain]
                .tables.setdefault(stringify(table), TableInfo())
                .chains
            )
            if subchain in chains:
                warning(f"Chain {subchain} already exists")
            else:
                chains[subchain] = ChainInfo()

        self.set_target(rule, jumptype, subchain)
        if keyword != "{":
            error(f'"{{" or chain name expected after {jumpkey}')

        inner = new_level(rule)
        inner.match = set()
        inner.options = []
        inner.chain = subchain
        inner.has_rule = False
        inner.has_action = False
        # The oracle builds %inner from scratch (:2711), copying only
        # domain/domain_family/domain_both/table/keywords -- crucially NOT
        # 'protocol'.  ``new_level`` copied it, so clear it: the parent's
        # protocol is carried only as ``auto_protocol`` (already inherited
        # by ``new_level``, overridden here when the parent had an explicit
        # protocol), so ``realize_protocol`` re-emits ``-p tcp`` inside the
        # sub-chain.
        inner.protocol = None
        if rule.protocol is not None:
            inner.auto_protocol = rule.protocol

        old_depth = len(self.scope.stack)
        frame = Frame(auto=dict(self.scope.top.auto))
        frame.auto["CHAIN"] = subchain
        self.scope.push(frame)
        self.enter(level + 1, inner)
        self.scope.pop()
        if len(self.scope.stack) != old_depth:
            raise internal_error()

        rule.script = SourcePosition(
            self.tokenizer.script.filename, self.tokenizer.script.line
        )
        self.mkrules(rule)
        rule = new_level(prev)
        rule.has_rule = False
        return rule

    def _parse_protocol(self, rule: Rule, negated: NegatedFlag) -> None:
        """
        Set the rule's protocol and merge its keywords (Perl ``:2844``).

        Emits the ``protocol`` option, then -- for a plain (non-array,
        non-negated) protocol -- canonicalises it and, when a proto module is
        defined for the family, merges that module's keywords and records its
        match module so options like ``dport`` parse afterwards.
        """
        descriptor = Keyword(
            name="", params=1, negation=True, pre_negation=False
        )
        protocol = self.parse_keyword(rule, descriptor, negated)
        rule.auto_protocol = None
        rule.protocol = protocol
        append_option(rule, "protocol", protocol)

        if isinstance(protocol, str):
            canonical = netfilter_canonical_protocol(protocol)
            defs = PROTO_DEFS.get(rule.domain_family or "", {}).get(canonical)
            if defs is not None:
                module = netfilter_protocol_module(canonical)
                merge_keywords(rule, defs.keywords, module)
                if module is not None:
                    rule.match.add(module)
