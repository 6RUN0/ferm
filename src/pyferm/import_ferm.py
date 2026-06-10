"""
Second console script: convert an iptables-save dump into ferm syntax.

Faithful port of ``reference/src/import-ferm``.  The Perl tool ``require``s
the main ``ferm`` program purely to reuse its module-definition tables and a
few netfilter predicates; this port imports the same data from
:mod:`pyferm.modules` and :mod:`pyferm.rules` instead.  It then re-implements
``import-ferm``'s *own* ``merge_keywords`` and ``parse_option`` (the Perl
``delete $main::{...}`` removes the conflicting ``ferm`` definitions), the
rule-merging ``optimize`` pass, and the ``flush*``/``write_line`` emitters.

The tool reads an ``iptables-save`` file (an argument, or stdin / a live
``iptables-save`` when none is given) and prints a suggested ferm
configuration.  It is exercised by the ``check-import`` round-trip
(SAVE -> import -> SAVE2, asserting SAVE == SAVE2) and underpins the
``check-preserve`` mock, so its output need not be byte-identical to the
Perl tool -- only round-trip equivalent after the golden sorter runs.

Rule structures are modelled as :class:`Rule`/:class:`MatchEntry` dataclasses
(the Perl ``%line`` hash and its ``[option, value]`` match pairs).  The
``optimize`` pass compares whole rules for equality; Perl does this with
``Data::Dumper`` (``$Data::Dumper::Sortkeys = 1``), which this port reproduces
with :func:`_canon` -- a structural canonical form that, like Dumper, tags
blessed values by class and collapses every coderef to one sentinel.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from pyferm.errors import FermError
from pyferm.modules import (
    MATCH_DEFS,
    PROTO_DEFS,
    TARGET_DEFS,
    Keyword,
    ParamFunction,
)
from pyferm.rules import (
    is_netfilter_core_target,
    is_netfilter_module_target,
    netfilter_canonical_protocol,
)
from pyferm.values import (
    Multi,
    Negated,
    Params,
    PreNegated,
    Value,
    stringify,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

#: import-ferm's own short-flag aliases (Perl ``%aliases``, ``:61``).  These
#: are the single-letter iptables options, unrelated to ferm's keyword
#: aliases; they map ``-s`` -> ``saddr`` and so on.
_ALIASES = {
    "i": "interface",
    "o": "outerface",
    "f": "fragment",
    "p": "protocol",
    "d": "daddr",
    "s": "saddr",
    "m": "match",
    "j": "jump",
    "g": "goto",
}

#: Protocols that gain ``sport``/``dport`` keywords (Perl ``:420``/``:447``).
_PORTED_PROTOCOLS = re.compile(r"tcp|udp|udplite|dccp|sctp")

#: ``\n?``: the oracle anchors with a bare-word ``$``, which also
#: matches before a trailing newline; ``re.ASCII``: Perl's byte-mode
#: ``\S`` includes ``\x1c``-``\x1f`` (found by the differential fuzzer).
_OPTION_RE = re.compile(r"-(\w)\n?", re.ASCII)
_LONG_OPTION_RE = re.compile(r"--(\S+)\n?", re.ASCII)
_ESCAPE_RE = re.compile(r"[^-\w.:/]", re.ASCII)

#: ``re.ASCII``: Perl's byte-mode ``\s`` is ``[ \t\n\r\f\x0B]``, so a
#: Unicode ``\s`` would swallow ``\x1c``-``\x1f`` bytes the oracle
#: lexes as words (found by the differential fuzzer).
_TOK_QUOTED = re.compile(r'\s*"([^"]*)"', re.ASCII)
_TOK_BANG = re.compile(r"\s*(!)", re.ASCII)
_TOK_WORD = re.compile(r"\s*(\S+)", re.ASCII)

_USAGE = (
    "Usage:\n"
    "    import-ferm > ferm.conf\n"
    "    iptables-save | import-ferm > ferm.conf\n"
    "    import-ferm inputfile > ferm.conf\n"
)


@dataclass
class MatchEntry:
    """One emitted option: ``[name, value]`` (Perl ``[$option, $value]``)."""

    name: str
    value: Value


@dataclass
class Rule:
    """
    A parsed rule (Perl's ``%line`` hash) or an ``optimize`` block node.

    ``cur`` aliases either :attr:`match` or :attr:`target` during parsing so
    that, like Perl's ``$line->{cur}``, pushed options land in the current
    section.  Optional fields default to ``None`` to mirror Perl ``exists``:
    a block node created by :func:`_optimize` sets only :attr:`match` and
    :attr:`block`.
    """

    keywords: dict[str, Keyword] = field(default_factory=dict)
    match: list[MatchEntry] = field(default_factory=list)
    mod: dict[str, int] = field(default_factory=dict)
    proto: Value | None = None
    jump: str | None = None
    goto: str | None = None
    target: list[MatchEntry] | None = None
    match_keywords: dict[str, Keyword] | None = None
    block: list[Rule] | None = None
    cur: list[MatchEntry] | None = field(default=None, repr=False)


def ferm_escape(value: object) -> str:
    r"""
    Quote a token unless it is a bare ferm word (Perl ``ferm_escape``).

    Returns the value verbatim when it is a non-empty string of only
    ``[-\\w.:/]`` characters; otherwise wraps it in single quotes (an empty
    string becomes ``''``).  A non-string stringifies first, matching Perl's
    implicit scalar coercion.
    """
    text = stringify(value)
    if text == "" or _ESCAPE_RE.search(text):
        return f"'{text}'"
    return text


def format_array(value: object) -> str:
    """
    Render a scalar or array value (Perl ``format_array``, ``:83``).

    A scalar escapes directly; a one-element array collapses to its element;
    a longer array becomes ``(a b c)``.  Perl dereferences any ref as an
    array, so a blessed ``multi`` value is treated like a plain array here.
    """
    if isinstance(value, Multi):
        items: list[Value] = value.values
    elif isinstance(value, list):
        items = value
    else:
        return ferm_escape(value)
    if len(items) == 1:
        return ferm_escape(items[0])
    return "(" + " ".join(ferm_escape(item) for item in items) + ")"


def _tokenize(text: str) -> list[str]:
    """
    Split a rule body into tokens (Perl ``tokenize``, ``:325``).

    Recognizes a double-quoted string (unquoted), a lone ``!``, or a run of
    non-whitespace, in that priority order, skipping leading whitespace.
    """
    result: list[str] = []
    rest = text
    while True:
        for pattern in (_TOK_QUOTED, _TOK_BANG, _TOK_WORD):
            match = pattern.match(rest)
            if match is not None:
                result.append(match.group(1))
                rest = rest[match.end() :]
                break
        else:
            return result


def _match_option(token: str) -> str | None:
    """
    Classify ``token`` as a ``-x``/``--long`` option (Perl ``:578``).

    Returns the option name, or ``None`` when the token is not an
    option (the caller warns or dies, depending on context).
    """
    match = _OPTION_RE.fullmatch(token) or _LONG_OPTION_RE.fullmatch(token)
    return None if match is None else match.group(1)


# --- Data::Dumper-equivalent structural canonicalization -------------


def _canon(value: object) -> object:
    """
    Canonicalize a value for equality (Perl's ``Dumper`` comparison).

    Produces nested tuples that compare equal exactly when Perl's
    ``Data::Dumper`` (with ``Sortkeys``) would emit equal strings: blessed
    values carry their class tag, hash keys sort, and every coderef collapses
    to one sentinel (Dumper renders all coderefs identically by default).
    """
    if value is None:
        return ("undef",)
    if isinstance(value, bool):
        return ("num", int(value))
    if isinstance(value, int):
        return ("num", value)
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, MatchEntry):
        return ("entry", value.name, _canon(value.value))
    if isinstance(value, Negated):
        return ("negated", _canon(value.value))
    if isinstance(value, PreNegated):
        return ("pre_negated", _canon(value.value))
    if isinstance(value, Multi):
        return ("multi", tuple(_canon(item) for item in value.values))
    if isinstance(value, Params):
        return ("params", tuple(_canon(item) for item in value.values))
    if isinstance(value, ParamFunction):
        return ("code",)
    if isinstance(value, Keyword):
        return (
            "kw",
            value.name,
            _canon(value.params),
            value.negation,
            value.pre_negation,
            value.ferm_name,
        )
    if isinstance(value, Rule):
        return _canon_rule(value, value.match)
    if isinstance(value, list):
        return ("array", tuple(_canon(item) for item in value))
    if isinstance(value, dict):
        return (
            "hash",
            tuple(
                sorted(
                    ((key, _canon(val)) for key, val in value.items()),
                    key=lambda pair: pair[0],
                )
            ),
        )
    raise FermError("internal error: uncanonicalizable value")


def _canon_rule(rule: Rule, match: list[MatchEntry]) -> object:
    """
    Canonicalize a rule with an explicit ``match`` list.

    Includes only the keys Perl's hash would hold (optional fields appear
    only when set), so that two rules compare equal iff their Dumper strings
    would.  ``_array_matches`` passes ``rule.match[1:]`` to drop the first
    option before comparing the remainder.
    """
    items: dict[str, object] = {
        "keywords": rule.keywords,
        "match": match,
        "mod": rule.mod,
    }
    if rule.proto is not None:
        items["proto"] = rule.proto
    if rule.jump is not None:
        items["jump"] = rule.jump
    if rule.goto is not None:
        items["goto"] = rule.goto
    if rule.target is not None:
        items["target"] = rule.target
    if rule.match_keywords is not None:
        items["match_keywords"] = rule.match_keywords
    if rule.block is not None:
        items["block"] = rule.block
    return _canon(items)


# --- the optimize pass -----------------------------------------------


def _prefix_matches(first: Rule, other: Rule) -> bool:
    """Whether ``other`` shares ``first``'s leading match (Perl ``:115``)."""
    return bool(other.match) and _canon(first.match[0]) == _canon(
        other.match[0]
    )


def _prefix_match_count(prefix: Rule, rules: Iterable[Rule]) -> int:
    """Count the consecutive rules sharing ``prefix``'s lead (``:121``)."""
    count = 0
    for rule in rules:
        if not _prefix_matches(prefix, rule):
            break
        count += 1
    return count


def _is_merging_array_member(value: Value) -> bool:
    """
    Whether a value can join an array (Perl ``:131``).

    True for a defined scalar or a plain array; blessed values (negated,
    multi, params) are excluded, so negated options never array-merge.
    """
    return value is not None and isinstance(value, (str, list))


def _array_matches(rule1: Rule, rule2: Rule) -> bool:
    """Whether two rules differ only in their first match (Perl ``:138``)."""
    if not rule1.match or not rule2.match:
        return False
    if not _is_merging_array_member(rule1.match[0].value):
        return False
    if not _is_merging_array_member(rule2.match[0].value):
        return False
    if rule1.match[0].name != rule2.match[0].name:
        return False
    return _canon_rule(rule1, rule1.match[1:]) == _canon_rule(
        rule2, rule2.match[1:]
    )


def _array_match_count(first: Rule, rules: Iterable[Rule]) -> int:
    """Count rules mergeable with ``first`` into an array (Perl ``:154``)."""
    if not first.match:
        return 0

    option = first.match[0].name
    params: int | str | ParamFunction | None = None
    if first.match_keywords is not None:
        keyword = first.match_keywords.get(option)
        if keyword is not None:
            params = keyword.params

    # Don't merge options that take exactly one string parameter (``=s``).
    if isinstance(params, str) and params == "s":
        return 0

    count = 0
    for rule in rules:
        if not _array_matches(first, rule):
            break
        count += 1
    return count


def _optimize(rules: list[Rule]) -> list[Rule]:
    """
    Merge rules by common prefix, then by array (Perl ``optimize``).

    Two passes: pull a shared leading match into a block, then combine rules
    that differ only in one option's value into a single array-valued rule.
    Recurses on each extracted block to find deeper structure.
    """
    # A deque makes consuming from the front O(1) (list.pop(0) is O(n),
    # quadratic over a large save file); the helpers only iterate it.
    work = deque(rules)
    result: list[Rule] = []

    # Pass 1: factor a common leading match into a block.
    while work:
        rule = work.popleft()
        if rule.match:
            count = _prefix_match_count(rule, work)
            if count > 0:
                match = rule.match[0]
                matching = [rule]
                matching.extend(work.popleft() for _ in range(count))
                for member in matching:
                    member.match.pop(0)
                block = _optimize(matching)
                if len(block) == 1:
                    rule = block[0]
                    rule.match.insert(0, match)
                    result.append(rule)
                else:
                    result.append(Rule(match=[match], block=block))
            else:
                result.append(rule)
        else:
            result.append(rule)

    # Pass 2: combine rules differing only in one option into an array.
    work = deque(result)
    result = []
    while work:
        rule = work.popleft()
        count = _array_match_count(rule, work)
        if count > 0:
            matching = [rule]
            matching.extend(work.popleft() for _ in range(count))
            params: list[Value] = []
            for member in matching:
                value = member.match[0].value
                if isinstance(value, list):
                    params.extend(value)
                else:
                    params.append(value)
            rule.match[0].value = params
        result.append(rule)

    return result


class Importer:
    """
    Stateful translator from ``iptables-save`` lines to ferm syntax.

    Holds the emitter indent and the current domain/table/chain plus the
    accumulated rules and recorded chain policies, mirroring ``import-ferm``'s
    package globals.  Output is written to the injected stream.
    """

    def __init__(self, out: TextIO, domain: str = "ip") -> None:
        """Bind the output stream and the initial target domain."""
        self.out = out
        self.indent: int = 0
        self.table: str | None = None
        self.chain: str | None = None
        self.domain: str | None = None
        self.next_domain: str = domain
        self.rules: list[Rule] = []
        self.policies: dict[str, str] = {}
        self.lineno: int = 0

    # --- emitters ----------------------------------------------------

    def write_line(self, *tokens: str) -> None:
        """Write one indented line of tokens (Perl ``write_line``, ``:90``)."""
        toks = list(tokens)
        comma = ""
        if toks and toks[-1] == ";":
            comma = toks.pop()
        if toks and toks[0].startswith("}"):
            self.indent -= 4
        self.out.write(" " * self.indent + " ".join(toks) + comma + "\n")
        if toks and toks[-1].endswith("{"):
            self.indent += 4

    def _flush_option(self, line: list[str], key: str, value: Value) -> None:
        """
        Append one option to a line (Perl ``flush_option``, ``:243``).

        A ``pre_negated`` value writes ``!`` before the key, a ``negated``
        value after it; ``params`` expands to several arguments.
        """
        if isinstance(value, PreNegated):
            line.append("!")
            value = value.value
        line.append(key)
        if isinstance(value, Negated):
            line.append("!")
            value = value.value
        if isinstance(value, Params):
            line.extend(format_array(param) for param in value.values)
        elif value is not None:
            line.append(format_array(value))

    def flush(self, rules: list[Rule] | None = None) -> None:
        """Optimize and emit a list of rules (Perl ``flush``, ``:267``)."""
        source = self.rules if rules is None else rules
        for rule in _optimize(source):
            line: list[str] = []
            for entry in rule.match:
                self._flush_option(line, entry.name, entry.value)

            if rule.jump is not None:
                if is_netfilter_core_target(
                    rule.jump
                ) or is_netfilter_module_target(TARGET_DEFS, "ip", rule.jump):
                    line.append(rule.jump)
                else:
                    self._flush_option(line, "jump", rule.jump)
            elif rule.goto is not None:
                self._flush_option(line, "goto", rule.goto)
            elif rule.block is None:
                line.append("NOP")

            if rule.target is not None:
                for entry in rule.target:
                    self._flush_option(line, entry.name, entry.value)

            if rule.block is not None:
                self.write_line(*line, "{")
                self.flush(rule.block)
                self.write_line("}")
            else:
                self.write_line(*line, ";")
        self.rules = []

    def _flush_policies(self) -> None:
        """
        Emit leftover chain policies (Perl's ``each %policies`` loop).

        Order is irrelevant -- Perl iterates a randomized hash and the golden
        sorter canonicalizes the output -- so a sorted walk keeps it stable.
        """
        for chain in sorted(self.policies):
            self.write_line(
                "chain", chain, "policy", self.policies[chain], ";"
            )
        self.policies = {}

    def _flush_domain(self) -> None:
        """Flush rules and close open chain/table/domain (Perl ``:314``)."""
        self.flush()
        if self.chain is not None:
            self.write_line("}")
        if self.table is not None:
            self.write_line("}")
        if self.domain is not None:
            self.write_line("}")
        self.chain = None
        self.table = None
        self.domain = None

    # --- parsing -----------------------------------------------------

    def _die(self) -> FermError:
        """Build the exception for a Perl bare ``die`` on malformed input."""
        return FermError(f"import-ferm: parse error in line {self.lineno}")

    def _warn(self, message: str) -> None:
        """Report a non-fatal problem to stderr (Perl ``print STDERR``)."""
        sys.stderr.write(f"warning: {message}\n")

    def _fetch_token(self, option: str, tokens: list[str]) -> str:
        """Consume one argument token (Perl ``fetch_token``, ``:334``)."""
        if not tokens:
            raise FermError(
                f"not enough arguments for option '{option}' "
                f"in line {self.lineno}"
            )
        return tokens.pop(0)

    @staticmethod
    def _fetch_negated(tokens: list[str]) -> bool:
        """Consume a leading ``!`` if present (Perl ``fetch_negated``)."""
        if tokens and tokens[0] == "!":
            tokens.pop(0)
            return True
        return False

    @staticmethod
    def _merge_keywords(rule: Rule, keywords: dict[str, Keyword]) -> None:
        """Copy keyword defs into a rule (import-ferm's ``merge_keywords``)."""
        for name, keyword in keywords.items():
            rule.keywords[name] = keyword

    @staticmethod
    def _add_port_keywords(rule: Rule) -> None:
        """Add ``sport``/``dport`` for a ported protocol (Perl ``:420``)."""
        rule.keywords["sport"] = Keyword(name="sport", params=1, negation=True)
        rule.keywords["dport"] = Keyword(name="dport", params=1, negation=True)

    def _parse_def_option(
        self,
        option: str,
        params: int | str | ParamFunction | None,
        pre_negation: bool,
        negated: bool,
        tokens: list[str],
    ) -> Value:
        """
        Parse an option's argument(s) (Perl ``parse_def_option``, ``:353``).

        ``params`` selects the shape: ``None`` (flag), a coderef (comma list),
        ``"m"`` (a ``multi``), a letter code (``s`` scalar / ``c`` comma list),
        ``1`` (one token), or N (a ``multi`` of N tokens).  A negated value is
        wrapped ``pre_negated`` or ``negated`` per the keyword's flag.
        """
        if self._fetch_negated(tokens):
            negated = True

        value: Value
        if params is None:
            value = None
        elif isinstance(params, ParamFunction):
            # XXX assumed to be ipt_multiport: a comma-separated list.
            csv: list[Value] = []
            csv.extend(self._fetch_token(option, tokens).split(","))
            value = csv
        elif isinstance(params, str):
            if params == "m":
                value = Multi([self._fetch_token(option, tokens)])
            else:
                if len(tokens) < len(params):
                    raise self._die()
                parts: list[Value] = []
                for code in params:
                    if code == "s":
                        parts.append(tokens.pop(0))
                    elif code == "c":
                        csv_part: list[Value] = []
                        csv_part.extend(tokens.pop(0).split(","))
                        parts.append(csv_part)
                    else:
                        raise self._die()
                value = parts[0] if len(parts) == 1 else Params(parts)
        elif params == 1:
            value = self._fetch_token(option, tokens)
        else:
            multi_tokens: list[Value] = [
                self._fetch_token(option, tokens) for _ in range(params)
            ]
            value = Multi(multi_tokens)

        if negated:
            value = PreNegated(value) if pre_negation else Negated(value)
        return value

    def parse_option(
        self, rule: Rule, option: str, pre_negated: bool, tokens: list[str]
    ) -> None:
        """
        Parse one iptables option into a rule (Perl ``parse_option``).

        Dispatches on the (alias-resolved) option name: ``protocol`` and
        ``match`` pull in module keywords, a known keyword parses its
        argument, ``jump``/``goto`` set the target.  Raises if a non-negatable
        option was negated.
        """
        cur = rule.cur
        if cur is None:
            raise self._die()

        option = _ALIASES.get(option, option)
        if option == "dports":
            option = "destination-ports"
        elif option == "sports":
            option = "source-ports"

        if option == "protocol":
            value = self._parse_def_option(
                option, 1, False, pre_negated, tokens
            )
            rule.proto = value
            cur.append(MatchEntry("protocol", value))
            if isinstance(value, str):
                module = netfilter_canonical_protocol(value)
                proto_def = PROTO_DEFS.get("ip", {}).get(module)
                if proto_def is not None:
                    self._merge_keywords(rule, proto_def.keywords)
                if _PORTED_PROTOCOLS.fullmatch(value):
                    self._add_port_keywords(rule)
            pre_negated = False
        elif option == "match":
            if not tokens:
                raise self._die()
            param = tokens.pop(0)
            rule.mod[param] = 1
            proto = rule.proto
            # We don't need a ``mod`` entry when the protocol already named
            # this module (or the ipv6-icmp/icmp6 spelling).
            covered = isinstance(proto, str) and (
                proto == param
                or (proto in ("ipv6-icmp", "icmpv6") and param == "icmp6")
            )
            if not covered:
                cur.append(MatchEntry("mod", param))
            module = "icmpv6" if param == "icmp6" else param
            match_def = MATCH_DEFS.get("ip", {}).get(module)
            if match_def is not None:
                self._merge_keywords(rule, match_def.keywords)
            else:
                proto_def = PROTO_DEFS.get("ip", {}).get(module)
                if proto_def is not None:
                    self._merge_keywords(rule, proto_def.keywords)
            if _PORTED_PROTOCOLS.fullmatch(param):
                self._add_port_keywords(rule)
        elif option in rule.keywords:
            keyword = rule.keywords[option]
            value = self._parse_def_option(
                option,
                keyword.params,
                keyword.pre_negation,
                pre_negated,
                tokens,
            )
            last = cur[-1] if cur else None
            if (
                isinstance(value, Multi)
                and last is not None
                and last.name == option
                and isinstance(last.value, Multi)
            ):
                # Merge consecutive ``--u32`` options into one ferm array.
                last.value.values.extend(value.values)
                return
            pre_negated = False
            cur.append(MatchEntry(keyword.ferm_name or keyword.name, value))
        elif option == "jump":
            if not tokens:
                raise self._die()
            target = tokens.pop(0)
            rule.jump = target
            rule.target = []
            rule.cur = rule.target
            rule.match_keywords = rule.keywords
            rule.keywords = {}
            target_def = TARGET_DEFS.get("ip", {}).get(target)
            if target_def is not None:
                self._merge_keywords(rule, target_def.keywords)
        elif option == "goto":
            if not tokens:
                raise self._die()
            rule.goto = tokens.pop(0)
        else:
            raise FermError(
                f"option '{option}' in line {self.lineno} not understood"
            )

        if pre_negated:
            raise FermError(
                f"option '{option}' in line {self.lineno} cannot be negated"
            )

    # --- main input loop ---------------------------------------------

    def run(self, lines: Iterable[str]) -> None:
        """Translate every input line, emitting the ferm config (``:510``)."""
        self.out.write("# ferm rules generated by import-ferm\n")
        self.out.write("# http://ferm.foo-projects.org/\n")
        for raw in lines:
            self.lineno += 1
            self._process_line(raw.rstrip("\r\n"))
        if self.policies:
            self._flush_policies()
        if self.domain is not None:
            self._flush_domain()
        if self.indent != 0:
            raise FermError("internal error: unbalanced indentation")

    def _process_line(self, line: str) -> None:
        """Dispatch one save-file line to its handler (the ``while`` body)."""
        if re.fullmatch(r"(?:#.*)?", line):
            match = re.match(r"#.*\b(ip|ip6)tables-save\b", line)
            if match is not None:
                self.next_domain = match.group(1)
            return

        match = re.fullmatch(r"\*(\w+)", line)
        if match is not None:
            self._handle_table(match.group(1))
            return

        match = re.match(r":(\S+)\s+-\s+", line)
        if match is not None:
            if self.table is None:
                raise self._die()
            self.write_line(f"chain {match.group(1)};")
            return

        match = re.match(r":(\S+)\s+(\w+)\s+", line)
        if match is not None:
            if self.table is None:
                raise self._die()
            self.policies[match.group(1)] = match.group(2)
            return

        match = re.match(r"-A (\S+)\s+", line)
        if match is not None:
            self._handle_rule(match.group(1), line[match.end() :])
            return

        if re.match(r"COMMIT", line):
            self.flush()
            if self.chain is not None:
                self.write_line("}")
                self.chain = None
            return

        self._warn(f"line {self.lineno} was not understood, ignoring it")

    def _handle_table(self, name: str) -> None:
        """Open a table block, switching domain if needed (Perl ``:522``)."""
        if self.policies:
            self._flush_policies()
        if not (self.domain is not None and self.domain == self.next_domain):
            self._flush_domain()
            domain = self.next_domain
            self.domain = domain
            self.write_line("domain", domain, "{")
        if self.table is not None:
            self.write_line("}")
        self.table = name
        self.write_line("table", name, "{")

    def _handle_rule(self, chain: str, rest: str) -> None:
        """Parse an ``-A`` rule, opening its chain block (Perl ``:549``)."""
        if self.chain is None:
            self.flush()
            self.chain = chain
            self.write_line("chain", chain, "{")
        elif chain != self.chain:
            self.flush()
            self.write_line("}")
            self.chain = chain
            self.write_line("chain", chain, "{")

        if chain in self.policies:
            self.write_line("policy", self.policies[chain], ";")
            del self.policies[chain]

        rule = Rule()
        base = MATCH_DEFS.get("ip", {}).get("")
        if base is not None:
            self._merge_keywords(rule, base.keywords)
        rule.cur = rule.match

        tokens = _tokenize(rest)
        while tokens:
            token = tokens.pop(0)
            option = _match_option(token)
            if option is not None:
                self.parse_option(rule, option, False, tokens)
            elif token == "!":
                if not tokens:
                    raise self._die()
                token = tokens.pop(0)
                option = _match_option(token)
                if option is None:
                    raise FermError(f"option expected in line {self.lineno}")
                self.parse_option(rule, option, True, tokens)
            else:
                self._warn(f"unknown token '{token}' in line {self.lineno}")

        rule.cur = None
        self.rules.append(rule)


def _gather_input(files: list[str]) -> list[str]:
    """
    Read input lines from the named files, or stdin when none.

    Perl reads the inputs through the ``<>`` operator: an unopenable
    file yields a ``Can't open ...`` warning on stderr and the run
    continues with the remaining files.
    """
    if not files:
        return list(sys.stdin)
    lines: list[str] = []
    for name in files:
        try:
            text = Path(name).read_text(encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"Can't open {name}: {exc.strerror or exc}\n")
            continue
        lines.extend(text.splitlines())
    return lines


def _iptables_save_lines() -> list[str]:
    """Run ``iptables-save`` and return its output lines (Perl ``:502``)."""
    try:
        proc = subprocess.run(
            ["iptables-save"], capture_output=True, text=True, check=True
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise FermError(f"Failed to run iptables-save: {exc}") from exc
    return proc.stdout.splitlines()


def main(argv: list[str] | None = None) -> int:
    """Run the import-ferm CLI (the script's top-level, ``:495``)."""
    args = list(sys.argv[1:] if argv is None else argv)
    if "-h" in args or "--help" in args:
        sys.stdout.write(_USAGE)
        return 0

    domain = os.environ.get("FERM_DOMAIN") or "ip"
    importer = Importer(sys.stdout, domain)
    try:
        if not args and sys.stdin.isatty():
            lines: Iterable[str] = _iptables_save_lines()
        elif any(re.match(r"-.", arg) for arg in args):
            sys.stderr.write(_USAGE)
            return 1
        else:
            lines = _gather_input(args)
        importer.run(lines)
    except FermError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
