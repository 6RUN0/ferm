"""
Canonical token-scan primitives over Parser.parse_to_block spans.

Shared by pyferm.analysis (the --lint analyzers, which re-export these
names) and pyferm.graph (the --graph builder). Pure structural scans:
no eval, no I/O. Moved here verbatim from analysis.py so both consumers
share one definition; analysis.py re-exports for backward compatibility.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from .tree import Block

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from .tree import Node

#: Public token-scan surface, re-exported by pyferm.analysis and consumed
#: by pyferm.graph. Listing the names marks them as intentional exports of
#: this otherwise-underscored module (keeps ruff/mypy/pyright quiet about
#: cross-module use of the leading-underscore primitives).
__all__ = [
    "_CHAIN_VALUE_BOUNDARY",
    "_INTERPOLATION_RE",
    "_JUMP_KW",
    "_NAME_RE",
    "_QUOTE_PAIR_MIN_LEN",
    "_SUBCHAIN_KW",
    "_child_blocks",
    "_declared_chains",
    "_index_of",
    "_is_quoted",
    "_is_quoted_interpolation",
    "_iter_func_refs",
    "_iter_var_refs",
    "_jump_targets",
    "_str_tokens",
    "_subchain_names",
    "_subchain_pairs",
    "_unquote",
]

_NAME_RE: Final[re.Pattern[str]] = re.compile(r"\w+")

#: The oracle's double-quote interpolation form: "$" immediately
#: followed by word chars. There is no ${name} form in ferm.
_INTERPOLATION_RE: Final[re.Pattern[str]] = re.compile(r"\$(\w+)")


def _index_of(span: Sequence[object], token: str) -> int | None:
    """Return the index of the first ``token`` in a span, or None if absent."""
    for i, tok in enumerate(span):
        if tok == token:
            return i
    return None


def _iter_var_refs(span: Sequence[object]) -> Iterator[str]:
    """
    Yield the $-variable names ($name) mentioned in a raw token span.

    The tokenizer lexes "$" as its own single-char token, so a bare
    variable reference is ALWAYS the token pair ("$", name) -- never a
    glued "$name". A double-quoted token is additionally scanned for
    the oracle's interpolation form ("prefix $x" mentions $x); a
    single-quoted token stays literal (ferm never interpolates it) and
    the ${name} spelling does not exist in ferm (the oracle passes it
    through verbatim), so neither counts as a use. Line sentinels and
    other non-str tokens are skipped.
    """
    for i, tok in enumerate(span):
        if tok == "$" and i + 1 < len(span):
            nxt = span[i + 1]
            if isinstance(nxt, str) and _NAME_RE.fullmatch(nxt):
                yield "$" + nxt
        elif isinstance(tok, str) and _is_quoted(tok) and tok[0] == '"':
            for match in _INTERPOLATION_RE.finditer(_unquote(tok)):
                yield "$" + match.group(1)


def _iter_func_refs(span: Sequence[object]) -> Iterator[str]:
    """
    Yield the &-function names (&name) mentioned in a raw token span.

    Like "$", the tokenizer lexes "&" as its own token, so a function
    reference is always the pair ("&", name). Callers must exclude a
    definition's own head, or the name would count as a self-mention.
    """
    for i, tok in enumerate(span):
        if tok == "&" and i + 1 < len(span):
            nxt = span[i + 1]
            if isinstance(nxt, str) and _NAME_RE.fullmatch(nxt):
                yield "&" + nxt


def _child_blocks(node: Node) -> Iterator[Block]:
    """
    Yield every structured sub-Block a node carries.

    Block bodies AND both @if branch bodies, so analysis descends into ALL
    nesting -- including untaken @if branches, the key capability the walk
    tree lacks.
    """
    for attr in ("body", "then_body", "else_body"):
        child = getattr(node, attr, None)
        if isinstance(child, Block):
            yield child


#: Subchain declaration keywords -- each names a chain.
_SUBCHAIN_KW: Final[frozenset[str]] = frozenset(
    {"@subchain", "subchain", "@gotosubchain"}
)

#: Rule keywords that create an explicit jump edge to a chain. realgoto
#: is the deprecated alias of goto: the eval path remaps it, but the
#: structural tree keeps the original token.
_JUMP_KW: Final[tuple[str, ...]] = ("jump", "goto", "realgoto")

#: A quoted token needs at least an opening and a closing quote.
_QUOTE_PAIR_MIN_LEN: Final[int] = 2

#: Structural boundaries that stand where a ``chain`` name would be, i.e. a
#: bare ``chain`` with no name (malformed input). NOT a name-run terminator:
#: ``chain`` takes exactly ONE value (a single name or a parenthesised array),
#: so a name colliding with a header keyword (``chain table {}``) is still the
#: chain name, not a stop word.
_CHAIN_VALUE_BOUNDARY: Final[frozenset[str]] = frozenset({"{", "}", ";"})


def _str_tokens(span: Sequence[object]) -> Iterator[str]:
    """Yield only the plain string tokens (skip Line sentinels / non-str)."""
    for tok in span:
        if isinstance(tok, str):
            yield tok


def _is_quoted(tok: str) -> bool:
    """Return whether a token is wrapped in a matching quote pair."""
    return (
        len(tok) >= _QUOTE_PAIR_MIN_LEN
        and tok[0] in ("'", '"')
        and tok[-1] == tok[0]
    )


def _unquote(tok: str) -> str:
    """Strip a matching pair of surrounding quotes from a token."""
    return tok[1:-1] if _is_quoted(tok) else tok


def _is_quoted_interpolation(tok: str) -> bool:
    """
    Return whether a double-quoted token is an interpolation, not a literal.

    The oracle interpolates ``"$x"``/``"@arr"`` inside double quotes, so a
    harvester that unquotes such a token verbatim would leak the
    variable/array reference as a literal chain/jump name (mirroring the
    bare ``$var`` skip, which a quoted form otherwise evades). A
    single-quoted token never interpolates (ferm passes it through
    literally) and chain names are restricted to ``[A-Za-z0-9_.+-]``, so
    the ``@`` check can never exclude a legitimate literal name.
    """
    return (
        _is_quoted(tok) and tok[0] == '"' and _unquote(tok)[:1] in ("$", "@")
    )


def _declared_chains(span: Sequence[object]) -> Iterator[str]:
    """
    Yield every chain name a token span declares.

    Scans for an EMBEDDED ``chain <name>...`` sub-sequence -- not just a
    leading token -- so both the nested ``chain FOO {}`` and the dominant
    one-line ``table filter chain FOO {}`` forms (one collapsed HeaderNode)
    are harvested, plus a ``chain (A B)`` array and a ``... chain X policy``
    header. ``chain`` takes exactly ONE value (a single name or a
    parenthesised array), matching the oracle's getvalues -- so a name
    colliding with a header keyword is still harvested. Also yields a quoted
    ``@subchain "NAME"`` declaration. $var names are skipped (literal-only).
    """
    yield from _chain_decls(list(_str_tokens(span)))


def _chain_decls(toks: Sequence[str]) -> Iterator[str]:
    """Scan pre-filtered string tokens (:func:`_declared_chains` core)."""
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "chain":
            i += 1
            if i < len(toks) and toks[i] == "(":
                # array form ``chain (A B ...)``: collect names up to ')'.
                # A ``$var`` member lexes as the pair ("$", name); consume
                # BOTH so the bare name is not leaked as a literal chain.
                i += 1
                while i < len(toks) and toks[i] != ")":
                    if toks[i] == "$":
                        i += 1
                        if i < len(toks) and _NAME_RE.fullmatch(toks[i]):
                            i += 1
                        continue
                    if toks[i].startswith("$"):
                        i += 1  # defensive: a glued "$name" token
                        continue
                    if not _is_quoted_interpolation(toks[i]):
                        yield _unquote(toks[i])
                    i += 1
                if i < len(toks) and toks[i] == ")":
                    i += 1
            elif i < len(toks) and toks[i] not in _CHAIN_VALUE_BOUNDARY:
                # bare form: exactly ONE name, even one spelled like a
                # keyword. A ``$var`` name is the pair ("$", name); consume
                # both and yield nothing (non-literal, eval-free contract).
                if toks[i] == "$":
                    i += 1
                    if i < len(toks) and _NAME_RE.fullmatch(toks[i]):
                        i += 1
                elif not toks[i].startswith("$"):
                    if not _is_quoted_interpolation(toks[i]):
                        yield _unquote(toks[i])
                    i += 1
                else:
                    i += 1  # defensive: a glued "$name" token
            continue
        if tok in _SUBCHAIN_KW:
            i += 1
            if (
                i < len(toks)
                and _is_quoted(toks[i])
                and not _is_quoted_interpolation(toks[i])
            ):
                yield _unquote(toks[i])
            continue
        i += 1


def _subchain_names(span: Sequence[object]) -> Iterator[str]:
    """
    Yield the chain names a quoted @subchain declares in a span.

    Unlike _declared_chains (declaration sites of ANY kind), this
    yields ONLY subchain names: an @subchain carries an implicit jump
    from its enclosing rule, so these names are reached without any
    literal jump/goto/realgoto token.
    """
    yield from _subchain_decls(list(_str_tokens(span)))


def _subchain_decls(toks: Sequence[str]) -> Iterator[str]:
    """Scan pre-filtered string tokens (:func:`_subchain_names` core)."""
    for _kw, name in _subchain_pairs(toks):
        yield name


def _subchain_pairs(toks: Sequence[str]) -> Iterator[tuple[str, str]]:
    """
    Yield (keyword, literal name) per quoted @subchain/@gotosubchain pair.

    The shared core of :func:`_subchain_decls` and the graph's edge scan
    (which additionally maps the keyword to an edge kind, mirroring
    :func:`_jump_pairs`/:func:`_jump_targets`): an interpolated
    ``"$x"``/``"@arr"`` quoted name is skipped, byte-identically for both.
    """
    for i, tok in enumerate(toks):
        if tok in _SUBCHAIN_KW and i + 1 < len(toks):
            candidate = toks[i + 1]
            if _is_quoted(candidate) and not _is_quoted_interpolation(
                candidate
            ):
                yield tok, _unquote(candidate)


def _jump_targets(span: Sequence[object]) -> Iterator[str]:
    """Yield literal jump/goto/realgoto targets in a span ($var skipped)."""
    for _kw, target in _jump_pairs(list(_str_tokens(span))):
        yield target


def _jump_pairs(toks: Sequence[str]) -> Iterator[tuple[str, str]]:
    """
    Yield (keyword, literal target) per jump/goto/realgoto token pair.

    The shared core of :func:`_jump_targets` and the graph's edge scan
    (which additionally maps the keyword to an edge kind); $var targets and
    interpolated quoted targets (``"$x"``/``"@arr"``) are skipped, and
    quotes are stripped from a literal target, byte-identically for both.
    """
    for i, tok in enumerate(toks):
        if tok in _JUMP_KW and i + 1 < len(toks):
            target = toks[i + 1]
            if not target.startswith("$") and not _is_quoted_interpolation(
                target
            ):
                yield tok, _unquote(target)
