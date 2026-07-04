"""
Canonical token-scan primitives over Parser.parse_to_block spans.

Shared by pyferm.analysis (the --lint analyzers, which re-export these
names) and pyferm.graph (the --graph builder). Pure structural scans:
no eval, no I/O. Moved here verbatim from analysis.py so both consumers
share one definition; analysis.py re-exports for backward compatibility.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

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
    "_iter_func_refs",
    "_iter_var_refs",
    "_jump_targets",
    "_str_tokens",
    "_subchain_names",
    "_unquote",
]

_NAME_RE = re.compile(r"\w+")

#: The oracle's double-quote interpolation form: "$" immediately
#: followed by word chars. There is no ${name} form in ferm.
_INTERPOLATION_RE = re.compile(r"\$(\w+)")


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
_SUBCHAIN_KW = frozenset({"@subchain", "subchain", "@gotosubchain"})

#: Rule keywords that create an explicit jump edge to a chain. realgoto
#: is the deprecated alias of goto: the eval path remaps it, but the
#: structural tree keeps the original token.
_JUMP_KW = ("jump", "goto", "realgoto")

#: A quoted token needs at least an opening and a closing quote.
_QUOTE_PAIR_MIN_LEN = 2

#: Structural boundaries that stand where a ``chain`` name would be, i.e. a
#: bare ``chain`` with no name (malformed input). NOT a name-run terminator:
#: ``chain`` takes exactly ONE value (a single name or a parenthesised array),
#: so a name colliding with a header keyword (``chain table {}``) is still the
#: chain name, not a stop word.
_CHAIN_VALUE_BOUNDARY = frozenset({"{", "}", ";"})


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
    toks = list(_str_tokens(span))
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "chain":
            i += 1
            if i < len(toks) and toks[i] == "(":
                # array form ``chain (A B ...)``: collect names up to ')'.
                i += 1
                while i < len(toks) and toks[i] != ")":
                    name = toks[i]
                    i += 1
                    if not name.startswith("$"):
                        yield _unquote(name)
                if i < len(toks) and toks[i] == ")":
                    i += 1
            elif i < len(toks) and toks[i] not in _CHAIN_VALUE_BOUNDARY:
                # bare form: exactly ONE name, even one spelled like a keyword.
                name = toks[i]
                i += 1
                if not name.startswith("$"):
                    yield _unquote(name)
            continue
        if tok in _SUBCHAIN_KW:
            i += 1
            if i < len(toks) and _is_quoted(toks[i]):
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
    toks = list(_str_tokens(span))
    for i, tok in enumerate(toks):
        if tok in _SUBCHAIN_KW and i + 1 < len(toks):
            candidate = toks[i + 1]
            if _is_quoted(candidate):
                yield _unquote(candidate)


def _jump_targets(span: Sequence[object]) -> Iterator[str]:
    """Yield literal jump/goto/realgoto targets in a span ($var skipped)."""
    toks = list(_str_tokens(span))
    for i, tok in enumerate(toks):
        if tok in _JUMP_KW and i + 1 < len(toks):
            target = toks[i + 1]
            if not target.startswith("$"):
                yield _unquote(target)
