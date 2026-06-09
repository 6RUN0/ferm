"""Error/warning reporting and the exit-code contract.

Faithful port of ``error`` and ``warning`` from ``reference/src/ferm``
(``:834-879``).  ``die`` maps to :class:`FermError`; the top-level CLI
handler turns an uncaught :class:`FermError` into ``exit(1)`` after
printing its message, exactly as Perl's uncaught ``die`` does.

Perl reaches the parser state through the global ``$script``.  To keep
this module a leaf of the dependency graph (it imports nothing from
``pyferm``), the parser registers its current script via
:func:`set_error_context`; ``error``/``warning`` read it from there.
"""

from __future__ import annotations

import sys
from typing import NoReturn, Protocol


class ErrorContext(Protocol):
    """The slice of the parser's ``$script`` the reporters need.

    ``past_tokens`` is a list of token lists (one list per consumed
    statement), mirroring ``$script->{past_tokens}``; ``error`` flattens
    it to reconstruct an indented view of the offending code.
    """

    filename: str
    line: int
    past_tokens: list[list[str]]


class FermError(Exception):
    """A fatal ferm error, i.e. the Python form of Perl's ``die``.

    The carried message is the already-joined ``die`` argument list,
    without the trailing newline (the handler adds it).
    """


_context: ErrorContext | None = None


def set_error_context(context: ErrorContext | None) -> None:
    """Register the current script for :func:`error`/:func:`warning`.

    The parser calls this once with its script object and then mutates
    that object's ``line``/``past_tokens`` in place, mirroring Perl's
    single global ``$script``.
    """
    global _context
    _context = context


def _render_context(context: ErrorContext) -> str:
    """Reconstruct the indented code view ``error`` prints to stderr.

    A line-for-line port of the ``error`` body (``:837-867``): it walks
    the flattened past tokens, tracking bracket/brace depth to re-indent,
    and keeps only the trailing few lines around the error location.
    """
    words: list[str] = [w for group in context.past_tokens for w in group]
    lines: list[str] = []
    tabs = 0
    cur = 0

    def put(idx: int, value: str) -> None:
        while len(lines) <= idx:
            lines.append("")
        lines[idx] = value

    for w, word in enumerate(words):
        # Perl reads $words[$w+1] past the end as undef (always != "{");
        # $words[$w-1] at w==0 wraps to the last element, which Python's
        # negative indexing reproduces exactly.
        nxt = words[w + 1] if w + 1 < len(words) else None
        prev = words[w - 1]

        if word == ")":
            cur += 1
            put(cur, "    " * (tabs - 1))
            tabs -= 1
        if word == "(":
            put(cur + 1, "    " * tabs)
            cur += 1
            tabs += 1
        if word == "}":
            cur += 1
            put(cur, "    " * (tabs - 1))
            tabs -= 1
        if word == "{":
            put(cur + 1, "    " * tabs)
            cur += 1
            tabs += 1
        if cur > len(lines) - 1:
            put(cur, "")
        lines[cur] += word + " "
        if word == "(":
            cur += 1
            put(cur, "    " * tabs)
        if word == ")" and nxt != "{":
            cur += 1
            put(cur, "    " * tabs)
        if word == "{":
            cur += 1
            put(cur, "    " * tabs)
        if word == "}" and nxt != "}":
            cur += 1
            put(cur, "    " * tabs)
        if word == ";" and nxt != "}":
            cur += 1
            put(cur, "    " * tabs)
        if prev == "option":
            cur += 1
            put(cur, "    " * tabs)

    start = len(lines) - 5
    if start < 0:
        start = 0
    return "\n".join(lines[start:])


def error(*message: str) -> NoReturn:
    """Report a fatal parser error and raise :class:`FermError`.

    Mirrors Perl ``error``: prints the located, re-indented code context
    to stderr, then raises with the joined message.  Like Perl ``die``,
    this never returns.
    """
    if _context is not None:
        sys.stderr.write(
            f"Error in {_context.filename} line {_context.line}:\n"
        )
        sys.stderr.write(_render_context(_context))
        sys.stderr.write("<--\n")
    raise FermError(" ".join(message))


def warning(message: str) -> None:
    """Print a warning about input-file code to stderr (Perl ``warning``)."""
    if _context is not None:
        sys.stderr.write(
            f"Warning in {_context.filename} line {_context.line}: {message}\n"
        )
    else:  # pragma: no cover - parser always sets the context first
        sys.stderr.write(f"Warning: {message}\n")
