"""Shared parser construction for the parser-driving unit tests."""

from __future__ import annotations

import io

from pyferm.config import Options
from pyferm.functions import Evaluator
from pyferm.parser import Parser
from pyferm.scope import Frame, Scope
from pyferm.tokenizer import Script, Tokenizer


def build_parser(
    source: str, *, filename: str = "<test>", options: Options | None = None
) -> Parser:
    """Build a parser over *source* without running :meth:`Parser.enter`.

    Returns the parser primed with a fresh tokenizer, scope, and evaluator so
    the caller can drive ``enter`` itself (e.g. to assert on a parse abort).
    """
    options = options if options is not None else Options(test=True)
    script = Script(filename=filename, handle=io.StringIO(source))
    tokenizer = Tokenizer(script)
    scope = Scope()
    scope.push(Frame())
    evaluator = Evaluator(tokenizer, scope)
    return Parser(evaluator, {}, options)


def parse_source(source: str, *, options: Options | None = None) -> Parser:
    """Parse *source* through :meth:`Parser.enter` and return the parser."""
    parser = build_parser(source, options=options)
    parser.enter(0, None)
    return parser
