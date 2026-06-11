"""
Tokenizer: ferm DSL lexing and the lazy token stream.

Faithful port of the lexing layer of ``reference/src/ferm`` (``:992-1218``).
ferm lexes one input line at a time: :meth:`Tokenizer.prepare_tokens`
reads a line, prepends a :class:`Line` sentinel that carries the line
number, and tokenizes the rest.  Consuming the sentinel updates
``script.line``, so positions are tracked as tokens are pulled, not
counted ahead.

The parser drives a single :class:`Tokenizer` and swaps its
:attr:`~Tokenizer.script` to descend into included files (each
:class:`Script` keeps a ``parent`` link), mirroring Perl's global
``$script``.  The token queue can hold strings, :class:`Line` sentinels
and -- after variable expansion injects them -- deferred values, so the
:data:`Token` type covers all three.
"""

from __future__ import annotations

import re
import subprocess  # pipe includes: '@include "program|"' reads its stdout
import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING, TypeAlias

from pyferm.errors import FermError, error, set_error_context
from pyferm.streams import reconfigure_latin1

if TYPE_CHECKING:
    from collections.abc import Callable

    from pyferm.values import Deferred


@dataclass
class Line:
    """A line-number sentinel inserted into the token stream (``:1008``)."""

    number: int


#: Anything that can sit in the token queue.
Token: TypeAlias = "str | Line | Deferred"


@dataclass
class Script:
    """
    One open ferm input file and its lazy token state (Perl ``$script``).

    Satisfies :class:`pyferm.errors.ErrorContext`, so the tokenizer can
    register it for located error messages.
    """

    filename: str
    handle: IO[str] | None
    line: int = 0
    past_tokens: list[list[object]] = field(default_factory=list[list[object]])
    #: A deque, not a list: Perl's shift/unshift are O(1) and the parser
    #: replays whole captured blocks through the queue (``_replay_array``/
    #: ``_call_function``), where ``list.pop(0)`` would be quadratic.
    tokens: deque[Token] = field(default_factory=deque[Token])
    parent: Script | None = None
    base_level: int | None = None
    #: The child of a pipe include (``'cmd|'``); the parser checks its exit
    #: status on close, as Perl's ``close`` does for a piped handle.
    process: subprocess.Popen[str] | None = None

    def close(self) -> None:
        """
        Release the input: close the handle, reap a pipe child.

        Perl closes filehandles implicitly when ``$script`` goes out of
        scope (and ``close`` on a piped handle waits for the child); this
        port closes explicitly so no error path leaks an open file --
        the test suite runs with ResourceWarning as an error.  Idempotent;
        the pipe child's exit status stays readable on :attr:`process`.
        """
        if self.handle is not None and self.handle is not sys.stdin:
            self.handle.close()
        self.handle = None
        if self.process is not None:
            self.process.wait()


# The lexer pattern, copied verbatim from Perl (``:997``): quoted strings,
# single special characters, word runs, ``@function`` names and ``#``.
_TOKEN_RE = re.compile(
    r"""(".*?"|'.*?'|`.*?`|[!,=&$%(){};]|[-+\w/.:]+|@\w+|#)"""
)
_NOT_ALLOWED_RE = re.compile(r"[;{}]")


def tokenize_string(string: str) -> list[str]:
    """Split one input line into tokens, stopping at ``#`` (``:992``)."""
    ret: list[str] = []
    for word in _TOKEN_RE.findall(string):
        if word == "#":
            break
        ret.append(word)
    return ret


def make_line_token(line: int) -> Line:
    """Build a line-number sentinel token (``:1008``)."""
    return Line(line)


def open_script(filename: str, parent: Script | None) -> Script:
    """
    Open a ferm (sub)script, rejecting include cycles (``:1066``).

    ``parent`` is the script doing the opening (``None`` for the top-level
    file); its chain is walked to detect circular includes.
    """
    node = parent
    while node is not None:
        if node.filename == filename:
            assert parent is not None
            raise FermError(
                f"Circular reference in {parent.filename} "
                f"line {parent.line}: {filename}"
            )
        node = node.parent

    handle: IO[str]
    process: subprocess.Popen[str] | None = None
    if filename == "-":
        # Only allowed for the command-line argument, not @includes (those
        # are filtered by collect_filenames); label it for error messages.
        handle = sys.stdin
        reconfigure_latin1(handle)
        filename = "<stdin>"
    elif filename.endswith("|"):
        # Perl's two-argument open runs a trailing-pipe filename through
        # the shell and reads its stdout ('@include "program|"').
        try:
            # The shell invocation is the oracle's semantics: the filename
            # comes from the root-owned config, exactly as in Perl.
            process = subprocess.Popen(
                filename[:-1],
                shell=True,
                stdout=subprocess.PIPE,
                encoding="latin-1",
            )
        except OSError as exc:
            raise FermError(
                f"Failed to open {filename}: {exc.strerror}"
            ) from exc
        assert process.stdout is not None
        handle = process.stdout
    else:
        try:
            # The handle is read lazily and closed later by the parser, so
            # a context manager is intentionally not used here.
            handle = Path(filename).open(encoding="latin-1")  # noqa: SIM115
        except OSError as exc:
            raise FermError(
                f"Failed to open {filename}: {exc.strerror}"
            ) from exc

    return Script(
        filename=filename, handle=handle, parent=parent, process=process
    )


class Tokenizer:
    """The lazy token reader over a stack of :class:`Script` files."""

    def __init__(self, script: Script | None) -> None:
        """
        Start lexing ``script`` and register it for error reporting.

        ``None`` builds a script-less tokenizer for evaluating ``--def``
        values: Perl runs those inside ``GetOptions`` while the global
        ``$script`` is still undef, so any built-in that reaches the script
        there aborts the run.
        """
        self._script = script
        set_error_context(script)

    @property
    def script(self) -> Script:
        """The script currently being lexed (Perl's global ``$script``)."""
        script = self._script
        if script is None:
            # the oracle dies dereferencing the undef $script
            raise FermError(
                "script context not available while evaluating --def"
            )
        return script

    @script.setter
    def script(self, value: Script) -> None:
        self._script = value
        set_error_context(value)

    @property
    def script_if_any(self) -> Script | None:
        """The current script, or ``None`` in ``--def`` evaluation."""
        return self._script

    def open_script(self, filename: str) -> Script:
        """Descend into ``filename`` as a sub-script of the current one."""
        self.script = open_script(filename, self._script)
        return self.script

    def prepare_tokens(self) -> bool:
        """
        Fill the queue from the input until it is non-empty (``:1014``).

        Returns ``False`` at end of file (Perl's bare ``return``).
        """
        tokens = self.script.tokens
        while len(tokens) == 0:
            handle = self.script.handle
            if handle is None:
                return False
            line = handle.readline()
            if line == "":
                return False
            tokens.append(make_line_token(self.script.line + 1))
            # the next parser stage eats the line sentinel
            tokens.extend(tokenize_string(line))
        return True

    def handle_special_token(self, token: Token) -> Token | None:
        """
        Act on a non-string queue token (``:1031``).

        A :class:`Line` advances ``script.line`` and is dropped (returns
        ``None``); a deferred value is kept (returned), which stops the
        caller's drain loop.
        """
        if isinstance(token, Line):
            self.script.line = token.number
            return None
        return token

    def handle_special_tokens(self) -> None:
        """Drop leading sentinels; stop at a deferred token (``:1044``)."""
        tokens = self.script.tokens
        while tokens and not isinstance(tokens[0], str):
            if self.handle_special_token(tokens[0]) is None:
                tokens.popleft()
            else:
                break

    def prepare_normal_tokens(self) -> bool:
        """:meth:`prepare_tokens` plus sentinel handling (``:1056``)."""
        tokens = self.script.tokens
        while True:
            self.handle_special_tokens()
            if len(tokens) > 0:
                return True
            if not self.prepare_tokens():
                return False

    def peek_token(self) -> Token | None:
        """Return the next token without consuming it (``:1158``)."""
        if not self.prepare_normal_tokens():
            return None
        return self.script.tokens[0]

    def next_raw_token(self) -> Token | None:
        """Consume the next token, sentinels included (``:1164``)."""
        if not self.prepare_tokens():
            return None
        return self.script.tokens.popleft()

    def next_token(self) -> Token | None:
        """Consume a real token, updating ``past_tokens`` (``:1170``)."""
        if not self.prepare_normal_tokens():
            return None
        token = self.script.tokens.popleft()

        past = self.script.past_tokens
        if past:
            last_group = past[-1]
            prev_token = last_group[-1] if last_group else None
            if prev_token == ";":
                past[-1] = ["{"] if len(past) > 1 else []
            if prev_token == "}":
                past.pop()
                if past:
                    first = past[-1][0] if past[-1] else None
                    past[-1] = ["{"] if first == "{" else []

        if token == "{" or not past:
            past.append([])
        past[-1].append(token)

        return token

    def expect_token(self, expect: str, msg: str | None = None) -> None:
        """Consume a token and require it to equal ``expect`` (``:1196``)."""
        token = self.next_token()
        if token is None or token != expect:
            error(msg or f"'{expect}' expected")

    def require_next_token(
        self, code: Callable[[], Token | None] | None = None
    ) -> Token:
        """
        Consume a token that must exist and not be ``;``/``{``/``}``.

        ``code`` overrides the token source (Perl's ``$code`` argument,
        used to read from an expanded shell-command stream); it defaults
        to :meth:`next_token` (``:1206``).
        """
        token = code() if code is not None else self.next_token()
        if token is None:
            error("unexpected end of file")
        if isinstance(token, str) and _NOT_ALLOWED_RE.fullmatch(token):
            error(f"'{token}' not allowed here")
        return token
