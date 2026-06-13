#!/usr/bin/env python3
"""
Coverage-guided crash fuzzer for the ferm config parser (atheris).

Where the Hypothesis differential fuzzers ask *"does the port agree with
the Perl oracle?"*, this asks the orthogonal question *"is there any input
that makes the port raise an unhandled exception (or hang)?"* -- the
robustness axis, not the fidelity axis.  libFuzzer's coverage feedback
mutates its way into tokenizer/``enter``/scope/deferred branches that a
grammar never reaches by construction.

The parser is driven in-process at the same seam the unit tests use
(:func:`_parse`-style ``Script`` over an in-memory handle), deliberately
*below* the CLI, because three parse-stage constructs reach a shell, the
filesystem or the network and must never fire on fuzz input:

* backticks (`` `cmd` ``) -- :meth:`Evaluator._run_shell` runs
  ``subprocess.run(shell=True)`` directly, *not* through the injected
  ``execute``; the :class:`_SafeEvaluator` subclass stubs it out.
* ``@include "f"`` / ``@include "cmd|"`` -- :func:`tokenizer.open_script`
  opens files and runs pipe commands through the shell; it is monkeypatched
  to raise :class:`FermError`, so the include path stays a clean handled
  error.
* ``@resolve(...)`` -- the resolver provider is left unset, so a lookup
  raises :class:`FermError` (no DNS, no zonefile read).

``@hook`` commands are merely *recorded* by the parser (the CLI runs them
later), and the previous-state capture stays inert because no
``capture_previous`` closure is injected (the ``None`` seam), so both are
harmless here too.

The exception allow-list -- inputs that are *not* a finding -- is just
:class:`FermError`, which covers every located ``error()``/``die`` and
the ``internal error: ...`` marker.  Both recursive readers that descend
the parse tree are now explicitly bounded, so no input should overflow
Python's stack: ``Parser.enter`` refuses past ``MAX_BLOCK_DEPTH`` (the
``too many nested blocks`` diagnostic, sanctioned deviation #6, covering
``{}``/array nesting) and the value reader ``Evaluator.getvalues`` /
``_read_array`` (Perl ``:1416``/``:1422``) refuses past
``MAX_VALUE_DEPTH`` (the ``values nested too deeply`` diagnostic,
sanctioned deviation #7, covering nested ``(``, chained ``!`` and nested
``@`` calls) -- both raising a located ``FermError`` instead of a bare
``RecursionError``.  This closes the Phase-2 entry debt #7 that
previously kept ``RecursionError`` on the allow-list (Perl still dies by
OOM near 200k parens; the port now fails earlier with a diagnostic).  A
``RecursionError`` -- or anything else -- now propagates to atheris as a
crash with a saved reproducer.

Run via ``nox -s crashfuzz``; standalone::

    uv run --group crashfuzz python fuzz/fuzz_config.py \
        fuzz/corpus/config tests/corpus/configs -max_total_time=60
"""

from __future__ import annotations

import contextlib
import io
import sys

import atheris

with atheris.instrument_imports():
    import pyferm.tokenizer as tokenizer_module
    from pyferm.config import Options
    from pyferm.errors import FermError
    from pyferm.functions import Evaluator
    from pyferm.parser import Parser
    from pyferm.resolver import set_resolver_provider
    from pyferm.scope import Frame, Scope
    from pyferm.tokenizer import Script, Tokenizer


class _SafeEvaluator(Evaluator):
    """An :class:`Evaluator` whose backtick operator runs no shell."""

    def _run_shell(self, command: str) -> str:  # noqa: ARG002
        """Return an empty word list instead of executing ``command``."""
        return ""


def _blocked_include(filename: str, parent: object = None) -> Script:  # noqa: ARG001
    """Stand in for ``open_script``: refuse every ``@include`` safely."""
    raise FermError(f"fuzz: @include disabled ({filename})")


# Install the guards once: never touch the shell, filesystem or network.
tokenizer_module.open_script = _blocked_include  # type: ignore[assignment]
set_resolver_provider(None)


def _parse(source: str) -> None:
    """Tokenize, parse and evaluate ``source`` with all I/O inert."""
    options = Options(test=True)
    script = Script(filename="<fuzz>", handle=io.StringIO(source))
    tokenizer = Tokenizer(script)
    scope = Scope()
    scope.push(Frame())
    evaluator = _SafeEvaluator(tokenizer, scope)
    parser = Parser(evaluator, {}, options)
    parser.enter(0, None)


def test_one_input(data: bytes) -> None:
    """Fuzz one input: parse it, swallowing the non-bug exceptions."""
    source = (
        atheris.FuzzedDataProvider(data)
        .ConsumeBytes(len(data))
        .decode("latin-1")
    )
    sink = io.StringIO()
    with (
        contextlib.redirect_stdout(sink),
        contextlib.redirect_stderr(sink),
    ):
        try:
            _parse(source)
        except FermError:
            return


def main() -> None:
    """Wire the harness into atheris and start fuzzing."""
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
