"""Command-line entry point: option parsing and apply orchestration.

Faithful port of ferm's top-level program in ``reference/src/ferm``: the
``GetOptions`` block and its ``%option`` derivation (``:620-700``), the main
flow that opens the script, runs the parser and applies the result per family
(``:751-819``), and the effectful helpers ``execute_command`` (``:2894``),
``confirm_rules`` (``:3189``) and the rollback loop (``:3147``).

The pieces the oracle reaches through globals are wired here instead.  The cli
owns the real I/O callables -- ``execute_command`` (run a shell command,
echoing it under ``--lines`` and skipping it under ``--noexec``),
``emit_line`` (the ``print LINES`` sink), ``read_save`` (run a ``*-save`` tool)
and ``restore`` (pipe a save to ``*-restore``) -- and injects them into
:func:`pyferm.domains.initialize_domain` (via the parser) and into
:meth:`pyferm.backend.base.Backend.commit`/``rollback``, so neither the parser
nor the backend touches global state or ``system`` directly.

Two sanctioned deviations live in this flow: the orchestration across domains
(apply all -> ``confirm_rules`` -> roll back all, with the closing message and
``exit 1``) is the cli's job, not the backend's (#3); and ``--interactive`` is
realised with :mod:`signal` (``signal.alarm``/``SIGALRM``) rather than Perl's
``alarm`` (#5).  ``--nolegacy`` (#4) is parsed here and threaded into
:class:`pyferm.config.Options`.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import subprocess  # live-only: run rules / hooks / *-save / *-restore
import sys

from pyferm import __version__
from pyferm.backend.base import (
    Backend,
    ExecuteCommand,
    LineEmitter,
    RestoreDomain,
)
from pyferm.backend.iptables import IptablesBackend, restore_domain
from pyferm.config import Options
from pyferm.domains import DomainInfo, SaveReader
from pyferm.errors import FermError
from pyferm.functions import Evaluator
from pyferm.parser import Parser, _splitpath_dir, _splitpath_file
from pyferm.resolver import pick_resolver, set_resolver_provider
from pyferm.scope import Frame, Scope
from pyferm.tokenizer import Tokenizer, open_script, tokenize_string

USAGE = (
    "Usage: ferm [--noexec] [--lines] [--slow] [--shell] "
    "[--interactive] [--flush] FILENAME\n"
)

_TIMEOUT_RE = re.compile(r"^[+-]?\d+$")
_DEF_RE = re.compile(r"\$?(\w+)=(.*)", re.DOTALL)


def _internal_error() -> FermError:
    """Exception for a Perl bare ``die`` (the ``@stack == 2`` sanity check)."""
    return FermError("internal error: parser left the scope stack unbalanced")


def printversion() -> None:
    """Print the version banner, verbatim from Perl ``printversion``."""
    sys.stdout.write(f"ferm {__version__}\n")
    sys.stdout.write("Copyright 2001-2021 Max Kellermann, Auke Kok\n")
    sys.stdout.write(
        "This program is free software released under GPLv2.\n"
    )
    sys.stdout.write("See the included COPYING file for license details.\n")


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser mirroring ferm's ``GetOptions`` (``:644``).

    ``allow_abbrev=False`` reproduces Getopt::Long's ``no_auto_abbrev``; help
    and version are handled manually (Perl prints its own banner and exits 0).
    Bundling of single-letter flags (Perl's ``bundling``) is not supported.
    """
    parser = argparse.ArgumentParser(
        prog="ferm", add_help=False, allow_abbrev=False
    )
    parser.add_argument("-n", "--noexec", action="store_true")
    parser.add_argument("-F", "--flush", action="store_true")
    parser.add_argument("--noflush", action="store_true")
    parser.add_argument("-l", "--lines", action="store_true")
    parser.add_argument("-i", "--interactive", action="store_true")
    parser.add_argument("-t", "--timeout")
    parser.add_argument("-h", "--help", action="store_true")
    parser.add_argument("-V", "--version", action="store_true")
    parser.add_argument("--test", action="store_true")
    # 'remote' is an alias for 'test' (Perl ``:657``).
    parser.add_argument(
        "--remote", dest="test", action="store_true"
    )
    parser.add_argument(
        "--test-mock-previous", action="append", default=[]
    )
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--slow", action="store_true")
    parser.add_argument("--shell", action="store_true")
    parser.add_argument("--domain")
    parser.add_argument("--def", dest="defs", action="append", default=[])
    # Sanctioned deviation #4 (no oracle counterpart).
    parser.add_argument("--nolegacy", action="store_true")
    parser.add_argument("files", nargs="*")
    return parser


def _resolve_options(args: argparse.Namespace) -> Options:
    """Derive the settled ``%option`` values from raw switches (``:675``).

    Reproduces the oracle's derivation: ``--test`` forces ``noexec`` and
    ``lines``; ``--shell`` forces ``lines``; ``fast`` is ``not --slow``;
    ``interactive`` requires ``not noexec``.  Validates ``--timeout`` and the
    interactive-mode tty requirements, raising :class:`FermError` for each
    ``die`` (``:691-698``).
    """
    noexec = args.noexec or args.test
    lines = args.lines or args.test or args.shell
    interactive = args.interactive and not noexec

    if args.timeout is not None and not _TIMEOUT_RE.match(args.timeout):
        raise FermError("invalid timeout. must be an integer")
    if not args.interactive and args.timeout is not None:
        raise FermError("ferm timeout has no sense without interactive mode")
    timeout = int(args.timeout) if args.timeout is not None else 30

    if interactive and not sys.stdin.isatty():
        raise FermError(
            "ferm interactive mode not possible: /dev/stdin is not a tty"
        )
    if interactive and not sys.stderr.isatty():
        raise FermError(
            "ferm interactive mode not possible: /dev/stderr is not a tty"
        )

    mock_previous: dict[str, str] = {}
    for spec in args.test_mock_previous:
        match = re.fullmatch(r"(\w+)=(.+)", spec)
        if match is None:
            raise FermError(f"Invalid --test-mock-previous: '{spec}'")
        mock_previous[match.group(1)] = match.group(2)

    return Options(
        test=args.test,
        noexec=noexec,
        lines=lines,
        fast=not args.slow,
        flush=args.flush,
        noflush=args.noflush,
        shell=args.shell,
        interactive=interactive,
        timeout=timeout,
        domain=args.domain,
        mock_previous=mock_previous,
        nolegacy=args.nolegacy,
    )


def _apply_def(evaluator: Evaluator, spec: str) -> None:
    """Evaluate one ``--def name=value`` into the scope (Perl ``opt_def``).

    The value is tokenized and read with :meth:`Evaluator.getvalues` over a
    private token source (Perl's ``getvalues(sub { shift @$tokens })``), then
    stored on the current top frame -- the global frame the auto-variables sit
    above once the script frame is pushed (``:618``/``:751``).
    """
    match = _DEF_RE.fullmatch(spec)
    if match is None:
        raise FermError("Invalid --def specification")
    name, unparsed = match.group(1), match.group(2)
    tokens = tokenize_string(unparsed)

    def _next() -> str | None:
        return tokens.pop(0) if tokens else None

    value = evaluator.getvalues(_next)
    if tokens:
        raise FermError("Extra tokens after --def")
    evaluator.scope.top.vars[name] = value


def _make_io(options: Options) -> tuple[
    ExecuteCommand, LineEmitter, SaveReader, RestoreDomain
]:
    """Build the four injected I/O callables bound to ``options``.

    Returns ``(execute, emit_line, read_save, restore)``.  ``execute`` is the
    port of ``execute_command`` (``:2894``); ``emit_line`` is the ``print
    LINES`` sink (raw, caller supplies newlines); ``read_save`` runs a
    ``*-save`` tool; ``restore`` adapts the backend's three-argument
    :func:`pyferm.backend.iptables.restore_domain` to the injected two-argument
    shape.  All but ``emit_line`` are no-ops under ``--test`` (never reached).
    """

    def emit_line(text: str) -> None:
        sys.stdout.write(text)

    def execute(command: str) -> int | None:
        if options.lines:
            emit_line(command + "\n")
        if options.noexec:
            return None
        completed = subprocess.run(command, shell=True, check=False)
        ret = completed.returncode
        if ret == 0:
            return None
        if ret < 0:
            sys.stderr.write(f"child died with signal {-ret}\n")
            return 1
        return ret

    def read_save(tool: str) -> str | None:
        try:
            completed = subprocess.run(
                [tool], capture_output=True, text=True, check=False
            )
        except OSError:
            return None
        return completed.stdout if completed.returncode == 0 else None

    def restore(domain_info: DomainInfo, save: str) -> None:
        restore_domain(domain_info, save, options)

    return execute, emit_line, read_save, restore


def _run_hook(
    command: str, options: Options, emit_line: LineEmitter
) -> None:
    """Run a ``@hook`` command (Perl ``:777-794``).

    Hooks echo under ``--lines`` and run under ``system`` unless ``--noexec``;
    unlike :func:`execute_command` their exit status is ignored and never feeds
    the rollback decision.
    """
    if options.lines:
        emit_line(command + "\n")
    if not options.noexec:
        subprocess.run(command, shell=True, check=False)


def _rollback_all(
    domains: dict[str, DomainInfo],
    options: Options,
    backend: Backend,
    *,
    execute: ExecuteCommand,
    restore: RestoreDomain,
) -> None:
    """Roll every family back and exit 1 (Perl ``rollback``, ``:3147``).

    The cross-domain loop and the closing message/``exit 1`` were split out of
    the backend (deviation #3): each family's restore lives in
    :meth:`Backend.rollback`; the orchestration is here.  Never returns.
    """
    for domain in sorted(domains):
        domain_info = domains[domain]
        if not domain_info.enabled:
            continue
        backend.rollback(
            domain,
            domain_info,
            options,
            execute=execute,
            restore=restore,
        )
    sys.stderr.write("\nFirewall rules rolled back.\n")
    raise SystemExit(1)


def _confirm_rules(options: Options) -> bool:
    """Ask the admin to confirm, with a timeout (Perl ``confirm_rules``).

    Sanctioned deviation #5: the oracle's ``alarm`` is realised with
    :mod:`signal`.  A no-op ``SIGALRM`` handler interrupts the blocking read
    after ``--timeout`` seconds; the input buffer is flushed with
    :func:`termios.tcflush` (best-effort, like Perl's ``eval``).  Returns
    ``True`` only when the admin typed exactly ``yes``.
    """
    import signal

    def _alrm_handler(_signum: int, _frame: object) -> None:
        """Interrupt the blocking read; do nothing else (Perl ``:3185``)."""

    previous = signal.signal(signal.SIGALRM, _alrm_handler)
    sys.stderr.write(
        "\nferm has applied the new firewall rules.\n"
        "Please type 'yes' to confirm:\n"
    )
    sys.stderr.flush()
    signal.alarm(options.timeout)

    try:
        data = os.read(sys.stdin.fileno(), 3)
        line = data.decode("utf-8", "replace")
    except (OSError, InterruptedError):
        line = ""
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)

    try:
        import termios

        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except (ImportError, OSError) as exc:  # pragma: no cover - tty only
        sys.stderr.write(f"{exc}\n")

    return line == "yes"


def main(argv: list[str] | None = None) -> int:
    """Run the ferm CLI (Perl's top-level program, ``:620-819``)."""
    try:
        return _main(argv)
    except FermError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1


def _main(argv: list[str] | None = None) -> int:
    """Run the flow proper; :func:`main` renders any :class:`FermError`."""
    args = _build_parser().parse_args(argv)

    if args.help:
        sys.stdout.write(USAGE)
        return 0
    if args.version:
        printversion()
        return 0

    options = _resolve_options(args)

    if len(args.files) != 1:
        sys.stderr.write(USAGE)
        return 1
    filename = args.files[0]

    execute, emit_line, read_save, restore = _make_io(options)

    # Scope: the global frame (Perl ``:618``) holds --def vars; the script
    # frame (Perl ``:751``) sits above it and carries the auto-variables.
    scope = Scope()
    scope.push(Frame())

    script = open_script(filename, None)
    tokenizer = Tokenizer(script)
    evaluator = Evaluator(tokenizer, scope)

    # ``@resolve`` picks a resolver per call from the *current* script's
    # directory (Perl ``pick_resolver`` reads ``$script->{filename}``,
    # ``:1298``), so the provider reads the live tokenizer at call time.
    set_resolver_provider(
        lambda: pick_resolver(options.test, tokenizer.script.filename)
    )

    for spec in args.defs:
        _apply_def(evaluator, spec)

    scope.push(Frame())
    scope.top.auto["FILENAME"] = filename
    scope.top.auto["FILEBNAME"] = _splitpath_file(filename)
    scope.top.auto["DIRNAME"] = _splitpath_dir(filename)

    parser = Parser(
        evaluator,
        {},
        options,
        execute=execute,
        emit_line=emit_line,
        read_save=read_save,
    )
    parser.enter(0, None)
    if len(scope.stack) != 2:
        raise _internal_error()

    domains = parser.domains
    backend: Backend = IptablesBackend()

    # Enable/disable hooks depending on --flush (Perl ``:765-772``).
    if options.flush:
        parser.pre_hooks.clear()
        parser.post_hooks.clear()
    else:
        parser.flush_hooks.clear()

    status: int | None = None
    for command in parser.pre_hooks:
        _run_hook(command, options, emit_line)

    for domain in sorted(domains):
        domain_info = domains[domain]
        if not domain_info.enabled:
            continue
        use_fast = options.fast and "tables-restore" in domain_info.tools
        domain_options = (
            options
            if use_fast == options.fast
            else dataclasses.replace(options, fast=use_fast)
        )
        rendered = backend.render(domain, domain_info, domain_options)
        result = backend.commit(
            domain,
            domain_info,
            rendered,
            domain_options,
            execute=execute,
            emit_line=emit_line,
            restore=restore,
        )
        if result is not None:
            status = result

    for command in [*parser.post_hooks, *parser.flush_hooks]:
        _run_hook(command, options, emit_line)

    if status is not None:
        _rollback_all(
            domains, options, backend, execute=execute, restore=restore
        )

    # Ask the user, and roll back if there is no confirmation (``:803-817``).
    if options.interactive:
        if options.shell:
            emit_line(
                "echo 'ferm has applied the new firewall rules.'\n"
            )
            emit_line("echo 'Please press Ctrl-C to confirm.'\n")
            emit_line(f"sleep {options.timeout}\n")
            for domain in sorted(domains):
                restore_tool = domains[domain].tools.get("tables-restore")
                if restore_tool is None:
                    continue
                emit_line(f"{restore_tool} <${domain}_tmp\n")

        if not options.noexec and not _confirm_rules(options):
            _rollback_all(
                domains, options, backend, execute=execute, restore=restore
            )

    return 0
