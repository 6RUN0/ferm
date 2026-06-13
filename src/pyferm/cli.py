"""
Command-line entry point: option parsing and apply orchestration.

Faithful port of ferm's top-level program in ``reference/src/ferm``: the
``GetOptions`` block and its ``%option`` derivation (``:620-700``), the main
flow that opens the script, runs the parser and applies the result per family
(``:751-819``), and the effectful helpers ``execute_command`` (``:2894``),
``confirm_rules`` (``:3189``) and the rollback loop (``:3147``).

The pieces the oracle reaches through globals are wired here instead.  The cli
owns the real I/O callables -- ``execute_command`` (run a shell command,
echoing it under ``--lines`` and skipping it under ``--noexec``),
``emit_line`` (the ``print LINES`` sink), ``read_save`` (run a ``*-save`` tool)
and ``restore`` (pipe a save to ``*-restore``).  ``emit_line`` is injected
into :func:`pyferm.domains.initialize_domain` (via the parser) directly;
the previous-state capture goes through a ``capture_previous`` closure that
folds backend + options + ``execute`` + ``read_save`` into the two-parameter
shape ``initialize_domain`` expects; ``execute``/``restore`` also feed
:meth:`pyferm.backend.base.Backend.commit`/``rollback``.  So neither the
parser nor the backend touches global state or ``system`` directly.

Two sanctioned deviations live in this flow: the orchestration across domains
(apply all -> ``confirm_rules`` -> roll back all, with the closing message and
``exit 1``) is the cli's job, not the backend's (#3); and ``--interactive`` is
realised with :mod:`signal` (``signal.alarm``/``SIGALRM``) rather than Perl's
``alarm`` (#5).  ``--nolegacy`` (#4) is parsed here and threaded into
:class:`pyferm.config.Options`.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess  # live-only: run rules / hooks / *-save / *-restore
import sys
from typing import TYPE_CHECKING, TextIO

from pyferm import __version__
from pyferm.backend.iptables import IptablesBackend, restore_domain
from pyferm.config import Options
from pyferm.domains import shell_snapshot
from pyferm.errors import FermError, internal_error
from pyferm.functions import Evaluator, splitpath_dir, splitpath_file
from pyferm.parser import Parser
from pyferm.resolver import pick_resolver, set_resolver_provider
from pyferm.scope import Frame, Scope
from pyferm.streams import reconfigure_latin1
from pyferm.tokenizer import Script, Tokenizer, open_script, tokenize_string

if TYPE_CHECKING:
    from collections.abc import Callable

    from pyferm.backend.base import (
        Backend,
        ExecuteCommand,
        LineEmitter,
        RestoreDomain,
        SaveReader,
    )
    from pyferm.domains import DomainInfo

# The pod2usage(-verbose => 1) rendering of the POD SYNOPSIS/OPTIONS
# (reference/src/ferm __END__ section), captured verbatim from
# ``perl reference/src/ferm --help``.  Perl prints it to stdout for both
# ``--help`` (exit 0) and the wrong-argument-count path (exit 1):
# pod2usage writes to STDOUT whenever the exit status is below 2.
HELP_TEXT = """\
Usage:
    ferm options inputfiles

Options:
     -n, --noexec      Do not execute the rules, just simulate
     -F, --flush       Flush all netfilter tables managed by ferm
     -l, --lines       Show all rules that were created
     -i, --interactive Interactive mode: revert if user does not confirm
     -t, --timeout s   Define interactive mode timeout in seconds
     --remote          Remote mode; ignore host specific configuration.
                       This implies --noexec and --lines.
     -V, --version     Show current version number
     -h, --help        Look at this text
     --slow            Slow mode, don't use iptables-restore
     --shell           Generate a shell script which calls iptables-restore
     --domain {ip|ip6} Handle only the specified domain
     --def '$name=v'   Override a variable

"""

_TIMEOUT_RE = re.compile(r"^[+-]?\d+$")
_DEF_RE = re.compile(r"\$?(\w+)=(.*)", re.DOTALL)

# Perl system() runs a one-string command through /bin/sh only when it
# contains shell metacharacters (perl doio.c, Perl_do_exec3); otherwise it
# splits on whitespace and execs the first word directly.  The extra
# Perl-side refinements (a trailing "2>&1", a trailing newline) force the
# shell here too -- both contain metacharacters from this set -- which only
# swaps an exec for an equivalent shell run.
_SHELL_META = "$&*(){}[]'\";\\|?<>~`\n"
_VAR_ASSIGN_RE = re.compile(r"[A-Za-z]*=")


def printversion() -> None:
    """Print the version banner, verbatim from Perl ``printversion``."""
    sys.stdout.write(f"ferm {__version__}\n")
    sys.stdout.write("Copyright 2001-2021 Max Kellermann, Auke Kok\n")
    sys.stdout.write("This program is free software released under GPLv2.\n")
    sys.stdout.write("See the included COPYING file for license details.\n")


def _build_parser() -> argparse.ArgumentParser:
    """
    Build the argument parser mirroring ferm's ``GetOptions`` (``:644``).

    ``allow_abbrev=False`` reproduces Getopt::Long's ``no_auto_abbrev``; help
    and version are handled manually (Perl prints its own banner and exits 0).
    Bundled single-letter flags (Perl's ``bundling``, e.g. ``-nl``) work via
    argparse's native short-flag concatenation.
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
    parser.add_argument("--remote", dest="test", action="store_true")
    parser.add_argument("--test-mock-previous", action="append", default=[])
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
    """
    Derive the settled ``%option`` values from raw switches (``:675``).

    Reproduces the oracle's derivation: ``--test`` forces ``noexec`` and
    ``lines``; ``--shell`` forces ``lines``; ``fast`` is ``not --slow``;
    ``interactive`` requires the raw ``--noexec`` switch to be absent
    (``--test`` does not suppress it).  Validates ``--timeout`` and the
    interactive-mode tty requirements, raising :class:`FermError` for each
    ``die`` (``:691-698``).
    """
    noexec = args.noexec or args.test
    lines = args.lines or args.test or args.shell
    # The oracle derives interactive from the RAW --noexec switch (:679),
    # so --test alone does not suppress interactive mode.
    interactive = args.interactive and not args.noexec

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
    """
    Evaluate one ``--def name=value`` into the scope (Perl ``opt_def``).

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


def _setup_streams(
    options: Options,
) -> tuple[TextIO, Callable[[], None]]:
    """
    Replicate Perl's ``LINES``/``STDOUT`` handle plumbing (``:738-739``).

    Under ``--shell`` the generated script must own the real stdout: the
    ``--lines`` sink keeps a duplicate of the original stdout while fd 1 is
    redirected to stderr, so child processes (hooks, ``*-save`` tools,
    slow-mode commands) cannot interleave their output with the script.
    Without ``--shell`` the sink is plain ``sys.stdout``.  Returns the sink
    and an undo callable (for in-process tests; the oracle never restores).
    """
    if not options.shell:
        return sys.stdout, lambda: None

    # Perl's open works on the STDOUT/STDERR handles, i.e. file descriptors
    # 1 and 2; children inherit the descriptor, not sys.stdout, so the
    # plumbing must happen at fd level.
    stdout_fd, stderr_fd = 1, 2
    saved_fd = os.dup(stdout_fd)
    # Line-buffered: each emitted line reaches the script file before any
    # subsequent child could have run.
    lines_stream = os.fdopen(saved_fd, "w", buffering=1, encoding="latin-1")
    sys.stdout.flush()
    os.dup2(stderr_fd, stdout_fd)

    def restore() -> None:
        sys.stdout.flush()
        os.dup2(saved_fd, stdout_fd)
        lines_stream.close()

    return lines_stream, restore


def _make_io(
    options: Options, lines_stream: TextIO
) -> tuple[ExecuteCommand, LineEmitter, SaveReader, RestoreDomain]:
    """
    Build the four injected I/O callables bound to ``options``.

    Returns ``(execute, emit_line, read_save, restore)``.  ``execute`` is the
    port of ``execute_command`` (``:2894``); ``emit_line`` is the ``print
    LINES`` sink (raw, caller supplies newlines) writing to ``lines_stream``
    from :func:`_setup_streams`; ``read_save`` runs a ``*-save`` tool and is
    consumed by ``_run``'s ``capture_previous`` closure over
    :meth:`pyferm.backend.base.Backend.capture_previous`; ``restore`` adapts
    the backend's three-argument
    :func:`pyferm.backend.iptables.restore_domain` to the injected two-argument
    shape.  All but ``emit_line`` are no-ops under ``--test`` (never reached).
    """

    def emit_line(text: str) -> None:
        lines_stream.write(text)

    def execute(command: str) -> int | None:
        if options.lines:
            emit_line(command + "\n")
        if options.noexec:
            return None
        use_shell = (
            command.startswith(". ")
            or _VAR_ASSIGN_RE.match(command) is not None
            or any(ch in _SHELL_META for ch in command)
            or not command.split()
        )
        try:
            completed = subprocess.run(
                command if use_shell else command.split(),
                shell=use_shell,
                check=False,
            )
        except OSError as exc:
            # Perl: $? == -1 -> print and exit 1 at once, skipping the
            # status bookkeeping, post hooks and rollback (:2903-2905).
            sys.stderr.write(f"failed to execute: {exc.strerror or exc}\n")
            raise SystemExit(1) from exc
        ret = completed.returncode
        if ret == 0:
            return None
        if ret < 0:
            sys.stderr.write(f"child died with signal {-ret}\n")
            return 1
        return ret

    def read_save(tool: str) -> str | None:
        # Perl never checks the pipe's exit status (:950-955): a partial
        # dump still becomes {previous}.  An unspawnable tool matches the
        # pipe-open whose child fails to exec: the parent reads EOF, so
        # {previous} is set to the empty string, not left unset.
        try:
            completed = subprocess.run(
                [tool], capture_output=True, encoding="latin-1", check=False
            )
        except OSError:
            return ""
        return completed.stdout

    def restore(domain_info: DomainInfo, save: str) -> None:
        restore_domain(domain_info, save, options)

    return execute, emit_line, read_save, restore


def _run_hook(command: str, options: Options, emit_line: LineEmitter) -> None:
    """
    Run a ``@hook`` command (Perl ``:777-794``).

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
    """
    Roll every family back and exit 1 (Perl ``rollback``, ``:3147``).

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


class _ConfirmTimeoutError(Exception):
    """Raised by the ``SIGALRM`` handler to abort the confirmation read."""


def _confirm_rules(options: Options) -> bool:
    """
    Ask the admin to confirm, with a timeout (Perl ``confirm_rules``).

    Sanctioned deviation #5: the oracle's ``alarm`` is realised with
    :mod:`signal`.  The ``SIGALRM`` handler must *raise* to abort the
    blocking read: Perl's ``sysread`` returns on ``EINTR``, but Python
    retries an interrupted ``os.read`` whenever the handler returns
    normally (PEP 475), which would disarm the timeout entirely.  The
    input buffer is flushed with :func:`termios.tcflush` (best-effort,
    like Perl's ``eval``).  Returns ``True`` only when the admin typed
    exactly ``yes``.
    """
    import signal

    def _alrm_handler(_signum: int, _frame: object) -> None:
        """Abort the blocking read (Perl ``:3185`` + PEP 475)."""
        raise _ConfirmTimeoutError

    previous = signal.signal(signal.SIGALRM, _alrm_handler)
    sys.stderr.write(
        "\nferm has applied the new firewall rules.\n"
        "Please type 'yes' to confirm:\n"
    )
    sys.stderr.flush()
    signal.alarm(options.timeout)

    try:
        data = os.read(sys.stdin.fileno(), 3)
        line = data.decode("latin-1")
    except (_ConfirmTimeoutError, OSError):
        line = ""
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)

    # Perl wraps the flush in a bare eval and prints $@ on any failure;
    # termios.error is not an OSError, so it needs its own clause.
    try:
        import termios
    except ImportError as exc:  # pragma: no cover - termios is POSIX
        sys.stderr.write(f"{exc}\n")
    else:
        try:
            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        except (OSError, termios.error) as exc:
            sys.stderr.write(f"{exc}\n")

    return line == "yes"


def main(argv: list[str] | None = None) -> int:
    """Run the ferm CLI (Perl's top-level program, ``:620-819``)."""
    # before any write: argparse renders usage/errors through these streams
    reconfigure_latin1(sys.stdout, errors="backslashreplace")
    reconfigure_latin1(sys.stderr, errors="backslashreplace")
    try:
        return _main(argv)
    except FermError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1


def _main(argv: list[str] | None = None) -> int:
    """Run the flow proper; :func:`main` renders any :class:`FermError`."""
    args = _build_parser().parse_args(argv)

    if args.help:
        sys.stdout.write(HELP_TEXT)
        return 0
    if args.version:
        printversion()
        return 0

    options = _resolve_options(args)

    if len(args.files) != 1:
        sys.stdout.write(HELP_TEXT)
        return 1

    lines_stream, restore_streams = _setup_streams(options)
    try:
        return _run(args, options, lines_stream)
    finally:
        restore_streams()


def _run(
    args: argparse.Namespace, options: Options, lines_stream: TextIO
) -> int:
    """Parse and apply the configuration with the streams already set up."""
    filename = args.files[0]
    execute, emit_line, read_save, restore = _make_io(options, lines_stream)

    # Scope: the global frame (Perl ``:618``) holds --def vars; the script
    # frame (Perl ``:751``) sits above it and carries the auto-variables.
    scope = Scope()
    scope.push(Frame())

    # --def is evaluated before the script exists (Perl runs it inside
    # GetOptions, ``:662``): plain values bind on the global frame, while
    # script-context built-ins abort, exactly as the oracle does.
    def_evaluator = Evaluator(Tokenizer(None), scope)
    for spec in args.defs:
        _apply_def(def_evaluator, spec)

    script = open_script(filename, None)
    tokenizer = Tokenizer(script)
    evaluator = Evaluator(tokenizer, scope)

    # ``@resolve`` picks a resolver per call from the *current* script's
    # directory (Perl ``pick_resolver`` reads ``$script->{filename}``,
    # ``:1298``), so the provider reads the live tokenizer at call time.
    set_resolver_provider(
        lambda: pick_resolver(options.test, tokenizer.script.filename)
    )

    scope.push(Frame())
    scope.top.auto["FILENAME"] = filename
    scope.top.auto["FILEBNAME"] = splitpath_file(filename)
    scope.top.auto["DIRNAME"] = splitpath_dir(filename)

    backend: Backend = IptablesBackend()

    def capture_previous(domain: str, domain_info: DomainInfo) -> None:
        # Folds backend + options + execute + read_save into the
        # two-parameter shape initialize_domain expects (debt design
        # section 1).
        backend.capture_previous(
            domain,
            domain_info,
            options,
            execute=execute,
            read_save=read_save,
        )

    parser = Parser(
        evaluator,
        {},
        options,
        capture_previous=capture_previous,
        emit_line=emit_line,
    )
    # finally: close the whole include chain (innermost first) on both
    # the success path and a parse abort, so no error path leaks an open
    # file or an unreaped pipe child.  Perl gets this from filehandle
    # garbage collection; the suite runs with ResourceWarning as error.
    try:
        parser.enter(0, None)
    finally:
        node: Script | None = tokenizer.script
        while node is not None:
            node.close()
            node = node.parent
    if len(scope.stack) != 2:  # noqa: PLR2004 -- global + script frames
        raise internal_error("parser left the scope stack unbalanced")

    domains = parser.domains

    # Enable/disable hooks depending on --flush (Perl ``:765-772``).
    if options.flush:
        parser.pre_hooks.clear()
        parser.post_hooks.clear()
    else:
        parser.flush_hooks.clear()

    # finally: drop the eb rollback snapshots once nothing can roll back
    # any more -- after _rollback_all (SystemExit passes through) and on
    # the success path alike.  Perl gets this from File::Temp's
    # destructor; the suite runs with ResourceWarning as error.
    status: int | None = None
    try:
        for command in parser.pre_hooks:
            _run_hook(command, options, emit_line)

        for domain in sorted(domains):
            domain_info = domains[domain]
            if not domain_info.enabled:
                continue
            # The arp/eb fallback to slow commands (no *-restore tool) is
            # the backend's decision: render picks the shape, commit
            # follows it.
            rendered = backend.render(domain, domain_info, options)
            try:
                result = backend.commit(
                    domain,
                    domain_info,
                    rendered,
                    options,
                    execute=execute,
                    emit_line=emit_line,
                    restore=restore,
                )
            finally:
                rendered.close()
            if result is not None:
                status = result

        for command in [*parser.post_hooks, *parser.flush_hooks]:
            _run_hook(command, options, emit_line)

        if status is not None:
            _rollback_all(
                domains, options, backend, execute=execute, restore=restore
            )

        # Ask the user, and roll back without confirmation (``:803-817``).
        if options.interactive:
            if options.shell:
                emit_line("echo 'ferm has applied the new firewall rules.'\n")
                emit_line("echo 'Please press Ctrl-C to confirm.'\n")
                emit_line(f"sleep {options.timeout}\n")
                for domain in sorted(domains):
                    snapshot = shell_snapshot(domain, domains[domain].tools)
                    if snapshot is None:
                        continue
                    emit_line(snapshot.restore)

            if not options.noexec and not _confirm_rules(options):
                _rollback_all(
                    domains, options, backend, execute=execute, restore=restore
                )
    finally:
        for info in domains.values():
            info.close()

    return 0
