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
import enum
import os
import re
import subprocess  # live-only: run rules / hooks / *-save / *-restore
import sys
from typing import TYPE_CHECKING, Final, TextIO

from pyferm import __version__, etckeeper
from pyferm.analysis import Severity, run_analysis
from pyferm.backend.iptables import (
    IptablesBackend,
    restore_domain,
    rules_to_save,
    validate_names,
)
from pyferm.backend.nft import TOOL_NFT, NftBackend
from pyferm.config import Options, PlanFormat
from pyferm.errors import FermError, internal_error
from pyferm.functions import Evaluator, splitpath_dir, splitpath_file
from pyferm.graph import (
    collect_graph,
    escape_control_chars,
    render_d2,
    render_dot,
)
from pyferm.introspect import describe, list_modules
from pyferm.parser import Parser
from pyferm.plan import (
    Plan,
    diff_tables,
    parse_nft_list,
    parse_nft_script,
    parse_save,
    render_plan,
    summary_line,
)
from pyferm.resolver import pick_resolver, set_resolver_provider
from pyferm.scope import Frame, Scope
from pyferm.streams import (
    BYTE_ENCODING,
    HUMAN_STREAM_ERRORS,
    argv_to_latin1,
    reconfigure_latin1,
)
from pyferm.tokenizer import Script, Tokenizer, open_script, tokenize_string

if TYPE_CHECKING:
    from collections.abc import Callable

    from pyferm.backend.base import (
        Backend,
        ExecuteCapture,
        ExecuteCommand,
        LineEmitter,
        RestoreDomain,
        SaveReader,
    )
    from pyferm.domains import DomainInfo, Family
    from pyferm.tree import Block


class ExitCode(enum.IntEnum):
    """
    Process exit status: the ferm/plan contract.

    ``0`` on success/no changes, ``2`` when ``--plan``/``--lint`` finds
    pending changes, ``1`` on a ferm error -- never a bare literal past
    this module boundary.
    """

    OK = 0
    ERROR = 1
    CHANGES = 2


#: A clean run leaves exactly two scope frames on the stack: the global
#: frame plus the top-level script frame.  Anything else is an internal bug.
BALANCED_STACK_DEPTH: Final[int] = 2

#: The config ``ferm rollback`` defaults to when none is named on the command
#: line -- the standard system path.
_DEFAULT_CONFIG: Final[str] = "/etc/ferm/ferm.conf"

# The pod2usage(-verbose => 1) rendering of the POD SYNOPSIS/OPTIONS
# (reference/src/ferm __END__ section), captured verbatim from
# ``perl reference/src/ferm --help``.  Perl prints it to stdout for both
# ``--help`` (exit 0) and the wrong-argument-count path (exit 1):
# pod2usage writes to STDOUT whenever the exit status is below 2.
HELP_TEXT: Final[str] = """\
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
     --lint            Static-analysis mode: report warnings, apply nothing
     --lint-strict     With --lint: exit non-zero if any warning is found
     --lint-fail-level Set the --lint gating threshold (error|warning|info)
     --list-modules    List supported netfilter modules and keywords
     --describe NAME   Show the options of one module, option or keyword
     --graph           Print the chain control-flow graph (d2 or DOT)
     --graph-format F  Graph renderer: dot or d2 (default d2)

"""

_TIMEOUT_RE: Final[re.Pattern[str]] = re.compile(r"^[+-]?\d+$")
_DEF_RE: Final[re.Pattern[str]] = re.compile(r"\$?(\w+)=(.*)", re.DOTALL)

# Perl system() runs a one-string command through /bin/sh only when it
# contains shell metacharacters (perl doio.c, Perl_do_exec3); otherwise it
# splits on whitespace and execs the first word directly.  The extra
# Perl-side refinements (a trailing "2>&1", a trailing newline) force the
# shell here too -- both contain metacharacters from this set -- which only
# swaps an exec for an equivalent shell run.
_SHELL_META: Final[str] = "$&*(){}[]'\";\\|?<>~`\n"
_VAR_ASSIGN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z]*=")


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
    # A sanctioned deviation (no oracle counterpart).
    parser.add_argument("--nolegacy", action="store_true")
    # Port-only: opt into the native nftables backend.
    parser.add_argument("--nft", action="store_true")
    # Port-only: opt out of delta-apply, force full flush+reload.
    parser.add_argument("--full-reload", action="store_true")
    # Port-only: skip the etckeeper history commit after a successful apply.
    parser.add_argument("--no-etckeeper", action="store_true")
    # Port-only: read-only diff preview.
    parser.add_argument("--plan", action="store_true")
    parser.add_argument(
        "--plan-format",
        choices=tuple(PlanFormat),
        default=PlanFormat.STRUCTURED,
    )
    # Port-only: eval-free static analysis (see _run_lint).
    parser.add_argument("--lint", action="store_true")
    parser.add_argument("--lint-strict", action="store_true")
    parser.add_argument(
        "--lint-fail-level",
        choices=("error", "warning", "info"),
        default=None,
    )
    # Port-only: registry/keyword introspection (see _run_introspection).
    parser.add_argument("--list-modules", action="store_true")
    parser.add_argument("--describe", default=None)
    # Port-only: read-only chain control-flow graph (see _run_graph).
    parser.add_argument("--graph", action="store_true")
    parser.add_argument("--graph-format", choices=("dot", "d2"), default=None)
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
    # argparse ``choices=`` only validates membership, it does not coerce a
    # user-supplied string to the enum; normalize once so every check below
    # (and the final Options field) sees a real PlanFormat.
    plan_format = PlanFormat(args.plan_format)

    # --lint is a self-contained terminal mode (dispatched on ``args.lint`` in
    # _main, before _setup_streams, so it never consumes the returned
    # Options).  Validate its conflicts FIRST -- before the apply-path timeout
    # and interactive-tty guards below -- so a combination like
    # ``--lint --interactive`` (in a non-tty) or ``--lint --timeout`` surfaces
    # the lint message rather than an apply-path die, and the accepted-but-
    # ignored switches (--noexec/--lines/--timeout/--test/--nolegacy/
    # --no-etckeeper/--test-mock-previous) stay genuinely ignored.  A benign
    # placeholder Options is returned; the lint path discards it.
    if args.lint_strict and not args.lint:
        raise FermError("ferm --lint-strict has no sense without --lint")
    if args.lint_fail_level is not None and not args.lint:
        raise FermError("ferm --lint-fail-level has no sense without --lint")
    if args.lint:
        # apply/plan modes: --lint applies and plans nothing.
        for flag, switch in (
            ("--plan", args.plan),
            ("--nft", args.nft),
            ("--fast", args.fast),
            ("--slow", args.slow),
            ("--shell", args.shell),
            ("--interactive", args.interactive),
            ("--flush", args.flush),
            ("--noflush", args.noflush),
            ("--full-reload", args.full_reload),
        ):
            if switch:
                raise FermError(f"ferm --lint cannot be combined with {flag}")
        # --plan-format is plan-only; caught here (before the generic
        # "no sense without --plan" check below) so the message names --lint.
        if plan_format != PlanFormat.STRUCTURED:
            raise FermError(
                "ferm --lint cannot be combined with --plan-format"
            )
        # eval-dependent flags: --def binds on the eval scope frame and
        # --domain filters during eval, so neither reaches parse_to_block --
        # accepting them silently would be a no-op.
        if args.defs:
            raise FermError("ferm --lint cannot be combined with --def")
        if args.domain is not None:
            raise FermError("ferm --lint cannot be combined with --domain")
        return Options()

    noexec = args.noexec or args.test
    lines = args.lines or args.test or args.shell
    # The oracle derives interactive from the RAW --noexec switch (:679),
    # so --test alone does not suppress interactive mode.
    interactive = args.interactive and not args.noexec

    # guard order is the oracle's (ferm:691-698): tty guards first, then
    # timeout-needs-interactive, then the integer-shape check.
    if interactive and not sys.stdin.isatty():
        raise FermError(
            "ferm interactive mode not possible: /dev/stdin is not a tty"
        )
    if interactive and not sys.stderr.isatty():
        raise FermError(
            "ferm interactive mode not possible: /dev/stderr is not a tty"
        )
    if not args.interactive and args.timeout is not None:
        raise FermError("ferm timeout has no sense without interactive mode")
    if args.timeout is not None and not _TIMEOUT_RE.match(args.timeout):
        raise FermError("invalid timeout. must be an integer")
    timeout = int(args.timeout) if args.timeout is not None else 30

    mock_previous: dict[str, str] = {}
    for spec in args.test_mock_previous:
        match = re.fullmatch(r"(\w+)=(.+)", spec)
        if match is None:
            raise FermError(f"Invalid --test-mock-previous: '{spec}'")
        mock_previous[match.group(1)] = match.group(2)

    if args.full_reload and not args.nft:
        raise FermError("ferm --full-reload has no sense without --nft")
    if plan_format != PlanFormat.STRUCTURED and not args.plan:
        raise FermError("ferm --plan-format has no sense without --plan")
    if args.plan and args.nft and args.noflush:
        raise FermError("--noflush is not supported with --plan --nft yet")

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
        nft=args.nft,
        plan=args.plan,
        plan_format=plan_format,
        full_reload=args.full_reload,
        etckeeper=not args.no_etckeeper,
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
    lines_stream = os.fdopen(
        saved_fd, "w", buffering=1, encoding=BYTE_ENCODING
    )
    sys.stdout.flush()
    os.dup2(stderr_fd, stdout_fd)

    def restore() -> None:
        sys.stdout.flush()
        os.dup2(saved_fd, stdout_fd)
        lines_stream.close()

    return lines_stream, restore


def _make_io(
    options: Options, lines_stream: TextIO
) -> tuple[
    ExecuteCommand, LineEmitter, SaveReader, RestoreDomain, ExecuteCapture
]:
    """
    Build the five injected I/O callables bound to ``options``.

    Returns ``(execute, emit_line, read_save, restore, capture)``.  ``execute``
    is the port of ``execute_command`` (``:2894``); ``emit_line`` is the
    ``print LINES`` sink (raw, caller supplies newlines) writing to
    ``lines_stream`` from :func:`_setup_streams`; ``read_save`` runs a
    ``*-save`` tool and ``capture`` runs a command capturing its stdout (the
    nft backend's snapshot seam) -- both consumed by ``_run``'s
    ``capture_previous`` closure over
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
            raise SystemExit(ExitCode.ERROR) from exc
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
        #
        # Under --plan a partial/empty current would under-count removals
        # and produce a falsely-clean plan, so the plan branch reads the
        # return code itself and fails loud instead.
        try:
            completed = subprocess.run(
                [tool],
                capture_output=True,
                encoding=BYTE_ENCODING,
                check=False,
            )
        except OSError as exc:
            if options.plan:
                raise FermError(
                    f"failed to read current ruleset via {tool}: {exc}"
                ) from exc
            return ""
        if options.plan and completed.returncode != 0:
            raise FermError(
                f"{tool} exited {completed.returncode}; cannot build a plan"
            )
        return completed.stdout

    nft_restore = _make_nft_restore(options) if options.nft else None

    def restore(domain_info: DomainInfo, save: str) -> None:
        if nft_restore is not None:
            nft_restore(domain_info, save)
        else:
            restore_domain(domain_info, save, options)

    def capture(command: str) -> str | None:
        # Like execute(), but returns stdout for snapshotting.
        #
        # A snapshot failure must NOT masquerade as "no previous table": the
        # nft rollback DELETES the table when `previous` is None, so a
        # transient capture failure on an EXISTING table would destroy it
        # (review 2026-06-14, finding C3).  Only a confirmed-absent target
        # collapses to None -- nft prints "No such file or directory" (ENOENT)
        # for a missing table, the genuine first run; every other nonzero exit
        # or spawn error raises, aborting before any kernel change.
        if options.noexec and not options.plan:
            return None
        try:
            completed = subprocess.run(
                command.split(),
                capture_output=True,
                encoding=BYTE_ENCODING,
                check=False,
            )
        except OSError as exc:
            raise FermError(f"failed to snapshot for rollback: {exc}") from exc
        if completed.returncode == 0:
            return completed.stdout or None
        if "No such file or directory" in (completed.stderr or ""):
            return None  # genuine first run: the target does not exist yet
        raise FermError(
            "failed to snapshot for rollback: "
            + (completed.stderr.strip() or f"exit {completed.returncode}")
        )

    return execute, emit_line, read_save, restore, capture


def _select_backend(options: Options) -> Backend:
    """Pick the backend: nft is opt-in, iptables the default."""
    return NftBackend() if options.nft else IptablesBackend()


def _run_failed(path: str, exc: OSError) -> FermError:
    """Build the spawn-failure error shared by both nft call sites below."""
    return FermError(f"Failed to run {path}: {exc}")


def _nft_check_save(path: str, save: str) -> None:
    """
    Validate a rendered nft script with ``nft -c -f -`` (installs nothing).

    The ``-c`` pre-check is a netlink validation (``--check``); its stderr is
    captured so a rejected ruleset surfaces nft's own diagnostic instead of a
    generic failure.  Raises :class:`FermError` if the tool cannot be run or
    the ruleset is rejected.  Shared by the apply path (before a real
    ``nft -f -``) and ``--plan`` (so an un-appliable plan is reported as an
    error instead of advertised as actionable).
    """
    # the path comes from find_tool; no shell is used.  latin-1:
    # one byte per char, reproducing the config bytes exactly.
    payload = save.encode(BYTE_ENCODING)
    try:
        check = subprocess.run(
            [path, "-c", "-f", "-"],
            input=payload,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise _run_failed(path, exc) from exc
    if check.returncode != 0:
        # backslashreplace: nft's stderr is a human-facing diagnostic.
        detail = check.stderr.decode(
            BYTE_ENCODING, HUMAN_STREAM_ERRORS
        ).strip()
        raise FermError(detail or f"Failed to run {path} -c")


def _validate_desired_nft(options: Options, path: str, save: str) -> None:
    """
    Pre-validate the desired nft script under ``--plan`` unless in test mode.

    ``--test`` substitutes a fake nft path and must never spawn the real tool,
    so the gate is a no-op there (the golden plan suite stays hermetic).  In a
    real run the desired ruleset is checked with ``nft -c`` so an un-appliable
    plan (e.g. an ``arp`` chain carrying a ``tcp`` match) aborts with nft's
    diagnostic rather than being presented as an actionable change.
    """
    if options.test:
        return
    _nft_check_save(path, save)


def _make_nft_restore(options: Options) -> RestoreDomain:
    """
    Build the ``nft -f -`` applier injected when ``--nft`` is set.

    Validates the rendered save with ``nft -c -f -`` first, then pipes it to
    the resolved ``nft`` binary, raising :class:`FermError` (the rollback
    trigger) if the tool cannot be run or either step exits non-zero -- the
    nft analogue of :func:`pyferm.backend.iptables.restore_domain`.

    The design kept the ``-c`` pre-check out of the ``--noexec`` path because
    it needs ``CAP_NET_ADMIN`` even on a valid ruleset; here we are about to
    apply for real, so that privilege is already in hand and the check is free.
    """
    del options  # parity with the iptables wrapper; nft adds no flags

    def restore(domain_info: DomainInfo, save: str) -> None:
        path = domain_info.tools[TOOL_NFT]
        _nft_check_save(path, save)
        # the path comes from find_tool; no shell is used.  latin-1:
        # one byte per char, reproducing the config bytes exactly.
        payload = save.encode(BYTE_ENCODING)
        try:
            completed = subprocess.run(
                [path, "-f", "-"],
                input=payload,
                check=False,
            )
        except OSError as exc:
            raise _run_failed(path, exc) from exc
        if completed.returncode != 0:
            raise FermError(f"Failed to run {path}")

    return restore


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
    domains: dict[Family, DomainInfo],
    options: Options,
    backend: Backend,
    *,
    execute: ExecuteCommand,
    restore: RestoreDomain,
) -> None:
    """
    Roll every family back and exit 1 (Perl ``rollback``, ``:3147``).

    The cross-domain loop and the closing message/``exit 1`` were split out of
    the backend (a sanctioned deviation): each family's restore lives in
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
    raise SystemExit(ExitCode.ERROR)


class _ConfirmTimeoutError(Exception):
    """Raised by the ``SIGALRM`` handler to abort the confirmation read."""


def _confirm_rules(options: Options) -> bool:
    """
    Ask the admin to confirm, with a timeout (Perl ``confirm_rules``).

    A sanctioned deviation: the oracle's ``alarm`` is realised with
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
        line = data.decode(BYTE_ENCODING)
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


def _parse_config_eval_free(config_path: str, *, mode: str) -> Block:
    """
    Open one config through ``open_script`` and parse it eval-free.

    Shared by ``--lint`` and ``--graph``: both advertise a read-only,
    subprocess-free contract meant to be pointed at untrusted files, so a
    trailing-``|`` pipe path is rejected rather than run through the shell
    (honouring it would be arbitrary command execution driven by a
    filename).  ``open_script`` supplies the input through the same
    boundary as apply/``--plan`` -- preserving ``-`` (stdin), the single
    ``FermError`` on a missing file, and the latin-1 byte model.
    """
    if config_path.endswith("|"):
        raise FermError(f"ferm {mode} cannot read from a pipe command")
    script = open_script(config_path, None)
    try:
        handle = script.handle
        if handle is None:  # open_script always sets it; guard for the type
            raise internal_error("open_script returned no handle")
        config = handle.read()
    finally:
        script.close()
    return Parser.parse_to_block(config)


def _run_lint(config_path: str, *, fail_level: Severity | None) -> int:
    """
    Run the eval-free static analysis for ``ferm --lint`` (port-only).

    Read-only like ``--plan`` but, unlike it, eval-free: the config is parsed
    into a structural tree with :meth:`Parser.parse_to_block` and handed to the
    analysers in :mod:`pyferm.analysis`, so no evaluation runs and no kernel,
    resolver, or previous-ruleset I/O is touched.  ``open_script`` supplies the
    input through the same boundary as apply/``--plan`` -- preserving ``-``
    (stdin), the single ``FermError`` on a missing file, and the latin-1 byte
    model -- so the analysis sees the exact config bytes.  The pipe-path
    rejection rationale lives on :func:`_parse_config_eval_free`.

    Findings print to stdout as ``<severity>: <message>`` lines in a
    fixed, deterministic order (severity tier, then analyzer
    registration order, then message; see analysis.run_analysis); the
    whole line passes through escape_control_chars.  Without a
    ``fail_level`` the exit code stays ``0`` even with findings
    (warnings must not break another project's CI on a heuristic); with
    one, any finding at or above the threshold exits ``2`` for opt-in
    CI gating.
    """
    block = _parse_config_eval_free(config_path, mode="--lint")

    findings = run_analysis(block)
    # The raw message is the sort key; escaping at print time is
    # byte-equivalent (the substitution is position-independent) and a
    # crafted name still cannot inject terminal-control bytes into CI
    # logs.
    for finding in findings:
        line = f"{finding.severity.name.lower()}: {finding.message}"
        sys.stdout.write(f"{escape_control_chars(line)}\n")

    if fail_level is None:
        return ExitCode.OK
    return (
        ExitCode.CHANGES
        if any(f.severity <= fail_level for f in findings)
        else ExitCode.OK
    )


#: Namespace attrs the introspection guard must not reject: its own two
#: flags, the earlier-dispatched help/version, and files (own guard).
_INTROSPECTION_EXEMPT: Final[frozenset[str]] = frozenset(
    {"list_modules", "describe", "help", "version", "files"}
)

#: dest -> user-facing flag, where the mechanical "--" + dest.replace()
#: derivation would lie (--remote/--test share dest="test").
_INTROSPECTION_FLAG_NAMES: Final[dict[str, str]] = {
    "defs": "--def",
    "test": "--test/--remote",
}


def _reject_other_flags(
    args: argparse.Namespace, *, mode: str, exempt: frozenset[str]
) -> None:
    """
    Reject every flag outside ``exempt`` via the default-Namespace diff.

    The diff (not a hand-kept flag list) is what keeps future flags
    auto-rejected instead of silently ignored; ``exempt`` names the
    mode's own flags plus attrs guarded separately by the caller.
    """
    defaults = vars(_build_parser().parse_args([]))
    for attr, default in defaults.items():
        if attr in exempt:
            continue
        if getattr(args, attr) != default:
            flag = _INTROSPECTION_FLAG_NAMES.get(
                attr, "--" + attr.replace("_", "-")
            )
            raise FermError(f"ferm {mode} cannot be combined with {flag}")


def _run_introspection(args: argparse.Namespace) -> int:
    """
    Run ``--list-modules`` / ``--describe`` (port-only, eval-free).

    Guard order is contractual: mode-XOR, then the no-input-file guard,
    then the default-Namespace diff -- the diff cannot see --describe
    (exempt) and would mislabel a stray input file, so the specific
    guards must fire first.  The diff (not a hand-kept flag list) is
    what keeps future flags auto-rejected instead of silently ignored.
    """
    mode = "--list-modules" if args.list_modules else "--describe"
    if args.list_modules and args.describe is not None:
        raise FermError(
            "ferm --list-modules cannot be combined with --describe"
        )
    if args.files:
        raise FermError(f"ferm {mode} takes no input file")
    _reject_other_flags(args, mode=mode, exempt=_INTROSPECTION_EXEMPT)
    if args.list_modules:
        text = list_modules()
    else:
        # _main only calls _run_introspection when list_modules or describe
        # is set, and the mode-XOR check above already ruled out
        # list_modules here, so describe is not None.
        assert args.describe is not None
        text = describe(args.describe)
    sys.stdout.write(text)
    return ExitCode.OK


#: Namespace attrs the --graph guard must not reject (its own flags,
#: earlier-dispatched help/version, and files -- guarded separately).
_GRAPH_EXEMPT: Final[frozenset[str]] = frozenset(
    {"graph", "graph_format", "help", "version", "files"}
)


def _run_graph(args: argparse.Namespace) -> int:
    """
    Run ``--graph`` (port-only, eval-free, read-only).

    Rejects any other flag via the default-Namespace diff (so future flags
    auto-reject), carries its own single-file guard -- it dispatches before
    _resolve_options and cannot inherit the generic len(files) check -- and
    refuses a trailing-``|`` pipe path like --lint. Parses one config with
    parse_to_block, builds the graph, and renders d2 (default) or DOT.
    """
    _reject_other_flags(args, mode="--graph", exempt=_GRAPH_EXEMPT)
    if len(args.files) != 1:
        raise FermError("ferm --graph requires exactly one input file")
    block = _parse_config_eval_free(args.files[0], mode="--graph")
    graph = collect_graph(block)
    fmt = args.graph_format or "d2"
    text = render_dot(graph) if fmt == "dot" else render_d2(graph)
    sys.stdout.write(text)
    return ExitCode.OK


def main(argv: list[str] | None = None) -> int:
    """Run the ferm CLI (Perl's top-level program, ``:620-819``)."""
    # before any write: argparse renders usage/errors through these streams
    reconfigure_latin1(sys.stdout, errors=HUMAN_STREAM_ERRORS)
    reconfigure_latin1(sys.stderr, errors=HUMAN_STREAM_ERRORS)
    try:
        return _main(argv)
    except FermError as exc:
        sys.stderr.write(f"{exc}\n")
        return ExitCode.ERROR


def _main(argv: list[str] | None = None) -> int:
    """Run the flow proper; :func:`main` renders any :class:`FermError`."""
    # Normalise argv before anything else: production entry (``main()`` /
    # console-script / frozen binary) calls ``_main(None)``, so the rollback
    # subcommand would be dead without reading ``sys.argv`` here.
    argv = sys.argv[1:] if argv is None else argv

    # ``rollback`` is a git-style subcommand: match the first token before the
    # main parser, whose ``files nargs="*"`` would otherwise swallow it.  A
    # config literally named ``rollback`` is passed as ``./rollback``.
    if argv and argv[0] == "rollback":
        return _rollback_main(argv[1:])

    args = _build_parser().parse_args(argv)

    if args.help:
        sys.stdout.write(HELP_TEXT)
        return ExitCode.OK
    if args.version:
        printversion()
        return ExitCode.OK

    # Introspection is a terminal read-only mode: dispatch before
    # _resolve_options so no apply-path validation (tty, timeout) runs.
    if args.list_modules or args.describe is not None:
        return _run_introspection(args)

    # --graph is a terminal read-only mode at the same seam as introspection.
    if args.graph_format is not None and not args.graph:
        raise FermError("ferm --graph-format requires --graph")
    if args.graph:
        return _run_graph(args)

    options = _resolve_options(args)

    if len(args.files) != 1:
        sys.stdout.write(HELP_TEXT)
        return ExitCode.ERROR

    # Eval-free lint must dispatch before any eval/kernel/previous-ruleset
    # I/O -- unlike --plan, which runs post-eval inside _apply_config.
    if args.lint:
        if args.lint_fail_level is not None:
            fail_level: Severity | None = Severity[
                args.lint_fail_level.upper()
            ]
        elif args.lint_strict:
            fail_level = Severity.WARNING
        else:
            fail_level = None
        return _run_lint(args.files[0], fail_level=fail_level)

    lines_stream, restore_streams = _setup_streams(options)
    try:
        return _run(args, options, lines_stream)
    finally:
        restore_streams()


def build_plan(
    domains: dict[Family, DomainInfo],
    options: Options,
    backend: Backend,
    *,
    validate: bool = True,
) -> Plan:
    """
    Construct the desired-vs-kernel :class:`Plan` -- pure, no I/O.

    Shared by ``--plan`` (:func:`_run_plan`) and the etckeeper commit-message
    builder, so both describe the applied delta identically.  Runs no hooks
    and never prints or commits.

    Under iptables the desired side comes from ``rules_to_save`` and both
    sides are parsed with ``parse_save``.  Under nft the desired side is
    rendered by the backend and both sides are parsed with the nft parsers;
    ``noflush`` is always ``False`` under nft because the append-only model
    differs fundamentally from the iptables ``--noflush`` semantics.

    ``validate`` runs the ``nft -c`` pre-check on the rendered desired script;
    the commit-message path passes ``False`` because the rules are already
    applied, so a second check is pointless and could raise post-apply.
    """
    plan = Plan()
    for domain in sorted(domains):
        domain_info = domains[domain]
        if not domain_info.enabled:
            continue
        if options.nft:
            # Reaching here with noflush is a logic error: _resolve_options
            # already rejects --plan --noflush --nft before this is called.
            if options.noflush:
                raise internal_error(
                    "build_plan: noflush set under --plan --nft"
                )
            family = domain.nft_name
            current = parse_nft_list(domain_info.previous or "", family=family)
            rendered = backend.render(domain, domain_info, options)
            try:
                desired_save = rendered.save
                if desired_save is None:
                    raise internal_error("nft render returned no save text")
                if validate:
                    _validate_desired_nft(
                        options, domain_info.tools[TOOL_NFT], desired_save
                    )
                desired = parse_nft_script(desired_save)
                plan.families[domain] = diff_tables(
                    current, desired, noflush=False
                )
            finally:
                rendered.close()
        else:
            if domain_info.plan_unsupported:
                plan.unsupported.append(domain)
                continue
            host_mask = "/32" if domain == "ip" else "/128"
            validate_names(domain_info)
            desired_text = rules_to_save(domain, domain_info, options)
            current_text = domain_info.previous or ""
            current = parse_save(current_text, host_mask=host_mask)
            desired = parse_save(desired_text, host_mask=host_mask)
            plan.families[domain] = diff_tables(
                current, desired, noflush=options.noflush
            )
    return plan


def _run_plan(
    domains: dict[Family, DomainInfo], options: Options, backend: Backend
) -> int:
    """
    Build and print the read-only plan; return the detailed exit code.

    Returns 0 (no changes) or 2 (changes); a ``FermError`` raised on the way
    (e.g. a strict save-read failure or an unsupported construct under nft)
    still exits 1 via :func:`main`.
    """
    plan = build_plan(domains, options, backend)
    sys.stdout.write(render_plan(plan, fmt=options.plan_format))
    return ExitCode.CHANGES if plan.has_changes() else ExitCode.OK


def _commit_subject(
    filename: str, domains: dict[Family, DomainInfo], options: Options
) -> str:
    """Build the default commit subject from the applied options."""
    verb = "flushed" if options.flush else "applied"
    families = " ".join(
        domain for domain in sorted(domains) if domains[domain].enabled
    )
    descriptors = [families] if families else []
    descriptors.append("nft" if options.nft else "iptables")
    if not options.fast:
        descriptors.append("slow")
    return f"{verb} {splitpath_file(filename)} ({', '.join(descriptors)})"


def _commit_body(plan: Plan) -> str:
    """Render the per-family semantic delta for the commit-message body."""
    lines = [
        f"  {family}: {summary_line(plan.families[family])}"
        for family in sorted(plan.families)
        if plan.families[family].has_changes()
    ]
    return "\n".join(lines)


def _build_commit_message(
    filename: str,
    domains: dict[Family, DomainInfo],
    options: Options,
    backend: Backend,
    subject: str | None,
) -> str:
    """
    Compose the etckeeper commit message (subject + semantic body).

    The body comes from :func:`build_plan` with ``validate=False`` -- the
    rules are already applied, so re-running ``nft -c`` is pointless and could
    raise post-apply.  If building the plan fails, degrade to a subject-only
    message rather than skipping the commit.
    """
    head = (
        subject
        if subject is not None
        else _commit_subject(filename, domains, options)
    )
    try:
        plan = build_plan(domains, options, backend, validate=False)
    except FermError:
        return f"ferm: {head}"
    body = _commit_body(plan)
    return f"ferm: {head}\n\n{body}" if body else f"ferm: {head}"


def _commit_history(
    filename: str,
    domains: dict[Family, DomainInfo],
    options: Options,
    backend: Backend,
    subject: str | None,
) -> None:
    """
    Commit the applied ruleset to ``/etc`` history via etckeeper (best-effort).

    Gated to a real apply that touched the kernel (not ``--noexec``/``--plan``/
    ``--test``) with etckeeper present and not disabled.  Skips silently when
    ``/etc`` has nothing to commit (a reboot/reload/idempotent re-run).  A
    failure here never disturbs the installed firewall.

    Scope caveat: etckeeper commits the WHOLE ``/etc`` tree, so an unrelated
    ``/etc`` edit left uncommitted at apply time is swept into this ferm-
    subjected commit.  The subject/body describe only the ferm delta; the
    recorded tree change may be broader.  This is inherent to etckeeper's
    "snapshot all of /etc" model, not a per-file commit.
    """
    if (
        options.noexec
        or options.plan
        or options.test
        or not options.etckeeper
        or etckeeper.find_etckeeper() is None
    ):
        return
    # Best-effort: the firewall is already applied, so no failure recording
    # history may propagate and flip the apply exit code.  A blanket guard
    # (Exception, not BaseException, so SystemExit/KeyboardInterrupt still
    # pass through) covers the status check, the plan rebuild and the commit.
    try:
        if not etckeeper.working_tree_dirty():
            return
        etckeeper.commit(
            _build_commit_message(filename, domains, options, backend, subject)
        )
    except Exception as exc:  # noqa: BLE001 -- never fail an applied firewall
        sys.stderr.write(f"ferm: etckeeper commit skipped: {exc}\n")


def _apply_config(
    config: str,
    options: Options,
    lines_stream: TextIO,
    *,
    defs: list[str],
    subject: str | None = None,
) -> int:
    """
    Parse and apply ``config`` with the streams already set up.

    Shared by the normal apply path (:func:`_run`) and the rollback re-apply
    (:func:`_rollback_main`).  ``subject`` overrides the etckeeper commit
    subject -- the rollback path passes ``rolled back to <sha>`` so the history
    records the revert rather than a plain ``applied``.
    """
    filename = config
    execute, emit_line, read_save, restore, capture = _make_io(
        options, lines_stream
    )

    # Scope: the global frame (Perl ``:618``) holds --def vars; the script
    # frame (Perl ``:751``) sits above it and carries the auto-variables.
    scope = Scope()
    scope.push(Frame())

    # --def is evaluated before the script exists (Perl runs it inside
    # GetOptions, ``:662``): plain values bind on the global frame, while
    # script-context built-ins abort, exactly as the oracle does.
    def_evaluator = Evaluator(Tokenizer(None), scope)
    for spec in defs:
        # argv is decoded by the interpreter before ferm runs; re-read it as
        # raw bytes so --def follows the same latin-1 model as every other
        # input boundary (and never overflows save.encode("latin-1")).
        _apply_def(def_evaluator, argv_to_latin1(spec))

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

    backend = _select_backend(options)

    def capture_previous(domain: Family, domain_info: DomainInfo) -> None:
        # Folds backend + options + execute + read_save into the
        # two-parameter shape initialize_domain expects.
        backend.capture_previous(
            domain,
            domain_info,
            options,
            execute=execute,
            read_save=read_save,
            capture=capture,
        )

    parser = Parser(
        evaluator,
        {},
        options,
        resolve_tools=backend.tool_names,
        capture_previous=capture_previous,
        emit_line=emit_line,
        shell_snapshot=backend.shell_snapshot,
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
    if len(scope.stack) != BALANCED_STACK_DEPTH:
        raise internal_error("parser left the scope stack unbalanced")

    domains = parser.domains

    if options.plan:
        return _run_plan(domains, options, backend)

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
                    snapshot = backend.shell_snapshot(domain, domains[domain])
                    if snapshot is None:
                        continue
                    emit_line(snapshot.restore)
                notice = backend.shell_rollback_notice()
                if notice is not None:
                    emit_line(notice)

            if not options.noexec and not _confirm_rules(options):
                _rollback_all(
                    domains, options, backend, execute=execute, restore=restore
                )

        # Record the applied ruleset in /etc history (best-effort, port-only).
        # Reached only on success: both rollback paths raise SystemExit above,
        # so no "did it roll back" flag is needed (or available).
        _commit_history(filename, domains, options, backend, subject)
    finally:
        for info in domains.values():
            info.close()

    return ExitCode.OK


def _run(
    args: argparse.Namespace, options: Options, lines_stream: TextIO
) -> int:
    """Apply the parsed CLI invocation via :func:`_apply_config`."""
    return _apply_config(args.files[0], options, lines_stream, defs=args.defs)


def _build_rollback_parser() -> argparse.ArgumentParser:
    """
    Build the parser for the ``ferm rollback`` subcommand.

    It carries the backend/mode/tool switches the re-apply must inherit (an
    nft install must roll back under nft, not silently fall to iptables; a
    ``--nolegacy`` install must keep avoiding the ``*-legacy`` tools, or the
    re-apply picks a different tool family and can fail), but never
    ``--shell``/``--noexec``/``--test``: a rollback must really apply the
    reverted config, or the worktree and the kernel would disagree.

    ``--def`` is inherited too: a config referencing a command-line variable
    would otherwise raise ``undefined variable`` on re-apply (the worktree is
    already reverted by then), leaving config and kernel out of step.
    ``add_help=True`` so ``ferm rollback --help`` prints usage rather than an
    "unrecognized arguments" error.
    """
    parser = argparse.ArgumentParser(
        prog="ferm rollback", add_help=True, allow_abbrev=False
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--list", action="store_true")
    target.add_argument("--to", metavar="SHA")
    parser.add_argument("--nft", action="store_true")
    parser.add_argument("--slow", action="store_true")
    parser.add_argument("--full-reload", action="store_true")
    parser.add_argument("--nolegacy", action="store_true")
    parser.add_argument("-i", "--interactive", action="store_true")
    parser.add_argument("-t", "--timeout", type=int, default=30)
    parser.add_argument("--domain")
    parser.add_argument("--def", dest="defs", action="append", default=[])
    parser.add_argument("--no-etckeeper", action="store_true")
    parser.add_argument("config", nargs="?")
    return parser


def _rollback_options(args: argparse.Namespace) -> Options:
    """Derive the inherited apply options for a rollback re-apply."""
    if args.full_reload and not args.nft:
        raise FermError("ferm --full-reload has no sense without --nft")
    # Same tty guard as _resolve_options: both rollback forms (bare and
    # --to) reach _apply_config -> _confirm_rules, and the bare form's
    # own tty check in _rollback_to only fires for its history
    # confirmation, not for the interactive-apply prompt further down --
    # without this, a non-tty --interactive rollback checks out the reverted
    # config and rolls back the kernel before failing, leaving the worktree
    # on the old config while the kernel still runs the pre-rollback rules.
    if args.interactive and not sys.stdin.isatty():
        raise FermError(
            "ferm interactive mode not possible: /dev/stdin is not a tty"
        )
    if args.interactive and not sys.stderr.isatty():
        raise FermError(
            "ferm interactive mode not possible: /dev/stderr is not a tty"
        )
    return Options(
        fast=not args.slow,
        interactive=args.interactive,
        timeout=args.timeout,
        domain=args.domain,
        nft=args.nft,
        full_reload=args.full_reload,
        nolegacy=args.nolegacy,
        etckeeper=not args.no_etckeeper,
    )


def _rollback_main(argv: list[str]) -> int:
    """
    Run the ``ferm rollback`` subcommand (git-only).

    ``--list`` prints the config's history; ``--to <sha>`` reverts to an exact
    revision; the bare form reverts one ferm revision back after showing the
    delta and asking for confirmation.  Every form re-applies the reverted
    config so the kernel matches and the revert is recorded as a new commit.
    """
    args = _build_rollback_parser().parse_args(argv)
    options = _rollback_options(args)
    config = args.config if args.config is not None else _DEFAULT_CONFIG

    if not etckeeper.rollback_available():
        raise FermError(
            "ferm rollback requires an etckeeper repository managed by git"
        )
    subpath = etckeeper.repo_relative_subpath(config)

    if args.list:
        sys.stdout.write(etckeeper.list_history(subpath))
        return ExitCode.OK

    if args.to is not None:
        return _rollback_to(
            args.to, config, subpath, options, defs=args.defs, confirm=False
        )

    sha = etckeeper.previous_revision(subpath)
    return _rollback_to(
        sha, config, subpath, options, defs=args.defs, confirm=True
    )


def _rollback_to(
    sha: str,
    config: str,
    subpath: str,
    options: Options,
    *,
    defs: list[str],
    confirm: bool,
) -> int:
    """
    Revert ``config`` to ``sha`` and re-apply it (the shared safe path).

    Refuses first if the worktree has uncommitted changes (``checkout`` would
    clobber them) -- this guard runs BEFORE the confirmation prompt so the
    operator is not asked to confirm a rollback that will then be rejected.
    The bare form (``confirm=True``) then shows the delta and requires a ``y``
    answer on a tty.  Both forms re-apply with the inherited options, the
    inherited ``--def`` overrides and a ``rolled back to <sha>`` commit
    subject.
    """
    if etckeeper.working_tree_dirty(subpath):
        raise FermError(
            f"{config} has uncommitted changes; commit or stash them before "
            "rolling back (checkout would overwrite them)"
        )

    if confirm:
        if not sys.stdin.isatty():
            raise FermError(
                "refusing to roll back without confirmation on a non-tty; "
                "re-run with --to <sha>"
            )
        sys.stderr.write(etckeeper.diff_revision(sha, subpath))
        sys.stderr.write(f"\nRoll back {config} to {sha}? [y/N] ")
        sys.stderr.flush()
        answer = sys.stdin.readline().strip().lower()
        if answer not in ("y", "yes"):
            sys.stderr.write("Rollback cancelled.\n")
            return ExitCode.OK

    etckeeper.rollback(sha, subpath)
    lines_stream, restore_streams = _setup_streams(options)
    try:
        return _apply_config(
            config,
            options,
            lines_stream,
            defs=defs,
            subject=f"rolled back to {sha}",
        )
    finally:
        restore_streams()
