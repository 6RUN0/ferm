"""
The apply orchestration: parse, commit per family, confirm, roll back.

The main flow of ``reference/src/ferm`` (``:751-819``) plus
``confirm_rules`` (``:3189``) and the rollback loop (``:3147``).  The
orchestration across domains (apply all -> ``confirm_rules`` -> roll
back all, with the closing message and ``exit 1``) is the cli's job,
not the backend's -- a sanctioned deviation (#3); ``--interactive`` is
realised with :mod:`signal` rather than Perl's ``alarm`` (#5).
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Final, TextIO

from ..errors import ExitCode, internal_error
from ..functions import Evaluator, splitpath_dir, splitpath_file
from ..parser import Parser
from ..resolver import pick_resolver, set_resolver_provider
from ..scope import Frame, Scope
from ..streams import BYTE_ENCODING, argv_to_latin1
from ..tokenizer import Tokenizer, open_script
from .history import _commit_history, _run_plan
from .io import _enabled_domains, _make_io, _run_hook, _select_backend
from .options import _apply_def

if TYPE_CHECKING:
    import argparse

    from ..backend.base import (
        Backend,
        ExecuteCommand,
        LineEmitter,
        RestoreDomain,
    )
    from ..config import Options
    from ..domains import DomainInfo, Family
    from ..tokenizer import Script


#: A clean run leaves exactly two scope frames on the stack: the global
#: frame plus the top-level script frame.  Anything else is an internal bug.
BALANCED_STACK_DEPTH: Final[int] = 2


class _RolledBackExit(SystemExit):
    """
    The exit raised once :func:`_rollback_all` restored every family.

    A distinct type so the rollback subcommand can tell "the kernel is
    back on the pre-apply rules" (and restore the reverted worktree
    too) from the exec-failure ``SystemExit`` in :mod:`.io`, which
    deliberately skips the kernel rollback (Perl ``:2903-2905``) and
    leaves the kernel state unknown.
    """


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
    :meth:`Backend.rollback`; the orchestration is here.  Never returns:
    raises :class:`_RolledBackExit`.
    """
    for domain, domain_info in _enabled_domains(domains):
        backend.rollback(
            domain,
            domain_info,
            options,
            execute=execute,
            restore=restore,
        )
    sys.stderr.write("\nFirewall rules rolled back.\n")
    raise _RolledBackExit(ExitCode.ERROR)


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


def _emit_shell_confirmation(
    backend: Backend,
    domains: dict[Family, DomainInfo],
    options: Options,
    emit_line: LineEmitter,
) -> None:
    """
    Emit the ``--shell`` interactive confirm/rollback script (``:803-817``).

    Writes the confirm prompt, the ``sleep`` window, each family's rollback
    snapshot, and the backend's closing notice, in that order.
    """
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
    (:func:`_rollback_main`).  ``subject`` overrides the etckeeper
    commit-subject head -- the rollback path passes ``roll back <config>
    to <sha>`` so the history records the revert rather than a plain
    ``apply``.
    """
    filename = config
    io = _make_io(options, lines_stream)

    # Scope: the global frame (Perl ``:618``) holds --def vars; the script
    # frame (Perl ``:751``) is pushed on top of it (innermost) and carries
    # the auto-variables.
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
            execute=io.execute,
            read_save=io.read_save,
            capture=io.capture,
        )

    parser = Parser(
        evaluator,
        {},
        options,
        resolve_tools=backend.tool_names,
        capture_previous=capture_previous,
        emit_line=io.emit_line,
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
            _run_hook(command, options, io.emit_line)

        for domain, domain_info in _enabled_domains(domains):
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
                    execute=io.execute,
                    emit_line=io.emit_line,
                    restore=io.restore,
                )
            finally:
                rendered.close()
            if result is not None:
                status = result

        for command in [*parser.post_hooks, *parser.flush_hooks]:
            _run_hook(command, options, io.emit_line)

        def _rollback() -> None:
            _rollback_all(
                domains,
                options,
                backend,
                execute=io.execute,
                restore=io.restore,
            )

        if status is not None:
            _rollback()

        # Ask the user, and roll back without confirmation (``:803-817``).
        if options.interactive:
            if options.shell:
                _emit_shell_confirmation(
                    backend, domains, options, io.emit_line
                )

            if not options.noexec and not _confirm_rules(options):
                _rollback()

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
