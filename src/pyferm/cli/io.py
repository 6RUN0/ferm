"""
Streams, the injected I/O seam and the backend plumbing.

The effectful helpers of the apply path: the ``LINES``/``STDOUT`` handle
plumbing (``reference/src/ferm:738-739``), ``execute_command``
(``:2894``) and the ``*-save`` reader bound into :class:`IoCallables`,
the ``@hook`` runner (``:777-794``), backend selection, and the nft
validation/apply subprocess wrappers.
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess  # live-only: run rules / hooks / *-save / *-restore
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, TextIO

from ..backend.iptables import IptablesBackend, restore_domain
from ..backend.nft import TOOL_NFT, NftBackend
from ..errors import ExitCode, FermError
from ..streams import BYTE_ENCODING, HUMAN_STREAM_ERRORS

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Iterator

    from ..backend.base import (
        Backend,
        ExecuteCapture,
        ExecuteCommand,
        LineEmitter,
        RestoreDomain,
        SaveReader,
    )
    from ..config import Options
    from ..domains import DomainInfo, Family


# contains shell metacharacters (perl doio.c, Perl_do_exec3); otherwise it
# splits on whitespace and execs the first word directly.  The extra
# Perl-side refinements (a trailing "2>&1", a trailing newline) force the
# shell here too -- both contain metacharacters from this set -- which only
# swaps an exec for an equivalent shell run.
_SHELL_META: Final[str] = "$&*(){}[]'\";\\|?<>~`\n"
_VAR_ASSIGN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z]*=")


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


@contextlib.contextmanager
def _shell_streams(options: Options) -> Generator[TextIO]:
    """Scope :func:`_setup_streams` to a ``with`` block (restore on exit)."""
    lines_stream, restore = _setup_streams(options)
    try:
        yield lines_stream
    finally:
        restore()


@dataclass(frozen=True)
class IoCallables:
    """The injected I/O seam bound to one Options/lines_stream pair."""

    execute: ExecuteCommand
    emit_line: LineEmitter
    read_save: SaveReader
    restore: RestoreDomain
    capture: ExecuteCapture


def _make_io(options: Options, lines_stream: TextIO) -> IoCallables:
    """
    Build the five injected I/O callables bound to ``options``.

    Returns an :class:`IoCallables` of ``(execute, emit_line, read_save,
    restore, capture)``.  ``execute`` is the port of ``execute_command``
    (``:2894``); ``emit_line`` is the ``print LINES`` sink (raw, caller
    supplies newlines) writing to ``lines_stream`` from
    :func:`_setup_streams`; ``read_save`` runs a ``*-save`` tool and
    ``capture`` runs a command capturing its stdout (the nft backend's
    snapshot seam) -- both consumed by ``_run``'s ``capture_previous``
    closure over :meth:`pyferm.backend.base.Backend.capture_previous`;
    ``restore`` adapts the backend's three-argument
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
                env=_nft_env(),
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

    return IoCallables(
        execute=execute,
        emit_line=emit_line,
        read_save=read_save,
        restore=restore,
        capture=capture,
    )


def _select_backend(options: Options) -> Backend:
    """Pick the backend: nft is opt-in, iptables the default."""
    return NftBackend() if options.nft else IptablesBackend()


def _run_failed(path: str, exc: OSError) -> FermError:
    """Build the spawn-failure error shared by both nft call sites below."""
    return FermError(f"Failed to run {path}: {exc}")


def _nft_env() -> dict[str, str]:
    """
    Environment for every nft subprocess: the inherited env pinned to UTC.

    nft converts a ``meta hour``/``meta time`` literal between local time and
    the UTC the kernel stores using the process ``TZ`` on both parse and
    print.  Pinning ``TZ=UTC`` makes the backend's emitted clock mean exactly
    what xt_time (without --kerneltz) means -- UTC -- and keeps the ``--plan``
    readback diff-free on any host regardless of its zone or DST state.
    """
    return {**os.environ, "TZ": "UTC"}


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
            env=_nft_env(),
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
                env=_nft_env(),
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


def _enabled_domains(
    domains: dict[Family, DomainInfo],
) -> Iterator[tuple[Family, DomainInfo]]:
    """Yield ``(domain, info)`` for enabled domains in sorted order."""
    for domain in sorted(domains):
        info = domains[domain]
        if info.enabled:
            yield domain, info
