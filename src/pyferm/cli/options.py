"""
Option parsing: argv to the settled :class:`pyferm.config.Options`.

The ``GetOptions`` block and its ``%option`` derivation from
``reference/src/ferm`` (``:620-700``): the argument parser, the
help/version banners, the ``--lint`` conflict guards and the ``--def``
evaluation (Perl ``opt_def``).
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import TYPE_CHECKING, Final

from .. import __version__
from ..cli_doc import render_help
from ..config import Options, PlanFormat
from ..errors import FermError
from ..tokenizer import tokenize_string

if TYPE_CHECKING:
    from ..functions import Evaluator


#: Assembled from the cli_doc table at import time, so a new option
#: cannot be forgotten here -- name drift is structurally impossible.
#: Divergence from the Perl help is cosmetic: byte parity covers the
#: emitted rules, not the banner.
HELP_TEXT: Final[str] = render_help()

_TIMEOUT_RE: Final[re.Pattern[str]] = re.compile(r"^[+-]?\d+$")
# re.ASCII: --def specs arrive as latin-1 byte views, and Perl matches
# them with byte-mode \w ([A-Za-z0-9_]) -- Unicode \w would widen the
# accepted names.
_DEF_RE: Final[re.Pattern[str]] = re.compile(
    r"\$?(\w+)=(.*)", re.DOTALL | re.ASCII
)


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


def _require_interactive_tty(interactive: bool) -> None:
    """Raise unless both stdin and stderr are a tty when ``interactive``."""
    if interactive and not sys.stdin.isatty():
        raise FermError(
            "ferm interactive mode not possible: /dev/stdin is not a tty"
        )
    if interactive and not sys.stderr.isatty():
        raise FermError(
            "ferm interactive mode not possible: /dev/stderr is not a tty"
        )


def _reject_lint_conflicts(
    args: argparse.Namespace, plan_format: PlanFormat
) -> None:
    """
    Reject switches that clash with the terminal ``--lint`` mode.

    Raises :class:`FermError` with the oracle's verbatim messages for each
    apply/plan switch, ``--plan-format``, and the eval-dependent ``--def`` /
    ``--domain``.  The ``return Options()`` for the lint path stays with the
    caller in :func:`_resolve_options`.
    """
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
        raise FermError("ferm --lint cannot be combined with --plan-format")
    # eval-dependent flags: --def binds on the eval scope frame and
    # --domain filters during eval, so neither reaches parse_to_block --
    # accepting them silently would be a no-op.
    if args.defs:
        raise FermError("ferm --lint cannot be combined with --def")
    if args.domain is not None:
        raise FermError("ferm --lint cannot be combined with --domain")


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
        _reject_lint_conflicts(args, plan_format)
        return Options()

    noexec = args.noexec or args.test
    lines = args.lines or args.test or args.shell
    # The oracle derives interactive from the RAW --noexec switch (:679),
    # so --test alone does not suppress interactive mode.
    interactive = args.interactive and not args.noexec

    # guard order is the oracle's (ferm:691-698): tty guards first, then
    # timeout-needs-interactive, then the integer-shape check.
    _require_interactive_tty(interactive)
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
