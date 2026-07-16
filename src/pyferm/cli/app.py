"""
The CLI dispatcher: :func:`main` and the mode dispatch in :func:`_main`.

Perl's top-level program (``reference/src/ferm:620-819``): help/version
banners, the rollback subcommand, the terminal read-only modes, option
resolution and the apply path.
"""

from __future__ import annotations

import sys

from ..analysis import Severity
from ..errors import ExitCode, FermError
from ..streams import reconfigure_std_streams
from .apply import _run
from .io import _shell_streams
from .modes import _run_graph, _run_introspection, _run_lint
from .options import HELP_TEXT, _build_parser, _resolve_options, printversion
from .rollback import _rollback_main


def main(argv: list[str] | None = None) -> int:
    """Run the ferm CLI (Perl's top-level program, ``:620-819``)."""
    # before any write: argparse renders usage/errors through these streams
    reconfigure_std_streams()
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

    with _shell_streams(options) as lines_stream:
        return _run(args, options, lines_stream)
