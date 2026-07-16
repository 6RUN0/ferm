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

from .app import _main, main
from .apply import _apply_config, _confirm_rules, _rollback_all
from .history import (
    _build_commit_message,
    _commit_history,
    _commit_subject,
    _run_plan,
    build_plan,
)
from .io import (
    _make_io,
    _make_nft_restore,
    _run_hook,
    _select_backend,
    _setup_streams,
    _validate_desired_nft,
)
from .options import HELP_TEXT, _build_parser, _resolve_options, printversion
from .rollback import _build_rollback_parser, _rollback_main, _rollback_options

__all__ = [
    "HELP_TEXT",
    "_apply_config",
    "_build_commit_message",
    "_build_parser",
    "_build_rollback_parser",
    "_commit_history",
    "_commit_subject",
    "_confirm_rules",
    "_main",
    "_make_io",
    "_make_nft_restore",
    "_resolve_options",
    "_rollback_all",
    "_rollback_main",
    "_rollback_options",
    "_run_hook",
    "_run_plan",
    "_select_backend",
    "_setup_streams",
    "_validate_desired_nft",
    "build_plan",
    "main",
    "printversion",
]
