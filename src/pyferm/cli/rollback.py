"""
The ``ferm rollback`` subcommand (port-only, etckeeper-backed).

Reverts a config to a recorded revision and re-applies it with the
inherited backend/mode switches, so the kernel matches the reverted
worktree and the revert is recorded as a new history commit.
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Final

from .. import etckeeper
from ..cli_doc import rollback_help
from ..config import Options
from ..errors import ExitCode, FermError
from ..functions import splitpath_file
from .apply import _apply_config, _RolledBackExit
from .io import _shell_streams
from .options import _require_interactive_tty

#: The config ``ferm rollback`` defaults to when none is named on the command
#: line -- the standard system path.
_DEFAULT_CONFIG: Final[str] = "/etc/ferm/ferm.conf"


#: Strictly the hex sha ``--list`` prints (4-40 hex digits).  The
#: generic etckeeper validator deliberately admits '/' and '.' (branch
#: names) -- through it, ``--diff /path/to/conf`` would swallow a config
#: path and die with a raw git error instead of a hint.
_DIFF_SHA_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-fA-F]{4,40}\Z")

#: ``--diff`` without a value: distinct from the ``default`` (None) so
#: "flag absent" and "flag present, no SHA" stay distinguishable.
_DIFF_PREVIOUS: Final[str] = ""


def _hex_sha(text: str) -> str:
    """Argparse type for ``--diff``: only a hex SHA, with a hint."""
    if text == _DIFF_PREVIOUS:
        # argparse pipes a str const through type= too (nargs="?"):
        # the bare-form sentinel must pass unharmed.
        return text
    if not _DIFF_SHA_RE.match(text):
        raise argparse.ArgumentTypeError(
            f"invalid SHA {text!r}: take the SHA from"
            " 'ferm rollback --list'; the config file is a separate"
            " argument -- name it first ('ferm rollback CONFIG --diff')"
            " or use '--diff= CONFIG'"
        )
    return text


def _positive_int(text: str) -> int:
    """
    Argparse type for ``--limit``: an integer >= 1.

    git itself is silent on bad values (``-n 0`` prints nothing,
    negatives are ignored), so the CLI must reject them loudly.
    """
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid limit {text!r}: must be an integer >= 1"
        ) from None
    if value < 1:
        raise argparse.ArgumentTypeError(
            f"invalid limit {value}: must be >= 1"
        )
    return value


def _mark_current(history: str) -> str:
    """
    Append `` (current)`` to the first history line.

    The first path-scoped entry is the config's current state -- the
    same semantics ``previous_revision`` builds on.  An empty history
    is returned unchanged.
    """
    head, sep, tail = history.partition("\n")
    if not head:
        return history
    return f"{head} (current){sep}{tail}"


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
    target.add_argument(
        "--list", action="store_true", help=rollback_help("list")
    )
    target.add_argument(
        "--diff",
        nargs="?",
        const=_DIFF_PREVIOUS,
        default=None,
        type=_hex_sha,
        metavar="SHA",
        help=rollback_help("diff"),
    )
    target.add_argument("--to", metavar="SHA", help=rollback_help("to"))
    parser.add_argument(
        "-n",
        "--limit",
        type=_positive_int,
        metavar="N",
        default=None,
        help=rollback_help("limit"),
    )
    parser.add_argument(
        "--nft", action="store_true", help=rollback_help("nft")
    )
    parser.add_argument(
        "--slow", action="store_true", help=rollback_help("slow")
    )
    parser.add_argument(
        "--full-reload",
        action="store_true",
        help=rollback_help("full_reload"),
    )
    parser.add_argument(
        "--nolegacy", action="store_true", help=rollback_help("nolegacy")
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help=rollback_help("interactive"),
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=30,
        help=rollback_help("timeout"),
    )
    parser.add_argument("--domain", help=rollback_help("domain"))
    parser.add_argument(
        "--def",
        dest="defs",
        action="append",
        default=[],
        help=rollback_help("defs"),
    )
    parser.add_argument(
        "--no-etckeeper",
        action="store_true",
        help=rollback_help("no_etckeeper"),
    )
    parser.add_argument("config", nargs="?", help=rollback_help("config"))
    return parser


def _rollback_options(args: argparse.Namespace) -> Options:
    """Derive the inherited apply options for a rollback re-apply."""
    if args.full_reload and not args.nft:
        raise FermError("ferm --full-reload has no sense without --nft")
    # Same tty guard as _resolve_options: both rollback forms (bare and
    # --to) reach _apply_config -> _confirm_rules, and the bare form's
    # own tty check in _rollback_to only fires for its history
    # confirmation, not for the interactive-apply prompt further down --
    # without this, a non-tty --interactive rollback would revert the
    # worktree and install the old rules only to fail the confirm read
    # and immediately undo both (the kernel via _rollback_all, the
    # worktree via _restore_worktree): pure churn on a live firewall.
    _require_interactive_tty(args.interactive)
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
    if args.limit is not None and not args.list:
        raise FermError("ferm rollback --limit has no sense without --list")
    options = _rollback_options(args)
    config = args.config if args.config is not None else _DEFAULT_CONFIG

    if not etckeeper.rollback_available():
        raise FermError(
            "ferm rollback requires an etckeeper repository managed by git"
        )
    subpath = etckeeper.repo_relative_subpath(config)

    if args.list:
        history = etckeeper.list_history(subpath, limit=args.limit)
        sys.stdout.write(_mark_current(history))
        return ExitCode.OK

    if args.diff is not None:
        sha = args.diff or etckeeper.previous_revision(subpath)
        sys.stdout.write(etckeeper.diff_revision(sha, subpath))
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
    inherited ``--def`` overrides and a ``roll back <config> to <sha>``
    commit-subject head.

    When the interactive re-apply is declined or times out, the kernel is
    already back on the pre-rollback rules (:class:`_RolledBackExit`), so the
    reverted worktree is restored too -- otherwise the config would sit on the
    old revision, uncommitted, disagreeing with the kernel and blocking the
    next rollback behind the dirty-worktree guard.  Other re-apply failures
    (a :class:`FermError`, an exec-failure exit) leave the worktree reverted:
    the kernel state is not known to be pre-rollback there, so a restore
    could just as well introduce the divergence it means to prevent.
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
    try:
        with _shell_streams(options) as lines_stream:
            return _apply_config(
                config,
                options,
                lines_stream,
                defs=defs,
                subject=f"roll back {splitpath_file(config)} to {sha}",
            )
    except _RolledBackExit:
        _restore_worktree(config, subpath)
        raise


#: What a failed re-apply restores the worktree to.  The dirty guard in
#: :func:`_rollback_to` has already proven the worktree clean, so the
#: committed state IS the pre-revert state.
_CURRENT_REVISION: Final[str] = "HEAD"


def _restore_worktree(config: str, subpath: str) -> None:
    """
    Put the reverted config back after the kernel was rolled back.

    The counterpart of the revert in :func:`_rollback_to` for the
    declined/timed-out interactive re-apply.  A failing restore must not
    mask the exit in flight: it warns and leaves the divergence to the
    operator.
    """
    try:
        etckeeper.rollback(_CURRENT_REVISION, subpath)
    except FermError as exc:
        sys.stderr.write(
            f"ferm: could not restore {config} after the aborted rollback:"
            f" {exc}\n"
            f"ferm: {config} is left at the reverted revision, uncommitted\n"
        )
        return
    sys.stderr.write(
        f"Rollback of {config} aborted; the config file was restored to"
        " match the running rules.\n"
    )
