"""
etckeeper integration: commit applied rulesets and roll config back.

Records applied rulesets in ``/etc`` history and rolls the ferm config back to
a prior revision.

A thin, stateless wrapper over the external ``etckeeper`` command (and, for
git-only operations, the ``etckeeper vcs`` passthrough).  Every call uses a
fixed :func:`subprocess.run` argv with no shell, so a revision or path is
never interpolated into a command line.

The commit side is VCS-agnostic and best-effort: a failure warns but never
disturbs the installed firewall.  The rollback side is git-only (etckeeper has
no portable "restore path X to revision Y" verb) and path-scoped to the ferm
config directory.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from pyferm.errors import FermError
from pyferm.streams import BYTE_ENCODING

#: How many path-scoped revisions to read to find the one before the current
#: state: the current config plus the previous one.
_PREVIOUS_DEPTH = 2

#: Safe alphabet for a user-supplied revision passed to git.  Branch and tag
#: names legitimately carry ``/``, ``.`` and ``-`` (e.g. ``origin/main``,
#: ``v1.2.3``, ``release-1``), so they stay in the whitelist; a leading ``-``
#: (flag injection) and a ``..`` sequence (commit range) are rejected
#: separately.  Extended revision syntax (``HEAD~3``, ``@{...}``) is out of
#: scope -- use ``--list`` to find the exact sha.
_REVISION_RE = re.compile(r"\A[A-Za-z0-9_./-]+\Z", re.ASCII)


def _validate_revision(sha: str) -> None:
    """
    Fail closed unless ``sha`` is a safe git revision identifier.

    The ``--`` separator and the leading-``-`` rejection block flag/pathspec
    injection; the ``..`` rejection blocks a commit range; the whitelist
    blocks shell metacharacters -- never reached (argv carries no shell), but
    a defence-in-depth border like the iptables name gate.
    """
    if sha.startswith("-"):
        raise FermError(f"invalid revision {sha!r}: leading '-' not allowed")
    if ".." in sha:
        raise FermError(f"invalid revision {sha!r}: range not allowed")
    if not _REVISION_RE.match(sha):
        raise FermError(f"invalid revision {sha!r}")


def _describe_failure(completed: subprocess.CompletedProcess[str]) -> str:
    """Return a one-line reason for a nonzero exit: stderr, else the code."""
    return (completed.stderr or "").strip() or f"exit {completed.returncode}"


def find_etckeeper() -> str | None:
    """Return the path to ``etckeeper``, or ``None`` (feature disabled)."""
    return shutil.which("etckeeper")


def commit(message: str) -> None:
    """
    Best-effort commit of all of ``/etc`` through the configured VCS.

    Never raises: ferm applying rules is the critical path, recording history
    is a side effect.  A spawn error or a nonzero exit writes a single warning
    line to stderr and returns ``None``.
    """
    try:
        completed = subprocess.run(
            ["etckeeper", "commit", message],
            capture_output=True,
            encoding=BYTE_ENCODING,
            check=False,
        )
    except OSError as exc:
        sys.stderr.write(f"ferm: etckeeper commit failed: {exc}\n")
        return
    if completed.returncode != 0:
        sys.stderr.write(
            f"ferm: etckeeper commit failed: {_describe_failure(completed)}\n"
        )


def _vcs(args: list[str], *, action: str) -> subprocess.CompletedProcess[str]:
    """
    Run ``etckeeper vcs <args>`` and return the completed process.

    ``action`` names the operation for error messages.  Raises
    :class:`FermError` on a spawn error; the caller decides how to treat a
    nonzero exit (read-only callers raise, :func:`rollback_available` does
    not).
    """
    try:
        return subprocess.run(
            ["etckeeper", "vcs", *args],
            capture_output=True,
            encoding=BYTE_ENCODING,
            check=False,
        )
    except OSError as exc:
        raise FermError(f"etckeeper vcs {action} failed: {exc}") from exc


def _stdout_or_raise(
    completed: subprocess.CompletedProcess[str], action: str
) -> str:
    """Return stdout for a clean read-only call, else raise ``FermError``."""
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip() or (
            f"etckeeper vcs {action} failed"
        )
        raise FermError(detail)
    return completed.stdout


def rollback_available() -> bool:
    """
    Return ``True`` when ``/etc`` is under etckeeper *and* the VCS is git.

    ``git rev-parse --show-toplevel`` succeeds only under git; hg/bzr/darcs
    fail it, so a clean exit doubles as the git probe.
    """
    try:
        completed = _vcs(["rev-parse", "--show-toplevel"], action="rev-parse")
    except FermError:
        return False
    return completed.returncode == 0


def repo_relative_subpath(config_path: str) -> str:
    """
    Return ``config_path``'s directory relative to the etckeeper repo root.

    Rollback is path-scoped to the ferm config directory inside the versioned
    ``/etc``.  ``git rev-parse --show-toplevel`` gives the root; a config that
    lives outside the repository yields a ``..`` escape, which is rejected --
    rolling back outside the versioned tree is unsupported.
    """
    completed = _vcs(["rev-parse", "--show-toplevel"], action="rev-parse")
    root = _stdout_or_raise(completed, "rev-parse").strip()
    config_dir = Path(config_path).resolve().parent
    relative = os.path.relpath(config_dir, root)
    if relative == ".." or relative.startswith(".." + os.sep):
        raise FermError(
            f"ferm config {config_path!r} is outside the etckeeper "
            "repository; rollback is unsupported there"
        )
    # A config sitting directly at the repo root makes ``relpath`` return
    # ``"."``: a path-scoped rollback would then pass ``.`` to ``checkout``
    # and ``clean -f -d``, reverting and deleting across the WHOLE versioned
    # tree (all of ``/etc``), not just the ferm config.  Refuse it -- rollback
    # must be scoped to a subdirectory.
    if relative in (os.curdir, ""):
        raise FermError(
            f"ferm config {config_path!r} sits at the etckeeper repository "
            "root; a path-scoped rollback would revert and clean the entire "
            "tree. Place the config in a subdirectory (e.g. /etc/ferm/)."
        )
    return relative


def list_history(config_subpath: str) -> str:
    """Return ``git log --oneline`` scoped to the ferm config (read-only)."""
    completed = _vcs(["log", "--oneline", "--", config_subpath], action="log")
    return _stdout_or_raise(completed, "log")


def previous_revision(config_subpath: str) -> str:
    """
    Return the sha of the previous ferm revision (read-only).

    The SECOND entry of the path-scoped history: the first is the config's
    current state.  This is deliberately not ``HEAD~1`` -- unrelated etckeeper
    commits and consecutive ferm applies land between ferm revisions, so the
    "previous config" is counted along the config's own history, not the tip
    of ``/etc``.  A single revision (nothing to roll back to) raises.
    """
    completed = _vcs(
        [
            "log",
            "--format=%H",
            "-n",
            str(_PREVIOUS_DEPTH),
            "--",
            config_subpath,
        ],
        action="log",
    )
    output = _stdout_or_raise(completed, "log")
    revisions = [line for line in output.splitlines() if line.strip()]
    if len(revisions) < _PREVIOUS_DEPTH:
        raise FermError("no previous version to roll back to")
    return revisions[1]


def diff_revision(sha: str, config_subpath: str) -> str:
    """Return the config diff against ``sha`` (read-only, for the operator)."""
    _validate_revision(sha)
    completed = _vcs(["diff", sha, "--", config_subpath], action="diff")
    return _stdout_or_raise(completed, "diff")


def working_tree_dirty(config_subpath: str | None = None) -> bool:
    """
    Return ``True`` when there are uncommitted changes.

    With ``config_subpath`` the check is path-scoped -- the rollback guard
    against silently overwriting edits (``checkout`` clobbers the worktree).
    Without it (``None``) the whole ``/etc`` repository is inspected, which is
    how the commit hook detects "nothing to commit".
    """
    args = ["status", "--porcelain"]
    if config_subpath is not None:
        args += ["--", config_subpath]
    completed = _vcs(args, action="status")
    return bool(_stdout_or_raise(completed, "status").strip())


def rollback(sha: str, config_subpath: str) -> None:
    """
    Revert ONLY ``config_subpath`` to revision ``sha``, cleanly.

    A bare ``checkout <sha> -- <path>`` does not clean the directory: files
    added after ``sha`` (e.g. ``ferm.d/new.conf``) are not in ``sha``'s tree
    and would survive, leaving a hybrid (old versions of old files plus extra
    new ones) that regenerates the wrong ruleset under ``@include
    ferm.d/*``.  So three path-scoped steps:

    1. unstage everything under the path (``rm -r --cached --ignore-unmatch``);
    2. restore ``sha``'s tracked files (``checkout <sha> -- <path>``);
    3. delete the now-untracked post-``sha`` files (``clean -f -d -- <path>``).

    Does not commit -- the post-apply hook records the rollback as a new
    commit.  Any step failing raises :class:`FermError`.
    """
    _validate_revision(sha)
    steps: tuple[tuple[list[str], str], ...] = (
        (
            ["rm", "-r", "--cached", "--ignore-unmatch", "--", config_subpath],
            "unstage",
        ),
        (["checkout", sha, "--", config_subpath], "checkout"),
        (["clean", "-f", "-d", "--", config_subpath], "clean"),
    )
    for args, action in steps:
        completed = _vcs(args, action=action)
        if completed.returncode != 0:
            raise FermError(
                f"rollback {action} failed: {_describe_failure(completed)}"
            )
