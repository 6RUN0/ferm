"""
Integration scenarios for :mod:`pyferm.etckeeper` against a real git repo.

Where ``tests/unit/test_etckeeper.py`` asserts the *argv* the module builds
(a tautology with respect to a real VCS), these scenarios run the production
functions through a real ``git`` (via the ``etckeeper`` shim from
``conftest.py``) and assert the *effect* on the working tree and history.  The
headline case is the three-step clean-revert: a file added after the target
revision must be gone after rollback, not left behind as a hybrid directory.

See ``conftest.py`` for why the git-only paths are faithful and why the real
``etckeeper commit`` verb (metadata hooks) is left to the containerized e2e.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import pytest

from pyferm import cli, etckeeper
from pyferm.backend.base import Rendered
from pyferm.cli import apply as cli_apply
from pyferm.errors import FermError

if TYPE_CHECKING:
    from tests.integration.conftest import EtckeeperSandbox


# --- commit (best-effort, through the shim) -------------------------------


def test_commit_records_a_revision(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """A first apply commit produces a real revision in the history."""
    sandbox = etckeeper_sandbox
    sandbox.write("ferm/ferm.conf", "table filter {}\n")

    etckeeper.commit("ferm: apply ferm.conf")

    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    history = etckeeper.list_history(subpath)
    assert "apply ferm.conf" in history
    assert etckeeper.working_tree_dirty() is False


def test_commit_nothing_to_commit_is_a_noop(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """A second commit with no change does not raise and adds no revision."""
    sandbox = etckeeper_sandbox
    sandbox.write("ferm/ferm.conf", "table filter {}\n")
    etckeeper.commit("ferm: apply ferm.conf")
    before = sandbox.head()

    etckeeper.commit("ferm: apply ferm.conf again")  # must not raise

    assert sandbox.head() == before


# --- rollback_available / repo_relative_subpath ---------------------------


def test_rollback_available_under_git(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """The repo is git-backed, so rollback is available."""
    sandbox = etckeeper_sandbox
    sandbox.write("ferm/ferm.conf", "table filter {}\n")
    assert etckeeper.rollback_available() is True


def test_repo_relative_subpath_inside_and_outside(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """The config dir resolves under the repo; an outside path is barred."""
    sandbox = etckeeper_sandbox
    assert etckeeper.repo_relative_subpath(sandbox.config_path) == "ferm"

    outside = str(sandbox.etc.parent / "elsewhere" / "ferm.conf")
    with pytest.raises(FermError, match="outside the etckeeper"):
        etckeeper.repo_relative_subpath(outside)


def test_repo_relative_subpath_at_repo_root_barred(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """
    A config sitting directly at the repo root is refused.

    ``os.path.relpath`` would return ``"."`` there, scoping a rollback to the
    whole ``/etc`` tree (``git checkout``/``clean`` over everything). The guard
    must bar it against real git, not just the mocked relpath.
    """
    sandbox = etckeeper_sandbox
    at_root = str(sandbox.etc / "ferm.conf")
    with pytest.raises(FermError, match="repository root"):
        etckeeper.repo_relative_subpath(at_root)


# --- previous_revision (path-scoped history semantics) --------------------


def test_previous_revision_is_path_scoped(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """
    ``previous_revision`` follows the config's own history, not ``/etc``'s tip.

    An unrelated ``/etc`` commit landing between two ferm applies must not be
    mistaken for the previous ferm config.
    """
    sandbox = etckeeper_sandbox
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)

    sandbox.write("ferm/ferm.conf", "table filter { chain INPUT; }\n")
    etckeeper.commit("ferm: apply A")
    rev_a = sandbox.head()

    # An unrelated /etc change commits between the two ferm applies.
    sandbox.write("hostname", "fermhost\n")
    etckeeper.commit("etckeeper: hostname change")

    sandbox.write("ferm/ferm.conf", "table filter { chain OUTPUT; }\n")
    etckeeper.commit("ferm: apply B")

    assert etckeeper.previous_revision(subpath) == rev_a


def test_previous_revision_single_revision_raises(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """With only one ferm revision there is nothing to roll back to."""
    sandbox = etckeeper_sandbox
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    sandbox.write("ferm/ferm.conf", "table filter {}\n")
    etckeeper.commit("ferm: apply A")

    with pytest.raises(FermError, match="no previous version"):
        etckeeper.previous_revision(subpath)


# --- diff_revision --------------------------------------------------------


def test_diff_revision_shows_the_change(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """A real diff between the config and a prior revision is returned."""
    sandbox = etckeeper_sandbox
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    sandbox.write("ferm/ferm.conf", "table filter { chain INPUT; }\n")
    etckeeper.commit("ferm: apply A")
    rev_a = sandbox.head()
    sandbox.write("ferm/ferm.conf", "table filter { chain OUTPUT; }\n")
    etckeeper.commit("ferm: apply B")

    diff = etckeeper.diff_revision(rev_a, subpath)
    assert "-table filter { chain INPUT; }" in diff
    assert "+table filter { chain OUTPUT; }" in diff


# --- working_tree_dirty ---------------------------------------------------


def test_working_tree_dirty_detects_uncommitted_edit(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """A path-scoped dirty check sees an uncommitted edit, not a clean tree."""
    sandbox = etckeeper_sandbox
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    sandbox.write("ferm/ferm.conf", "table filter {}\n")
    etckeeper.commit("ferm: apply A")
    assert etckeeper.working_tree_dirty(subpath) is False

    sandbox.write("ferm/ferm.conf", "table filter { chain INPUT; }\n")
    assert etckeeper.working_tree_dirty(subpath) is True


# --- rollback (the three-step clean revert) -------------------------------


def test_rollback_clean_revert_round_trip(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """
    Rollback restores tracked files AND removes files added after the target.

    This is the regression the three-step revert exists for: a bare
    ``checkout <sha> -- <path>`` would leave ``ferm.d/new.conf`` behind,
    yielding a hybrid directory that regenerates the wrong ruleset.
    """
    sandbox = etckeeper_sandbox
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)

    # Revision A: a base config plus an included fragment.
    sandbox.write("ferm/ferm.conf", "table filter { chain INPUT; }\n")
    sandbox.write("ferm/ferm.d/old.conf", "# old fragment\n")
    etckeeper.commit("ferm: apply A")
    rev_a = sandbox.head()

    # Revision B: change the base config and add a new fragment.
    sandbox.write("ferm/ferm.conf", "table filter { chain OUTPUT; }\n")
    sandbox.write("ferm/ferm.d/new.conf", "# new fragment\n")
    etckeeper.commit("ferm: apply B")

    etckeeper.rollback(rev_a, subpath)

    assert sandbox.read("ferm/ferm.conf") == "table filter { chain INPUT; }\n"
    assert sandbox.exists("ferm/ferm.d/old.conf")
    assert not sandbox.exists("ferm/ferm.d/new.conf")


def test_rollback_does_not_create_a_commit(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """
    Rollback only touches the working tree; the apply hook records it.

    The reverted state is left staged/working so the subsequent re-apply hook
    commits it as a new revision.
    """
    sandbox = etckeeper_sandbox
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    sandbox.write("ferm/ferm.conf", "table filter { chain INPUT; }\n")
    etckeeper.commit("ferm: apply A")
    rev_a = sandbox.head()
    sandbox.write("ferm/ferm.conf", "table filter { chain OUTPUT; }\n")
    etckeeper.commit("ferm: apply B")
    rev_b = sandbox.head()

    etckeeper.rollback(rev_a, subpath)

    # No new commit; the tip is still B and the tree now differs from it.
    assert sandbox.head() == rev_b
    assert etckeeper.working_tree_dirty(subpath) is True


def test_rollback_rejects_leading_dash(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """A leading ``-`` (flag injection) is rejected before any git call."""
    sandbox = etckeeper_sandbox
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    with pytest.raises(FermError, match="leading '-'"):
        etckeeper.rollback("-rf", subpath)


def test_rollback_rejects_commit_range(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """A ``..`` range is rejected before any git call."""
    sandbox = etckeeper_sandbox
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    with pytest.raises(FermError, match="range not allowed"):
        etckeeper.rollback("HEAD~2..HEAD", subpath)


def test_rollback_to_missing_revision_raises(
    etckeeper_sandbox: EtckeeperSandbox,
) -> None:
    """A syntactically valid but nonexistent revision fails at checkout."""
    sandbox = etckeeper_sandbox
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    sandbox.write("ferm/ferm.conf", "table filter {}\n")
    etckeeper.commit("ferm: apply A")

    with pytest.raises(FermError, match="rollback checkout failed"):
        etckeeper.rollback("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", subpath)


# --- bare-form `ferm rollback` CLI wiring (real git, no kernel apply) ------
#
# These drive cli._rollback_main through the real previous_revision +
# diff_revision + working_tree_dirty against the git sandbox.  Each case
# deliberately stops before the kernel re-apply (cancel, dirty-guard refusal,
# or non-tty refusal), so no backend ever touches the host firewall -- the
# real apply is the container e2e's job.


class _FakeStdin:
    """A minimal stdin stand-in for driving the confirmation prompt."""

    def __init__(self, answer: str, *, tty: bool) -> None:
        self._answer = answer
        self._tty = tty

    def isatty(self) -> bool:
        """Whether the rollback should treat input as interactive."""
        return self._tty

    def readline(self) -> str:
        """Return the canned confirmation answer."""
        return self._answer


def _two_ferm_revisions(sandbox: EtckeeperSandbox) -> None:
    """Commit two distinct ferm revisions so a previous one exists."""
    sandbox.write("ferm/ferm.conf", "table filter { chain INPUT; }\n")
    etckeeper.commit("ferm: apply A")
    sandbox.write("ferm/ferm.conf", "table filter { chain OUTPUT; }\n")
    etckeeper.commit("ferm: apply B")


def test_bare_rollback_cancel_leaves_config_untouched(
    etckeeper_sandbox: EtckeeperSandbox,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Answering ``n`` shows the real diff and reverts nothing."""
    sandbox = etckeeper_sandbox
    _two_ferm_revisions(sandbox)
    monkeypatch.setattr("sys.stdin", _FakeStdin("n\n", tty=True))

    code = cli._rollback_main([sandbox.config_path])

    assert code == 0
    captured = capsys.readouterr()
    assert "Rollback cancelled" in captured.err
    # The real diff against the previous revision was rendered.
    assert "chain INPUT" in captured.err
    assert sandbox.read("ferm/ferm.conf") == "table filter { chain OUTPUT; }\n"


def test_bare_rollback_refuses_dirty_worktree(
    etckeeper_sandbox: EtckeeperSandbox,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A confirmed rollback aborts when the worktree has uncommitted edits."""
    sandbox = etckeeper_sandbox
    _two_ferm_revisions(sandbox)
    sandbox.write("ferm/ferm.conf", "table filter { chain FORWARD; }\n")
    monkeypatch.setattr("sys.stdin", _FakeStdin("y\n", tty=True))

    with pytest.raises(FermError, match="uncommitted changes"):
        cli._rollback_main([sandbox.config_path])


def test_bare_rollback_refuses_non_tty(
    etckeeper_sandbox: EtckeeperSandbox,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a tty the bare form refuses rather than guessing consent."""
    sandbox = etckeeper_sandbox
    _two_ferm_revisions(sandbox)
    monkeypatch.setattr("sys.stdin", _FakeStdin("y\n", tty=False))

    with pytest.raises(FermError, match="non-tty"):
        cli._rollback_main([sandbox.config_path])


# --- declined interactive re-apply (real git, faked backend) ---------------


def test_interactive_rollback_declined_restores_worktree(
    etckeeper_sandbox: EtckeeperSandbox,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    Declining the post-apply confirm restores the reverted worktree.

    Runs the revert -> re-apply -> kernel rollback -> worktree restore
    chain end to end through the real git plumbing; only the backend
    (kernel) and the confirm prompt are faked, so the host firewall is
    never touched.  Without the restore the config would sit on the old
    revision, uncommitted, and the next rollback would refuse behind the
    dirty-worktree guard.
    """
    sandbox = etckeeper_sandbox
    _two_ferm_revisions(sandbox)
    monkeypatch.setattr("sys.stdin", _FakeStdin("y\n", tty=True))
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)

    events: list[str] = []

    class _FakeBackend:
        """Records the kernel-facing calls; never spawns a tool."""

        def tool_names(self, _domain: object) -> dict[str, str]:
            """No tools to resolve."""
            return {}

        def capture_previous(self, *_args: object, **_kwargs: object) -> None:
            """No previous kernel state to read."""

        def shell_snapshot(self, *_args: object, **_kwargs: object) -> None:
            """No --shell snapshot."""
            return

        def render(self, *_args: object, **_kwargs: object) -> Rendered:
            """An empty ruleset stand-in."""
            return Rendered(save="")

        def commit(self, *_args: object, **_kwargs: object) -> None:
            """Record the apply; report success."""
            events.append("commit")

        def rollback(self, *_args: object, **_kwargs: object) -> None:
            """Record the kernel restore."""
            events.append("rollback")

    monkeypatch.setattr(
        cli_apply, "_select_backend", lambda _options: _FakeBackend()
    )
    monkeypatch.setattr(cli_apply, "_confirm_rules", lambda _options: False)

    with pytest.raises(SystemExit) as exc:
        cli._rollback_main(["--interactive", sandbox.config_path])

    assert exc.value.code == 1
    assert events == ["commit", "rollback"]
    # the worktree is back on the current revision, clean
    assert sandbox.read("ferm/ferm.conf") == "table filter { chain OUTPUT; }\n"
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    assert etckeeper.working_tree_dirty(subpath) is False
    err = capsys.readouterr().err
    assert "Firewall rules rolled back." in err
    assert "restored to match the running rules." in err


def test_rollback_to_unparsable_revision_restores_worktree(
    etckeeper_sandbox: EtckeeperSandbox,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    A revert to a config that no longer parses restores the worktree.

    The re-apply dies in the parse phase -- before any hook, render or
    commit -- so the kernel provably still runs the pre-rollback rules
    (:class:`_KernelUntouchedFermError`); leaving the reverted config
    in place would diverge from the kernel and block the next rollback
    behind the dirty-worktree guard.  Real git plumbing and the real
    parser; only the backend is faked, so no tool is ever spawned.
    """
    sandbox = etckeeper_sandbox
    sandbox.write("ferm/ferm.conf", "bork bork;\n")
    etckeeper.commit("ferm: apply A")
    sandbox.write("ferm/ferm.conf", "table filter { chain OUTPUT; }\n")
    etckeeper.commit("ferm: apply B")
    monkeypatch.setattr("sys.stdin", _FakeStdin("y\n", tty=True))
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)

    events: list[str] = []

    class _FakeBackend:
        """Records kernel-facing calls; the parse dies before any."""

        def tool_names(self, _domain: object) -> dict[str, str]:
            """No tools to resolve."""
            return {}

        def capture_previous(self, *_args: object, **_kwargs: object) -> None:
            """No previous kernel state to read."""

        def shell_snapshot(self, *_args: object, **_kwargs: object) -> None:
            """No --shell snapshot."""
            return

        def commit(self, *_args: object, **_kwargs: object) -> None:
            """Record a (never expected) apply."""
            events.append("commit")

    monkeypatch.setattr(
        cli_apply, "_select_backend", lambda _options: _FakeBackend()
    )

    with pytest.raises(FermError):
        cli._rollback_main([sandbox.config_path])

    assert events == []  # the kernel was never touched
    # the worktree is back on the current revision, clean
    assert sandbox.read("ferm/ferm.conf") == "table filter { chain OUTPUT; }\n"
    subpath = etckeeper.repo_relative_subpath(sandbox.config_path)
    assert etckeeper.working_tree_dirty(subpath) is False
    err = capsys.readouterr().err
    assert "restored to match the running rules." in err
