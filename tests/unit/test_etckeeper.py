"""
Unit tests for :mod:`pyferm.etckeeper`.

All external calls are mocked at the :func:`subprocess.run` boundary, so no
real ``/etc``, ``git`` or ``etckeeper`` is touched.  The clean-revert
guarantee (a file added after ``sha`` is gone after rollback) is verified
through the issued command sequence -- the ``git clean`` step is the mechanism
that removes the now-untracked post-``sha`` files.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

from pyferm import etckeeper
from pyferm.errors import FermError

if TYPE_CHECKING:
    from collections.abc import Sequence


class _Recorder:
    """A ``subprocess.run`` stand-in that records argv and replays results."""

    def __init__(self, responses: Sequence[object] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[list[str]] = []

    def __call__(
        self, argv: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        response = self.responses.pop(0) if self.responses else _ok()
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, subprocess.CompletedProcess)
        return response


def _ok(
    stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 0, stdout, stderr)


def _fail(
    code: int = 1, stderr: str = "boom"
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, "", stderr)


def _patch(monkeypatch: pytest.MonkeyPatch, recorder: _Recorder) -> None:
    monkeypatch.setattr("pyferm.etckeeper.subprocess.run", recorder)


# --- find_etckeeper -------------------------------------------------------


def test_find_etckeeper_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "pyferm.etckeeper.shutil.which", lambda _name: "/usr/bin/etckeeper"
    )
    assert etckeeper.find_etckeeper() == "/usr/bin/etckeeper"


def test_find_etckeeper_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pyferm.etckeeper.shutil.which", lambda _name: None)
    assert etckeeper.find_etckeeper() is None


# --- commit (best-effort) -------------------------------------------------


def test_commit_success_verb_led_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok()])
    _patch(monkeypatch, recorder)
    etckeeper.commit("ferm: applied ferm.conf")
    assert recorder.calls == [
        ["etckeeper", "commit", "ferm: applied ferm.conf"]
    ]


def test_commit_nonzero_warns_without_raising(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch(monkeypatch, _Recorder([_fail(stderr="nope")]))
    etckeeper.commit("msg")  # must not raise
    assert "etckeeper commit failed" in capsys.readouterr().err


def test_commit_oserror_warns_without_raising(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch(monkeypatch, _Recorder([OSError("no etckeeper")]))
    etckeeper.commit("msg")  # must not raise
    assert "etckeeper commit failed" in capsys.readouterr().err


# --- rollback_available ---------------------------------------------------


def test_rollback_available_git(monkeypatch: pytest.MonkeyPatch) -> None:
    recorder = _Recorder([_ok(stdout="/etc\n")])
    _patch(monkeypatch, recorder)
    assert etckeeper.rollback_available() is True
    assert recorder.calls[0] == [
        "etckeeper",
        "vcs",
        "rev-parse",
        "--show-toplevel",
    ]


def test_rollback_available_non_git(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _Recorder([_fail()]))
    assert etckeeper.rollback_available() is False


def test_rollback_available_spawn_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([OSError("missing")]))
    assert etckeeper.rollback_available() is False


# --- repo_relative_subpath ------------------------------------------------


def test_repo_relative_subpath_inside(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([_ok(stdout="/etc\n")]))
    assert etckeeper.repo_relative_subpath("/etc/ferm/ferm.conf") == "ferm"


def test_repo_relative_subpath_outside_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([_ok(stdout="/etc\n")]))
    with pytest.raises(FermError, match="outside the etckeeper"):
        etckeeper.repo_relative_subpath("/home/user/ferm.conf")


# --- list_history / diff_revision (read-only) -----------------------------


def test_list_history_argv_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok(stdout="abc fix\n")])
    _patch(monkeypatch, recorder)
    assert etckeeper.list_history("ferm") == "abc fix\n"
    assert recorder.calls[0] == [
        "etckeeper",
        "vcs",
        "log",
        "--oneline",
        "--",
        "ferm",
    ]


def test_list_history_failure_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([_fail(stderr="bad")]))
    with pytest.raises(FermError, match="bad"):
        etckeeper.list_history("ferm")


def test_diff_revision_argv_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok(stdout="diff text")])
    _patch(monkeypatch, recorder)
    assert etckeeper.diff_revision("deadbeef", "ferm") == "diff text"
    assert recorder.calls[0] == [
        "etckeeper",
        "vcs",
        "diff",
        "deadbeef",
        "--",
        "ferm",
    ]


def test_diff_revision_validates_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([]))
    with pytest.raises(FermError, match="leading '-'"):
        etckeeper.diff_revision("-rf", "ferm")


# --- previous_revision ----------------------------------------------------


def test_previous_revision_second_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok(stdout="cur1111\nprev222\n")])
    _patch(monkeypatch, recorder)
    assert etckeeper.previous_revision("ferm") == "prev222"
    assert recorder.calls[0] == [
        "etckeeper",
        "vcs",
        "log",
        "--format=%H",
        "-n",
        "2",
        "--",
        "ferm",
    ]


def test_previous_revision_single_revision_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([_ok(stdout="only1111\n")]))
    with pytest.raises(FermError, match="no previous version"):
        etckeeper.previous_revision("ferm")


def test_previous_revision_failure_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([_fail(stderr="git boom")]))
    with pytest.raises(FermError, match="git boom"):
        etckeeper.previous_revision("ferm")


# --- working_tree_dirty ---------------------------------------------------


def test_working_tree_dirty_whole_repo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok(stdout=" M etc/some.file\n")])
    _patch(monkeypatch, recorder)
    assert etckeeper.working_tree_dirty() is True
    assert recorder.calls[0] == ["etckeeper", "vcs", "status", "--porcelain"]


def test_working_tree_clean_whole_repo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([_ok(stdout="")]))
    assert etckeeper.working_tree_dirty() is False


def test_working_tree_dirty_path_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok(stdout=" M ferm/ferm.conf\n")])
    _patch(monkeypatch, recorder)
    assert etckeeper.working_tree_dirty("ferm") is True
    assert recorder.calls[0] == [
        "etckeeper",
        "vcs",
        "status",
        "--porcelain",
        "--",
        "ferm",
    ]


# --- rollback (clean revert) ----------------------------------------------


def test_rollback_clean_revert_sequence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok(), _ok(), _ok()])
    _patch(monkeypatch, recorder)
    etckeeper.rollback("deadbeef", "ferm")
    assert recorder.calls == [
        [
            "etckeeper",
            "vcs",
            "rm",
            "-r",
            "--cached",
            "--ignore-unmatch",
            "--",
            "ferm",
        ],
        ["etckeeper", "vcs", "checkout", "deadbeef", "--", "ferm"],
        ["etckeeper", "vcs", "clean", "-f", "-d", "--", "ferm"],
    ]


def test_rollback_includes_clean_step_removing_post_sha_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The clean step is what deletes files added after sha (now untracked);
    # without it the revert would leave a hybrid directory.
    recorder = _Recorder([_ok(), _ok(), _ok()])
    _patch(monkeypatch, recorder)
    etckeeper.rollback("HEAD", "ferm")
    assert any(call[2] == "clean" for call in recorder.calls)


def test_rollback_step_failure_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The checkout (second) step fails: rollback aborts with FermError.
    _patch(monkeypatch, _Recorder([_ok(), _fail(stderr="conflict")]))
    with pytest.raises(FermError, match="rollback checkout failed"):
        etckeeper.rollback("deadbeef", "ferm")


@pytest.mark.parametrize(
    "bad_sha",
    ["-rf", "a..b", "a;b", "$(id)", "a b", "a`b`"],
)
def test_rollback_rejects_unsafe_sha(
    monkeypatch: pytest.MonkeyPatch, bad_sha: str
) -> None:
    _patch(monkeypatch, _Recorder([]))
    with pytest.raises(FermError, match=r"invalid revision|range not allowed"):
        etckeeper.rollback(bad_sha, "ferm")


def test_rollback_accepts_branch_and_tag_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good_revisions = (
        "origin/main",
        "v1.2.3",
        "release-1",
        "deadbeef0123",  # pragma: allowlist secret -- a fake git sha
    )
    for good in good_revisions:
        recorder = _Recorder([_ok(), _ok(), _ok()])
        _patch(monkeypatch, recorder)
        etckeeper.rollback(good, "ferm")  # must not raise
        assert recorder.calls[1][3] == good
