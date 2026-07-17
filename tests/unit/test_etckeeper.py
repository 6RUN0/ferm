"""
Unit tests for :mod:`pyferm.etckeeper`.

All external calls are mocked at the :func:`subprocess.run` boundary, so no
real ``/etc``, ``git`` or ``etckeeper`` is touched.  The clean-revert
guarantee (a file added after ``sha`` is gone after rollback) is verified
through the issued command sequence -- the ``git clean`` step is the mechanism
that removes the now-untracked post-``sha`` files.
"""

from __future__ import annotations

import re
import subprocess
from typing import TYPE_CHECKING

import pytest

from pyferm import etckeeper
from pyferm.errors import FermError
from pyferm.streams import BYTE_ENCODING

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence


class _Recorder:
    """A ``subprocess.run`` stand-in that records argv and replays results."""

    def __init__(self, responses: Sequence[object] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[list[str]] = []
        self.kwargs: list[dict[str, object]] = []

    def __call__(
        self, argv: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        self.kwargs.append(kwargs)
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


# The three-step clean-revert argv sequence issued by etckeeper.rollback for
# subpath "ferm" at revision "deadbeef": unstage, checkout, clean.
_ROLLBACK_ARGV = [
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
    etckeeper.commit("ferm: apply ferm.conf")
    assert recorder.calls == [["etckeeper", "commit", "ferm: apply ferm.conf"]]


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


def test_repo_relative_subpath_at_repo_root_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A config directly at the repo root yields relpath ".", which would scope
    # a rollback to the WHOLE tree (git checkout/clean over all of /etc). Must
    # be refused, not silently widened.
    _patch(monkeypatch, _Recorder([_ok(stdout="/etc\n")]))
    with pytest.raises(FermError, match="repository root"):
        etckeeper.repo_relative_subpath("/etc/ferm.conf")


# --- list_history / diff_revision (read-only) -----------------------------


def test_list_history_argv_read_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok(stdout="abc  2026-07-17 10:00  fix\n")])
    _patch(monkeypatch, recorder)
    assert etckeeper.list_history("ferm") == ("abc  2026-07-17 10:00  fix\n")
    assert recorder.calls[0] == [
        "etckeeper",
        "vcs",
        "log",
        "--date=format:%Y-%m-%d %H:%M",
        "--format=%h  %ad  %s",
        "--",
        "ferm",
    ]


def test_list_history_limit_becomes_git_n(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok()])
    _patch(monkeypatch, recorder)
    etckeeper.list_history("ferm", limit=5)
    argv = recorder.calls[0]
    assert argv[2:5] == [
        "log",
        "--date=format:%Y-%m-%d %H:%M",
        "--format=%h  %ad  %s",
    ]
    assert argv[5:7] == ["-n", "5"]


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
    assert recorder.calls == _ROLLBACK_ARGV


def test_rollback_injected_runner_replaces_subprocess() -> None:
    # The runner parameter (the capture_previous convention) carries the
    # whole git sequence: no monkeypatching of module state, so a failing
    # assertion cannot leak a patched subprocess.run into later tests.
    recorder = _Recorder([_ok(), _ok(), _ok()])
    etckeeper.rollback("deadbeef", "ferm", runner=recorder)
    assert recorder.calls == _ROLLBACK_ARGV


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


# --- subprocess.run contract (mocked-boundary blind spot) -----------------
# The _Recorder swallows kwargs, so the run() keyword contract
# (capture_output/encoding/check) is invisible unless a test pins it. These
# assert it explicitly: capture_output so stdout/stderr are readable, and
# check=False so a nonzero exit is handled by hand rather than raising.


def test_vcs_run_captures_output_without_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok(stdout="x\n")])
    _patch(monkeypatch, recorder)
    etckeeper.list_history("ferm")
    kwargs = recorder.kwargs[0]
    assert kwargs.get("capture_output") is True
    assert kwargs.get("encoding") == BYTE_ENCODING
    assert kwargs.get("check") is False


def test_commit_run_captures_output_without_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok()])
    _patch(monkeypatch, recorder)
    etckeeper.commit("msg")
    kwargs = recorder.kwargs[0]
    assert kwargs.get("capture_output") is True
    assert kwargs.get("encoding") == BYTE_ENCODING
    assert kwargs.get("check") is False


# --- find_etckeeper program name ------------------------------------------


def test_find_etckeeper_queries_program_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def fake_which(name: str) -> str:
        seen.append(name)
        return "/usr/bin/etckeeper"

    monkeypatch.setattr("pyferm.etckeeper.shutil.which", fake_which)
    etckeeper.find_etckeeper()
    assert seen == ["etckeeper"]


# --- repo_relative_subpath: issued argv and parent-escape guard -----------


def test_repo_relative_subpath_issues_rev_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder([_ok(stdout="/etc\n")])
    _patch(monkeypatch, recorder)
    etckeeper.repo_relative_subpath("/etc/ferm/ferm.conf")
    assert recorder.calls[0] == [
        "etckeeper",
        "vcs",
        "rev-parse",
        "--show-toplevel",
    ]


def test_repo_relative_subpath_one_level_above_root_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # config_dir is exactly the repo's parent: relpath is ".." with no trailing
    # separator, which the startswith("../") guard misses; the exact "==" check
    # is what rejects it. Missing it would scope rollback to "..".
    _patch(monkeypatch, _Recorder([_ok(stdout="/etc/ferm\n")]))
    with pytest.raises(FermError, match="outside the etckeeper"):
        etckeeper.repo_relative_subpath("/etc/config.conf")


# --- commit failure detail (_describe_failure) ----------------------------


def test_commit_warning_reports_stderr_detail(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch(monkeypatch, _Recorder([_fail(stderr="boom")]))
    etckeeper.commit("msg")
    assert "boom" in capsys.readouterr().err


def test_commit_warning_reports_exit_code_when_stderr_empty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch(monkeypatch, _Recorder([_fail(code=2, stderr="")]))
    etckeeper.commit("msg")
    assert "exit 2" in capsys.readouterr().err


# --- read-only helpers name the failed operation --------------------------
# Every _vcs caller labels its operation (the ``action``) so a failure says
# which git verb broke. Exercised on both failure paths: a spawn error
# (OSError in _vcs) and a nonzero exit with empty stderr (the
# _stdout_or_raise fallback). Existing failure tests use non-empty stderr,
# which shadows the action label entirely.

_VCS_ACTIONS = [
    pytest.param(
        lambda: etckeeper.list_history("ferm"), "log", id="list_history"
    ),
    pytest.param(
        lambda: etckeeper.diff_revision("deadbeef", "ferm"),
        "diff",
        id="diff_revision",
    ),
    pytest.param(
        lambda: etckeeper.previous_revision("ferm"),
        "log",
        id="previous_revision",
    ),
    pytest.param(
        lambda: etckeeper.repo_relative_subpath("/etc/ferm/ferm.conf"),
        "rev-parse",
        id="repo_relative_subpath",
    ),
    pytest.param(
        lambda: etckeeper.working_tree_dirty("ferm"),
        "status",
        id="working_tree_dirty",
    ),
]


@pytest.mark.parametrize(("invoke", "action_word"), _VCS_ACTIONS)
def test_vcs_spawn_error_names_action(
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[], object],
    action_word: str,
) -> None:
    _patch(monkeypatch, _Recorder([OSError("no etckeeper")]))
    with pytest.raises(
        FermError, match=rf"vcs {re.escape(action_word)} failed"
    ):
        invoke()


@pytest.mark.parametrize(("invoke", "action_word"), _VCS_ACTIONS)
def test_vcs_nonzero_empty_stderr_names_action(
    monkeypatch: pytest.MonkeyPatch,
    invoke: Callable[[], object],
    action_word: str,
) -> None:
    _patch(monkeypatch, _Recorder([_fail(stderr="")]))
    with pytest.raises(
        FermError, match=rf"vcs {re.escape(action_word)} failed"
    ):
        invoke()


# --- rollback names the failing step / vcs action -------------------------


def test_rollback_unstage_step_failure_names_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([_fail(stderr="x")]))
    with pytest.raises(FermError, match="rollback unstage failed"):
        etckeeper.rollback("deadbeef", "ferm")


def test_rollback_clean_step_failure_names_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([_ok(), _ok(), _fail(stderr="x")]))
    with pytest.raises(FermError, match="rollback clean failed"):
        etckeeper.rollback("deadbeef", "ferm")


def test_rollback_spawn_error_names_vcs_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _Recorder([OSError("no etckeeper")]))
    with pytest.raises(FermError, match="vcs unstage failed"):
        etckeeper.rollback("deadbeef", "ferm")


# --- runner threads through every public entry point ----------------------
# Each read-only helper forwards its ``runner`` down to ``_vcs``; dropping the
# forward (``runner=None`` / omitting the kwarg) would silently fall back to
# the real ``subprocess.run`` and ignore the injected recorder. The
# ``test_rollback_injected_runner_replaces_subprocess`` case already pins this
# for ``rollback``; these pin it for the remaining six via the runner alone
# (no ``subprocess.run`` monkeypatch), so a lost forward leaves the recorder
# unused and the assertion fails.

_RUNNER_POINTS = [
    pytest.param(
        lambda recorder: etckeeper.rollback_available(runner=recorder),
        [_ok(stdout="/etc\n")],
        "rev-parse",
        id="rollback_available",
    ),
    pytest.param(
        lambda recorder: etckeeper.repo_relative_subpath(
            "/etc/ferm/ferm.conf", runner=recorder
        ),
        [_ok(stdout="/etc\n")],
        "rev-parse",
        id="repo_relative_subpath",
    ),
    pytest.param(
        lambda recorder: etckeeper.list_history("ferm", runner=recorder),
        [_ok(stdout="abc fix\n")],
        "log",
        id="list_history",
    ),
    pytest.param(
        lambda recorder: etckeeper.previous_revision("ferm", runner=recorder),
        [_ok(stdout="cur1111\nprev222\n")],
        "log",
        id="previous_revision",
    ),
    pytest.param(
        lambda recorder: etckeeper.diff_revision(
            "deadbeef", "ferm", runner=recorder
        ),
        [_ok(stdout="diff text")],
        "diff",
        id="diff_revision",
    ),
    pytest.param(
        lambda recorder: etckeeper.working_tree_dirty("ferm", runner=recorder),
        [_ok(stdout=" M ferm/ferm.conf\n")],
        "status",
        id="working_tree_dirty",
    ),
]


@pytest.mark.parametrize(("invoke", "responses", "verb"), _RUNNER_POINTS)
def test_public_entry_forwards_runner_to_vcs(
    invoke: Callable[[_Recorder], object],
    responses: Sequence[object],
    verb: str,
) -> None:
    recorder = _Recorder(responses)
    invoke(recorder)
    # the injected runner must have been used (a lost forward would leave it
    # untouched and fall back to the real subprocess.run)
    assert recorder.calls, "runner was not threaded through to _vcs"
    assert recorder.calls[0][:3] == ["etckeeper", "vcs", verb]
