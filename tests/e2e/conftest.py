"""
Turn a silent all-skip of the opt-in kernel e2e suite into a hard failure.

The kernel e2e tests self-skip when their prerequisites (rootless user
namespaces, nftables, docker, ...) are absent, so a CI leg meant to exercise a
live kernel path can finish green having executed nothing. When a job declares
those prerequisites present by exporting ``FERM_E2E=1`` (the
``delta_apply_e2e`` nox session does), a run in which zero non-skipped tests
executed is a
configuration failure, not a pass: this hook converts that silent all-skip into
a non-zero exit.

Scoped to ``tests/e2e`` and inert unless ``FERM_E2E=1`` is set, so the
docker-backed legs that legitimately self-skip (they export their own
``FERM_*_E2E`` flags, never ``FERM_E2E``) and ordinary local collection are
unaffected.
"""

from __future__ import annotations

import os
import subprocess
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

_executed_test_count = [0]


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Count tests whose call phase actually executed (passed or failed)."""
    if report.when == "call" and report.outcome in ("passed", "failed"):
        _executed_test_count[0] += 1


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail a green ``FERM_E2E`` run that executed no non-skipped test."""
    if os.environ.get("FERM_E2E") != "1":
        return
    if _executed_test_count[0] == 0 and exitstatus == 0:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_line(
                "FERM_E2E=1 but no non-skipped test ran in tests/e2e: the "
                "kernel prerequisites were expected to be present; failing "
                "instead of passing on a silent all-skip.",
                red=True,
            )


# --- shared driver harness for the containerized e2e suites --------------
#
# Every containerized e2e file follows the same shape: ``docker build -q`` a
# per-suite context, then ``docker run --rm`` its ``driver.py`` and assert a
# per-suite PASS marker on stdout with the full driver output attached to any
# failure.  These helpers factor out that mechanics; a suite with its own
# skip/verdict protocol (datapath) composes ``build_driver`` + ``run_driver``
# and keeps its bespoke assertions local.


def build_driver(
    image: str, context_dir: Path, *, build_args: list[str] | None = None
) -> None:
    """``docker build -q`` *context_dir* into *image*, asserting success."""
    cmd = ["docker", "build", "-q", "-t", image]
    if build_args:
        cmd += build_args
    cmd.append(str(context_dir))
    build = subprocess.run(
        cmd,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert build.returncode == 0, f"docker build failed:\n{build.stderr}"


def run_driver(run_args: list[str]) -> subprocess.CompletedProcess[str]:
    """``docker run --rm`` with *run_args* (mounts, env, image, command)."""
    return subprocess.run(
        ["docker", "run", "--rm", *run_args],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def assert_driver_pass(
    run: subprocess.CompletedProcess[str], pass_marker: str
) -> None:
    """Assert the driver exited 0 and printed *pass_marker* on stdout."""
    verdict = f"driver verdict:\n{run.stdout}\n{run.stderr}"
    assert run.returncode == 0, verdict
    assert pass_marker in run.stdout, verdict


def build_and_run_driver(
    image: str, context_dir: Path, *, run_args: list[str], pass_marker: str
) -> None:
    """Build the suite image, run its driver, and assert a PASS verdict."""
    build_driver(image, context_dir)
    assert_driver_pass(run_driver(run_args), pass_marker)
