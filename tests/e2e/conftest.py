"""Turn a silent all-skip of the opt-in kernel e2e suite into a hard failure.

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

import pytest

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
