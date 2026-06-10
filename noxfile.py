"""
Nox sessions for ferm -- run via ``uv run nox``.

``default_venv_backend = "none"`` so nox creates no environments of its
own: every tool runs through ``uv run``, making uv the single source of
the environment (``.venv`` / ``uv.lock``).

Examples::

    uv run nox                       # default: lint + tests + typecheck
    uv run nox -s preflight          # everything a push should pass
    uv run nox -s lint               # pre-commit hooks on all files
    uv run nox -s tests              # unit + golden against the port
    uv run nox -s tests -- tests/unit              # subset
    uv run nox -s golden_oracle      # golden harness vs the Perl oracle
    uv run nox -s typecheck          # mypy + pyright
    uv run nox -s coverage           # tests under coverage
    uv run nox -s audit              # bandit + pip-audit
    uv run nox -s workflows          # actionlint + zizmor on CI configs
    uv run nox -s fuzz               # thorough differential fuzzing
"""

import shutil

import nox

nox.options.default_venv_backend = "none"
nox.options.sessions = ["lint", "tests", "typecheck"]

#: The golden harness runs the Python port unless told otherwise; the
#: ``golden_oracle`` session flips this to validate the harness itself.
_GOLDEN_ENV = {"FERM_GOLDEN_TARGET": "python"}


def _uv(
    session: nox.Session, *args: str, env: dict[str, str] | None = None
) -> None:
    session.run("uv", "run", *args, external=True, env=env)


@nox.session
def lint(session: nox.Session) -> None:
    """Run every pre-commit hook against all files."""
    _uv(
        session,
        "pre-commit",
        "run",
        "--all-files",
        "--show-diff-on-failure",
    )


@nox.session
def tests(session: nox.Session) -> None:
    """Run the test suite (unit + golden) against the Python port."""
    _uv(session, "pytest", *session.posargs, env=_GOLDEN_ENV)


@nox.session
def golden_oracle(session: nox.Session) -> None:
    """
    Validate the golden harness against the Perl oracle.

    The harness was proven by pointing it at ``reference/src/ferm``
    first; this session keeps that proof repeatable (it needs ``perl``
    and ``Net::DNS::Resolver::Mock`` on the machine).
    """
    _uv(
        session,
        "pytest",
        "tests/golden",
        *session.posargs,
        env={"FERM_GOLDEN_TARGET": "perl"},
    )


@nox.session
def typecheck(session: nox.Session) -> None:
    """Run static type checks with mypy and pyright."""
    _uv(session, "mypy")
    _uv(session, "pyright")
    # Public API type completeness: pyright exits non-zero below 100%,
    # so this is a no-regression gate (py.typed promises full typing).
    _uv(session, "pyright", "--verifytypes", "pyferm")


@nox.session
def coverage(session: nox.Session) -> None:
    """Run the test suite under coverage."""
    _uv(
        session,
        "pytest",
        "--cov",
        "--cov-report=term-missing",
        *session.posargs,
        env=_GOLDEN_ENV,
    )
    # pytest-cov prints the fail_under verdict but exits zero (observed
    # with pytest-cov 7.1 / pytest 9), so the floor is enforced here:
    # `coverage report` exits non-zero below [tool.coverage.report]
    # fail_under.
    _uv(session, "coverage", "report", "--format=total")


@nox.session
def fuzz(session: nox.Session) -> None:
    """
    Differential fuzzing against the Perl oracle, thorough profile.

    The property tests already run (at the default example count) inside
    ``tests``/``coverage``; this session reruns them with the "thorough"
    Hypothesis profile for a deeper sweep.  Needs ``perl`` on PATH.
    """
    _uv(
        session,
        "pytest",
        "tests/property",
        "--hypothesis-profile=thorough",
        *session.posargs,
    )


@nox.session
def audit(session: nox.Session) -> None:
    """Security/vulnerability audit (bandit + pip-audit)."""
    _uv(session, "bandit", "-q", "-c", "pyproject.toml", "-r", "src")
    _uv(session, "pip-audit")


@nox.session
def workflows(session: nox.Session) -> None:
    """
    Lint the GitHub Actions workflows (actionlint + zizmor).

    Both linters are system binaries (not Python packages), so each one
    is skipped with a notice when absent from PATH; the session fails
    only on real findings.
    """
    available = [
        tool for tool in ("actionlint", "zizmor") if shutil.which(tool)
    ]
    for tool in available:
        # actionlint discovers .github/workflows on its own; zizmor
        # needs the path spelled out.
        args = [tool] if tool == "actionlint" else [tool, ".github/workflows"]
        session.run(*args, external=True)
    if not available:
        session.skip("neither actionlint nor zizmor is installed")


@nox.session
def preflight(session: nox.Session) -> None:
    """Queue everything a push should pass: lint, typecheck, tests."""
    # `coverage` rather than `tests`: the same suite, but the coverage
    # floor (fail_under) is actually enforced before a push.
    queue = (
        "lint",
        "typecheck",
        "coverage",
        "golden_oracle",
        "fuzz",
        "workflows",
    )
    for name in queue:
        session.notify(name)
