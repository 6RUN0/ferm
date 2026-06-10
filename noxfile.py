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
"""

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


@nox.session
def audit(session: nox.Session) -> None:
    """Security/vulnerability audit (bandit + pip-audit)."""
    _uv(session, "bandit", "-q", "-c", "pyproject.toml", "-r", "src")
    _uv(session, "pip-audit")


@nox.session
def preflight(session: nox.Session) -> None:
    """Queue everything a push should pass: lint, typecheck, tests."""
    for name in ("lint", "typecheck", "tests", "golden_oracle"):
        session.notify(name)
