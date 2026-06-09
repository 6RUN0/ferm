"""Nox sessions for ferm.

``default_venv_backend = "none"`` so nox creates no environments of its
own: every tool runs through ``uv run``, making uv the single source of
the environment (``.venv`` / ``uv.lock``).
"""

import nox

nox.options.default_venv_backend = "none"
nox.options.sessions = ["lint", "tests", "typecheck"]


def _uv(session: nox.Session, *args: str) -> None:
    session.run("uv", "run", *args, external=True)


@nox.session
def lint(session: nox.Session) -> None:
    """Ruff lint and format check."""
    _uv(session, "ruff", "check", ".")
    _uv(session, "ruff", "format", "--check", ".")


@nox.session
def tests(session: nox.Session) -> None:
    """Run the test suite (golden harness grows here)."""
    _uv(session, "pytest", *session.posargs)


@nox.session
def typecheck(session: nox.Session) -> None:
    """Run static type checks with mypy and pyright."""
    _uv(session, "mypy")
    _uv(session, "pyright")


@nox.session
def coverage(session: nox.Session) -> None:
    """Run the test suite under coverage."""
    _uv(session, "pytest", "--cov", "--cov-report=term-missing")


@nox.session
def audit(session: nox.Session) -> None:
    """Security/vulnerability audit (bandit + pip-audit)."""
    _uv(session, "bandit", "-c", "pyproject.toml", "-r", "src")
    _uv(session, "pip-audit")
