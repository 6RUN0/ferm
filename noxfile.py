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
    uv run nox -s matrix             # test suite on every supported python
    uv run nox -s golden_oracle      # golden harness vs the Perl oracle
    uv run nox -s typecheck          # mypy + pyright
    uv run nox -s coverage           # tests under coverage
    uv run nox -s audit              # bandit + pip-audit
    uv run nox -s workflows          # actionlint + zizmor on CI configs
    uv run nox -s deps_lowest        # test suite on lowest dep bounds
    uv run nox -s build              # wheel/sdist build + install smoke
    uv run nox -s fuzz               # thorough differential fuzzing
    uv run nox -s mutation           # mutmut over the unit suite (slow)
    uv run nox -s crashfuzz          # atheris crash fuzzing of the parsers
    uv run nox -s lockout            # containerized anti-lockout e2e (docker)
"""

import os
import shutil
import subprocess
from pathlib import Path

import nox

nox.options.default_venv_backend = "none"
nox.options.sessions = ["lint", "tests", "typecheck"]

#: Emit EncodingWarning wherever IO falls back to the locale encoding;
#: pytest's ``filterwarnings = error`` then fails the test.  An env var
#: (not a pytest option) because the interpreter reads it at startup --
#: and the children the golden/corpus suites spawn inherit it too.
_WARN_ENV = {"PYTHONWARNDEFAULTENCODING": "1"}

#: The golden harness runs the Python port unless told otherwise; the
#: ``golden_oracle`` session flips this to validate the harness itself.
_GOLDEN_ENV = {"FERM_GOLDEN_TARGET": "python", **_WARN_ENV}

#: Every interpreter declared supported in the trove classifiers; keep
#: in sync with ``[project.classifiers]`` and the CI ``port`` matrix.
_SUPPORTED_PYTHONS = ("3.11", "3.12", "3.13", "3.14")


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
@nox.parametrize("python", _SUPPORTED_PYTHONS)
def matrix(session: nox.Session, python: str) -> None:
    """
    Run the test suite on one supported interpreter (all by default).

    Local mirror of the CI ``port`` matrix.  Each interpreter gets its
    own environment (``.venv-<version>``) so the main ``.venv`` stays
    untouched; uv downloads any missing interpreter on demand.
    """
    session.run(
        "uv",
        "run",
        "--locked",
        "--python",
        python,
        "pytest",
        *session.posargs,
        external=True,
        env={
            **_GOLDEN_ENV,
            "UV_PROJECT_ENVIRONMENT": f".venv-{python}",
            # An inherited VIRTUAL_ENV=.venv would make uv warn about
            # the mismatch with the per-interpreter environment.
            "VIRTUAL_ENV": f".venv-{python}",
        },
    )


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
        env={"FERM_GOLDEN_TARGET": "perl", **_WARN_ENV},
    )


@nox.session
def typecheck(session: nox.Session) -> None:
    """Run static type checks with mypy and pyright."""
    _uv(session, "mypy")
    _uv(session, "pyright")
    # Public API type completeness: pyright exits non-zero below 100%,
    # so this is a no-regression gate (py.typed promises full typing).
    _uv(session, "pyright", "--verifytypes", "pyferm")


#: Base ref for the diff-cover patch-coverage gate: the branch a local
#: preflight is about to push to.  In CI the checked-out commit equals
#: this ref, the diff is empty and the gate passes trivially -- the gate
#: bites locally, before the push.
_PATCH_COVERAGE_BASE = os.environ.get("FERM_DIFF_BASE", "origin/python-port")


@nox.session
def coverage(session: nox.Session) -> None:
    """Run the test suite under coverage (global floor + patch gate)."""
    _uv(
        session,
        "pytest",
        "--cov",
        "--cov-report=term-missing",
        "--cov-report=xml",
        *session.posargs,
        env=_GOLDEN_ENV,
    )
    # pytest-cov prints the fail_under verdict but exits zero (observed
    # with pytest-cov 7.1 / pytest 9), so the floor is enforced here:
    # `coverage report` exits non-zero below [tool.coverage.report]
    # fail_under.
    _uv(session, "coverage", "report", "--format=total")
    # Patch coverage: lines added/changed relative to the push target are
    # held to a higher floor than the global ratchet, so new code cannot
    # coast on the existing suite's percentage.
    base_exists = (
        subprocess.run(
            ["git", "rev-parse", "--verify", "-q", _PATCH_COVERAGE_BASE],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )
    if base_exists:
        _uv(
            session,
            "diff-cover",
            "coverage.xml",
            f"--compare-branch={_PATCH_COVERAGE_BASE}",
            "--fail-under=90",
        )
    else:
        session.log(
            f"{_PATCH_COVERAGE_BASE} not found; skipping the patch gate"
        )


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
        env=_WARN_ENV,
    )


@nox.session
def mutation(session: nox.Session) -> None:
    """
    Mutation testing with mutmut (periodic, NOT a gate).

    Generates trampoline mutants for ``src/`` under ``mutants/`` and
    runs the coverage-selected unit tests against each one (see
    ``[tool.mutmut]`` for the kill-set rationale).  A full sweep takes
    hours; scope it to a module with a mutant-name glob::

        uv run nox -s mutation -- "pyferm.scope.*"

    ``mutmut run`` resumes from previous results, so interrupted sweeps
    just continue.  Triage survivors with ``uv run --group mutation
    mutmut browse``.  Deliberately absent from ``preflight``.
    """
    _uv(session, "--group", "mutation", "mutmut", "run", *session.posargs)
    _uv(session, "--group", "mutation", "mutmut", "results")


#: atheris ships cp311-cp313 wheels only; the crashfuzz session pins this
#: interpreter so the run never lands on an unsupported one (e.g. 3.14).
_CRASHFUZZ_PYTHON = "3.13"

#: One crash-fuzz target: harness script plus the read-only seed corpora
#: libFuzzer mines for an initial coverage frontier.
_CRASHFUZZ_TARGETS = {
    "config": ("fuzz/fuzz_config.py", ("tests/corpus/configs",)),
    "import": ("fuzz/fuzz_import.py", ("fuzz/seeds/import",)),
}


@nox.session
def crashfuzz(session: nox.Session) -> None:
    """
    Coverage-guided crash fuzzing of both parsers with atheris (opt-in).

    Asks the robustness question the differential fuzzers do not -- "is
    there an input that makes the port raise an unhandled exception or
    hang?" -- driving the config parser and ``import-ferm`` below the CLI
    with every shell/file/network seam neutralized (see ``fuzz/README.md``).
    Each target runs for ``posargs[0]`` seconds (default 60); findings are
    saved under ``fuzz/crashes/`` and the working corpus grows in
    ``fuzz/corpus/`` across runs.  Needs the ``crashfuzz`` dependency group
    (``atheris``, cp311-cp313 only); deliberately absent from ``preflight``.
    """
    seconds = session.posargs[0] if session.posargs else "60"
    for name, (harness, seeds) in _CRASHFUZZ_TARGETS.items():
        corpus = Path("fuzz/corpus") / name
        corpus.mkdir(parents=True, exist_ok=True)
        Path("fuzz/crashes").mkdir(parents=True, exist_ok=True)
        session.run(
            "uv",
            "run",
            "--group",
            "crashfuzz",
            "--python",
            _CRASHFUZZ_PYTHON,
            "python",
            harness,
            str(corpus),
            *seeds,
            f"-artifact_prefix=fuzz/crashes/{name}-",
            f"-max_total_time={seconds}",
            external=True,
        )


@nox.session
def lockout(session: nox.Session) -> None:
    """
    Containerized ``--interactive`` anti-lockout e2e (needs docker).

    Provokes a real lockout inside a throwaway container network
    namespace: applies an ``INPUT DROP`` ruleset, never answers the
    confirmation prompt, and asserts the timeout rollback restores the
    previous ruleset and revives the frozen connection.  Netfilter is
    a namespaced subsystem of the shared kernel, so this is as real as
    a bare-host run.  Opt-in (needs the docker daemon; the test skips
    itself when docker is absent) and deliberately absent from
    ``preflight``.
    """
    _uv(
        session,
        "pytest",
        "tests/e2e",
        *session.posargs,
        env={"FERM_LOCKOUT_E2E": "1"},
    )


@nox.session
def deps_lowest(session: nox.Session) -> None:
    """
    Run the test suite against the lowest declared dependency bounds.

    Installs the project plus the ``test`` group with ``--resolution
    lowest-direct`` into its own environment (``.venv-lowest``), proving
    the ``>=`` floors in pyproject.toml are honest rather than
    aspirational.  ``uv pip`` resolves independently of ``uv.lock``, so
    the lockfile stays untouched.
    """
    session.run(
        "uv", "venv", "--quiet", "--clear", ".venv-lowest", external=True
    )
    session.run(
        "uv",
        "pip",
        "install",
        "--quiet",
        "--resolution",
        "lowest-direct",
        "-e",
        ".",
        "--group",
        "test",
        external=True,
        env={"VIRTUAL_ENV": ".venv-lowest"},
    )
    session.run(
        ".venv-lowest/bin/python",
        "-m",
        "pytest",
        *session.posargs,
        external=True,
        env=_GOLDEN_ENV,
    )


@nox.session
def build(session: nox.Session) -> None:
    """
    Build the wheel/sdist and smoke-test the wheel in a clean venv.

    Every other gate runs against the editable src-layout install, so
    none of them notices a wheel that ships without ``py.typed`` or with
    broken entry points.  ``twine check`` and ``check-wheel-contents``
    validate the artifacts; the explicit zipfile assertion covers
    ``py.typed`` (the one promise ``--verifytypes`` makes that
    check-wheel-contents does not test for); then the wheel installs
    into a throwaway venv where both console scripts must answer.
    """
    out = Path(session.create_tmp())
    # create_tmp does not wipe an existing directory: stale artifacts
    # from a previous run (an old-version wheel, the smoke venv) would
    # leak into the globs below.
    shutil.rmtree(out)
    out.mkdir()
    session.run("uv", "build", "--out-dir", str(out), external=True)
    artifacts = sorted(str(path) for path in out.glob("ferm-*"))
    _uv(session, "--group", "build", "twine", "check", "--strict", *artifacts)
    wheel = next(str(path) for path in out.glob("*.whl"))
    _uv(session, "--group", "build", "check-wheel-contents", wheel)
    session.run(
        "uv",
        "run",
        "python",
        "-c",
        "import sys, zipfile\n"
        f"names = zipfile.ZipFile({wheel!r}).namelist()\n"
        "sys.exit('py.typed missing from the wheel'\n"
        "         if 'pyferm/py.typed' not in names else 0)",
        external=True,
    )
    venv = out / "smoke-venv"
    session.run("uv", "venv", "--quiet", str(venv), external=True)
    session.run(
        "uv",
        "pip",
        "install",
        "--quiet",
        wheel,
        external=True,
        env={"VIRTUAL_ENV": str(venv)},
    )
    session.run(str(venv / "bin" / "ferm"), "--version", external=True)
    session.run(str(venv / "bin" / "import-ferm"), "--help", external=True)


@nox.session
def audit(session: nox.Session) -> None:
    """Security/vulnerability audit (bandit + pip-audit)."""
    _uv(session, "bandit", "-q", "-c", "pyproject.toml", "-r", "src")
    _uv(session, "pip-audit")


@nox.session
def workflows(session: nox.Session) -> None:
    """
    Lint the GitHub Actions workflows (actionlint + zizmor).

    Both linters come from the locked ``lint`` group (actionlint via the
    ``actionlint-py`` vendored-binary wheel), so the session runs the
    same versions everywhere -- locally and in the weekly audit job.
    """
    # actionlint discovers .github/workflows on its own; zizmor needs
    # the path spelled out.
    _uv(session, "actionlint")
    _uv(session, "zizmor", ".github/workflows")


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
        "deps_lowest",
        "build",
        # Parametrized sessions are notified per signature; the bare
        # name would not expand to the variants.
        *(f"matrix(python='{python}')" for python in _SUPPORTED_PYTHONS),
    )
    for name in queue:
        session.notify(name)
