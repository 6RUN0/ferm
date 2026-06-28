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
    uv run nox -s image_scan         # trivy CVE scan of bundled native libs
    uv run nox -s deps_lowest        # test suite on lowest dep bounds
    uv run nox -s build              # wheel/sdist build + install smoke
    uv run nox -s fuzz               # thorough differential fuzzing
    uv run nox -s mutation           # mutmut over the unit suite (slow)
    uv run nox -s crashfuzz          # atheris crash fuzzing of the parsers
    uv run nox -s lockout            # containerized anti-lockout e2e (docker)
    uv run nox -s nft_e2e            # containerized nft backend e2e (docker)
    uv run nox -s nft_conformance   # nft canonicalizer conformance (network)
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


#: Parallelise the suite across cores with pytest-xdist.  The suite is
#: dominated by subprocess spawns (the Perl oracle, ``python -m pyferm``),
#: so ``-n auto`` is near-linear: ~59s -> ~14s on a 16-core box.  Kept out
#: of pytest ``addopts`` on purpose -- mutmut reruns ``tests/unit`` per
#: mutant and relies on stable per-test timing, and single-test debugging
#: wants serial; both pass ``-n0`` via posargs to override (last ``-n``
#: wins).
_XDIST = ("-n", "auto")


@nox.session
def tests(session: nox.Session) -> None:
    """Run the test suite (unit + golden) against the Python port."""
    _uv(session, "pytest", *_XDIST, *session.posargs, env=_GOLDEN_ENV)


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
        *_XDIST,
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
        *_XDIST,
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
#: preflight is about to push to.  On push CI the checked-out commit
#: equals this ref, the diff is empty and the gate passes trivially --
#: there it already ran in the local preflight.  On pull requests the
#: workflow overrides the base with the PR target branch, so the gate
#: also bites on contributions that skipped the local preflight.
_PATCH_COVERAGE_BASE = os.environ.get("FERM_DIFF_BASE", "origin/python-port")


@nox.session
def coverage(session: nox.Session) -> None:
    """Run the test suite under coverage (global floor + patch gate)."""
    _uv(
        session,
        "pytest",
        # pytest-cov combines the per-worker data files automatically, so
        # the coverage total is identical to a serial run.
        *_XDIST,
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
        *_XDIST,
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
def nft_e2e(session: nox.Session) -> None:
    """
    Containerized ``--nft`` backend round-trip e2e (needs docker).

    Inside a throwaway container network namespace, renders a ferm
    config with the native nftables backend, validates the save file
    against netlink with ``nft -c``, applies it for real, and proves the
    kernel holds the rules.  It also plants a foreign table beforehand
    to assert the own-table coexistence invariant (ferm never
    ``flush ruleset``) and witnesses the documented DROP-policy priority
    shift.  Netfilter is a namespaced subsystem of the shared kernel, so
    this is as real as a bare-host run.  Opt-in (needs the docker
    daemon; the test skips itself when docker is absent) and
    deliberately absent from ``preflight``.
    """
    _uv(
        session,
        "pytest",
        "tests/e2e/test_nft_e2e.py",
        *session.posargs,
        env={"FERM_NFT_E2E": "1"},
    )


@nox.session
def etckeeper_e2e(session: nox.Session) -> None:
    """
    Containerized etckeeper integration e2e (needs docker).

    Inside a throwaway container, turns ``/etc`` into a git-backed
    etckeeper repository and drives the full operator loop against the
    real ``etckeeper`` binary (with its global ``commit.d`` metadata
    hooks, which need a real ``/etc`` and root) and a real nftables
    kernel: apply a config and prove the apply auto-committed a semantic
    message and the kernel holds the rule, apply a changed config, then
    ``ferm rollback --to`` the first revision and prove the config and the
    live ruleset both return to the earlier state.  The host integration
    suite (``tests/integration/``) covers the git-only paths without
    docker; this is the layer that exercises the real commit verb.  Opt-in
    (needs the docker daemon; the test skips itself when docker is absent)
    and deliberately absent from ``preflight``.
    """
    _uv(
        session,
        "pytest",
        "tests/e2e/test_etckeeper_e2e.py",
        *session.posargs,
        env={"FERM_ETCKEEPER_E2E": "1"},
    )


#: Pinned nftables tag whose ``tests/py`` corpus drives nft_conformance.
#: Bump deliberately (verify via ``git ls-remote --tags`` -- currency rule),
#: not from memory; the idempotency layer is version-independent, the
#: differential layer compares against the *system* nft regardless.
_NFT_CORPUS_TAG = "v1.1.6"
_NFT_CORPUS_REPO = "https://git.netfilter.org/nftables"


@nox.session
def nft_conformance(session: nox.Session) -> None:
    """
    Opt-in nft-canonicalizer conformance vs the upstream ``.t`` corpus.

    Shallow-clones nftables at a pinned tag into a temp dir and runs the
    conformance suite: layer 1 (idempotency, host-only) always; layer 2
    (differential vs live ``nft list ruleset`` in a rootless netns) when
    ``nft`` and unprivileged user namespaces are available.  The corpus
    is never vendored -- GPLv2 source stays out of the tree.  Needs
    network for the clone; deliberately absent from ``preflight``.
    """
    # create_tmp returns a stable path that nox does not wipe between runs,
    # so a prior clone survives.  Keying the checkout dir on the tag makes
    # reuse correct without any re-fetch: an immutable tag never changes, and
    # bumping _NFT_CORPUS_TAG lands in a fresh dir instead of silently running
    # the suite against a stale corpus.  A single pinned tag is intentional --
    # layer 2's baseline is coupled to one (corpus, system nft) pair, so there
    # is no loop over versions.
    corpus = Path(session.create_tmp()) / f"nftables-{_NFT_CORPUS_TAG}"
    if not (corpus / "tests" / "py").is_dir():
        if corpus.exists():
            # Partial or stale leftover: git refuses a non-empty target.
            shutil.rmtree(corpus)
        session.run(
            "git",
            "clone",
            "--depth=1",
            "--branch",
            _NFT_CORPUS_TAG,
            _NFT_CORPUS_REPO,
            str(corpus),
            external=True,
        )
    _uv(
        session,
        "pytest",
        "tests/conformance/nft",
        *session.posargs,
        env={
            "FERM_NFT_CORPUS": str(corpus / "tests" / "py"),
            **_WARN_ENV,
        },
    )


@nox.session
def datapath_e2e(session: nox.Session) -> None:
    """
    Containerized data-plane e2e: real traffic through ferm rules (docker).

    Builds a three-netns topology (client/fw/backend on veth) in one
    container, applies each ferm scenario config inside ``fw`` for both
    the ``--nft`` and the default iptables backend, and probes from
    ``client`` with ``nmap --reason`` / ``ncat``.  Proves the data plane
    (allowed traffic passes, blocked is cut) and backend parity on the
    same config.  Opt-in (needs the docker daemon; the test skips itself
    when docker is absent or the host kernel lacks conntrack) and
    deliberately absent from ``preflight``.
    """
    _uv(
        session,
        "pytest",
        "tests/e2e/test_datapath_e2e.py",
        *session.posargs,
        env={
            "FERM_DATAPATH_E2E": "1",
            "FERM_DATAPATH_TAG": "debian-bookworm",
            "FERM_DATAPATH_BASE": "debian:bookworm-slim",
        },
    )


#: Distro matrix for ``datapath_e2e_matrix``.  Each value is the base
#: image fed to the Dockerfile's ``BASE`` build ARG; the key is both the
#: parametrize id and the image tag (``FERM_DATAPATH_TAG``).  Adding a
#: distro is a one-line entry -- install-toolbox.sh already detects the
#: package manager and installs the family's package names.
DATAPATH_MATRIX = {
    "debian-bookworm": "debian:bookworm-slim",
    "debian-trixie": "debian:trixie-slim",
    "ubuntu-2404": "ubuntu:24.04",
    "alpine": "alpine:3.20",
    "rocky9": "rockylinux:9",
    "fedora": "fedora:41",
    "arch": "archlinux:latest",
    "opensuse-leap": "opensuse/leap:15.6",
}


@nox.session
@nox.parametrize("distro", list(DATAPATH_MATRIX))
def datapath_e2e_matrix(session: nox.Session, distro: str) -> None:
    """
    Run the datapath e2e on one matrix distro (opt-in, docker).

    Select one with `nox -s "datapath_e2e_matrix(distro='alpine')"`;
    a bare `nox -s datapath_e2e_matrix` runs every distro in turn.
    """
    base = DATAPATH_MATRIX[distro]
    _uv(
        session,
        "pytest",
        "tests/e2e/test_datapath_e2e.py",
        *session.posargs,
        env={
            "FERM_DATAPATH_E2E": "1",
            "FERM_DATAPATH_BASE": base,
            "FERM_DATAPATH_TAG": distro,
        },
    )


@nox.session
def docker_coexistence_e2e(session: nox.Session) -> None:
    """
    Containerized ferm/docker coexistence e2e against a real engine (docker).

    Runs a genuine docker 29 engine inside a privileged docker-in-docker
    container (native nftables backend), lets it create its
    ``docker-bridges`` tables, then applies a ferm ``--nft`` config twice
    (the second apply models ``ferm reload``) and asserts the docker
    tables survive byte-for-byte -- the operational promise that a rule
    edit no longer forces a full ``docker restart``.  Also witnesses that
    docker's forward chain shares ferm's default priority (0), the basis
    for the base-chain priority knob.  The inner engine's netfilter state
    lives in the throwaway container netns, so the host firewall is never
    touched.  Opt-in (needs the docker daemon; the test skips itself when
    docker is absent) and deliberately absent from ``preflight``.
    """
    _uv(
        session,
        "pytest",
        "tests/e2e/test_docker_coexist_e2e.py",
        *session.posargs,
        env={"FERM_DOCKER_COEXIST_E2E": "1"},
    )


@nox.session
def delta_apply_e2e(session: nox.Session) -> None:
    """
    Opt-in live proof that delta-apply preserves counters/set state.

    Runs the port inside its uv venv (so ``python -m pyferm`` imports); each
    test wraps its nft work in its own rootless ``unshare -rn`` and skips
    itself when nft or unprivileged user namespaces are absent.  Deliberately
    absent from ``preflight``.
    """
    _uv(
        session,
        "pytest",
        "tests/e2e/test_delta_apply_e2e.py",
        *session.posargs,
        env={"FERM_E2E": "1", **_WARN_ENV},
    )


@nox.session
def binary(session: nox.Session) -> None:
    """
    Build the standalone binary and run golden against it (opt-in, docker).

    Builds with packaging/build.py, then runs the FULL golden suite against
    the artifact via a pyferm-free venv + scrubbed-env binary child, then the
    fast smoke checks. Cold Nuitka builds take minutes; absent from
    ``preflight``.
    """
    session.run(
        "python",
        "packaging/build.py",
        "--action=build",
        "--mode=dev",
        "--out",
        "dist",
        external=True,
    )
    session.run(
        "python",
        "packaging/build.py",
        "--action=verify-golden",
        "--out",
        "dist",
        external=True,
    )
    session.run(
        "python",
        "packaging/build.py",
        "--action=smoke",
        "--out",
        "dist",
        external=True,
    )


#: Old-glibc runtime image for the glibc-floor gate. debian:10-slim (buster)
#: ships glibc 2.28, matching the manylinux_2_28 build floor exactly -- a newer
#: runtime (e.g. bullseye's 2.31) would only prove "runs on 2.31+", never the
#: 2.28 promise. Deliberately tag-pinned, not @sha256-pinned: buster is EOL, so
#: its glibc stays frozen at 2.28 (only security patches land within the same
#: minor), and the tag will not drift to a newer glibc.
_GLIBC_FLOOR_IMAGE = "debian:10-slim"


@nox.session
def binary_glibc(session: nox.Session) -> None:
    """
    Run the packaged binary on a pinned old-glibc image (opt-in, docker).

    The real distribution contract: the finished tarball must load and run on
    a SEPARATE pinned old-glibc image, not just the build container. Opt-in
    (needs the docker daemon) and deliberately absent from ``preflight``.
    """
    session.run(
        "python",
        "packaging/build.py",
        "--action=run-on-image",
        "--image",
        _GLIBC_FLOOR_IMAGE,
        "--out",
        "dist",
        external=True,
    )


@nox.session
def binary_dns(session: nox.Session) -> None:
    """
    Verify the frozen dnspython resolves a non-A record (opt-in, docker).

    Runs the hermetic non-A resolve gate against the PACKAGED tar in a
    one-shot container: a throwaway authoritative resolver answers an MX
    query the stdlib stub cannot serve, proving dnspython really froze in.
    Deliberately absent from ``preflight``.
    """
    session.run(
        "python",
        "packaging/build.py",
        "--action=run-dns-gate",
        "--out",
        "dist",
        external=True,
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
        # Install the ``dns`` extra so lowest-direct actually pins the EXTRA's
        # floor (dnspython 2.2.1, the bookworm version). Without ``.[dns]`` the
        # only dnspython requirement is the test group's higher pin, and the
        # lower-bound test would be theatre.
        "-e",
        ".[dns]",
        "--group",
        "test",
        external=True,
        env={"VIRTUAL_ENV": ".venv-lowest"},
    )
    session.run(
        ".venv-lowest/bin/python",
        "-m",
        "pytest",
        *_XDIST,
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
    broken entry points.  PyPI publishing uses ``uv`` (no ``twine``), so
    artifact validation is ``check-wheel-contents`` plus the explicit
    zipfile assertion that covers ``py.typed`` (the one promise
    ``--verifytypes`` makes that check-wheel-contents does not test for);
    the build itself (``uv build``) is the metadata check that
    ``twine check`` used to provide.  Then the wheel installs into a
    throwaway venv where both console scripts must answer.
    """
    out = Path(session.create_tmp())
    # create_tmp does not wipe an existing directory: stale artifacts
    # from a previous run (an old-version wheel, the smoke venv) would
    # leak into the globs below.
    shutil.rmtree(out)
    out.mkdir()
    session.run("uv", "build", "--out-dir", str(out), external=True)
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
def build_deb(session: nox.Session) -> None:
    """
    Build the native .deb in the pinned debian image (opt-in, docker).

    Assembles a clean source tree with debian/ at its root, stamps the version
    via dch, runs dpkg-buildpackage + lintian (E: reds) inside the
    digest-pinned debian:bookworm-slim toolchain image, and version-anchors
    the dpkg Version field. Cold runs pull the base image; absent from
    ``preflight`` (like ``binary``).
    """
    session.run(
        "python",
        "packaging/build.py",
        "--action=build-deb",
        "--mode=dev",
        "--out",
        "dist",
        external=True,
    )


@nox.session
def deb_smoke(session: nox.Session) -> None:
    """
    Install-smoke the built .deb in clean containers (opt-in, docker).

    Runs the install-smoke cells against the artifact in ``dist/`` (build it
    first with ``nox -s build_deb``): a clean install (version, config parse,
    examples, stdlib-resolver fallback, file-based not-enabled assert), the
    Perl-ferm migration paths, and the fail-closed source-tar / sdist
    allowlist manifest. Absent from ``preflight``.
    """
    session.run(
        "python",
        "packaging/build.py",
        "--action=smoke-deb",
        "--out",
        "dist",
        external=True,
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

    Both linters come from the locked ``lint`` group (actionlint via the
    ``actionlint-py`` vendored-binary wheel), so the session runs the
    same versions everywhere -- locally and in the weekly audit job.
    """
    # actionlint discovers .github/workflows on its own; zizmor needs
    # the path spelled out.
    _uv(session, "actionlint")
    _uv(session, "zizmor", ".github/workflows")


@nox.session
def image_scan(session: nox.Session) -> None:
    """
    Scan the pinned build image for fixable CVEs in bundled native libs.

    ``pip-audit`` (the ``audit`` session) sees only Python deps; this covers
    the OpenSSL/libffi/xz/... shared objects Nuitka freezes into the
    standalone dist -- and the manylinux OpenSSL is the EOL 1.1.x series, so a
    CVE there arrives with no push a code-time gate would catch.  Needs docker
    + network (Trivy pulls the digest-pinned image and its vuln DB).  Reports
    only fixable HIGH/CRITICAL CVEs in the rpm packages that actually ship a
    ``.so``, so it is an ACTIONABLE rebuild trigger, not noise.  Opt-in (absent
    from the default sessions); the weekly ``audit.yml`` runs it.
    """
    if shutil.which("docker") is None:
        session.skip("docker not available")
    session.run(
        "python",
        "packaging/scan_image.py",
        *session.posargs,
        external=True,
    )


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
