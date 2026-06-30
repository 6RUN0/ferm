"""
Standalone-binary build driver.

A thin wrapper over ``docker build``/``docker run`` (mirrors
``tests/e2e/datapath/driver.py``), parametrized by ``--arch`` so aarch64
is one matrix row, not a refactor. Two source modes:

* ``--mode=dev`` (default): bind-mount the working tree (x86_64 convenience).
* ``--mode=release``: build ONLY from ``git archive <tag>`` into a scratch
  dir -- clean by construction and tag-bound (supply-chain hygiene). NEVER
  from a bind-mounted live tree.

Emits ``ferm-<version>-linux-<arch>.tar.gz`` + ``SHA256SUMS`` into ``--out``.
Fails the build (red, no partial artifact published) on: missing toolchain,
a frozen-import probe miss, a Nuitka unresolved-import warning, or any ``.so``
outside the fail-closed allow-list.

``--action`` selects the operation; every gate the later tasks and
``release.yml`` invoke is a declared action here, NOT an undeclared flag:

* ``build`` (default) -- compile, run the BLOCKER frozen-import and
  allow-list gates, package the tar.
* ``verify-golden`` -- run the FULL golden suite against the packaged binary
  in a pyferm-free interpreter + scrubbed child env.
* ``smoke`` -- fast version/help/config/diagnostics checks.
* ``run-dns-gate`` -- hermetic non-A resolve gate (BLOCKER).
* ``run-interactive-gate`` -- ``--interactive`` confirm-timeout.
* ``run-on-image`` -- run the packaged tar on ``--image`` (glibc floor).

All non-``build`` actions operate on the ALREADY-PACKAGED tar in ``--out``
(located + unpacked via ``_dist_binary``), never on a fresh compile, so a
release runs ``build`` once then verifies the same artifact every gate ships.
"""

from __future__ import annotations

import argparse
import atexit
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

_REPO_ROOT = Path(__file__).resolve().parents[1]
_IMAGE = "ferm-build"
#: Native .deb build image (debian:bookworm-slim + deb toolchain) and the
#: source dir holding ``debian/`` plus the shipped config/examples.
_DEB_IMAGE = "ferm-deb-build"
_DEB_DIR = _REPO_ROOT / "packaging" / "deb"
#: Maintainer identity for ``dch`` (DEBFULLNAME/DEBEMAIL); a placeholder would
#: be a lintian E:. Matches debian/control's Maintainer and the git identity.
_DEB_FULLNAME = "Boris Talovikov"
_DEB_EMAIL = "boris@talovikov.ru"
#: Native .rpm build image (Fedora + rpm toolchain) and the source dir holding
#: the spec. The smoke runs on a stock Fedora to prove a non-toolchain host.
_RPM_IMAGE = "ferm-rpm-build"
_RPM_DIR = _REPO_ROOT / "packaging" / "rpm"
_RPM_SMOKE_BASE = "fedora:43"
#: Native .apk build image (Alpine + abuild toolchain) and the source dir
#: holding the APKBUILD, the OpenRC service and the install scriptlets. The
#: smoke runs on a stock Alpine to prove a non-toolchain host.
_APK_IMAGE = "ferm-apk-build"
_APK_DIR = _REPO_ROOT / "packaging" / "apk"
_APK_SMOKE_BASE = "alpine:3.24"
#: pyproject distribution name (``[project].name``); the rpm Source0 tarball is
#: ``<dist>-<version>.tar.gz`` and the spec's ``%autosetup`` unpacks that dir.
_PACKAGE_DIST = "ferm"
#: Canonical dist directory name inside the shipped tar (``ferm.dist/``).
#: Nuitka names it after the main module (``entry.dist``); the container
#: build script renames it so the user-facing path matches docs.
_DIST_DIRNAME = "ferm.dist"
#: The hermetic non-A resolve gate lives in its own throwaway image so the
#: authoritative test resolver never touches the build workspace.
_DNS_GATE_DIR = _REPO_ROOT / "packaging" / "dns_gate"
_DNS_GATE_IMAGE = "ferm-dns-gate"
#: The interactive confirm/timeout gate reuses the datapath image (a
#: netfilter + Python toolbox) but runs its standalone interactive scenario.
_INTERACTIVE_GATE_IMAGE = "ferm-datapath-e2e-interactive"

# The canonical list of load-bearing frozen modules lives in
# packaging/entry.py (_REQUIRED_FROZEN). The integrity gate proves them FROM
# the binary via FERM_SELFCHECK, so build.py does not redeclare it.

# Fail-CLOSED allow-list of EXACT .so basenames Nuitka legitimately freezes
# into the dist. A prefix allow-list ("lib*") is fail-OPEN: it would admit a
# planted libcrypto.so/libssl.so -- exactly the library-planting LPE target.
# So this is an exact set, version suffix normalized, and anything not on it
# -> red build. glibc/libnss_*/libm/libpthread are deliberately host-side and
# must be ABSENT.
#
# SEED THIS from the first real build: run, list the actual .so set, and
# freeze it here. Until seeded, the gate treats an unknown .so as a hard
# failure -- that is the point, not a nuisance. Grows only via review.
# Seeded from the first real build: manylinux_2_28 cp313, Nuitka 4.1.2. The
# Manylinux Python flavor names stdlib extension modules WITHOUT the
# ``.cpython-313-...`` ABI suffix (plain ``_ssl.so``), and OpenSSL is the
# 1.1 series here (``libssl.so.1.1`` -> key ``libssl.so.1``). Re-seed and
# review on any image-digest or Python/OpenSSL bump.
_ALLOWED_SO_NAMES: frozenset[str] = frozenset(
    {
        "_asyncio.so",
        "_blake2.so",
        "_bz2.so",
        "_codecs_cn.so",
        "_codecs_hk.so",
        "_codecs_iso2022.so",
        "_codecs_jp.so",
        "_codecs_kr.so",
        "_codecs_tw.so",
        "_contextvars.so",
        "_csv.so",
        "_ctypes.so",
        "_datetime.so",
        "_decimal.so",
        "_hashlib.so",
        "_heapq.so",
        "_lzma.so",
        "_md5.so",
        "_multibytecodec.so",
        "_multiprocessing.so",
        "_opcode.so",
        "_pickle.so",
        "_posixshmem.so",
        "_posixsubprocess.so",
        "_queue.so",
        "_random.so",
        "_sha1.so",
        "_sha2.so",
        "_sha3.so",
        "_socket.so",
        "_ssl.so",
        "_statistics.so",
        "_struct.so",
        "array.so",
        "binascii.so",
        "fcntl.so",
        "grp.so",
        "libbz2.so.1",
        "libcrypto.so.1",
        "libffi.so.6",
        "liblzma.so.5",
        "libmpdec.so.4",
        "libssl.so.1",
        "math.so",
        "mmap.so",
        "pyexpat.so",
        "select.so",
        "termios.so",
        "unicodedata.so",
        "zlib.so",
    },
)
# Host libs that must NEVER appear inside the dist (belt-and-suspenders on top
# of the exact allow-list): their presence means a static link leaked in.
_FORBIDDEN_SO_SUBSTRINGS = ("libc.so", "libnss_", "libm.so", "libpthread")


_ACTIONS = (
    "build",
    "build-deb",
    "smoke-deb",
    "build-rpm",
    "smoke-rpm",
    "build-apk",
    "smoke-apk",
    "print-version",
    "verify-golden",
    "smoke",
    "run-dns-gate",
    "run-interactive-gate",
    "run-on-image",
)

#: Port releases are tagged ``py-v<PEP440>`` -- a namespace distinct from the
#: upstream Perl ``v*`` tags also reachable from this branch. The host version
#: function strips THIS prefix, never a bare ``v`` (which would mis-read an
#: upstream tag as a port release).
_TAG_PREFIX = "py-v"

#: A pushed tag reaches ``dch``/``docker -e``/the changelog as DATA. Validate
#: it against the PEP 440 charset (after the py-v prefix) BEFORE any subprocess
#: so a tag like ``py-v0.1.0;touch x`` fails early and no metacharacter ever
#: reaches a shell. The body must start with a digit (rejects ``py-vabc`` and
#: the bare prefix) and admits only PEP 440 / dpkg-version characters.
_VALID_TAG_RE = re.compile(r"^py-v[0-9][0-9A-Za-z.+!~-]*$")


def _strip_tag_prefix(tag: str) -> str:
    """Drop the ``py-v`` release prefix, leaving the PEP 440 version."""
    return tag.removeprefix(_TAG_PREFIX)


def _validate_tag(tag: str) -> None:
    """
    Reject a tag that is not a charset-clean ``py-v<PEP440>`` release tag.

    Fails CLOSED (``SystemExit``) before the tag can flow into any
    subprocess argument, so shell metacharacters in a crafted tag never
    reach ``dch``/``docker``/the changelog (injection defense).
    """
    if not _VALID_TAG_RE.fullmatch(tag):
        raise SystemExit(
            f"refusing tag {tag!r}: not a py-v<PEP440> release tag "
            "(must match ^py-v[0-9][0-9A-Za-z.+!~-]*$)",
        )


def _tag_version(sanitize: Callable[[str], str] | None = None) -> str:
    """
    Return the (optionally sanitized) prefix-stripped release tag, or "".

    Centralizes the release discriminator: the value is a release version ONLY
    when GITHUB_REF_TYPE == "tag" (not the mere presence of GITHUB_REF_NAME,
    which GitHub sets on branch pushes too). _validate_tag runs BEFORE the
    value is returned, so the injection-defense ordering holds for every
    caller.
    """
    ref = os.environ.get("GITHUB_REF_NAME", "")
    if not ref or os.environ.get("GITHUB_REF_TYPE") != "tag":
        return ""
    _validate_tag(ref)
    stripped = _strip_tag_prefix(ref)
    return sanitize(stripped) if sanitize else stripped


#: PEP 440 charset gate for the OFF-TAG (setuptools-scm) version. The tag path
#: validates via ``_validate_tag``; this enforces the same injection-defense on
#: the dev/dispatch path before the value flows to ``sed``/``--define``/env.
_VALID_SCM_RE = re.compile(r"^[0-9][0-9A-Za-z.+!~-]*$")


def _tilde_prerelease(base: str) -> str:
    """
    ``~``-prefix PEP 440 pre-release/dev markers so they sort BELOW the final.

    ``rpmvercmp`` and dpkg ``verrevcmp`` both rank a trailing alphanumeric run
    (``a2``, ``dev5``) ABOVE the bare release, so an un-prefixed ``0.1.0a2``
    sorts above ``0.1.0`` and the final release looks like a DOWNGRADE -- the
    package manager then refuses the upgrade. ``~`` is the one token both
    comparators sort before the empty end-of-part, so ``0.1.0~a2`` restores the
    PEP 440 order. ``.postN`` is intentionally left alone: a post-release
    legitimately sorts ABOVE its base release.
    """
    base = re.sub(r"(?<=\d)(a|b|rc)(\d+)", r"~\1\2", base)
    return re.sub(r"\.dev(\d+)", r"~dev\1", base)


def _sanitize_deb(version: str) -> str:
    """
    Normalize a PEP 440 version into a native-dpkg-safe version.

    Native dpkg forbids a debian revision (``-N``) and the local PEP 440
    segment (``+g<hash>``, plus the ``.dYYYYMMDD`` dirty marker that rides in
    it) is unwanted in a native version, so this DROPS the whole local ``+``
    segment. Pre-release/dev markers are then ``~``-prefixed (see
    ``_tilde_prerelease``) so a later final release sorts ABOVE the alpha and
    ``apt`` delivers the upgrade. The SAME function feeds the changelog
    and the version-anchor gate, or the gate would false-red.
    """
    return _tilde_prerelease(version.split("+", 1)[0])


def _sanitize_rpm(version: str) -> str:
    """
    Normalize a PEP 440 version into an rpm-safe Version field.

    rpm forbids ``-`` in a Version (it separates name-version-release), so this
    DROPS the local ``+...`` segment and maps any ``-`` to ``~``. Pre-release/
    dev markers are ``~``-prefixed (see ``_tilde_prerelease``) so a later final
    release sorts ABOVE the alpha -- the ordering the apk sanitizer reaches
    with its ``_alpha``/``_pre`` suffixes, one strategy across all three native
    packages. The full PEP 440 string is fed to hatch-vcs (the spec's
    ``scm_version``), so the wheel METADATA keeps the exact version regardless.
    """
    return _tilde_prerelease(version.split("+", 1)[0]).replace("-", "~")


def _sanitize_apk(version: str) -> str:
    """
    Normalize a PEP 440 version into an Alpine-pkgver-safe Version field.

    Alpine's grammar accepts a numeric release optionally followed by
    ``_<suffix><number>`` markers, NOT the PEP 440 ``a``/``b``/``rc``/``.dev``/
    ``.post`` spellings. So this DROPS the local ``+...`` segment (as the
    deb/rpm sanitizers do) and maps the markers to their Alpine forms: ``a`` ->
    ``_alpha``, ``b`` -> ``_beta``, ``rc`` -> ``_rc``, ``.devN`` -> ``_preN``
    (``_pre`` keeps dev builds distinct from a real alpha; both sort BELOW the
    release), ``.postN`` -> ``_pN`` (the Alpine post suffix, sorts ABOVE the
    release like PEP 440 intends). The full PEP 440 string is fed to hatch-vcs
    separately, so the wheel METADATA keeps the exact version regardless.

    Caveat: apk orders ``_alpha < _beta < _pre < _rc < release``, so mapping
    ``.devN`` to ``_preN`` sorts a dev marker ABOVE ``_alpha``/``_beta``. The
    PEP 440 ``dev < alpha`` ordering therefore holds only for the combined
    ``aN.devM`` shape (where the ``_alphaN`` prefix dominates the compare), not
    for a bare ``.devM``. This affects only unpublished dev/CI artifacts;
    released versions never carry a bare dev marker.
    """
    base = version.split("+", 1)[0]
    base = re.sub(r"\.post(\d+)", r"_p\1", base)
    base = re.sub(r"\.dev(\d+)", r"_pre\1", base)
    base = re.sub(r"(?<=\d)a(\d+)", r"_alpha\1", base)
    base = re.sub(r"(?<=\d)b(\d+)", r"_beta\1", base)
    return re.sub(r"(?<=\d)rc(\d+)", r"_rc\1", base)


#: Shell ``sani()`` mirroring _sanitize_deb EXACTLY (and _sanitize_rpm up to
#: the hyphen -- deb keeps ``-`` where rpm maps it to ``~``), injected into the
#: deb install-smoke cell so the package Version can be anchored against the
#: binary's PEP 440 self-report (a ~-prefixed pre-release no longer equals a
#: bare ``${ver%%+*}``). An independent reimplementation IS the point -- it is
#: the verification oracle, not a reuse of the Python sanitizer.
_SANI_SH_TILDE = (
    "sani() { printf '%s' \"${1%%+*}\" | "
    "sed -E 's/([0-9])(a|b|rc)([0-9])/\\1~\\2\\3/g; "
    "s/\\.dev([0-9])/~dev\\1/g'; }\n"
)

#: Shell ``sani()`` faithful to _sanitize_rpm: _SANI_SH_TILDE plus the rpm
#: '-'->'~' map (rpm forbids '-' in a Version). deb keeps '-', so it stays on
#: _SANI_SH_TILDE.
_SANI_SH_RPM = (
    "sani() { printf '%s' \"${1%%+*}\" | "
    "sed -E 's/([0-9])(a|b|rc)([0-9])/\\1~\\2\\3/g; "
    "s/\\.dev([0-9])/~dev\\1/g; s/-/~/g'; }\n"
)

#: Shell ``sani()`` mirroring _sanitize_apk for the apk install-smoke anchor.
_SANI_SH_APK = (
    "sani() { printf '%s' \"${1%%+*}\" | "
    "sed -E 's/\\.post([0-9])/_p\\1/g; s/\\.dev([0-9])/_pre\\1/g; "
    "s/([0-9])a([0-9])/\\1_alpha\\2/g; s/([0-9])b([0-9])/\\1_beta\\2/g; "
    "s/([0-9])rc([0-9])/\\1_rc\\2/g'; }\n"
)


def _scm_version() -> str:
    """
    Return the version hatch-vcs will freeze, via ``hatch version``.

    NOT ``python -m setuptools_scm``: the scoped describe/tag config lives
    under ``[tool.hatch.version.raw-options]`` (hatch-vcs's namespace), which
    the bare setuptools-scm CLI does not read -- it would pick an upstream
    ``v*`` tag and emit the wrong line. ``hatch version`` reads the project's
    real version source, so it returns EXACTLY what gets frozen into the
    wheel/binary METADATA. Only reached off-tag (dev / dispatch); a release
    tag short-circuits in ``_resolve_version`` and never shells out.
    """
    result = subprocess.run(
        ["uvx", "hatch", "version"],
        capture_output=True,
        text=True,
        check=True,
    )
    # ``uvx`` prints dependency-sync chatter to stderr; the version is the
    # last non-empty stdout line.
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise SystemExit(
            "`uvx hatch version` produced no version on stdout",
        )
    version = lines[-1].strip()
    # Charset-gate the off-tag version too (the tag path has _validate_tag), so
    # the same injection-defense holds before it flows to sed/--define/env.
    if not _VALID_SCM_RE.fullmatch(version):
        raise SystemExit(
            f"refusing scm version {version!r}: not a PEP 440 charset",
        )
    return version


def _resolve_version() -> str:
    """
    Resolve the single version string fed to every artifact.

    Release (``GITHUB_REF_TYPE == tag``, e.g. ``py-v0.1.0``): validate the tag
    (charset gate) and strip the ``py-v`` prefix. Off-tag (dev / dispatch):
    the setuptools-scm value via ``_scm_version``. The discriminator is
    ``GITHUB_REF_TYPE``, not the mere presence of ``GITHUB_REF_NAME`` (which
    GitHub sets on branch pushes / ``workflow_dispatch`` too).
    """
    if tv := _tag_version():
        return tv
    return _scm_version()


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the build-driver command line."""
    parser = argparse.ArgumentParser(prog="build.py")
    parser.add_argument("--action", choices=_ACTIONS, default="build")
    parser.add_argument("--arch", default="x86_64")
    parser.add_argument("--mode", choices=("dev", "release"), default="dev")
    parser.add_argument("--tag", help="git tag/ref for --mode=release")
    parser.add_argument(
        "--image",
        help="runtime image for --action=run-on-image",
    )
    parser.add_argument("--out", type=Path, default=_REPO_ROOT / "dist")
    parser.add_argument(
        "--deb",
        action="store_true",
        help="with --action=print-version: emit the deb-sanitized version",
    )
    return parser.parse_args(argv)


def _scratch_dir(prefix: str) -> Path:
    """
    Make a temp dir auto-removed when the build driver exits.

    The archive, build-output, and unpack dirs each outlive the function that
    creates them -- their paths are returned to the caller and used by later
    steps -- so cleanup is deferred to process exit rather than a local
    context manager. ``ignore_errors`` keeps a half-written tree from masking
    the real build error on the way out.
    """
    path = Path(tempfile.mkdtemp(prefix=prefix))
    atexit.register(shutil.rmtree, path, ignore_errors=True)
    return path


def _source_root(mode: str, tag: str | None) -> Path:
    """Return the dir whose ``src``/``packaging`` Nuitka compiles."""
    if mode == "dev":
        _assert_clean_optional()
        return _REPO_ROOT
    if not tag:
        raise SystemExit("--mode=release requires --tag <vX.Y.Z>")
    return _git_archive(tag)


def _git_archive(tag: str) -> Path:
    """Export a clean tag checkout into a scratch dir (supply-chain safety)."""
    # Annotated tags: rev-parse <tag> yields the tag OBJECT, not the commit;
    # dereference via rev-list -n1 (the classic mistake).
    commit = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "rev-list", "-n1", tag],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    scratch = _scratch_dir("ferm-release-")
    archive = scratch / "src.tar"
    subprocess.run(
        [
            "git",
            "-C",
            str(_REPO_ROOT),
            "archive",
            "--format=tar",
            "-o",
            str(archive),
            commit,
        ],
        check=True,
    )
    shutil.unpack_archive(str(archive), str(scratch / "tree"))
    archive.unlink()
    return scratch / "tree"


def _assert_clean_optional() -> None:
    """
    Warn (belt-and-suspenders) if the dev tree is dirty.

    Untracked files MUST be visible (no -uno): a planted untracked file is
    invisible otherwise. Release builds never reach here.
    """
    status = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if status.strip():
        print(
            "WARNING: dev build from a dirty tree (not tag-bound)",
            file=sys.stderr,
        )


def _nuitka_argv(out_dir: str) -> list[str]:
    """
    Build the Nuitka command line.

    Network downloads must FAIL, not silently pull an unpinned supply-chain
    input -- so the container runs with --network=none and the cache is
    pre-seeded.
    """
    return [
        "python",
        "-m",
        "nuitka",
        "--standalone",
        "--include-module=signal",
        "--include-module=termios",
        "--include-package=dns",
        "--include-package=dns.rdtypes",
        # Sever only the async RESOLVER (the bloat target). dns.asyncbackend
        # must NOT be excluded: dnspython 2.8.0 eagerly imports it via
        # dns.resolver -> dns._ddr at module top, so excluding it makes the
        # frozen ``import dns.resolver`` (resolver.py) raise ImportError --
        # the integrity gate catches this. asyncbackend itself only
        # pulls dns.exception/dns._asyncbackend at import time; the trio/curio
        # backends stay function-local and uninstalled, so no extra bloat.
        "--nofollow-import-to=dns.asyncresolver",
        "--include-distribution-metadata=ferm",  # --version fix
        # Emit the compilation report so the integrity gate can scan it for
        # unresolved-import warnings. Nuitka writes NO report by default --
        # without this the gate's report arm is inert.
        f"--report={out_dir}/Nuitka-report.xml",
        f"--output-dir={out_dir}",
        "/work/packaging/entry.py",
    ]


def _container_build_script(out_dir: str, uid: int, gid: int) -> str:
    """
    Render the in-container shell: install, compile, post-process, chown.

    Post-processing (rename ``entry.bin``->``ferm``, ``entry.dist``->
    ``ferm.dist``, create the in-dist ``import-ferm`` symlink) happens IN the
    container, because Nuitka writes root-owned output a host user could not
    rename. The final ``chown`` hands the tree to the invoking uid so
    packaging and every gate run unprivileged. ``pip install .`` first so
    Nuitka can statically trace ``entry.py`` -> ``pyferm.*``.

    ``--no-build-isolation`` is required under --network=none: pip would
    otherwise spin a fresh build env and re-fetch the PEP 517 backend
    (hatchling) from PyPI. The image pre-installs the pinned hatchling, so
    the build uses it offline.

    License collection (``collect_licenses.py``) also runs here, before the
    chown: it needs the container's ``rpm`` and ``/usr/share/licenses`` tree
    to copy each bundled library's notice into the dist, and fails closed on
    a missing one.
    """
    nuitka = " ".join(_nuitka_argv(out_dir))
    return (
        f"pip install --no-cache-dir --no-build-isolation /work "
        f"&& {nuitka} && "
        f"cd {out_dir} && "
        f"mv entry.dist/entry.bin entry.dist/ferm && "
        # relative in-dist symlink
        f"ln -sf ferm entry.dist/import-ferm && "
        f"mv entry.dist {_DIST_DIRNAME} && "
        # Gather third-party license texts INTO the dist (needs in-container
        # rpm + the system license tree); fail-closed on any missing notice.
        f"python /work/packaging/collect_licenses.py "
        f"{out_dir}/{_DIST_DIRNAME} && "
        f"chown -R {uid}:{gid} {_DIST_DIRNAME} entry.build "
        f"Nuitka-report.xml"
    )


def _run_build(source_root: Path, version: str) -> Path:
    """
    Build inside the image; return the host path to ``ferm.dist``.

    The writable output is a host tempdir OUTSIDE ``source_root`` (dev
    hygiene): writing ``build-out/`` inside the repo tree would show up as
    untracked dirt to the very ``git status`` check that guards the dev path.

    ``version`` is injected as ``SETUPTOOLS_SCM_PRETEND_VERSION`` so hatch-vcs
    freezes the right version inside the ``.git``-less container (``git
    archive`` strips ``.git``, so a describe would otherwise fall to the
    ``fallback_version`` 0.0.0). The GENERIC pretend variable is used, NOT the
    scoped ``..._FOR_FERM``: hatch-vcs 0.5.0 wraps vcs-versioning and does not
    pass the dist name through, so the scoped form is silently ignored
    (verified). The generic form takes absolute precedence over any tree state
    and is safe here -- only ``ferm`` is built in this container.
    """
    build_out = _scratch_dir("ferm-build-out-")
    out_dir = "/work-out"
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "-v",
        f"{source_root}:/work:ro",
        "-v",
        f"{build_out}:{out_dir}",  # writable out, outside the source tree
        "-e",
        f"SETUPTOOLS_SCM_PRETEND_VERSION={version}",
        _IMAGE,
        "sh",
        "-c",
        _container_build_script(out_dir, os.getuid(), os.getgid()),
    ]
    subprocess.run(cmd, check=True)
    dist = build_out / _DIST_DIRNAME
    produced = dist / "ferm"
    if not produced.is_file():
        raise SystemExit(
            f"build produced no {produced} -- Nuitka layout changed",
        )
    return dist


def _assert_frozen_imports(dist: Path) -> None:
    """
    Prove required modules are frozen in -- two conditions.

    A typo in --include-* silently no-ops AND Nuitka often exits 0 with only a
    warning on an unresolved import, so a BLOCKER gate is mandatory.

    Condition 1 (FROM the binary): run the binary with FERM_SELFCHECK=1 --
    entry.selfcheck_frozen() imports signal/termios/dns.resolver/dns.rdtypes
    in the FROZEN runtime and exits non-zero if any failed to bundle. This is
    authoritative: it tests importability, not mere file presence (a glob can
    match a package dir whose submodules are absent).

    Condition 2 (build report): scan Nuitka's compilation report (emitted by
    --report=) for unresolved-import warnings.
    """
    # Condition 1: the self-probe from the binary. The dist binary targets
    # glibc 2.28; the (newer) build host is forward-compatible, so it runs
    # here.
    probe = subprocess.run(
        [str(dist / "ferm")],
        env={**os.environ, "FERM_SELFCHECK": "1"},
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0 or "FROZEN-SELFCHECK-OK" not in probe.stdout:
        raise SystemExit(
            "frozen self-probe failed -- a required module did not bundle "
            f"(silent --include-* no-op):\n{probe.stderr}",
        )
    # Condition 2: scan the compilation report for unresolved-import warnings.
    # This is a BACKSTOP to the authoritative self-probe in Condition 1, not
    # the primary check. The raw lowercased substring below is deliberately
    # broad; hardening it into a structured XML match anchored to Nuitka's
    # real unresolved-import marker element/attribute is a tracked follow-up
    # pending inspection of an actual Nuitka-report.xml from a real build (a
    # wrong guess at the marker name could turn this security gate false-green,
    # so it is left fail-closed-broad until a real report is on hand).
    report = dist.parent / "Nuitka-report.xml"
    if not report.exists():
        raise SystemExit(
            f"no Nuitka report at {report} -- --report= missing from the "
            "compile; the gate's report arm cannot run",
        )
    text = report.read_text(encoding="utf-8").lower()
    if "unresolved" in text:
        raise SystemExit(
            "Nuitka report flags an unresolved import -- red build "
            "(possible --include-* typo)",
        )


def _so_key(name: str) -> str:
    """
    Normalize a versioned .so basename to its allow-list key.

    libssl.so.3.0.14 -> libssl.so.3 (keep one ABI digit); _ssl.cpython-...
    stays as-is. Tune the truncation to the actual set seen on first build.

    By design this pins only the SONAME ABI MAJOR version: libssl.so.1.1 and
    libssl.so.1.0 both map to libssl.so.1. That is intentional -- the
    exact-major allow-list membership check plus the forbidden-substring gate
    still block host libs and major-version swaps, so collapsing the minor is
    safe here.
    """
    if ".so." in name:
        head, _, tail = name.partition(".so.")
        return f"{head}.so.{tail.split('.', 1)[0]}"
    return name


def _assert_so_allow_list(dist: Path) -> None:
    """
    Every .so physically in the dist must be on the EXACT allow-list.

    Enumerate files actually in the dist -- NOT ldd, which mixes bundled libs
    with host ones (glibc/libnss_* are deliberately host-side). The allow-list
    is exact (not prefix): a prefix list is fail-open and would admit a
    planted libcrypto.so (the library-planting LPE target). Reject by default.

    Also reject any .so that is a symlink pointing OUTSIDE the dist: a
    name-only check is bypassable by symlinking an allowed name to a host lib.
    """
    if not _ALLOWED_SO_NAMES:
        raise SystemExit(
            "_ALLOWED_SO_NAMES is empty -- seed it from the first build "
            "before this gate can pass (fail-closed by design)",
        )
    dist_resolved = dist.resolve()
    for so in dist.glob("**/*.so*"):
        name = so.name
        for bad in _FORBIDDEN_SO_SUBSTRINGS:
            if bad in name:
                raise SystemExit(f"forbidden host lib in dist: {name}")
        if _so_key(name) not in _ALLOWED_SO_NAMES:
            raise SystemExit(f"unexpected .so in dist: {name}")
        if so.is_symlink():
            target = so.resolve()
            if dist_resolved not in target.parents:
                raise SystemExit(
                    f".so symlink escapes the dist: {name} -> {target}",
                )


def _assert_no_unbundled_extras(dist: Path) -> None:
    """
    Assert dnspython's optional extras did not leak into the dist.

    A bare ``dnspython`` install pulls neither ``cryptography`` nor ``httpx``
    (they are [dnssec]/[doh] extras) and --nofollow-import-to severs the
    async/DoH paths. Assert they are absent so the license/size radius is a
    gate, not an assumption.
    """
    for forbidden in ("cryptography", "httpx", "h2", "aioquic"):
        as_dir = list(dist.glob(f"**/{forbidden}/"))
        as_file = list(dist.glob(f"**/{forbidden}.*"))
        if as_dir or as_file:
            raise SystemExit(
                f"unexpected optional dep {forbidden!r} in dist -- a "
                "DoH/DNSSEC extra leaked in (widens license/size radius)",
            )


def _assert_licenses_present(dist: Path) -> None:
    """
    Fail closed unless the in-container collector populated ``LICENSES/``.

    The actual license texts are gathered inside the build container by
    ``collect_licenses.py`` (it needs ``rpm`` and the system license tree,
    neither present on the host). This host-side cross-check refuses to
    package if that step was skipped or incomplete: every bundled third-party
    native library (``lib*.so*``, the non-stdlib set) must have a shipped
    license text, and the manifest index must exist. A binary that statically
    links OpenSSL/libffi/... without reproducing their notices is a GPLv2
    compliance gap, so a gap stops the build rather than shipping.
    """
    licenses_dir = dist / "LICENSES"
    manifest = licenses_dir / "MANIFEST.txt"
    if not manifest.is_file():
        raise SystemExit(
            f"no license manifest at {manifest} -- the in-container license "
            "collector did not run; refusing to package",
        )
    sonames = sorted(
        {
            so.name
            for so in dist.glob("**/lib*.so*")
            if licenses_dir not in so.parents
        },
    )
    for soname in sonames:
        if not list(licenses_dir.glob(f"{soname}.*")):
            raise SystemExit(
                f"bundled {soname} has no license text in {licenses_dir} -- "
                "compliance gap; refusing to package",
            )


def _package(dist: Path, out: Path, version: str, arch: str) -> Path:
    """tar.gz the dist (root-owned, numeric, symlinks) + SHA256SUMS."""
    out.mkdir(parents=True, exist_ok=True)
    base = f"ferm-{version}-linux-{arch}"
    tarball = out / f"{base}.tar.gz"
    # The in-container collector already wrote LICENSES/ into the dist; refuse
    # to package if any bundled library's notice is missing, then archive.
    _assert_licenses_present(dist)
    subprocess.run(
        [
            "tar",
            "czf",
            str(tarball),
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "-C",
            str(dist.parent),
            dist.name,
        ],
        check=True,
    )
    digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
    (out / "SHA256SUMS").write_text(
        f"{digest}  {tarball.name}\n",
        encoding="utf-8",
    )
    return tarball


def _dist_binary(out: Path) -> Path:
    """
    Locate + unpack the packaged tar in ``out``; return ``ferm.dist/ferm``.

    Every non-build action operates on the SAME shipped artifact, not a fresh
    compile, so each gate verifies exactly what users get. Unpacks into a
    tempdir (symlinks preserved) and returns the canonical binary path.
    """
    tarballs = sorted(out.glob("ferm-*-linux-*.tar.gz"))
    if not tarballs:
        raise SystemExit(
            f"no packaged tar in {out} -- run --action=build first",
        )
    unpack = _scratch_dir("ferm-verify-")
    with tarfile.open(tarballs[-1]) as tar:
        # filter=data: refuse unsafe members
        tar.extractall(unpack, filter="data")
    binary = unpack / _DIST_DIRNAME / "ferm"
    if not binary.is_file():
        raise SystemExit(f"packaged tar has no {_DIST_DIRNAME}/ferm")
    return binary


def _ensure_image(source_root: Path) -> None:
    """
    Build the manylinux image and hard-fail if its toolchain is missing.

    ``patchelf``/``gcc`` are load-bearing for Nuitka's standalone link step:
    their absence is not our error to recover from, so probe the freshly
    built image with ``command -v`` and refuse the build outright.
    """
    subprocess.run(
        ["docker", "build", "-t", _IMAGE, str(source_root / "packaging")],
        check=True,
    )
    probe = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            _IMAGE,
            "sh",
            "-c",
            "command -v patchelf && command -v gcc",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        raise SystemExit(
            "build image lacks patchelf or gcc -- invalid toolchain "
            f"(hard-fail):\n{probe.stdout}{probe.stderr}",
        )


def _detect_version(binary: Path) -> str:
    """
    Return the frozen package version from ``<binary> --version``.

    The first stdout line is ``ferm <ver>`` (cli.printversion); parse the
    second whitespace-separated token. The version is the dynamic hatch-vcs
    value frozen into the package METADATA via
    ``--include-distribution-metadata=ferm`` (the pretend version injected at
    build time, see ``_run_build``), so no git/hatch-vcs lookup is needed
    here -- this reads back what was frozen.
    """
    result = subprocess.run(
        [str(binary), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    lines = result.stdout.splitlines()
    first_line = lines[0] if lines else ""
    label, _, version = first_line.partition(" ")
    if label != "ferm" or not version:
        raise SystemExit(
            f"cannot parse version from {first_line!r} -- "
            "expected 'ferm <ver>'",
        )
    return version


def _action_build(args: argparse.Namespace) -> int:
    """Compile, run the BLOCKER build gates, package."""
    source_root = _source_root(args.mode, args.tag)
    _ensure_image(source_root)  # docker build + toolchain hard-fail
    # Resolve the version on the HOST (where .git / the tag is visible) and
    # inject it as the container's pretend version -- the keystone that keeps
    # the frozen METADATA correct in the .git-less build container.
    version = _resolve_version()
    dist = _run_build(source_root, version)
    _assert_frozen_imports(dist)  # frozen-import gate (BLOCKER)
    _assert_so_allow_list(dist)  # .so allow-list (BLOCKER)
    _assert_no_unbundled_extras(dist)  # optional-extra radius (BLOCKER)
    # Package under what actually froze into the binary METADATA (read back
    # from <binary> --version), not the host string -- the smoke gate then
    # cross-checks the two against the tag.
    detected = _detect_version(dist / "ferm")
    _package(dist, args.out, detected, args.arch)
    return 0


def _ensure_native_image(image: str, context_dir: Path) -> None:
    """
    Build a digest-pinned native build image (toolchain baked in).

    Shared by the deb/rpm/apk drivers: each passes its own image tag and build
    context. Unlike ``_ensure_image`` (the Nuitka image), this does not probe a
    toolchain afterward -- the native build steps fail loudly on a missing
    tool.
    """
    subprocess.run(
        ["docker", "build", "-t", image, str(context_dir)],
        check=True,
    )


def _native_source_tree(prefix: str, mode: str, tag: str | None) -> Path:
    """
    Assemble the clean source tree a native package's tarball is built from.

    Shared by the deb/rpm/apk drivers. Release: ``git archive`` the tag (clean,
    tag-bound, export-ignore honored). Dev: copy the working-tree build inputs
    -- the changes under test are typically uncommitted, so ``git archive``
    would miss them. Dev-only droppings (OMC state, bytecode) are stripped so
    they never reach the wheel hatchling builds from this tree; release mode
    never carries them, and a release build must match the dev one.
    """
    if mode == "release":
        if not tag:
            raise SystemExit("--mode=release requires --tag <py-vX.Y.Z>")
        return _git_archive(tag)
    tree = _scratch_dir(prefix) / "tree"
    tree.mkdir(parents=True)
    for rel in ("pyproject.toml", "README.md", "CHANGELOG.md", "COPYING"):
        shutil.copy2(_REPO_ROOT / rel, tree / rel)
    junk = shutil.ignore_patterns(".omc", "__pycache__", "*.pyc")
    shutil.copytree(_REPO_ROOT / "src", tree / "src", ignore=junk)
    shutil.copytree(_REPO_ROOT / "packaging", tree / "packaging", ignore=junk)
    return tree


def _deb_source_tree(mode: str, tag: str | None) -> Path:
    """
    Assemble a clean source tree with ``debian/`` at its root for dpkg.

    Shares ``_native_source_tree`` (release ``git archive`` / dev working-tree
    copy), then overlays the ``debian/`` dir (which lives under
    ``packaging/deb/``) at the tree root where ``dpkg-buildpackage`` wants it.
    """
    tree = _native_source_tree("ferm-deb-dev-", mode, tag)
    shutil.copytree(tree / "packaging" / "deb" / "debian", tree / "debian")
    return tree


def _deb_container_script(uid: int, gid: int) -> str:
    """
    Render the in-container deb build: changelog, build, lintian, anchor.

    Copies the read-only source mount into a writable build dir (dch edits the
    changelog), stamps the version via ``dch`` (the version is charset-
    validated host-side and passed by env, never interpolated into shell --
    injection-safe), builds binary-only, gates lintian on ``error`` (``E:``
    reds, ``W:`` is logged), version-anchors the ``dpkg-deb`` Version field,
    and hands the artifact to the invoking uid.
    """
    return (
        "set -e\n"
        "mkdir -p /tmp/b\n"
        "cp -a /work/. /tmp/b/pyferm\n"
        "cd /tmp/b/pyferm\n"
        'export DEBEMAIL="$DEB_EMAIL" DEBFULLNAME="$DEB_NAME"\n'
        'dch --newversion "$DEB_VER" --distribution unstable -b '
        '"Automated release build $DEB_VER"\n'
        "dpkg-buildpackage -us -uc -b\n"
        "deb=$(ls /tmp/b/pyferm_*.deb)\n"
        'echo "DEB_ARTIFACT=$deb"\n'
        # lintian: fail only on E:, W: stays informational (baseline noise
        # like binary-without-manpage / virtual-package from Provides).
        'lintian --fail-on error "$deb"\n'
        'ver=$(dpkg-deb -f "$deb" Version)\n'
        'echo "DEB_VERSION_FIELD=$ver"\n'
        # version-anchor: on a tag the deb Version must START WITH the tag;
        # off-tag it must EQUAL the host-sanitized version (catches a dch /
        # pretend-version drift and a 0+unknown from a missing PYBUILD_NAME).
        'if [ -n "$TAG_VER" ]; then\n'
        '  case "$ver" in "$TAG_VER"*) ;; *) echo "version-anchor: deb'
        ' $ver does not start with tag $TAG_VER" >&2; exit 1;; esac\n'
        "else\n"
        '  [ "$ver" = "$EXPECT_DEB_VER" ] || { echo "version-anchor: deb'
        ' $ver != expected $EXPECT_DEB_VER" >&2; exit 1; }\n'
        "fi\n"
        'cp "$deb" /work-out/\n'
        f"chown {uid}:{gid} /work-out/pyferm_*.deb\n"
    )


def _action_build_deb(args: argparse.Namespace) -> int:
    """
    Build the native ``.deb`` in the pinned debian image; gate it.

    Version flows from the single host function: the full PEP 440 string is
    injected as the package METADATA pretend version, the deb-sanitized string
    stamps the changelog and anchors the dpkg Version field.
    """
    _ensure_native_image(_DEB_IMAGE, _DEB_DIR)
    version_full = _resolve_version()
    version_deb = _sanitize_deb(version_full)
    # The build anchor compares the sanitized dpkg Version against this, so it
    # must be sanitized too (a tilde'd pre-release tag, else mismatch).
    tag_ver = _tag_version(_sanitize_deb)
    tree = _deb_source_tree(args.mode, args.tag)
    args.out.mkdir(parents=True, exist_ok=True)
    # Absolute path: ``docker -v`` treats a relative path as a NAMED VOLUME,
    # not a bind mount, so the artifact would never reach the host dir.
    out = args.out.resolve()
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{tree}:/work:ro",
        "-v",
        f"{out}:/work-out",
        "-e",
        f"SETUPTOOLS_SCM_PRETEND_VERSION={version_full}",
        "-e",
        f"DEB_VER={version_deb}",
        "-e",
        f"EXPECT_DEB_VER={version_deb}",
        "-e",
        f"TAG_VER={tag_ver}",
        "-e",
        f"DEB_NAME={_DEB_FULLNAME}",
        "-e",
        f"DEB_EMAIL={_DEB_EMAIL}",
        _DEB_IMAGE,
        "sh",
        "-c",
        _deb_container_script(os.getuid(), os.getgid()),
    ]
    subprocess.run(cmd, check=True)
    debs = sorted(args.out.glob("pyferm_*.deb"))
    if len(debs) != 1:
        raise SystemExit(
            f"expected exactly one pyferm_*.deb in {args.out}, found "
            f"{len(debs)} (a stale artifact would confuse the smoke gate)",
        )
    return 0


#: A clean base for the install-smoke (no toolchain): proves the deb installs
#: and runs on a stock debian, not just the build image.
_DEB_SMOKE_BASE = "debian:bookworm-slim"

#: Top-level entries the PyPI sdist is ALLOWED to carry (fail-closed
#: allowlist, mirrors the .gitattributes export-ignore for the deb channel).
#: hatchling always adds pyproject.toml / PKG-INFO / .gitignore.
_SDIST_ALLOWED_TOP = frozenset(
    {
        "src",
        "README.md",
        "CHANGELOG.md",
        "COPYING",
        "pyproject.toml",
        "PKG-INFO",
        ".gitignore",
    },
)

#: Private top-level paths that must NEVER appear in the deb source-tar.
_FORBIDDEN_ARCHIVE_PATHS = (
    "CLAUDE.md",
    ".mcp.json",
    ".github/",
    ".omc/",
    ".claude/",
    "docs/superpowers/",
    "tests/corpus/configs/",
    "scratch/",
    "notes/",
    "drafts/",
)


def _smoke_cell_clean() -> str:
    """Cell 1: clean install, version-anchor, config, examples, not-enabled."""
    return (
        "set -e\n"
        # The slim base ships /etc/dpkg/dpkg.cfg.d/docker with
        # `path-exclude /usr/share/doc/*`, which would drop the shipped
        # example on install. Remove it so the smoke reflects a normal system.
        "rm -f /etc/dpkg/dpkg.cfg.d/docker\n"
        "apt-get update >/dev/null\n"
        "apt-get install -y --no-install-recommends /work-out/$ART"
        " >/dev/null\n"
        "ferm --version\n"
        "import-ferm --help >/dev/null\n"
        # the shipped default config parses (--test: no real iptables needed)
        "ferm --noexec --lines --test /etc/ferm/ferm.conf >/dev/null\n"
        # the throttle example is really installed
        "test -f /usr/share/doc/pyferm/examples/ssh-throttle.conf.example\n"
        # anti-lockout: the unit is NOT enabled (no wants symlink on disk)
        "test ! -L /etc/systemd/system/multi-user.target.wants/ferm.service\n"
        # resolver stdlib fallback works without python3-dnspython: an
        # A-record @resolve() (localhost -> 127.0.0.1 via getaddrinfo) must not
        # fail. REAL resolution -- NOT --test, which would use a mock zonefile
        # and never exercise the stdlib stub -- so ferm needs the iptables tool
        # present for find_tool (it is not a package dependency).
        "apt-get install -y --no-install-recommends iptables >/dev/null\n"
        "printf 'domain ip table filter chain OUTPUT {\\n"
        " daddr @resolve(localhost) ACCEPT;\\n}\\n' > /tmp/r.ferm\n"
        "ferm --noexec --lines /tmp/r.ferm >/dev/null\n"
        # version-anchor (sani() oracle): the package Version must equal the
        # binary's PEP 440 self-report run through the SAME sanitizer -- a
        # ~-prefixed pre-release no longer equals a bare ${vferm%%+*}. On a tag
        # the binary must also self-report the tag's full PEP 440 version
        # (catches a 0+unknown from a wrong PYBUILD_NAME). TAG_VER is the
        # unsanitized tag here.
        + _SANI_SH_TILDE
        + "vferm=$(ferm --version | head -1 | cut -d' ' -f2)\n"
        "vdeb=$(dpkg-deb -f /work-out/$ART Version)\n"
        'expect=$(sani "$vferm")\n'
        '[ "$vdeb" = "$expect" ] || { echo "deb $vdeb != sani($vferm)='
        '$expect" >&2; exit 1; }\n'
        'if [ -n "$TAG_VER" ]; then\n'
        '  case "$vferm" in *"$TAG_VER") ;; *) echo "ferm $vferm not tag'
        ' $TAG_VER" >&2; exit 1;; esac\n'
        "fi\n"
        "echo CELL1-OK\n"
    )


def _smoke_cell_migration() -> str:
    """Cell 2: over a Perl-ferm layout -- config kept, downgrade breadcrumb."""
    return (
        "set -e\n"
        "apt-get update >/dev/null\n"
        "mkdir -p /etc/ferm /lib/systemd/system"
        " /etc/systemd/system/multi-user.target.wants\n"
        # an admin-edited config already at the new path + the old unit enabled
        "printf '# MARKER admin config\\n' > /etc/ferm/ferm.conf\n"
        "touch /lib/systemd/system/ferm.service\n"
        "ln -s /lib/systemd/system/ferm.service"
        " /etc/systemd/system/multi-user.target.wants/ferm.service\n"
        # An admin-customized conffile already on disk triggers dpkg's
        # "created by you" prompt; on unattended apt (closed stdin) that would
        # EOF-error. --force-confold keeps the admin's file non-interactively
        # -- exactly the migration goal (the README documents this for
        # unattended upgrades).
        "DEBIAN_FRONTEND=noninteractive apt-get install -y"
        " --no-install-recommends"
        " -o Dpkg::Options::=--force-confold"
        " -o Dpkg::Options::=--force-confdef"
        " /work-out/$ART >/dev/null\n"
        # the admin config is preserved, not clobbered by the shipped default
        "grep -q 'MARKER admin config' /etc/ferm/ferm.conf\n"
        # the posture-downgrade breadcrumb is written somewhere durable
        "test -f /etc/ferm/POSTURE-DOWNGRADE.README\n"
        "echo CELL2-OK\n"
    )


def _smoke_cell_symlink_refusal() -> str:
    """Cell 3 (R3): a symlinked legacy config is refused, not followed."""
    return (
        "set -e\n"
        "apt-get update >/dev/null\n"
        "printf 'evil\\n' > /tmp/evil.conf\n"
        "ln -sf /tmp/evil.conf /etc/ferm.conf\n"
        "apt-get install -y --no-install-recommends /work-out/$ART"
        " >/dev/null 2>/tmp/err.txt || true\n"
        # the shipped default lands as a REGULAR file, never a symlink to the
        # attacker-controlled path, and carries no evil content
        "test ! -L /etc/ferm/ferm.conf\n"
        "test -f /etc/ferm/ferm.conf\n"
        "! grep -q evil /etc/ferm/ferm.conf\n"
        "echo CELL3-OK\n"
    )


def _run_install_smoke_cell(
    out: Path,
    base_image: str,
    script: str,
    tag_ver: str,
    art: str,
    label: str,
    fmt: str,
) -> None:
    """
    Run one install-smoke cell in a clean container for any native format.

    Shared by the deb/rpm/apk smoke actions: they differ only in the stock
    base image, the single artifact basename (``art``, referenced as ``$ART``
    in the cell), and the format noun (``fmt``) used in the failure message.
    ``art`` is the exact basename the host already resolved to a single file,
    passed by env (injection-safe, mirroring ``TAG_VER``) so the cell
    references ``/work-out/$ART`` instead of a ``*`` glob that misbehaves on
    >1 match.
    """
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{out}:/work-out:ro",
            "-e",
            f"TAG_VER={tag_ver}",
            "-e",
            f"ART={art}",
            base_image,
            "sh",
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    marker = f"{label}-OK"
    if run.returncode != 0 or marker not in run.stdout:
        raise SystemExit(
            f"{fmt} install-smoke {label} failed:\n{run.stdout}\n{run.stderr}",
        )


def _assert_sdist_allowlist(out: Path) -> None:
    """Build the sdist and assert its top-level entries are all allowed."""
    subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(out)],
        check=True,
        capture_output=True,
    )
    tarballs = sorted(out.glob("ferm-*.tar.gz"))
    if not tarballs:
        raise SystemExit(f"no sdist tarball in {out}")
    with tarfile.open(tarballs[-1]) as tar:
        tops = {
            name.split("/", 2)[1]
            for name in tar.getnames()
            if "/" in name and len(name.split("/", 2)) > 1
        }
    leaked = tops - _SDIST_ALLOWED_TOP
    if leaked:
        raise SystemExit(
            f"sdist carries unexpected top-level entries: {sorted(leaked)}",
        )


def _assert_deb_source_tar_clean() -> None:
    """Assert git archive HEAD carries no private path (the deb source-tar)."""
    archive = subprocess.run(
        [
            "git",
            "-C",
            str(_REPO_ROOT),
            "archive",
            "--worktree-attributes",
            "HEAD",
        ],
        capture_output=True,
        check=True,
    )
    listing = subprocess.run(
        ["tar", "t"],
        input=archive.stdout,
        capture_output=True,
        check=True,
    ).stdout.decode("utf-8", "replace")
    for forbidden in _FORBIDDEN_ARCHIVE_PATHS:
        for line in listing.splitlines():
            if line == forbidden or line.startswith(forbidden):
                raise SystemExit(
                    f"deb source-tar leaks a private path: {line}",
                )


def _action_smoke_deb(args: argparse.Namespace) -> int:
    """
    Install-smoke the built .deb in clean containers + allowlist manifest.

    Three cells (clean install / Perl-ferm migration / symlinked-legacy
    refusal) plus the fail-closed manifest over the deb source-tar and the
    PyPI sdist. Operates on the .deb already in ``--out``.
    """
    # Absolute path: docker bind mounts need it (a relative path becomes a
    # named volume).
    out = args.out.resolve()
    debs = sorted(out.glob("pyferm_*.deb"))
    if len(debs) != 1:
        raise SystemExit(
            f"expected exactly one pyferm_*.deb in {out}, found {len(debs)} "
            "-- run --action=build-deb into a clean dist first (an ambiguous "
            "or missing artifact would version-anchor the wrong file)",
        )
    art = debs[0].name
    tag_ver = _tag_version()
    base = _DEB_SMOKE_BASE
    _run_install_smoke_cell(
        out, base, _smoke_cell_clean(), tag_ver, art, "CELL1", "deb"
    )
    _run_install_smoke_cell(
        out, base, _smoke_cell_migration(), tag_ver, art, "CELL2", "deb"
    )
    _run_install_smoke_cell(
        out, base, _smoke_cell_symlink_refusal(), tag_ver, art, "CELL3", "deb"
    )
    _assert_deb_source_tar_clean()
    _assert_sdist_allowlist(out)
    return 0


def _rpm_source_tree(mode: str, tag: str | None) -> Path:
    """
    Assemble a clean source tree the spec's Source0 tarball is built from.

    Delegates to ``_native_source_tree``: the tree carries ``packaging/`` (the
    spec installs the shipped ferm.conf, unit and example from
    ``packaging/deb/``) plus the python sources and metadata.
    """
    return _native_source_tree("ferm-rpm-dev-", mode, tag)


def _rpm_sources_dir(tree: Path, version_rpm: str) -> Path:
    """
    Pack the source tree into ``ferm-<version>.tar.gz`` next to the spec.

    Returns a scratch dir mounted at ``/work-src``: it holds the Source0
    tarball (top dir ``ferm-<version>/``, matching the spec's ``%autosetup``)
    and a copy of the spec, so the container reads both from one mount.
    """
    sources = _scratch_dir("ferm-rpm-src-")
    arc_prefix = f"{_PACKAGE_DIST}-{version_rpm}"
    with tarfile.open(sources / f"{arc_prefix}.tar.gz", "w:gz") as tar:
        tar.add(tree, arcname=arc_prefix)
    rpm_dir = tree / "packaging" / "rpm"
    shutil.copy2(rpm_dir / "pyferm.spec", sources / "pyferm.spec")
    shutil.copy2(rpm_dir / "rpmlint.toml", sources / "rpmlint.toml")
    return sources


def _rpm_container_script(uid: int, gid: int) -> str:
    """
    Render the in-container rpm build: rpmbuild, rpmlint, version-anchor.

    Builds from the spec + tarball under ``/work-src`` (the version is charset-
    validated host-side and passed by env, never interpolated into shell --
    injection-safe), gates rpmlint on errors only (``E:``; warnings stay
    informational, like the deb's ``lintian --fail-on error``), version-anchors
    the rpm Version field, and hands the artifact to the invoking uid.
    """
    return (
        "set -e\n"
        "rpmbuild -ba /work-src/pyferm.spec"
        ' --define "_topdir /tmp/rpmbuild"'
        ' --define "_sourcedir /work-src"'
        ' --define "_ferm_version $RPM_VER"'
        ' --define "_ferm_scm_version $SCM_VER"\n'
        "rpm=$(ls /tmp/rpmbuild/RPMS/noarch/pyferm-*.noarch.rpm)\n"
        'echo "RPM_ARTIFACT=$rpm"\n'
        # rpmlint: fail only on E:, warnings stay informational (baseline noise
        # like no-manual-page-for-binary / no-documentation). The curated
        # config filters domain spelling + by-design scriptlet findings.
        'rpmlint -c /work-src/rpmlint.toml "$rpm" | tee /tmp/rl.txt || true\n'
        # Fail closed if rpmlint did not run to completion (crash, missing
        # binary, bad config): its summary footer must be present, else the
        # ": E: " grep below would pass vacuously on empty output.
        "grep -Eq '[0-9]+ packages and [0-9]+ specfiles checked' /tmp/rl.txt"
        ' || { echo "rpmlint did not run to completion" >&2; exit 1; }\n'
        'if grep -q ": E: " /tmp/rl.txt; then echo "rpmlint errors" >&2;'
        " exit 1; fi\n"
        "ver=$(rpm -qp --qf '%{VERSION}' \"$rpm\")\n"
        'echo "RPM_VERSION_FIELD=$ver"\n'
        # version-anchor: on a tag the rpm Version must START WITH the tag;
        # off-tag it must EQUAL the host-sanitized version (catches a pretend-
        # version drift or a 0+unknown from a missing dist name).
        'if [ -n "$TAG_VER" ]; then\n'
        '  case "$ver" in "$TAG_VER"*) ;; *) echo "version-anchor: rpm'
        ' $ver does not start with tag $TAG_VER" >&2; exit 1;; esac\n'
        "else\n"
        '  [ "$ver" = "$EXPECT_RPM_VER" ] || { echo "version-anchor: rpm'
        ' $ver != expected $EXPECT_RPM_VER" >&2; exit 1; }\n'
        "fi\n"
        'cp "$rpm" /work-out/\n'
        f"chown {uid}:{gid} /work-out/pyferm-*.rpm\n"
    )


def _action_build_rpm(args: argparse.Namespace) -> int:
    """
    Build the native ``.rpm`` in the pinned Fedora image; gate it.

    Version flows from the single host function: the full PEP 440 string is the
    hatch-vcs pretend version (the wheel METADATA), the rpm-sanitized string is
    the rpm Version field and the version-anchor expectation.
    """
    _ensure_native_image(_RPM_IMAGE, _RPM_DIR)
    version_full = _resolve_version()
    version_rpm = _sanitize_rpm(version_full)
    tag_ver = _tag_version(_sanitize_rpm)
    tree = _rpm_source_tree(args.mode, args.tag)
    sources = _rpm_sources_dir(tree, version_rpm)
    args.out.mkdir(parents=True, exist_ok=True)
    # Absolute path: ``docker -v`` treats a relative path as a NAMED VOLUME,
    # not a bind mount, so the artifact would never reach the host dir.
    out = args.out.resolve()
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{sources}:/work-src:ro",
        "-v",
        f"{out}:/work-out",
        "-e",
        f"RPM_VER={version_rpm}",
        "-e",
        f"SCM_VER={version_full}",
        "-e",
        f"EXPECT_RPM_VER={version_rpm}",
        "-e",
        f"TAG_VER={tag_ver}",
        _RPM_IMAGE,
        "sh",
        "-c",
        _rpm_container_script(os.getuid(), os.getgid()),
    ]
    subprocess.run(cmd, check=True)
    rpms = sorted(args.out.glob("pyferm-*.rpm"))
    if len(rpms) != 1:
        raise SystemExit(
            f"expected exactly one pyferm-*.rpm in {args.out}, found "
            f"{len(rpms)} (a stale artifact would confuse the smoke gate)",
        )
    return 0


def _rpm_smoke_cell_clean() -> str:
    """Cell 1: clean install, version-anchor, config, example, not-enabled."""
    return (
        "set -e\n"
        # install_weak_deps=False so the Recommends (python3-dnspython) is NOT
        # pulled -- the stdlib-resolver fallback below must run without it. The
        # hard Requires (iptables) is still resolved from the repos. tsflags=
        # clears the Fedora image's ``nodocs`` so the shipped example (a doc
        # file) actually lands -- the rpm analog of the deb smoke removing the
        # docker doc path-exclude; a normal Fedora host installs docs.
        "dnf -y --setopt=install_weak_deps=False --setopt=tsflags= install"
        " /work-out/$ART >/dev/null\n"
        "ferm --version\n"
        "import-ferm --help >/dev/null\n"
        # the shipped default config parses (--test: no real iptables needed)
        "ferm --noexec --lines --test /etc/ferm/ferm.conf >/dev/null\n"
        # the throttle example is really installed
        "test -f /usr/share/doc/pyferm/examples/ssh-throttle.conf.example\n"
        # anti-lockout: the unit is NOT enabled (no wants symlink on disk)
        "test ! -L /etc/systemd/system/multi-user.target.wants/ferm.service\n"
        # resolver stdlib fallback works without python3-dnspython: an A-record
        # @resolve() (localhost -> 127.0.0.1 via getaddrinfo) must not fail.
        # REAL resolution (not --test, which would use a mock zonefile), so
        # iptables must be present -- it came in as a hard Requires above.
        "printf 'domain ip table filter chain OUTPUT {\\n"
        " daddr @resolve(localhost) ACCEPT;\\n}\\n' > /tmp/r.ferm\n"
        "ferm --noexec --lines /tmp/r.ferm >/dev/null\n"
        # version-anchor (sani() oracle): the rpm Version must equal the
        # binary's PEP 440 self-report run through the same sanitizer; on a tag
        # the binary must also self-report the tag's full PEP 440 version.
        # TAG_VER is the unsanitized tag here.
        + _SANI_SH_RPM
        + "vferm=$(ferm --version | head -1 | cut -d' ' -f2)\n"
        "vrpm=$(rpm -q --qf '%{VERSION}' pyferm)\n"
        'expect=$(sani "$vferm")\n'
        '[ "$vrpm" = "$expect" ] || { echo "rpm $vrpm != sani($vferm)='
        '$expect" >&2; exit 1; }\n'
        'if [ -n "$TAG_VER" ]; then\n'
        '  case "$vferm" in *"$TAG_VER") ;; *) echo "ferm $vferm not tag'
        ' $TAG_VER" >&2; exit 1;; esac\n'
        "fi\n"
        "echo CELL1-OK\n"
    )


def _rpm_smoke_cell_breadcrumb() -> str:
    """Cell 2: posture-downgrade breadcrumb when the old unit was enabled."""
    return (
        "set -e\n"
        "mkdir -p /usr/lib/systemd/system"
        " /etc/systemd/system/multi-user.target.wants\n"
        # the previous ferm unit was ENABLED -- its wants symlink is on disk
        "touch /usr/lib/systemd/system/ferm.service\n"
        "ln -s /usr/lib/systemd/system/ferm.service"
        " /etc/systemd/system/multi-user.target.wants/ferm.service\n"
        "dnf -y --setopt=install_weak_deps=False --setopt=tsflags= install"
        " /work-out/$ART >/dev/null\n"
        # this package does not auto-enable its unit (anti-lockout), so it
        # warns durably: the posture-downgrade breadcrumb must be written.
        "test -f /etc/ferm/POSTURE-DOWNGRADE.README\n"
        "echo CELL2-OK\n"
    )


def _action_smoke_rpm(args: argparse.Namespace) -> int:
    """
    Install-smoke the built .rpm in clean Fedora containers.

    Two cells: a clean install (version, config parse, example, stdlib-resolver
    fallback, file-based not-enabled assert) and the posture-downgrade
    breadcrumb when the prior unit was enabled. The deb's legacy-config
    migration and symlink-refusal cells have no rpm analog (see the spec: rpm
    %config(noreplace) does not adopt a %pre-seeded file, and the migration is
    a Debian-ism). Operates on the .rpm already in ``--out``.
    """
    # Absolute path: docker bind mounts need it (a relative path becomes a
    # named volume).
    out = args.out.resolve()
    rpms = sorted(out.glob("pyferm-*.rpm"))
    if len(rpms) != 1:
        raise SystemExit(
            f"expected exactly one pyferm-*.rpm in {out}, found {len(rpms)} "
            "-- run --action=build-rpm into a clean dist first (an ambiguous "
            "or missing artifact would version-anchor the wrong file)",
        )
    art = rpms[0].name
    # The smoke anchors the binary's PEP 440 self-report against the tag
    # (unsanitized); the package Version is anchored via shell sani().
    tag_ver = _tag_version()
    base = _RPM_SMOKE_BASE
    _run_install_smoke_cell(
        out, base, _rpm_smoke_cell_clean(), tag_ver, art, "CELL1", "rpm"
    )
    _run_install_smoke_cell(
        out, base, _rpm_smoke_cell_breadcrumb(), tag_ver, art, "CELL2", "rpm"
    )
    return 0


def _apk_source_tree(mode: str, tag: str | None) -> Path:
    """
    Assemble a clean source tree the APKBUILD's source tarball is built from.

    Delegates to ``_native_source_tree``: the tree carries ``packaging/`` (the
    APKBUILD installs the ferm.conf and example from ``packaging/deb/``)
    plus the python sources and metadata.
    """
    return _native_source_tree("ferm-apk-dev-", mode, tag)


def _apk_sources_dir(tree: Path, version_apk: str) -> Path:
    """
    Pack the source tree into ``pyferm-<version>.tar.gz`` next to the APKBUILD.

    Returns a scratch dir mounted at ``/work-src``: it holds the source tarball
    (top dir ``pyferm-<version>/``, matching the APKBUILD's ``builddir``) and a
    copy of the APKBUILD, the OpenRC service and the install scriptlets, so the
    container reads them all from one mount. The tarball is named for the apk
    pkgver because abuild derives both the source name and builddir from it.
    """
    sources = _scratch_dir("ferm-apk-src-")
    arc_prefix = f"pyferm-{version_apk}"
    with tarfile.open(sources / f"{arc_prefix}.tar.gz", "w:gz") as tar:
        tar.add(tree, arcname=arc_prefix)
    apk_dir = tree / "packaging" / "apk"
    for name in (
        "APKBUILD",
        "ferm.initd",
        "pyferm.post-install",
        "pyferm.post-deinstall",
    ):
        shutil.copy2(apk_dir / name, sources / name)
    return sources


def _apk_container_script(uid: int, gid: int) -> str:
    """
    Render the in-container apk build: abuild, sanitycheck, version-anchor.

    Generates a throwaway signing key (abuild signs the package), stamps the
    pkgver into the APKBUILD (the version is charset-validated host-side and
    passed by env, never interpolated into shell -- injection-safe), exports
    full PEP 440 version for hatch-vcs, runs ``abuild`` (whose own sanity /
    file-tracking / dependency checks are the lint gate, the analog of the
    deb's lintian and the rpm's rpmlint), version-anchors the pkgver, and hands
    the artifact to the invoking uid. ``-F`` lets abuild run as root in the
    container; the ``-doc`` auto-subpackage is excluded when locating the main
    artifact.
    """
    return (
        "set -e\n"
        # abuild refuses to run as root without -F and needs a signing key to
        # sign the package (the smoke installs it with --allow-untrusted, so
        # the key never has to be trusted downstream). Copy the public key into
        # /etc/apk/keys directly (abuild-keygen -i would shell out to sudo,
        # absent in the image) so abuild's final repo-index signing verifies.
        "abuild-keygen -a -n >/dev/null 2>&1\n"
        'cp "$HOME"/.abuild/*.rsa.pub /etc/apk/keys/\n'
        "mkdir -p /tmp/aports/pyferm\n"
        "cp /work-src/APKBUILD /work-src/ferm.initd"
        " /work-src/pyferm.post-install /work-src/pyferm.post-deinstall"
        " /work-src/pyferm-*.tar.gz /tmp/aports/pyferm/\n"
        "cd /tmp/aports/pyferm\n"
        'sed -i "s/^pkgver=.*/pkgver=$APK_VER/" APKBUILD\n'
        "export SETUPTOOLS_SCM_PRETEND_VERSION=$SCM_VER\n"
        "export REPODEST=/tmp/repo\n"
        # checksum populates sha512sums for the local source; validate lints
        # the APKBUILD fields; the build itself fails on any unpackaged file or
        # version drift. -d disables the dependency check: a noarch wheel needs
        # neither the runtime depends (iptables, verified by the smoke) nor a
        # network round-trip to install them, and the makedepends are baked
        # into the image.
        "abuild -F checksum\n"
        "abuild -F validate\n"
        "abuild -F -d\n"
        "apk=$(find /tmp/repo -name 'pyferm-*.apk'"
        " ! -name 'pyferm-doc-*.apk' | head -1)\n"
        '[ -n "$apk" ] || { echo "no pyferm apk produced" >&2; exit 1; }\n'
        'echo "APK_ARTIFACT=$apk"\n'
        # version-anchor: pkgver parsed from the .apk filename.
        'ver=$(basename "$apk" | sed -n'
        " 's/^pyferm-\\(.*\\)-r[0-9]*\\.apk$/\\1/p')\n"
        'echo "APK_VERSION_FIELD=$ver"\n'
        'if [ -n "$TAG_VER" ]; then\n'
        '  case "$ver" in "$TAG_VER"*) ;; *) echo "version-anchor: apk'
        ' $ver does not start with tag $TAG_VER" >&2; exit 1;; esac\n'
        "else\n"
        '  [ "$ver" = "$EXPECT_APK_VER" ] || { echo "version-anchor: apk'
        ' $ver != expected $EXPECT_APK_VER" >&2; exit 1; }\n'
        "fi\n"
        'cp "$apk" /work-out/\n'
        f"chown {uid}:{gid} /work-out/pyferm-*.apk\n"
    )


def _action_build_apk(args: argparse.Namespace) -> int:
    """
    Build the native ``.apk`` in the pinned Alpine image; gate it.

    Version flows from the single host function: the full PEP 440 string is the
    hatch-vcs pretend version (the wheel METADATA), the apk-sanitized string is
    the pkgver and the version-anchor expectation.
    """
    _ensure_native_image(_APK_IMAGE, _APK_DIR)
    version_full = _resolve_version()
    version_apk = _sanitize_apk(version_full)
    tag_ver = _tag_version(_sanitize_apk)
    tree = _apk_source_tree(args.mode, args.tag)
    sources = _apk_sources_dir(tree, version_apk)
    args.out.mkdir(parents=True, exist_ok=True)
    # Absolute path: ``docker -v`` treats a relative path as a NAMED VOLUME,
    # not a bind mount, so the artifact would never reach the host dir.
    out = args.out.resolve()
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{sources}:/work-src:ro",
        "-v",
        f"{out}:/work-out",
        "-e",
        f"APK_VER={version_apk}",
        "-e",
        f"SCM_VER={version_full}",
        "-e",
        f"EXPECT_APK_VER={version_apk}",
        "-e",
        f"TAG_VER={tag_ver}",
        _APK_IMAGE,
        "sh",
        "-c",
        _apk_container_script(os.getuid(), os.getgid()),
    ]
    subprocess.run(cmd, check=True)
    apks = sorted(args.out.glob("pyferm-*.apk"))
    if len(apks) != 1:
        raise SystemExit(
            f"expected exactly one pyferm-*.apk in {args.out}, found "
            f"{len(apks)} (a stale artifact would confuse the smoke gate)",
        )
    return 0


def _apk_smoke_cell_clean() -> str:
    """Cell 1: clean install, version-anchor, config, example, not-enabled."""
    return (
        "set -e\n"
        # --allow-untrusted: the package was signed with a throwaway build key
        # not in /etc/apk/keys. The hard depends (iptables) resolves from the
        # repos; apk has no Recommends, so py3-dnspython is never pulled -- the
        # stdlib-resolver fallback below must run without it.
        "apk add --no-cache --allow-untrusted /work-out/$ART"
        " >/dev/null\n"
        "ferm --version\n"
        "import-ferm --help >/dev/null\n"
        # the shipped default config parses (--test: no real iptables needed)
        "ferm --noexec --lines --test /etc/ferm/ferm.conf >/dev/null\n"
        # the throttle example is really installed
        "test -f /usr/share/doc/pyferm/examples/ssh-throttle.conf.example\n"
        # anti-lockout: OpenRC service installed but added to NO runlevel
        "test -f /etc/init.d/ferm\n"
        "! ls /etc/runlevels/*/ferm >/dev/null 2>&1\n"
        # the systemd opt-in hint was rewritten to the OpenRC form for Alpine
        "grep -q 'rc-update add ferm' /etc/ferm/ferm.conf\n"
        "! grep -q 'systemctl enable --now ferm' /etc/ferm/ferm.conf\n"
        # resolver stdlib fallback works without py3-dnspython: an A-record
        # @resolve() (localhost -> 127.0.0.1 via getaddrinfo) must not fail.
        # REAL resolution (not --test), so iptables must be present -- it came
        # in as a hard depends above.
        "printf 'domain ip table filter chain OUTPUT {\\n"
        " daddr @resolve(localhost) ACCEPT;\\n}\\n' > /tmp/r.ferm\n"
        "ferm --noexec --lines /tmp/r.ferm >/dev/null\n"
        # version-anchor (sani() oracle): the apk pkgver (from the artifact
        # filename) must equal the binary's PEP 440 self-report run through the
        # same apk sanitizer; on a tag the binary must also self-report the
        # tag's full PEP 440 version (a failed injection would report 0.0.0 and
        # mismatch). Derived from the artifact + binary, NOT a host re-resolve,
        # so a commit between build and smoke does not false-red. TAG_VER here
        # is the unsanitized tag.
        + _SANI_SH_APK
        + "vferm=$(ferm --version | head -1 | cut -d' ' -f2)\n"
        "vapk=$(basename /work-out/$ART | sed -n"
        " 's/^pyferm-\\(.*\\)-r[0-9]*\\.apk$/\\1/p')\n"
        'expect=$(sani "$vferm")\n'
        '[ "$vapk" = "$expect" ] || { echo "apk $vapk != sani($vferm)='
        '$expect" >&2; exit 1; }\n'
        'if [ -n "$TAG_VER" ]; then\n'
        '  case "$vferm" in *"$TAG_VER") ;; *) echo "ferm $vferm not tag'
        ' $TAG_VER" >&2; exit 1;; esac\n'
        "fi\n"
        "echo CELL1-OK\n"
    )


def _apk_smoke_cell_breadcrumb() -> str:
    """Cell 2: posture-downgrade breadcrumb when an old service was enabled."""
    return (
        "set -e\n"
        # the previous ferm service was ENABLED -- its runlevel symlink is on
        # disk (dangling until our package lands /etc/init.d/ferm, which is all
        # the file-wise check needs).
        "mkdir -p /etc/runlevels/default\n"
        "ln -sf /etc/init.d/ferm /etc/runlevels/default/ferm\n"
        "apk add --no-cache --allow-untrusted /work-out/$ART"
        " >/dev/null\n"
        # this package adds the service to no runlevel (anti-lockout), so it
        # warns durably: the posture-downgrade breadcrumb must be written.
        "test -f /etc/ferm/POSTURE-DOWNGRADE.README\n"
        "echo CELL2-OK\n"
    )


def _action_smoke_apk(args: argparse.Namespace) -> int:
    """
    Install-smoke the built .apk in clean Alpine containers.

    Two cells: a clean install (version, config parse, example, OpenRC-service
    present-but-not-enabled, conf-hint rewrite, stdlib-resolver fallback) and
    the posture-downgrade breadcrumb when an old service was enabled. The deb's
    legacy-config migration and symlink-refusal cells have no apk analog (apk
    auto-protects /etc on upgrade, and there is no cross-path legacy config on
    Alpine). Operates on the .apk already in ``--out``.
    """
    # Absolute path: docker bind mounts need it (a relative path becomes a
    # named volume).
    out = args.out.resolve()
    apks = sorted(out.glob("pyferm-*.apk"))
    if len(apks) != 1:
        raise SystemExit(
            f"expected exactly one pyferm-*.apk in {out}, found {len(apks)} "
            "-- run --action=build-apk into a clean dist first (an ambiguous "
            "or missing artifact would version-anchor the wrong file)",
        )
    art = apks[0].name
    # The smoke anchors the apk pkgver against the binary's PEP 440 self-report
    # via shell sani() (artifact + binary, not a host re-resolve); on a tag the
    # binary must also self-report the tag's full PEP 440 version.
    tag_ver = _tag_version()
    base = _APK_SMOKE_BASE
    _run_install_smoke_cell(
        out, base, _apk_smoke_cell_clean(), tag_ver, art, "CELL1", "apk"
    )
    _run_install_smoke_cell(
        out, base, _apk_smoke_cell_breadcrumb(), tag_ver, art, "CELL2", "apk"
    )
    return 0


def _action_print_version(args: argparse.Namespace) -> int:
    """
    Print the resolved version to stdout (single host version function).

    The one source every consumer reads: the binary/deb pretend version, the
    ``debian/changelog`` entry, and the version-anchor gate expectations. On a
    tag it is the validated, prefix-stripped tag; off-tag it is the
    setuptools-scm value (``_scm_version``). With ``--deb`` the version is
    run through ``_sanitize_deb`` (drop the local ``+`` segment) for the
    native-dpkg changelog and the deb version-anchor gate -- the SAME function
    on both sides, so they cannot disagree. Printing one line keeps it
    shell-consumable from nox / the workflow.
    """
    version = _resolve_version()
    if args.deb:
        version = _sanitize_deb(version)
    sys.stdout.write(f"{version}\n")
    return 0


def _action_verify_golden(args: argparse.Namespace) -> int:
    """
    Run the full golden suite against the packaged binary.

    Two-part validity: (a) pytest runs from /opt/golden-venv, a venv WITHOUT
    pyferm, so the harness cannot accidentally import the package; (b) the
    binary child runs under ``env -i`` (scrubbed PATH/PYTHONPATH/PYTHONHOME) so
    an unfrozen stdlib module cannot fall through to a host interpreter. The
    ldd assertion confirms the binary needs no /opt/python build interpreter
    (self-containment). Operates on the ALREADY-PACKAGED tar via
    ``_dist_binary``; it does not rebuild.
    """
    binary = _dist_binary(args.out)  # host: <tmp>/ferm.dist/ferm
    dist_root = binary.parent.parent  # <tmp> holding ferm.dist/
    in_dist = f"/work-dist/{_DIST_DIRNAME}/ferm"
    script = (
        f"! ldd {in_dist} | grep -q /opt/python && "  # self-containment
        "env -i PATH=/usr/bin:/bin LC_ALL=C LANG=C PYTHONPATH= PYTHONHOME= "
        "FERM_GOLDEN_TARGET=binary "
        f"FERM_BINARY={in_dist} "
        # -o addopts= neutralizes repo addopts: /opt/golden-venv carries only
        # pytest, not pytest-timeout/xdist the repo config may reference.
        # -p no:cacheprovider: /work is mounted read-only, so a cache write
        # would raise PytestCacheWarning -- and the repo's filterwarnings=error
        # turns that into a session failure. The one-shot gate needs no cache.
        "/opt/golden-venv/bin/pytest /work/tests/golden -q "
        "-o addopts= -p no:cacheprovider"
    )
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "-v",
        f"{_REPO_ROOT}:/work:ro",
        "-v",
        f"{dist_root}:/work-dist:ro",
        _IMAGE,
        "sh",
        "-c",
        script,
    ]
    subprocess.run(cmd, check=True)
    return 0


#: Representative inputs for the config smoke. nft and iptables forms each
#: parse + emit a non-empty ruleset at exit 0; the diagnostics input drives
#: ferm to a non-zero exit with a non-empty stderr. All three are real,
#: checked-in configs (no temp fixtures), resolved against the repo root.
_SMOKE_NFT_CONFIG = _REPO_ROOT / "tests" / "golden" / "nft" / "basic.ferm"
_SMOKE_IPTABLES_CONFIG = (
    _REPO_ROOT / "reference" / "test" / "misc" / "base.ferm"
)
#: uncovered.ferm uses an option the nft backend does not implement, so
#: ferm exits non-zero with a backend error on stderr -- the diagnostics arm.
_SMOKE_DIAGNOSTICS_CONFIG = (
    _REPO_ROOT / "tests" / "golden" / "nft" / "uncovered.ferm"
)


def _expected_version(binary: Path) -> str:
    """
    Return the version the binary's ``--version`` first line MUST report.

    Release mode (a TAG ref, e.g. ``py-v0.1.0``): anchor to the TAG,
    ``${GITHUB_REF_NAME#py-v}`` (the py-v prefix, NOT a bare v -- the repo
    also carries upstream v* tags). hatch-vcs derives the version from the
    tag, so in release mode the binary version equals the tag BY
    CONSTRUCTION; this gate is NOT a tautology against the binary's
    self-report, it is the thin check that the pretend-version INJECTION
    actually worked. A ``0.0.0`` fallback (a shallow / git-less build that
    skipped injection) or a ``0+unknown`` reports something other than the
    tag and fails here. The tag is charset-validated first, so a crafted tag
    cannot smuggle metacharacters this far.

    Dev mode (no tag ref): no tag to anchor to, so fall back to the binary's
    own reported version via ``_detect_version`` (which already rejects an
    empty / unparsable first line). The discriminator is ``GITHUB_REF_TYPE``,
    not the mere presence of ``GITHUB_REF_NAME``: GitHub sets the latter in
    every context (branch pushes, ``workflow_dispatch`` from a branch), so
    keying on it alone would mis-anchor a manual dry-run build to a BRANCH
    name and fail the smoke gate. Only ``GITHUB_REF_TYPE == "tag"`` is a
    release.
    """
    if tv := _tag_version():
        return tv
    return _detect_version(binary)


def _action_smoke(args: argparse.Namespace) -> int:
    """Run the version/help/config/diagnostics smoke checks fast."""
    binary = _dist_binary(args.out)
    # 1) --version: assert the EXACT first line, tag-anchored in release mode.
    version_out = subprocess.run(
        [str(binary), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    expected = f"ferm {_expected_version(binary)}\n"
    if not version_out.stdout.startswith(expected):
        raise SystemExit(
            f"--version mismatch: {version_out.stdout!r} != {expected!r} -- "
            "in release mode the binary's static version must equal the tag "
            "(bump pyproject before tagging); a stale version or 0+unknown "
            "fails here",
        )
    # 2) import-ferm --help: the in-dist symlink next to ferm, Usage on stdout.
    import_ferm = binary.with_name("import-ferm")
    help_out = subprocess.run(
        [str(import_ferm), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    if "Usage" not in help_out.stdout:
        raise SystemExit(
            f"import-ferm --help has no 'Usage' on stdout: "
            f"{help_out.stdout!r} (stderr: {help_out.stderr!r})",
        )
    # 3) one nft + one iptables config: non-empty output at exit 0. --test
    # substitutes fake tool paths so no real iptables/nft need be installed.
    for label, argv in (
        (
            "nft",
            [
                str(binary),
                "--nft",
                "--test",
                "--noexec",
                "--lines",
                str(_SMOKE_NFT_CONFIG),
            ],
        ),
        (
            "iptables",
            [
                str(binary),
                "--test",
                "--noexec",
                "--lines",
                str(_SMOKE_IPTABLES_CONFIG),
            ],
        ),
    ):
        if not argv[-1] or not Path(argv[-1]).is_file():
            raise SystemExit(f"{label} smoke config missing: {argv[-1]}")
        run = subprocess.run(argv, capture_output=True, text=True, check=False)
        if run.returncode != 0 or not run.stdout.strip():
            raise SystemExit(
                f"{label} config smoke failed (rc={run.returncode}, "
                f"empty output={not run.stdout.strip()}):\n{run.stderr}",
            )
    # 4) diagnostics pair: a config that fails non-zero with a non-empty
    # stderr -- proves the error path reaches the user, not a silent green.
    if not _SMOKE_DIAGNOSTICS_CONFIG.is_file():
        raise SystemExit(
            f"diagnostics smoke config missing: {_SMOKE_DIAGNOSTICS_CONFIG}",
        )
    diag = subprocess.run(
        [
            str(binary),
            "--nft",
            "--test",
            "--noexec",
            "--lines",
            str(_SMOKE_DIAGNOSTICS_CONFIG),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if diag.returncode == 0 or not diag.stderr.strip():
        raise SystemExit(
            f"diagnostics smoke failed to surface an error "
            f"(rc={diag.returncode}, stderr empty={not diag.stderr.strip()}): "
            "the failing config should exit non-zero with a message on stderr",
        )
    return 0


def _action_run_dns_gate(args: argparse.Namespace) -> int:
    """
    Prove the frozen dnspython resolves a non-A record (BLOCKER).

    Hermetic + real: a throwaway authoritative resolver on 127.0.0.1 serves
    MX/A; the packaged binary queries it via the container-local
    /etc/resolv.conf. getaddrinfo won't do (A/AAAA only), and monkeypatching
    dns.resolver is impossible against a frozen binary. Runs in a SEPARATE
    one-shot container against the PACKAGED tar, never the build workspace.
    """
    binary = _dist_binary(args.out)
    dist_root = binary.parent.parent
    subprocess.run(
        ["docker", "build", "-t", _DNS_GATE_IMAGE, str(_DNS_GATE_DIR)],
        check=True,
    )
    # The image CMD (run.sh): start resolver.py, await DNS-GATE-READY, then
    # `ferm --noexec --lines check.ferm` capturing stderr. It exits non-zero
    # (and the run fails) on a stub-warning. --network=none gives the container
    # only its loopback interface, which is all the 127.0.0.1 resolver and the
    # binary's query need -- so the gate is hermetic with no internet egress.
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "-v",
            f"{dist_root}:/work-dist:ro",
            "-e",
            f"FERM_BINARY=/work-dist/{_DIST_DIRNAME}/ferm",
            _DNS_GATE_IMAGE,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    out = run.stdout + run.stderr
    if run.returncode != 0 or "DNS-GATE-OK" not in run.stdout:
        raise SystemExit(f"dnspython non-A gate failed:\n{out}")
    if "stub" in out.lower():  # silent stdlib degradation -> red
        raise SystemExit(
            f"stub-resolver warning -- dnspython not frozen:\n{out}"
        )
    return 0


def _action_run_interactive_gate(args: argparse.Namespace) -> int:
    """
    Exercise the ``--interactive`` confirm/timeout path (BLOCKER).

    Runs the datapath image's interactive scenario against the PACKAGED
    binary on a stock runner (--cap-add=NET_ADMIN only -- the interactive
    scenario applies/rolls back nft rules but builds no netns and remounts
    nothing, so it needs no SYS_ADMIN; no real traffic). This is the ONLY
    release gate that enters signal.alarm + the
    function-local ``import termios``, so a silent --include-module=termios
    no-op fails HERE, not in production on the most dangerous (lockout)
    path. Operates on the ALREADY-PACKAGED tar via ``_dist_binary``.
    """
    binary = _dist_binary(args.out)
    dist_root = binary.parent.parent
    datapath_dir = _REPO_ROOT / "tests" / "e2e" / "datapath"
    subprocess.run(
        ["docker", "build", "-t", _INTERACTIVE_GATE_IMAGE, str(datapath_dir)],
        check=True,
    )
    # The driver package is bind-mounted (the image never copies it in), the
    # dist root is mounted read-only, and FERM_BINARY points the driver at
    # the packaged binary. DATAPATH_SCENARIO=interactive selects the
    # confirm/timeout path -- no netns topology, no real traffic.
    run = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--cap-add=NET_ADMIN",
            "-v",
            f"{datapath_dir}:/work/datapath:ro",
            "-v",
            f"{dist_root}:/work-dist:ro",
            "-e",
            f"FERM_BINARY=/work-dist/{_DIST_DIRNAME}/ferm",
            "-e",
            "DATAPATH_SCENARIO=interactive",
            _INTERACTIVE_GATE_IMAGE,
            "python3",
            "/work/datapath/driver.py",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    out = run.stdout + run.stderr
    if run.returncode != 0 or "INTERACTIVE-ROLLBACK-OK" not in run.stdout:
        raise SystemExit(f"interactive/termios gate failed:\n{out}")
    return 0


def _action_run_on_image(args: argparse.Namespace) -> int:
    """
    Run the packaged tar on ``--image`` (glibc-floor gate).

    The build container is itself glibc 2.28, so verify-golden proves
    self-containment on the BUILD glibc, not the floor promise "runs on
    2.28+". Here the floor image (pinned old Debian) must load the binary at
    all -- a too-new build glibc fails with GLIBC_x.yz not found before main.
    Full golden parity is already proven by verify-golden; this proves the
    FLOOR runtime executes: --version + frozen self-probe + a representative
    config producing output at exit 0. Operates on the ALREADY-PACKAGED tar
    via ``_dist_binary``; it does not rebuild.
    """
    if not args.image:
        raise SystemExit("--action=run-on-image requires --image=<pinned ref>")
    binary = _dist_binary(args.out)
    dist_root = binary.parent.parent
    b = f"/work-dist/{_DIST_DIRNAME}/ferm"
    # A self-contained representative config: the IPv4 filter base case has no
    # @include/@glob/backtick/@resolve, so it runs anywhere at exit 0 and is
    # mounted read-only under /work. --test substitutes fake tool paths, so the
    # parse/emit pipeline runs without iptables installed on the minimal floor
    # image (find_tool resolves a real binary even under --noexec otherwise).
    floor_config = "/work/reference/test/misc/base.ferm"
    script = (
        f"{b} --version && "
        f"FERM_SELFCHECK=1 {b} && "
        f"{b} --test --noexec --lines {floor_config} >/dev/null"
    )
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "-v",
        f"{_REPO_ROOT}:/work:ro",
        "-v",
        f"{dist_root}:/work-dist:ro",
        args.image,
        "sh",
        "-c",
        script,
    ]
    subprocess.run(cmd, check=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Dispatch the requested ``--action``."""
    args = _parse_args(argv)
    if args.arch != "x86_64":
        raise SystemExit(f"arch {args.arch!r} not built yet")
    # Explicit dispatch table over the --action choices; each handler owns one
    # build/gate step and is selected by name.
    if args.action == "build":
        return _action_build(args)
    if args.action == "build-deb":
        return _action_build_deb(args)
    if args.action == "smoke-deb":
        return _action_smoke_deb(args)
    if args.action == "build-rpm":
        return _action_build_rpm(args)
    if args.action == "smoke-rpm":
        return _action_smoke_rpm(args)
    if args.action == "build-apk":
        return _action_build_apk(args)
    if args.action == "smoke-apk":
        return _action_smoke_apk(args)
    if args.action == "print-version":
        return _action_print_version(args)
    if args.action == "verify-golden":
        return _action_verify_golden(args)
    if args.action == "smoke":
        return _action_smoke(args)
    if args.action == "run-dns-gate":
        return _action_run_dns_gate(args)
    if args.action == "run-interactive-gate":
        return _action_run_interactive_gate(args)
    if args.action == "run-on-image":
        return _action_run_on_image(args)
    raise SystemExit(f"unknown action {args.action!r}")


if __name__ == "__main__":
    sys.exit(main())
