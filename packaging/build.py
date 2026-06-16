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
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_IMAGE = "ferm-build"
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
    "verify-golden",
    "smoke",
    "run-dns-gate",
    "run-interactive-gate",
    "run-on-image",
)


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


def _run_build(source_root: Path) -> Path:
    """
    Build inside the image; return the host path to ``ferm.dist``.

    The writable output is a host tempdir OUTSIDE ``source_root`` (dev
    hygiene): writing ``build-out/`` inside the repo tree would show up as
    untracked dirt to the very ``git status`` check that guards the dev path.
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
    second whitespace-separated token. The version is the static metadata
    frozen in via ``--include-distribution-metadata=ferm`` (pyproject
    ``project.version``), so no git/hatch-vcs lookup is needed here.
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
    dist = _run_build(source_root)
    _assert_frozen_imports(dist)  # frozen-import gate (BLOCKER)
    _assert_so_allow_list(dist)  # .so allow-list (BLOCKER)
    _assert_no_unbundled_extras(dist)  # optional-extra radius (BLOCKER)
    version = _detect_version(dist / "ferm")  # run <binary> --version, parse
    _package(dist, args.out, version, args.arch)
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

    Release mode (a TAG ref, e.g. ``v0.1.0``): anchor to the TAG,
    ``${GITHUB_REF_NAME#v}``. The shipped version is STATIC in pyproject
    (frozen via ``--include-distribution-metadata=ferm``), so this is NOT a
    tautology against the binary's self-report: it enforces that the
    maintainer bumped the static version to match the tag BEFORE tagging. A
    forgotten bump (binary ``0.1.0.dev0`` vs tag ``v0.1.0``), a stale static
    version, or a ``0+unknown`` fallback all fail this check.

    Dev mode (no tag ref): no tag to anchor to, so fall back to the binary's
    own reported version via ``_detect_version`` (which already rejects an
    empty / unparsable first line). The discriminator is ``GITHUB_REF_TYPE``,
    not the mere presence of ``GITHUB_REF_NAME``: GitHub sets the latter in
    every context (branch pushes, ``workflow_dispatch`` from a branch), so
    keying on it alone would mis-anchor a manual dry-run build to a BRANCH
    name and fail the smoke gate. Only ``GITHUB_REF_TYPE == "tag"`` is a
    release.
    """
    ref = os.environ.get("GITHUB_REF_NAME", "")
    if ref and os.environ.get("GITHUB_REF_TYPE") == "tag":
        return ref.removeprefix("v")
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
