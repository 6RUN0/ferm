"""
Collect third-party license texts into the dist, fail-closed.

Runs INSIDE the manylinux build container (it needs ``rpm`` and the system
license tree, neither of which exists on the host). For every native library
actually frozen into ``ferm.dist`` that is NOT a CPython standard-library
extension, resolve and copy the owning package's license text; additionally
copy the CPython (PSF) and dnspython (ISC) license texts. A bundled GPLv2
binary that statically links OpenSSL/zlib/libffi/... must reproduce those
notices, so a library whose license text cannot be located fails the build
rather than shipping silently.

Invoked by ``build._container_build_script`` as
``python /work/packaging/collect_licenses.py <dist-dir>`` after the dist is
laid out and before the ownership handoff, so the written ``LICENSES/`` tree
is chowned to the invoking user along with the rest of the dist.
"""

from __future__ import annotations

import importlib.metadata
import subprocess
import sys
from pathlib import Path

#: Native libraries whose soname is NOT owned by a system rpm because the
#: manylinux CPython build vendors them. Mapped to the rpm whose license text
#: is nonetheless the authoritative one for the same upstream project.
_VENDORED_LIB_RPM: dict[str, str] = {
    "libmpdec": "mpdecimal",
}

#: Search roots for resolving a bundled soname back to its system path so
#: ``rpm -qf`` can name the owning package.
_SYSTEM_LIB_DIRS: tuple[str, ...] = ("/usr/lib64", "/lib64", "/usr/lib")


def _rpm_license_files(package: str) -> list[Path]:
    """Return the license paths rpm records for ``package`` (maybe empty)."""
    result = subprocess.run(
        ["rpm", "-q", "--licensefiles", package],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    return [Path(line) for line in result.stdout.split("\n") if line.strip()]


def _owning_package(soname: str) -> str | None:
    """Resolve a bundled soname to the rpm that owns it, or ``None``."""
    for lib_dir in _SYSTEM_LIB_DIRS:
        candidate = Path(lib_dir) / soname
        if not candidate.exists():
            continue
        result = subprocess.run(
            ["rpm", "-qf", str(candidate)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    return None


def _license_files_for(soname: str) -> list[Path]:
    """
    Resolve the license texts for one bundled native library.

    Tries the rpm that owns the soname on disk first; falls back to the
    vendored-library map for libraries the CPython build ships itself.
    """
    package = _owning_package(soname)
    if package is not None:
        files = _rpm_license_files(package)
        if files:
            return files
    stem = soname.split(".so", 1)[0]
    vendored = _VENDORED_LIB_RPM.get(stem)
    if vendored is not None:
        return _rpm_license_files(vendored)
    return []


def _copy_cpython_license(licenses_dir: Path) -> str:
    """Copy the interpreter's PSF license; return the shipped filename."""
    prefix = Path(sys.base_prefix)
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    source = prefix / "lib" / pyver / "LICENSE.txt"
    if not source.is_file():
        raise SystemExit(f"CPython license not found at {source}")
    target_name = "CPython-LICENSE.txt"
    (licenses_dir / target_name).write_bytes(source.read_bytes())
    return target_name


def _copy_dnspython_license(licenses_dir: Path) -> str:
    """Copy dnspython's ISC license from its dist-info; return the filename."""
    distribution = importlib.metadata.distribution("dnspython")
    for entry in distribution.files or []:
        if entry.name in ("LICENSE", "COPYING") and "dist-info" in str(entry):
            text = Path(str(distribution.locate_file(entry))).read_bytes()
            target_name = "dnspython-LICENSE.txt"
            (licenses_dir / target_name).write_bytes(text)
            return target_name
    raise SystemExit("dnspython license file not found in its dist-info")


def _collect_native_licenses(
    dist: Path,
    licenses_dir: Path,
) -> tuple[dict[str, list[str]], list[str]]:
    """
    Copy license texts for every bundled third-party native library.

    Returns a mapping of soname -> shipped license filenames and a list of
    sonames for which no license text could be located (the fail-closed set).
    """
    shipped: dict[str, list[str]] = {}
    missing: list[str] = []
    sonames = sorted(
        {
            so.name
            for so in dist.glob("**/lib*.so*")
            if licenses_dir not in so.parents
        },
    )
    for soname in sonames:
        files = _license_files_for(soname)
        if not files:
            missing.append(soname)
            continue
        names: list[str] = []
        for source in files:
            if not source.is_file():
                continue
            target_name = f"{soname}.{source.name}"
            (licenses_dir / target_name).write_bytes(source.read_bytes())
            names.append(target_name)
        if names:
            shipped[soname] = names
        else:
            missing.append(soname)
    return shipped, missing


def _write_manifest(
    dist: Path,
    licenses_dir: Path,
    tarball_name: str,
    runtime_licenses: dict[str, str],
    native_licenses: dict[str, list[str]],
) -> None:
    """Write the human-readable index tying each library to its text."""
    so_names = sorted(
        {
            so.name
            for so in dist.glob("**/*.so*")
            if licenses_dir not in so.parents
        },
    )
    lines = [
        f"Native libraries bundled in {tarball_name}:",
        "",
        *(so_names or ["(none)"]),
        "",
        "License texts shipped alongside this manifest:",
    ]
    for label, filename in sorted(runtime_licenses.items()):
        lines.append(f"  - {label}: {filename}")
    for soname, filenames in sorted(native_licenses.items()):
        lines.append(f"  - {soname}: {', '.join(filenames)}")
    lines.extend(
        [
            "",
            "License note: ferm is distributed under GPLv2 (see the",
            "banner in src/pyferm/cli.py printversion). Linking against",
            "OpenSSL is permitted under the GPL system-library exception",
            "because OpenSSL is a system/standard library; the OpenSSL build",
            "here is pulled in transitively by the CPython stdlib ssl module,",
            "not vendored by ferm.",
        ],
    )
    (licenses_dir / "MANIFEST.txt").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    """Collect licenses into ``<dist>/LICENSES`` and fail closed on gaps."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        raise SystemExit("usage: collect_licenses.py <dist-dir>")
    dist = Path(args[0])
    if not dist.is_dir():
        raise SystemExit(f"dist dir {dist} does not exist")
    licenses_dir = dist / "LICENSES"
    licenses_dir.mkdir(parents=True, exist_ok=True)
    runtime_licenses = {
        "CPython interpreter / standard library (PSF)": _copy_cpython_license(
            licenses_dir,
        ),
        "dnspython (ISC)": _copy_dnspython_license(licenses_dir),
    }
    native_licenses, missing = _collect_native_licenses(dist, licenses_dir)
    if missing:
        joined = ", ".join(missing)
        raise SystemExit(
            f"no license text located for bundled libraries: {joined} -- "
            "a missing notice is a compliance gap; failing the build",
        )
    _write_manifest(
        dist,
        licenses_dir,
        f"ferm-{dist.name}",
        runtime_licenses,
        native_licenses,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
