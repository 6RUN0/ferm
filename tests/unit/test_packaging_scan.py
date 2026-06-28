"""Unit tests for the native-library CVE scanner (packaging/scan_image.py).

The docker/Trivy-calling parts are exercised by the opt-in ``image_scan`` nox
session; here we pin down the PURE logic -- digest extraction, the
shipped-library filter, and the drift guard that keeps the scanner's bundled
SONAME set in lockstep with build.py's ``.so`` allow-list.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType


def _find_repo_root() -> Path:
    for parent in Path(__file__).resolve().parents:
        if (parent / "packaging").is_dir():
            return parent
    msg = "could not locate repo root (no ancestor contains packaging/)"
    raise RuntimeError(msg)


_REPO_ROOT = _find_repo_root()


def _load(name: str, filename: str) -> ModuleType:
    path = _REPO_ROOT / "packaging" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_scan() -> ModuleType:
    return _load("packaging_scan", "scan_image.py")


def _load_build() -> ModuleType:
    return _load("packaging_build", "build.py")


def test_read_pinned_image_extracts_digest_ref(tmp_path: Path) -> None:
    # A real FROM line with a sha256 digest yields the ref verbatim.
    dockerfile = tmp_path / "Dockerfile"
    digest = "a" * 64
    dockerfile.write_text(
        f"# comment\nFROM quay.io/pypa/manylinux@sha256:{digest}\nRUN x\n",
        encoding="utf-8",
    )
    scan = _load_scan()
    assert (
        scan.read_pinned_image(dockerfile)
        == f"quay.io/pypa/manylinux@sha256:{digest}"
    )


def test_read_pinned_image_rejects_unpinned(tmp_path: Path) -> None:
    # A floating-tag FROM (no @sha256:) must fail closed, never scan a moving
    # target silently.
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM debian:bookworm-slim\n", encoding="utf-8")
    scan = _load_scan()
    with pytest.raises(SystemExit):
        scan.read_pinned_image(dockerfile)


def test_real_dockerfile_is_pinned() -> None:
    # The actual build Dockerfile must stay digest-pinned (the scan depends on
    # it as the single source of truth).
    scan = _load_scan()
    ref = scan.read_pinned_image(_REPO_ROOT / "packaging" / "Dockerfile")
    assert "@sha256:" in ref


def test_bundled_stems_match_build_allow_list() -> None:
    # Drift guard: the scanner's bundled-library set MUST equal the lib*.so*
    # subset derived from build.py's allow-list, so adding/removing a bundled
    # native library in one place can never silently desync the CVE scan.
    scan = _load_scan()
    build = _load_build()
    derived = scan.lib_stems_from_allow_list(build._ALLOWED_SO_NAMES)
    assert derived == scan._BUNDLED_LIB_STEMS


def test_lib_stems_drops_stdlib_extensions() -> None:
    # Stdlib extension modules (no rpm identity) drop out; only lib*.so* stay.
    scan = _load_scan()
    stems = scan.lib_stems_from_allow_list(
        frozenset({"_ssl.so", "array.so", "libssl.so.1", "libffi.so.6"}),
    )
    assert stems == frozenset({"libssl", "libffi"})


def test_probe_script_lists_every_stem_safely() -> None:
    # Each stem appears in the rendered shell, the script emits stem<TAB>pkg
    # pairs (so the driver can assert per-stem coverage), and it carries no
    # injectable metacharacter from the (fixed, literal) stem set.
    scan = _load_scan()
    script = scan.package_probe_script(frozenset({"libssl", "libcrypto"}))
    assert "for stem in libcrypto libssl;" in script
    assert "rpm -qf" in script
    assert "printf" in script
    assert r"%s\t%s\n" in script
    assert '"$stem"' in script


def test_filter_findings_keeps_only_shipped_packages() -> None:
    # A CVE in gcc (not shipped) is dropped; one in openssl-libs (shipped) is
    # kept -- the noise filter that makes the blocking gate actionable.
    scan = _load_scan()
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-1",
                        "PkgName": "openssl-libs",
                        "InstalledVersion": "1.1.1k",
                        "FixedVersion": "1.1.1n",
                        "Severity": "CRITICAL",
                        "Title": "openssl bug",
                    },
                    {
                        "VulnerabilityID": "CVE-2",
                        "PkgName": "gcc",
                        "InstalledVersion": "8.5",
                        "FixedVersion": "8.6",
                        "Severity": "HIGH",
                        "Title": "gcc bug",
                    },
                ],
            },
        ],
    }
    findings = scan.filter_findings(report, frozenset({"openssl-libs"}))
    assert [f["id"] for f in findings] == ["CVE-1"]
    assert findings[0]["pkg"] == "openssl-libs"


def test_filter_findings_tolerates_missing_keys() -> None:
    # Trivy omits Vulnerabilities entirely when a result is clean; the filter
    # must not KeyError on that shape.
    scan = _load_scan()
    report = {"Results": [{"Target": "x"}, {"Vulnerabilities": None}]}
    assert scan.filter_findings(report, frozenset({"openssl-libs"})) == []


def test_format_findings_empty_is_reassuring() -> None:
    scan = _load_scan()
    assert "no fixable" in scan.format_findings([])


def test_format_findings_nonempty_names_the_cve() -> None:
    scan = _load_scan()
    out = scan.format_findings(
        [
            scan.Finding(
                id="CVE-9",
                pkg="openssl-libs",
                installed="1.1.1k",
                fixed="1.1.1n",
                severity="CRITICAL",
                title="t",
            ),
        ],
    )
    assert "CVE-9" in out
    assert "openssl-libs" in out
    assert "rebuild" in out


def test_format_findings_renders_title() -> None:
    # The human-useful Title is rendered (it used to be collected but dropped).
    scan = _load_scan()
    out = scan.format_findings(
        [
            scan.Finding(
                id="CVE-9",
                pkg="p",
                installed="1",
                fixed="2",
                severity="HIGH",
                title="heap buffer overflow",
            ),
        ],
    )
    assert "heap buffer overflow" in out


def test_read_pinned_image_accepts_platform_flag(tmp_path: Path) -> None:
    # A digest-pinned FROM with a leading --platform flag is still recognized
    # (not mistaken for unpinned).
    scan = _load_scan()
    digest = "b" * 64
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        f"FROM --platform=linux/amd64 quay.io/x@sha256:{digest}\n",
        encoding="utf-8",
    )
    assert scan.read_pinned_image(dockerfile) == f"quay.io/x@sha256:{digest}"


def _completed(
    stdout: str,
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["docker"],
        returncode=returncode,
        stdout=stdout,
        stderr="",
    )


def _const(value: object) -> Callable[..., object]:
    """Return a function that ignores its args and yields ``value``."""

    def run(*_a: object, **_k: object) -> object:
        return value

    return run


def test_resolve_shipped_packages_maps_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # stem<TAB>pkg pairs collapse to the set of owning packages.
    scan = _load_scan()
    out = "libcrypto\topenssl-libs\nlibffi\tlibffi\nlibssl\topenssl-libs\n"
    monkeypatch.setattr(scan.subprocess, "run", _const(_completed(out)))
    pkgs = scan.resolve_shipped_packages(
        "img",
        frozenset({"libssl", "libcrypto", "libffi"}),
    )
    assert pkgs == frozenset({"openssl-libs", "libffi"})


def test_resolve_shipped_packages_fails_closed_on_missing_stem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # libffi resolves but libssl does not -> partial coverage MUST red, so the
    # missing library's CVEs can never be silently filtered out.
    scan = _load_scan()
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        _const(_completed("libffi\tlibffi\n")),
    )
    with pytest.raises(SystemExit, match="partial coverage"):
        scan.resolve_shipped_packages("img", frozenset({"libssl", "libffi"}))


def test_resolve_shipped_packages_exempts_known_no_rpm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A reviewed source-built stem (no rpm) is exempt from the coverage check.
    scan = _load_scan()
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        _const(_completed("libssl\topenssl-libs\n")),
    )
    monkeypatch.setattr(scan, "_KNOWN_NO_RPM_STEMS", frozenset({"libsrc"}))
    pkgs = scan.resolve_shipped_packages(
        "img",
        frozenset({"libssl", "libsrc"}),
    )
    assert pkgs == frozenset({"openssl-libs"})


def test_resolve_shipped_packages_fails_closed_on_probe_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = _load_scan()
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        _const(_completed("", returncode=1)),
    )
    with pytest.raises(SystemExit, match="probe failed"):
        scan.resolve_shipped_packages("img", frozenset({"libssl"}))


def test_resolve_shipped_packages_fails_closed_on_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Empty probe output is the "always-green filter" trap -- it must red.
    scan = _load_scan()
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        _const(_completed("  \n\n")),
    )
    with pytest.raises(SystemExit):
        scan.resolve_shipped_packages("img", frozenset({"libssl"}))


def test_resolve_shipped_packages_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = _load_scan()

    def boom(*_a: object, **_k: object) -> object:
        raise subprocess.TimeoutExpired(cmd="docker", timeout=1)

    monkeypatch.setattr(scan.subprocess, "run", boom)
    with pytest.raises(SystemExit, match="timed out"):
        scan.resolve_shipped_packages("img", frozenset({"libssl"}))


def test_run_trivy_fails_closed_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = _load_scan()
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        _const(_completed("", returncode=1)),
    )
    with pytest.raises(SystemExit, match="trivy scan"):
        scan.run_trivy("img", None)


def test_run_trivy_fails_closed_on_bad_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = _load_scan()
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        _const(_completed("not json at all")),
    )
    with pytest.raises(SystemExit, match="unparsable"):
        scan.run_trivy("img", None)


def test_run_trivy_fails_closed_on_schema_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Valid JSON but no Results list = the schema changed under a Trivy bump;
    # fail closed instead of reading it as zero findings (a silent green).
    scan = _load_scan()
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        _const(_completed('{"SchemaVersion": 99}')),
    )
    with pytest.raises(SystemExit, match="schema changed"):
        scan.run_trivy("img", None)


def test_run_trivy_returns_parsed_on_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan = _load_scan()
    monkeypatch.setattr(
        scan.subprocess,
        "run",
        _const(_completed('{"Results": []}')),
    )
    assert scan.run_trivy("img", None) == {"Results": []}


def test_run_trivy_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    scan = _load_scan()

    def boom(*_a: object, **_k: object) -> object:
        raise subprocess.TimeoutExpired(cmd="trivy", timeout=1)

    monkeypatch.setattr(scan.subprocess, "run", boom)
    with pytest.raises(SystemExit, match="timed out"):
        scan.run_trivy("img", None)


def test_main_reds_on_finding(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # End-to-end gate decision: a shipped-package finding -> exit 1.
    scan = _load_scan()
    monkeypatch.setattr(
        scan,
        "resolve_shipped_packages",
        _const(frozenset({"openssl-libs"})),
    )
    report = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-X",
                        "PkgName": "openssl-libs",
                        "InstalledVersion": "1",
                        "FixedVersion": "2",
                        "Severity": "HIGH",
                        "Title": "t",
                    },
                ],
            },
        ],
    }
    monkeypatch.setattr(scan, "run_trivy", _const(report))
    assert scan.main([]) == 1
    assert "CVE-X" in capsys.readouterr().out


def test_main_greens_when_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    # No shipped-package finding -> exit 0.
    scan = _load_scan()
    monkeypatch.setattr(
        scan,
        "resolve_shipped_packages",
        _const(frozenset({"openssl-libs"})),
    )
    monkeypatch.setattr(scan, "run_trivy", _const({"Results": []}))
    assert scan.main([]) == 0
