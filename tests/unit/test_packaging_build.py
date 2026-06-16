"""The release version gate anchors to a TAG ref, never a branch ref."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

def _find_repo_root() -> Path:
    # Anchor on the ``packaging/`` tree rather than a fixed parent depth: the
    # mutmut sandbox copies only ``src`` + ``tests`` into ``mutants/``, so the
    # test sits one level deeper there and ``packaging/`` lives in the real
    # checkout above it. Ascend to the nearest ancestor that actually has it.
    for parent in Path(__file__).resolve().parents:
        if (parent / "packaging").is_dir():
            return parent
    msg = "could not locate repo root (no ancestor contains packaging/)"
    raise RuntimeError(msg)


_BUILD = _find_repo_root() / "packaging" / "build.py"


def _load_build() -> ModuleType:
    spec = importlib.util.spec_from_file_location("packaging_build", _BUILD)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tag_ref_anchors_to_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    # A pushed py-v* tag: anchor to the tag, stripping the py-v prefix (NOT
    # just v -- the repo also carries upstream v* tags, see _strip_tag_prefix).
    build = _load_build()
    monkeypatch.setattr(build, "_detect_version", lambda _binary: "0.1.0.dev0")
    monkeypatch.setenv("GITHUB_REF_NAME", "py-v0.1.0")
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    assert build._expected_version(Path("/fake/ferm")) == "0.1.0"


def test_fallback_version_on_tag_reds_the_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A shallow checkout / git-less build on a tag freezes the 0.0.0 fallback.
    # The version-anchor gate must anchor to the TAG (0.1.0), so a smoke that
    # compares the binary's 0.0.0 against this expected 0.1.0 fails -- the gate
    # reds, it does not coast on the binary's self-report (anti-tautology).
    build = _load_build()
    monkeypatch.setattr(build, "_detect_version", lambda _binary: "0.0.0")
    monkeypatch.setenv("GITHUB_REF_NAME", "py-v0.1.0")
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    assert build._expected_version(Path("/fake/ferm")) == "0.1.0"


def test_branch_dispatch_falls_back_to_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # workflow_dispatch from a branch sets GITHUB_REF_NAME to the BRANCH name;
    # keying on its mere presence would anchor the smoke gate to the branch
    # and fail every manual dry-run. GITHUB_REF_TYPE=branch must stay dev mode.
    build = _load_build()
    monkeypatch.setattr(build, "_detect_version", lambda _binary: "0.1.0.dev0")
    monkeypatch.setenv("GITHUB_REF_NAME", "python-port")
    monkeypatch.setenv("GITHUB_REF_TYPE", "branch")
    assert build._expected_version(Path("/fake/ferm")) == "0.1.0.dev0"


def test_local_build_falls_back_to_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A local build outside CI: no GitHub ref env at all -> dev mode.
    build = _load_build()
    monkeypatch.setattr(build, "_detect_version", lambda _binary: "0.1.0.dev0")
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    monkeypatch.delenv("GITHUB_REF_TYPE", raising=False)
    assert build._expected_version(Path("/fake/ferm")) == "0.1.0.dev0"


# -- pure version helpers (string in, string out -- no working tree) --------


def test_strip_tag_prefix_removes_py_v() -> None:
    build = _load_build()
    assert build._strip_tag_prefix("py-v0.1.0") == "0.1.0"
    # An upstream v* tag must NOT be silently accepted as a port release: the
    # prefix is py-v, so a bare v-tag keeps its v and fails the charset gate.
    assert build._strip_tag_prefix("py-v2.7.dev3+gabc") == "2.7.dev3+gabc"


@pytest.mark.parametrize(
    "version",
    [
        "0.1.0",
        "0.1.1.dev3",
        "0.0.1.dev1511",  # state (a), local segment already dropped
    ],
)
def test_sanitize_deb_is_noop_without_local_segment(version: str) -> None:
    build = _load_build()
    assert build._sanitize_deb(version) == version


def test_sanitize_deb_drops_local_segment() -> None:
    # Native dpkg forbids a debian revision and dislikes the local +g<hash>
    # PEP 440 segment; the chosen strategy DROPS the whole +-segment (NOT
    # +-> ~), incl. the .dYYYYMMDD dirty marker that rides in the same segment.
    build = _load_build()
    assert build._sanitize_deb("0.1.1.dev3+gabc1234") == "0.1.1.dev3"
    assert (
        build._sanitize_deb("0.0.1.dev1511+g4fcd266ae.d20260616")
        == "0.0.1.dev1511"
    )


@pytest.mark.parametrize(
    "tag",
    ["py-v0.1.0", "py-v0.1.1.dev3+gabc1234", "py-v1.2.3"],
)
def test_validate_tag_accepts_pep440_port_tags(tag: str) -> None:
    build = _load_build()
    build._validate_tag(tag)  # must not raise


@pytest.mark.parametrize(
    "tag",
    [
        "py-v0.1.0;touch /tmp/x",  # shell metacharacters -> injection attempt
        "py-v0.1.0 && rm -rf /",
        "py-v$(id)",
        "v0.1.0",  # upstream prefix, not a port tag
        "py-vabc",  # must start with a digit after the prefix
        "py-v",  # empty version
        "random-branch",
    ],
)
def test_validate_tag_rejects_bad_tags(tag: str) -> None:
    # The tag reaches dch/docker -e as data; a bad tag must fail EARLY, before
    # any subprocess, so metacharacters never reach a shell.
    build = _load_build()
    with pytest.raises(SystemExit, match="tag"):
        build._validate_tag(tag)


def test_resolve_version_tag_path_validates_and_strips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build = _load_build()
    monkeypatch.setenv("GITHUB_REF_NAME", "py-v0.1.0")
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    assert build._resolve_version() == "0.1.0"


def test_resolve_version_rejects_injection_tag_before_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build = _load_build()
    monkeypatch.setenv("GITHUB_REF_NAME", "py-v0.1.0;touch /tmp/pwn")
    monkeypatch.setenv("GITHUB_REF_TYPE", "tag")
    with pytest.raises(SystemExit, match="tag"):
        build._resolve_version()


def test_resolve_version_dev_path_uses_scm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Off-tag (dev / dispatch): resolve via setuptools-scm (mocked here, NOT
    # the working tree, so the test is hermetic and tag-independent).
    build = _load_build()
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    monkeypatch.delenv("GITHUB_REF_TYPE", raising=False)
    monkeypatch.setattr(
        build, "_scm_version", lambda: "0.0.1.dev1511+g4fcd266ae"
    )
    assert build._resolve_version() == "0.0.1.dev1511+g4fcd266ae"


def test_print_version_deb_flag_sanitizes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # --action=print-version --deb is the single host source for the deb
    # changelog and the deb version-anchor gate: it must emit the sanitized
    # (local-segment-dropped) version, while the bare action emits the full
    # PEP 440 string.
    build = _load_build()
    monkeypatch.setattr(build, "_scm_version", lambda: "0.1.1.dev3+gabc1234")
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    monkeypatch.delenv("GITHUB_REF_TYPE", raising=False)

    assert build.main(["--action=print-version"]) == 0
    assert capsys.readouterr().out == "0.1.1.dev3+gabc1234\n"

    assert build.main(["--action=print-version", "--deb"]) == 0
    assert capsys.readouterr().out == "0.1.1.dev3\n"


def _fake_dist(root: Path, *, with_license: bool) -> Path:
    """Lay out a minimal dist with one bundled native lib for the gate."""
    dist = root / "ferm.dist"
    dist.mkdir()
    (dist / "libcrypto.so.1.1").write_text("", encoding="utf-8")
    licenses_dir = dist / "LICENSES"
    licenses_dir.mkdir()
    (licenses_dir / "MANIFEST.txt").write_text("ok\n", encoding="utf-8")
    if with_license:
        (licenses_dir / "libcrypto.so.1.1.LICENSE").write_text(
            "license text",
            encoding="utf-8",
        )
    return dist


def test_licenses_present_passes_when_complete(tmp_path: Path) -> None:
    build = _load_build()
    dist = _fake_dist(tmp_path, with_license=True)
    build._assert_licenses_present(dist)  # must not raise


def test_licenses_present_fails_on_missing_text(tmp_path: Path) -> None:
    # A bundled lib without a shipped license text is a compliance gap.
    build = _load_build()
    dist = _fake_dist(tmp_path, with_license=False)
    with pytest.raises(SystemExit, match="has no license text"):
        build._assert_licenses_present(dist)


def test_licenses_present_fails_without_manifest(tmp_path: Path) -> None:
    # The collector did not run at all: no manifest index.
    build = _load_build()
    dist = tmp_path / "ferm.dist"
    (dist / "LICENSES").mkdir(parents=True)
    with pytest.raises(SystemExit, match="no license manifest"):
        build._assert_licenses_present(dist)
