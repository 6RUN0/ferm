"""The release version gate anchors to a TAG ref, never a branch ref."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

_BUILD = Path(__file__).resolve().parents[2] / "packaging" / "build.py"


def _load_build() -> ModuleType:
    spec = importlib.util.spec_from_file_location("packaging_build", _BUILD)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tag_ref_anchors_to_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    # A pushed v* tag: anchor to the tag, stripping the leading v.
    build = _load_build()
    monkeypatch.setattr(build, "_detect_version", lambda _binary: "0.1.0.dev0")
    monkeypatch.setenv("GITHUB_REF_NAME", "v0.1.0")
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
