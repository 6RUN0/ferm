"""
Freshness gate: the committed docs/man/*.1 match a regeneration.

Regenerates the whole chain (jinja template -> pod -> pod2man) into a
temp dir and diffs the troff, normalising the entire ``.TH`` line
(release/date live there).  Skips: without pod2man (perl-skip), when
the local Pod::Man version differs from the committed preamble (the
preamble and troff idioms are version-dependent -- a cross-version
diff is noise, not staleness) and without jinja2 (dev-only dep).
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("jinja2")

if shutil.which("pod2man") is None:  # pragma: no cover -- env-dependent
    pytest.skip("pod2man not found", allow_module_level=True)

_ROOT = Path(__file__).resolve().parents[2]
_MAN_DIR = _ROOT / "docs" / "man"
_POD_MAN_VERSION_RE = re.compile(r"Pod::Man v?([\w.]+)")


def _load_gen_man() -> object:
    spec = importlib.util.spec_from_file_location(
        "gen_man", _ROOT / "tools" / "gen_man.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _local_pod_man_version() -> str:
    completed = subprocess.run(
        ["perl", "-MPod::Man", "-e", "print Pod::Man->VERSION"],
        capture_output=True,
        encoding="utf-8",
        check=True,
    )
    # perl prints "v6.0.2" while the .1 preamble regex captures "6.0.2"
    # -- normalise, or the version skip fires on EVERY run and the gate
    # never actually checks freshness.
    return completed.stdout.strip().removeprefix("v")


def _committed_pod_man_version(page: Path) -> str:
    match = _POD_MAN_VERSION_RE.search(page.read_text(encoding="utf-8"))
    assert match is not None, f"{page}: no Pod::Man preamble marker"
    return match.group(1)


def _normalise(text: str) -> str:
    return "\n".join(
        ".TH" if line.startswith(".TH") else line for line in text.splitlines()
    )


@pytest.mark.parametrize("page", ["ferm.1", "import-ferm.1"])
def test_committed_man_page_is_fresh(page: str, tmp_path: Path) -> None:
    committed = _MAN_DIR / page
    assert committed.is_file(), "run `uv run nox -s man` first"
    if _committed_pod_man_version(committed) != _local_pod_man_version():
        pytest.skip("local Pod::Man differs from the committed preamble")
    gen_man = _load_gen_man()
    gen_man.build(tmp_path, tmp_path / "man")  # type: ignore[attr-defined]
    regenerated = tmp_path / "man" / page
    assert _normalise(regenerated.read_text(encoding="utf-8")) == _normalise(
        committed.read_text(encoding="utf-8")
    ), f"{page} is stale: run `uv run nox -s man` and commit the result"
