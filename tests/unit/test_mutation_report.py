"""Unit tests for tools/mutation_report.py (the mutmut triage report).

The tool is a standalone script outside the pyferm package, so it is
loaded by file path, mirroring the packaging/entry.py test idiom. All
fixtures build a synthetic mutants/ working copy under tmp_path; the
real mutants/ directory is never touched.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType


def _find_repo_root() -> Path:
    # Anchor on the ``tools/`` tree rather than a fixed parent depth:
    # the mutmut sandbox copies only ``src`` + ``tests`` into
    # ``mutants/``, so the test sits one level deeper there and
    # ``tools/`` lives in the real checkout above it.
    for parent in Path(__file__).resolve().parents:
        if (parent / "tools").is_dir():
            return parent
    msg = "could not locate repo root (no ancestor contains tools/)"
    raise RuntimeError(msg)


_TOOL = _find_repo_root() / "tools" / "mutation_report.py"


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("mutation_report", _TOOL)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: Trampoline-shaped source the way mutmut writes it: one ``_orig``
#: copy plus one numbered mutant per function, class methods mangled
#: with the U+01C1 separator.
_TRAMPOLINE_SOURCE = """\
def x_add__mutmut_orig(a, b):
    return a + b


def x_add__mutmut_1(a, b):
    return a - b


class C:
    def xǁCǁm__mutmut_orig(self):
        return 1

    def xǁCǁm__mutmut_1(self):
        return 2
"""

#: One mutant per status bucket, plus a survivor whose source is
#: missing from the trampoline file (exercises the fallback branch).
_EXIT_CODES = {
    "pkg.mod.x_add__mutmut_1": 0,
    "pkg.mod.xǁCǁm__mutmut_1": 1,
    "pkg.mod.x_add__mutmut_2": 33,
    "pkg.mod.x_add__mutmut_3": -24,
    "pkg.mod.x_gone__mutmut_1": 0,
}


@pytest.fixture
def mutants_dir(tmp_path: Path) -> Path:
    pkg = tmp_path / "mutants" / "src" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "mod.py").write_text(_TRAMPOLINE_SOURCE, encoding="utf-8")
    meta = {"exit_code_by_key": _EXIT_CODES}
    (pkg / "mod.py.meta").write_text(json.dumps(meta), encoding="utf-8")
    return tmp_path / "mutants"


def test_demangle_module_function() -> None:
    tool = _load_tool()
    assert tool._demangle("x_add__mutmut_3") == "add"
    assert tool._demangle("x__private__mutmut_2") == "_private"
    assert tool._demangle("xǁCǁm__mutmut_1") == "C.m"


def test_status_buckets() -> None:
    tool = _load_tool()
    assert tool._status(0) == "survived"
    assert tool._status(1) == "killed"
    assert tool._status(33) == "no-tests"
    assert tool._status(-24) == "timeout"
    # any other positive pytest exit still means the mutant died.
    assert tool._status(2) == "killed"


def test_summary_counts_every_status(
    mutants_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _load_tool()
    assert tool.main(["--mutants-dir", str(mutants_dir)]) == 0
    out = capsys.readouterr().out
    total_row = next(
        line for line in out.splitlines() if line.startswith("TOTAL")
    )
    # 5 mutants: 1 killed, 2 survived, 1 no-tests, 1 timeout -> 20.0%.
    assert total_row.split() == ["TOTAL", "5", "1", "2", "1", "1", "20.0%"]
    assert "pkg.mod.add" in out  # top-survivors list


def test_module_breakdown_marks_survivors(
    mutants_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _load_tool()
    assert (
        tool.main(["--mutants-dir", str(mutants_dir), "--module", "pkg.mod"])
        == 0
    )
    lines = capsys.readouterr().out.splitlines()
    add_row = next(line for line in lines if line.startswith("add"))
    assert "surv=  1" in add_row
    assert add_row.endswith("<-- SURVIVORS")
    method_row = next(line for line in lines if line.startswith("C.m"))
    assert "surv=  0" in method_row
    assert "SURVIVORS" not in method_row


def test_module_breakdown_unknown_module(
    mutants_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _load_tool()
    assert (
        tool.main(["--mutants-dir", str(mutants_dir), "--module", "no.such"])
        == 0
    )
    assert "no recorded mutants match" in capsys.readouterr().out


def test_diffs_show_surviving_mutant_only(
    mutants_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _load_tool()
    argv = [
        "--mutants-dir",
        str(mutants_dir),
        "--module",
        "pkg.mod",
        "--diffs",
    ]
    assert tool.main(argv) == 0
    out = capsys.readouterr().out
    assert "### pkg.mod.x_add__mutmut_1" in out
    assert "-    return a + b" in out
    assert "+    return a - b" in out
    # the killed method mutant must not be diffed.
    assert "mutmut_1(self)" not in out
    # the survivor with no trampoline source hits the fallback branch.
    assert "### pkg.mod.x_gone__mutmut_1: source not found" in out
    assert "# surviving mutant diffs shown: 1" in out


def test_diffs_function_filter(
    mutants_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _load_tool()
    argv = [
        "--mutants-dir",
        str(mutants_dir),
        "--module",
        "pkg.mod",
        "--diffs",
        "--function",
        "gone",
    ]
    assert tool.main(argv) == 0
    out = capsys.readouterr().out
    assert "x_add__mutmut_1" not in out
    assert "x_gone__mutmut_1: source not found" in out


def test_missing_results_dir_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _load_tool()
    assert tool.main(["--mutants-dir", str(tmp_path / "absent")]) == 1
    assert "no .meta results" in capsys.readouterr().err


def test_diffs_without_module_is_a_usage_error(mutants_dir: Path) -> None:
    tool = _load_tool()
    with pytest.raises(SystemExit) as excinfo:
        tool.main(["--mutants-dir", str(mutants_dir), "--diffs"])
    assert excinfo.value.code == 2
