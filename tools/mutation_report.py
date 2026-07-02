"""
Aggregate mutmut results from ``mutants/**/*.meta`` into a triage report.

The ``mutation`` nox session leaves one JSON ``<module>.py.meta`` file
next to each trampoline-instrumented copy under ``mutants/src/``; its
``exit_code_by_key`` maps every mutant to the pytest exit code of its
check run.  This tool is the read-only consumer: it rolls those codes up
into per-module and per-function kill statistics and can print unified
diffs of the surviving mutants, so triage does not need the interactive
``mutmut browse`` TUI.

Run it through nox (``uv run nox -s mutation_report``) or directly::

    uv run python tools/mutation_report.py
    uv run python tools/mutation_report.py --module pyferm.analysis
    uv run python tools/mutation_report.py --module pyferm.analysis --diffs
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import re
import sys
from collections import Counter
from pathlib import Path

#: pytest exit codes as recorded by mutmut; negative values are the
#: signal that killed the check run (timeouts arrive as SIGXCPU).
_EXIT_SURVIVED = 0
_EXIT_KILLED = 1
_EXIT_NO_TESTS = 33

_STATUSES = ("killed", "survived", "no-tests", "timeout")

_MUTANT_SUFFIX_RE = re.compile(r"__mutmut_\d+$")

#: mutmut mangles ``Class.method`` into ``x<SEP>Class<SEP>method`` using
#: U+01C1 (latin letter lateral click) as the separator.
_CLASS_SEP = "ǁ"

_ORIG_SUFFIX = "__mutmut_orig"


def _status(exit_code: int) -> str:
    """Map a recorded exit code onto a triage status bucket."""
    if exit_code == _EXIT_SURVIVED:
        return "survived"
    if exit_code == _EXIT_NO_TESTS:
        return "no-tests"
    if exit_code < 0:
        return "timeout"
    # 1 is the ordinary kill; any other positive pytest exit (usage
    # error, internal error) still means the mutant did not survive.
    return "killed"


def _demangle(mangled: str) -> str:
    """Turn a trampoline function name back into ``function`` form."""
    name = _MUTANT_SUFFIX_RE.sub("", mangled)
    if name.startswith("x" + _CLASS_SEP):
        _, cls, method = name.split(_CLASS_SEP)
        return f"{cls}.{method}"
    return name.removeprefix("x_")


def _load_exit_codes(meta_path: Path) -> dict[str, int]:
    """Read ``exit_code_by_key`` from one ``.meta`` file."""
    data = json.loads(meta_path.read_text(encoding="utf-8"))
    codes = data.get("exit_code_by_key", {})
    return {str(key): int(code) for key, code in codes.items()}


def _iter_meta_files(mutants_dir: Path) -> list[Path]:
    """Every ``.meta`` result file under the mutants working copy."""
    return sorted((mutants_dir / "src").rglob("*.meta"))


def _module_of(key: str) -> str:
    """Dotted module part of a mutant key (all but the mangled name)."""
    return key.rsplit(".", 1)[0]


def _function_of(key: str) -> str:
    """Demangled ``function`` / ``Class.method`` part of a mutant key."""
    return _demangle(key.rsplit(".", 1)[1])


def _kill_percent(counts: Counter[str]) -> float:
    """Killed share of all checked mutants in ``counts``."""
    total = sum(counts.values())
    return 100.0 * counts["killed"] / total if total else 0.0


def _print_summary(codes_by_key: dict[str, int], top: int) -> None:
    """Print the per-module table and the top survivor functions."""
    by_module: dict[str, Counter[str]] = {}
    by_function: Counter[str] = Counter()
    for key, code in codes_by_key.items():
        status = _status(code)
        by_module.setdefault(_module_of(key), Counter())[status] += 1
        if status == "survived":
            by_function[f"{_module_of(key)}.{_function_of(key)}"] += 1

    header = (
        f"{'module':32s} {'total':>6s} {'killed':>7s} {'surv':>6s}"
        f" {'notest':>6s} {'tmout':>6s} {'kill%':>6s}"
    )
    print(header)
    grand: Counter[str] = Counter()
    ranked = sorted(by_module.items(), key=lambda item: -item[1]["survived"])
    for module, counts in ranked:
        grand.update(counts)
        print(_summary_row(module, counts))
    print(_summary_row("TOTAL", grand))

    if top and by_function:
        print(f"\ntop {top} functions by surviving mutants:")
        for name, count in by_function.most_common(top):
            print(f"  {count:5d}  {name}")


def _summary_row(label: str, counts: Counter[str]) -> str:
    """One formatted summary-table row."""
    total = sum(counts.values())
    cells = " ".join(
        f"{counts[status]:{width}d}"
        for status, width in zip(_STATUSES, (7, 6, 6, 6), strict=True)
    )
    return f"{label:32s} {total:6d} {cells} {_kill_percent(counts):5.1f}%"


def _print_module(
    codes_by_key: dict[str, int], module: str, function: str | None
) -> None:
    """Print the per-function status breakdown for one module."""
    by_function: dict[str, Counter[str]] = {}
    for key, code in codes_by_key.items():
        if _module_of(key) != module:
            continue
        name = _function_of(key)
        if function is not None and name != function:
            continue
        by_function.setdefault(name, Counter())[_status(code)] += 1
    if not by_function:
        print(f"no recorded mutants match module {module!r}")
        return
    for name, counts in sorted(by_function.items()):
        survived = counts["survived"]
        marker = "  <-- SURVIVORS" if survived else ""
        print(
            f"{name:52s} total={sum(counts.values()):4d}"
            f" killed={counts['killed']:4d} surv={survived:3d}{marker}"
        )


def _function_spans(source: str) -> dict[str, list[str]]:
    """Map every (mangled) def name in ``source`` to its line block."""
    lines = source.splitlines()
    spans: dict[str, list[str]] = {}

    def record(node: ast.stmt) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            end = node.end_lineno or node.lineno
            spans[node.name] = lines[node.lineno - 1 : end]

    for node in ast.parse(source).body:
        record(node)
        if isinstance(node, ast.ClassDef):
            for sub in node.body:
                record(sub)
    return spans


def _print_diffs(
    codes_by_key: dict[str, int],
    mutants_dir: Path,
    module: str,
    function: str | None,
) -> None:
    """Print a minimal unified diff for each surviving mutant."""
    source_path = mutants_dir / "src" / Path(*module.split("."))
    source_path = source_path.with_suffix(".py")
    if not source_path.is_file():
        print(f"no mutants source file for module {module!r}")
        return
    spans = _function_spans(source_path.read_text(encoding="utf-8"))
    shown = 0
    for key, code in sorted(codes_by_key.items()):
        if _status(code) != "survived" or _module_of(key) != module:
            continue
        if function is not None and _function_of(key) != function:
            continue
        mangled = key.rsplit(".", 1)[1]
        base = _MUTANT_SUFFIX_RE.sub("", mangled)
        original = spans.get(base + _ORIG_SUFFIX)
        mutant = spans.get(mangled)
        if original is None or mutant is None:
            print(f"### {key}: source not found in {source_path}")
            continue
        shown += 1
        print(f"### {key}")
        diff = difflib.unified_diff(original, mutant, lineterm="", n=0)
        for line in diff:
            if line[:1] in "+-" and line[:3] not in ("+++", "---"):
                print("   " + line)
    print(f"# surviving mutant diffs shown: {shown}")


def _build_parser() -> argparse.ArgumentParser:
    """Command-line interface of the report tool."""
    parser = argparse.ArgumentParser(
        description=(
            "Summarize mutmut results recorded under mutants/ "
            "(read-only; run `nox -s mutation` first)."
        )
    )
    parser.add_argument(
        "--mutants-dir",
        type=Path,
        default=Path("mutants"),
        help="mutmut working directory (default: ./mutants)",
    )
    parser.add_argument(
        "--module",
        help="dotted module to break down (e.g. pyferm.analysis)",
    )
    parser.add_argument(
        "--function",
        help="restrict --module / --diffs output to one function",
    )
    parser.add_argument(
        "--diffs",
        action="store_true",
        help="with --module: print diffs of surviving mutants",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=20,
        help="how many top survivor functions to list (0 disables)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    args = _build_parser().parse_args(argv)
    if args.diffs and not args.module:
        _build_parser().error("--diffs requires --module")
    meta_files = _iter_meta_files(args.mutants_dir)
    if not meta_files:
        print(
            f"no .meta results under {args.mutants_dir}/src;"
            " run `uv run nox -s mutation` first",
            file=sys.stderr,
        )
        return 1
    codes_by_key: dict[str, int] = {}
    for meta_path in meta_files:
        codes_by_key.update(_load_exit_codes(meta_path))
    if args.module is None:
        _print_summary(codes_by_key, args.top)
    elif args.diffs:
        _print_diffs(
            codes_by_key, args.mutants_dir, args.module, args.function
        )
    else:
        _print_module(codes_by_key, args.module, args.function)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
