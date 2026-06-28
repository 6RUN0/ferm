"""Equivalence gate: a named set expands to the same iptables ruleset.

Under the default iptables backend a ``@set`` reference is expanded back
to its element list in a parse-phase pre-pass, so a config that names a
set must produce byte-for-byte the same rules as the equivalent config
that wrote the elements inline.  This gate proves that on *real* reference
goldens rather than toy inputs: it rewrites one selector of a checked-in
reference ``.ferm`` into a ``@set`` declaration plus a reference to it,
runs the Python port, and asserts the canonicalized output equals the
checked-in reference ``.result`` (the Perl oracle's output).

The rewrite is self-checking: it must observably change the source and
insert the ``$equivset`` reference, otherwise the case fails loudly rather
than passing vacuously.  Two rewrite shapes are exercised:

- ``list``   -- a multi-element literal list ``selector (a b c)`` becomes
  ``@set $equivset = (a b c)`` plus ``selector $equivset`` (the cartesian
  expansion path).
- ``scalar`` -- a single literal operand ``selector x`` becomes a
  one-element set, which must expand to the identical single rule.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve()
# Under a mutmut sweep this file is the copy in <repo>/mutants/tests/unit,
# so parents[2] is <repo>/mutants, which has no reference/ corpus (mutmut
# copies only src + tests).  Fall back to the real repo root one level up.
_repo_root = _HERE.parents[2]
if not (_repo_root / "reference").is_dir() and _repo_root.name == "mutants":
    _repo_root = _repo_root.parent
_REPO_ROOT = _repo_root
_REFERENCE_ROOT = _REPO_ROOT / "reference"

# The golden-harness canonicalizers (sort.pl replica + result sed) live
# under tests/golden; make that package importable like the datapath suite.
sys.path.insert(0, str(_REPO_ROOT / "tests"))
from golden.normalize import result_sed  # noqa: E402
from golden.sortpl import sort_output  # noqa: E402

# Force the deterministic locale the reference golden harness uses; the
# ferm banner and any directory walk depend on collation/formatting.
_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

# A multi-line literal list ``selector ( ... )`` with no nested parens.
_LIST_RE = re.compile(
    r"\b(saddr|daddr|sport|dport)[ \t]+\(([^()]*)\)", re.DOTALL
)
# A single literal operand ``selector value`` (alnum plus the address /
# port / service punctuation; no ``$`` variable, no CIDR slash).
_SCALAR_RE = re.compile(r"\b(saddr|daddr|sport|dport)[ \t]+([A-Za-z0-9_.:-]+)")

_SET_NAME = "equivset"


def _strip_line_comments(body: str) -> str:
    """Drop ``# ...`` trailers per line, then collapse to one line."""
    return " ".join(line.split("#", 1)[0] for line in body.splitlines())


def _rewrite_list(source: str) -> tuple[str, list[str]]:
    """Rewrite the first clean multi-element list into a ``@set`` + ref."""
    for match in _LIST_RE.finditer(source):
        elements = _strip_line_comments(match.group(2)).split()
        if not elements:
            continue
        if any(element.startswith("$") for element in elements):
            continue
        if any(":" in element for element in elements):
            continue
        selector = match.group(1)
        decl = f"@set ${_SET_NAME} = ({' '.join(elements)});\n"
        rewritten = (
            decl
            + source[: match.start()]
            + f"{selector} ${_SET_NAME}"
            + source[match.end() :]
        )
        return rewritten, elements
    raise AssertionError("no clean literal list selector found")


def _rewrite_scalar(source: str) -> tuple[str, list[str]]:
    """Rewrite the first clean literal scalar into a one-element ``@set``."""
    for match in _SCALAR_RE.finditer(source):
        value = match.group(2)
        if "/" in value:
            continue
        selector = match.group(1)
        decl = f"@set ${_SET_NAME} = ({value});\n"
        rewritten = (
            decl
            + source[: match.start()]
            + f"{selector} ${_SET_NAME}"
            + source[match.end() :]
        )
        return rewritten, [value]
    raise AssertionError("no clean literal scalar selector found")


_REWRITERS = {"list": _rewrite_list, "scalar": _rewrite_scalar}


# (reference stem, rewrite mode).  Each input carries a checked-in
# ``.result`` (the Perl oracle output) and uses no ``@resolve``/
# ``@preserve``/``@ipfilter`` (those do not rewrite into one selector).
_CASES = [
    ("misc/subchain", "list"),
    ("misc/comments", "list"),
    ("misc/def", "scalar"),
    ("modules/state", "scalar"),
    ("protocols/tcp", "scalar"),
]


@pytest.mark.parametrize(
    ("stem", "mode"), _CASES, ids=[f"{s}-{m}" for s, m in _CASES]
)
def test_named_set_expands_to_reference_ruleset(stem: str, mode: str) -> None:
    """A ``@set`` rewrite of a golden matches its reference ``.result``."""
    ferm_file = _REFERENCE_ROOT / "test" / f"{stem}.ferm"
    result_file = ferm_file.with_suffix(".result")
    source = ferm_file.read_text(encoding="utf-8")

    rewritten, elements = _REWRITERS[mode](source)
    # Self-check: the rewrite must observably change the source and insert
    # exactly one reference to the named set, else the gate is vacuous.
    assert rewritten != source
    assert rewritten.count(f"${_SET_NAME}") == 2  # the @set decl + the ref
    assert f"@set ${_SET_NAME} = ({' '.join(elements)});" in rewritten

    # A unique temp name per run: the file must sit under reference/test/
    # (pyferm runs with cwd=reference and a relative path), so a fixed name
    # would race across concurrent xdist workers (FileNotFoundError on the
    # shared unlink).  mkstemp guarantees a distinct path per process.
    fd, tmp_name = tempfile.mkstemp(
        prefix="_equiv_gate_", suffix=".ferm", dir=_REFERENCE_ROOT / "test"
    )
    os.close(fd)
    tmp = Path(tmp_name)
    tmp.write_text(rewritten, encoding="utf-8")
    try:
        proc = subprocess.run(  # fixed argv, no shell
            [
                sys.executable,
                "-m",
                "pyferm",
                "--test",
                "--slow",
                "--noflush",
                str(tmp.relative_to(_REFERENCE_ROOT)),
            ],
            capture_output=True,
            encoding="utf-8",
            check=False,
            env=_ENV,
            cwd=_REFERENCE_ROOT,
        )
    finally:
        tmp.unlink(missing_ok=True)

    assert proc.returncode == 0, proc.stderr
    generated = result_sed(sort_output(proc.stdout))
    expected = sort_output(result_file.read_text(encoding="utf-8"))
    assert generated == expected
