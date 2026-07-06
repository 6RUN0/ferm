"""Consistency gate for the corpus provenance manifest.

Validates ``provenance.yaml`` against the vendored ``configs/`` tree
without any golden files: the manifest must cover exactly the checked-in
configs, carry the required provenance fields, and every config must
keep its sanitization sinks (backticks, absolute or pipe ``@include``)
neutralized.  Multi-file entries (a directory per config with its
vendored includes) may keep *relative* ``@include`` lines live, as long
as every target resolves inside the entry directory.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import yaml

_HERE = Path(__file__).resolve().parent
CONFIGS = _HERE / "configs"
TRANSLATED = _HERE / "translated"
MANIFEST = _HERE / "provenance.yaml"

_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_REQUIRED_FIELDS = ("file", "repo", "path", "commit", "license", "features")

#: The ferm forms actually used by vendored configs; anything fancier
#: (variables, lists, unquoted names) should fail the gate for a human
#: to look at rather than silently pass.
_INCLUDE_RE = re.compile(r"@include\s+(?:'([^']+)'|\"([^\"]+)\")\s*;")


def _load_manifest() -> list[dict[str, object]]:
    with MANIFEST.open(encoding="utf-8") as handle:
        return cast("list[dict[str, object]]", yaml.safe_load(handle))


def _vendored_files() -> dict[str, Path]:
    """Map manifest-relative names to the vendored files they describe.

    Top level: the ``*.ferm`` configs (the ``zonefile`` DNS mock is
    support data, not a config).  Entry directories: every file,
    whatever its name -- includes like ``ferm.d/dns`` carry no
    extension.
    """
    files = {path.name: path for path in CONFIGS.glob("*.ferm")}
    for sub in sorted(CONFIGS.iterdir()):
        # Skip dot-directories: stray tool state, not vendored configs
        # (ferm's own directory include skips dot-files the same way).
        if not sub.is_dir() or sub.name.startswith("."):
            continue
        for path in sorted(sub.rglob("*")):
            if path.is_file():
                files[path.relative_to(CONFIGS).as_posix()] = path
    return files


def test_manifest_bijection() -> None:
    """Manifest covers exactly the vendored configs.

    The set of declared ``file`` names must equal the set of vendored
    config files (top-level ``*.ferm`` plus every file of each entry
    directory), with no duplicate entries.
    """
    entries = _load_manifest()
    declared = [str(entry["file"]) for entry in entries]
    assert len(declared) == len(set(declared)), "duplicate file entries"
    assert set(declared) == set(_vendored_files())


def test_required_fields() -> None:
    """Every entry carries the required provenance fields.

    The ``commit`` must be a 40-hex revision pin and ``features`` a
    non-empty list; the ``license`` key must be present.
    """
    for entry in _load_manifest():
        for field in _REQUIRED_FIELDS:
            assert field in entry, f"{entry.get('file')!r} missing {field}"
        commit = entry["commit"]
        assert isinstance(commit, str)
        assert _COMMIT_RE.fullmatch(commit), commit
        features = entry["features"]
        assert isinstance(features, list)
        assert features, f"{entry['file']!r} has no features"


def test_sink_absence() -> None:
    """Every config keeps its sanitization sinks neutralized.

    For each vendored file the comment is stripped from the first ``#``
    of every line, and the surviving code must contain no backtick and
    no trailing pipe-include.  A live ``@include`` is allowed only
    inside an entry directory, only with a relative dot-free path, and
    only when the target exists next to the including file; everywhere
    else ``@include`` must stay commented out.
    """
    for name, path in _vendored_files().items():
        in_entry_dir = "/" in name
        for line in path.read_text(encoding="utf-8").splitlines():
            # First-'#' strip approximates the ferm lexer: a '#' inside a
            # string literal (e.g. mod comment "a#b") would be over-
            # truncated, which only ever hides a sink, never invents one.
            code = line.split("#", 1)[0]
            assert "`" not in code, name
            # Deliberately stricter than the translated/ gate below: a
            # legitimate hex-string payload literal ends in '|"', but no
            # wild config vendors one today, so the simpler pipe-include
            # check stays until one does (then relax it the same way).
            assert '|"' not in code, name
            if "@include" not in code:
                continue
            assert in_entry_dir, f"live @include in flat config {name}"
            match = _INCLUDE_RE.search(code)
            assert match, f"unrecognized @include form in {name}: {line!r}"
            target = match.group(1) or match.group(2)
            assert target is not None, name
            assert not target.startswith("/"), name
            assert not target.endswith("|"), name
            assert ".." not in Path(target).parts, name
            assert (path.parent / target).exists(), (
                f"{name}: @include target {target!r} not vendored"
            )


def test_translated_configs_documented_and_sink_free() -> None:
    """Hand-translated configs carry an Origin header and no sinks.

    ``translated/*.ferm`` are authored for this repository (real-world
    iptables/nft setups rewritten into ferm), so they have no upstream
    manifest entry; instead each must document what it was translated
    from in an ``Origin:`` header comment, and, being fully
    self-contained, may not use ``@include`` or backticks at all.
    """
    configs = sorted(TRANSLATED.glob("*.ferm"))
    assert configs, "translated corpus directory is empty"
    for path in configs:
        text = path.read_text(encoding="utf-8")
        assert re.search(r"^# Origin:", text, re.MULTILINE), (
            f"{path.name}: missing '# Origin:' header comment"
        )
        for line in text.splitlines():
            code = line.split("#", 1)[0]
            assert "`" not in code, path.name
            # No pipe-include heuristic here: ferm can only run a
            # command through '@include "cmd|"', and @include is banned
            # outright, while legitimate payload literals (mod string
            # hex-string "|de ad be ef|") end with the '|"' sequence.
            assert "@include" not in code, path.name
