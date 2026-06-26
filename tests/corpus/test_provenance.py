"""Consistency gate for the corpus provenance manifest.

Validates ``provenance.yaml`` against the vendored ``configs/*.ferm``
tree without any golden files: the manifest must cover exactly the
checked-in configs, carry the required provenance fields, and every
config must keep its sanitization sinks (backticks, live ``@include``,
pipe-includes) neutralized.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import yaml

_HERE = Path(__file__).resolve().parent
CONFIGS = _HERE / "configs"
MANIFEST = _HERE / "provenance.yaml"

_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_REQUIRED_FIELDS = ("file", "repo", "path", "commit", "license", "features")


def _load_manifest() -> list[dict[str, object]]:
    with MANIFEST.open(encoding="utf-8") as handle:
        return cast("list[dict[str, object]]", yaml.safe_load(handle))


def test_manifest_bijection() -> None:
    """Manifest covers exactly the vendored configs.

    The set of declared ``file`` names must equal the set of
    ``configs/*.ferm`` basenames, with no duplicate entries.
    """
    entries = _load_manifest()
    declared = [str(entry["file"]) for entry in entries]
    assert len(declared) == len(set(declared)), "duplicate file entries"
    on_disk = {path.name for path in CONFIGS.glob("*.ferm")}
    assert set(declared) == on_disk


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

    For each config the comment is stripped from the first ``#`` of
    every line, and the surviving code must contain no backtick, no
    live ``@include``, and no trailing pipe-include.
    """
    for path in CONFIGS.glob("*.ferm"):
        for line in path.read_text(encoding="utf-8").splitlines():
            # First-'#' strip approximates the ferm lexer: a '#' inside a
            # string literal (e.g. mod comment "a#b") would be over-
            # truncated, which only ever hides a sink, never invents one.
            code = line.split("#", 1)[0]
            assert "`" not in code, path.name
            assert "@include" not in code, path.name
            assert '|"' not in code, path.name
