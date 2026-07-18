"""Freshness gate: the committed completion matches a regeneration."""

from __future__ import annotations

import importlib.util

from tests.unit._packaging import find_repo_root

# find_repo_root, not parents[2]: the mutmut sandbox copies only
# src + tests into mutants/, so packaging/ and tools/ live in the real
# checkout above.
_ROOT = find_repo_root()
_COMMITTED = _ROOT / "packaging" / "completions" / "ferm.bash"


def _load_gen_completion() -> object:
    spec = importlib.util.spec_from_file_location(
        "gen_completion", _ROOT / "tools" / "gen_completion.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_completion_is_fresh() -> None:
    generated = _load_gen_completion().generate()  # type: ignore[attr-defined]
    committed = _COMMITTED.read_text(encoding="utf-8")
    assert generated == committed, (
        "ferm.bash is stale: run `uv run nox -s completion` and commit"
    )


def test_completion_covers_every_option_and_choices() -> None:
    text = _COMMITTED.read_text(encoding="utf-8")
    from pyferm.cli_doc import FERM_OPTIONS, ROLLBACK_OPTIONS

    for table in (FERM_OPTIONS, ROLLBACK_OPTIONS):
        for opt in table:
            if opt.positional:
                continue
            for spelling in opt.spellings:
                assert spelling in text, spelling
    assert '"structured diff"' in text
    assert '"ip ip6 arp eb"' in text
    assert "complete -F _import_ferm import-ferm" in text
