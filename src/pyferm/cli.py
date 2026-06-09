"""Command-line entry point: argument parsing and apply orchestration.

Phase 1 scaffold: the real flow (parse -> structural ruleset ->
backend.render/commit, plus confirm/rollback across domains) is ported
incrementally. This stub only wires the console-script entry point.
"""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    """Run the ferm CLI. Not yet implemented (Phase 1 scaffold)."""
    raise NotImplementedError("pyferm.cli.main is a Phase 1 scaffold stub")
