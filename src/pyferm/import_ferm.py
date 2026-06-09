"""Second console script: convert an iptables-save dump into ferm syntax.

Imports ``pyferm.modules`` for the shared module registry, exactly as the
Perl ``import-ferm`` ``require``s ``ferm``. The registry must therefore be
import-safe (no import-time side effects). Phase 1 scaffold stub.
"""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    """Run the import-ferm CLI. Not yet implemented (Phase 1 scaffold)."""
    raise NotImplementedError(
        "pyferm.import_ferm.main is a Phase 1 scaffold stub"
    )
