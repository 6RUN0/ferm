"""Pin the hand-transcribed oracle snippets to their Perl source.

Most oracles in :mod:`tests.property.oracle_driver` are regex-extracted
verbatim from the frozen Perl source at run time, so they cannot drift.
Three of them -- ``backtick_split``, ``substr3`` and ``option_token`` --
are inline code in the original (no ``sub`` to extract) and are therefore
*copied by hand* into ``oracle_driver.pl``.  A hand copy can silently
desync if the Perl source is edited: the differential fuzz would then
compare the port against a stale "oracle" and both could agree on a wrong
answer.

This test fails loudly when the cited source lines change, forcing the
copies in ``oracle_driver.pl`` to be re-synced.  It does not prove the copy
is correct today (the line citations + a human did that); it guards against
future drift, which is the actual risk.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_FERM = _REPO_ROOT / "reference" / "src" / "ferm"
_IMPORT_FERM = _REPO_ROOT / "reference" / "src" / "import-ferm"

#: (oracle name, source file, verbatim fragment that must still be present).
#: Each fragment is the exact line copied into oracle_driver.pl's inline
#: dispatch; keep both in lockstep.
_PINS = [
    ("backtick_split", _FERM, r"$output =~ s/#.*//mg;"),
    (
        "backtick_split",
        _FERM,
        r"my @tokens = grep { length } split /\s+/s, $output;",
    ),
    ("substr3", _FERM, r"return substr($params[0],$params[1],$params[2]);"),
    ("option_token", _IMPORT_FERM, r"if (/^-(\w)$/ || /^--(\S+)$/) {"),
]


@pytest.mark.parametrize(
    ("oracle", "source", "fragment"),
    _PINS,
    ids=[f"{oracle}:{fragment[:24]}" for oracle, _src, fragment in _PINS],
)
def test_transcribed_snippet_still_matches_source(
    oracle: str, source: Path, fragment: str
) -> None:
    if not source.exists():
        pytest.skip(f"frozen Perl source missing: {source}")
    text = source.read_text(encoding="latin-1")
    assert fragment in text, (
        f"oracle '{oracle}' is hand-copied from {source.name} but that "
        f"source no longer contains:\n    {fragment}\n"
        "Re-sync the inline copy in tests/property/oracle_driver.pl."
    )
