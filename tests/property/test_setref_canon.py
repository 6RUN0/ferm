"""Named-set canonicalization and conflict-predicate properties.

Two properties guard the named-set machinery:

- ``sort_set_elements`` is idempotent -- canonicalizing an already
  canonical list is a fixed point, so the two diff sides of a plan
  converge rather than oscillating.
- the declaration aggregator rejects a name reused with conflicting
  element sets in one family *always*, not just on hand-picked inputs.
  Off-by-one bugs in multi-call aggregation slip past single unit cases,
  so the conflict is generated rather than enumerated.
"""

from __future__ import annotations

import subprocess
import sys

from hypothesis import given, settings
from hypothesis import strategies as st

from pyferm.nftset import sort_set_elements

_PORTS = st.lists(st.integers(1, 65535).map(str), min_size=1, max_size=8)


@given(_PORTS)
def test_set_canon_idempotent(elements: list[str]) -> None:
    """Canonicalizing a canonical list returns the same list."""
    once = sort_set_elements(elements)
    assert sort_set_elements(once) == once


def _run_nft(src: str) -> subprocess.CompletedProcess[str]:
    """Compile *src* through the nft backend; return the finished process."""
    return subprocess.run(  # fixed argv, no shell
        [
            sys.executable,
            "-m",
            "pyferm",
            "--nft",
            "--test",
            "--noexec",
            "--lines",
            "-",
        ],
        input=src,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


@settings(max_examples=25)
@given(
    st.lists(
        st.integers(1, 65535).map(str), min_size=1, max_size=4, unique=True
    ),
    st.lists(
        st.integers(1, 65535).map(str), min_size=1, max_size=4, unique=True
    ),
)
def test_element_conflict_always_rejected(
    first: list[str], second: list[str]
) -> None:
    """A name reused with conflicting elements in one family is rejected."""
    if sort_set_elements(first) == sort_set_elements(second):
        return  # same canonical set is not a conflict
    src = (
        f"@set $x = ({' '.join(first)});\n"
        "domain ip table filter chain INPUT { proto tcp dport $x ACCEPT; }\n"
        f"@set $x = ({' '.join(second)});\n"
        "domain ip table filter chain OUTPUT { proto tcp dport $x ACCEPT; }\n"
    )
    proc = _run_nft(src)
    assert proc.returncode != 0
    assert "conflicting element sets" in proc.stderr
