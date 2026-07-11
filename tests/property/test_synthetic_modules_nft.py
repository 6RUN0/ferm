"""
nft-backend dichotomy gate over the synthetic module matrix.

:mod:`tests.corpus.test_corpus_nft` pins translate-or-refuse-cleanly over
the real-world corpus; this gate pins the same dichotomy over the FULL
netfilter module vocabulary that :mod:`tests.property.test_synthetic_modules`
synthesizes (the 2026-07-09 ad-hoc sweep, formalized):

* every synthesized case under ``--nft --test --noexec --lines`` either
  translates (exit 0) or is refused with a clean one-line ferm error --
  never a traceback, never a silently-broken script;
* a translating case must never emit ``jump``/``goto`` to a *registered
  target keyword* -- the fall-through that once turned ``TARPIT`` into
  ``jump TARPIT``, a chain that never exists, visible only at apply time.

There is deliberately no pinned per-case verdict list here (backend
growth would churn it without adding safety) and no live ``nft -c`` half
(the corpus gate already exercises the live tool; this matrix is large).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from pyferm.modules import TARGET_DEFS
from tests._oracle import ORACLE_ENV
from tests.corpus.test_corpus_nft import _NFT_LINE
from tests.property.test_synthetic_modules import _CASES, Case

pytestmark = pytest.mark.usefixtures("require_perl")

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]

#: Every registered target keyword of every family: a translating rule
#: must never carry one as a jump/goto operand.
_REGISTERED_TARGETS = frozenset(
    name for family in TARGET_DEFS.values() for name in family
)

_JUMP_OPERAND = re.compile(r"\b(?:jump|goto)\s+(\S+)")


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case.case_id)
def test_synthetic_case_translates_or_refuses_cleanly(
    case: Case, tmp_path: Path
) -> None:
    config = tmp_path / f"{case.case_id}.ferm"
    config.write_text(case.config, encoding="utf-8")
    proc = subprocess.run(  # fixed argv, no shell
        [
            sys.executable,
            "-m",
            "pyferm",
            "--nft",
            "--test",
            "--noexec",
            "--lines",
            str(config),
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
        env=ORACLE_ENV,
        cwd=REPO_ROOT,
    )
    if proc.returncode != 0:
        assert proc.returncode == 1, proc.stderr
        assert "Traceback" not in proc.stderr, proc.stderr
        assert proc.stderr.strip(), "refusal must explain itself"
        return

    script = [
        line for line in proc.stdout.splitlines() if _NFT_LINE.match(line)
    ]
    assert script, f"{case.case_id}: empty nft ruleset"
    for line in script:
        for operand in _JUMP_OPERAND.findall(line):
            assert operand not in _REGISTERED_TARGETS, (
                f"{case.case_id}: registered target emitted as a chain "
                f"jump: {line}"
            )
