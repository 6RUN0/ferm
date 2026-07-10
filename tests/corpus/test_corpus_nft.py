"""nft-backend gate over the corpus: translate cleanly or refuse cleanly.

Unlike :mod:`tests.corpus.test_corpus` there is no oracle here (Perl
ferm has no nft backend), so the contract is weaker but still
load-bearing:

* every corpus-owned config under ``--nft --test --lines`` either
  translates (exit 0) or is refused with a clean ferm error -- never a
  traceback, never a silently-broken script;
* the set of refusing configs is pinned in
  :data:`_EXPECTED_NFT_REFUSALS`, so backend growth or a translation
  regression must update the list consciously;
* whatever translates must be accepted by a live ``nft -c`` inside a
  rootless network namespace; that half degrades to the dichotomy-only
  check where ``unshare -rn``/``nft`` are unavailable.

The upstream ``reference/examples`` set is deliberately out of scope:
this gate documents the port's own nft surface over the corpus it owns.
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]
CONFIGS = _HERE / "configs"
TRANSLATED = _HERE / "translated"

_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

#: Configs the nft backend currently refuses (clean FermError). Every
#: entry documents a known translation gap ("not yet supported",
#: invalid nft identifier, inexpressible multi-value); removing a
#: capability gap upstream must shrink this list in the same change.
_EXPECTED_NFT_REFUSALS = frozenset(
    {
        # wild corpus
        "antizapret-vpn",
        "brutesque-out",
        "grnet-synnefo",
        "ivansible-natmss",
        "rwthctf2012-vpn",
        "stuart-ha-server",
        # translated adversarial set
        "deep-nesting",
        "four-domains",
        "ipset-lifecycle",
        "jump-cycles",
        "match-overload",
        "nat-cascade",
        "qos-mangle",
        "raw-edge",
    }
)

#: Lines the nft backend emits into ``--lines`` output; everything else
#: there (``@hook`` command echoes) is not part of the ruleset fed to
#: ``nft -f`` on the real apply path and must not reach ``nft -c``.
_NFT_LINE = re.compile(r"^(add|create|delete|insert|flush|replace) ")


def _corpus_owned_configs() -> list[Path]:
    flat = sorted(CONFIGS.glob("*.ferm"))
    # Same multi-file convention as test_corpus._corpus_configs: each
    # directory must hold a same-named entry file, and a missing one
    # fails loudly downstream (FileNotFoundError), never skips.
    nested = sorted(
        path / f"{path.name}.ferm"
        for path in CONFIGS.iterdir()
        if path.is_dir() and not path.name.startswith(".")
    )
    return flat + nested + sorted(TRANSLATED.glob("*.ferm"))


@functools.cache
def _live_nft_usable() -> bool:
    """Probe for ``nft`` plus a rootless network namespace."""
    if shutil.which("nft") is None or shutil.which("unshare") is None:
        return False
    try:
        probe = subprocess.run(
            ["unshare", "-rn", "nft", "list", "ruleset"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


@pytest.mark.parametrize(
    "config", _corpus_owned_configs(), ids=lambda path: path.stem
)
def test_corpus_config_translates_or_refuses_cleanly(config: Path) -> None:
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
        env=_ENV,
        cwd=REPO_ROOT,
    )
    expected_refusal = config.stem in _EXPECTED_NFT_REFUSALS

    if proc.returncode != 0:
        assert expected_refusal, (
            f"{config.stem} stopped translating: {proc.stderr}"
        )
        assert proc.returncode == 1, proc.stderr
        assert "Traceback" not in proc.stderr, proc.stderr
        assert proc.stderr.strip(), "refusal must explain itself"
        return

    assert not expected_refusal, (
        f"{config.stem} translates now; update _EXPECTED_NFT_REFUSALS"
    )
    script = "".join(
        line
        for line in proc.stdout.splitlines(keepends=True)
        if _NFT_LINE.match(line)
    )
    assert script, f"{config.stem}: empty nft ruleset"
    if not _live_nft_usable():
        return
    check = subprocess.run(
        ["unshare", "-rn", "nft", "-c", "-f", "-"],
        input=script,
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=60,
    )
    assert check.returncode == 0, (
        f"live nft -c rejected {config.stem}:\n{check.stderr}"
    )
