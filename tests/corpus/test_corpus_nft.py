"""
nft-backend gate over the corpus: translate cleanly or refuse cleanly.

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

import re
import subprocess
from pathlib import Path

import pytest

from tests._netns import nft_rootless_netns_works
from tests._oracle import PORT_FERM, spawn_ferm
from tests.corpus.test_corpus import flat_and_nested_configs

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]
CONFIGS = _HERE / "configs"
TRANSLATED = _HERE / "translated"

#: Configs the nft backend currently refuses (clean FermError). Every
#: entry documents a known translation gap ("not yet supported",
#: invalid nft identifier, inexpressible multi-value); removing a
#: capability gap upstream must shrink this list in the same change.
_EXPECTED_NFT_REFUSALS = frozenset(
    {
        # wild corpus
        "antizapret-vpn",
        "brutesque-out",
        "ivansible-natmss",
        "stuart-ha-server",
        # translated adversarial set
        "deep-nesting",
        "four-domains",
        "ipset-lifecycle",
        "jump-cycles",
        "match-overload",
        "nat-cascade",
        "qos-mangle",
    }
)

#: Lines the nft backend emits into ``--lines`` output; everything else
#: there (``@hook`` command echoes) is not part of the ruleset fed to
#: ``nft -f`` on the real apply path and must not reach ``nft -c``.
_NFT_LINE = re.compile(r"^(add|create|delete|insert|flush|replace) ")


def _corpus_owned_configs() -> list[Path]:
    # Upstream reference/examples is out of scope here (see module
    # docstring); only the corpus the port owns plus the translated set.
    return flat_and_nested_configs(CONFIGS) + sorted(TRANSLATED.glob("*.ferm"))


def assert_live_nft_accepts(script: str, label: str = "") -> None:
    """
    Feed an nft script to a live ``nft -c`` in a rootless netns.

    A no-op where ``unshare -rn``/``nft`` are unavailable -- the same
    graceful degradation the corpus and packaged-config gates share.
    ``label`` is appended to the failure message to name the offending
    config.
    """
    if not nft_rootless_netns_works():
        return
    payload = script if script.endswith("\n") else script + "\n"
    check = subprocess.run(  # fixed argv, no shell
        ["unshare", "-rn", "nft", "-c", "-f", "-"],
        input=payload,
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=60,
    )
    assert check.returncode == 0, (
        f"live nft -c rejected{label}:\n{check.stderr}"
    )


@pytest.mark.parametrize(
    "config", _corpus_owned_configs(), ids=lambda path: path.stem
)
def test_corpus_config_translates_or_refuses_cleanly(config: Path) -> None:
    proc = spawn_ferm(
        PORT_FERM,
        ["--nft", "--test", "--noexec", "--lines", str(config)],
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
    assert_live_nft_accepts(script, f" {config.stem}")
