"""
Opt-in nft-canonicalizer conformance against the upstream ``.t`` corpus.

Two independent layers, each degrading by environment:

* Layer 1 (host-only, needs only the corpus): the canonicalizers are
  idempotent projections -- ``c(c(x)) == c(x)`` for every corpus rule and
  header.  Catches an oscillating canonicalizer with no nft present.
* Layer 2 (needs nft + rootless userns): the port's canonical form equals
  what live ``nft list ruleset`` prints for the same input.  This is the
  real conformance oracle (added in a later task).

Corpus path comes from ``FERM_NFT_CORPUS`` (a checkout's ``tests/py``);
when unset the whole module is empty/skipped so it never touches the
filesystem during an ordinary collection.  Run via ``nox -s nft_conformance``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from pyferm.plan import canonicalize_nft_header, canonicalize_nft_rule
from tests.conformance.nft.tdotparser import (
    HeaderCase,
    RuleCase,
    parse_t_file,
)

_CORPUS_ENV = "FERM_NFT_CORPUS"


def _load_corpus() -> list[RuleCase | HeaderCase]:
    """Parse every ``.t`` file under ``$FERM_NFT_CORPUS`` (lazy).

    The whole ``tests/py`` tree is scanned recursively, NOT just the
    ``ip``/``ip6``/``inet`` directories: the ``any/`` tree declares those
    same families via ``*ip``/``*ip6``/``*inet`` lines and is the largest
    single source of in-scope cases.  ``parse_t_file`` already filters by
    the ``*family`` declaration (``ALLOWED_FAMILIES``), so directory layout
    is irrelevant -- a per-directory walk would silently drop cases.
    """
    root = os.environ.get(_CORPUS_ENV)
    if not root:
        return []
    base = Path(root)
    if not base.is_dir():
        return []
    cases: list[RuleCase | HeaderCase] = []
    for path in sorted(base.rglob("*.t")):
        cases.extend(parse_t_file(path.read_text(encoding="utf-8")))
    return cases


def _rule_cases() -> list[RuleCase]:
    return [c for c in _load_corpus() if isinstance(c, RuleCase)]


def _header_cases() -> list[HeaderCase]:
    return [c for c in _load_corpus() if isinstance(c, HeaderCase)]


@pytest.mark.conformance
@pytest.mark.parametrize(
    "case", _rule_cases(), ids=lambda c: f"{c.family}:{c.rule}"
)
def test_rule_canon_is_idempotent(case: RuleCase) -> None:
    forms: list[str] = [case.rule]
    if case.normalized is not None:
        forms.append(case.normalized)
    for form in forms:
        once = canonicalize_nft_rule(form, family=case.family)
        twice = canonicalize_nft_rule(once, family=case.family)
        assert twice == once, (
            f"non-idempotent: {form!r} -> {once!r} -> {twice!r}"
        )


@pytest.mark.conformance
@pytest.mark.parametrize(
    "case", _header_cases(), ids=lambda c: f"{c.family}:{c.header}"
)
def test_header_canon_is_idempotent(case: HeaderCase) -> None:
    once = canonicalize_nft_header(case.header, family=case.family)
    twice = canonicalize_nft_header(once, family=case.family)
    assert twice == once, f"non-idempotent header: {case.header!r}"


# --- Layer 2: differential against live nft ------------------------------

# Gate layer 2 to ONLY the statement-level transforms the canonicalizer
# actually implements: ct-state bitmask reorder, reject-with collapse,
# limit-rate burst normalization.  A bare ``{`` trigger is deliberately NOT
# used -- it admits hundreds of brace rules (service-name sets like
# ``{telnet, http}``) the canonicalizer makes no conformance promise about,
# which would turn the differential red on arrival.  The braced ct-state set,
# bitwise ``|`` flag sets and ``.`` concatenations are now handled (operator
# members are no longer shattered; a braced ct-state set reorders to the
# bitmask sequence), so the remaining baseline below is the genuine residue.
_ALLOW_LIST = re.compile(r"\bct state\b|\breject with\b|\blimit rate\b")

# Baseline of corpus rules whose port canon is known to differ from the
# canonicalized nft readback -- genuine narrowness/bugs in the ct-state,
# reject-with and limit-rate transforms (the canon gaps still tracked:
# numeric ct-state/reject codes not resolved, irregular UNBRACED ct-state
# spacing not reordered, ``bytes / second`` spacing, the ``over N/unit`` rate
# form, ct-state concatenation ordering).  The census test below
# asserts the live-measured divergence set EQUALS this baseline: a NEW
# divergence is a regression (fail); a baselined rule that now matches means
# the gap was fixed (fail -> prune it here).  This is the self-cleaning
# ``xfail(strict=True)`` intent, keyed on exact rule strings so it neither
# over-matches nor silently skips.  Derived from a live run against the
# pinned corpus + system nft; re-derive on a corpus/nft bump (see Step 2).
_BASELINE_DIVERGENCES: frozenset[str] = frozenset(
    {
        "ct state . ct mark"
        " { new . 0x12345678, new . 0x34127856, established . 0x12785634}",
        "ct state 8",
        "ct state new,established, related, untracked",
        "limit rate 1 bytes / second",
        "limit rate 1 kbytes / second",
        "limit rate 1 mbytes / second",
        "limit rate over 20/second",
        "limit rate over 40/day",
        "limit rate over 400/hour",
        "limit rate over 400/minute",
        "limit rate over 400/week",
        "mark 0x80000000 reject with tcp reset",
        "mark 12345 reject with tcp reset",
        "meta nfproto ipv4 reject with icmp host-unreachable",
        "meta nfproto ipv6 reject with icmpv6 no-route",
        "reject with icmp 3",
        "reject with icmpv6 3",
        "reject with icmpx 3",
        "reject with icmpx port-unreachable",
    }
)


def _rootless_netns_works() -> bool:
    """Probe whether ``unshare -rn`` can make a rootless network namespace."""
    if shutil.which("unshare") is None:
        return False
    try:
        probe = subprocess.run(
            ["unshare", "-rn", "true"],
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


_NFT_OK = shutil.which("nft") is not None
# Short-circuit on corpus presence so the probe never runs during an
# ordinary (non-opt-in) collection.
_NETNS_OK = bool(os.environ.get(_CORPUS_ENV)) and _rootless_netns_works()


def _extract_rule(listing: str) -> str | None:
    """Return the single rule body nft printed inside chain ``c``."""
    for line in listing.splitlines():
        text = line.strip()
        if (
            not text
            or text == "}"
            or text.startswith(("table ", "chain ", "type ", "policy "))
        ):
            continue
        return text
    return None


def _nft_readback(family: str, header: str, rule: str) -> str | None:
    """Apply *rule* in a rootless netns and return nft's canonical readback.

    Returns ``None`` when nft rejects the wrapped rule (a corpus rule not
    valid in our minimal chain) -- those are skipped, not failed.
    """
    script = (
        f"add table {family} t\n"
        f"add chain {family} t c {{ {header}; }}\n"
        f"add rule {family} t c {rule}\n"
    )
    proc = subprocess.run(
        [
            "unshare",
            "-rn",
            "bash",
            "-c",
            f"nft -f - && nft list table {family} t",
        ],
        input=script,
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=30,
    )
    if proc.returncode != 0:
        return None
    return _extract_rule(proc.stdout)


def _allow_list_rule_cases() -> list[RuleCase]:
    return [c for c in _rule_cases() if _ALLOW_LIST.search(c.rule)]


def _measure_layer2() -> tuple[set[str], int]:
    """Return (diverging input rules, count compared) against live nft.

    For each allow-listed corpus rule, apply it in a minimal ``hook input``
    chain and compare the production invariant ``canon(input) ==
    canon(readback)`` -- ``ferm --plan --nft`` canonicalizes BOTH the desired
    rule and the kernel readback before diffing, so textual identity to nft's
    raw printer is NOT the property under test (pure sort/format differences
    cancel once both sides are canonicalized).  Rules nft rejects in the
    minimal chain return ``None`` and are skipped, not counted.
    """
    diverging: set[str] = set()
    compared = 0
    for case in _allow_list_rule_cases():
        readback = _nft_readback(
            case.family, "type filter hook input priority 0", case.rule
        )
        if readback is None:
            continue
        compared += 1
        port = canonicalize_nft_rule(case.rule, family=case.family)
        nft = canonicalize_nft_rule(readback, family=case.family)
        if port != nft:
            diverging.add(case.rule)
    return diverging, compared


@pytest.mark.conformance
@pytest.mark.skipif(not _NFT_OK, reason="nft not installed")
@pytest.mark.skipif(
    not _NETNS_OK, reason="rootless network namespace unavailable"
)
def test_layer2_divergences_match_baseline() -> None:
    """Census the canon-vs-live-nft divergences against the known baseline.

    The differential is a GAP CENSUS, not a universal-equality assertion: the
    three transforms the allow-list gates (ct-state / reject-with / limit-rate)
    have genuine, corpus-visible narrowness, so a strict per-rule pass would be
    red on arrival.  Instead the measured divergence set must EQUAL
    ``_BASELINE_DIVERGENCES``.  A rule outside the baseline that diverges is a
    regression (fail); a baselined rule that now matches means the canon gap
    was closed -- prune it from the baseline (the self-cleaning intent of a
    strict xfail, keyed on exact strings).
    """
    diverging, compared = _measure_layer2()
    assert compared >= 20, (
        f"only {compared} allow-listed rules survived nft readback "
        "-- allow-list or minimal chain is broken"
    )
    regressions = sorted(diverging - _BASELINE_DIVERGENCES)
    assert not regressions, (
        f"NEW canon divergences (regressions): {regressions}"
    )
    fixed = sorted(_BASELINE_DIVERGENCES - diverging)
    assert not fixed, (
        "baselined rules no longer diverge -- the canon gap was fixed, "
        f"prune them from _BASELINE_DIVERGENCES: {fixed}"
    )
