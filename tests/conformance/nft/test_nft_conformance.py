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
