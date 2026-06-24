"""Default-suite safety net for nft delta-apply: idempotency + convergence.

These run without a kernel.  The convergence interpreter is an independent
reimplementation of the delta's STRUCTURE -- the order in which flush/add/
delete statements take effect -- so a structural divergence between emitter
and interpreter surfaces a real bug.  It deliberately reuses the
canonicalizers (``canonicalize_nft_rule``/``canonicalize_set_elements``) as
the shared normalization both sides agree on; a bug inside a canonicalizer is
therefore NOT what this layer catches (that is the live e2e suite's job).
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from pyferm.nftset import canonicalize_set_elements
from pyferm.plan import (
    ParsedChain,
    ParsedSet,
    ParsedTable,
    build_nft_delta,
    canonicalize_nft_rule,
    parse_nft_list,
    parse_nft_script,
)

_DELTA_DIR = Path(__file__).resolve().parents[1] / "golden" / "delta_nft"


def _apply_delta(
    current: dict[str, ParsedTable], delta: str, *, family: str
) -> dict[str, ParsedTable]:
    """Interpret a delta script against a copy of the current model."""
    tables = copy.deepcopy(current)
    table = tables.setdefault("ferm", ParsedTable())
    for raw in delta.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        verb, sub = parts[0], parts[1]
        if (verb == "add" and sub == "table") or (
            verb == "flush" and sub == "table"
        ):
            continue
        assert len(parts) >= 5, f"unexpected short delta line: {raw!r}"
        name = parts[4]
        if verb == "add" and sub == "chain":
            brace = raw.find("{")
            policy = "-"
            if brace != -1:
                inner = raw[brace + 1 : raw.rfind("}")]
                policy = " ".join(inner.replace(";", " ").split())
            table.chains.setdefault(name, ParsedChain(policy))
            table.chains[name].policy = policy
        elif verb == "flush" and sub == "chain":
            table.chains[name].rules = []
        elif verb == "delete" and sub == "chain":
            table.chains.pop(name, None)
        elif verb == "add" and sub == "rule":
            body = raw.split(f"ferm {name} ", 1)[1]
            table.chains[name].rules.append(
                canonicalize_nft_rule(body, family=family)
            )
        elif verb == "add" and sub == "set":
            brace = raw.find("{")
            inner = raw[brace + 1 : raw.rfind("}")]
            type_ = None
            flags: tuple[str, ...] = ()
            for stmt in inner.replace("\n", ";").split(";"):
                tok = stmt.split()
                if tok[:1] == ["type"]:
                    type_ = tok[1]
                elif tok[:1] == ["flags"]:
                    flags = tuple(tok[1:])
            table.sets[name] = ParsedSet(name, [], type_, flags)
        elif verb == "delete" and sub == "set":
            table.sets.pop(name, None)
        elif sub == "element":
            inner = raw[raw.find("{") + 1 : raw.rfind("}")]
            members = [e.strip() for e in inner.split(",") if e.strip()]
            s = table.sets[name]
            if verb == "add":
                s.elements = canonicalize_set_elements(
                    s.elements + members, absorb_contained=False
                )
            else:  # delete element
                s.elements = [e for e in s.elements if e not in members]
    return tables


# Precedence order for mock suffix lookup.  Multi-mock configs (e.g. dual_stack
# with both .save and .save6) are tested on the first-matching family only;
# the other family is covered by its own single-family golden case
# (e.g. add_rule6 covers ip6).
_MOCK = [
    (".save", "ip"),
    (".save6", "ip6"),
    (".savearp", "arp"),
    (".saveeb", "eb"),
]
_CASES = sorted(_DELTA_DIR.glob("*.ferm"))


def _sides(ferm_file: Path) -> tuple[str, str, str]:
    """Return (previous_text, family, desired_save) for one golden case."""
    import subprocess
    import sys

    mock: Path | None = None
    family = "ip"
    previous = ""
    for suffix, fam in _MOCK:
        candidate = ferm_file.with_suffix(suffix)
        if candidate.exists():
            mock = candidate
            family = fam
            previous = mock.read_text(encoding="utf-8")
            break
    # desired = render().save: full-reload output restricted to one family
    cmd = [
        sys.executable,
        "-m",
        "pyferm",
        "--nft",
        "--full-reload",
        "--test",
        "--noexec",
        "--lines",
        f"--domain={family}",
    ]
    if mock is not None:
        cmd.append(f"--test-mock-previous={family}={mock}")
    cmd.append(str(ferm_file))
    proc = subprocess.run(
        cmd,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return previous, family, proc.stdout


@pytest.mark.parametrize("ferm_file", _CASES, ids=[p.stem for p in _CASES])
def test_delta_converges_to_desired(ferm_file: Path) -> None:
    previous, family, desired_save = _sides(ferm_file)
    delta = build_nft_delta(previous, desired_save, family=family)
    if delta is None:
        pytest.skip("set-remove delta: full-reload path, skip convergence")
    current = parse_nft_list(previous, family=family)
    applied = _apply_delta(current, delta, family=family)
    desired = parse_nft_script(desired_save)
    # convergence: applying the delta to current yields the desired model
    assert applied["ferm"].chains.keys() == desired["ferm"].chains.keys()
    for name, chain in desired["ferm"].chains.items():
        assert applied["ferm"].chains[name].rules == chain.rules
        assert applied["ferm"].chains[name].policy == chain.policy
    assert applied["ferm"].sets.keys() == desired["ferm"].sets.keys()
    for name, s in desired["ferm"].sets.items():
        assert applied["ferm"].sets[name].elements == s.elements


def test_delta_idempotent_case_emits_empty() -> None:
    """Idempotency gate: live snapshot already equal to desired -> empty delta.

    Keyed to the golden ``idempotent`` case, whose ``.save`` is a REAL
    ``nft list`` snapshot describing exactly the desired state.  Feeding that
    list-form ``previous`` and the render-form ``desired_save`` to
    ``build_nft_delta`` must yield ``""`` -- a non-empty result here means a
    canonicalization asymmetry between list-form and render-form would silently
    churn an unchanged ruleset (flush a chain -> reset its counters), defeating
    the whole point of delta-apply.  This is the honest gate: ``previous`` is
    real kernel text, not synthesized from ``desired`` (no shared-canon
    tautology, no fragile round-trip).
    """
    ferm_file = _DELTA_DIR / "idempotent.ferm"
    previous, family, desired_save = _sides(ferm_file)
    assert build_nft_delta(previous, desired_save, family=family) == ""
