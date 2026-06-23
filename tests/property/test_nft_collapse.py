"""Binding property gate for nft set collapse and canon (no kernel needed)."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from pyferm.backend.nft import (
    NftMatch,
    NftRule,
    NftVerdict,
    _collapse_chain_rules,
)
from pyferm.plan import canonicalize_nft_rule

_ports = st.lists(
    st.integers(min_value=1, max_value=65535).map(str),
    min_size=1,
    max_size=8,
    unique=True,
)

#: Mixed element types the slice admits: CIDR, bare address, interval.  The
#: generators are kept PAIRWISE DISJOINT (a /24 in 10.0.0.0/8, a host in
#: 172.16.0.0/16, a numeric range on a stride-100 grid) so neither the kernel's
#: contained-network absorption nor a range/CIDR spelling collapse can fire --
#: both legitimately map two distinct raw sets to one canon, which would break
#: the strict-injectivity invariant below.  Absorption correctness is pinned
#: directly in ``test_nftset.py``; here the concern is the false-"no-changes"
#: guard, i.e. that two genuinely distinct sets never canonicalize equal.
_mixed_elements = st.lists(
    st.one_of(
        st.builds(
            lambda a, b: f"10.{a}.{b}.0/24",
            st.integers(0, 255),
            st.integers(0, 255),
        ),
        st.builds(
            lambda a, b: f"172.16.{a}.{b}",
            st.integers(0, 255),
            st.integers(0, 255),
        ),
        st.builds(lambda k: f"{100 * k}-{100 * k + 10}", st.integers(1, 600)),
    ),
    min_size=1,
    max_size=6,
    unique=True,
)


def _rules(ports: list[str]) -> list[NftRule]:
    return [
        NftRule(
            statements=[
                NftMatch(f"tcp dport {p}", set_key="tcp dport", element=p),
                NftVerdict("accept"),
            ]
        )
        for p in ports
    ]


@given(_ports)
def test_collapse_preserves_matched_value_set(ports: list[str]) -> None:
    # Semantic equivalence: the folded set carries exactly the input values.
    # A single-element list stays as a plain match (no set braces needed).
    out = _collapse_chain_rules(_rules(ports))
    assert len(out) == 1
    match = out[0].statements[0]
    assert isinstance(match, NftMatch)
    text = match.to_text()
    if "{" in text:
        folded = text[text.index("{") + 1 : text.index("}")]
        members = {e.strip() for e in folded.split(",")}
    else:
        # Single port: no set syntax, extract the port token from the expr.
        members = {text.split()[-1]}
    assert members == set(ports)


@given(_ports)
def test_collapse_idempotent(ports: list[str]) -> None:
    once = _collapse_chain_rules(_rules(ports))
    assert _collapse_chain_rules(once) == once


@given(_ports)
def test_canon_set_order_insensitive(ports: list[str]) -> None:
    forward = "tcp dport { " + ", ".join(ports) + " } accept"
    reverse = "tcp dport { " + ", ".join(reversed(ports)) + " } accept"
    assert canonicalize_nft_rule(
        forward, family="ip"
    ) == canonicalize_nft_rule(reverse, family="ip")


@given(_ports, _ports)
def test_canon_injective_on_content(a: list[str], b: list[str]) -> None:
    # Distinct value sets must NOT canonicalize equal (the dangerous
    # direction).
    body_a = "tcp dport { " + ", ".join(a) + " } accept"
    body_b = "tcp dport { " + ", ".join(b) + " } accept"
    canon_a = canonicalize_nft_rule(body_a, family="ip")
    canon_b = canonicalize_nft_rule(body_b, family="ip")
    assert (canon_a == canon_b) == (set(a) == set(b))


@given(_mixed_elements, _mixed_elements)
def test_canon_injective_on_mixed_elements(a: list[str], b: list[str]) -> None:
    # Same false-"no-changes" guard over the CIDR/address/interval element
    # types the slice newly admits, not just integer ports.
    body_a = "ip saddr { " + ", ".join(a) + " } accept"
    body_b = "ip saddr { " + ", ".join(b) + " } accept"
    canon_a = canonicalize_nft_rule(body_a, family="ip")
    canon_b = canonicalize_nft_rule(body_b, family="ip")
    assert (canon_a == canon_b) == (set(a) == set(b))


def test_collapse_never_reorders_through_inequivalent() -> None:
    # Order preserved: a non-equivalent rule between two ports blocks
    # the merge.
    out = _collapse_chain_rules(
        [
            NftRule(
                statements=[
                    NftMatch(
                        "tcp dport 22", set_key="tcp dport", element="22"
                    ),
                    NftVerdict("accept"),
                ]
            ),
            NftRule(statements=[NftVerdict("drop")]),
            NftRule(
                statements=[
                    NftMatch(
                        "tcp dport 80", set_key="tcp dport", element="80"
                    ),
                    NftVerdict("accept"),
                ]
            ),
        ]
    )
    assert [r.statements[-1].to_text() for r in out] == [
        "accept",
        "drop",
        "accept",
    ]
