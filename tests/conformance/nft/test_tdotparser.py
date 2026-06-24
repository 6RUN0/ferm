"""Host-only unit tests for the .t-format parser (no network, no nft)."""

from tests.conformance.nft.tdotparser import (
    HeaderCase,
    RuleCase,
    parse_t_file,
)

# Mirrors the real upstream block shape: ':' chain headers first, then
# several '*family' table lines, then a block of rules that applies to
# every declared family.
_SAMPLE = """\
# a comment
:input;type filter hook input priority 0
*ip;test-ip4;input
*ip6;test-ip6;input
*inet;test-inet;input
*bridge;test-bridge;input

tcp dport 22 accept;ok
tcp dport {80, 90, 23};ok;tcp dport { 23, 80, 90 }
ip saddr 1.2.3.4 drop;fail
- broken rule here;ok
!set1 type ipv4_addr;ok
?set1 192.168.3.4;ok
"""


def test_skips_fail_and_sigil_lines() -> None:
    cases = parse_t_file(_SAMPLE)
    rules = [c for c in cases if isinstance(c, RuleCase)]
    bodies = {r.rule for r in rules}
    # ';fail', '-', '!', '?' lines must never become a RuleCase.
    assert "ip saddr 1.2.3.4 drop" not in bodies
    assert "broken rule here" not in bodies
    assert not any(b.startswith(("set1", "type ipv4_addr")) for b in bodies)


def test_filters_to_allowed_families() -> None:
    cases = parse_t_file(_SAMPLE)
    fams = {c.family for c in cases}
    # bridge is declared in the sample but is not in the v1 allow-set.
    assert fams == {"ip", "ip6", "inet"}


def test_one_header_fans_out_to_every_family() -> None:
    cases = parse_t_file(_SAMPLE)
    headers = [c for c in cases if isinstance(c, HeaderCase)]
    by_family = {h.family for h in headers}
    assert by_family == {"ip", "ip6", "inet"}
    assert all(
        h.header == "type filter hook input priority 0" for h in headers
    )


def test_rule_forms_input_and_normalized() -> None:
    cases = parse_t_file(_SAMPLE)
    ip_rules = {
        r.rule: r.normalized
        for r in cases
        if isinstance(r, RuleCase) and r.family == "ip"
    }
    # plain ';ok' -> normalized is None
    assert ip_rules["tcp dport 22 accept"] is None
    # ';ok;<normalized>' -> normalized captured verbatim
    assert ip_rules["tcp dport {80, 90, 23}"] == "tcp dport { 23, 80, 90 }"


def test_empty_third_column_is_none_not_input() -> None:
    # 'rule;ok;' (trailing empty field) must yield normalized=None,
    # not silently fall back to the input form.
    cases = parse_t_file("*ip;t;c\nmeta mark 1;ok;\n")
    rule = next(c for c in cases if isinstance(c, RuleCase))
    assert rule.normalized is None


def test_compound_chain_field_is_tolerated() -> None:
    # netdev's '*netdev;name;ingress,egress' must not crash the parser;
    # netdev is out of the allow-set so it produces no cases.
    cases = parse_t_file("*netdev;test;ingress,egress\nmeta mark 1;ok\n")
    assert cases == []
