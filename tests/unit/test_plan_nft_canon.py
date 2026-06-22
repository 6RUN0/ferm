"""Unit tests for the nft canonicalizer: canonicalize_nft_rule and
canonicalize_nft_header.

These tests drive TDD: written before the implementation and document the
exact transforms applied on each side (desired=our emitter, current=nft list).
"""

from pyferm.plan import canonicalize_nft_header, canonicalize_nft_rule


def test_ct_state_full_reorder() -> None:
    # All five members in the worst order; must come out in bitmask order.
    body = "ct state untracked,new,related,established,invalid accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "ct state invalid,established,related,new,untracked accept"


def test_ct_state_two_members_reorder() -> None:
    # Our emitter produces related,established; nft echoes established,related.
    body = "ct state related,established accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "ct state established,related accept"


def test_ct_state_negated_keeps_operator_and_reorders() -> None:
    body = "ct state != new,established drop"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "ct state != established,new drop"


def test_ct_state_unknown_member_left_verbatim() -> None:
    # 'zombie' not in whitelist -> safe-bias: leave the whole token alone.
    body = "ct state established,zombie accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "ct state established,zombie accept"


def test_ct_state_idempotent() -> None:
    body = "ct state related,established accept"
    once = canonicalize_nft_rule(body, family="ip")
    twice = canonicalize_nft_rule(once, family="ip")
    assert once == twice


def test_reject_icmp_type_erased_for_ip_default() -> None:
    # ip family default: reject with icmp port-unreachable -> bare reject
    body = "reject with icmp type port-unreachable"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "reject"


def test_reject_icmpv6_type_non_default_drops_type_word() -> None:
    # non-default message type: only the word 'type' is dropped
    body = "reject with icmpv6 type admin-prohibited"
    out = canonicalize_nft_rule(body, family="ip6")
    assert out == "reject with icmpv6 admin-prohibited"


def test_reject_icmpv6_type_default_collapses_for_ip6() -> None:
    # ip6 family default: reject with icmpv6 port-unreachable -> bare reject
    body = "reject with icmpv6 type port-unreachable"
    out = canonicalize_nft_rule(body, family="ip6")
    assert out == "reject"


def test_reject_tcp_reset_unchanged() -> None:
    body = "reject with tcp reset"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "reject with tcp reset"


def test_reject_bare_unchanged() -> None:
    body = "reject"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "reject"


def test_reject_idempotent_bare() -> None:
    body = "reject"
    once = canonicalize_nft_rule(body, family="ip")
    twice = canonicalize_nft_rule(once, family="ip")
    assert once == twice


def test_reject_idempotent_non_default() -> None:
    body = "reject with icmpv6 type admin-prohibited"
    once = canonicalize_nft_rule(body, family="ip6")
    twice = canonicalize_nft_rule(once, family="ip6")
    assert once == twice


def test_limit_rate_appends_burst() -> None:
    body = "limit rate 3/second accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "limit rate 3/second burst 5 packets accept"


def test_limit_rate_already_has_burst_unchanged() -> None:
    body = "limit rate 3/second burst 5 packets accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == body


def test_limit_rate_idempotent() -> None:
    body = "limit rate 3/second accept"
    once = canonicalize_nft_rule(body, family="ip")
    twice = canonicalize_nft_rule(once, family="ip")
    assert once == twice


def test_combined_ct_state_and_limit() -> None:
    # A rule exercising both ct-state reorder and limit burst injection.
    body = "ct state related,established limit rate 10/second accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == (
        "ct state established,related"
        " limit rate 10/second burst 5 packets accept"
    )


def test_header_priority_filter_ip() -> None:
    h = "type filter hook input priority filter; policy accept;"
    out = canonicalize_nft_header(h, family="ip")
    assert "priority 0" in out


def test_header_priority_srcnat_ip() -> None:
    h = "type nat hook postrouting priority srcnat;"
    out = canonicalize_nft_header(h, family="ip")
    assert "priority 100" in out


def test_header_priority_dstnat_ip() -> None:
    h = "type nat hook prerouting priority dstnat;"
    out = canonicalize_nft_header(h, family="ip")
    assert "priority -100" in out


def test_header_priority_dstnat_bridge() -> None:
    h = "type filter hook prerouting priority dstnat;"
    out = canonicalize_nft_header(h, family="bridge")
    assert "priority -300" in out


def test_header_priority_numeric_unchanged() -> None:
    h = "type filter hook input priority -150; policy accept;"
    out = canonicalize_nft_header(h, family="ip")
    assert "priority -150" in out


def test_header_priority_unrecognized_name_verbatim() -> None:
    # An unknown name stays as-is (safe-bias, never crash).
    h = "type filter hook input priority unknown_landmark;"
    out = canonicalize_nft_header(h, family="ip")
    assert "priority unknown_landmark" in out


def test_header_no_policy_gains_accept() -> None:
    h = "type filter hook input priority 0"
    out = canonicalize_nft_header(h, family="ip")
    assert out.endswith("policy accept")


def test_header_policy_drop_kept() -> None:
    h = "type filter hook input priority 0; policy drop;"
    out = canonicalize_nft_header(h, family="ip")
    assert "policy drop" in out
    assert "policy accept" not in out


def test_header_semicolons_stripped() -> None:
    h1 = "type filter hook input priority 0;"
    h2 = "type filter hook input priority 0 ; policy accept ;"
    assert canonicalize_nft_header(h1, family="ip") == canonicalize_nft_header(
        h2, family="ip"
    )


def test_header_idempotent() -> None:
    h = "type filter hook input priority filter; policy accept;"
    once = canonicalize_nft_header(h, family="ip")
    twice = canonicalize_nft_header(once, family="ip")
    assert once == twice
