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


def test_header_full_string_equality() -> None:
    # Full-string check: semicolons stripped, priority mapped, policy kept.
    h = "type filter hook input priority filter; policy accept;"
    assert canonicalize_nft_header(h, family="ip") == (
        "type filter hook input priority 0 policy accept"
    )


def test_header_priority_offset_form_verbatim() -> None:
    # Offset form 'priority <name> + <n>' must not be partially mapped.
    h = "type filter hook input priority filter + 7;"
    out = canonicalize_nft_header(h, family="ip")
    assert "priority filter + 7" in out


def test_header_priority_unknown_family_verbatim() -> None:
    # An unknown family must not silently apply inet mappings.
    h = "type filter hook input priority filter;"
    out = canonicalize_nft_header(h, family="netdev")
    assert "priority filter" in out
    assert "priority 0" not in out


def test_reject_already_normalized_non_default_unchanged() -> None:
    # Already-normalized form without 'type' keyword, non-default: stays as-is.
    body = "reject with icmpv6 admin-prohibited"
    out = canonicalize_nft_rule(body, family="ip6")
    assert out == "reject with icmpv6 admin-prohibited"


def test_limit_non_default_burst_unchanged() -> None:
    # A burst value other than the default 5 must be left alone.
    body = "limit rate 3/second burst 3 packets accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == body


def test_set_spacing_normalized_from_glued_form() -> None:
    # Kernel/glued spelling -> canonical spaced form.
    body = "tcp dport {22,80} accept"
    assert canonicalize_nft_rule(body, family="ip") == (
        "tcp dport { 22, 80 } accept"
    )


def test_set_elements_sorted_numerically() -> None:
    body = "tcp dport { 443, 22, 80 } accept"
    assert canonicalize_nft_rule(body, family="ip") == (
        "tcp dport { 22, 80, 443 } accept"
    )


def test_set_canon_idempotent() -> None:
    once = canonicalize_nft_rule("tcp dport {80,22} accept", family="ip")
    assert canonicalize_nft_rule(once, family="ip") == once


def test_set_canon_converges_both_spellings() -> None:
    # The emitter's spaced form and a kernel glued form canon-equal.
    emitted = "tcp dport { 22, 80 } accept"
    kernel = "tcp dport {80, 22} accept"
    assert canonicalize_nft_rule(
        emitted, family="ip"
    ) == canonicalize_nft_rule(kernel, family="ip")


def test_set_injectivity_distinct_sets_differ() -> None:
    a = canonicalize_nft_rule("tcp dport { 22, 80 } accept", family="ip")
    b = canonicalize_nft_rule("tcp dport { 22, 81 } accept", family="ip")
    assert a != b


def test_set_braces_inside_comment_not_reordered() -> None:
    # Braces inside a quoted comment are free text: two rules differing ONLY
    # inside the comment braces must NOT canonicalize equal (a false "no
    # changes" would be a firewall-honesty bug).
    a = canonicalize_nft_rule(
        'tcp dport 22 accept comment "p { 80, 22 }"', family="ip"
    )
    b = canonicalize_nft_rule(
        'tcp dport 22 accept comment "p { 22, 80 }"', family="ip"
    )
    assert a != b


def test_canon_unicode_in_comment_braces_does_not_crash() -> None:
    # A non-ASCII digit inside comment braces must not crash the canon: the
    # quote-aware skip never feeds it to the sorter, and even a genuine set
    # element would fall through to unparsable rather than raise.
    result = canonicalize_nft_rule(
        'tcp dport 22 accept comment "x { ² }"', family="ip"
    )
    assert isinstance(result, str)


def test_vmap_canon_orders_members_by_key() -> None:
    out = canonicalize_nft_rule(
        "tcp dport vmap { 80 : drop, 22 : accept }", family="ip"
    )
    assert out == "tcp dport vmap { 22 : accept, 80 : drop }"


def test_vmap_canon_converges_both_orders() -> None:
    desired = canonicalize_nft_rule(
        "tcp dport vmap { 22 : accept, 80 : drop, 443 : drop }", family="ip"
    )
    kernel = canonicalize_nft_rule(
        "tcp dport vmap { 443 : drop, 80 : drop, 22 : accept }", family="ip"
    )
    assert desired == kernel


def test_vmap_canon_idempotent() -> None:
    once = canonicalize_nft_rule(
        "tcp dport vmap { 80 : drop, 22 : accept }", family="ip"
    )
    assert canonicalize_nft_rule(once, family="ip") == once


def test_vmap_canon_injective_on_verdicts() -> None:
    # Distinct key->verdict mappings must NOT canonicalize equal: the verdict
    # rides with its key, so swapping verdicts is a real change.
    a = canonicalize_nft_rule(
        "tcp dport vmap { 22 : accept, 80 : drop }", family="ip"
    )
    b = canonicalize_nft_rule(
        "tcp dport vmap { 22 : drop, 80 : accept }", family="ip"
    )
    assert a != b


def test_vmap_canon_keeps_multitoken_verdict() -> None:
    out = canonicalize_nft_rule(
        "tcp dport vmap { 80 : jump foo, 22 : accept }", family="ip"
    )
    assert out == "tcp dport vmap { 22 : accept, 80 : jump foo }"


def test_ipv6_set_not_misread_as_vmap() -> None:
    # An IPv6 set element carries ':' but no 'vmap' marker, so it must be
    # ordered as a set, never split into key:verdict pairs.
    out = canonicalize_nft_rule(
        "ip6 saddr { 2001:db8::2, 2001:db8::1 } accept", family="ip6"
    )
    assert out == "ip6 saddr { 2001:db8::1, 2001:db8::2 } accept"


def test_vmap_ipv6_key_not_split_on_colon() -> None:
    # An IPv6 vmap key carries its own ':'; splitting on the first colon
    # would mangle it.  The separator is ' : ', so the key survives whole.
    out = canonicalize_nft_rule(
        "ip6 daddr vmap { 2001:db8::1 : accept, 2001:db8::2 : drop }",
        family="ip6",
    )
    assert out == (
        "ip6 daddr vmap { 2001:db8::1 : accept, 2001:db8::2 : drop }"
    )


def test_vmap_ipv6_key_converges_both_orders() -> None:
    # The same IPv6-keyed vmap in either source order canonicalizes equal, so
    # an unchanged ruleset does not read as a perpetual plan modification.
    one = canonicalize_nft_rule(
        "ip6 daddr vmap { 2001:db8::1 : accept, 2001:db8::2 : drop }",
        family="ip6",
    )
    two = canonicalize_nft_rule(
        "ip6 daddr vmap { 2001:db8::2 : drop, 2001:db8::1 : accept }",
        family="ip6",
    )
    assert one == two


def test_vmap_key_canonicalized_to_kernel_form() -> None:
    # A long-form IPv6 key from our emitter must converge with nft's
    # zero-compressed readback form via canonicalize_element on the key.
    desired = canonicalize_nft_rule(
        "ip6 daddr vmap { 2001:db8:0:0:0:0:0:1 : accept }", family="ip6"
    )
    current = canonicalize_nft_rule(
        "ip6 daddr vmap { 2001:db8::1 : accept }", family="ip6"
    )
    assert desired == current
