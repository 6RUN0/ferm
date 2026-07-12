"""
Unit tests for the nft canonicalizer: canonicalize_nft_rule and
canonicalize_nft_header.

These tests drive TDD: written before the implementation and document the
exact transforms applied on each side (desired=our emitter, current=nft list).
"""

import pytest

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


def test_reject_no_type_word_default_collapses() -> None:
    # The already-'type'-less form of the family default still collapses to
    # bare reject.  A leading match keeps the reject token mid-rule so the
    # index advance past the collapsed tokens is exercised too.
    body = "ct state new reject with icmp port-unreachable"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "ct state new reject"


def test_reject_with_fam_but_no_message_left_verbatim() -> None:
    # 'reject with icmp' has no message token to inspect, so the collapse
    # lookahead must stay in bounds and leave the run verbatim.
    body = "reject with icmp"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "reject with icmp"


def test_reject_no_type_word_non_default_left_verbatim() -> None:
    # A 'type'-less reject that is NOT the family default is kept verbatim
    # (safe-bias): only the exact default port-unreachable collapses.
    body = "reject with icmp host-unreachable"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "reject with icmp host-unreachable"


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


# --- anonymous-set canon: braced ct-state, concat and OR operators ---


def test_ct_state_braced_reordered_to_bitmask() -> None:
    # A braced ct-state set reorders to nft's bitmask order, like the
    # unbraced form (regression: it used to keep input order).
    body = "ct state { related, new, established } accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "ct state { established, related, new } accept"


def test_ct_state_braced_negated_reordered() -> None:
    body = "ct state != { related, new, established } accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "ct state != { established, related, new } accept"


def test_ct_state_braced_irregular_spacing_reordered() -> None:
    body = "ct state {new,established, related, untracked} accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "ct state { established, related, new, untracked } accept"


def test_ct_state_braced_idempotent() -> None:
    body = "ct state { related, new, established } accept"
    once = canonicalize_nft_rule(body, family="ip")
    twice = canonicalize_nft_rule(once, family="ip")
    assert once == twice


def test_ct_state_braced_unknown_member_left_verbatim() -> None:
    # An unknown member disqualifies the bitmask reorder (safe-bias);
    # the run is normalized but member order is preserved.
    body = "ct state { established, zombie } accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "ct state { established, zombie } accept"


def test_concat_member_not_split_on_dot() -> None:
    # A concatenation member ('a . b') is one member, not three: the
    # '.' operator must not be emitted as a standalone set member.
    body = "ip saddr . tcp dport { 1.1.1.1 . 20, 2.2.2.2 . 80 } accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == (
        "ip saddr . tcp dport { 1.1.1.1 . 20, 2.2.2.2 . 80 } accept"
    )


def test_tcp_flags_or_member_not_split_on_pipe() -> None:
    # A bitwise-OR flag member ('syn | ack') is one member: the '|'
    # operator must not be emitted as a standalone set member.
    body = "tcp flags { syn, syn | ack } accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "tcp flags { syn, syn | ack } accept"


def test_mixed_plain_and_operator_members_kept_verbatim() -> None:
    # A set mixing a scalar and an operator member is left verbatim
    # (normalized spacing only): scalar sort/dedup is not safe here.
    body = "tcp dport { 22, 1.1.1.1 . 20 } accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "tcp dport { 22, 1.1.1.1 . 20 } accept"


def test_concat_set_idempotent() -> None:
    body = "ip saddr . tcp dport { 1.1.1.1 . 20, 2.2.2.2 . 80 } accept"
    once = canonicalize_nft_rule(body, family="ip")
    twice = canonicalize_nft_rule(once, family="ip")
    assert once == twice


def test_plain_port_set_still_sorted() -> None:
    # Regression guard: a plain scalar set keeps dedup + canonical sort.
    body = "tcp dport { 80, 22, 443 } accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "tcp dport { 22, 80, 443 } accept"


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


def test_header_priority_offset_form_resolves_to_int() -> None:
    # nft pretty-prints a near-landmark priority as an offset (e.g. 7 ->
    # 'filter + 7').  Canon resolves the WHOLE expression to the integer --
    # never a partial map like 'priority 0 + 7' -- so the kernel's display
    # matches a config's numeric priority (delta idempotency).
    h = "type filter hook input priority filter + 7;"
    out = canonicalize_nft_header(h, family="ip")
    assert "priority 7" in out
    assert "priority filter" not in out


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


def test_vmap_marker_needs_left_word_boundary() -> None:
    # A real, space-separated vmap still folds by key order...
    real = canonicalize_nft_rule(
        "tcp dport vmap { 80 : accept, 22 : drop }", family="ip"
    )
    assert real == "tcp dport vmap { 22 : drop, 80 : accept }"
    # ...but a token merely ending in 'vmap' is NOT a marker: its braces are
    # a plain set and get sorted, not mistaken for a verbatim malformed vmap.
    glued = canonicalize_nft_rule(
        "tcp dport xvmap { 80, 22 } accept", family="ip"
    )
    assert "{ 22, 80 }" in glued


def test_map_statement_not_mangled_as_set() -> None:
    # A 'map { k : v }' carries ' : ' members but is not an anonymous set;
    # splitting it on whitespace would corrupt it, so it is left verbatim.
    body = "meta mark set ip saddr map { 1.2.3.4 : 0x1 } accept"
    assert canonicalize_nft_rule(body, family="ip") == body


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


def test_set_after_closing_comment_is_still_normalized() -> None:
    # The quote-state machine must CLOSE the comment quote so a set that
    # follows the quoted comment is still recognized and canonicalized.
    body = 'tcp dport 22 accept comment "hi" tcp dport {80,22}'
    out = canonicalize_nft_rule(body, family="ip")
    assert out == 'tcp dport 22 accept comment "hi" tcp dport { 22, 80 }'


def test_comment_span_kept_byte_faithful() -> None:
    # A quoted comment span is emitted verbatim, including its closing quote
    # and last character -- the slice must not drop or duplicate a byte, and
    # the surrounding pieces are joined with nothing.
    body = 'tcp dport 22 accept comment "abcd"'
    out = canonicalize_nft_rule(body, family="ip")
    assert out == body


def test_canon_unicode_in_comment_braces_does_not_crash() -> None:
    # A non-ASCII digit inside comment braces must not crash the canon: the
    # quote-aware skip never feeds it to the sorter, and even a genuine set
    # element would fall through to unparsable rather than raise.
    result = canonicalize_nft_rule(
        'tcp dport 22 accept comment "x { ² }"', family="ip"
    )
    assert isinstance(result, str)


def test_quoted_ifname_set_converges_regardless_of_config_order() -> None:
    # nft stores a quoted ifname set element as a string and reads the set
    # back in lexical order; both permutations must canonicalize to that one
    # order or the plan diff never converges (see nftset.RANK_QUOTED).
    a = canonicalize_nft_rule(
        'iifname { "wlan0", "eth1", "eth0", "ppp1" } accept', family="ip"
    )
    b = canonicalize_nft_rule(
        'iifname { "eth0", "eth1", "ppp1", "wlan0" } accept', family="ip"
    )
    assert a == b == 'iifname { "eth0", "eth1", "ppp1", "wlan0" } accept'


def test_quoted_ifname_set_and_comment_braces_both_handled_correctly() -> None:
    # The ifname set's quotes sit at brace depth one (sorted); the comment's
    # quote sits at depth zero and its braces stay free text (untouched).
    body = 'iifname { "wlan0", "eth0" } accept comment "x { b, a }"'
    out = canonicalize_nft_rule(body, family="ip")
    assert out == 'iifname { "eth0", "wlan0" } accept comment "x { b, a }"'


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


def test_vmap_malformed_member_returned_verbatim() -> None:
    # A vmap member with no ' : ' separator (key and verdict not separated by
    # the expected token) triggers the safe-bias fallback: the whole run is
    # returned verbatim rather than silently corrupting it into a false diff.
    body = "tcp dport vmap { malformed } accept"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "tcp dport vmap { malformed } accept"


def test_reject_no_type_word_default_collapse_keeps_trailing_token() -> None:
    # A token FOLLOWING the collapsed default reject must be preserved: the
    # index advance past the 'type'-less reject run is exactly four tokens
    # (reject with <fam> <msg>), so an over-advance would swallow the tail.
    body = "reject with icmp port-unreachable counter"
    out = canonicalize_nft_rule(body, family="ip")
    assert out == "reject counter"


def test_header_priority_landmark_offset_resolved() -> None:
    # nft pretty-prints a numeric priority near a landmark as an offset;
    # 'filter + 5' -> 5 and 'security - 1' -> 49 must resolve to the integer
    # so a config's numeric priority canonicalizes to the kernel readback.
    assert "priority 5 " in canonicalize_nft_header(
        "type filter hook input priority filter + 5;", family="ip"
    )
    assert "priority 49 " in canonicalize_nft_header(
        "type filter hook input priority security - 1;", family="ip"
    )


def test_header_priority_malformed_offset_left_verbatim() -> None:
    # A non-numeric offset magnitude is safe-bias kept verbatim: no crash,
    # no dropped tokens, no partial resolution.
    out = canonicalize_nft_header(
        "type filter hook input priority filter + xx;", family="ip"
    )
    assert out == "type filter hook input priority filter + xx policy accept"


_CANON_FIXED_POINTS = [
    # batch-9 vocabulary: meta/ct selectors, ext-header and fib matches.
    # Each spelling is the live kernel readback (nft v1.1.6); the
    # canonicalizer must pass it through untouched or --plan phantoms a
    # diff on an applied ruleset.
    pytest.param("meta cpu 0 accept", "ip", id="meta-cpu-0-accept"),
    pytest.param("iifgroup 5 accept", "ip", id="iifgroup-5-accept"),
    pytest.param("oifgroup != 16 accept", "ip", id="oifgroup-16-accept"),
    pytest.param(
        "meta rtclassid 42 accept", "ip", id="meta-rtclassid-42-accept"
    ),
    pytest.param(
        "meta cgroup 1048577 accept", "ip", id="meta-cgroup-1048577-accept"
    ),
    pytest.param(
        "socket wildcard 0 socket transparent 1 accept",
        "ip",
        id="socket-wildcard-0-socket-tra",
    ),
    pytest.param(
        "socket wildcard <= 1 accept", "ip", id="socket-wildcard-1-accept"
    ),
    pytest.param(
        "ct original ip saddr 192.0.2.1 accept",
        "ip",
        id="ct-original-ip-saddr-192-0-2",
    ),
    pytest.param(
        "ct reply ip6 saddr 2001:db8::1 accept",
        "ip6",
        id="ct-reply-ip6-saddr-2001-db8",
    ),
    pytest.param(
        "ct original proto-src 80-90 accept",
        "ip",
        id="ct-original-proto-src-80-90",
    ),
    pytest.param("ct protocol tcp accept", "ip", id="ct-protocol-tcp-accept"),
    pytest.param(
        "ct expiration 1m40s accept", "ip", id="ct-expiration-1m40s-accept"
    ),
    pytest.param(
        "ct expiration 3600s-7200s accept",
        "ip",
        id="ct-expiration-3600s-7200s-ac",
    ),
    pytest.param(
        "ct direction original accept", "ip", id="ct-direction-original-accept"
    ),
    pytest.param("ct label 40 accept", "ip", id="ct-label-40-accept"),
    pytest.param("ct label & 7 != 7 drop", "ip", id="ct-label-7-7-drop"),
    pytest.param("ah spi 1-1000 accept", "ip", id="ah-spi-1-1000-accept"),
    pytest.param("esp spi 500 accept", "ip", id="esp-spi-500-accept"),
    pytest.param(
        "mh type binding-update accept",
        "ip",
        id="mh-type-binding-update-accep",
    ),
    pytest.param(
        "meta l4proto mobility-header mh type != careof-test-init drop",
        "ip",
        id="meta-l4proto-mobility-header",
    ),
    pytest.param("hbh hdrlength 8 accept", "ip6", id="hbh-hdrlength-8-accept"),
    pytest.param("dst hdrlength 8 accept", "ip6", id="dst-hdrlength-8-accept"),
    pytest.param(
        "rt type 0 rt seg-left 1 accept",
        "ip",
        id="rt-type-0-rt-seg-left-1-acce",
    ),
    pytest.param(
        "exthdr frag exists exthdr mh exists accept",
        "ip",
        id="exthdr-frag-exists-exthdr-mh",
    ),
    pytest.param(
        "dccp type { request, response } drop",
        "ip",
        id="dccp-type-request-response-d",
    ),
    pytest.param(
        "dccp type != { reset, sync } accept",
        "ip",
        id="dccp-type-reset-sync-accept",
    ),
    pytest.param(
        "meta ipsec exists accept", "ip", id="meta-ipsec-exists-accept"
    ),
    pytest.param(
        "meta ipsec missing drop", "ip", id="meta-ipsec-missing-drop"
    ),
    pytest.param(
        "fib saddr . iif oif != 0 accept",
        "ip",
        id="fib-saddr-iif-oif-0-accept",
    ),
    pytest.param(
        "fib saddr . mark oif 0 drop", "ip", id="fib-saddr-mark-oif-0-drop"
    ),
    pytest.param(
        "ip option lsrr exists drop", "ip", id="ip-option-lsrr-exists-drop"
    ),
    pytest.param("ip ecn not-ect accept", "ip", id="ip-ecn-not-ect-accept"),
    pytest.param("log level audit", "ip", id="log-level-audit"),
    # batch-10 vocabulary: helper match, nth numgen, CT event/zone mangle.
    # Each spelling is the live kernel readback (nft v1.1.6), so the
    # canonicalizer must pass it through untouched -- a mangled token or
    # reordered event list would surface as a phantom --plan diff.
    pytest.param('ct helper "ftp" accept', "ip", id="ct-helper-ftp-accept"),
    pytest.param(
        "numgen inc mod 4 0 accept", "ip", id="numgen-inc-mod-4-0-accept"
    ),
    pytest.param(
        "numgen inc mod 8 3 accept", "ip", id="numgen-inc-mod-8-3-accept"
    ),
    pytest.param("notrack", "ip", id="notrack"),
    pytest.param(
        "ct event set new,related,destroy",
        "ip",
        id="ct-event-set-new-related-des",
    ),
    pytest.param("ct zone set 5", "ip", id="ct-zone-set-5"),
    pytest.param("ct original zone set 5", "ip", id="ct-original-zone-set-5"),
    pytest.param("ct reply zone set 7", "ip", id="ct-reply-zone-set-7"),
    pytest.param(
        "notrack ct zone set 1 ct event set new,destroy",
        "ip",
        id="notrack-ct-zone-set-1-ct-eve",
    ),
    # batch-11a vocabulary: CONNSECMARK secmark moves and HMARK jhash.
    # Each spelling is the live kernel readback (nft v1.1.6); the seed
    # 0x-hex canon and dropped `offset 0` must pass through untouched.
    pytest.param(
        "ct secmark set meta secmark", "ip", id="ct-secmark-set-meta-secmark"
    ),
    pytest.param(
        "meta secmark set ct secmark", "ip", id="meta-secmark-set-ct-secmark"
    ),
    pytest.param(
        "meta mark set jhash ip saddr . ip daddr . th sport . th dport . "
        "meta l4proto mod 10 seed 0xabc offset 100",
        "ip",
        id="meta-mark-set-jhash-ip-saddr",
    ),
    pytest.param(
        "meta mark set jhash ip saddr . ip daddr mod 8 seed 0xabc",
        "ip",
        id="meta-mark-set-jhash-ip-saddr-1",
    ),
    pytest.param(
        "meta mark set jhash th dport mod 4 seed 0x0",
        "ip",
        id="meta-mark-set-jhash-th-dport",
    ),
    pytest.param(
        "meta mark set jhash ip6 saddr . ip6 daddr mod 8 seed 0xabc",
        "ip6",
        id="meta-mark-set-jhash-ip6-sadd",
    ),
    # batch-11b: the SECMARK object reference. The `meta secmark set
    # "<name>"` statement is the live readback; the canonicalizer must
    # pass the quoted content-hash object name through untouched (the
    # secmark object block round-trips in test_backend_nft_vocab_objects).
    pytest.param(
        'meta secmark set "secmark_46e9b254fd6f"',
        "ip",
        id="meta-secmark-set-secmark-46e",
    ),
]


@pytest.mark.parametrize(("body", "family"), _CANON_FIXED_POINTS)
def test_vocabulary_is_canon_fixed_point(body: str, family: str) -> None:
    assert canonicalize_nft_rule(body, family=family) == body
