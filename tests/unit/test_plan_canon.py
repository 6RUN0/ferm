from pyferm.plan import _canonicalize_rule as canon
from pyferm.plan.readback import _proto_of


def test_long_options_become_short() -> None:
    out = canon("--protocol tcp --jump ACCEPT", "/32")
    assert out == "-p tcp -j ACCEPT"


def test_source_dest_aliases() -> None:
    assert canon("--source 1.2.3.4 --destination 5.6.7.8", "/32") == (
        "-s 1.2.3.4 -d 5.6.7.8"
    )


def test_source_ports_alias_not_prefix_collapsed() -> None:
    # --source-ports must NOT be matched as the --source prefix
    assert canon("-m multiport --source-ports 22,80", "/32") == (
        "-m multiport --sports 22,80"
    )


def test_multiport_long_to_short_and_dedup_m() -> None:
    # ferm: long --destination-ports + duplicated -m multiport
    ferm = (
        "-m multiport --destination-ports 22,80"
        " -m multiport --source-ports 1024"
    )
    # kernel: short --dports/--sports + single -m multiport
    kernel = "-m multiport --dports 22,80 --sports 1024"
    assert canon(ferm, "/32") == canon(kernel, "/32")


def test_injected_m_tcp_dropped_when_proto_tcp() -> None:
    # kernel injects -m tcp implied by -p tcp; ferm does not emit it
    assert canon("-p tcp -m tcp --dport 22", "/32") == canon(
        "-p tcp --dport 22", "/32"
    )


def test_non_implied_m_kept() -> None:
    # -m conntrack is NOT whitelisted away -- stays visible verbatim
    out = canon("-p tcp -m conntrack --ctstate NEW", "/32")
    assert out == "-p tcp -m conntrack --ctstate NEW"


def test_host_mask_stripped_on_source_ipv4() -> None:
    assert canon("-s 1.2.3.4/32 -j ACCEPT", "/32") == "-s 1.2.3.4 -j ACCEPT"


def test_host_mask_family_correct_ipv6() -> None:
    assert canon("-d dead::beef/128 -j DROP", "/128") == (
        "-d dead::beef -j DROP"
    )
    # /32 must NOT be stripped on an ipv6 family
    assert canon("-s dead::/32 -j DROP", "/128") == "-s dead::/32 -j DROP"


def test_network_mask_not_stripped() -> None:
    assert canon("-s 10.0.0.0/8 -j ACCEPT", "/32") == "-s 10.0.0.0/8 -j ACCEPT"


def test_mark_value_not_treated_as_host_mask() -> None:
    # /32 after --mark must survive: not scoped to -s/-d
    out = canon("-m mark --mark 0x1/0x32 -j ACCEPT", "/32")
    assert "0x1/0x32" in out


def test_implied_m_kept_when_proto_differs() -> None:
    # -m tcp is dropped ONLY when it equals -p's proto.  With -p udp the
    # tcp match is a real, distinct match and must survive verbatim.
    out = canon("-p udp -m tcp --dport 22", "/32")
    assert out == "-p udp -m tcp --dport 22"


def test_proto_read_only_from_dash_p() -> None:
    # Without a -p option there is no implied proto, so a lone -m tcp is
    # never mistaken for the injected match and stays.
    out = canon("-m tcp --dport 22", "/32")
    assert out == "-m tcp --dport 22"


def test_implied_m_dropped_when_m_is_second_to_last_token() -> None:
    # The '-m <module>' lookahead must reach the module even when '-m' is
    # the second-to-last token: '-m tcp' after '-p tcp' still collapses away.
    out = canon("-p tcp -m tcp", "/32")
    assert out == "-p tcp"


def test_host_mask_only_stripped_for_source_dest() -> None:
    # A '/32' operand belongs to -s/-d only; after --mark it must survive.
    out = canon("--mark 0x1/32 -j ACCEPT", "/32")
    assert "0x1/32" in out


def test_host_mask_stripped_when_source_is_second_to_last() -> None:
    # The -s/-d operand lookahead must reach the operand even when -s is
    # the second-to-last token.
    out = canon("-j ACCEPT -s 1.2.3.4/32", "/32")
    assert out == "-j ACCEPT -s 1.2.3.4"


def test_bare_counter_line_collapses_to_empty() -> None:
    # A leading '-c pkts bytes' counter of exactly three tokens is stripped
    # whole, leaving nothing.
    assert canon("-c 5 100", "/32") == ""


# --- trailing option flags: a flag whose value has been cut off ---
#
# The '-m'/'-s'/'-d' rewrites peek one token past the flag, bounded by
# 'index + 1 < len(tokens)'.  A rule ending in a bare flag (no operand) must
# fall through and keep the flag verbatim; the bound stops the following
# 'tokens[index + 1]' read from running off the list end.  A loosened bound
# ('<=', a subtracted offset) reaches past it and crashes on such input.


def test_trailing_dash_m_left_verbatim() -> None:
    # A '-m' with no module name behind it is kept as-is, not a crash.
    assert canon("-p tcp -m", "/32") == "-p tcp -m"


def test_trailing_dash_s_left_verbatim() -> None:
    # A '-s' with no address behind it is kept as-is, not a crash.
    assert canon("-j ACCEPT -s", "/32") == "-j ACCEPT -s"


def test_trailing_dash_d_left_verbatim() -> None:
    # A '-d' with no address behind it is kept as-is, not a crash.
    assert canon("-j ACCEPT -d", "/32") == "-j ACCEPT -d"


def test_new_module_off_token_zero_advances_relatively() -> None:
    # A freshly seen '-m <module>' advances the cursor by two RELATIVE to its
    # position.  When the '-m' sits past token 0, an absolute 'index = 2'
    # rewinds the cursor and reprocesses the intervening tokens, duplicating
    # them in the output.  Placing '-m conntrack' at token 4 exposes that.
    out = canon("-p tcp -j ACCEPT -m conntrack", "/32")
    assert out == "-p tcp -j ACCEPT -m conntrack"


def test_proto_of_reads_operand_after_dash_p() -> None:
    # '-p' with an operand behind it returns that operand.  The one-token
    # lookahead must reach it even when '-p' is the second-to-last token.
    assert _proto_of(["-p", "tcp"]) == "tcp"


def test_proto_of_trailing_dash_p_returns_none() -> None:
    # A trailing '-p' has no operand: the lookahead bound stops the read at
    # the list end and the function reports 'no proto' rather than crashing.
    assert _proto_of(["-j", "ACCEPT", "-p"]) is None
