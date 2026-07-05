from pyferm.plan import _canonicalize_rule as canon


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
