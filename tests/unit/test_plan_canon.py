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
