"""Tests for pyferm.introspect (Phase-7 slice 3)."""

from __future__ import annotations

import pytest

from pyferm.errors import FermError
from pyferm.introspect import _render_module, describe, render_params
from pyferm.modules import MATCH_DEFS, PROTO_DEFS, KeywordParams, ParamFunction


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        (None, "(no argument)"),
        (1, "<value>"),
        ("2", "<2 values>"),  # defensive: no digit-strings in real data
        ("s", "<value>"),
        ("c", "<comma-separated list>"),
        ("cc", "<comma-separated list> <comma-separated list>"),
        ("sc", "<value> <comma-separated list>"),
        ("sz", "<value> <value>"),  # defensive: unknown letters fall back
        ("m", "<value>... (repeatable)"),
        (ParamFunction("address_magic"), "<address[/mask]>"),
        (ParamFunction("cgroup_classid"), "<special: cgroup_classid>"),
    ],
)
def test_render_params(params: KeywordParams, expected: str) -> None:
    assert render_params(params) == expected


def test_render_module_connlimit_block() -> None:
    block = _render_module(
        "match", "connlimit", "ip", MATCH_DEFS["ip"]["connlimit"]
    )
    lines = block.splitlines()
    assert lines[0] == "match module 'connlimit' (ip/ip6):"
    assert lines[-1] == "  see iptables-extensions(8) and ferm(1)"
    joined = "\n".join(lines)
    assert "connlimit-upto" in joined
    assert "negatable (! before keyword)" in joined
    assert "(no argument)" in joined  # connlimit-saddr


def test_render_module_alias_grouping() -> None:
    block = _render_module("proto", "icmp", "ip", PROTO_DEFS["ip"]["icmp"])
    # icmpv6-type is an alias key of icmp-type: one row, no own line
    assert "(aliases: icmpv6-type)" in block
    assert block.count("icmpv6-type") == 1


def test_render_module_lines_fit_width() -> None:
    from pyferm.introspect import MAX_WIDTH

    # The design spec scopes the 79-column invariant to --list-modules'
    # own name-column layout, not to --describe's per-module option
    # tables. 'set' (ip match, i.e. ipset) combines a 19-char option name
    # ("update-subcounters") with a wide "sc" argument rendering, so its
    # fixed-width columns exceed 79 in every row regardless of gutter --
    # a real data shape, not a rendering defect.
    _known_wide = {("ip", "set")}
    for family, mods in MATCH_DEFS.items():
        for name, module in mods.items():
            if (family, name) in _known_wide:
                continue
            for line in _render_module(
                "match", name, family, module
            ).splitlines():
                assert len(line) <= MAX_WIDTH, (family, name, line)


def test_describe_multi_hit_mark_target_both_families() -> None:
    text = describe("MARK")
    assert "target module 'MARK' (ip/ip6):" in text
    assert "target module 'MARK' (eb):" in text
    assert text.count("target module 'MARK'") == 2


def test_describe_tcp_single_protocol_block() -> None:
    text = describe("tcp")
    assert "protocol module 'tcp' (ip/ip6):" in text
    assert text.count("module 'tcp'") == 1


def test_describe_comment_module_and_shortcut() -> None:
    text = describe("comment")
    assert "match module 'comment' (ip/ip6):" in text
    assert "shortcut 'comment'" in text


def test_describe_builtin_function() -> None:
    text = describe("@cat")
    assert "built-in function '@cat':" in text
    assert "@cat(a, b, ...)" in text


def test_describe_bare_form_def() -> None:
    assert "deprecated spelling of '@def'" in describe("def")


def test_describe_deprecated_realgoto() -> None:
    assert describe("realgoto").startswith(
        "deprecated keyword 'realgoto': use 'goto'"
    )


def test_describe_shortcut_dports() -> None:
    text = describe("dports")
    assert (
        "shortcut 'dports' (ip/ip6) = match module 'multiport', "
        "option 'destination-ports'" in text
    )


def test_describe_option_fallback_source_implicit() -> None:
    text = describe("source")
    assert "option 'source' of the implicit base match (ip/ip6)" in text


def test_describe_option_fallback_module_option() -> None:
    text = describe("connlimit-mask")
    assert "option 'connlimit-mask' of match module 'connlimit'" in text


def test_describe_option_fallback_alias() -> None:
    text = describe("saddr")
    assert "alias of 'source'" in text


@pytest.mark.parametrize("name", ["", "no-such-name-xyzzy"])
def test_describe_unknown_raises(name: str) -> None:
    with pytest.raises(FermError, match="unknown name"):
        describe(name)


def test_list_modules_sections_and_width() -> None:
    from pyferm.introspect import MAX_WIDTH, list_modules

    text = list_modules()
    for header in (
        "protocol modules (ip/ip6):",
        "protocol modules (eb):",
        "match modules (ip/ip6):",
        "match modules (arp):",
        "match modules (eb):",
        "target modules (ip/ip6):",
        "target modules (eb):",
        "built-in keywords:",
    ):
        assert header in text, header
    assert "match module ''" not in text
    assert text.count("implicit base options:") == 3  # ip, arp, eb
    assert text.rstrip().endswith(
        "Use --describe NAME for details on a module, option or keyword."
    )
    for line in text.splitlines():
        assert len(line) <= MAX_WIDTH, line


def test_list_modules_first_section_golden() -> None:
    from pyferm.introspect import list_modules

    text = list_modules()
    assert text.startswith(
        "protocol modules (ip/ip6):\n"
        "  dccp  icmp  mh    sctp  tcp   udp\n"
        "\n"
        "protocol modules (eb):\n"
        "  802_1Q  ARP     IPv4    IPv6    RARP\n"
    )


def test_describe_connlimit_golden() -> None:
    assert describe("connlimit") == (
        "match module 'connlimit' (ip/ip6):\n"
        "  connlimit-upto   <value>        negatable (! before keyword)\n"
        "  connlimit-above  <value>        negatable (! before keyword)\n"
        "  connlimit-mask   <value>\n"
        "  connlimit-saddr  (no argument)\n"
        "  connlimit-daddr  (no argument)\n"
        "  see iptables-extensions(8) and ferm(1)\n"
    )


_LIST_MODULES_GOLDEN = """\
protocol modules (ip/ip6):
  dccp  icmp  mh    sctp  tcp   udp

protocol modules (eb):
  802_1Q  ARP     IPv4    IPv6    RARP

match modules (ip/ip6):
  account      addrtype     ah           bpf          cgroup
  comment      condition    connbytes    connlabel    connlimit
  connmark     conntrack    cpu          devgroup     dscp
  dst          ecn          esp          eui64        fuzzy
  geoip        hashlimit    hbh          helper       hl
  iprange      ipv4options  ipv6header   ipvs         length
  length2      limit        mac          mark         multiport
  nfacct       nth          osf          owner        physdev
  pkttype      policy       psd          quota        random
  realm        recent       rpfilter     rt           set
  socket       state        statistic    string       tcpmss
  time         tos          ttl          u32
  implicit base options:
    destination    fragment       in-interface   out-interface  source

match modules (arp):
  implicit base options:
    destination-ip   destination-mac  h-length         h-type
    in-interface     mangle-ip-d      mangle-ip-s      mangle-mac-d
    mangle-mac-s     mangle-target    opcode           out-interface
    proto-type       source-ip        source-mac

match modules (eb):
  implicit base options:
    802_3-sap          802_3-type         among-dst
    among-dst-file     among-src          among-src-file
    destination        in-interface       limit
    limit-burst        log                log-arp
    log-ip             log-level          log-prefix
    logical-in         logical-out        mark
    out-interface      pkttype-type       source
    stp-flags          stp-forward-delay  stp-hello-time
    stp-max-age        stp-msg-age        stp-port
    stp-root-addr      stp-root-cost      stp-root-prio
    stp-sender-addr    stp-sender-prio    stp-type

target modules (ip/ip6):
  AUDIT          BALANCE        CHECKSUM       CLASSIFY       CLUSTERIP
  CONNMARK       CONNSECMARK    CT             DNAT           DNPT
  DSCP           ECN            HL             HMARK          IDLETIMER
  IPV4OPTSSTRIP  JOOL           JOOL_SIIT      LED            LOG
  MARK           MASQUERADE     MIRROR         NETMAP         NFLOG
  NFQUEUE        NOTRACK        RATEEST        REDIRECT       REJECT
  ROUTE          RTPENGINE      SAME           SECMARK        SET
  SNAT           SNPT           SYNPROXY       TARPIT         TCPMSS
  TCPOPTSTRIP    TEE            TOS            TPROXY         TRACE
  TTL            ULOG

target modules (eb):
  MARK      arpreply  dnat      redirect  snat

built-in keywords:
  @basename      @cat           @def           @defined       @dirname
  @else          @eq            @glob          @gotosubchain  @hook
  @if            @include       @ipfilter      @join          @length
  @ne            @not           @preserve      @resolve       @set
  @subchain      @substr        ACCEPT         DROP           NOP
  QUEUE          RETURN         chain          def            domain
  goto           hook           include        jump           mod
  module         policy         priority       proto          protocol
  subchain       table

Use --describe NAME for details on a module, option or keyword.
"""

_DESCRIBE_SADDR_GOLDEN = """\
option 'saddr' of the implicit base match (ip/ip6):
  source  <address[/mask]>  negatable (aliases: saddr) alias of 'source'

option 'saddr' of the implicit base match (arp):
  source-ip  <value>  negatable (aliases: saddr) alias of 'source-ip'

option 'saddr' of the implicit base match (eb):
  source  <value>  negatable (aliases: saddr) alias of 'source'
"""


def test_list_modules_full_golden() -> None:
    """Pin the complete catalogue text, not just the first section.

    The shape test above cannot notice a whole name list silently
    dropping out (e.g. the built-in keywords fold or an implicit
    base-options fold rendering empty); only full-text equality can.
    """
    from pyferm.introspect import list_modules

    assert list_modules() == _LIST_MODULES_GOLDEN


def test_describe_saddr_fallback_golden() -> None:
    # Exact text: pins the row layout (name/arg/notes columns), the bare
    # "negatable" note and the "alias of" tail of the option fallback.
    assert describe("saddr") == _DESCRIBE_SADDR_GOLDEN


def test_describe_comment_two_block_golden() -> None:
    # Exact text of a two-hit describe: pins the blank-line separator
    # between blocks, which substring checks cannot.
    assert describe("comment") == (
        "match module 'comment' (ip/ip6):\n"
        "  comment  <value>\n"
        "  see iptables-extensions(8) and ferm(1)\n"
        "\n"
        "shortcut 'comment' (ip/ip6) = match module 'comment', "
        "option 'comment'\n"
    )


def test_fold_columns_floors_at_one_name_per_row() -> None:
    from pyferm.introspect import _fold_columns

    # column (52) exceeds half the width budget: the fold must floor at
    # ONE name per row rather than widen past MAX_WIDTH
    names = ["a" * 50, "b" * 50]
    assert _fold_columns(names, 2) == ["  " + names[0], "  " + names[1]]


def test_fold_columns_budget_shrinks_with_indent() -> None:
    from pyferm.introspect import MAX_WIDTH, _fold_columns

    # 4 names of width 18 fold at column 20: (79 - 4) // 20 = 3 per row,
    # so the fourth name wraps instead of stretching the row to 82
    rows = _fold_columns(["n" * 18] * 4, 4)
    assert len(rows) == 2
    assert all(len(row) <= MAX_WIDTH for row in rows)
