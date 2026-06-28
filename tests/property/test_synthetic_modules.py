"""Synthetic parametric differential test: port vs oracle for thin modules.

The corpus (:mod:`tests.corpus.test_corpus`) exercises real-world ferm
configs, but some netfilter modules have *no* public wild configuration to
mine (TPROXY, ``mod geoip``), and others (``set``, ``CONNMARK``,
``TCPMSS``) are only touched on a single option path.  The grammar fuzzer
(:mod:`tests.property.test_config_differential`) cannot reach the long
tail of a module's option matrix either, since its grammar is "what was
seen in the corpus".

This module fills the gap by *synthesis*: the parameter matrix below IS
the set of test cases.  Each case is a small ferm config built in Python
and compiled by BOTH the frozen Perl oracle and the Python port with
``--test --noexec --lines`` (text-only -- no kernel, no module load), in
fast and slow mode.

Like the corpus, this asserts **parity, not validity**: the oracle is
ground truth.  A config that is "wrong" by our imperfect knowledge of the
DSL simply makes both implementations fail (or accept) in lockstep -- a
false divergence born of our ignorance is impossible, only a real one.
That is why the error-parity probe (``tcpmss_no_proto``) is kept on
purpose: both sides must reject it with the same diagnostic.  The three
asserts are identical to the corpus contract: exit verdict, byte-for-byte
stderr, and canonicalized stdout.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from pyferm.modules import MATCH_DEFS, PROTO_DEFS, TARGET_DEFS
from tests.corpus.canon import canonicalize

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]

_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}


@dataclass(frozen=True)
class Case:
    """A synthesized ferm config and the id under which it is reported."""

    case_id: str
    config: str


def _block(table: str, chain: str, *rules: str) -> str:
    """Build a single ``table T chain C { ... }`` block from rule lines."""
    body = "\n".join(f"    {rule};" for rule in rules)
    return f"table {table} chain {chain} {{\n{body}\n}}\n"


#: Synthesized cases.  Each one isolates an option (or option combination)
#: of an under-covered module so the matrix doubles as documentation of
#: what is being differentially exercised.  Plausible table/chain homes are
#: used (TPROXY in mangle/PREROUTING, TCPMSS in mangle/FORWARD with a
#: leading ``proto tcp`` the validator requires, the rest in filter/INPUT).
_CASES: list[Case] = [
    # -- TPROXY target (tproxy-mark on-ip on-port) ---------------------
    Case(
        "tproxy_mark",
        _block("mangle", "PREROUTING", "proto tcp TPROXY tproxy-mark 0x1/0x1"),
    ),
    Case(
        "tproxy_on_port",
        _block("mangle", "PREROUTING", "proto tcp TPROXY on-port 50080"),
    ),
    Case(
        "tproxy_on_ip_port",
        _block(
            "mangle",
            "PREROUTING",
            "proto tcp TPROXY on-ip 127.0.0.1 on-port 50080",
        ),
    ),
    Case(
        "tproxy_udp",
        _block(
            "mangle",
            "PREROUTING",
            "proto udp TPROXY tproxy-mark 0x1/0x1 on-port 50080",
        ),
    ),
    # -- geoip match (!src-cc=s !dst-cc=s; CC list is one string) ------
    Case(
        "geoip_src_cc",
        _block("filter", "INPUT", "mod geoip src-cc US ACCEPT"),
    ),
    Case(
        "geoip_dst_cc",
        _block("filter", "INPUT", "mod geoip dst-cc DE DROP"),
    ),
    Case(
        "geoip_cc_list",
        # The CC list is a single scalar; the comma is a token separator,
        # so it must be quoted to survive tokenization.
        _block("filter", "INPUT", 'mod geoip src-cc "US,DE" ACCEPT'),
    ),
    Case(
        "geoip_negated",
        _block("filter", "INPUT", "mod geoip ! src-cc RU DROP"),
    ),
    Case(
        "geoip_proto",
        _block("filter", "INPUT", "mod geoip proto tcp dst-cc DE ACCEPT"),
    ),
    # -- set match (!match-set=sc, flags, counters, negation) ----------
    Case(
        "set_match_src",
        _block("filter", "INPUT", "mod set match-set foo src ACCEPT"),
    ),
    Case(
        "set_flags_src_dst",
        _block("filter", "INPUT", "mod set match-set foo (src dst) ACCEPT"),
    ),
    Case(
        "set_negated",
        _block("filter", "INPUT", "mod set ! match-set foo src DROP"),
    ),
    Case(
        "set_return_nomatch",
        _block(
            "filter",
            "INPUT",
            "mod set match-set foo src return-nomatch ACCEPT",
        ),
    ),
    Case(
        "set_multiple_refs",
        # Two match-set refs in one rule -- a parity probe; whatever the
        # oracle does (accept or reject), the port must do the same.
        _block(
            "filter",
            "INPUT",
            "mod set match-set foo src match-set bar dst ACCEPT",
        ),
    ),
    Case(
        "set_packets_gt",
        _block(
            "filter",
            "INPUT",
            "mod set match-set foo src packets-gt 5 ACCEPT",
        ),
    ),
    # -- CONNMARK target (set-xmark save/restore-mark nfmask ctmask) ---
    Case(
        "connmark_set_xmark",
        _block("filter", "INPUT", "proto tcp CONNMARK set-xmark 0x1/0xff"),
    ),
    Case(
        "connmark_save_mark",
        _block("filter", "INPUT", "proto tcp CONNMARK save-mark"),
    ),
    Case(
        "connmark_restore_mark",
        _block("filter", "INPUT", "proto tcp CONNMARK restore-mark"),
    ),
    Case(
        "connmark_masks",
        _block(
            "filter",
            "INPUT",
            "proto tcp CONNMARK save-mark nfmask 0xff ctmask 0xff",
        ),
    ),
    # -- TCPMSS target (set-mss clamp-mss-to-pmtu; needs proto tcp) ----
    Case(
        "tcpmss_set_mss",
        _block("mangle", "FORWARD", "proto tcp TCPMSS set-mss 1400"),
    ),
    Case(
        "tcpmss_clamp",
        _block("mangle", "FORWARD", "proto tcp TCPMSS clamp-mss-to-pmtu"),
    ),
    Case(
        # Deliberate error-parity probe: TCPMSS without a preceding
        # ``proto tcp`` must be rejected identically by both sides.  Kept
        # even though it "fails to compile" -- the matching failure is the
        # signal.
        "tcpmss_no_proto",
        _block("mangle", "FORWARD", "TCPMSS set-mss 1400"),
    ),
    # -- cross axes: cartesian proto expansion crossed with a module ---
    Case(
        "cross_proto_set",
        _block(
            "filter",
            "INPUT",
            "proto (tcp udp) mod set match-set foo src ACCEPT",
        ),
    ),
    # ================================================================
    # Batch 2: exotic DSL paths most likely to expose port divergence
    # ================================================================
    # -- multiport (&-helper: ferm arrays become comma-joined lists) ---
    # The multiport_params Perl helper requires proto tcp/udp first,
    # chunks arrays >15 ports into separate --source-ports options,
    # and joins the array with commas.  Verifies: --match multiport.
    Case(
        "multiport_src_single",
        _block(
            "filter",
            "INPUT",
            "proto tcp mod multiport source-ports (22) ACCEPT",
        ),
    ),
    Case(
        "multiport_dst_list",
        # Array (22 80 443) is joined to "22,80,443" by the helper.
        _block(
            "filter",
            "INPUT",
            "proto udp mod multiport destination-ports (22 80 443) ACCEPT",
        ),
    ),
    Case(
        "multiport_ports_range",
        # A range element like 1024:2048 is passed through as-is.
        _block(
            "filter",
            "INPUT",
            "proto tcp mod multiport ports (1024:2048) ACCEPT",
        ),
    ),
    Case(
        "multiport_negated",
        _block(
            "filter",
            "INPUT",
            "proto tcp mod multiport destination-ports !(200 201 202) DROP",
        ),
    ),
    # -- tcp proto-flags (tcp-flags!=cc double-comma encoding) ---------
    # Exercises the protocol-level options registered via add_proto_def.
    # Verifies: --tcp-flags, --syn, --tcp-option in output.
    Case(
        "tcp_flags_basic",
        _block(
            "filter",
            "INPUT",
            "proto tcp tcp-flags (SYN ACK) SYN DROP",
        ),
    ),
    Case(
        "tcp_flags_all",
        # ALL is a predefined mask alias understood by both sides.
        _block(
            "filter",
            "INPUT",
            "proto tcp tcp-flags ALL SYN DROP",
        ),
    ),
    Case(
        "tcp_flags_negated",
        # Negation comes between the keyword and its two arguments
        # (the !=cc encoding: ! after the option name, before args).
        _block(
            "filter",
            "INPUT",
            "proto tcp tcp-flags ! (SYN RST) RST ACCEPT",
        ),
    ),
    Case(
        "tcp_syn",
        _block("filter", "INPUT", "proto tcp syn ACCEPT"),
    ),
    Case(
        "tcp_syn_negated",
        _block("filter", "INPUT", "proto tcp !syn DROP"),
    ),
    Case(
        "tcp_option",
        _block("filter", "INPUT", "proto tcp tcp-option 8 ACCEPT"),
    ),
    Case(
        "tcp_mss",
        # mss in the tcp proto def is the MSS-match option; takes a
        # value or range, like the reference test uses "mss 100:200".
        _block(
            "filter",
            "INPUT",
            "proto tcp mss 1024:1536 DROP",
        ),
    ),
    # -- conntrack (!ctstate=c, negatable scalars) ---------------------
    # Verifies: --match conntrack in output.
    Case(
        "conntrack_ctstate_multi",
        _block(
            "filter",
            "INPUT",
            "mod conntrack ctstate (NEW ESTABLISHED) ACCEPT",
        ),
    ),
    Case(
        "conntrack_ctstate_single",
        _block(
            "filter",
            "INPUT",
            "mod conntrack ctstate ESTABLISHED ACCEPT",
        ),
    ),
    Case(
        "conntrack_ctstate_negated",
        _block(
            "filter",
            "INPUT",
            "mod conntrack ! ctstate INVALID DROP",
        ),
    ),
    Case(
        "conntrack_ctorigsrc_dst",
        # RFC 5737 documentation addresses -- safe to use in test rules.
        _block(
            "filter",
            "INPUT",
            "mod conntrack ctorigsrc 192.0.2.1 ctorigdst 198.51.100.1 ACCEPT",
        ),
    ),
    Case(
        "conntrack_ctproto",
        _block(
            "filter",
            "INPUT",
            "mod conntrack ctproto tcp ACCEPT",
        ),
    ),
    # -- u32 raw match (!u32=m: array -> repeated --u32 options) --------
    # The =m encoding and shell_escape of the quoted expression is the
    # highest-yield quoting parity probe for the port.
    # Verifies: --match u32 in output; quotes preserved around expr.
    Case(
        "u32_basic",
        # Single quotes wrap the Python string; double quotes are the
        # ferm token that ferm passes verbatim to iptables.
        _block(
            "filter",
            "INPUT",
            'mod u32 u32 "0x6&0xff=0x6" ACCEPT',
        ),
    ),
    Case(
        "u32_negated",
        _block(
            "filter",
            "INPUT",
            'mod u32 ! u32 "0x0>>22&0x3c@12>>26=0x1" DROP',
        ),
    ),
    # -- MARK target (set-mark set-xmark and-mark or-mark xor-mark) ----
    # Verifies: --jump MARK in output.
    Case(
        "mark_set",
        _block("mangle", "PREROUTING", "MARK set-mark 0x1"),
    ),
    Case(
        "mark_set_xmark",
        _block("mangle", "PREROUTING", "MARK set-xmark 0x1/0xff"),
    ),
    Case(
        "mark_or",
        _block("mangle", "PREROUTING", "MARK or-mark 0x2"),
    ),
    Case(
        "mark_xor",
        _block("mangle", "PREROUTING", "MARK xor-mark 0x3"),
    ),
    # -- recent (!set*0 !update*0 !rcheck*0 + scalars) -----------------
    # Verifies: --match recent in output.
    Case(
        "recent_set",
        _block(
            "filter",
            "INPUT",
            "mod recent set name foo rsource DROP",
        ),
    ),
    Case(
        "recent_update",
        _block(
            "filter",
            "INPUT",
            "mod recent update seconds 60 hitcount 4 name foo ACCEPT",
        ),
    ),
    Case(
        "recent_negated_rcheck",
        # Negation on a *0 (no-arg) option: ! before the keyword.
        _block(
            "filter",
            "INPUT",
            "mod recent ! rcheck DROP",
        ),
    ),
    # -- time (=c comma-joined days array, *0 flags) -------------------
    # Verifies: --match time in output; days array comma-joined.
    Case(
        "time_window",
        _block(
            "filter",
            "INPUT",
            "mod time timestart 08:00 timestop 18:00 ACCEPT",
        ),
    ),
    Case(
        "time_days",
        # days=c: array (Mon Tue Wed) is comma-joined to Mon,Tue,Wed.
        _block(
            "filter",
            "INPUT",
            "mod time days (Mon Tue Wed) ACCEPT",
        ),
    ),
    Case(
        "time_datestart_kerneltz",
        _block(
            "filter",
            "INPUT",
            "mod time datestart 2024-01-01 kerneltz ACCEPT",
        ),
    ),
    # -- icmp / icmpv6 proto (alias icmpv6-type:=icmp-type) -----------
    # Domain-scoped configs: domain ip uses iptables, ip6 uses ip6tables.
    # Verifies: --icmp-type / --icmpv6-type in output.
    Case(
        "icmp_echo_request",
        (
            "domain ip table filter chain INPUT {\n"
            "    proto icmp icmp-type echo-request ACCEPT;\n"
            "}\n"
        ),
    ),
    Case(
        "icmpv6_echo_request",
        # icmpv6-type is registered as an alias for icmp-type via
        # icmpv6-type:=icmp-type in the icmp proto def.
        (
            "domain ip6 table filter chain INPUT {\n"
            "    proto ipv6-icmp icmpv6-type echo-request ACCEPT;\n"
            "}\n"
        ),
    ),
    # -- REDIRECT target (nat table) -----------------------------------
    # Verifies: --jump REDIRECT in output.
    Case(
        "redirect_to_ports",
        _block(
            "nat",
            "PREROUTING",
            "proto tcp REDIRECT to-ports 8080",
        ),
    ),
    Case(
        "redirect_random",
        _block(
            "nat",
            "PREROUTING",
            "proto tcp REDIRECT to-ports 8080 random",
        ),
    ),
    # -- hashlimit (=c mode, =s scalars, continuation opts) ------------
    # Verifies: --match hashlimit in output; mode comma-joined.
    Case(
        "hashlimit_full",
        _block(
            "filter",
            "INPUT",
            # Python adjacent-literal concat keeps each source line <=79.
            "mod hashlimit hashlimit 10/min hashlimit-burst 5"
            " hashlimit-mode srcip hashlimit-name foo ACCEPT",
        ),
    ),
    Case(
        "hashlimit_upto",
        _block(
            "filter",
            "INPUT",
            "mod hashlimit hashlimit-upto 5/min hashlimit-name bar ACCEPT",
        ),
    ),
    # ================================================================
    # Batch 3: quoting/shell_escape parity + NAT ranges + exotic DSL
    # ================================================================
    # -- LOG target (log-prefix quoting is the prime divergence probe) -
    # When a prefix contains spaces, ferm shell_escape emits it quoted;
    # without spaces the token passes through unquoted.  Both behaviours
    # must agree byte-for-byte.  Verifies: --jump LOG --log-prefix.
    Case(
        "log_prefix_trailing_space",
        # Trailing space inside the prefix forces quoting in output.
        _block("filter", "INPUT", 'LOG log-prefix "fw drop: "'),
    ),
    Case(
        "log_prefix_brackets",
        _block(
            "filter",
            "INPUT",
            'LOG log-prefix "with [brackets] and spaces"',
        ),
    ),
    Case(
        "log_level_and_prefix",
        # A prefix with no spaces is emitted unquoted; level is a plain int.
        _block("filter", "INPUT", 'LOG log-level 4 log-prefix "pfx-no-space"'),
    ),
    Case(
        "log_prefix_punctuation",
        # Punctuation-only prefix has no space -> unquoted in output.
        _block("filter", "INPUT", 'LOG log-prefix "fw:drop!"'),
    ),
    # -- NFLOG target --------------------------------------------------
    # Verifies: --jump NFLOG --nflog-prefix (quoting parity).
    Case(
        "nflog_prefix_group",
        _block(
            "filter",
            "INPUT",
            'NFLOG nflog-prefix "nf log here" nflog-group 1',
        ),
    ),
    Case(
        "nflog_group_threshold",
        _block("filter", "INPUT", "NFLOG nflog-group 2 nflog-threshold 5"),
    ),
    # -- ULOG target ---------------------------------------------------
    # Verifies: --jump ULOG --ulog-prefix (quoting parity).
    Case(
        "ulog_prefix_group",
        _block(
            "filter",
            "INPUT",
            'ULOG ulog-prefix "ulog pfx" ulog-nlgroup 1',
        ),
    ),
    Case(
        "ulog_group_cprange",
        _block("filter", "INPUT", "ULOG ulog-nlgroup 2 ulog-cprange 100"),
    ),
    # -- comment match (comment=s: quoted scalar) ----------------------
    # Verifies: --match comment --comment "..." (quoting parity).
    Case(
        "comment_spaces",
        _block(
            "filter",
            "INPUT",
            'mod comment comment "has spaces" ACCEPT',
        ),
    ),
    Case(
        "comment_punctuation",
        _block(
            "filter",
            "INPUT",
            'mod comment comment "rule #1: allow" ACCEPT',
        ),
    ),
    # -- string match (algo=s, from=s, to=s, string, hex-string) ------
    # Verifies: --match string --string/--hex-string quoting parity.
    # The pipe-delimited |hex| form is preserved as an unquoted token.
    Case(
        "string_with_space",
        _block(
            "filter",
            "INPUT",
            'mod string string "GET /" algo bm ACCEPT',
        ),
    ),
    Case(
        "string_hex_plain",
        _block(
            "filter",
            "INPUT",
            'mod string algo kmp from 0 to 100 hex-string "deadbeef" ACCEPT',
        ),
    ),
    Case(
        "string_hex_pipe",
        # Pipe delimiters are ferm-transparent tokens; both sides must
        # pass them through unmodified without quoting.
        _block(
            "filter",
            "INPUT",
            'mod string hex-string "|deadbeef|" algo bm ACCEPT',
        ),
    ),
    # -- DNAT target (to-destination=m, to:= alias, ranges) -----------
    # to-destination=m: an ferm array expands to repeated --to-destination
    # options in one iptables rule -- the =m encoding parity probe.
    # Verifies: --jump DNAT --to-destination in output.
    Case(
        "dnat_to_alias",
        # to:=to-destination alias; both names must produce identical output.
        _block("nat", "PREROUTING", "proto tcp DNAT to 192.0.2.1"),
    ),
    Case(
        "dnat_to_destination",
        _block("nat", "PREROUTING", "proto tcp DNAT to-destination 192.0.2.1"),
    ),
    Case(
        "dnat_addr_range",
        _block(
            "nat",
            "PREROUTING",
            "proto tcp DNAT to-destination 192.0.2.1-192.0.2.10",
        ),
    ),
    Case(
        "dnat_addr_port",
        _block(
            "nat",
            "PREROUTING",
            "proto tcp DNAT to-destination 192.0.2.1:8080",
        ),
    ),
    Case(
        "dnat_addr_port_range",
        _block(
            "nat",
            "PREROUTING",
            "proto tcp DNAT to-destination 192.0.2.1:8080-8090",
        ),
    ),
    Case(
        "dnat_multi",
        # Array (a b) with =m renders as --to-destination a --to-destination b.
        _block(
            "nat",
            "PREROUTING",
            "proto tcp DNAT to-destination (192.0.2.1 192.0.2.2)",
        ),
    ),
    Case(
        "dnat_persistent",
        _block(
            "nat",
            "PREROUTING",
            "proto tcp DNAT to-destination 192.0.2.1 persistent",
        ),
    ),
    Case(
        "dnat_random",
        _block(
            "nat",
            "PREROUTING",
            "proto tcp DNAT to-destination 192.0.2.1 random",
        ),
    ),
    # -- SNAT target (to-source=m, to:= alias) -------------------------
    # Verifies: --jump SNAT --to-source in output.
    Case(
        "snat_single",
        _block(
            "nat",
            "POSTROUTING",
            "outerface eth0 SNAT to-source 192.0.2.1",
        ),
    ),
    Case(
        "snat_range",
        _block(
            "nat",
            "POSTROUTING",
            "outerface eth0 SNAT to-source 192.0.2.1-192.0.2.10",
        ),
    ),
    Case(
        "snat_to_alias",
        _block(
            "nat",
            "POSTROUTING",
            "outerface eth0 SNAT to 192.0.2.1",
        ),
    ),
    Case(
        "snat_persistent",
        _block(
            "nat",
            "POSTROUTING",
            "outerface eth0 SNAT to-source 192.0.2.1 persistent",
        ),
    ),
    # -- MASQUERADE target ---------------------------------------------
    # Verifies: --jump MASQUERADE in output.
    Case(
        "masq_bare",
        _block("nat", "POSTROUTING", "outerface eth0 MASQUERADE"),
    ),
    Case(
        "masq_to_ports",
        _block(
            "nat",
            "POSTROUTING",
            "outerface eth0 MASQUERADE to-ports 1024-2048",
        ),
    ),
    Case(
        "masq_random",
        _block("nat", "POSTROUTING", "outerface eth0 MASQUERADE random"),
    ),
    Case(
        "masq_random_fully",
        _block("nat", "POSTROUTING", "outerface eth0 MASQUERADE random-fully"),
    ),
    # -- NETMAP target -------------------------------------------------
    # Verifies: --jump NETMAP --to in output.
    Case(
        "netmap_to",
        _block(
            "nat",
            "POSTROUTING",
            "outerface eth0 NETMAP to 192.0.2.0/24",
        ),
    ),
    # -- iprange match (!src-range !dst-range) -------------------------
    # Verifies: --match iprange --src-range/--dst-range in output.
    Case(
        "iprange_src",
        _block(
            "filter",
            "INPUT",
            "mod iprange src-range 192.0.2.1-192.0.2.50 ACCEPT",
        ),
    ),
    Case(
        "iprange_src_negated",
        _block(
            "filter",
            "INPUT",
            "mod iprange ! src-range 192.0.2.1-192.0.2.50 DROP",
        ),
    ),
    Case(
        "iprange_dst",
        _block(
            "filter",
            "INPUT",
            "mod iprange dst-range 198.51.100.1-198.51.100.50 ACCEPT",
        ),
    ),
    # -- CT target (notrack*0 helper ctevents=c zone) ------------------
    # ctevents=c: array is comma-joined (=c encoding).
    # Verifies: --jump CT in output.
    Case(
        "ct_notrack",
        _block("filter", "INPUT", "CT notrack"),
    ),
    Case(
        "ct_helper",
        _block("filter", "INPUT", "CT helper ftp"),
    ),
    Case(
        "ct_ctevents_array",
        # (new destroy) is comma-joined to new,destroy by the =c encoder.
        _block("filter", "INPUT", "CT ctevents (new destroy)"),
    ),
    Case(
        "ct_zone",
        _block("filter", "INPUT", "CT zone 1"),
    ),
    # -- dccp proto (dccp-types!=c dccp-option!) -----------------------
    # Verifies: --protocol dccp --dccp-types in output.
    Case(
        "dccp_types",
        _block(
            "filter",
            "INPUT",
            "proto dccp dccp-types (REQUEST RESPONSE) DROP",
        ),
    ),
    Case(
        "dccp_types_negated",
        _block(
            "filter",
            "INPUT",
            "proto dccp dccp-types ! (RESET SYNC) ACCEPT",
        ),
    ),
    Case(
        "dccp_option",
        _block("filter", "INPUT", "proto dccp dccp-option 2 ACCEPT"),
    ),
    # -- owner match (!uid-owner !gid-owner, OUTPUT chain) -------------
    # Verifies: --match owner --uid-owner/--gid-owner in output.
    Case(
        "owner_uid",
        _block("filter", "OUTPUT", "mod owner uid-owner 0 ACCEPT"),
    ),
    Case(
        "owner_uid_negated",
        _block("filter", "OUTPUT", "mod owner ! uid-owner 1000 DROP"),
    ),
    Case(
        "owner_gid",
        _block("filter", "OUTPUT", "mod owner gid-owner 100 ACCEPT"),
    ),
    # -- mac match (mac-source!) ---------------------------------------
    # mac-source! means the ! comes AFTER the keyword and BEFORE the arg
    # (between keyword and argument), not before the keyword name.
    # Verifies: --match mac --mac-source in output.
    Case(
        "mac_source",
        _block(
            "filter",
            "INPUT",
            "mod mac mac-source 00:11:22:33:44:55 ACCEPT",
        ),
    ),
    Case(
        "mac_source_negated",
        # mac-source! encoding: negation sits between keyword and arg.
        _block(
            "filter",
            "INPUT",
            "mod mac mac-source ! 00:11:22:33:44:55 DROP",
        ),
    ),
    # -- rt match (IPv6 routing header, domain ip6) --------------------
    # rt-0-addrs=c: address array is comma-joined.
    # Verifies: --match rt in output (ip6tables-save format).
    Case(
        "rt_type_ip6",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    proto ipv6-route mod rt rt-type 0 ACCEPT;\n"
            "}\n"
        ),
    ),
    Case(
        "rt_addrs_ip6",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    mod rt rt-0-addrs"
            " (2001:db8::1 2001:db8::2) rt-0-not-strict ACCEPT;\n"
            "}\n"
        ),
    ),
    # -- TCPOPTSTRIP target (strip-options=c) --------------------------
    # strip-options=c: array (wscale timestamp) -> wscale,timestamp.
    # Verifies: --jump TCPOPTSTRIP --strip-options in output.
    Case(
        "tcpoptstrip_strip",
        _block(
            "mangle",
            "FORWARD",
            "TCPOPTSTRIP strip-options (wscale timestamp)",
        ),
    ),
    # ================================================================
    # Batch 4: registry completeness sweep (remaining modules)
    # ================================================================
    # -- REJECT target (reject-with) ---------------------------------
    # Verifies: --jump REJECT (bare and with reject-with) in output.
    Case("reject_bare", _block("filter", "INPUT", "REJECT")),
    Case(
        "reject_icmp_port_unreach",
        _block(
            "filter",
            "INPUT",
            "REJECT reject-with icmp-port-unreachable",
        ),
    ),
    Case(
        "reject_tcp_reset",
        _block(
            "filter",
            "INPUT",
            "proto tcp REJECT reject-with tcp-reset",
        ),
    ),
    # -- state match (!state=c) --------------------------------------
    # Verifies: --match state --state in output.
    Case(
        "state_multi",
        _block(
            "filter",
            "INPUT",
            "mod state state (NEW ESTABLISHED) ACCEPT",
        ),
    ),
    Case(
        "state_negated",
        _block("filter", "INPUT", "mod state ! state INVALID DROP"),
    ),
    # -- statistic match (mode=s probability=s every=s packet=s) ----
    # Verifies: --match statistic --mode in output.
    Case(
        "statistic_random",
        _block(
            "filter",
            "INPUT",
            "mod statistic mode random probability 0.5 ACCEPT",
        ),
    ),
    Case(
        "statistic_nth",
        _block(
            "filter",
            "INPUT",
            "mod statistic mode nth every 4 packet 0 ACCEPT",
        ),
    ),
    # -- addrtype match (!src-type !dst-type limit-iface-in*0) -------
    # Verifies: --match addrtype --src-type/--dst-type in output.
    Case(
        "addrtype_src",
        _block("filter", "INPUT", "mod addrtype src-type LOCAL ACCEPT"),
    ),
    Case(
        "addrtype_dst_negated",
        _block(
            "filter",
            "INPUT",
            "mod addrtype ! dst-type BROADCAST DROP",
        ),
    ),
    # -- connlimit match (!connlimit-upto !connlimit-above mask) -----
    # Verifies: --match connlimit --connlimit-above in output.
    Case(
        "connlimit_above",
        _block(
            "filter",
            "INPUT",
            "mod connlimit connlimit-above 10 connlimit-mask 24 DROP",
        ),
    ),
    Case(
        "connlimit_saddr",
        _block(
            "filter",
            "INPUT",
            "mod connlimit connlimit-above 5 connlimit-saddr DROP",
        ),
    ),
    # -- connbytes match (!connbytes connbytes-dir connbytes-mode) ---
    # Verifies: --match connbytes in output.
    Case(
        "connbytes_both",
        _block(
            "filter",
            "INPUT",
            "mod connbytes connbytes 1024"
            " connbytes-dir both connbytes-mode bytes ACCEPT",
        ),
    ),
    Case(
        "connbytes_negated",
        _block(
            "filter",
            "INPUT",
            "mod connbytes ! connbytes 65536"
            " connbytes-dir original connbytes-mode packets DROP",
        ),
    ),
    # -- connmark match (!mark; distinct from CONNMARK target) -------
    # Verifies: --match connmark --mark in output.
    Case(
        "connmark_match_value",
        _block("filter", "INPUT", "mod connmark mark 7 ACCEPT"),
    ),
    Case(
        "connmark_match_negated",
        _block("filter", "INPUT", "mod connmark ! mark 0x10 DROP"),
    ),
    # -- connlabel match (!label set*0) ------------------------------
    # Verifies: --match connlabel --label in output.
    Case(
        "connlabel_match",
        _block("filter", "INPUT", "mod connlabel label test ACCEPT"),
    ),
    Case(
        "connlabel_set_flag",
        # set*0 is a no-arg flag that follows the label value.
        _block(
            "filter",
            "INPUT",
            "mod connlabel label test set ACCEPT",
        ),
    ),
    # -- mark match (!mark; distinct from MARK target) ---------------
    # Verifies: --match mark --mark in output.
    Case(
        "mark_match_value",
        _block("filter", "INPUT", "mod mark mark 0x1 ACCEPT"),
    ),
    Case(
        "mark_match_negated",
        _block("filter", "INPUT", "mod mark ! mark 0x2 DROP"),
    ),
    # -- realm match (realm!) ----------------------------------------
    # Verifies: --match realm --realm in output.
    Case(
        "realm_value",
        _block("filter", "INPUT", "mod realm realm 42 ACCEPT"),
    ),
    Case(
        "realm_negated",
        _block("filter", "INPUT", "mod realm realm ! 99 DROP"),
    ),
    # -- pkttype match (pkt-type!) -----------------------------------
    # Verifies: --match pkttype --pkt-type in output.
    Case(
        "pkttype_unicast",
        _block(
            "filter",
            "INPUT",
            "mod pkttype pkt-type unicast ACCEPT",
        ),
    ),
    Case(
        "pkttype_negated",
        _block(
            "filter",
            "INPUT",
            "mod pkttype pkt-type ! broadcast DROP",
        ),
    ),
    # -- physdev match (physdev-in! physdev-out! physdev-is-*) -------
    # Verifies: --match physdev in output.
    Case(
        "physdev_in",
        _block(
            "filter",
            "INPUT",
            "mod physdev physdev-in eth0 ACCEPT",
        ),
    ),
    Case(
        "physdev_bridged",
        _block(
            "filter",
            "INPUT",
            "mod physdev physdev-is-bridged ACCEPT",
        ),
    ),
    # -- socket match (transparent*0 nowildcard*0 restore-skmark*0) -
    # Verifies: --match socket --transparent in output.
    Case(
        "socket_transparent",
        _block("filter", "INPUT", "mod socket transparent ACCEPT"),
    ),
    # -- limit match (limit=s limit-burst=s) -------------------------
    # Verifies: --match limit --limit in output.
    Case(
        "limit_with_burst",
        _block(
            "filter",
            "INPUT",
            "mod limit limit 10/min limit-burst 5 ACCEPT",
        ),
    ),
    Case(
        "limit_simple",
        _block("filter", "INPUT", "mod limit limit 5/sec ACCEPT"),
    ),
    # -- length match (length!) --------------------------------------
    # Verifies: --match length --length in output.
    Case(
        "length_range",
        _block("filter", "INPUT", "mod length length 100:200 ACCEPT"),
    ),
    Case(
        "length_negated",
        _block("filter", "INPUT", "mod length length ! 1500 DROP"),
    ),
    # -- length2 match (length! layer3*0 layer4*0 layer5*0) ----------
    Case(
        "length2_range",
        _block(
            "filter",
            "INPUT",
            "mod length2 length 64:1400 ACCEPT",
        ),
    ),
    # -- quota match (quota=s) ---------------------------------------
    Case(
        "quota_bytes",
        _block("filter", "INPUT", "mod quota quota 1000000 DROP"),
    ),
    # -- random match (average) --------------------------------------
    Case(
        "random_average",
        _block("filter", "INPUT", "mod random average 50 ACCEPT"),
    ),
    # -- tos match (!tos) --------------------------------------------
    # Verifies: --match tos --tos in output.
    Case(
        "tos_match_value",
        _block("filter", "INPUT", "mod tos tos 0x10 ACCEPT"),
    ),
    Case(
        "tos_match_negated",
        _block("filter", "INPUT", "mod tos ! tos 0x08 DROP"),
    ),
    # -- ttl match (ttl-eq ttl-lt=s ttl-gt=s) -----------------------
    # Verifies: --match ttl --ttl-eq/--ttl-lt in output.
    Case(
        "ttl_match_eq",
        _block("filter", "INPUT", "mod ttl ttl-eq 64 ACCEPT"),
    ),
    Case(
        "ttl_match_lt",
        _block("filter", "INPUT", "mod ttl ttl-lt 10 DROP"),
    ),
    # -- dscp match (dscp dscp-class) --------------------------------
    # Verifies: --match dscp --dscp/--dscp-class in output.
    Case(
        "dscp_match_hex",
        _block("filter", "INPUT", "mod dscp dscp 0x0a ACCEPT"),
    ),
    Case(
        "dscp_match_class",
        _block("filter", "INPUT", "mod dscp dscp-class EF ACCEPT"),
    ),
    # -- ecn match (ecn-tcp-cwr*0 ecn-tcp-ece*0 ecn-ip-ect) ---------
    # Verifies: --match ecn in output.
    Case(
        "ecn_match_cwr",
        _block("filter", "INPUT", "mod ecn ecn-tcp-cwr ACCEPT"),
    ),
    Case(
        "ecn_match_ect",
        _block("filter", "INPUT", "mod ecn ecn-ip-ect 0 ACCEPT"),
    ),
    # -- sctp proto (chunk-types!=sc, port access) -------------------
    # chunk-types!=sc: negation between keyword and two scalar args
    # (flag word + chunk-name list).
    # Verifies: --protocol sctp --chunk-types in output.
    Case(
        "sctp_chunk_types",
        _block(
            "filter",
            "INPUT",
            "proto sctp chunk-types any INIT ACCEPT",
        ),
    ),
    Case(
        "sctp_chunk_negated",
        _block(
            "filter",
            "INPUT",
            "proto sctp chunk-types ! any DATA DROP",
        ),
    ),
    # -- udp proto (no options; sport/dport from base match def) -----
    # Verifies: --protocol udp --sport/--dport in output.
    Case(
        "udp_sport",
        _block("filter", "INPUT", "proto udp sport 53 ACCEPT"),
    ),
    Case(
        "udp_dport",
        _block("filter", "INPUT", "proto udp dport 123 ACCEPT"),
    ),
    # -- ah proto (ahspi! ahlen! ahres*0) ----------------------------
    Case(
        "ah_spi",
        _block(
            "filter",
            "INPUT",
            "proto ah mod ah ahspi 1:1000 ACCEPT",
        ),
    ),
    # -- esp proto (espspi!) -----------------------------------------
    Case(
        "esp_spi",
        _block(
            "filter",
            "INPUT",
            "proto esp mod esp espspi 1:1000 ACCEPT",
        ),
    ),
    # -- mh proto (IPv6 mobile header, mh-type!) ---------------------
    # Proto-level option, not a match module; needs domain ip6.
    # Verifies: --protocol mh --mh-type in ip6tables output.
    Case(
        "mh_type",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    proto mh mh-type 1 ACCEPT;\n"
            "}\n"
        ),
    ),
    Case(
        "mh_type_negated",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    proto mh mh-type ! 2 DROP;\n"
            "}\n"
        ),
    ),
    # -- hl match (IPv6 hop-limit; hl-eq! hl-lt=s hl-gt=s) ----------
    # Verifies: --match hl --hl-eq/--hl-lt in ip6tables output.
    Case(
        "hl_match_eq",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    mod hl hl-eq 64 ACCEPT;\n"
            "}\n"
        ),
    ),
    Case(
        "hl_match_lt",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    mod hl hl-lt 10 DROP;\n"
            "}\n"
        ),
    ),
    # -- hbh match (hop-by-hop options header, IPv6) -----------------
    Case(
        "hbh_len",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    mod hbh hbh-len 0 ACCEPT;\n"
            "}\n"
        ),
    ),
    # -- dst match (destination options header, IPv6, !dst-len=s) ---
    Case(
        "dst_len",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    mod dst dst-len 0 ACCEPT;\n"
            "}\n"
        ),
    ),
    # -- eui64 match (no options, IPv6 EUI-64 address check) ---------
    Case(
        "eui64_bare",
        ("domain ip6 table filter chain INPUT {\n    mod eui64 ACCEPT;\n}\n"),
    ),
    # -- ipv6header match (header!=c soft*0, IPv6) -------------------
    # Verifies: --match ipv6header --header (comma-joined) in output.
    Case(
        "ipv6header_multi",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    mod ipv6header header (frag auth) ACCEPT;\n"
            "}\n"
        ),
    ),
    Case(
        "ipv6header_negated",
        (
            "domain ip6 table filter chain INPUT {\n"
            "    mod ipv6header header ! (ah) DROP;\n"
            "}\n"
        ),
    ),
    # -- ipv4options match (flags!=c any*0) --------------------------
    Case(
        "ipv4options_flags",
        _block(
            "filter",
            "INPUT",
            "mod ipv4options flags (rr lsrr ssrr) any ACCEPT",
        ),
    ),
    # -- rpfilter match (loose*0 validmark*0 accept-local*0 invert*0)
    # Verifies: --match rpfilter in output.
    Case(
        "rpfilter_bare",
        _block("filter", "INPUT", "mod rpfilter ACCEPT"),
    ),
    Case(
        "rpfilter_loose",
        _block("filter", "INPUT", "mod rpfilter loose ACCEPT"),
    ),
    # -- policy match (dir pol strict*0 + IPsec sub-options) ---------
    # The most complex match module: multiple positional scalars.
    # Verifies: --match policy --dir --pol in output.
    Case(
        "policy_ipsec",
        _block(
            "filter",
            "INPUT",
            "mod policy dir in pol ipsec proto esp mode tunnel ACCEPT",
        ),
    ),
    Case(
        "policy_none",
        _block(
            "filter",
            "INPUT",
            "mod policy dir out pol none ACCEPT",
        ),
    ),
    # -- condition match (condition!) --------------------------------
    Case(
        "condition_value",
        _block(
            "filter",
            "INPUT",
            "mod condition condition foo ACCEPT",
        ),
    ),
    # -- helper match (helper) ---------------------------------------
    Case(
        "helper_ftp",
        _block("filter", "INPUT", "mod helper helper ftp ACCEPT"),
    ),
    # -- nth match (every counter start packet) ----------------------
    # Verifies: --match nth --every in output.
    Case(
        "nth_every",
        _block("filter", "INPUT", "mod nth every 4 ACCEPT"),
    ),
    Case(
        "nth_full",
        _block(
            "filter",
            "INPUT",
            "mod nth every 4 counter 0 start 0 packet 0 ACCEPT",
        ),
    ),
    # -- osf match (!genre ttl=s log=s) ------------------------------
    Case(
        "osf_genre",
        _block("filter", "INPUT", "mod osf genre Linux ACCEPT"),
    ),
    # -- nfacct match (nfacct-name=s) --------------------------------
    Case(
        "nfacct_name",
        _block(
            "filter",
            "INPUT",
            "mod nfacct nfacct-name counter1 ACCEPT",
        ),
    ),
    # -- fuzzy match (lower-limit=s upper-limit=s) -------------------
    Case(
        "fuzzy_limits",
        _block(
            "filter",
            "INPUT",
            "mod fuzzy lower-limit 20 upper-limit 100 ACCEPT",
        ),
    ),
    # -- psd match (all four scalar options required) ----------------
    Case(
        "psd_full",
        _block(
            "filter",
            "INPUT",
            "mod psd psd-weight-threshold 15"
            " psd-delay-threshold 2000"
            " psd-lo-ports-weight 1"
            " psd-hi-ports-weight 3 ACCEPT",
        ),
    ),
    # -- devgroup match (!src-group !dst-group) ----------------------
    Case(
        "devgroup_src",
        _block("filter", "INPUT", "mod devgroup src-group 1 ACCEPT"),
    ),
    Case(
        "devgroup_dst_negated",
        _block(
            "filter",
            "INPUT",
            "mod devgroup ! dst-group 2 DROP",
        ),
    ),
    # -- cpu match (!cpu) --------------------------------------------
    Case(
        "cpu_match",
        _block("filter", "INPUT", "mod cpu cpu 0 ACCEPT"),
    ),
    # -- account match (aaddr=s aname=s ashort*0) --------------------
    Case(
        "account_subnet",
        _block(
            "filter",
            "INPUT",
            "mod account aaddr 192.0.2.0/24 aname acct1 ACCEPT",
        ),
    ),
    # -- bpf match (bytecode with spaces: quoting parity probe) ------
    # Verifies: --match bpf --bytecode "..." in output.
    Case(
        "bpf_bytecode",
        _block(
            "filter",
            "INPUT",
            'mod bpf bytecode "4,48 0 0 9,21 0 1 17,6 0 0 1,6 0 0 0" ACCEPT',
        ),
    ),
    # -- cgroup match (path!) ----------------------------------------
    Case(
        "cgroup_path",
        _block(
            "filter",
            "INPUT",
            'mod cgroup path "/sys/fs/cgroup/foo" ACCEPT',
        ),
    ),
    # -- ipvs match (!ipvs*0 !vproto !vaddr !vport ...) --------------
    Case(
        "ipvs_flag",
        _block("filter", "INPUT", "mod ipvs ipvs ACCEPT"),
    ),
    # == Target modules ===============================================
    # -- DSCP target (set-dscp set-dscp-class) -----------------------
    # Verifies: --jump DSCP in output.
    Case(
        "dscp_target_hex",
        _block("mangle", "PREROUTING", "DSCP set-dscp 0x0a"),
    ),
    Case(
        "dscp_target_class",
        _block("mangle", "PREROUTING", "DSCP set-dscp-class EF"),
    ),
    # -- TOS target (set-tos and-tos or-tos xor-tos) ----------------
    # Verifies: --jump TOS in output.
    Case(
        "tos_target_set",
        _block("mangle", "PREROUTING", "TOS set-tos 0x10"),
    ),
    Case(
        "tos_target_and",
        _block("mangle", "PREROUTING", "TOS and-tos 0xf0"),
    ),
    # -- TTL target (ttl-set ttl-dec ttl-inc, IPv4) ------------------
    # Verifies: --jump TTL in output.
    Case(
        "ttl_target_set",
        _block("mangle", "PREROUTING", "TTL ttl-set 64"),
    ),
    Case(
        "ttl_target_dec",
        _block("mangle", "PREROUTING", "TTL ttl-dec 1"),
    ),
    # -- ECN target (ecn-tcp-remove*0) -------------------------------
    Case(
        "ecn_target",
        _block("mangle", "POSTROUTING", "ECN ecn-tcp-remove"),
    ),
    # -- HL target (hl-set hl-dec hl-inc, IPv6) ----------------------
    # Verifies: --jump HL in ip6tables output.
    Case(
        "hl_target_set",
        ("domain ip6 table mangle chain PREROUTING {\n    HL hl-set 64;\n}\n"),
    ),
    Case(
        "hl_target_dec",
        ("domain ip6 table mangle chain PREROUTING {\n    HL hl-dec 1;\n}\n"),
    ),
    # -- CHECKSUM target (checksum-fill*0) ---------------------------
    Case(
        "checksum_fill",
        _block("mangle", "POSTROUTING", "CHECKSUM checksum-fill"),
    ),
    # -- CLASSIFY target (set-class) ---------------------------------
    Case(
        "classify_set_class",
        _block("mangle", "POSTROUTING", "CLASSIFY set-class 1:1"),
    ),
    # -- NFQUEUE target (queue-num queue-balance queue-bypass*0) -----
    # Verifies: --jump NFQUEUE in output.
    Case(
        "nfqueue_num",
        _block("filter", "INPUT", "NFQUEUE queue-num 0"),
    ),
    Case(
        "nfqueue_balance",
        _block("filter", "INPUT", "NFQUEUE queue-balance 0:3"),
    ),
    # -- NOTRACK target (no options) ---------------------------------
    Case("notrack_bare", _block("filter", "INPUT", "NOTRACK")),
    # -- TRACE target (no options) -----------------------------------
    Case("trace_bare", _block("filter", "INPUT", "TRACE")),
    # -- MIRROR target (no options) ----------------------------------
    Case("mirror_bare", _block("filter", "INPUT", "MIRROR")),
    # -- TARPIT target (no options) ----------------------------------
    Case("tarpit_bare", _block("filter", "INPUT", "TARPIT")),
    # -- IPV4OPTSSTRIP target (no options) ---------------------------
    Case(
        "ipv4optsstrip_bare",
        _block("filter", "INPUT", "IPV4OPTSSTRIP"),
    ),
    # -- SYNPROXY target (sack-perm*0 timestamp*0 wscale=s mss=s) ---
    # Verifies: --jump SYNPROXY in output.
    Case(
        "synproxy_full",
        _block(
            "filter",
            "INPUT",
            "proto tcp SYNPROXY sack-perm timestamp wscale 7 mss 1460",
        ),
    ),
    Case(
        "synproxy_bare",
        _block("filter", "INPUT", "proto tcp SYNPROXY"),
    ),
    # -- SECMARK target (selctx) -------------------------------------
    Case(
        "secmark_ctx",
        _block(
            "mangle",
            "INPUT",
            "SECMARK selctx system_u:object_r:ssh_server_packet_t:s0",
        ),
    ),
    # -- CONNSECMARK target (save*0 restore*0) -----------------------
    Case(
        "connsecmark_save",
        _block("mangle", "INPUT", "CONNSECMARK save"),
    ),
    Case(
        "connsecmark_restore",
        _block("mangle", "INPUT", "CONNSECMARK restore"),
    ),
    # -- SET target (add-set=sc del-set=sc exist*0) ------------------
    # Verifies: --jump SET --add-set/--del-set in output.
    Case(
        "set_target_add",
        _block("filter", "INPUT", "SET add-set foo src"),
    ),
    Case(
        "set_target_del",
        _block("filter", "INPUT", "SET del-set bar dst"),
    ),
    # -- AUDIT target (type) -----------------------------------------
    Case(
        "audit_accept",
        _block("filter", "INPUT", "AUDIT type accept"),
    ),
    # -- HMARK target (hmark-tuple quoted; =m encoding for tuple) ----
    # The comma-containing tuple value must be quoted in ferm.
    # Verifies: --jump HMARK --hmark-tuple in output.
    Case(
        "hmark_tuple",
        _block(
            "mangle",
            "PREROUTING",
            'HMARK hmark-tuple "src,dst,sport,dport,proto"'
            " hmark-mod 10 hmark-offset 10",
        ),
    ),
    # -- IDLETIMER target (timeout label) ----------------------------
    Case(
        "idletimer_timeout",
        _block(
            "mangle",
            "PREROUTING",
            "IDLETIMER timeout 10 label test",
        ),
    ),
    # -- ROUTE target (oif iif gw continue*0 tee*0) -----------------
    # Verifies: --jump ROUTE in output.
    Case(
        "route_oif",
        _block("mangle", "PREROUTING", "ROUTE oif eth0"),
    ),
    Case(
        "route_iif_continue",
        _block("mangle", "PREROUTING", "ROUTE iif eth1 continue"),
    ),
    # -- LED target (led-trigger-id led-delay led-always-blink*0) ---
    Case(
        "led_trigger",
        _block("mangle", "PREROUTING", "LED led-trigger-id myled"),
    ),
    # -- TEE target (gateway) ----------------------------------------
    Case(
        "tee_gateway",
        _block("mangle", "PREROUTING", "TEE gateway 192.0.2.1"),
    ),
    # -- CLUSTERIP target (new*0 hashmode clustermac ...) ------------
    Case(
        "clusterip_config",
        _block(
            "filter",
            "FORWARD",
            "CLUSTERIP new hashmode sourceip"
            " clustermac 01:00:5e:00:00:20"
            " total-nodes 2 local-node 1",
        ),
    ),
    # -- BALANCE target (to:= alias, nat) ----------------------------
    Case(
        "balance_to",
        _block(
            "nat",
            "PREROUTING",
            "BALANCE to 10.0.0.1-10.0.0.3",
        ),
    ),
    # -- SAME target (nat) -------------------------------------------
    Case(
        "same_to",
        _block("nat", "PREROUTING", "SAME to 192.168.1.1"),
    ),
    # -- RATEEST target (rateest-name rateest-interval rateest-ewmalog)
    Case(
        "rateest_config",
        _block(
            "nat",
            "PREROUTING",
            "RATEEST rateest-name myest"
            " rateest-interval 1000 rateest-ewmalog 8",
        ),
    ),
    # -- RTPENGINE target (id with quoted space) ----------------------
    # Verifies: --jump RTPENGINE --id "..." quoting parity.
    Case(
        "rtpengine_id",
        _block("nat", "PREROUTING", 'RTPENGINE id "0 DFGH"'),
    ),
    # -- JOOL / JOOL_SIIT targets (instance) -------------------------
    Case(
        "jool_instance",
        _block("nat", "PREROUTING", "JOOL instance default"),
    ),
    Case(
        "jool_siit_instance",
        _block("nat", "PREROUTING", "JOOL_SIIT instance default"),
    ),
    # -- DNPT / SNPT targets (IPv6 NAT prefix translation) -----------
    # Verifies: --jump DNPT/SNPT in ip6tables output.
    Case(
        "dnpt_pfx",
        (
            "domain ip6 table nat chain POSTROUTING {\n"
            "    DNPT src-pfx 2001:db8:1::/32"
            " dst-pfx 2001:db8::/32;\n"
            "}\n"
        ),
    ),
    Case(
        "snpt_pfx",
        (
            "domain ip6 table nat chain POSTROUTING {\n"
            "    SNPT src-pfx 2001:db8::/32"
            " dst-pfx 2001:db8:1::/32;\n"
            "}\n"
        ),
    ),
    # -- tcpmss match (!mss) -------------------------------------------
    Case(
        "tcpmss_match_mss",
        _block("filter", "INPUT", "proto tcp mod tcpmss mss 1400 ACCEPT"),
    ),
    # -- ebtables named protocols (proto IPv4/IPv6/ARP/RARP/802_1Q) ----
    # ebtables lives in its own domain; these names are eb-only PROTO_DEFS
    # keys with no iptables namesake, so the iptables-focused matrix above
    # never reaches them.
    Case(
        "eb_proto_ipv4",
        "domain eb chain FORWARD {\n"
        "    proto IPv4 ip-source 192.168.1.1 DROP;\n"
        "}\n",
    ),
    Case(
        "eb_proto_ipv6",
        "domain eb chain FORWARD {\n"
        "    proto IPv6 ip6-source 2001:db8::1 DROP;\n"
        "}\n",
    ),
    Case(
        "eb_proto_arp",
        "domain eb chain FORWARD {\n"
        "    proto ARP arp-mac-src 00:11:22:33:44:55 ACCEPT;\n"
        "}\n",
    ),
    Case(
        "eb_proto_rarp",
        "domain eb chain FORWARD {\n    proto RARP ACCEPT;\n}\n",
    ),
    Case(
        "eb_proto_802_1q",
        "domain eb chain FORWARD {\n    proto 802_1Q ACCEPT;\n}\n",
    ),
    # -- ebtables nat-family targets (arpreply/dnat/redirect/snat) ------
    # Lower-case eb targets, distinct from the upper-case iptables DNAT/SNAT
    # targets; only reachable in the eb domain's nat table.
    Case(
        "eb_target_arpreply",
        "domain eb table nat chain PREROUTING {\n"
        "    arpreply arpreply-mac 00:00:de:ad:be:ef arpreply-target DROP;\n"
        "}\n",
    ),
    Case(
        "eb_target_dnat",
        "domain eb table nat chain PREROUTING {\n"
        "    dnat to-destination 00:00:de:ad:be:ef dnat-target DROP;\n"
        "}\n",
    ),
    Case(
        "eb_target_redirect",
        "domain eb table nat chain PREROUTING {\n"
        "    redirect redirect-target DROP;\n"
        "}\n",
    ),
    Case(
        "eb_target_snat",
        "domain eb table nat chain POSTROUTING {\n"
        "    snat to-source 00:00:de:ad:be:ef snat-target DROP;\n"
        "}\n",
    ),
]


def _compile(
    prefix: tuple[str, ...], args: list[str]
) -> tuple[bool, str, str]:
    proc = subprocess.run(  # fixed argv, no shell
        [*prefix, *args],
        capture_output=True,
        encoding="utf-8",
        check=False,
        env=_ENV,
        cwd=REPO_ROOT,
    )
    return proc.returncode == 0, proc.stdout, proc.stderr


@pytest.mark.parametrize("mode_args", [[], ["--slow"]], ids=["fast", "slow"])
@pytest.mark.parametrize("case", _CASES, ids=lambda case: case.case_id)
def test_synthetic_module_matches_oracle(
    case: Case, mode_args: list[str], tmp_path: Path
) -> None:
    config_path = tmp_path / "case.ferm"
    config_path.write_text(case.config, encoding="utf-8")

    args = ["--test", "--noexec", "--lines", *mode_args, str(config_path)]
    oracle = _compile(
        ("perl", str(REPO_ROOT / "reference" / "src" / "ferm")), args
    )
    port = _compile((sys.executable, "-m", "pyferm"), args)

    assert port[0] == oracle[0], f"exit verdict differs\n{port[2]}{oracle[2]}"
    assert port[2] == oracle[2], "stderr differs"
    assert canonicalize(port[1]) == canonicalize(oracle[1])


#: Module names the differential matrix deliberately does not synthesize.
#: Keep this empty unless a module genuinely cannot be expressed as a
#: standalone rule; a newly registered ``add_*_def`` should gain a ``Case``
#: above, not a waiver.  Map each entry to the reason / covering suite.
_COVERAGE_WAIVERS: dict[str, str] = {}


def _registry_module_names() -> set[str]:
    """All module names registered across families (skip the '' default)."""
    names: set[str] = set()
    for registry in (PROTO_DEFS, MATCH_DEFS, TARGET_DEFS):
        for family_defs in registry.values():
            names.update(name for name in family_defs if name)
    return names


def _case_tokens() -> set[str]:
    """Whitespace tokens across all case configs, stripped of punctuation."""
    tokens: set[str] = set()
    for case in _CASES:
        for word in re.split(r"\s+", case.config):
            tokens.add(word.strip('";,!'))
    return tokens


def test_every_registered_module_has_a_synthetic_case() -> None:
    """Guard the matrix's completeness: a new module must gain a Case.

    ``_CASES`` is hand-maintained, so a freshly registered module would
    otherwise carry zero differential coverage with nothing to flag it.
    Matching is by module name appearing as a token in some case config --
    coarse, so a module whose name happens to coincide with a common token
    (e.g. ``to``, ``set``, ``mode``) could be reported covered by an
    incidental match rather than a dedicated Case; the guard's strength is a
    distinctively-named new module, whose name cannot appear by accident.
    No registered module currently relies on an incidental match.
    """
    registry = _registry_module_names()

    # Guard the guard: a waiver must name a real module that genuinely has no
    # Case, else a stale/typo'd waiver silently masks a future coverage gap.
    stale = set(_COVERAGE_WAIVERS) - registry
    assert not stale, (
        f"_COVERAGE_WAIVERS names unknown modules: {sorted(stale)}"
    )
    redundant = set(_COVERAGE_WAIVERS) & _case_tokens()
    assert not redundant, (
        "_COVERAGE_WAIVERS names modules that already have a case (drop the "
        f"waiver): {sorted(redundant)}"
    )

    tokens = _case_tokens()
    uncovered = {
        name
        for name in registry
        if name not in tokens and name not in _COVERAGE_WAIVERS
    }
    assert not uncovered, (
        "registered modules with no synthetic case (add a Case above or a "
        f"_COVERAGE_WAIVERS entry): {sorted(uncovered)}"
    )
