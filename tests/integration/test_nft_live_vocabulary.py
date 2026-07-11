"""
Live-nft validation of the backend's translated vocabulary.

The unit layer pins the emitted *text*; this suite pins that the text is
*real nft* and that an applied ruleset converges under ``--plan`` (the
2026-07-09 ad-hoc netns probes, formalized).  Two halves:

* ``nft -c`` must accept a config exercising every translated construct
  (the full icmp/icmpv6 type maps, numeric respell, multiport sets,
  limit units and burst, log level/NFLOG shapes, mark, dashed chains,
  addrtype fib types with RTN-ordered lists and limit-iface qualifiers,
  the dscp name canon, DSCP/CLASSIFY targets with tc-handle respell,
  ct status forms with bang negation, NFQUEUE queue-to shapes, SYNPROXY,
  TTL/HL rewrites, masked marks, set-xmark, mod hl, NETMAP prefix maps,
  statistic random/nth samplers, pkttype meta classes, TCPOPTSTRIP resets,
  connbytes ct counters, per-rule connlimit sets, quota unit canon, iprange
  address ranges, MARK/CONNMARK mark arithmetic, SET target runtime
  buckets with the ban-list lookup, tcpmss/tcp-option kind respells);
* applying it inside a rootless network namespace and re-running
  ``--plan`` must report convergence -- the readback-canonicality
  contract (kernel respells marks to hex, drops default log levels,
  omits implied ``meta l4proto``, prints service ports numerically)
  that no text-only test can see.

Both skip where ``unshare -rn``/``nft`` are unavailable, mirroring
:func:`tests.corpus.test_corpus_nft._live_nft_usable`.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from tests.corpus.test_corpus_nft import _live_nft_usable

_HERE = Path(__file__).resolve().parent
REPO_ROOT = _HERE.parents[1]

_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

_NFT_LINE = re.compile(r"^(add|create|delete|insert|flush|replace) ")

#: One config exercising every construct the nft backend translates.
_VOCABULARY = """\
@set $BADGUYS = (10.66.6.6 192.168.66.0/24);
@set $DYNBAN = ();
@def $ICMP_V4 = (
    echo-reply pong destination-unreachable source-quench redirect
    echo-request ping router-advertisement router-solicitation
    time-exceeded ttl-exceeded parameter-problem timestamp-request
    timestamp-reply address-mask-request address-mask-reply
    0 3 4 5 8 9 10 11 12 13 14 15 16 17 18 42 3/1
);
@def $ICMP_V6 = (
    destination-unreachable packet-too-big time-exceeded ttl-exceeded
    parameter-problem echo-request ping echo-reply pong
    router-solicitation router-advertisement neighbour-solicitation
    neighbor-solicitation neighbour-advertisement neighbor-advertisement
    redirect
    1 2 3 4 128 129 130 131 132 133 134 135 136 137 138 141 142 143
    100 1/4
);
domain ip table filter {
    chain INPUT {
        policy DROP;
        proto icmp icmp-type $ICMP_V4 ACCEPT;
        proto icmp icmp-type !echo-request DROP;
        proto tcp dport ssh ACCEPT;
        proto tcp mod multiport destination-ports (http 8000:8080) ACCEPT;
        proto udp mod multiport source-ports (domain 123) ACCEPT;
        mod conntrack ctstate (ESTABLISHED RELATED) ACCEPT;
        mod limit limit 10/min limit-burst 30 ACCEPT;
        mod limit limit-burst 7 ACCEPT;
        mod mark mark 2 ACCEPT;
        mod connmark mark 0x10 ACCEPT;
        LOG log-prefix "in: " log-level info;
        LOG log-prefix "warn-default: " log-level warning;
        NFLOG nflog-group 2 nflog-prefix "nf: " nflog-threshold 20;
        proto tcp tcp-flags (SYN RST) SYN ACCEPT;
        proto tcp tcp-flags ALL (SYN ACK) DROP;
        proto tcp tcp-flags (FIN SYN) NONE ACCEPT;
        proto tcp !syn DROP;
        mod length length 100:200 DROP;
        mod ttl ttl-eq 64 ACCEPT;
        mod ttl ttl-gt 128 DROP;
        mod mac mac-source AA:BB:CC:DD:EE:FF ACCEPT;
        mod mark mark 2/0xffffffff ACCEPT;
        mod addrtype dst-type LOCAL ACCEPT;
        mod addrtype dst-type (BROADCAST MULTICAST) DROP;
        mod addrtype dst-type "BROADCAST,LOCAL" ACCEPT;
        mod addrtype ! src-type "BROADCAST,LOCAL,UNSPEC" DROP;
        mod addrtype src-type LOCAL limit-iface-in ACCEPT;
        mod dscp dscp 0x2c ACCEPT;
        mod dscp dscp 46 ACCEPT;
        mod dscp dscp 0x3f ACCEPT;
        mod dscp dscp-class be ACCEPT;
        mod set match-set $BADGUYS src DROP;
        mod set ! match-set $BADGUYS src ACCEPT;
        mod conntrack ctstate DNAT ACCEPT;
        mod conntrack ctstate "DNAT,SNAT" ACCEPT;
        mod conntrack ! ctstate "DNAT,SNAT" DROP;
        mod conntrack ctstatus "CONFIRMED,ASSURED" ACCEPT;
        mod conntrack ! ctstatus SEEN_REPLY DROP;
        mod state ! state "ESTABLISHED,RELATED" DROP;
        mod mark mark "0x80000000/0x80000000" DROP;
        mod connmark ! mark "0x1/0x3" ACCEPT;
        NFQUEUE;
        NFQUEUE queue-num 65535;
        NFQUEUE queue-balance 0:3 queue-bypass queue-cpu-fanout;
        proto tcp dport 8443 SYNPROXY sack-perm timestamp wscale 7 mss 1460;
        proto tcp dport 8444 SYNPROXY mss 1460;
        mod statistic mode random probability 0.5 ACCEPT;
        mod statistic mode random probability 1.0 DROP;
        mod statistic mode nth every 10 packet 3 ACCEPT;
        mod statistic mode nth every 4 DROP;
        mod pkttype pkt-type unicast ACCEPT;
        mod pkttype pkt-type ! broadcast DROP;
        mod time timestart 09:00 timestop 18:00 ACCEPT;
        mod time timestart 23:30:30 ACCEPT;
        mod time weekdays "Mon,Tue,Sat" ACCEPT;
        mod time days "Sun" ACCEPT;
        mod time ! weekdays "Sat,Sun" DROP;
        mod time datestart 2026-01-01 datestop 2026-12-31 ACCEPT;
        mod time datestart 2026-06-01T09:30:00 ACCEPT;
        mod time datestop 2026-12-31 DROP;
        proto tcp dport 22 mod time timestart 09:00 timestop 17:00
            weekdays "Mon,Tue,Wed,Thu,Fri" ACCEPT;
        jump fail2ban-ssh;
    }
    chain OUTPUT {
        mod owner uid-owner root ACCEPT;
        mod owner uid-owner !1000 DROP;
        mod addrtype dst-type UNICAST limit-iface-out ACCEPT;
    }
    chain fail2ban-ssh RETURN;
    chain mangle-ish {
        MARK set-mark 0x2;
        CONNMARK save-mark;
        CONNMARK restore-mark;
        CONNMARK set-mark 5;
        TEE gateway 10.0.0.2;
        NOTRACK;
        TRACE;
    }
    chain mss-ish {
        proto tcp tcp-flags (SYN RST) SYN TCPMSS clamp-mss-to-pmtu;
        proto tcp tcp-flags (SYN RST) SYN TCPMSS set-mss 1400;
    }
    chain tcpopt-ish {
        proto tcp TCPOPTSTRIP strip-options "mss,wscale,sack-permitted,md5";
        proto tcp TCPOPTSTRIP strip-options "sack,8,254";
    }
    chain qos-ish {
        DSCP set-dscp-class af31;
        DSCP set-dscp 0x01;
        CLASSIFY set-class 0001:0020;
        CLASSIFY set-class ffff:ffff;
        TTL ttl-set 42;
        MARK set-xmark "0xffffffff/0xffffffff";
    }
    chain recent-ish {
        mod recent rcheck seconds 60 hitcount 4 name SSHV4 goto fail2ban-ssh;
        mod recent set name SSHV4 NOP;
    }
    chain hashlimit-ish {
        proto tcp mod hashlimit hashlimit-upto 3/minute hashlimit-burst 5
            hashlimit-name hl_upto hashlimit-mode srcip
            hashlimit-htable-expire 60000 ACCEPT;
        proto tcp mod hashlimit hashlimit-above 10/second
            hashlimit-name hl_conc hashlimit-mode "srcip,dstport"
            hashlimit-srcmask 24 DROP;
        proto udp mod hashlimit hashlimit-upto 5/second
            hashlimit-name hl_persec hashlimit-mode dstip ACCEPT;
    }
    chain connbytes-ish {
        mod connbytes connbytes "1048576:" connbytes-dir both
            connbytes-mode bytes ACCEPT;
        mod connbytes connbytes "100:200" connbytes-dir original
            connbytes-mode packets ACCEPT;
        mod connbytes ! connbytes "500:" connbytes-dir reply
            connbytes-mode avgpkt DROP;
        mod connbytes connbytes ":5000" connbytes-dir both
            connbytes-mode bytes ACCEPT;
    }
    chain quota-iprange-ish {
        mod quota quota 1048576 ACCEPT;
        mod quota quota 1500000 DROP;
        mod iprange src-range 10.0.0.1-10.0.0.5 ACCEPT;
        mod iprange ! dst-range 192.168.0.1-192.168.0.10 DROP;
    }
    chain set-target-ish {
        mod set match-set $DYNBAN src DROP;
        proto tcp dport 2222 SET add-set $DYNBAN src timeout 3600;
        proto tcp dport 2223 SET add-set $DYNBAN src exist;
        proto tcp dport 2224 SET del-set $DYNBAN src;
        proto tcp mod tcpmss mss 1400:1500 ACCEPT;
        proto tcp mod tcpmss ! mss 536 ACCEPT;
        proto tcp tcp-option 8 ACCEPT;
        proto tcp tcp-option !19 ACCEPT;
        proto tcp tcp-option 254 mss 536 DROP;
    }
    chain connlimit-ish {
        proto tcp dport 443 mod connlimit connlimit-above 20
            connlimit-mask 24 DROP;
        proto tcp dport 80 mod connlimit connlimit-above 20
            connlimit-mask 24 DROP;
        mod connlimit connlimit-upto 5 DROP;
        mod connlimit connlimit-above 10 connlimit-mask 24
            connlimit-daddr DROP;
    }
    chain mark-arith-ish {
        MARK set-xmark 0x1/0xff;
        MARK set-mark 0xff/0x0f;
        MARK or-mark 0x4;
        MARK and-mark 0xf0;
        MARK xor-mark 0x8;
        CONNMARK set-xmark 0x2/0xff;
        CONNMARK or-mark 0x10;
        CONNMARK and-mark 0xf0;
        CONNMARK xor-mark 0x8;
    }
}
domain ip table nat {
    chain PREROUTING {
        daddr 10.66.0.0/24 NETMAP to 192.0.2.0/24;
        proto tcp dport 8080 DNAT to-destination 192.0.2.2 random persistent;
        proto tcp dport 8081 REDIRECT to-ports 8082 random;
    }
    chain POSTROUTING {
        saddr 192.0.2.0/24 NETMAP to 10.66.0.0/24;
        source 10.0.0.0/8 SNAT to-source 192.0.2.1 random;
        out-interface eth9 MASQUERADE random-fully;
        out-interface eth8 MASQUERADE random random-fully;
    }
}
domain ip table raw chain PREROUTING {
    proto udp dport 53 NOTRACK;
    proto tcp dport 53 CT notrack;
}
domain ip table mangle chain PREROUTING {
    proto tcp dport 3129 TPROXY on-port 3129 tproxy-mark "0x1/0x1";
    proto tcp dport 3130 TPROXY on-port 3130 on-ip 127.0.0.1;
}
domain arp table filter chain INPUT {
    opcode 1 ACCEPT;
    opcode 2 source-mac aa:bb:cc:dd:ee:ff DROP;
}
domain ip6 {
    table filter chain INPUT {
        proto ipv6-icmp icmp-type $ICMP_V6 ACCEPT;
        mod addrtype dst-type LOCAL ACCEPT;
        mod dscp dscp-class af21 ACCEPT;
        mod hl hl-gt 254 ACCEPT;
        mod hl hl-lt 1 DROP;
        mod conntrack ctstate DNAT ACCEPT;
        mod recent rcheck seconds 300 hitcount 8 name SSHV6 rdest DROP;
        mod recent set name SSHV6 rdest NOP;
        proto tcp mod hashlimit hashlimit-upto 3/minute hashlimit-name hl_v6
            hashlimit-mode srcip hashlimit-srcmask 64 ACCEPT;
        mod connbytes connbytes "1024:" connbytes-dir reply
            connbytes-mode bytes ACCEPT;
        proto tcp dport 22 mod connlimit connlimit-above 5
            connlimit-mask 64 DROP;
    }
    table mangle chain PREROUTING {
        HL hl-set 255;
        proto tcp dport 3129 TPROXY on-port 3129 tproxy-mark "0x1/0x1";
        proto tcp dport 3131 TPROXY on-port 3131 on-ip fe80::1;
    }
}
"""

pytestmark = pytest.mark.skipif(
    not _live_nft_usable(), reason="needs unshare -rn plus nft"
)


@pytest.fixture(scope="module")
def vocabulary_config(tmp_path_factory: pytest.TempPathFactory) -> Path:
    config = tmp_path_factory.mktemp("nftvocab") / "vocabulary.ferm"
    config.write_text(_VOCABULARY, encoding="utf-8")
    return config


def test_vocabulary_translates_and_live_nft_accepts(
    vocabulary_config: Path,
) -> None:
    proc = subprocess.run(  # fixed argv, no shell
        [
            sys.executable,
            "-m",
            "pyferm",
            "--nft",
            "--test",
            "--noexec",
            "--lines",
            str(vocabulary_config),
        ],
        capture_output=True,
        encoding="utf-8",
        check=False,
        env=_ENV,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    script = "".join(
        line
        for line in proc.stdout.splitlines(keepends=True)
        if _NFT_LINE.match(line)
    )
    assert script, "empty nft ruleset"
    check = subprocess.run(
        ["unshare", "-rn", "nft", "-c", "-f", "-"],
        input=script,
        capture_output=True,
        encoding="utf-8",
        check=False,
        timeout=60,
    )
    assert check.returncode == 0, f"live nft -c rejected:\n{check.stderr}"


def test_vocabulary_plan_converges_after_apply(
    vocabulary_config: Path,
) -> None:
    # Apply and re-plan inside ONE namespace: pyferm must run under the
    # unshare itself so --plan reads the namespace's live ruleset.
    python = shlex.quote(sys.executable)
    config = shlex.quote(str(vocabulary_config))
    inner = (
        f"{python} -m pyferm --nft {config} >/dev/null 2>&1; "
        f"exec {python} -m pyferm --nft --plan {config}"
    )
    proc = subprocess.run(
        ["unshare", "-rn", "sh", "-c", inner],
        capture_output=True,
        encoding="utf-8",
        check=False,
        env=_ENV,
        cwd=REPO_ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, (
        f"--plan did not converge:\n{proc.stdout}\n{proc.stderr}"
    )
    assert "No changes." in proc.stdout, proc.stdout


def test_time_plan_converges_under_foreign_tz(
    vocabulary_config: Path,
) -> None:
    # meta hour/meta time literals are TZ-converted by nft on both parse and
    # print, so a non-UTC parent TZ would leave --plan diffing an applied
    # `meta hour` forever unless every nft subprocess is pinned to UTC
    # (cli._nft_env).  Running the whole apply+plan under TZ=Europe/Berlin
    # proves the pin holds: convergence here is exactly the pin working.
    python = shlex.quote(sys.executable)
    config = shlex.quote(str(vocabulary_config))
    inner = (
        f"{python} -m pyferm --nft {config} >/dev/null 2>&1; "
        f"exec {python} -m pyferm --nft --plan {config}"
    )
    proc = subprocess.run(
        ["unshare", "-rn", "sh", "-c", inner],
        capture_output=True,
        encoding="utf-8",
        check=False,
        env={**_ENV, "TZ": "Europe/Berlin"},
        cwd=REPO_ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, (
        f"--plan did not converge under TZ=Europe/Berlin:\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
    assert "No changes." in proc.stdout, proc.stdout


def test_stateful_plan_converges_with_populated_set(
    vocabulary_config: Path,
) -> None:
    # A dynamic set is empty right after apply, so a bare apply+--plan would be
    # falsely green: it never exercises the plan.py guard that excludes a
    # dynamic set's kernel-accrued elements from the diff.  Populate one set
    # (an injected element stands in for a matched packet's `update @set`) and
    # only then re-plan: the desired side still declares no elements, so
    # convergence proves the guard, not an empty coincidence.
    python = shlex.quote(sys.executable)
    config = shlex.quote(str(vocabulary_config))
    # The connlimit set name is a content hash unknown at test-write time,
    # so it is discovered from the applied ruleset before an element (a
    # matched packet's `add @set`) is injected -- the same guard exercise as
    # recent/hashlimit, over a set whose stateful expression is `ct count`.
    inner = (
        f"{python} -m pyferm --nft {config} >/dev/null 2>&1; "
        "nft add element ip ferm recent_SSHV4 "
        "'{ 203.0.113.7 timeout 1m }' >/dev/null 2>&1; "
        "nft add element ip ferm hashlimit_hl_upto "
        "'{ 203.0.113.8 timeout 1m }' >/dev/null 2>&1; "
        "CL=$(nft list sets ip ferm | "
        "grep -o 'connlimit_[0-9a-f]*' | head -1); "
        '[ -n "$CL" ] && nft add element ip ferm "$CL" '
        "'{ 203.0.113.9 ct count over 20 }' >/dev/null 2>&1; "
        f"exec {python} -m pyferm --nft --plan {config}"
    )
    proc = subprocess.run(
        ["unshare", "-rn", "sh", "-c", inner],
        capture_output=True,
        encoding="utf-8",
        check=False,
        env=_ENV,
        cwd=REPO_ROOT,
        timeout=120,
    )
    assert proc.returncode == 0, (
        f"--plan did not converge over a populated set:\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
    assert "No changes." in proc.stdout, proc.stdout
