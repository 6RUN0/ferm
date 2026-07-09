"""Live-nft validation of the backend's translated vocabulary.

The unit layer pins the emitted *text*; this suite pins that the text is
*real nft* and that an applied ruleset converges under ``--plan`` (the
2026-07-09 ad-hoc netns probes, formalized).  Two halves:

* ``nft -c`` must accept a config exercising every translated construct
  (the full icmp/icmpv6 type maps, numeric respell, multiport sets,
  limit units and burst, log level/NFLOG shapes, mark, dashed chains,
  addrtype fib types with RTN-ordered lists and limit-iface qualifiers,
  the dscp name canon, DSCP/CLASSIFY targets with tc-handle respell);
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
    chain qos-ish {
        DSCP set-dscp-class af31;
        DSCP set-dscp 0x01;
        CLASSIFY set-class 0001:0020;
        CLASSIFY set-class ffff:ffff;
    }
}
domain arp table filter chain INPUT {
    opcode 1 ACCEPT;
    opcode 2 source-mac aa:bb:cc:dd:ee:ff DROP;
}
domain ip6 table filter chain INPUT {
    proto ipv6-icmp icmp-type $ICMP_V6 ACCEPT;
    mod addrtype dst-type LOCAL ACCEPT;
    mod dscp dscp-class af21 ACCEPT;
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
