"""
Kernel-readback canon pin for the nft QoS/addrtype vocabulary -- runs
INSIDE the container.

The nft backend must emit the exact spelling ``nft list ruleset`` prints
back, or ``--plan``/delta-apply show a phantom diff forever.  The tables
this driver pins were captured live (nft v1.1.6, 2026-07-09) while
designing the match-set/addrtype/QoS slice; the containerized nft
(v1.1.3, alpine) was verified byte-identical before pinning.  If a base
image bump makes this driver fail, the emission maps in the backend must
be re-captured against the new nft, not the test relaxed.

The checks:

1. ``fib ... type`` accepts exactly the nine RTN names the backend will
   translate and rejects ``throw``/``nat``/``xresolve``;
2. a type-list readback is re-sorted into kernel RTN order -- including
   the negated-list form, which the kernel accepts;
3. ``fib daddr . iif type local`` and the negations spell back verbatim
   in both ip and ip6; the ``. iif`` qualifier composes with plain and
   negated lists; ``. oif`` works in an output hook and spells back
   verbatim, but in an input hook the kernel refuses it at COMMIT time
   while ``nft -c`` still passes -- a pre-check cannot catch it;
4. the dscp value->name readback map over all 64 codepoints, identical
   for the match and ``set`` forms and for ip and ip6 (includes the
   ``lephb``/``va`` names absent from the iptables class table);
5. ``meta priority`` (CLASSIFY) readback strips leading zeros and
   renders the tc-special handles ``ffff:ffff`` -> ``root`` and ``0:0``
   -> ``none``; a 5-hex-digit half is rejected;
6. the 2026-07-10 vocabulary batch: ct state/status lists re-sort into
   bit order and negate via the masked bang form (``ct status !
   snat,dnat``; the ``!=`` spelling is a whole-register compare); NFQUEUE
   reads back as ``queue [flags ...] to N``; synproxy prints its parts
   in mss/wscale/timestamp/sack-perm order with mss and wscale as a pair
   whenever either is given; a partial-mask mark prints 8-digit hex on
   both operands; NETMAP's prefix-to-prefix NAT map and ``ip ttl set``/
   ``ip6 hoplimit set`` spell back verbatim.

Prints ``NFT-READBACK-PASS`` only after every check has passed.  Stdlib
only: it runs under the container's system ``python3`` and imports
nothing from the test deps.
"""

# This driver is bind-mounted into the container per file, so the shared
# tests/ helpers are unreachable here: it stays self-contained (stdlib-only)
# and its overlap with the sibling drivers is intentional, not to be hoisted.
from __future__ import annotations

import re
import subprocess
import sys

#: RTN route types nft's fib expression accepts, in kernel RTN order
#: (RTN_UNSPEC=0 ... RTN_PROHIBIT=8); list readback re-sorts into this
#: order, so the backend must emit literals pre-sorted the same way.
FIB_ACCEPTED = [
    "unspec",
    "unicast",
    "local",
    "broadcast",
    "anycast",
    "multicast",
    "blackhole",
    "unreachable",
    "prohibit",
]

#: iptables addrtype values with no fib equivalent -- the backend
#: refuses them, and nft itself must keep rejecting them.
FIB_REJECTED = ["throw", "nat", "xresolve"]

#: dscp codepoints nft prints by name; every other value reads back as
#: 0x%02x hex.  Note lephb (0x01) and va (0x2c): nft knows them, the
#: iptables --dscp-class table does not.
DSCP_NAMES = {
    0x00: "cs0",
    0x01: "lephb",
    0x08: "cs1",
    0x0A: "af11",
    0x0C: "af12",
    0x0E: "af13",
    0x10: "cs2",
    0x12: "af21",
    0x14: "af22",
    0x16: "af23",
    0x18: "cs3",
    0x1A: "af31",
    0x1C: "af32",
    0x1E: "af33",
    0x20: "cs4",
    0x22: "af41",
    0x24: "af42",
    0x26: "af43",
    0x28: "cs5",
    0x2C: "va",
    0x2E: "ef",
    0x30: "cs6",
    0x38: "cs7",
}


def _sh(
    *cmd: str, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def _fail(label: str, detail: str) -> None:
    print(f"FAIL: {label}\n{detail}")
    sys.exit(1)


def _load_and_list(script: str) -> str:
    """Replace the ruleset with *script* and return its kernel readback."""
    _sh("nft", "flush", "ruleset")
    load = _sh("nft", "-f", "-", input_text=script)
    if load.returncode != 0:
        _fail("nft -f rejected the fixture script", load.stderr)
    return _sh("nft", "list", "ruleset").stdout


def _rule_lines(readback: str) -> list[str]:
    return [line.strip() for line in readback.splitlines()]


def check_fib_type_acceptance() -> None:
    for rtn_type in FIB_ACCEPTED + FIB_REJECTED:
        script = (
            "table ip t {\n chain c {\n"
            " type filter hook input priority 0;\n"
            f" fib daddr type {rtn_type} drop\n }}\n}}\n"
        )
        result = _sh("nft", "-c", "-f", "-", input_text=script)
        accepted = result.returncode == 0
        if rtn_type in FIB_ACCEPTED and not accepted:
            _fail(f"fib type {rtn_type} should be accepted", result.stderr)
        if rtn_type in FIB_REJECTED and accepted:
            _fail(f"fib type {rtn_type} should be rejected", "accepted")


def check_fib_readback() -> None:
    # nft accepts a newline after a set-literal comma, so the scrambled
    # input list stays under the line limit without changing semantics.
    script = """\
table ip t {
  chain c {
    type filter hook input priority 0;
    fib daddr type { broadcast, multicast,
      unspec, prohibit, blackhole, local } drop
    fib saddr type != { broadcast, local, unspec } drop
    fib daddr . iif type local drop
    fib daddr . iif type { broadcast, local } drop
    fib daddr . iif type != { broadcast, local, unspec } drop
    fib saddr type != local drop
  }
  chain co {
    type filter hook output priority 0;
    fib saddr . oif type local drop
  }
}
table ip6 t6 {
  chain c {
    type filter hook input priority 0;
    fib daddr type local drop
    fib daddr . iif type local drop
    fib saddr type != { broadcast, local } drop
  }
}
"""
    expected = [
        # Input order above is scrambled on purpose: the kernel re-sorts
        # into RTN order, negated lists included.
        "fib daddr type { unspec, local, broadcast, multicast,"
        " blackhole, prohibit } drop",
        "fib saddr type != { unspec, local, broadcast } drop",
        "fib daddr . iif type local drop",
        "fib daddr . iif type { local, broadcast } drop",
        "fib daddr . iif type != { unspec, local, broadcast } drop",
        "fib saddr . oif type local drop",
        "fib saddr type != local drop",
        "fib saddr type != { local, broadcast } drop",
    ]
    lines = _rule_lines(_load_and_list(script))
    for want in expected:
        if want not in lines:
            _fail(f"fib readback line missing: {want}", "\n".join(lines))


def check_fib_oif_hook_constraint() -> None:
    # fib oif needs a hook with an output interface (parity with
    # iptables, where --limit-iface-out is likewise restricted to
    # output-side chains): committing it in an input hook must fail.
    # Whether ``nft -c`` catches it first is VERSION-DEPENDENT -- 1.1.3
    # rejects at -c, 1.1.6 passes -c and fails only at commit -- so only
    # the commit failure is pinned and a pre-check pipeline must not be
    # trusted to catch the mistake.
    script = (
        "table ip t {\n chain c {\n"
        " type filter hook input priority 0;\n"
        " fib saddr . oif type local drop\n }\n}\n"
    )
    _sh("nft", "flush", "ruleset")
    load = _sh("nft", "-f", "-", input_text=script)
    if load.returncode == 0:
        _fail("fib oif in input hook should fail at commit", "accepted")


def check_dscp_map() -> None:
    for family, selector in (("ip", "ip"), ("ip6", "ip6")):
        for form in ("", "set "):
            rules = "\n".join(
                f"    {selector} dscp {form}0x{value:02x} accept"
                for value in range(64)
            )
            script = f"table {family} t {{\n  chain c {{\n{rules}\n  }}\n}}\n"
            readback = _load_and_list(script)
            got = re.findall(rf"{selector} dscp {form}(\S+) accept", readback)
            want = [
                DSCP_NAMES.get(value, f"0x{value:02x}") for value in range(64)
            ]
            if got != want:
                # strict=False on purpose: a truncated readback should
                # still report the per-value diff, not a ValueError.
                diff = [
                    f"0x{value:02x}: want {w} got {g}"
                    for value, (w, g) in enumerate(
                        zip(want, got, strict=False)
                    )
                    if w != g
                ]
                _fail(
                    f"dscp {form.strip() or 'match'} map diverged ({family})",
                    "\n".join(diff) or readback,
                )


def check_classify_readback() -> None:
    script = """\
table ip t {
  chain c {
    meta priority set 0001:0020 accept
    meta priority set abcd:ffff accept
    meta priority set ffff:ffff accept
    meta priority set 0:0 accept
    meta priority set 00ff:0abc accept
  }
}
"""
    expected = [
        "meta priority set 1:20 accept",
        "meta priority set abcd:ffff accept",
        "meta priority set root accept",
        "meta priority set none accept",
        "meta priority set ff:abc accept",
    ]
    lines = _rule_lines(_load_and_list(script))
    for want in expected:
        if want not in lines:
            _fail(f"classify readback line missing: {want}", "\n".join(lines))

    bad = _sh(
        "nft",
        "-c",
        "-f",
        "-",
        input_text=(
            "table ip t {\n chain c {\n"
            " meta priority set abcde:1 accept\n }\n}\n"
        ),
    )
    if bad.returncode == 0:
        _fail("5-hex-digit tc handle should be rejected", "accepted")


def check_ct_queue_netmap_readback() -> None:
    # Input spellings are scrambled on purpose (list order, flag order,
    # `queue num`, unpadded hex) to pin the kernel's canonical respell.
    script = """\
table ip t {
  chain c {
    type filter hook input priority 0;
    ct state related,established accept
    ct state ! established,related drop
    ct state != invalid accept
    ct status dnat,snat accept
    ct status ! dnat drop
    ct status ! snat,dnat drop
    ct status expected,confirmed,assured,seen-reply accept
    queue num 65535
    queue num 0-3 bypass,fanout
    queue num 1 bypass
    tcp dport 80 synproxy sack-perm timestamp wscale 7 mss 1460
    tcp dport 81 synproxy mss 1460
    tcp dport 82 synproxy sack-perm
    meta mark & 0x3 != 0x1 accept
    ct mark & 0x80000000 == 0x80000000 drop
    ip ttl set 42
  }
  chain pre {
    type nat hook prerouting priority -100;
    ip daddr 10.66.0.0/24 dnat ip prefix to ip daddr map \\
      { 10.66.0.0/24 : 192.0.2.0/24 }
  }
}
table ip6 t6 {
  chain c {
    type filter hook input priority 0;
    ip6 hoplimit set 255
    ip6 hoplimit > 254 accept
  }
}
"""
    expected = [
        "ct state established,related accept",
        "ct state ! established,related drop",
        "ct state != invalid accept",
        "ct status snat,dnat accept",
        "ct status ! dnat drop",
        "ct status ! snat,dnat drop",
        "ct status expected,seen-reply,assured,confirmed accept",
        "queue to 65535",
        "queue flags bypass,fanout to 0-3",
        "queue flags bypass to 1",
        "tcp dport 80 synproxy mss 1460 wscale 7 timestamp sack-perm",
        "tcp dport 81 synproxy mss 1460 wscale 0",
        "tcp dport 82 synproxy sack-perm",
        "meta mark & 0x00000003 != 0x00000001 accept",
        "ct mark & 0x80000000 == 0x80000000 drop",
        "ip ttl set 42",
        "ip daddr 10.66.0.0/24 dnat ip prefix to ip daddr map"
        " { 10.66.0.0/24 : 192.0.2.0/24 }",
        "ip6 hoplimit set 255",
        "ip6 hoplimit > 254 accept",
    ]
    lines = _rule_lines(_load_and_list(script))
    for want in expected:
        if want not in lines:
            _fail(
                f"ct/queue/netmap readback line missing: {want}",
                "\n".join(lines),
            )


def check_stateful_dynset_readback() -> None:
    # The recent/hashlimit slice emits implicit dynamic sets.  Pin, on a real
    # apply+relist, that the emitted declaration and update-element forms are
    # exactly what the kernel prints back -- otherwise --plan/delta-apply see a
    # phantom diff forever and the delta wipes the accrued stateful state.
    # Built by concatenation so each nft statement stays one logical line
    # while the source lines fit the 79-column limit.
    script = (
        "table ip t {\n"
        "  set recent_SSH { type ipv4_addr; size 65535;"
        " flags dynamic,timeout; }\n"
        "  set hl_conc { type ipv4_addr . inet_service; size 65535;"
        " flags dynamic,timeout; }\n"
        "  set hl_persec { type ipv4_addr; size 65535; flags dynamic; }\n"
        "  chain c {\n"
        "    type filter hook input priority 0;\n"
        "    update @recent_SSH { ip saddr timeout 1m limit rate over"
        " 8/minute burst 7 packets } drop\n"
        "    update @hl_conc { ip saddr & 255.255.255.0 . tcp dport timeout"
        " 1m30s limit rate over 10/second burst 5 packets } drop\n"
        "    meta l4proto tcp update @hl_persec { ip saddr limit rate"
        " 5/second burst 5 packets } accept\n"
        "  }\n"
        "}\n"
    )
    lines = _rule_lines(_load_and_list(script))
    expected = [
        # declaration flag spelling (comma, no space) and size injection
        "flags dynamic,timeout",
        "flags dynamic",
        "size 65535",
        "type ipv4_addr . inet_service",
        # element order: key, timeout, limit; burst injected; time canon
        "update @recent_SSH { ip saddr timeout 1m limit rate over 8/minute"
        " burst 7 packets } drop",
        "update @hl_conc { ip saddr & 255.255.255.0 . tcp dport timeout"
        " 1m30s limit rate over 10/second burst 5 packets } drop",
        # a /second element carries no timeout; the update form is stable
        # (never respelled into a legacy `meter`) after apply+relist
        "meta l4proto tcp update @hl_persec { ip saddr limit rate 5/second"
        " burst 5 packets } accept",
    ]
    for want in expected:
        if want not in lines:
            _fail(
                f"stateful dynset readback line missing: {want}",
                "\n".join(lines),
            )
    if any("meter" in line for line in lines):
        _fail("update form respelled into a legacy meter", "\n".join(lines))


#: Batch-9 vocabulary lines: the emitter's exact output, which must read
#: back verbatim (a respelled token = --plan/delta phantom diff forever).
#: Captured from nft v1.1.6; re-capture on an nft bump, do not hand-edit.
BATCH9_IP_LINES = [
    "meta cpu 0 accept",
    "iifgroup 5 accept",
    "oifgroup != 16 accept",
    "meta rtclassid 42 accept",
    "meta cgroup 1048577 accept",
    "socket wildcard 0 socket transparent 1 accept",
    "socket wildcard <= 1 accept",
    "ct original ip saddr 192.0.2.1 accept",
    "ct original proto-src 80-90 accept",
    "ct protocol tcp accept",
    "ct expiration 1m40s accept",
    "ct expiration 0s accept",
    "ct expiration 3600s-7200s accept",
    "ct direction original accept",
    "ct label 40 accept",
    "ct label & 7 != 7 drop",
    "ah spi 1-1000 accept",
    "esp spi 500 accept",
    "dccp type { request, response } drop",
    "dccp type != { reset, sync } accept",
    "meta ipsec exists accept",
    "meta ipsec missing drop",
    "fib saddr . iif oif != 0 accept",
    "fib saddr . mark oif 0 drop",
    "ip option lsrr exists drop",
    "ip option ra missing accept",
    "ip ecn not-ect accept",
    "tcp flags cwr accept",
    "log level audit",
]

BATCH9_IP6_LINES = [
    "meta l4proto mobility-header mh type binding-update accept",
    "meta l4proto mobility-header mh type != careof-test-init drop",
    "mh type 2-4 accept",
    "hbh hdrlength 8 accept",
    "dst hdrlength 8 accept",
    "rt type 0 rt seg-left 1 accept",
    "exthdr frag exists exthdr mh exists accept",
    "ct reply ip6 saddr 2001:db8::1 accept",
    "ip6 ecn ect0 accept",
]


def check_batch9_vocab_readback() -> None:
    # Apply every batch-9 emission and require the identical line back:
    # this is the whole batch's --plan convergence contract in one pass.
    body_ip = "\n".join(f" {line}" for line in BATCH9_IP_LINES)
    body_ip6 = "\n".join(f" {line}" for line in BATCH9_IP6_LINES)
    script = (
        "table ip t {\n chain c {\n"
        " type filter hook input priority 0;\n"
        f"{body_ip}\n }}\n}}\n"
        "table ip6 t6 {\n chain c {\n"
        " type filter hook input priority 0;\n"
        f"{body_ip6}\n }}\n}}\n"
    )
    lines = _rule_lines(_load_and_list(script))
    for want in BATCH9_IP_LINES + BATCH9_IP6_LINES:
        if want not in lines:
            _fail(
                f"batch-9 vocab readback line missing: {want}",
                "\n".join(lines),
            )


BATCH10_IP_LINES = [
    'ct helper "ftp" accept',
    "numgen inc mod 4 0 accept",
    "numgen inc mod 8 3 accept",
    "notrack",
    "ct event set new,related,destroy",
    "ct zone set 5",
    "ct original zone set 5",
    "ct reply zone set 7",
    "notrack ct zone set 1 ct event set new,destroy",
]


def check_batch10_vocab_readback() -> None:
    # Apply every batch-10 emission (helper match, nth numgen, CT event/zone
    # mangle) and require the identical line back -- the --plan convergence
    # contract, including the ctevents canonical reorder and the fixed
    # multi-statement CT order.
    body = "\n".join(f" {line}" for line in BATCH10_IP_LINES)
    script = (
        "table ip t {\n chain c {\n"
        " type filter hook input priority 0;\n"
        f"{body}\n }}\n}}\n"
    )
    lines = _rule_lines(_load_and_list(script))
    for want in BATCH10_IP_LINES:
        if want not in lines:
            _fail(
                f"batch-10 vocab readback line missing: {want}",
                "\n".join(lines),
            )


BATCH11A_IP_LINES = [
    "ct secmark set meta secmark",
    "meta secmark set ct secmark",
    (
        "meta mark set jhash ip saddr . ip daddr . th sport . th dport . "
        "meta l4proto mod 10 seed 0xabc offset 100"
    ),
    "meta mark set jhash ip saddr . ip daddr mod 8 seed 0xabc",
]

BATCH11A_IP6_LINES = [
    "meta mark set jhash ip6 saddr . ip6 daddr mod 8 seed 0xabc",
]


def check_batch11a_vocab_readback() -> None:
    # CONNSECMARK secmark moves and HMARK jhash mangles in a prerouting hook;
    # require each emission back verbatim (the --plan convergence contract,
    # including the seed 0x-hex canon and the dropped `offset 0`).
    body_ip = "\n".join(f" {line}" for line in BATCH11A_IP_LINES)
    body_ip6 = "\n".join(f" {line}" for line in BATCH11A_IP6_LINES)
    script = (
        "table ip t {\n chain c {\n"
        " type filter hook prerouting priority -150;\n"
        f"{body_ip}\n }}\n}}\n"
        "table ip6 t6 {\n chain c {\n"
        " type filter hook prerouting priority -150;\n"
        f"{body_ip6}\n }}\n}}\n"
    )
    lines = _rule_lines(_load_and_list(script))
    for want in BATCH11A_IP_LINES + BATCH11A_IP6_LINES:
        if want not in lines:
            _fail(
                f"batch-11a vocab readback line missing: {want}",
                "\n".join(lines),
            )


#: SECMARK's content-hash object name for the ssh context (batch 11b); the
#: hash is family-independent, so ip and ip6 reuse the same name.
BATCH11B_CONTEXT = "system_u:object_r:ssh_port_t:s0"
BATCH11B_OBJECT = "secmark_46e9b254fd6f"


def check_batch11b_vocab_readback() -> None:
    # A SECMARK table object plus the rule that references it; require the
    # object block AND the `meta secmark set` rule back verbatim (the --plan
    # convergence contract for a content-addressed table object).
    script = (
        "table ip t {\n"
        f' secmark {BATCH11B_OBJECT} {{ "{BATCH11B_CONTEXT}" }}\n'
        " chain c {\n"
        " type route hook output priority -150;\n"
        f' meta secmark set "{BATCH11B_OBJECT}"\n'
        " }\n}\n"
    )
    lines = _rule_lines(_load_and_list(script))
    for want in (
        f"secmark {BATCH11B_OBJECT} {{",
        f'"{BATCH11B_CONTEXT}"',
        f'meta secmark set "{BATCH11B_OBJECT}"',
    ):
        if want not in lines:
            _fail(
                f"batch-11b secmark readback line missing: {want}",
                "\n".join(lines),
            )


def check_batch11b_cthelper_readback() -> None:
    # A ct-helper table object plus the rule that references it.  The kernel
    # augments the readback body with `l3proto ip` (absent from the save form);
    # require the object block, that augmentation, AND the `ct helper set` rule
    # back verbatim -- content-addressed name-only diffing must converge in
    # spite of the body asymmetry (the --plan contract for a ct-helper object).
    script = (
        "table ip t {\n"
        ' ct helper cthelper_ftp { type "ftp" protocol tcp; }\n'
        " chain c {\n"
        " type filter hook prerouting priority -300;\n"
        ' tcp dport 21 ct helper set "cthelper_ftp"\n'
        " }\n}\n"
    )
    lines = _rule_lines(_load_and_list(script))
    for want in (
        "ct helper cthelper_ftp {",
        'type "ftp" protocol tcp',
        "l3proto ip",
        'tcp dport 21 ct helper set "cthelper_ftp"',
    ):
        if want not in lines:
            _fail(
                f"batch-11b ct-helper readback line missing: {want}",
                "\n".join(lines),
            )


def main() -> None:
    version = _sh("nft", "--version").stdout.strip()
    print(f"driver nft: {version}")
    check_fib_type_acceptance()
    check_fib_readback()
    check_fib_oif_hook_constraint()
    check_dscp_map()
    check_classify_readback()
    check_ct_queue_netmap_readback()
    check_stateful_dynset_readback()
    check_batch9_vocab_readback()
    check_batch10_vocab_readback()
    check_batch11a_vocab_readback()
    check_batch11b_vocab_readback()
    check_batch11b_cthelper_readback()
    print("NFT-READBACK-PASS")


if __name__ == "__main__":
    main()
