"""
Datapath e2e scenarios (the data the driver iterates).

Each scenario is a literal, valid ferm config plus the probes that
assert its data-plane behaviour.  Interface/address names match the
topology in ``netns.py``:

    client ─(v_cl_fw/v_fw_cl)─ fw ─(v_fw_be/v_be_fw)─ backend
     .2                        .1  .1                  .2
     10.0.0.0/24 fd00:0::/64       10.0.1.0/24 fd00:1::/64

Chain-policy rules baked into every config (omitting them is a silent
false-negative):
  * INPUT policy is per-scenario (usually DROP);
  * OUTPUT is ``policy ACCEPT`` so listener replies, RSTs, UDP echoes and
    pre-establish SYNs from fw are not cut;
  * v6 configs MUST accept inbound ICMPv6 -- Neighbor Discovery traverses
    the nft input hook (unlike v4 ARP at L2), so policy DROP without it
    makes nmap see the host down and the v6 probe returns empty;
  * the NAT config carries a FORWARD chain passing the DNAT flow (the
    DNAT packet goes through FORWARD, not INPUT).
"""

from __future__ import annotations

from oracle import Probe

# --- core v4: ACCEPT/REJECT-reset/REJECT-default/DROP over tcp+udp ---
_CORE_V4 = """\
domain ip table filter {
    chain INPUT {
        policy DROP;
        proto tcp dport 22 ACCEPT;
        proto tcp dport 23 REJECT reject-with tcp-reset;
        proto tcp dport 24 REJECT;
        proto tcp dport 80 DROP;
        proto udp dport 53 ACCEPT;
        proto udp dport 54 REJECT;
        proto udp dport 55 DROP;
    }
    chain OUTPUT { policy ACCEPT; }
}
"""

# --- core v6: same verdicts, plus mandatory ICMPv6 (ND) accept ---
_CORE_V6 = """\
domain ip6 table filter {
    chain INPUT {
        policy DROP;
        proto ipv6-icmp ACCEPT;
        proto tcp dport 22 ACCEPT;
        proto tcp dport 23 REJECT reject-with tcp-reset;
        proto tcp dport 24 REJECT;
        proto tcp dport 80 DROP;
        proto udp dport 53 ACCEPT;
        proto udp dport 54 REJECT;
        proto udp dport 55 DROP;
    }
    chain OUTPUT { policy ACCEPT; }
}
"""

# --- rule order: first match wins; ACCEPT before DROP on the same port ---
_ORDER_V4 = """\
domain ip table filter {
    chain INPUT {
        policy DROP;
        proto tcp dport 22 ACCEPT;
        proto tcp dport 22 DROP;
    }
    chain OUTPUT { policy ACCEPT; }
}
"""

# --- rule order, mirror: DROP before ACCEPT -> the DROP wins (no-response).
# The pair makes order discriminating in BOTH directions: a backend that
# reordered or dropped the second rule fails one of the two.
_ORDER_REV_V4 = """\
domain ip table filter {
    chain INPUT {
        policy DROP;
        proto tcp dport 22 DROP;
        proto tcp dport 22 ACCEPT;
    }
    chain OUTPUT { policy ACCEPT; }
}
"""

# --- state/conntrack: established return accepted, fresh inbound NEW cut ---
_STATE_V4 = """\
domain ip table filter {
    chain INPUT {
        policy DROP;
        mod state state (ESTABLISHED RELATED) ACCEPT;
        mod state state NEW DROP;
    }
    chain OUTPUT { policy ACCEPT; }
}
"""

# --- NAT: DNAT fw:8080 -> backend:80, masquerade on egress to backend ---
_NAT_V4 = """\
domain ip {
    table nat {
        chain PREROUTING {
            proto tcp dport 8080 DNAT to 10.0.1.2:80;
        }
        chain POSTROUTING {
            outerface v_fw_be MASQUERADE;
        }
    }
    table filter {
        chain INPUT { policy DROP; }
        chain FORWARD {
            policy DROP;
            mod state state (ESTABLISHED RELATED) ACCEPT;
            proto tcp dport 80 ACCEPT;
        }
        chain OUTPUT { policy ACCEPT; }
    }
}
"""

_BOTH = ["nft", "iptables"]

SCENARIOS: list[dict] = [
    {
        "type": "probe",
        "name": "core-v4",
        "config": _CORE_V4,
        "backends": _BOTH,
        "probes": [
            Probe("tcp", "client", "10.0.0.1", 22, 4, "syn-ack", 1),
            Probe("tcp", "client", "10.0.0.1", 23, 4, "reset", 1),
            Probe("tcp", "client", "10.0.0.1", 24, 4, "port-unreach", 1),
            Probe("tcp", "client", "10.0.0.1", 80, 4, "no-response", 1),
            Probe("udp", "client", "10.0.0.1", 53, 4, "udp-response", 2),
            Probe("udp", "client", "10.0.0.1", 54, 4, "port-unreach", 1),
            Probe("udp", "client", "10.0.0.1", 55, 4, "no-response", 1),
        ],
    },
    {
        "type": "probe",
        "name": "core-v6",
        "config": _CORE_V6,
        "backends": _BOTH,
        "probes": [
            Probe("tcp", "client", "fd00:0::1", 22, 6, "syn-ack", 1),
            Probe("tcp", "client", "fd00:0::1", 23, 6, "reset", 1),
            Probe("tcp", "client", "fd00:0::1", 24, 6, "port-unreach", 1),
            Probe("tcp", "client", "fd00:0::1", 80, 6, "no-response", 1),
            Probe("udp", "client", "fd00:0::1", 53, 6, "udp-response", 2),
            Probe("udp", "client", "fd00:0::1", 54, 6, "port-unreach", 1),
            Probe("udp", "client", "fd00:0::1", 55, 6, "no-response", 1),
        ],
    },
    {
        "type": "probe",
        "name": "order-v4",
        "config": _ORDER_V4,
        "backends": _BOTH,
        "probes": [
            # ACCEPT precedes DROP on :22 -> first match wins -> syn-ack.
            Probe("tcp", "client", "10.0.0.1", 22, 4, "syn-ack", 1),
        ],
    },
    {
        "type": "probe",
        "name": "order-rev-v4",
        "config": _ORDER_REV_V4,
        "backends": _BOTH,
        "probes": [
            # DROP precedes ACCEPT on :22 -> first match wins -> no-response.
            # (A live listener sits on :22; only the DROP rule yields silence.)
            Probe("tcp", "client", "10.0.0.1", 22, 4, "no-response", 1),
        ],
    },
    {
        "type": "stateful",
        "name": "state-v4",
        "config": _STATE_V4,
        "backends": _BOTH,
        "established_check": {
            "from_netns": "fw",
            "to_addr": "10.0.1.2",
            "port": 9000,
            "timeout_s": 3,
        },
        "probes": [
            # Corroborator only -- a fresh inbound NEW to fw:9000 is cut.
            # NOTE: this `no-response` does NOT by itself prove the NEW-DROP
            # rule, since policy DROP (or simply no listener on fw:9000)
            # yields the same silence -- it is non-discriminating in
            # isolation.  The DISCRIMINATING proof of stateful behaviour is
            # `established_check` above (fw->backend echo succeeds only
            # because the ESTABLISHED return is accepted inbound under a
            # DROP policy).  Keep this probe as a sanity corroborator, not
            # the load-bearing state assertion.
            Probe("tcp", "client", "10.0.0.1", 9000, 4, "no-response", 1),
        ],
    },
    {
        "type": "probe",
        "name": "nat-v4",
        "config": _NAT_V4,
        "backends": _BOTH,
        "probes": [
            # Main: DNAT to backend:80 (listener up) -> backend SYN-ACK.
            Probe("tcp", "client", "10.0.0.1", 8080, 4, "syn-ack", 1),
        ],
        # Control: stop the backend listener, re-probe -> backend kernel
        # RSTs the DNAT'd packet -> ``reset``.  Proves the main syn-ack
        # came from backend through DNAT, not from fw itself.
        "control": {
            "stop_listener": "be-tcp80-v4",
            "probe": Probe("tcp", "client", "10.0.0.1", 8080, 4, "reset", 1),
        },
    },
]
