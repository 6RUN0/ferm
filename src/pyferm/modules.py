"""
Module-definition registry: the option-encoding DSL and the tables.

Faithful port of the ``add_*_def`` machinery and every module table from
``reference/src/ferm`` (``:96-448``).  ferm supports a netfilter module by
registering it with one ``add_proto_def`` / ``add_match_def`` /
``add_target_def`` call whose extra arguments are *encoded* keyword
strings.  The encoding (Perl comment ``:96-141``):

==================  =====================================================
``foo``             one argument (may be a ferm array); ``params`` = 1
``foo*0``           no arguments
``foo=s``           one scalar argument (no array)
``foo=c``           one argument, arrays joined comma-separated
``foo=sac``         several arguments, one letter code each
``u32=m``           an array rendered as repeated options in one rule
``foo&bar``         one argument parsed by the named function ``bar``
``!foo``            negatable, ``!`` written before the keyword
``foo!``            negatable, ``!`` written after the keyword
``to:=dest``        ``to`` aliases the already-declared ``dest`` keyword
==================  =====================================================

The registry is built at import (as Perl builds it at load time) into the
module-level :data:`PROTO_DEFS`, :data:`MATCH_DEFS`, :data:`TARGET_DEFS`
and :data:`SHORTCUTS`; construction is pure and deterministic.  This
module depends only on :mod:`pyferm.values` (for Perl truthiness) and
:mod:`pyferm.errors`, so it stays low in the dependency graph.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TypeAlias

from pyferm.errors import FermError
from pyferm.values import perl_true


@dataclass(frozen=True)
class ParamFunction:
    """
    A named option-argument parser (Perl coderef from ``&name``).

    ferm resolves ``&address_magic`` to a coderef at registration; to avoid
    a ``modules`` -> ``functions`` import cycle this records only the name.
    The consumer (the parser) maps it to the real callable at use time.
    """

    name: str


#: A keyword's ``params``: ``None`` (no argument), an ``int`` count
#: (default 1), a code string (``"s"``/``"c"``/``"m"`` and combinations),
#: or a :class:`ParamFunction`.  Mirrors the Perl ``$k->{params}`` values
#: dispatched on in ``parse_keyword`` (``:1946``).
KeywordParams: TypeAlias = "int | str | ParamFunction | None"


@dataclass
class Keyword:
    """
    One option of a module (Perl's per-keyword ``$k`` hash, ``:177``).

    ``name`` is the iptables option name; ``negation``/``pre_negation``
    mirror Perl's ``exists`` flags; ``ferm_name`` is set when an alias
    points at this keyword (read back by ``import-ferm``).  Aliases share
    the *same* :class:`Keyword` instance as their target, so a mutation of
    ``ferm_name`` is visible through every alias.
    """

    name: str
    params: KeywordParams
    negation: bool = False
    pre_negation: bool = False
    ferm_name: str | None = None


@dataclass
class ModuleDef:
    """One registered module (Perl's ``$def`` hash: ``{keywords => ...}``)."""

    keywords: dict[str, Keyword] = field(default_factory=dict)


#: A registry: ``domain_family -> module_name -> ModuleDef``.
Registry: TypeAlias = "dict[str, dict[str, ModuleDef]]"

_ALIAS_RE = re.compile(r":=(\S+)$")
_STAR_RE = re.compile(r"\*(\d+)$")
_EQ_RE = re.compile(r"=([acs]+|m)$")
_AMP_RE = re.compile(r"&(\S+)$")


def _add_def(
    defs: Registry,
    domain_family: str,
    params_default: KeywordParams,
    name: str,
    specs: tuple[str, ...],
) -> ModuleDef:
    """
    Register one module from its encoded keyword specs (Perl ``:154``).

    ``params_default`` is the family's default ``params`` (1 for protocol
    and match modules, ``"s"`` for target modules).  Returns the new
    :class:`ModuleDef`, mirroring Perl's ``return $def``.
    """
    family = defs.setdefault(domain_family, {})
    if name in family:
        raise FermError(f"module '{name}' already defined")
    module = ModuleDef()
    family[name] = module

    for spec in specs:
        keyword = spec

        alias = _ALIAS_RE.search(keyword)
        if alias is not None:
            keyword = keyword[: alias.start()]
            target = module.keywords.get(alias.group(1))
            if target is None:
                raise FermError(f"alias target '{alias.group(1)}' unknown")
            # ||=: only the first alias names the keyword.
            if not target.ferm_name:
                target.ferm_name = keyword
            module.keywords[keyword] = target
            continue

        params: KeywordParams = params_default
        star = _STAR_RE.search(keyword)
        if star is not None:
            params = star.group(1)
            keyword = keyword[: star.start()]
        eq = _EQ_RE.search(keyword)
        if eq is not None:
            params = eq.group(1)
            keyword = keyword[: eq.start()]
        amp = _AMP_RE.search(keyword)
        if amp is not None:
            params = ParamFunction(amp.group(1))
            keyword = keyword[: amp.start()]

        negation = False
        pre_negation = False
        if keyword.startswith("!"):
            negation = pre_negation = True
            keyword = keyword[1:]
        if keyword.endswith("!"):
            negation = True
            keyword = keyword[:-1]

        module.keywords[keyword] = Keyword(
            name=keyword,
            # "$k->{params} = $params if $params": a falsy params (the
            # string "0" from *0) leaves it unset, i.e. a no-arg option.
            params=params if perl_true(params) else None,
            negation=negation,
            pre_negation=pre_negation,
        )

    return module


def _build_registry() -> tuple[Registry, Registry, Registry]:
    """Build the protocol/match/target tables (Perl ``:229-440``)."""
    proto_defs: Registry = {}
    match_defs: Registry = {}
    target_defs: Registry = {}

    def proto(name: str, *specs: str) -> None:
        _add_def(proto_defs, "ip", 1, name, specs)

    def match(name: str, *specs: str) -> None:
        _add_def(match_defs, "ip", 1, name, specs)

    def target(name: str, *specs: str) -> None:
        _add_def(target_defs, "ip", "s", name, specs)

    def proto_x(family: str, name: str, *specs: str) -> None:
        _add_def(proto_defs, family, 1, name, specs)

    def match_x(family: str, name: str, *specs: str) -> None:
        _add_def(match_defs, family, 1, name, specs)

    def target_x(family: str, name: str, *specs: str) -> None:
        _add_def(target_defs, family, "s", name, specs)

    proto("dccp", "dccp-types!=c", "dccp-option!")
    proto("mh", "mh-type!")
    proto("icmp", "icmp-type!", "icmpv6-type:=icmp-type")
    proto("sctp", "chunk-types!=sc")
    proto("tcp", "tcp-flags!=cc", "!syn*0", "tcp-option!", "mss")
    proto("udp")

    match(
        "",
        # --source, --destination
        "source!&address_magic",
        "saddr:=source",
        "destination!&address_magic",
        "daddr:=destination",
        # --in-interface
        "in-interface!",
        "interface:=in-interface",
        "if:=in-interface",
        # --out-interface
        "out-interface!",
        "outerface:=out-interface",
        "of:=out-interface",
        # --fragment
        "!fragment*0",
    )
    match("account", "aaddr=s", "aname=s", "ashort*0")
    match(
        "addrtype",
        "!src-type",
        "!dst-type",
        "limit-iface-in*0",
        "limit-iface-out*0",
    )
    match("ah", "ahspi!", "ahlen!", "ahres*0")
    match("bpf", "bytecode")
    match("cgroup", "path!", "cgroup&cgroup_classid")
    match("comment", "comment=s")
    match("condition", "condition!")
    match("connbytes", "!connbytes", "connbytes-dir", "connbytes-mode")
    match("connlabel", "!label", "set*0")
    match(
        "connlimit",
        "!connlimit-upto",
        "!connlimit-above",
        "connlimit-mask",
        "connlimit-saddr*0",
        "connlimit-daddr*0",
    )
    match("connmark", "!mark")
    match(
        "conntrack",
        "!ctstate=c",
        "!ctproto",
        "ctorigsrc!",
        "ctorigdst!",
        "ctorigsrcport!",
        "ctorigdstport!",
        "ctreplsrc!",
        "ctrepldst!",
        "!ctstatus",
        "!ctexpire=s",
        "ctdir=s",
    )
    match("cpu", "!cpu")
    match("devgroup", "!src-group", "!dst-group")
    match("dscp", "dscp", "dscp-class")
    match("dst", "!dst-len=s", "dst-opts=c")
    match("ecn", "ecn-tcp-cwr*0", "ecn-tcp-ece*0", "ecn-ip-ect")
    match("esp", "espspi!")
    match("eui64")
    match("fuzzy", "lower-limit=s", "upper-limit=s")
    match("geoip", "!src-cc=s", "!dst-cc=s")
    match("hbh", "hbh-len!", "hbh-opts=c")
    match("helper", "helper")
    match("hl", "hl-eq!", "hl-lt=s", "hl-gt=s")
    match(
        "hashlimit",
        "hashlimit=s",
        "hashlimit-burst=s",
        "hashlimit-mode=c",
        "hashlimit-name=s",
        "hashlimit-upto=s",
        "hashlimit-above=s",
        "hashlimit-srcmask=s",
        "hashlimit-dstmask=s",
        "hashlimit-htable-size=s",
        "hashlimit-htable-max=s",
        "hashlimit-htable-expire=s",
        "hashlimit-htable-gcinterval=s",
    )
    match("iprange", "!src-range", "!dst-range")
    match("ipv4options", "flags!=c", "any*0")
    match("ipv6header", "header!=c", "soft*0")
    match(
        "ipvs", "!ipvs*0", "!vproto", "!vaddr", "!vport", "vdir", "!vportctl"
    )
    match("length", "length!")
    match("length2", "length!", "layer3*0", "layer4*0", "layer5*0")
    match("limit", "limit=s", "limit-burst=s")
    match("mac", "mac-source!")
    match("mark", "!mark")
    match(
        "multiport",
        "source-ports!&multiport_params",
        "destination-ports!&multiport_params",
        "ports!&multiport_params",
    )
    match("nfacct", "nfacct-name=s")
    match("nth", "every", "counter", "start", "packet")
    match("osf", "!genre", "ttl=s", "log=s")
    match(
        "owner",
        "!uid-owner",
        "!gid-owner",
        "pid-owner",
        "sid-owner",
        "cmd-owner",
        "!socket-exists=0",
    )
    match(
        "physdev",
        "physdev-in!",
        "physdev-out!",
        "!physdev-is-in*0",
        "!physdev-is-out*0",
        "!physdev-is-bridged*0",
    )
    # Upstream (:295) ends "pkttype" with a stray comma, so Perl folds the
    # following add_match_def('policy', ...) call's return value in as an
    # extra (unreachable, address-stringified) keyword.  Faithful behaviour
    # is the two modules below; the junk keyword is intentionally dropped.
    match("pkttype", "pkt-type!")
    match(
        "policy",
        "dir",
        "pol",
        "strict*0",
        "!reqid",
        "!spi",
        "!proto",
        "!mode",
        "!tunnel-src",
        "!tunnel-dst",
        "next*0",
    )
    match(
        "psd",
        "psd-weight-threshold",
        "psd-delay-threshold",
        "psd-lo-ports-weight",
        "psd-hi-ports-weight",
    )
    match("quota", "quota=s")
    match("random", "average")
    match("realm", "realm!")
    match(
        "recent",
        "name=s",
        "!set*0",
        "!remove*0",
        "!rcheck*0",
        "!update*0",
        "!seconds",
        "!hitcount",
        "rttl*0",
        "rsource*0",
        "rdest*0",
        "mask=s",
        "reap*0",
    )
    match("rpfilter", "loose*0", "validmark*0", "accept-local*0", "invert*0")
    match(
        "rt",
        "rt-type!",
        "rt-segsleft!",
        "rt-len!",
        "rt-0-res*0",
        "rt-0-addrs=c",
        "rt-0-not-strict*0",
    )
    match(
        "set",
        "!match-set=sc",
        "set:=match-set",
        "return-nomatch*0",
        "!update-counters*0",
        "!update-subcounters*0",
        "!packets-eq=s",
        "packets-lt=s",
        "packets-gt=s",
        "!bytes-eq=s",
        "bytes-lt=s",
        "bytes-gt=s",
    )
    match("socket", "transparent*0", "nowildcard*0", "restore-skmark*0")
    match("state", "!state=c")
    match("statistic", "mode=s", "probability=s", "every=s", "packet=s")
    match("string", "algo=s", "from=s", "to=s", "string", "hex-string")
    match("tcpmss", "!mss")
    match(
        "time",
        "timestart=s",
        "timestop=s",
        "days=c",
        "datestart=s",
        "datestop=s",
        "!monthday=c",
        "!weekdays=c",
        "kerneltz*0",
        "contiguous*0",
    )
    match("tos", "!tos")
    match("ttl", "ttl-eq", "ttl-lt=s", "ttl-gt=s")
    match("u32", "!u32=m")

    target("AUDIT", "type")
    target("BALANCE", "to-destination", "to:=to-destination")
    target("CHECKSUM", "checksum-fill*0")
    target("CLASSIFY", "set-class")
    target(
        "CLUSTERIP",
        "new*0",
        "hashmode",
        "clustermac",
        "total-nodes",
        "local-node",
        "hash-init",
    )
    target(
        "CONNMARK",
        "set-xmark",
        "save-mark*0",
        "restore-mark*0",
        "nfmask",
        "ctmask",
        "and-mark",
        "or-mark",
        "xor-mark",
        "set-mark",
        "mask",
    )
    target("CONNSECMARK", "save*0", "restore*0")
    target(
        "CT",
        "notrack*0",
        "helper",
        "ctevents=c",
        "expevents=c",
        "zone-orig",
        "zone-reply",
        "zone",
        "timeout",
    )
    target(
        "DNAT",
        "to-destination=m",
        "to:=to-destination",
        "persistent*0",
        "random*0",
    )
    target("DNPT", "src-pfx", "dst-pfx")
    target("DSCP", "set-dscp", "set-dscp-class")
    target("ECN", "ecn-tcp-remove*0")
    target("HL", "hl-set", "hl-dec", "hl-inc")
    target(
        "HMARK",
        "hmark-tuple",
        "hmark-mod",
        "hmark-offset",
        "hmark-src-prefix",
        "hmark-dst-prefix",
        "hmark-sport-mask",
        "hmark-dport-mask",
        "hmark-spi-mask",
        "hmark-proto-mask",
        "hmark-rnd",
    )
    target("IDLETIMER", "timeout", "label")
    target("IPV4OPTSSTRIP")
    target("JOOL", "instance")
    target("JOOL_SIIT", "instance")
    target("LED", "led-trigger-id", "led-delay", "led-always-blink*0")
    target(
        "LOG",
        "log-level",
        "log-prefix",
        "log-tcp-sequence*0",
        "log-tcp-options*0",
        "log-ip-options*0",
        "log-uid*0",
    )
    target("MARK", "set-mark", "set-xmark", "and-mark", "or-mark", "xor-mark")
    target("MASQUERADE", "to-ports", "random*0", "random-fully*0")
    target("MIRROR")
    target("NETMAP", "to")
    target(
        "NFLOG",
        "nflog-group",
        "nflog-prefix",
        "nflog-range",
        "nflog-threshold",
    )
    target(
        "NFQUEUE",
        "queue-num",
        "queue-balance",
        "queue-bypass*0",
        "queue-cpu-fanout*0",
    )
    target("NOTRACK")
    target("RATEEST", "rateest-name", "rateest-interval", "rateest-ewmalog")
    target("REDIRECT", "to-ports", "random*0")
    target("REJECT", "reject-with")
    target("ROUTE", "oif", "iif", "gw", "continue*0", "tee*0")
    target("RTPENGINE", "id")
    target("SAME", "to", "nodst*0", "random*0")
    target("SECMARK", "selctx")
    target("SET", "add-set=sc", "del-set=sc", "timeout", "exist*0")
    target("SNAT", "to-source=m", "to:=to-source", "persistent*0", "random*0")
    target("SNPT", "src-pfx", "dst-pfx")
    target(
        "SYNPROXY", "sack-perm*0", "timestamp*0", "ecn*0", "wscale=s", "mss=s"
    )
    target("TARPIT")
    target("TCPMSS", "set-mss", "clamp-mss-to-pmtu*0")
    target("TCPOPTSTRIP", "strip-options=c")
    target("TEE", "gateway")
    target("TOS", "set-tos", "and-tos", "or-tos", "xor-tos")
    target("TPROXY", "tproxy-mark", "on-ip", "on-port")
    target("TRACE")
    target("TTL", "ttl-set", "ttl-dec", "ttl-inc")
    target(
        "ULOG",
        "ulog-nlgroup",
        "ulog-prefix",
        "ulog-cprange",
        "ulog-qthreshold",
    )

    match_x(
        "arp",
        "",
        # ip
        "source-ip!",
        "destination-ip!",
        "saddr:=source-ip",
        "daddr:=destination-ip",
        # mac
        "source-mac!",
        "destination-mac!",
        # --in-interface
        "in-interface!",
        "interface:=in-interface",
        "if:=in-interface",
        # --out-interface
        "out-interface!",
        "outerface:=out-interface",
        "of:=out-interface",
        # misc
        "h-length=s",
        "opcode=s",
        "h-type=s",
        "proto-type=s",
        "mangle-ip-s=s",
        "mangle-ip-d=s",
        "mangle-mac-s=s",
        "mangle-mac-d=s",
        "mangle-target=s",
    )

    proto_x(
        "eb",
        "IPv4",
        "ip-source!",
        "ip-destination!",
        "ip-src:=ip-source",
        "ip-dst:=ip-destination",
        "ip-tos!",
        "ip-protocol!",
        "ip-proto:=ip-protocol",
        "ip-source-port!",
        "ip-sport:=ip-source-port",
        "ip-destination-port!",
        "ip-dport:=ip-destination-port",
    )

    proto_x(
        "eb",
        "IPv6",
        "ip6-source!",
        "ip6-destination!",
        "ip6-src:=ip6-source",
        "ip6-dst:=ip6-destination",
        "ip6-tclass!",
        "ip6-protocol!",
        "ip6-proto:=ip6-protocol",
        "ip6-source-port!",
        "ip6-sport:=ip6-source-port",
        "ip6-destination-port!",
        "ip6-dport:=ip6-destination-port",
    )

    proto_x(
        "eb",
        "ARP",
        "!arp-gratuitous*0",
        "arp-opcode!",
        "arp-htype!=ss",
        "arp-ptype!=ss",
        "arp-ip-src!",
        "arp-ip-dst!",
        "arp-mac-src!",
        "arp-mac-dst!",
    )

    proto_x(
        "eb",
        "RARP",
        "!arp-gratuitous*0",
        "arp-opcode!",
        "arp-htype!=ss",
        "arp-ptype!=ss",
        "arp-ip-src!",
        "arp-ip-dst!",
        "arp-mac-src!",
        "arp-mac-dst!",
    )

    # Upstream (:407) ends "802_1Q" with a stray comma, folding the
    # following add_match_def_x('eb', '', ...) return value in as a junk
    # keyword (as with pkttype above); dropped here.
    proto_x("eb", "802_1Q", "vlan-id!", "vlan-prio!", "vlan-encap!")

    match_x(
        "eb",
        "",
        # --in-interface
        "in-interface!",
        "interface:=in-interface",
        "if:=in-interface",
        # --out-interface
        "out-interface!",
        "outerface:=out-interface",
        "of:=out-interface",
        # logical interface
        "logical-in!",
        "logical-out!",
        # --source, --destination
        "source!",
        "saddr:=source",
        "destination!",
        "daddr:=destination",
        # 802.3
        "802_3-sap!",
        "802_3-type!",
        # among
        "!among-dst=c",
        "!among-src=c",
        "!among-dst-file",
        "!among-src-file",
        # limit
        "limit=s",
        "limit-burst=s",
        # mark_m
        "mark!",
        # pkttype
        "pkttype-type!",
        # stp
        "stp-type!",
        "stp-flags!",
        "stp-root-prio!",
        "stp-root-addr!",
        "stp-root-cost!",
        "stp-sender-prio!",
        "stp-sender-addr!",
        "stp-port!",
        "stp-msg-age!",
        "stp-max-age!",
        "stp-hello-time!",
        "stp-forward-delay!",
        # log
        "log*0",
        "log-level=s",
        "log-prefix=s",
        "log-ip*0",
        "log-arp*0",
    )

    target_x("eb", "arpreply", "arpreply-mac", "arpreply-target")
    target_x("eb", "dnat", "to-destination", "dnat-target")
    target_x("eb", "MARK", "set-mark", "mark-target")
    target_x("eb", "redirect", "redirect-target")
    target_x("eb", "snat", "to-source", "snat-target", "snat-arp*0")

    return proto_defs, match_defs, target_defs


PROTO_DEFS, MATCH_DEFS, TARGET_DEFS = _build_registry()

#: ``domain_family -> shortcut_keyword -> [module_name, real_keyword]``
#: (Perl ``%shortcuts``, ``:442``).  ``import-ferm`` reads these too.
SHORTCUTS: dict[str, dict[str, list[str]]] = {
    "ip": {
        "sports": ["multiport", "source-ports"],
        "dports": ["multiport", "destination-ports"],
        "comment": ["comment", "comment"],
    },
}
