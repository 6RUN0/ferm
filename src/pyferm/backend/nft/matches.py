"""Match-option translation: translate_match and its vocabulary tables."""

from __future__ import annotations

import grp
import ipaddress
import pwd
import re
from typing import TYPE_CHECKING, Final

from ...domains import (
    NFT_CT_STATES,
    Family,
)
from ...errors import FermError, internal_error
from ...modules import PORT_PROTOCOLS
from ...values import (
    Negated,
    Params,
    PreNegated,
    SetRef,
    Value,
)

if TYPE_CHECKING:
    from ...rules import (
        RenderedOption,
    )

from .model import (
    _UNSUPPORTED_VALUE_SHAPE,
    NftMatch,
    _nft_ifname,
    _op,
    _validate_address,
    _validate_port,
    _validate_set_name,
    unwrap_value,
)

#: An nft ``limit rate`` value: ``N`` or ``N/unit`` (``3/second``).
_NFT_RATE_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(\d+)(?:/([A-Za-z]+))?\Z"
)

#: nft's limit units; xt_limit accepts any (case-insensitive) prefix of
#: these, so ``10/min``/``10/m`` expand to ``10/minute``.
_NFT_RATE_UNITS: Final[tuple[str, ...]] = ("second", "minute", "hour", "day")

#: ct state keywords nft accepts for ``ct state`` (the ferm ``state`` module
#: maps to iptables ``--state``, whose vocabulary is this set).
_CT_STATES: Final[frozenset[str]] = frozenset(NFT_CT_STATES)

#: ct state bit values: the kernel readback prints a state list
#: deduplicated in ascending bit order, so emission pre-sorts to match
#: (the _FIB_TYPE_RANK pattern).
_CT_STATE_RANK: Final[dict[str, int]] = {
    "invalid": 0x01,
    "established": 0x02,
    "related": 0x04,
    "new": 0x08,
    "untracked": 0x40,
}

#: ct status bits (IPS_* order), same readback-order contract.  The
#: xt_conntrack-only SNAT/DNAT pseudo-states live in this register, not
#: in ct state.
_CT_STATUS_RANK: Final[dict[str, int]] = {
    "expected": 0x01,
    "seen-reply": 0x02,
    "assured": 0x04,
    "confirmed": 0x08,
    "snat": 0x10,
    "dnat": 0x20,
}

_CT_NAT_PSEUDO_STATES: Final[frozenset[str]] = frozenset({"snat", "dnat"})

#: the --ctstatus vocabulary xt_conntrack accepts, minus NONE (an empty
#: status mask, which no nft ``ct status`` spelling can express).
_CTSTATUS_TOKENS: Final[frozenset[str]] = frozenset(
    {"expected", "seen-reply", "assured", "confirmed"}
)

#: canonical option name -> nft address keyword.
_ADDR_KEYWORD: Final[dict[str, str]] = {
    "source": "saddr",
    "destination": "daddr",
}

#: canonical option name -> nft interface keyword.
_IFACE_KEYWORD: Final[dict[str, str]] = {
    "in-interface": "iifname",
    "out-interface": "oifname",
}

#: port option names; the nft keyword equals the ferm name.
_PORT_KEYWORD: Final[dict[str, str]] = {"sport": "sport", "dport": "dport"}

#: multiport option name -> nft port keyword.  The both-directions
#: ``ports`` form matches source OR destination; no single nft match
#: spells that disjunction, so it stays refused.
_MULTIPORT_KEYWORD: Final[dict[str, str]] = {
    "source-ports": "sport",
    "destination-ports": "dport",
}

#: xt_limit ``--limit-burst``: a positive packet count.
_NFT_BURST_RE: Final[re.Pattern[str]] = re.compile(r"\A[1-9]\d*\Z")

#: xt_limit's default rate, made explicit when only a burst is given.
_NFT_DEFAULT_LIMIT_RATE: Final[str] = "3/hour"

#: xt ``--pkt-type`` value -> nft ``meta pkttype`` keyword.  The kernel
#: respells ``unicast`` as ``host`` on readback, so it is emitted directly;
#: broadcast/multicast are spelled the same in both.
_PKTTYPE_MAP: Final[dict[str, str]] = {
    "unicast": "host",
    "broadcast": "broadcast",
    "multicast": "multicast",
}

#: iptables ``--icmp-type`` name -> nft ``icmp type`` name (ip family).
#: Only the top-level (code-less) type names translate; the iptables
#: subtype names (``network-unreachable``, ...) are type+code pairs with
#: no single nft type keyword and refuse cleanly.
_ICMP_TYPE_MAP: Final[dict[str, str]] = {
    "echo-reply": "echo-reply",
    "pong": "echo-reply",
    "destination-unreachable": "destination-unreachable",
    "source-quench": "source-quench",
    "redirect": "redirect",
    "echo-request": "echo-request",
    "ping": "echo-request",
    "router-advertisement": "router-advertisement",
    "router-solicitation": "router-solicitation",
    "time-exceeded": "time-exceeded",
    "ttl-exceeded": "time-exceeded",
    "parameter-problem": "parameter-problem",
    "timestamp-request": "timestamp-request",
    "timestamp-reply": "timestamp-reply",
    "address-mask-request": "address-mask-request",
    "address-mask-reply": "address-mask-reply",
}

#: iptables ``--icmpv6-type`` name -> nft ``icmpv6 type`` name.  The ND
#: names are respelled to nft's ``nd-*`` vocabulary; the shared names
#: keep their spelling (verified against nft v1.1.6).
_ICMP6_TYPE_MAP: Final[dict[str, str]] = {
    "destination-unreachable": "destination-unreachable",
    "packet-too-big": "packet-too-big",
    "time-exceeded": "time-exceeded",
    "ttl-exceeded": "time-exceeded",
    "parameter-problem": "parameter-problem",
    "echo-request": "echo-request",
    "ping": "echo-request",
    "echo-reply": "echo-reply",
    "pong": "echo-reply",
    "router-solicitation": "nd-router-solicit",
    "router-advertisement": "nd-router-advert",
    "neighbour-solicitation": "nd-neighbor-solicit",
    "neighbor-solicitation": "nd-neighbor-solicit",
    "neighbour-advertisement": "nd-neighbor-advert",
    "neighbor-advertisement": "nd-neighbor-advert",
    "redirect": "nd-redirect",
}

#: iptables numeric ``type`` or ``type/code`` form (one octet each).
_ICMP_NUMERIC_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(\d{1,3})(?:/(\d{1,3}))?\Z"
)

#: An icmp type/code is one octet.
_ICMP_OCTET_MAX: Final[int] = 255

#: iptables ``--tcp-option`` takes one option-kind octet.
_TCP_OPTION_KIND_MAX: Final[int] = 255

#: ``--tcp-option`` kind number -> the name the kernel readback respells
#: it to (verified against nft v1.1.6); unknown kinds read back numeric
#: and are emitted as such.
_TCP_OPTION_KIND: Final[dict[int, str]] = {
    0: "eol",
    1: "nop",
    2: "maxseg",
    3: "window",
    4: "sack-perm",
    5: "sack",
    8: "timestamp",
    19: "md5sig",
    30: "mptcp",
    34: "fastopen",
}

#: A packet/ct mark is a 32-bit value.
_MARK_MAX: Final[int] = 0xFFFFFFFF

#: u16 ceiling shared by NFQUEUE queue numbers and synproxy mss/wscale.
_U16_MAX: Final[int] = 0xFFFF

#: the 8-bit IPv4 TTL / IPv6 hop-limit ceiling.
_HOPLIMIT_MAX: Final[int] = 255

#: An nflog group is a 16-bit netlink group number.
_NFLOG_GROUP_MAX: Final[int] = 65535

#: numeric icmp type -> the name the kernel readback prints it as
#: (captured from a live nft v1.1.6 ``nft list ruleset``).  A numeric
#: operand must emit that name, else the applied rule reads back
#: differently and ``--plan`` never converges; a number absent here
#: prints back numeric and stays as-is.  Codes always read back numeric.
_ICMP_TYPE_BY_NUMBER: Final[dict[int, str]] = {
    0: "echo-reply",
    3: "destination-unreachable",
    4: "source-quench",
    5: "redirect",
    8: "echo-request",
    9: "router-advertisement",
    10: "router-solicitation",
    11: "time-exceeded",
    12: "parameter-problem",
    13: "timestamp-request",
    14: "timestamp-reply",
    15: "info-request",
    16: "info-reply",
    17: "address-mask-request",
    18: "address-mask-reply",
}

#: numeric icmpv6 type -> kernel-readback name (same capture).
_ICMP6_TYPE_BY_NUMBER: Final[dict[int, str]] = {
    1: "destination-unreachable",
    2: "packet-too-big",
    3: "time-exceeded",
    4: "parameter-problem",
    128: "echo-request",
    129: "echo-reply",
    130: "mld-listener-query",
    131: "mld-listener-report",
    132: "mld-listener-done",
    133: "nd-router-solicit",
    134: "nd-router-advert",
    135: "nd-neighbor-solicit",
    136: "nd-neighbor-advert",
    137: "nd-redirect",
    138: "router-renumbering",
    141: "ind-neighbor-solicit",
    142: "ind-neighbor-advert",
    143: "mld2-listener-report",
}

#: TCP flag names in header bit order -- the kernel-readback order for
#: both the mask parenthesis and the comparison list.
_TCP_FLAG_ORDER: Final[tuple[str, ...]] = (
    "fin",
    "syn",
    "rst",
    "psh",
    "ack",
    "urg",
)

#: numeric arp opcode -> the operation name the kernel readback prints
#: (captured live from nft v1.1.6); unknown numbers stay numeric.
_ARP_OPERATION_BY_NUMBER: Final[dict[int, str]] = {
    1: "request",
    2: "reply",
    3: "rrequest",
    4: "rreply",
    8: "inrequest",
    9: "inreply",
    10: "nak",
}

#: A numeric low-high range operand (uid/gid, length after the colon
#: rewrite): the readback keeps the dash form.
_NUMERIC_RANGE_RE: Final[re.Pattern[str]] = re.compile(r"\A\d+-\d+\Z")

#: A colon-separated MAC address; the readback lowercases it.
_MAC_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\Z"
)

#: xt_ttl option name -> the comparator the kernel readback prints
#: (``gt``/``lt`` read back as ``>``/``<``).
_TTL_COMPARATOR: Final[dict[str, str]] = {
    "ttl-eq": "",
    "ttl-gt": "> ",
    "ttl-lt": "< ",
}

#: mod hl, xt_ttl's ip6 twin: the same comparator shapes over
#: ``ip6 hoplimit`` (readback prints ``>``/``<`` -- verified live).
_HL_COMPARATOR: Final[dict[str, str]] = {
    "hl-eq": "",
    "hl-gt": "> ",
    "hl-lt": "< ",
}

#: iptables addrtype value -> nft fib route type, keyed by kernel RTN
#: number (RTN_UNSPEC=0 ... RTN_PROHIBIT=8).  A type-list readback is
#: re-sorted into this order, so a comma-list literal must be emitted
#: pre-sorted the same way or --plan diffs an already-applied ruleset
#: forever.  throw/nat/xresolve carry no fib type and refuse.
_FIB_TYPE_RANK: Final[dict[str, int]] = {
    "unspec": 0,
    "unicast": 1,
    "local": 2,
    "broadcast": 3,
    "anycast": 4,
    "multicast": 5,
    "blackhole": 6,
    "unreachable": 7,
    "prohibit": 8,
}

#: addrtype option name -> the fib address selector it queries.
_FIB_SELECTOR: Final[dict[str, str]] = {
    "src-type": "saddr",
    "dst-type": "daddr",
}

#: dscp codepoint -> the class name nft's readback prints; every other
#: value in 0-63 reads back as 0x%02x.  Pinned by
#: tests/e2e/readback/driver.py (nft v1.1.6); re-capture on an nft bump
#: rather than editing by hand.  nft knows lephb (0x01) and va (0x2c),
#: which the iptables --dscp-class input table below does not.
_DSCP_NAMES: Final[dict[int, str]] = {
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

#: iptables --dscp-class name -> codepoint (the input class table).  `be`
#: (best effort) is 0x00, so it emits as cs0 after canonicalization.
_DSCP_CLASS: Final[dict[str, int]] = {
    "cs0": 0x00,
    "cs1": 0x08,
    "cs2": 0x10,
    "cs3": 0x18,
    "cs4": 0x20,
    "cs5": 0x28,
    "cs6": 0x30,
    "cs7": 0x38,
    "af11": 0x0A,
    "af12": 0x0C,
    "af13": 0x0E,
    "af21": 0x12,
    "af22": 0x14,
    "af23": 0x16,
    "af31": 0x1A,
    "af32": 0x1C,
    "af33": 0x1E,
    "af41": 0x22,
    "af42": 0x24,
    "af43": 0x26,
    "ef": 0x2E,
    "be": 0x00,
}

#: max dscp codepoint (the 6-bit DSCP field).
_DSCP_MAX: Final[int] = 0x3F

#: tc classid handle for CLASSIFY: two 1-4 hex-digit halves.  A wider half
#: is rejected -- the kernel refuses it too.
_CLASSID_RE: Final = re.compile(r"\A([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})\Z")

#: tc reserves handle ffff:ffff for the root qdisc (spelled ``root``).
_TC_HANDLE_ROOT: Final[int] = 0xFFFF


def _tcp_flag_list(scalar: str) -> list[str]:
    """Parse one iptables flag list into header-bit order (``ALL`` too)."""
    if scalar.lower() == "all":
        return list(_TCP_FLAG_ORDER)
    seen: set[str] = set()
    for raw in scalar.split(","):
        token = raw.lower()
        if token not in _TCP_FLAG_ORDER:
            raise FermError(f"unknown tcp flag '{raw}' for nft backend")
        seen.add(token)
    return [flag for flag in _TCP_FLAG_ORDER if flag in seen]


def _tcp_flags_expr(value: Value) -> str:
    """
    Translate ``--tcp-flags MASK COMP`` to the kernel-readback spelling.

    The readback prints the BITWISE form (``tcp flags & (fin | syn) ==
    syn``), not iptables-translate's slash form; a single-flag mask is
    unparenthesized and a multi-flag comparison carries no parentheses
    (all verified live).  ``COMP == NONE`` reads back as the
    flag-absence form ``tcp flags ! fin,syn``; its negation would need
    a ``!= 0x0`` the readback respells, so it refuses.
    """
    neg = False
    if isinstance(value, (Negated, PreNegated)):
        value = value.value
        neg = True
    if not isinstance(value, Params):
        raise FermError(_UNSUPPORTED_VALUE_SHAPE)
    try:
        mask_raw, comp_raw = value.values
    except ValueError:
        raise FermError(_UNSUPPORTED_VALUE_SHAPE) from None
    if not isinstance(mask_raw, str) or not isinstance(comp_raw, str):
        raise FermError(_UNSUPPORTED_VALUE_SHAPE)
    mask = _tcp_flag_list(mask_raw)
    if comp_raw.lower() == "none":
        if neg:
            raise FermError(
                "negated tcp-flags NONE cannot be expressed for nft backend"
            )
        return f"tcp flags ! {','.join(mask)}"
    comp = _tcp_flag_list(comp_raw)
    mask_text = mask[0] if len(mask) == 1 else f"({' | '.join(mask)})"
    operator = "!=" if neg else "=="
    return f"tcp flags & {mask_text} {operator} {' | '.join(comp)}"


def _owner_value(name: str, scalar: str) -> str:
    """
    Canonicalize a ``--uid-owner``/``--gid-owner`` operand to a number.

    nft resolves a user/group name at parse time and the kernel
    readback prints the id, so a name emitted verbatim would leave
    ``--plan`` diffing forever; numeric ids and dash ranges pass
    through (the readback keeps both).
    """
    if scalar.isdigit() or _NUMERIC_RANGE_RE.match(scalar):
        return scalar
    if name == "uid-owner":
        try:
            return str(pwd.getpwnam(scalar).pw_uid)
        except KeyError:
            raise FermError(
                f"unknown user '{scalar}' for nft backend"
            ) from None
    try:
        return str(grp.getgrnam(scalar).gr_gid)
    except KeyError:
        raise FermError(f"unknown group '{scalar}' for nft backend") from None


def _nft_rate(scalar: str) -> str:
    """
    Normalize an xt_limit rate to nft's spelling.

    xt_limit accepts any case-insensitive prefix of the unit
    (``10/min``, ``10/m``) and treats a bare number as per-second; nft's
    grammar wants the full lowercase unit (upstream reference:
    ``iptables-translate``).  Passing the abbreviated form through would
    emit a script ``nft -f`` rejects only at apply time.
    """
    match = _NFT_RATE_RE.match(scalar)
    if match:
        count, prefix = match.group(1), match.group(2)
        if prefix is None:
            return f"{count}/second"
        lowered = prefix.lower()
        for unit in _NFT_RATE_UNITS:
            if unit.startswith(lowered):
                return f"{count}/{unit}"
    raise FermError(f"invalid rate '{scalar}' for nft backend")


def _mark_value(scalar: str) -> str:
    """
    Canonicalize a mark operand to the kernel-readback spelling.

    nft prints a mark as 8-digit hex (``0x00000002``), so any other
    emission leaves ``--plan`` diffing an applied ruleset forever.
    Accepts the iptables decimal/hex forms; the ``value/mask`` form has
    no single infix nft match and refuses.
    """
    if "/" in scalar:
        base, _, mask = scalar.partition("/")
        try:
            full_mask = int(mask, 0) == _MARK_MAX
        except ValueError:
            full_mask = False
        if not full_mask:
            raise FermError(
                f"masked mark '{scalar}' not yet supported by nft backend"
            )
        # (mark & 0xffffffff) == value IS the plain equality
        scalar = base
    try:
        value = int(scalar, 0)
    except ValueError:
        raise FermError(f"invalid mark '{scalar}' for nft backend") from None
    if not 0 <= value <= _MARK_MAX:
        raise FermError(f"invalid mark '{scalar}' for nft backend")
    return f"0x{value:08x}"


def _masked_mark_expr(selector: str, scalar: str, neg: bool) -> str | None:
    """
    Spell a partial-mask xt mark match as nft's infix bitwise form.

    Returns None when the plain-equality path applies instead.
    xt matches ``(mark & mask) == value``; the kernel readback prints
    both operands as 8-digit hex (``& 0x00000003 == 0x00000000``) --
    verified live.  A full mask folds to plain equality inside
    :func:`_mark_value` instead.
    """
    if "/" not in scalar:
        return None
    base, _, mask = scalar.partition("/")
    try:
        value = int(base, 0)
        mask_value = int(mask, 0)
    except ValueError:
        raise FermError(f"invalid mark '{scalar}' for nft backend") from None
    if mask_value == _MARK_MAX:
        return None
    if not (0 <= value <= _MARK_MAX and 0 <= mask_value <= _MARK_MAX):
        raise FermError(f"invalid mark '{scalar}' for nft backend")
    operator = "!=" if neg else "=="
    return f"{selector} & 0x{mask_value:08x} {operator} 0x{value:08x}"


def _icmp_type_expr(domain: Family, scalar: str, neg: bool) -> str:
    """
    Translate one ``icmp-type`` operand to an nft match expression.

    The selector keyword follows the *domain* (``icmpv6`` under ip6, cf.
    :func:`_nft_l4proto`), not the rendered protocol, which stays the raw
    ``icmp`` spelling.  Accepted operands mirror what iptables accepts:
    a top-level type name (mapped per family), a numeric type, or a
    numeric ``type/code`` pair.  A negated ``type/code`` pair refuses --
    ``!(type == t && code == c)`` has no infix nft equivalent, and the
    De Morgan misreading ``type != t code != c`` would match the wrong
    packets.
    """
    keyword = "icmpv6" if domain is Family.IP6 else "icmp"
    by_number = (
        _ICMP6_TYPE_BY_NUMBER if domain is Family.IP6 else _ICMP_TYPE_BY_NUMBER
    )
    numeric = _ICMP_NUMERIC_RE.match(scalar)
    if numeric:
        type_num, code_num = numeric.group(1), numeric.group(2)
        if int(type_num) > _ICMP_OCTET_MAX or (
            code_num is not None and int(code_num) > _ICMP_OCTET_MAX
        ):
            raise FermError(f"invalid icmp type '{scalar}' for nft backend")
        type_text = by_number.get(int(type_num), type_num)
        if code_num is None:
            return f"{keyword} type {_op(neg)}{type_text}"
        if neg:
            raise FermError(
                "negated icmp type/code match cannot be expressed as "
                "infix nft matches"
            )
        return f"{keyword} type {type_text} {keyword} code {code_num}"
    table = _ICMP6_TYPE_MAP if domain is Family.IP6 else _ICMP_TYPE_MAP
    name = table.get(scalar)
    if name is None:
        raise FermError(
            f"icmp-type '{scalar}' not yet supported by nft backend"
        )
    return f"{keyword} type {_op(neg)}{name}"


def _fib_type_literal(scalar: str) -> str:
    """
    Render the fib type operand from an iptables addrtype value.

    A comma-list is sorted into kernel RTN order (the readback re-sorts it,
    negated lists included), so the emitted literal already matches what
    ``nft list ruleset`` prints back.  A type with no fib equivalent
    (throw/nat/xresolve, or anything unknown) refuses by name.
    """
    ordered: list[str] = []
    for token in scalar.split(","):
        lowered = token.strip().lower()
        if lowered not in _FIB_TYPE_RANK:
            raise FermError(
                f"address type '{token.strip()}' has no nft fib equivalent"
            )
        ordered.append(lowered)
    ordered.sort(key=lambda type_name: _FIB_TYPE_RANK[type_name])
    if len(ordered) == 1:
        return ordered[0]
    return f"{{ {', '.join(ordered)} }}"


def _fib_type_match(name: str, value: Value, iface: str) -> str:
    """
    Build the ``fib <selector>[ . iif|oif] type <literal>`` match.

    *iface* is the routing-interface qualifier collected rule-wide from
    addrtype's limit-iface-in/out flags ("" when absent); it applies to
    every fib match in the rule.  fib works in both ip and ip6 with no
    family prefix, so the selector needs no ``domain``.
    """
    scalar, neg = unwrap_value(value)
    selector = _FIB_SELECTOR[name]
    return f"fib {selector}{iface} type {_op(neg)}{_fib_type_literal(scalar)}"


def _dscp_canon(value: int) -> str:
    """Spell a dscp codepoint as nft's kernel readback does (name or 0xNN)."""
    return _DSCP_NAMES.get(value, f"0x{value:02x}")


def _dscp_value(name: str, scalar: str) -> int:
    """Parse a numeric dscp value (``int(x, 0)``, 0-63) or refuse by name."""
    try:
        value = int(scalar, 0)
    except ValueError:
        raise FermError(
            f"option '{name}': invalid dscp value '{scalar}' for nft backend"
        ) from None
    if not 0 <= value <= _DSCP_MAX:
        raise FermError(
            f"option '{name}': dscp value '{scalar}' out of range 0-63 "
            f"for nft backend"
        )
    return value


def _dscp_class_value(name: str, scalar: str) -> int:
    """Resolve an iptables dscp class to its codepoint or refuse by name."""
    value = _DSCP_CLASS.get(scalar.lower())
    if value is None:
        raise FermError(
            f"option '{name}': unknown dscp class '{scalar}' for nft backend"
        )
    return value


def _tos_refusal(kind: str, name: str) -> FermError:
    """
    Build the shared TOS refusal (match ``tos`` and target ``TOS``).

    No single nft selector spans the whole 8-bit TOS byte with a mask, so
    silently emitting dscp alone would drop the ECN bits -- a fail-loud
    refusal instead, phrased so it does not promise a future fix.
    """
    return FermError(
        f"{kind} '{name}' has no nft equivalent (no single nft selector "
        f"covers the full 8-bit TOS byte with a mask; nft exposes dscp "
        f"and ecn separately)"
    )


def _ct_bitmask_expr(
    selector: str, members: list[str], rank: dict[str, int], neg: bool
) -> str:
    """
    Spell a ``ct state``/``ct status`` bitmask match in readback canon.

    The readback prints members deduplicated in ascending bit order.  A
    negated match must use the masked bang form (``ct status ! a,b``,
    "none of the bits set"): the ``!=`` spelling compares the WHOLE
    register against the OR of the bits -- true for nearly every packet
    -- which is not what iptables' ``! --ctstate a,b`` means (verified
    against the netlink bytecode).  The one exception: a packet's ct
    state register holds exactly one state bit, so a single-member
    negated state keeps the pre-existing ``!=`` canon (both forms
    round-trip and are faithful there).
    """
    ordered = sorted(set(members), key=rank.__getitem__)
    joined = ",".join(ordered)
    if not neg:
        return f"{selector} {joined}"
    if selector == "ct state" and len(ordered) == 1:
        return f"{selector} != {joined}"
    return f"{selector} ! {joined}"


def _iprange_bound(domain: Family, scalar: str) -> str:
    """
    Validate one ``mod iprange`` boundary as an address of *domain*'s family.

    The bound passes the safe-operand regex (:func:`_validate_address`) and
    must be a literal address of the rule's family -- an ip6 bound in an ip
    rule refuses here rather than emitting a script ``nft -c`` would reject.
    """
    safe = _validate_address(scalar)
    try:
        addr = ipaddress.ip_address(safe)
    except ValueError:
        raise FermError(
            f"invalid iprange bound '{scalar}' for the nft backend"
        ) from None
    if addr.version != (4 if domain is Family.IP else 6):
        raise FermError(
            f"iprange bound '{scalar}' does not match the {domain} family "
            "for the nft backend"
        )
    return safe


def _translate_match_parts(
    domain: Family, option: RenderedOption, protocol: str | None
) -> tuple[str, str | None, str | None]:
    """
    Translate one match option to (expr, set_key, element).

    ``set_key``/``element`` are non-None only for an eligible, non-negated
    match; the element string is the SAME operand baked into ``expr`` (single
    source of truth -- no reverse-parsing).
    """
    name = option.name
    # The tcp-flags/syn shapes carry Params/None values that unwrap_value
    # refuses, so they dispatch before it.
    if name == "tcp-flags":
        return (_tcp_flags_expr(option.value), None, None)
    if name == "syn":
        # --syn is --tcp-flags FIN,SYN,RST,ACK SYN (a no-arg option)
        negated = isinstance(option.value, (Negated, PreNegated))
        operator = "!=" if negated else "=="
        return (
            f"tcp flags & (fin | syn | rst | ack) {operator} syn",
            None,
            None,
        )
    try:
        scalar, neg = unwrap_value(option.value)
    except FermError as exc:
        # the bare unwrap message ("multi-value cannot...") would leave
        # a corpus refusal anonymous; the option name makes it actionable
        raise FermError(f"option '{name}': {exc}") from None
    if name in _ADDR_KEYWORD:
        addr = _validate_address(scalar)
        key = _match_selector(domain, name, protocol)
        expr = f"{key} {_op(neg)}{addr}"
        return (expr, None, None) if neg else (expr, key, addr)
    if name in _IFACE_KEYWORD:
        # An interface is an nft quoted string; the iptables trailing-`+`
        # wildcard becomes nft's `*` inside the quotes.
        quoted = _nft_ifname(scalar)
        key = _match_selector(domain, name, protocol)
        expr = f"{key} {_op(neg)}{quoted}"
        # The element is the quoted form ('"eth0"'): a folded set renders
        # iifname { "eth0", "eth1" } which is valid nft syntax.
        return (expr, None, None) if neg else (expr, key, quoted)
    if name in _PORT_KEYWORD:
        # _match_selector carries the tcp/udp guard; it must fire before
        # the port operand is validated (error-order contract).
        key = _match_selector(domain, name, protocol)
        port = _validate_port(scalar)
        expr = f"{key} {_op(neg)}{port}"
        return (expr, None, None) if neg else (expr, key, port)
    if name in ("state", "ctstate"):
        # mod conntrack's ctstate and mod state translate to `ct state`;
        # the xt_conntrack-only SNAT/DNAT pseudo-states are ct STATUS
        # bits.  A mixed list matches ANY member in iptables (one OR
        # across both registers), which no single nft rule can spell.
        members = scalar.lower().split(",")
        for member in members:
            if member not in _CT_STATES and (
                member not in _CT_NAT_PSEUDO_STATES
            ):
                raise FermError(f"unknown ct state '{member}' for nft backend")
        states = [m for m in members if m in _CT_STATES]
        statuses = [m for m in members if m in _CT_NAT_PSEUDO_STATES]
        if states and statuses:
            raise FermError(
                f"option '{name}': a list mixing connection states and "
                f"SNAT/DNAT pseudo-states matches any of them; nft cannot "
                f"OR 'ct state' with 'ct status' in one rule"
            )
        if statuses:
            expr = _ct_bitmask_expr(
                "ct status", statuses, _CT_STATUS_RANK, neg
            )
        else:
            expr = _ct_bitmask_expr("ct state", states, _CT_STATE_RANK, neg)
        return (expr, None, None)
    if name == "ctstatus":
        # xt_conntrack --ctstatus, with the same any-bit OR semantics as
        # ctstate; NONE (an empty status mask) has no nft spelling.
        members = [m.lower().replace("_", "-") for m in scalar.split(",")]
        for member in members:
            if member not in _CTSTATUS_TOKENS:
                raise FermError(
                    f"ct status '{member}' not yet supported by nft backend"
                )
        return (
            _ct_bitmask_expr("ct status", members, _CT_STATUS_RANK, neg),
            None,
            None,
        )
    if name in _MULTIPORT_KEYWORD:
        if protocol not in PORT_PROTOCOLS:
            raise FermError(
                f"option '{name}' needs a tcp/udp protocol for the nft backend"
            )
        members = [_validate_port(member) for member in scalar.split(",")]
        key = f"{protocol} {_MULTIPORT_KEYWORD[name]}"
        if len(members) == 1:
            return (f"{key} {_op(neg)}{members[0]}", None, None)
        return (
            f"{key} {_op(neg)}{{ {', '.join(members)} }}",
            None,
            None,
        )
    if name == "limit":
        return (f"limit rate {_nft_rate(scalar)}", None, None)
    if name == "icmp-type":
        # Not set-eligible: a bare-word element has no canonical rank in
        # sort_set_elements (unparsable stays in input order), so a
        # folded { echo-request, echo-reply } set could not converge
        # under --plan.
        return (_icmp_type_expr(domain, scalar, neg), None, None)
    if name in ("dscp", "dscp-class") and domain in (Family.IP, Family.IP6):
        # Not set-eligible (icmp-type precedent): class names are bare words
        # with no rank in sort_set_elements, so a folded set could not
        # converge under --plan; a ferm array stays a cartesian unfold.
        # arp/eb have no dscp selector and fall through to the refusal.
        value = (
            _dscp_value(name, scalar)
            if name == "dscp"
            else _dscp_class_value(name, scalar)
        )
        return (f"{domain} dscp {_op(neg)}{_dscp_canon(value)}", None, None)
    if name == "tos":
        raise _tos_refusal("option", "tos")
    if name == "mark":
        # mod mark and mod connmark both spell their option `mark`; the
        # module tells the packet-mark selector from the ct one.
        selector = "ct mark" if option.module == "connmark" else "meta mark"
        masked = _masked_mark_expr(selector, scalar, neg)
        if masked is not None:
            return (masked, None, None)
        return (f"{selector} {_op(neg)}{_mark_value(scalar)}", None, None)
    if name in ("uid-owner", "gid-owner"):
        meta = "skuid" if name == "uid-owner" else "skgid"
        owner = _owner_value(name, scalar)
        return (f"meta {meta} {_op(neg)}{owner}", None, None)
    if name == "length":
        if ":" in scalar:
            low, _, high = scalar.partition(":")
            if low.isdigit() and high.isdigit():
                scalar = f"{low}-{high}"
            else:
                raise FermError(f"invalid length '{scalar}' for nft backend")
        elif not (scalar.isdigit() or _NUMERIC_RANGE_RE.match(scalar)):
            raise FermError(f"invalid length '{scalar}' for nft backend")
        return (f"meta length {_op(neg)}{scalar}", None, None)
    if name == "opcode":
        if not scalar.isdigit():
            raise FermError(f"invalid arp opcode '{scalar}' for nft backend")
        operation = _ARP_OPERATION_BY_NUMBER.get(int(scalar), scalar)
        return (f"arp operation {_op(neg)}{operation}", None, None)
    if name in _TTL_COMPARATOR and domain is not Family.IP6:
        # xt_ttl is ip-only (mod hl is its ip6 twin below), so the ip6
        # pass falls through to the generic refusal.
        if not scalar.isdigit():
            raise FermError(f"invalid ttl '{scalar}' for nft backend")
        return (
            f"ip ttl {_op(neg)}{_TTL_COMPARATOR[name]}{scalar}",
            None,
            None,
        )
    if name in _HL_COMPARATOR and domain is Family.IP6:
        # ip6t_hl is ip6-only; the ip pass falls through to the refusal.
        if not scalar.isdigit():
            raise FermError(f"invalid hl '{scalar}' for nft backend")
        return (
            f"ip6 hoplimit {_op(neg)}{_HL_COMPARATOR[name]}{scalar}",
            None,
            None,
        )
    if name == "mac-source":
        if not _MAC_RE.match(scalar):
            raise FermError(f"invalid mac '{scalar}' for nft backend")
        return (f"ether saddr {_op(neg)}{scalar.lower()}", None, None)
    if name in ("source-mac", "destination-mac"):
        # the arp family spells its MAC selectors arp saddr/daddr ether
        if not _MAC_RE.match(scalar):
            raise FermError(f"invalid mac '{scalar}' for nft backend")
        side = "saddr" if name == "source-mac" else "daddr"
        return (
            f"arp {side} ether {_op(neg)}{scalar.lower()}",
            None,
            None,
        )
    if name == "pkt-type":
        # Not set-eligible (icmp-type precedent): the packet-type words are
        # bare tokens with no rank in sort_set_elements.  xt's `unicast`
        # reads back from the kernel as `host`, so it is emitted as `host`.
        kind = _PKTTYPE_MAP.get(scalar)
        if kind is None:
            raise FermError(f"invalid pkttype '{scalar}' for nft backend")
        return (f"meta pkttype {_op(neg)}{kind}", None, None)
    if name == "mss":
        # mod tcpmss and the tcp proto option spell the same match; the
        # SYNPROXY companion of this name never reaches here (consumed by
        # the module-qualified companion pass).
        if protocol != "tcp":
            raise FermError(
                "option 'mss' needs a tcp protocol for the nft backend"
            )
        low, sep, high = scalar.partition(":")
        if sep and low.isdigit() and high.isdigit():
            operand = f"{low}-{high}"
        elif scalar.isdigit():
            operand = scalar
        else:
            raise FermError(f"invalid mss '{scalar}' for nft backend")
        return (
            f"tcp option maxseg size {_op(neg)}{operand}",
            None,
            None,
        )
    if name == "tcp-option":
        if protocol != "tcp":
            raise FermError(
                "option 'tcp-option' needs a tcp protocol for the nft backend"
            )
        if not scalar.isdigit() or int(scalar) > _TCP_OPTION_KIND_MAX:
            raise FermError(f"invalid tcp-option '{scalar}' for nft backend")
        kind = _TCP_OPTION_KIND.get(int(scalar), scalar)
        state = "missing" if neg else "exists"
        return (f"tcp option {kind} {state}", None, None)
    if name in ("src-range", "dst-range") and domain in (
        Family.IP,
        Family.IP6,
    ):
        # mod iprange address ranges; arp/eb have no saddr/daddr range and
        # fall through to the generic refusal.  Not set-eligible: a range is
        # a single interval operand, not a foldable member.
        side = "saddr" if name == "src-range" else "daddr"
        low, sep, high = scalar.partition("-")
        if not sep or not low or not high:
            raise FermError(f"invalid iprange '{scalar}' for the nft backend")
        low_addr = _iprange_bound(domain, low)
        high_addr = _iprange_bound(domain, high)
        return (
            f"{domain} {side} {_op(neg)}{low_addr}-{high_addr}",
            None,
            None,
        )
    raise FermError(f"option '{name}' not yet supported by nft backend")


def translate_match(
    domain: Family, option: RenderedOption, protocol: str | None
) -> str:
    """Translate one match option to an nft expression."""
    return _translate_match_parts(domain, option, protocol)[0]


def _match_selector(domain: Family, name: str, protocol: str | None) -> str:
    """
    Return the nft selector text for an address/interface/port keyword.

    The single source of the selector for :func:`_translate_match_parts`
    (which appends an operand) and :func:`_setref_selector` (which appends
    a set reference) -- previously two mirrored computations that could
    drift.  The port arm carries the shared tcp/udp guard.  Callers vet
    ``name`` against the keyword maps first; an unknown name here is an
    internal error.
    """
    if name in _ADDR_KEYWORD:
        return f"{domain} {_ADDR_KEYWORD[name]}"
    if name in _IFACE_KEYWORD:
        return _IFACE_KEYWORD[name]
    if name in _PORT_KEYWORD:
        if protocol not in PORT_PROTOCOLS:
            raise FermError(
                f"option '{name}' needs a tcp/udp protocol for the nft backend"
            )
        return f"{protocol} {_PORT_KEYWORD[name]}"
    raise internal_error()


def _setref_selector(domain: Family, name: str, protocol: str | None) -> str:
    """
    Return the nft selector left of a set reference (@name).

    Used in :func:`translate_rule` when the option value is a
    :class:`~pyferm.values.SetRef`.
    """
    if (
        name not in _ADDR_KEYWORD
        and name not in _IFACE_KEYWORD
        and name not in _PORT_KEYWORD
    ):
        raise FermError(f"option '{name}' cannot reference a named set")
    return _match_selector(domain, name, protocol)


#: ``mod set match-set`` direction flag -> nft address selector.
_MATCH_SET_FLAG: Final[dict[str, str]] = {"src": "saddr", "dst": "daddr"}

#: match-set's value is always ``Params([SetRef|name, flag])`` (the ``sc``
#: keyword code), so exactly two positional elements.
_MATCH_SET_PARAM_COUNT: Final[int] = 2


def _translate_match_set(domain: Family, value: Value) -> NftMatch:
    """
    Translate ``mod set match-set $x <dir>`` to an nft named-set match.

    The value is ``Params([SetRef, flag])`` (``PreNegated`` around it for the
    ``! match-set`` form).  Only a ferm-owned ``@set`` (a :class:`SetRef`)
    translates; a bare name is an external ipset -- a distinct kernel
    subsystem nft cannot reference across tables -- and refuses with a
    migration hint.  The comma-joined multi-flag form (``src,dst``) would need
    a concatenated set type that ``@set`` never declares, so it refuses too.
    The emitted :class:`NftMatch` carries the SetRef and its family-prefixed
    selector, the same shape the address arm produces, so
    :func:`_collect_set_declarations` picks up the declaration unchanged.
    """
    negated = False
    if isinstance(value, (Negated, PreNegated)):
        value = value.value
        negated = True
    if (
        not isinstance(value, Params)
        or len(value.values) != _MATCH_SET_PARAM_COUNT
    ):
        raise internal_error()
    operand, flags = value.values
    if not isinstance(operand, SetRef):
        raise FermError(
            f"option 'match-set': external ipset '{operand}' cannot be "
            f"referenced from nftables; declare it with @set ${operand} = "
            "(...) or keep the iptables backend"
        )
    if not isinstance(flags, str):
        raise internal_error()
    if "," in flags:
        raise FermError(
            "option 'match-set': multiple set-match flags need a "
            "concatenated set type that @set does not declare"
        )
    selector_tail = _MATCH_SET_FLAG.get(flags)
    if selector_tail is None:
        raise FermError(
            f"option 'match-set': unsupported set-match flag '{flags}' "
            "for the nft backend"
        )
    selector = f"{domain} {selector_tail}"
    expr = f"{selector} {_op(negated)}@{_validate_set_name(operand.name)}"
    return NftMatch(expr, set_key=None, setref=operand, set_selector=selector)
