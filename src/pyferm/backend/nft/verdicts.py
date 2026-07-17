"""Target translation: build_verdict, NAT/LOG/REJECT shapes, SET target."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Final

from ...domains import (
    ICMP6_REJECT_MAP,
    Family,
)
from ...errors import FermError, internal_error
from ...modules import TARGET_DEFS
from ...rules import (
    CORE_TARGETS,
    RenderedOption,
    is_netfilter_builtin_chain,
    is_netfilter_module_target,
)
from ...streams import BYTE_ENCODING
from ...values import (
    Params,
    SetRef,
)
from .chains import nft_chain_name
from .matches import (
    _CLASSID_RE,
    _HOPLIMIT_MAX,
    _MARK_MAX,
    _MATCH_SET_FLAG,
    _MATCH_SET_PARAM_COUNT,
    _NFLOG_GROUP_MAX,
    _TC_HANDLE_ROOT,
    _TCP_OPTION_KIND,
    _TCP_OPTION_KIND_MAX,
    _U16_MAX,
    _dscp_canon,
    _dscp_class_value,
    _dscp_value,
    _mark_value,
    _tos_refusal,
)
from .model import (
    NftObjectRef,
    NftReset,
    NftSetUpdate,
    NftStatement,
    NftVerdict,
    _addr_set_type,
    _bounded_uint,
    _is_ascii_uint,
    _nft_quote_string,
    _nft_time_canon,
    _validate_address,
    _validate_port,
    _validate_set_name,
    first_scalar,
    unwrap_value,
)


def _masked_mark_set(
    scalar: str,
    option_name: str = "tproxy-mark",
    register: str = "meta mark",
) -> str:
    """
    Spell a ``value[/mask]`` mark rewrite as an nft *register* assignment.

    Shared by TPROXY's ``--tproxy-mark`` and the MARK/CONNMARK ``set-xmark``
    forms (``register`` selects ``meta mark`` or ``ct mark``).  xt computes
    ``newmark = (mark & ~mask) ^ value``; the kernel canonicalizes the and/xor
    tree to an and/or form when ``value`` lies within ``mask`` (xor over zeroed
    bits is or), and the ``& A`` operand it prints already carries the ``| V``
    bits -- ``A = ~mask | value`` does, so the and/or emission round-trips.  A
    full mask (or the xt default when the mask is omitted) folds to a plain
    set.  A value with bits outside its mask has a different canonical form
    that would not round-trip, and a zero mask is an identity assignment; both
    refuse.
    """
    base, sep, mask = scalar.partition("/")
    if not sep:
        return f"{register} set {_mark_value(base)}"
    try:
        value = int(base, 0)
        mask_value = int(mask, 0)
    except ValueError:
        raise FermError(
            f"invalid {option_name} '{scalar}' for nft backend"
        ) from None
    if not (0 <= value <= _MARK_MAX and 0 <= mask_value <= _MARK_MAX):
        raise FermError(f"invalid {option_name} '{scalar}' for nft backend")
    if mask_value == 0:
        raise FermError(
            f"{option_name} '{scalar}' has a zero mask (a no-op) for nft "
            "backend"
        )
    if value & ~mask_value & _MARK_MAX:
        raise FermError(
            f"{option_name} '{scalar}' value has bits outside its mask for "
            f"nft backend"
        )
    if mask_value == _MARK_MAX:
        return f"{register} set {_mark_value(base)}"
    and_operand = (~mask_value | value) & _MARK_MAX
    if and_operand == _MARK_MAX and value != 0:
        return f"{register} set {register} | 0x{value:08x}"
    if value == 0:
        return f"{register} set {register} & 0x{and_operand:08x}"
    return f"{register} set {register} & 0x{and_operand:08x} | 0x{value:08x}"


def _setmark_effective(scalar: str) -> str:
    """
    Rewrite ``--set-mark value/mask`` to the xmark form the kernel compiles.

    xt's MARK/CONNMARK ``--set-mark`` clears then sets only the masked bits
    but does so with an EFFECTIVE mask ``m' = value | mask``, so a value with
    bits outside the literal mask (``0xff/0x0f``) is legal and its result is
    ``(mark & ~m') | value``.  Substituting ``m'`` before the and/or canon
    keeps the ``value`` within its mask, so the shared ``set-mark`` path never
    needs the ``value ⊄ mask`` guard.  A bare value (no mask) passes through
    to the plain-set path unchanged.
    """
    base, sep, mask = scalar.partition("/")
    if not sep:
        return scalar
    try:
        value = int(base, 0)
        mask_value = int(mask, 0)
    except ValueError:
        raise FermError(
            f"invalid set-mark '{scalar}' for nft backend"
        ) from None
    if not (0 <= value <= _MARK_MAX and 0 <= mask_value <= _MARK_MAX):
        raise FermError(f"invalid set-mark '{scalar}' for nft backend")
    return f"0x{value:x}/0x{value | mask_value:x}"


def _mark_arith_operand(option: RenderedOption) -> str:
    """Validate an and/or/xor-mark operand and spell it as 8-digit hex."""
    scalar, _ = unwrap_value(option.value)
    return _mark_value(scalar)


def _mark_arith_set(
    register: str, target: str, companions: dict[str, RenderedOption]
) -> str:
    """
    Spell one MARK/CONNMARK mark-arithmetic op as a *register* rewrite.

    Exactly one of ``set-mark``/``set-xmark``/``and-mark``/``or-mark``/
    ``xor-mark`` may be present (``provided != 1`` refuses with the target's
    own message); ``set-mark``/``set-xmark`` fold to the and/or canon (via
    :func:`_masked_mark_set`, with ``set-mark``'s effective mask applied
    first), and the bitwise ops emit ``<reg> set <reg> <op> 0x%08x`` in the
    kernel-readback spelling (``&``/``|``/``^``).
    """
    setmark = companions.get("set-mark")
    setxmark = companions.get("set-xmark")
    andmark = companions.get("and-mark")
    ormark = companions.get("or-mark")
    xormark = companions.get("xor-mark")
    provided = sum(
        option is not None
        for option in (setmark, setxmark, andmark, ormark, xormark)
    )
    if provided != 1:
        raise FermError(f"{target} target not yet supported by nft backend")
    if setxmark is not None:
        scalar, _ = unwrap_value(setxmark.value)
        return _masked_mark_set(scalar, "set-xmark", register)
    if setmark is not None:
        scalar, _ = unwrap_value(setmark.value)
        return _masked_mark_set(
            _setmark_effective(scalar), "set-mark", register
        )
    if andmark is not None:
        return f"{register} set {register} & {_mark_arith_operand(andmark)}"
    if ormark is not None:
        return f"{register} set {register} | {_mark_arith_operand(ormark)}"
    if (
        xormark is None
    ):  # narrowed by provided == 1; keep the checker convinced
        raise internal_error()
    return f"{register} set {register} ^ {_mark_arith_operand(xormark)}"


def _classify_priority(scalar: str) -> str:
    """
    Render a tc classid (H:M) as nft's ``meta priority`` readback spells it.

    Leading zeros strip in each half and it lowercases (00ff:0abc -> ff:abc);
    the tc specials ffff:ffff and 0:0 read back as root and none.  A half
    wider than four hex digits is rejected, mirroring the kernel.
    """
    matched = _CLASSID_RE.match(scalar)
    if matched is None:
        raise FermError(
            f"option 'set-class': invalid tc class '{scalar}' for nft backend"
        )
    major = int(matched.group(1), 16)
    minor = int(matched.group(2), 16)
    if major == _TC_HANDLE_ROOT and minor == _TC_HANDLE_ROOT:
        return "root"
    if major == 0 and minor == 0:
        return "none"
    return f"{major:x}:{minor:x}"


def _nfqueue_verdict(companions: dict[str, RenderedOption]) -> NftVerdict:
    """
    Spell NFQUEUE as nft's ``queue`` statement.

    The kernel reads ``queue num N`` back as ``queue [flags ...] to N``
    (flags in bypass,fanout order; a bare NFQUEUE as ``queue to 0``), so
    that form is emitted directly.  xt_NFQUEUE refuses --queue-cpu-fanout
    without --queue-balance, so the translation refuses too.
    """
    num = companions.get("queue-num")
    balance = companions.get("queue-balance")
    if num is not None and balance is not None:
        raise FermError(
            "'queue-num' and 'queue-balance' are mutually exclusive for "
            "the nft backend"
        )
    if "queue-cpu-fanout" in companions and balance is None:
        raise FermError(
            "option 'queue-cpu-fanout' needs 'queue-balance' for the "
            "nft backend"
        )
    if balance is not None:
        scalar, _ = unwrap_value(balance.value)
        low, sep, high = scalar.partition(":")
        if not (sep and _is_ascii_uint(low) and _is_ascii_uint(high)):
            raise FermError(
                f"invalid queue-balance '{scalar}' for nft backend"
            )
        to = f"{int(low)}-{int(high)}"
    elif num is not None:
        scalar, _ = unwrap_value(num.value)
        to = str(_bounded_uint(scalar, _U16_MAX, "queue-num"))
    else:
        to = "0"
    flags = [
        flag
        for companion_name, flag in (
            ("queue-bypass", "bypass"),
            ("queue-cpu-fanout", "fanout"),
        )
        if companion_name in companions
    ]
    parts = ["queue"]
    if flags:
        parts.append(f"flags {','.join(flags)}")
    parts.append(f"to {to}")
    return NftVerdict(" ".join(parts))


def _hoplimit_verdict(
    target_value: str, companions: dict[str, RenderedOption]
) -> NftVerdict:
    """
    Spell ``--ttl-set``/``--hl-set`` as an nft hop-limit rewrite.

    The readback canon is ``ip ttl set N`` / ``ip6 hoplimit set N``.
    nft's payload-set grammar has no arithmetic form, so the inc/dec
    variants refuse.
    """
    prefix = "ttl" if target_value == "TTL" else "hl"
    for arith in (f"{prefix}-inc", f"{prefix}-dec"):
        if arith in companions:
            raise FermError(
                f"option '{arith}' not yet supported by nft backend"
            )
    comp = companions.get(f"{prefix}-set")
    if comp is None:
        raise FermError(
            f"{target_value} target not yet supported by nft backend"
        )
    scalar, _ = unwrap_value(comp.value)
    value = _bounded_uint(scalar, _HOPLIMIT_MAX, f"{prefix}-set")
    selector = "ip ttl" if target_value == "TTL" else "ip6 hoplimit"
    return NftVerdict(f"{selector} set {value}")


def _synproxy_verdict(companions: dict[str, RenderedOption]) -> NftVerdict:
    """
    Spell SYNPROXY as nft's ``synproxy`` statement.

    The kernel readback prints the parts in a fixed order (mss, wscale,
    timestamp, sack-perm) and prints mss/wscale as a PAIR whenever either
    is given: the nft frontend raises both kernel flags together, so the
    absent one reads back as 0 -- verified live; the pair is emitted to
    match.  nft's synproxy grammar has no --ecn twin.
    """
    if "ecn" in companions:
        raise FermError("option 'ecn' has no nft synproxy equivalent")
    parts = ["synproxy"]
    mss = companions.get("mss")
    wscale = companions.get("wscale")
    if mss is not None or wscale is not None:
        for label, comp in (("mss", mss), ("wscale", wscale)):
            scalar = "0" if comp is None else unwrap_value(comp.value)[0]
            value = _bounded_uint(scalar, _U16_MAX, f"synproxy {label}")
            parts.append(f"{label} {value}")
    if "timestamp" in companions:
        parts.append("timestamp")
    if "sack-perm" in companions:
        parts.append("sack-perm")
    return NftVerdict(" ".join(parts))


def _tproxy_verdict(
    domain: Family,
    companions: dict[str, RenderedOption],
    *,
    has_transport: bool,
) -> NftVerdict:
    """
    Spell TPROXY as nft's ``tproxy`` statement plus a terminal accept.

    xt_TPROXY needs a transport match (the kernel rejects the applied rule
    without one) and always demands ``--on-port`` (the xt oracle refuses a
    bare or on-ip-only form).  The readback keeps a bare on-port as
    ``tproxy to :P``, an on-ip mapping as ``tproxy to A:P`` (bracketed for
    ip6), and a ``--tproxy-mark`` as a following mark rewrite.  xt_TPROXY
    returns NF_ACCEPT, so a terminal accept is appended; the whole thing is
    one composite verdict statement (the NFQUEUE/SYNPROXY precedent).
    """
    if not has_transport:
        raise FermError(
            "TPROXY needs a transport protocol match (tcp/udp) for the "
            "nft backend"
        )
    on_port = companions.get("on-port")
    if on_port is None:
        raise FermError("TPROXY needs 'on-port' for the nft backend")
    port_scalar = first_scalar(on_port.value)
    port = str(_bounded_uint(port_scalar, _U16_MAX, "on-port"))
    on_ip = companions.get("on-ip")
    if on_ip is None:
        destination = f":{port}"
    else:
        addr = _validate_address(first_scalar(on_ip.value))
        destination = (
            f"[{addr}]:{port}" if domain is Family.IP6 else f"{addr}:{port}"
        )
    parts = [f"tproxy to {destination}"]
    mark = companions.get("tproxy-mark")
    if mark is not None:
        parts.append(_masked_mark_set(first_scalar(mark.value)))
    parts.append("accept")
    return NftVerdict(" ".join(parts))


#: built-in nat chain -> the address side xt NETMAP rewrites on its hook
#: (prerouting/output rewrite the destination, postrouting/input the
#: source).
_NETMAP_SIDE: Final[dict[str, str]] = {
    "PREROUTING": "daddr",
    "OUTPUT": "daddr",
    "INPUT": "saddr",
    "POSTROUTING": "saddr",
}


def _netmap_network(
    scalar: str, domain: Family
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """
    Parse a strict CIDR network of *domain*'s family, else a plain error.

    xt NETMAP silently masks host bits out of ``--to``; the nft map form
    spells the network literally, so a host-bit operand (or a bare
    address without a prefix length) refuses instead of being rewritten.
    """
    if "/" not in scalar:
        raise FermError(
            f"NETMAP prefix '{scalar}' needs an explicit prefix length "
            f"for the nft backend"
        )
    try:
        network = ipaddress.ip_network(scalar, strict=True)
    except ValueError as exc:
        raise FermError(f"NETMAP prefix '{scalar}': {exc}") from None
    if network.version != (4 if domain is Family.IP else 6):
        raise FermError(
            f"NETMAP prefix '{scalar}' does not match the {domain} family"
        )
    return network


def _netmap_verdict(
    domain: Family,
    table: str,
    chain: str | None,
    companions: dict[str, RenderedOption],
    options: list[RenderedOption],
) -> NftVerdict:
    """
    Spell NETMAP as nft's prefix-to-prefix NAT map.

    The readback canon is ``dnat ip prefix to ip daddr map { A : B }``.
    The nft map form needs the original prefix as its key, so the rule
    must carry a same-side address match of the same prefix length; and
    the hook side is only known statically inside a built-in nat chain
    (a custom chain can be jumped from either side).
    """
    side = _NETMAP_SIDE.get(chain or "") if table == "nat" else None
    if side is None:
        raise FermError(
            "NETMAP translates only inside a built-in nat chain "
            "(PREROUTING/OUTPUT rewrite the destination, "
            "POSTROUTING/INPUT the source) for the nft backend"
        )
    comp = companions.get("to")
    if comp is None:
        raise FermError("NETMAP target not yet supported by nft backend")
    match_name = "destination" if side == "daddr" else "source"
    operands = [o for o in options if o.name == match_name]
    if len(operands) != 1:
        raise FermError(
            f"NETMAP needs exactly one '{match_name}' match to name the "
            f"mapped prefix for the nft backend"
        )
    original, neg = unwrap_value(operands[0].value)
    if neg:
        raise FermError(
            f"NETMAP cannot map a negated '{match_name}' match for the "
            f"nft backend"
        )
    to_scalar, _ = unwrap_value(comp.value)
    original_net = _netmap_network(original, domain)
    to_net = _netmap_network(to_scalar, domain)
    if original_net.prefixlen != to_net.prefixlen:
        raise FermError(
            f"NETMAP prefix lengths differ ('{original}' vs '{to_scalar}') "
            f"for the nft backend"
        )
    statement = "dnat" if side == "daddr" else "snat"
    return NftVerdict(
        f"{statement} {domain} prefix to {domain} {side} "
        f"map {{ {original_net} : {to_net} }}"
    )


def _set_target_operand(option: RenderedOption) -> tuple[SetRef, str]:
    """
    Unpack an ``add-set``/``del-set`` companion to (SetRef, selector tail).

    The value shape is match-set's (``sc``-coded ``Params([SetRef|name,
    flags])``), and so are the refusals: an external ipset name and the
    comma-joined multi-flag form have no @set translation.  The registry
    marks neither option negatable, so a Negated wrapper is a wiring bug.
    """
    value = option.value
    if (
        not isinstance(value, Params)
        or len(value.values) != _MATCH_SET_PARAM_COUNT
    ):
        raise internal_error()
    operand, flags = value.values
    if not isinstance(operand, SetRef):
        raise FermError(
            f"option '{option.name}': external ipset '{operand}' cannot be "
            f"referenced from nftables; declare it with @set ${operand} = "
            "() or keep the iptables backend"
        )
    if not isinstance(flags, str):
        raise internal_error()
    if "," in flags:
        raise FermError(
            f"option '{option.name}': multiple SET target flags need a "
            "concatenated set type that @set does not declare"
        )
    selector_tail = _MATCH_SET_FLAG.get(flags)
    if selector_tail is None:
        raise FermError(
            f"option '{option.name}': unsupported SET target flag "
            f"'{flags}' for the nft backend"
        )
    return operand, selector_tail


def _set_target_statement(
    domain: Family, companions: dict[str, RenderedOption]
) -> NftSetUpdate:
    """
    Translate the SET target to an ``add/update/delete @set`` statement.

    The xt_set mapping is exact: a plain ``add-set`` neither refreshes an
    existing entry's timeout (nft ``add`` is a no-op on a present element),
    ``add-set`` + ``exist`` refreshes it (nft ``update`` is add-or-refresh),
    and ``del-set`` removes it (a packet-path ``delete`` of an absent
    element is a no-op on both sides).  ``timeout N`` becomes the element
    timeout in the kernel readback spelling (``90`` -> ``1m30s``); xt's
    ``timeout 0`` means a permanent entry, which is exactly an nft element
    without a timeout.  The mutated set must be a config-empty ferm
    ``@set``: a dynamic declaration never emits config elements, and
    ``--plan`` compares dynamic sets on (type, flags) alone, so declared
    elements would silently never install.
    """
    add = companions.get("add-set")
    delete = companions.get("del-set")
    # add-set alongside del-set needs no guard here: each carries a set
    # reference, so the one-named-set-per-rule guard already refused.
    primary = add if add is not None else delete
    if primary is None:
        raise FermError(
            "SET target needs 'add-set' or 'del-set' for the nft backend"
        )
    setref, selector_tail = _set_target_operand(primary)
    if setref.elements:
        raise FermError(
            f"SET target set '{setref.name}' is a runtime bucket and must "
            "be declared empty (@set $x = ()) for the nft backend"
        )
    name = _validate_set_name(setref.name)
    timeout: str | None = None
    if delete is not None:
        for extra in ("timeout", "exist"):
            if extra in companions:
                raise FermError(
                    f"SET target option '{extra}' is only valid with 'add-set'"
                )
        verb = "delete"
    else:
        verb = "update" if "exist" in companions else "add"
        comp = companions.get("timeout")
        if comp is not None:
            scalar, _ = unwrap_value(comp.value)
            if not _is_ascii_uint(scalar):
                raise FermError(
                    f"invalid SET timeout '{scalar}' for nft backend"
                )
            seconds = int(scalar)
            if seconds > 0:
                timeout = _nft_time_canon(seconds * 1000)
    set_type = _addr_set_type(domain)
    return NftSetUpdate(
        name,
        f"{domain} {selector_tail}",
        set_type,
        timeout=timeout,
        verb=verb,
        owned=False,
    )


#: target VALUE -> nft verdict; QUEUE is core, REJECT is not.  Derived from
#: :data:`CORE_TARGETS` so the two cannot drift; every core target lower-cases
#: to its nft spelling (ACCEPT->accept, ...), preserving insertion order.
_VERDICT_TARGET: Final[dict[str, str]] = {
    target: target.lower() for target in CORE_TARGETS
}

#: The ebtables NAT targets ``translate_rule`` intercepts (it holds the
#: chain name, which the placement check below needs and
#: :func:`build_verdict` does not see -- the NETMAP precedent) and
#: translates via :func:`_eb_nat_statement`; they never reach
#: :func:`build_verdict`.
_EB_NAT_TARGETS: Final[frozenset[str]] = frozenset({"snat", "dnat"})

#: eb NAT target -> (builtin nat chains it is legal in, ether field,
#: MAC companion name).  ebtables restricts the placement (man ebtables:
#: snat only in nat/POSTROUTING, dnat only in nat/PREROUTING|OUTPUT) and
#: the legacy kernel enforces it with hook masks at insert time, so a
#: rule elsewhere can never apply on the ebtables path; a user chain's
#: hook side is statically unknown (the NETMAP precedent), so it
#: refuses too.
_EB_NAT_SPEC: Final[dict[str, tuple[tuple[str, ...], str, str]]] = {
    "snat": (("POSTROUTING",), "saddr", "to-source"),
    "dnat": (("PREROUTING", "OUTPUT"), "daddr", "to-destination"),
}

#: ebtables ``--snat-target``/``--dnat-target`` operand -> nft verdict.
#: The emitted text is the VALUE of this dict (a canonical constant,
#: the :data:`_VERDICT_TARGET` pattern), never a transform of the config
#: string -- the verdict lands unquoted in the nft script.
_EB_NAT_VERDICT: Final[dict[str, str]] = {
    "ACCEPT": "accept",
    "DROP": "drop",
    "CONTINUE": "continue",
    "RETURN": "return",
}

#: A colon-separated MAC as ebtables and arptables accept it: 1-2 hex
#: digits per octet.  \A...\Z anchoring is a security invariant -- the
#: canon below is the only barrier between the config string and the nft
#: script (``$`` would match before a trailing newline).
_MAC_CANON_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[0-9A-Fa-f]{1,2}(?::[0-9A-Fa-f]{1,2}){5}\Z"
)

#: ebtables target keywords with no nft bridge-family translation
#: (``modules.py`` ``target_x("eb", ...)`` minus the NAT pair): they are
#: targets, never user chains, so :func:`build_verdict` refuses them
#: explicitly.  The parser rewrites the eb ``MARK`` keyword to ebtables'
#: ``mark`` spelling before it reaches the backend, so both forms are
#: guarded.
_EB_REFUSED_TARGETS: Final[frozenset[str]] = frozenset(
    {"arpreply", "redirect", "MARK", "mark"}
)


def _mac_canon(scalar: str) -> str:
    """
    Canonicalize a MAC operand to the kernel readback spelling.

    The readback prints lowercase octets zero-padded to two hex digits
    (ebtables-translate emits them unpadded and arptables-translate
    sign-extends them into garbage -- both a phantom ``--plan`` diff),
    so the result is rebuilt from the parsed octets rather than
    lower-casing the input; ebtables and arptables accept 1-2 digits per
    octet.  Anything else -- mask suffix, dash separators (nft itself
    would swallow those, the legacy tools would not), stray whitespace --
    refuses.
    """
    if not _MAC_CANON_RE.match(scalar):
        raise FermError(f"invalid mac '{scalar}' for nft backend")
    return ":".join(f"{int(octet, 16):02x}" for octet in scalar.split(":"))


def _eb_nat_statement(
    table: str,
    chain: str | None,
    target_value: str,
    companions: dict[str, RenderedOption],
) -> NftVerdict:
    """
    Translate the ebtables snat/dnat target to ``ether <field> set``.

    The shape is the ebtables-translate one, verified live against the
    kernel readback: rewrite first, then the ``--snat-target``/
    ``--dnat-target`` verdict (``accept`` when absent, ebtables'
    default).  ``snat-arp`` refuses -- nft cannot rewrite the ARP
    payload, and silently dropping that half would make the rule do
    less than the config asked.  Always translates or raises; there is
    no fall-through to a user-chain jump.
    """
    chains, field, mac_name = _EB_NAT_SPEC[target_value]
    if table != "nat" or chain not in chains:
        places = " or ".join(f"nat/{name}" for name in chains)
        raise FermError(
            f"eb {target_value} translates only inside the built-in "
            f"{places} chain for the nft backend"
        )
    if "snat-arp" in companions:
        raise FermError(
            "option 'snat-arp' has no nft equivalent (nft cannot rewrite "
            "the ARP payload); use the iptables backend for this rule"
        )
    comp = companions.get(mac_name)
    if comp is None:
        raise FermError(
            f"eb {target_value} needs '{mac_name}' for the nft backend"
        )
    scalar, _ = unwrap_value(comp.value)
    mac = _mac_canon(scalar)
    verdict = "accept"
    target_comp = companions.get(f"{target_value}-target")
    if target_comp is not None:
        operand, _ = unwrap_value(target_comp.value)
        mapped = _EB_NAT_VERDICT.get(operand)
        if mapped is None:
            raise FermError(
                f"invalid {target_value}-target '{operand}' for the "
                f"nft backend"
            )
        verdict = mapped
    return NftVerdict(f"ether {field} set {mac} {verdict}")


#: arptables ``--mangle-target`` operand -> nft verdict suffix.  NOT
#: :data:`_EB_NAT_VERDICT`: arptables accepts only these three (RETURN
#: is "bad target for --mangle-target" even though the nft kernel would
#: take ``return``), and it spells CONTINUE as NO verdict -- the rule
#: ends at ``set ...``, the rewrites run, then rule processing falls
#: through.  The kernel readback preserves the written form, so the
#: empty value means "emit no verdict token".
_ARP_MANGLE_VERDICT: Final[dict[str, str]] = {
    "ACCEPT": "accept",
    "DROP": "drop",
    "CONTINUE": "",
}

#: arp mangle rewrite companion -> nft field expression, in the
#: arptables-translate emission order (saddr ip, saddr ether, daddr ip,
#: daddr ether).  The kernel readback preserves the written order
#: verbatim, so this fixed order round-trips into itself under --plan.
_ARP_MANGLE_REWRITES: Final[tuple[tuple[str, str], ...]] = (
    ("mangle-ip-s", "arp saddr ip set"),
    ("mangle-mac-s", "arp saddr ether set"),
    ("mangle-ip-d", "arp daddr ip set"),
    ("mangle-mac-d", "arp daddr ether set"),
)

#: every arp mangle companion option; ``translate_rule`` refuses an arp
#: rule that carries one of these under any target other than ``mangle``
#: (their _TARGET_COMPANIONS registration takes them out of the match
#: path, so silently ignoring them there would be fail-open).
_ARP_MANGLE_COMPANIONS: Final[frozenset[str]] = frozenset(
    {name for name, _ in _ARP_MANGLE_REWRITES} | {"mangle-target"}
)

#: The arptables-translate sanity guards: arpt_mangle.c assumes hln/pln
#: "were checked in the match", so the target only mangles a valid
#: Ethernet/IPv4 ARP packet.  ``translate_rule`` prepends them as the
#: rule's FIRST match: nft merges adjacent arp payload loads and prints
#: the fields in header-offset order (htype 0-1, hlen 4, plen 5 sit
#: below operation 6-7), so appending them after an ``arp operation``
#: match would read back reordered -- a phantom ``--plan`` diff,
#: verified live.
_ARP_MANGLE_GUARDS: Final[str] = "arp htype 1 arp hlen 6 arp plen 4"


def _arp_mangle_statement(
    companions: dict[str, RenderedOption],
) -> NftVerdict | None:
    """
    Translate the arptables mangle target to ``arp ... set`` rewrites.

    The shape is the arptables-translate one, verified live against the
    kernel readback: the rewrites in canonical order, then the
    ``--mangle-target`` verdict (``accept`` when absent, arptables'
    default; CONTINUE is the empty form -- with no rewrites either the
    whole tail vanishes and only the :data:`_ARP_MANGLE_GUARDS` match
    remains, hence ``None``).  A bare ``jump mangle`` is a legal no-op:
    guards plus the default verdict.  Always translates or raises;
    there is no fall-through to a user-chain jump (arptables reads
    ``-j mangle`` as the target unconditionally, so a user chain of
    that name is unreachable on the oracle side too).
    """
    parts: list[str] = []
    for name, field in _ARP_MANGLE_REWRITES:
        comp = companions.get(name)
        if comp is None:
            continue
        scalar, _ = unwrap_value(comp.value)
        if name.startswith("mangle-ip"):
            # Strictly an IPv4 literal: IPv4Address rejects leading
            # zeros, hex/int forms and ip6 colons (_validate_address
            # would let an ip6 literal through into an arp rewrite).
            # A hostname resolves before it gets here.
            try:
                value = str(ipaddress.IPv4Address(scalar))
            except ValueError:
                raise FermError(
                    f"invalid arp mangle ip '{scalar}' for nft backend"
                ) from None
        else:
            value = _mac_canon(scalar)
        parts.append(f"{field} {value}")
    verdict = "accept"
    target_comp = companions.get("mangle-target")
    if target_comp is not None:
        operand, _ = unwrap_value(target_comp.value)
        mapped = _ARP_MANGLE_VERDICT.get(operand)
        if mapped is None:
            raise FermError(
                f"invalid mangle-target '{operand}' for the nft backend"
            )
        verdict = mapped
    if verdict:
        parts.append(verdict)
    if not parts:
        return None
    return NftVerdict(" ".join(parts))


#: iptables ``reject-with`` canonical name -> nft reject spec, ip family.
#: Covers every type ``iptables -j REJECT`` accepts; the short aliases
#: (``net-unreach`` ...) resolve to these keys via :data:`_REJECT_ALIAS`.
#: nft spells iptables ``icmp-proto-unreachable`` as ``prot-unreachable``
#: (verified against nft v1.1.6).
_REJECT_WITH: Final[dict[str, str]] = {
    "icmp-net-unreachable": "reject with icmp type net-unreachable",
    "icmp-host-unreachable": "reject with icmp type host-unreachable",
    "icmp-proto-unreachable": "reject with icmp type prot-unreachable",
    "icmp-port-unreachable": "reject with icmp type port-unreachable",
    "icmp-net-prohibited": "reject with icmp type net-prohibited",
    "icmp-host-prohibited": "reject with icmp type host-prohibited",
    "icmp-admin-prohibited": "reject with icmp type admin-prohibited",
    "tcp-reset": "reject with tcp reset",
}

#: iptables ip-family short alias -> canonical :data:`_REJECT_WITH` key.
_REJECT_ALIAS: Final[dict[str, str]] = {
    "net-unreach": "icmp-net-unreachable",
    "host-unreach": "icmp-host-unreachable",
    "proto-unreach": "icmp-proto-unreachable",
    "port-unreach": "icmp-port-unreachable",
    "net-prohib": "icmp-net-prohibited",
    "host-prohib": "icmp-host-prohibited",
    "admin-prohib": "icmp-admin-prohibited",
    "tcp-rst": "tcp-reset",
}

#: ip6 ``reject-with`` canonical name -> nft reject spec (icmpv6 types plus
#: the family-agnostic tcp reset).  Covers every type ``ip6tables -j REJECT``
#: accepts; short aliases resolve via :data:`_REJECT_ALIAS_IP6`.
_REJECT_WITH_IP6: Final[dict[str, str]] = {
    "icmp6-no-route": "reject with icmpv6 type no-route",
    "icmp6-adm-prohibited": "reject with icmpv6 type admin-prohibited",
    "icmp6-addr-unreachable": "reject with icmpv6 type addr-unreachable",
    "icmp6-port-unreachable": "reject with icmpv6 type port-unreachable",
    "icmp6-policy-fail": "reject with icmpv6 type policy-fail",
    "icmp6-reject-route": "reject with icmpv6 type reject-route",
    "tcp-reset": "reject with tcp reset",
}

#: ip6 short alias -> canonical :data:`_REJECT_WITH_IP6` key.
_REJECT_ALIAS_IP6: Final[dict[str, str]] = {
    "no-route": "icmp6-no-route",
    "adm-prohibited": "icmp6-adm-prohibited",
    "addr-unreach": "icmp6-addr-unreachable",
    "port-unreach": "icmp6-port-unreachable",
    "policy-fail": "icmp6-policy-fail",
    "reject-route": "icmp6-reject-route",
}

#: The error a port-bearing NAT verdict raises without a transport match
#: nft would reject the applied script, so fail at translate.
_NAT_PORT_NEEDS_PROTO: Final[str] = (
    "NAT to a port needs a tcp/udp protocol match for the nft backend"
)

#: iptables ``--log-level`` spelling (name or syslog number) -> nft level
#: keyword.  nft's default level (``warn``) is dropped by the kernel
#: readback, so :func:`build_verdict` omits it from the emission.
_LOG_LEVEL_MAP: Final[dict[str, str]] = {
    "emerg": "emerg",
    "panic": "emerg",
    "0": "emerg",
    "alert": "alert",
    "1": "alert",
    "crit": "crit",
    "2": "crit",
    "error": "err",
    "err": "err",
    "3": "err",
    "warning": "warn",
    "warn": "warn",
    "4": "warn",
    "notice": "notice",
    "5": "notice",
    "info": "info",
    "6": "info",
    "debug": "debug",
    "7": "debug",
}


def _nat_has_port(domain: Family, operand: str) -> bool:
    """
    Return whether a NAT address operand carries a ``:port``.

    nft accepts an ``addr:port`` mapping only after a transport match.  In an
    IPv4 family any ``:`` is the port separator.  An IPv6 host carries its own
    ``:`` colons, so those must NOT count as a port (else a port-less
    ``dnat to fe80::1`` would falsely demand a transport match); a port is
    bracketed (``[2001:db8::1]:80``), i.e. a ``]:``.  That bracketed form is
    in practice already rejected upstream by :func:`_validate_address` (the
    ``[``/``]`` are not in ``_NFT_ADDR_RE``), so the ``]:`` arm is defensive;
    the load-bearing case is the ip6 ``return False`` that avoids the false
    positive on a plain IPv6 host.
    """
    if domain is Family.IP6:
        return "]:" in operand
    return ":" in operand


def _reject_for(domain: Family, scalar: str) -> str:
    if domain is Family.IP6:
        # normalize an ip4 reject spelling written in an ip6 domain before
        # the ip6 lookup (shared oracle ip4->icmp6 alias set)
        scalar = ICMP6_REJECT_MAP.get(scalar, scalar)
        scalar = _REJECT_ALIAS_IP6.get(scalar, scalar)
        spec = _REJECT_WITH_IP6.get(scalar)
    else:
        scalar = _REJECT_ALIAS.get(scalar, scalar)
        spec = _REJECT_WITH.get(scalar)
    if spec is None:
        raise FermError(
            f"reject-with '{scalar}' not yet supported by nft backend"
        )
    return spec


def _nflog_verdict(companions: dict[str, RenderedOption]) -> NftVerdict:
    """
    NFLOG shape: nft ``log group N`` with optional prefix/threshold.

    Field order follows the kernel readback (prefix, group,
    queue-threshold) so an applied rule reads back byte-identically.
    ``--nflog-range`` is accepted-but-ignored by xt_NFLOG; there is no
    honest nft spelling for it, so it refuses rather than mistranslate
    to ``snaplen``.  A missing group keeps xt_NFLOG's default 0.
    """
    if "nflog-range" in companions:
        raise FermError(
            "option 'nflog-range' not yet supported by nft backend"
        )
    parts = ["log"]
    prefix = companions.get("nflog-prefix")
    if prefix is not None:
        scalar, _ = unwrap_value(prefix.value)
        parts.append(f"prefix {_nft_quote_string(scalar)}")
    group_num = "0"
    group = companions.get("nflog-group")
    if group is not None:
        scalar, _ = unwrap_value(group.value)
        _bounded_uint(scalar, _NFLOG_GROUP_MAX, "nflog-group")
        group_num = scalar
    parts.append(f"group {group_num}")
    threshold = companions.get("nflog-threshold")
    if threshold is not None:
        scalar, _ = unwrap_value(threshold.value)
        if not _is_ascii_uint(scalar) or int(scalar) == 0:
            raise FermError(
                f"invalid nflog-threshold '{scalar}' for nft backend"
            )
        parts.append(f"queue-threshold {scalar}")
    return NftVerdict(" ".join(parts))


#: xt NAT flag option -> nft spelling, in the fixed kernel-readback order
#: (random / fully-random first, persistent last).  ``--random-fully`` is
#: the xt spelling of nft's ``fully-random``.
_NAT_FLAG_SPELLING: Final[tuple[tuple[str, str], ...]] = (
    ("random", "random"),
    ("random-fully", "fully-random"),
    ("persistent", "persistent"),
)


def _nat_flags(companions: dict[str, RenderedOption]) -> str:
    """
    Spell the NAT flag companions as an nft suffix (``""`` when none).

    xt's ``--random`` / ``--random-fully`` / ``--persistent`` read back from
    nft in a fixed order, comma-joined with no surrounding space; the
    returned string carries a single leading space so a caller appends it
    unconditionally.
    """
    flags = [
        spelling
        for option_name, spelling in _NAT_FLAG_SPELLING
        if option_name in companions
    ]
    return f" {','.join(flags)}" if flags else ""


def _nat_to_ports(
    verb: str,
    companions: dict[str, RenderedOption],
    *,
    has_transport: bool,
) -> NftVerdict:
    """
    MASQUERADE/REDIRECT shape: an OPTIONAL ``to-ports`` companion.

    Without one the bare verb is a complete statement (unlike the
    SNAT/DNAT shape, which raises); with one, a transport match is
    required first (nft would reject the applied script).  NAT flags append
    to both forms, so a flag-only ``masquerade random`` still emits.
    """
    flags = _nat_flags(companions)
    comp = companions.get("to-ports")
    if comp is not None:
        if not has_transport:
            raise FermError(_NAT_PORT_NEEDS_PROTO)
        port = _validate_port(first_scalar(comp.value))
        return NftVerdict(f"{verb} to :{port}{flags}")
    return NftVerdict(f"{verb}{flags}")


def _nat_to_addr(
    verb: str,
    target: str,
    comp_key: str,
    domain: Family,
    companions: dict[str, RenderedOption],
    *,
    has_transport: bool,
) -> NftVerdict:
    """
    SNAT/DNAT shape: a MANDATORY address companion (raises without one).

    A port-bearing address mapping additionally requires a transport
    match, mirroring the to-ports shape's guard.
    """
    comp = companions.get(comp_key)
    if comp is None:
        raise FermError(f"{target} target not yet supported by nft backend")
    addr = _validate_address(first_scalar(comp.value))
    if _nat_has_port(domain, addr) and not has_transport:
        raise FermError(_NAT_PORT_NEEDS_PROTO)
    return NftVerdict(f"{verb} to {addr}{_nat_flags(companions)}")


#: nft conntrack zones are a 16-bit id (verified live: 65536 -> range error).
_CT_ZONE_MAX: Final[int] = 0xFFFF

#: xt_CT ctevents names -> nft ct-event bits, in nft's canonical readback
#: order (verified live: a fully-reversed input reorders to exactly this).
#: xt names with no nft event bit (helper/mark/natseqinfo/secmark) are absent,
#: so a rule naming one refuses rather than silently dropping it.
_CT_EVENT_ORDER: Final[tuple[str, ...]] = (
    "new",
    "related",
    "destroy",
    "reply",
    "assured",
    "protoinfo",
    "label",
)
_CT_EVENT_RANK: Final[dict[str, int]] = {
    name: rank for rank, name in enumerate(_CT_EVENT_ORDER)
}


def _ct_zone_value(name: str, scalar: str) -> str:
    """Validate a CT-target zone id (0-65535), returning its decimal canon."""
    # `_is_ascii_uint(str)` is true for non-ASCII digits (e.g. the latin-1
    # superscripts b2/b3/b9 a config's latin-1 bytes decode to) that int()
    # then rejects; the isascii() guard turns that into a clean refusal
    # instead of a ValueError traceback.
    if not _is_ascii_uint(scalar):
        raise FermError(f"invalid CT {name} '{scalar}' for nft backend")
    if int(scalar) > _CT_ZONE_MAX:
        raise FermError(
            f"CT {name} '{scalar}' exceeds 0-65535 for the nft backend"
        )
    return str(int(scalar))


def _ct_event_canon(option: RenderedOption) -> str:
    """
    Map an xt_CT ``ctevents`` array to nft's canonical event-bit list.

    The ``=c`` array reaches us comma-joined.  Every member must have an nft
    event bit; the first that does not refuses the whole rule (no partial
    emission -- dropping an event would silently narrow what fires).  The
    survivors emit deduplicated in :data:`_CT_EVENT_ORDER`, the order nft
    prints, so a ``--plan`` over an unchanged ruleset converges.
    """
    scalar, neg = unwrap_value(option.value)
    if neg:
        raise FermError("CT 'ctevents' cannot be negated for the nft backend")
    members = [token.strip() for token in scalar.split(",") if token.strip()]
    if not members:
        raise FermError(
            "CT 'ctevents' needs at least one event for the nft backend"
        )
    for member in members:
        if member not in _CT_EVENT_RANK:
            raise FermError(f"CT event '{member}' has no nft equivalent")
    ordered = sorted(set(members), key=_CT_EVENT_RANK.__getitem__)
    return ",".join(ordered)


#: xt conntrack-helper name -> the single L4 protocol its nft ``ct helper``
#: object binds (verified live against kernel 6.18.38: each name loads with
#: exactly this transport).  ``sip`` and ``h323`` are absent on purpose:
#: ``sip`` registers for BOTH tcp and udp (a single-protocol object would
#: silently cover only one transport -- a fail-open narrowing), and ``h323``
#: exposes no loadable ct-helper object (``type "h323"`` is ENOENT).  A name
#: outside this map refuses rather than emit an object the kernel rejects.
_CT_HELPER_PROTO: Final[dict[str, str]] = {
    "ftp": "tcp",
    "irc": "tcp",
    "sane": "tcp",
    "pptp": "tcp",
    "tftp": "udp",
    "amanda": "udp",
    "snmp": "udp",
    "netbios-ns": "udp",
}


def _ct_helper_object(helper: RenderedOption) -> NftObjectRef:
    """
    Build the ``ct helper`` object-ref statement for a ``CT helper <name>``.

    nft models an assigned conntrack helper as a table ``ct helper`` object
    declaring the helper's name and L4 protocol, referenced by
    ``ct helper set "<obj>"``.  The object is content-addressed: the helper
    name fixes the protocol (:data:`_CT_HELPER_PROTO`), so two sightings dedup
    and :func:`diff_tables` compares by name alone -- which sidesteps the
    ``l3proto`` line the kernel adds on readback but the save form omits.  The
    object name is ``cthelper_<name>`` with dashes folded to underscores
    (``netbios-ns`` -> ``cthelper_netbios_ns``) so it satisfies the nft
    bare-identifier grammar the readback validates.  A helper nft cannot model
    with one protocol refuses rather than narrow the rule (the SECMARK object
    precedent for a statement that carries a declaration).
    """
    name, neg = unwrap_value(helper.value)
    if neg:
        raise FermError("CT 'helper' cannot be negated for the nft backend")
    if not name:
        raise FermError(
            "CT target option 'helper' needs a helper name for the nft backend"
        )
    proto = _CT_HELPER_PROTO.get(name)
    if proto is None:
        supported = ", ".join(sorted(_CT_HELPER_PROTO))
        raise FermError(
            f"CT helper '{name}' has no single-protocol nft ct-helper object "
            f"(supported: {supported}); use the iptables backend for this rule"
        )
    obj_name = "cthelper_" + name.replace("-", "_")
    return NftObjectRef(
        kind="ct helper",
        name=obj_name,
        body=f"type {_nft_quote_string(name)} protocol {proto};",
        rule_expr=f"ct helper set {_nft_quote_string(obj_name)}",
    )


def _ct_target_statements(
    companions: dict[str, RenderedOption],
) -> list[NftStatement]:
    """
    Translate the CT target's options into an ordered nft statement list.

    xt_CT carries several independent knobs on one rule; each maps to its own
    nft statement.  ``expevents`` and ``timeout`` have no nft equivalent
    (``ct expectation event set`` is a syntax error; a timeout policy needs a
    ``ct timeout`` object this batch does not build), so they refuse UP FRONT,
    before any statement is emitted -- a rule mixing one with a translatable
    option (``CT helper ftp timeout ...``) must fail cleanly, never silently
    drop the unsupported half (a fail-open mangle).  The translatable knobs
    emit in one fixed order (notrack -> zone forms -> events -> helper); nft
    preserves rule-statement order on readback, so ``--plan`` converges.  The
    helper alone declares a table object, so it rides an :class:`NftObjectRef`;
    the rest are plain verdict statements joined verbatim.
    """
    for unsupported in ("expevents", "timeout"):
        if unsupported in companions:
            raise FermError(
                f"CT target option '{unsupported}' not yet supported by "
                f"nft backend"
            )
    parts: list[str] = []
    if "notrack" in companions:
        parts.append("notrack")
    for zone_name, prefix in (
        ("zone", "ct zone set "),
        ("zone-orig", "ct original zone set "),
        ("zone-reply", "ct reply zone set "),
    ):
        comp = companions.get(zone_name)
        if comp is not None:
            scalar, _ = unwrap_value(comp.value)
            parts.append(prefix + _ct_zone_value(zone_name, scalar))
    if "ctevents" in companions:
        events = _ct_event_canon(companions["ctevents"])
        parts.append(f"ct event set {events}")
    statements: list[NftStatement] = []
    if parts:
        statements.append(NftVerdict(" ".join(parts)))
    if "helper" in companions:
        statements.append(_ct_helper_object(companions["helper"]))
    if not statements:
        raise FermError("CT target not yet supported by nft backend")
    return statements


#: xt HMARK tuple field spellings that map to a fixed nft jhash selector.
_HMARK_FIXED_FIELD: Final[dict[str, str]] = {
    "sport": "th sport",
    "dport": "th dport",
    "proto": "meta l4proto",
}


def _hmark_field(domain: Family, token: str) -> str:
    """
    Map one xt HMARK tuple field to its nft jhash selector.

    The address fields are family-prefixed (``ip``/``ip6``); ``spi``/``ct``
    have no clean jhash selector and refuse rather than hash a wrong field.
    """
    if token in ("src", "dst"):
        side = "saddr" if token == "src" else "daddr"
        return f"{domain} {side}"
    if token in _HMARK_FIXED_FIELD:
        return _HMARK_FIXED_FIELD[token]
    raise FermError(
        f"HMARK tuple field '{token}' has no nft jhash equivalent for the "
        "nft backend"
    )


#: HMARK operands (mod/seed/offset) are 32-bit; nft rejects a value above u32
#: ("Numerical result out of range"), so ferm bounds them rather than emit a
#: value the kernel would reject or (for a modulus) silently wrap.
_HMARK_U32_MAX: Final[int] = 0xFFFFFFFF

#: An HMARK operand: 0x-hex or a leading-zero-free decimal.  A leading-zero
#: form (``010``, ``08``) is refused rather than parsed: iptables reads it as
#: C octal (``010`` -> 8) while a plain decimal read would give 10, so the nft
#: backend declines the ambiguous spelling instead of silently disagreeing
#: with the kernel (and the ``[0-9]``/``[1-9]`` pinning also rejects non-ASCII
#: digits and the ``1_000``/``0o17`` sugar an ``int(scalar, 0)`` would take).
_HMARK_U32_RE: Final[re.Pattern[str]] = re.compile(
    r"0[xX][0-9a-fA-F]+|0|[1-9][0-9]*"
)


def _hmark_u32(name: str, scalar: str) -> int:
    """Parse an HMARK 32-bit operand (decimal or 0x-hex), else refuse."""
    if not _HMARK_U32_RE.fullmatch(scalar):
        raise FermError(f"invalid HMARK {name} '{scalar}' for nft backend")
    # Branch on the 0x prefix rather than passing base 0: the regex has already
    # excluded the leading-zero forms base 0 would reject with a ValueError, so
    # a clean int() is all that is left.
    base = 16 if scalar[1:2] in ("x", "X") else 10
    value = int(scalar, base)
    if value > _HMARK_U32_MAX:
        raise FermError(f"invalid HMARK {name} '{scalar}' for nft backend")
    return value


def _hmark_verdict(
    domain: Family, companions: dict[str, RenderedOption]
) -> NftVerdict:
    """
    Spell HMARK as ``meta mark set jhash <fields> mod M seed S [offset O]``.

    xt_HMARK masks each tuple field before hashing; nft jhash hashes the
    concatenated fields whole, so any per-field mask/prefix has no faithful
    nft form and refuses (rather than silently hashing an unmasked field).
    xt makes ``--hmark-mod`` and ``--hmark-rnd`` mandatory, so both are
    required.  ``offset`` is dropped when zero (the readback omits it) and the
    seed canonicalizes to ``0x``-hex.  nft jhash yields a different value than
    xt's hash: this maps the hash DISTRIBUTION, not the exact mark (the same
    nft bar as recent/hashlimit, which do not reproduce runtime state either).
    """
    for masked in (
        "hmark-src-prefix",
        "hmark-dst-prefix",
        "hmark-sport-mask",
        "hmark-dport-mask",
        "hmark-spi-mask",
        "hmark-proto-mask",
    ):
        if masked in companions:
            raise FermError(
                f"HMARK '{masked}' has no nft jhash equivalent (jhash hashes "
                "fields whole) for the nft backend"
            )
    tuple_opt = companions.get("hmark-tuple")
    mod_opt = companions.get("hmark-mod")
    rnd_opt = companions.get("hmark-rnd")
    if tuple_opt is None or mod_opt is None or rnd_opt is None:
        raise FermError(
            "HMARK needs 'hmark-tuple', 'hmark-mod', and 'hmark-rnd' for the "
            "nft backend"
        )
    tuple_scalar, _ = unwrap_value(tuple_opt.value)
    fields = [
        _hmark_field(domain, token.strip())
        for token in tuple_scalar.split(",")
        if token.strip()
    ]
    if not fields:
        raise FermError("HMARK 'hmark-tuple' is empty for the nft backend")
    # mod/rnd/offset share `_hmark_u32`, so all three accept the decimal or
    # 0x-hex iptables takes (nft prints mod/offset back in decimal, the seed
    # in hex).  mod additionally must be >= 1 (a modulus of zero is invalid).
    mod_scalar = unwrap_value(mod_opt.value)[0]
    mod = _hmark_u32("hmark-mod", mod_scalar)
    if mod < 1:
        raise FermError(
            f"invalid HMARK hmark-mod '{mod_scalar}' for nft backend"
        )
    seed = _hmark_u32("hmark-rnd", unwrap_value(rnd_opt.value)[0])
    expr = (
        f"meta mark set jhash {' . '.join(fields)} mod {mod} seed 0x{seed:x}"
    )
    offset_opt = companions.get("hmark-offset")
    if offset_opt is not None:
        offset = _hmark_u32("hmark-offset", unwrap_value(offset_opt.value)[0])
        if offset != 0:
            expr += f" offset {offset}"
    return NftVerdict(expr)


def _secmark_statement(companions: dict[str, RenderedOption]) -> NftObjectRef:
    """
    Build the SECMARK object-ref statement from its ``selctx`` companion.

    ``SECMARK selctx "<context>"`` stamps a security context on the packet.
    nft models this as a table ``secmark`` object holding the context string,
    referenced by ``meta secmark set "<name>"``.  The object name is a content
    hash of the context (identical contexts dedup to one object -- the
    connlimit-naming precedent), prefixed ``secmark_`` so it cannot collide
    with a user ``@set``.  The context is quoted via :func:`_nft_quote_string`
    (which rejects an embedded quote/backslash/control char); nft stores it
    verbatim, deferring SELinux validation to the kernel at load.  Unlike a
    plain verdict this both declares an object and references it, so it returns
    an :class:`NftObjectRef` the collector harvests -- hence a dedicated
    ``translate_rule`` branch rather than a :func:`build_verdict` case.
    """
    selctx = companions.get("selctx")
    if selctx is None:
        raise FermError("SECMARK target needs 'selctx' for the nft backend")
    context, _ = unwrap_value(selctx.value)
    if not context:
        # Reject an empty context early (symmetric with the missing-selctx
        # guard) rather than emitting `{ "" }` for the kernel to reject at
        # load.
        raise FermError(
            "SECMARK 'selctx' must be a non-empty security context"
        )
    digest = hashlib.sha256(context.encode(BYTE_ENCODING)).hexdigest()[:12]
    name = f"secmark_{digest}"
    return NftObjectRef(
        kind="secmark",
        name=name,
        body=_nft_quote_string(context),
        rule_expr=f"meta secmark set {_nft_quote_string(name)}",
    )


def build_verdict(
    domain: Family,
    table: str,
    target_name: str,
    target_value: str,
    companions: dict[str, RenderedOption],
    *,
    has_transport: bool = False,
) -> NftVerdict:
    """
    Build the verdict statement from the ``jump`` marker value.

    Dispatches on ``target_value`` (the discriminator, since every target
    arrives as ``name='jump'``): core verdicts, NAT/LOG/REJECT (which take
    a companion option), or a ``jump``/``goto`` to a chain in the SAME
    iptables table (name disambiguated via :func:`nft_chain_name`).

    ``has_transport`` reports whether the rule established an L4 protocol
    (port match or ``meta l4proto tcp/udp``); a port-bearing NAT mapping
    without one is rejected at translate time, since nft would
    otherwise reject the applied script and force a rollback.
    """
    if target_value in _VERDICT_TARGET:
        return NftVerdict(_VERDICT_TARGET[target_value])
    if target_value == "MASQUERADE":
        return _nat_to_ports(
            "masquerade", companions, has_transport=has_transport
        )
    if target_value == "REDIRECT":
        return _nat_to_ports(
            "redirect", companions, has_transport=has_transport
        )
    if target_value == "LOG":
        parts = ["log"]
        comp = companions.get("log-prefix")
        if comp is not None:
            scalar, _ = unwrap_value(comp.value)
            parts.append(f"prefix {_nft_quote_string(scalar)}")
        level = companions.get("log-level")
        if level is not None:
            scalar, _ = unwrap_value(level.value)
            mapped = _LOG_LEVEL_MAP.get(scalar.lower())
            if mapped is None:
                raise FermError(
                    f"log-level '{scalar}' not yet supported by nft backend"
                )
            if mapped != "warn":  # nft's default; the readback drops it
                parts.append(f"level {mapped}")
        return NftVerdict(" ".join(parts))
    if target_value == "NFLOG":
        return _nflog_verdict(companions)
    if target_value == "REJECT":
        comp = companions.get("reject-with")
        if comp is None:
            return NftVerdict("reject")
        scalar, _ = unwrap_value(comp.value)
        return NftVerdict(_reject_for(domain, scalar))
    if target_value == "SNAT":
        return _nat_to_addr(
            "snat",
            "SNAT",
            "to-source",
            domain,
            companions,
            has_transport=has_transport,
        )
    if target_value == "DNAT":
        return _nat_to_addr(
            "dnat",
            "DNAT",
            "to-destination",
            domain,
            companions,
            has_transport=has_transport,
        )
    if target_value == "TCPMSS":
        clamp = companions.get("clamp-mss-to-pmtu")
        setmss = companions.get("set-mss")
        if clamp is not None and setmss is None:
            return NftVerdict("tcp option maxseg size set rt mtu")
        if setmss is not None and clamp is None:
            scalar, _ = unwrap_value(setmss.value)
            if not _is_ascii_uint(scalar):
                raise FermError(f"invalid set-mss '{scalar}' for nft backend")
            return NftVerdict(f"tcp option maxseg size set {scalar}")
        raise FermError("TCPMSS target not yet supported by nft backend")
    if target_value == "TEE":
        comp = companions.get("gateway")
        if comp is None:
            raise FermError("TEE target not yet supported by nft backend")
        addr = _validate_address(first_scalar(comp.value))
        return NftVerdict(f"dup to {addr}")
    if target_value == "NOTRACK":
        return NftVerdict("notrack")
    if target_value == "AUDIT":
        # xt_AUDIT records identically for every --type since kernel 4.12
        # (the type is parsed and ignored), and nft has the one spelling;
        # the type still validates so a typo fails loud.  Like LOG, this
        # is a non-terminating log statement in verdict position.
        comp = companions.get("type")
        if comp is None:
            raise FermError("AUDIT needs 'type' for the nft backend")
        scalar, _ = unwrap_value(comp.value)
        if scalar.lower() not in ("accept", "drop", "reject"):
            raise FermError(f"invalid AUDIT type '{scalar}' for nft backend")
        return NftVerdict("log level audit")
    if target_value == "TRACE":
        return NftVerdict("meta nftrace set 1")
    if target_value == "CONNMARK":
        # save/restore-mark with nfmask/ctmask/mask carries bits BETWEEN the
        # packet and ct registers under two independent masks; nft's grammar
        # has no single expression for that (iptables-translate emits a form
        # the kernel silently collapses), so it refuses rather than mangle it.
        for masked in ("nfmask", "ctmask", "mask"):
            if masked in companions:
                raise FermError(
                    f"CONNMARK '{masked}' mixes two masked registers; nft "
                    "cannot express it for the nft backend"
                )
        has_save = "save-mark" in companions
        has_restore = "restore-mark" in companions
        has_arith = any(
            op in companions
            for op in (
                "set-mark",
                "set-xmark",
                "and-mark",
                "or-mark",
                "xor-mark",
            )
        )
        provided = sum((has_save, has_restore, has_arith))
        if provided != 1:
            raise FermError("CONNMARK target not yet supported by nft backend")
        if has_save:
            return NftVerdict("ct mark set meta mark")
        if has_restore:
            return NftVerdict("meta mark set ct mark")
        return NftVerdict(_mark_arith_set("ct mark", "CONNMARK", companions))
    if target_value == "CONNSECMARK":
        # save copies the packet secmark to the ct entry, restore copies it
        # back (the CONNMARK save/restore shape); exactly one applies.
        has_save = "save" in companions
        has_restore = "restore" in companions
        if has_save == has_restore:
            raise FermError(
                "CONNSECMARK target not yet supported by nft backend"
            )
        if has_save:
            return NftVerdict("ct secmark set meta secmark")
        return NftVerdict("meta secmark set ct secmark")
    # The eb-family MARK keyword stays under the eb guard below (its
    # companion spellings are ebtables-specific), so this branch handles
    # the ip/ip6/arp target only.
    if target_value == "MARK" and domain is not Family.EB:
        return NftVerdict(_mark_arith_set("meta mark", "MARK", companions))
    if target_value == "HMARK" and domain in (Family.IP, Family.IP6):
        return _hmark_verdict(domain, companions)
    if target_value == "DSCP" and domain in (Family.IP, Family.IP6):
        # Exactly one of set-dscp / set-dscp-class (TCPMSS/CONNMARK pattern);
        # the selector is family-prefixed like the dscp match.  arp/eb fall
        # through to the registry refusal below.
        setdscp = companions.get("set-dscp")
        setclass = companions.get("set-dscp-class")
        if setdscp is not None and setclass is None:
            scalar, _ = unwrap_value(setdscp.value)
            value = _dscp_value("set-dscp", scalar)
        elif setclass is not None and setdscp is None:
            scalar, _ = unwrap_value(setclass.value)
            value = _dscp_class_value("set-dscp-class", scalar)
        else:
            raise FermError("DSCP target not yet supported by nft backend")
        return NftVerdict(f"{domain} dscp set {_dscp_canon(value)}")
    if target_value == "CLASSIFY":
        comp = companions.get("set-class")
        if comp is None:
            raise FermError("CLASSIFY target not yet supported by nft backend")
        scalar, _ = unwrap_value(comp.value)
        return NftVerdict(f"meta priority set {_classify_priority(scalar)}")
    if target_value == "TOS":
        raise _tos_refusal("target", "TOS")
    if target_value == "NFQUEUE":
        return _nfqueue_verdict(companions)
    # TTL is the ip twin of ip6's HL; each other family falls through to
    # the registry refusal below.
    if target_value == "TTL" and domain is Family.IP:
        return _hoplimit_verdict("TTL", companions)
    if target_value == "HL" and domain is Family.IP6:
        return _hoplimit_verdict("HL", companions)
    if target_value == "SYNPROXY" and domain in (Family.IP, Family.IP6):
        return _synproxy_verdict(companions)
    if target_value == "TPROXY" and domain in (Family.IP, Family.IP6):
        return _tproxy_verdict(domain, companions, has_transport=has_transport)
    # The CT target declares a table object for its `helper` knob, so it is
    # intercepted in `translate_rule` (the SECMARK object precedent) and never
    # reaches build_verdict -- see `_ct_target_statements`.
    if target_value == "CHECKSUM":
        raise FermError(
            "CHECKSUM target has no nft equivalent (kernels since 4.19 "
            "handle virtio checksum offload without it); use the iptables "
            "backend for this rule"
        )
    # The ebtables target keywords share companion option names with the
    # inet NAT targets (snat/to-source, dnat/to-destination), so without
    # this guard they would fall through to the user-chain branch below,
    # swallow the companion and emit a jump to a chain that never exists
    # -- a silently-broken script instead of a clean refusal.  The eb NAT
    # pair is intercepted in translate_rule and never reaches here.
    if domain is Family.EB and target_value in _EB_REFUSED_TARGETS:
        # The keyword alone cannot tell the built-in target from a user
        # chain that happens to share its name, so the message names
        # both readings.
        raise FermError(
            f"eb target '{target_value}' (or jump to a chain of that "
            f"name) not yet supported by nft backend"
        )
    # Every remaining registered target keyword (TARPIT, MARK, NOTRACK,
    # ...) has no nft translation either; without this registry guard it
    # would fall through to the user-chain branch below and emit a jump
    # to a chain that never exists -- rejected by `nft -f` only at apply
    # time, while --test/--noexec --lines report success.  Same
    # keyword-vs-chain ambiguity as the eb guard, so the message names
    # both readings.  ip6 folds to the "ip" registry family (the parser
    # convention, cf. graph._defs_family).
    defs_family = "ip" if domain is Family.IP6 else domain.value
    if is_netfilter_module_target(TARGET_DEFS, defs_family, target_value):
        raise FermError(
            f"target '{target_value}' (or jump to a chain of that name) "
            f"not yet supported by nft backend"
        )
    # A jump/goto to a chain in the same iptables table.  nft forbids
    # jumping to a base chain (one with a hook), so a jump/goto whose
    # target is a built-in chain has NO nft equivalent -> a plain ferm
    # error (ontology gap), NOT a silently-broken script.
    if is_netfilter_builtin_chain(table, target_value):
        raise FermError(
            f"jump/goto to built-in chain '{target_value}' not yet "
            f"supported by nft backend"
        )
    return NftVerdict(f"{target_name} {nft_chain_name(table, target_value)}")


#: xt TCPOPTSTRIP mnemonic -> nft ``reset tcp option`` keyword.
_TCPOPT_NAME: Final[dict[str, str]] = {
    "wscale": "window",
    "mss": "maxseg",
    "sack-permitted": "sack-perm",
    "sack": "sack",
    "timestamp": "timestamp",
    "md5": "md5sig",
}


def _tcpopt_nft_name(token: str) -> str:
    """Map one xt strip-options token (mnemonic or number) to nft."""
    if token in _TCPOPT_NAME:
        return _TCPOPT_NAME[token]
    if _is_ascii_uint(token):
        number = int(token)
        if number > _TCP_OPTION_KIND_MAX:
            raise FermError(f"invalid tcp option '{token}' for nft backend")
        return _TCP_OPTION_KIND.get(number, str(number))
    raise FermError(f"unknown tcp option '{token}' for nft backend")


def _tcpoptstrip_resets(
    companions: dict[str, RenderedOption], protocol: str | None
) -> list[NftReset]:
    """
    Spell TCPOPTSTRIP as a series of ``reset tcp option <x>`` statements.

    One reset per stripped option, in user order.  nft's reset acts on the
    tcp header, so the rule must carry a ``proto tcp`` match (xt requires
    ``-p tcp`` too); the precedent is the NAT-to-a-port transport guard.
    """
    if protocol != "tcp":
        raise FermError(
            "TCPOPTSTRIP needs a tcp protocol match for the nft backend"
        )
    comp = companions.get("strip-options")
    if comp is None:
        raise FermError(
            "TCPOPTSTRIP needs 'strip-options' for the nft backend"
        )
    scalar, _ = unwrap_value(comp.value)
    return [
        NftReset(f"reset tcp option {_tcpopt_nft_name(token.strip())}")
        for token in scalar.split(",")
    ]
