"""translate_rule two-pass assembly plus the collapse/vmap passes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from ...domains import (
    Family,
)
from ...errors import FermError, internal_error
from ...modules import PORT_PROTOCOLS
from ...nftset import (
    sort_set_elements,
)
from ...scope import OptionKind
from ...values import (
    SetRef,
    iter_setrefs,
)

if TYPE_CHECKING:
    from ...rules import (
        RenderedOption,
        RenderedRule,
    )

from .matches import (
    _FIB_SELECTOR,
    _MULTIPORT_KEYWORD,
    _NFT_BURST_RE,
    _NFT_DEFAULT_LIMIT_RATE,
    _PORT_KEYWORD,
    _fib_type_match,
    _ipv4options_matches,
    _ipv6header_matches,
    _osf_match,
    _policy_match,
    _rpfilter_match,
    _setref_selector,
    _socket_matches,
    _translate_match_parts,
    _translate_match_set,
)
from .model import (
    NftMatch,
    NftRule,
    NftStatement,
    NftVerdict,
    NftVmap,
    _nft_l4proto,
    _op,
    _validate_protocol,
    _validate_set_name,
    unwrap_value,
)
from .sets import _references_empty_named_set
from .stateful import (
    _connbytes_match,
    _connlimit_update,
    _hashlimit_key_implies_l4proto,
    _hashlimit_update,
    _nth_match,
    _quota_statement,
    _recent_update,
    _RecentSpec,
    _statistic_match,
    _time_matches,
)
from .verdicts import (
    _EB_NAT_TARGETS,
    _ct_target_statements,
    _eb_nat_statement,
    _netmap_verdict,
    _secmark_statement,
    _set_target_statement,
    _tcpoptstrip_resets,
    build_verdict,
)

#: option names that are companion arguments of a target, consumed by
#: :func:`build_verdict` rather than emitted as matches.
_TARGET_COMPANIONS: Final[frozenset[str]] = frozenset(
    {
        "reject-with",
        "to-source",
        "to-destination",
        "log-prefix",
        "log-level",
        "to-ports",
        "nflog-group",
        "nflog-prefix",
        "nflog-threshold",
        "nflog-range",
        "set-mark",
        "set-xmark",
        "and-mark",
        "or-mark",
        "xor-mark",
        "set-mss",
        "clamp-mss-to-pmtu",
        "gateway",
        "save-mark",
        "restore-mark",
        "nfmask",
        "ctmask",
        "mask",
        "set-dscp",
        "set-dscp-class",
        "set-class",
        # TOS companions: collected so the target refuses with the TOS message
        # rather than the generic "option not supported" from the match path.
        "set-tos",
        "and-tos",
        "or-tos",
        "xor-tos",
        "queue-num",
        "queue-balance",
        "queue-bypass",
        "queue-cpu-fanout",
        "ttl-set",
        "ttl-dec",
        "ttl-inc",
        "hl-set",
        "hl-dec",
        "hl-inc",
        "wscale",
        "sack-perm",
        "timestamp",
        "ecn",
        "strip-options",
        # NAT flag options (SNAT/DNAT/MASQUERADE/REDIRECT); flag options carry
        # no argument and reach build_verdict as bare-name companions.
        "random",
        "random-fully",
        "persistent",
        # CT notrack (the only CT companion with an nft spelling); the other
        # seven CT options are module-qualified below to dodge the `helper`
        # collision with the `mod helper` match.
        "notrack",
        # TPROXY companions.
        "on-port",
        "on-ip",
        "tproxy-mark",
        # CHECKSUM's only option; collected so the target refuses with the
        # CHECKSUM message rather than a generic match-path "not supported".
        "checksum-fill",
        # AUDIT's only option (`type`); no match module spells it, so the
        # plain name is collision-free.
        "type",
        # CONNSECMARK save/restore (collision-free bare flags).
        "save",
        "restore",
        # SECMARK's only option (the security context); collision-free.
        "selctx",
        # ebtables snat/dnat companions (collision-free names; to-source/
        # to-destination above are shared with ip SNAT/DNAT).  Without them
        # the options would fall into the match path and refuse there
        # before the eb NAT translation ever runs.
        "snat-target",
        "dnat-target",
        "snat-arp",
        # HMARK companions (all `hmark-` prefixed, collision-free); the
        # masks/prefixes are collected so the target refuses with the HMARK
        # message rather than a generic match-path "not supported".
        "hmark-tuple",
        "hmark-mod",
        "hmark-offset",
        "hmark-rnd",
        "hmark-src-prefix",
        "hmark-dst-prefix",
        "hmark-sport-mask",
        "hmark-dport-mask",
        "hmark-spi-mask",
        "hmark-proto-mask",
    }
)

#: companion names that collide with a match option of the same spelling
#: (`mss` is both SYNPROXY's option and the tcp match's; `to` is NETMAP's
#: and the string match's; each `CT` option shares a name with a match
#: module -- notably `helper` with `mod helper`), so they are consumed as
#: companions only when the introducing module IS that target.
_MODULE_COMPANIONS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("NETMAP", "to"),
        ("SYNPROXY", "mss"),
        ("CT", "helper"),
        ("CT", "ctevents"),
        ("CT", "expevents"),
        ("CT", "zone-orig"),
        ("CT", "zone-reply"),
        ("CT", "zone"),
        ("CT", "timeout"),
        # SET's `timeout` collides with CT's; add/del-set are `sc`-coded
        # like match-set and must never reach the generic match pass.
        ("SET", "add-set"),
        ("SET", "del-set"),
        ("SET", "timeout"),
        ("SET", "exist"),
    }
)

#: Match modules whose BARE ``mod X`` load matches every packet (their xt
#: parse accepts zero flags and then checks nothing), so dropping the
#: ``-m`` marker loses no semantics.  Every other bare load either IS the
#: match (``hbh``/``dst``/``eui64`` header checks, ``limit``'s implicit
#: default rate) or is invalid iptables (mandatory options); both refuse
#: rather than silently widen the rule.  A marker whose module contributes
#: at least one option to the rule is always skippable: the options carry
#: (or refuse) the semantics.
_BARE_INERT_MATCH_MODULES: Final[frozenset[str]] = frozenset(
    {"state", "conntrack"}
)


def translate_rule(
    domain: Family,
    table: str,
    rule: RenderedRule,
    *,
    chain: str | None = None,
    recent_specs: dict[str, _RecentSpec] | None = None,
    set_targets: frozenset[str] = frozenset(),
) -> NftRule:
    """
    Translate one RenderedRule to an NftRule (two-pass).

    Pass intent: ``match_module`` markers are dropped (``-m`` is implicit
    in nft); ``comment`` becomes the rule comment; the ``protocol`` option
    sets the port context and emits ``meta l4proto`` ONLY when no port
    match subsumes it; ``kind == 'target'`` records the verdict discriminator
    and companion options feed it.  Match statements keep their source order
    (nft is order-sensitive); the verdict is appended last.

    ``chain`` is the ORIGINAL (pre-``nft_chain_name``) chain name, the hook
    context for verdicts whose translation depends on the hook side (NETMAP);
    ``None`` means unknown, making such a verdict refuse cleanly.
    ``set_targets`` carries the family's SET-mutated set names (the
    whole-family pre-pass, like ``recent_specs``), exempting them from the
    empty-set wiring assertion below.
    """
    if _references_empty_named_set(rule, set_targets):
        raise internal_error(
            "a rule over a family-filtered empty named set reached "
            "translate_rule; the caller must drop it first"
        )
    # First pass: resolve rule-wide context (the l4 protocol and whether a
    # port match exists) so a port option that textually precedes the
    # `protocol` option still translates correctly (order-independent).
    has_port = any(
        o.name in _PORT_KEYWORD or o.name in _MULTIPORT_KEYWORD
        for o in rule.options
    )
    # `icmp type` and `tcp flags` (like a port match) imply their l4proto
    # dependency, and the kernel readback omits the `meta l4proto` prefix
    # for such a rule, so emitting it would leave --plan diffing forever.
    # The `tcp option` MATCH forms (mss, tcp-option) imply it too, but
    # module-qualified: SYNPROXY's `mss` companion and the TCPMSS verdict
    # are `tcp option maxseg` SET-statements, whose readback KEEPS the
    # prefix -- both facts verified live.
    # `dccp type`, `ah spi` and `esp spi` suppress their prefix the same
    # way (verified live); `mh type` does NOT (the readback keeps
    # `meta l4proto mobility-header`), so mh stays off this list.  The
    # ecn tcp-flag forms are `tcp flags` matches and inherit that
    # suppression.
    has_implied_l4proto = any(
        o.name
        in (
            "icmp-type",
            "tcp-flags",
            "syn",
            "ecn-tcp-cwr",
            "ecn-tcp-ece",
            "ahspi",
            "espspi",
        )
        or (o.name in ("mss", "tcp-option") and o.module in ("tcp", "tcpmss"))
        or (o.name == "dccp-types" and o.module == "dccp")
        for o in rule.options
    ) or _hashlimit_key_implies_l4proto(rule.options)
    # `--limit-burst` is a companion of the SAME xt_limit match, folded
    # into the limit statement below (the kernel readback always prints
    # an explicit burst, so the pair must emit as one statement).
    # RenderedRule flattens module instances, so with several `limit`
    # options (or several bursts) a burst cannot be paired back with
    # its own match -- refuse rather than attach one burst to every
    # limit statement.
    limit_count = sum(o.name == "limit" for o in rule.options)
    has_limit = limit_count > 0
    burst: str | None = None
    for option in rule.options:
        if option.name == "limit-burst":
            scalar, _ = unwrap_value(option.value)
            if not _NFT_BURST_RE.match(scalar):
                raise FermError(
                    f"invalid limit burst '{scalar}' for nft backend"
                )
            if burst is not None:
                raise FermError(
                    "more than one 'limit-burst' per rule cannot be "
                    "paired for the nft backend"
                )
            burst = scalar
    if burst is not None and limit_count > 1:
        raise FermError(
            "'limit-burst' with more than one 'limit' per rule cannot "
            "be paired for the nft backend"
        )
    # addrtype's --limit-iface-in/out are no-arg flags on the SAME match as
    # src-/dst-type; each qualifies the fib selector with the routing input
    # or output interface.  Collected rule-wide (like the burst) so the
    # modifier reaches every fib match regardless of source order.  arp/eb
    # have no fib translation, so their addrtype falls through to the
    # generic refusal untouched.
    fib_capable = domain in (Family.IP, Family.IP6)
    fib_iface = ""
    if fib_capable:
        iface_in = any(o.name == "limit-iface-in" for o in rule.options)
        iface_out = any(o.name == "limit-iface-out" for o in rule.options)
        if iface_in and iface_out:
            raise FermError(
                "'limit-iface-in' and 'limit-iface-out' are mutually "
                "exclusive for the nft backend"
            )
        if (iface_in or iface_out) and not any(
            o.name in _FIB_SELECTOR for o in rule.options
        ):
            raise FermError(
                "'limit-iface-in'/'limit-iface-out' needs a src-type or "
                "dst-type match for the nft backend"
            )
        fib_iface = " . iif" if iface_in else " . oif" if iface_out else ""
    protocol: str | None = None
    for option in rule.options:
        if option.kind is OptionKind.PROTO:
            protocol, _ = unwrap_value(option.value)
            protocol = _validate_protocol(protocol)
            break
    # nft's `... to <addr>:<port>` NAT mapping is "only valid after transport
    # protocol match" -- a port match or a `meta l4proto tcp/udp` covers it,
    # both implied by the rule carrying a port-bearing protocol.
    has_transport = protocol in PORT_PROTOCOLS

    # Guard: at most one SetRef option per rule (a second would need two
    # named-set declarations sharing one rule, which is not supported yet).
    setref_count = sum(1 for o in rule.options for _ in iter_setrefs(o.value))
    if setref_count > 1:
        raise FermError("at most one named set per rule in this version")

    # mod statistic's options depend on each other (mode selects which of
    # probability/every/packet apply), so they are collected rule-wide.  The
    # collection is module-qualified: `every`/`packet` also name `mod nth`'s
    # own keywords, which must NOT be folded into a statistic match.
    statistic_opts: dict[str, RenderedOption] = {
        o.name: o for o in rule.options if o.module == "statistic"
    }

    # mod nth folds to the same numgen form as `mod statistic mode nth`; its
    # every/counter/start/packet options are collected rule-wide (and
    # module-qualified, since every/packet collide with mod statistic).
    nth_opts: dict[str, RenderedOption] = {
        o.name: o for o in rule.options if o.module == "nth"
    }

    # mod time spreads across several options (timestart/timestop/days/...)
    # that fold into up to three independent meta matches, so they are
    # collected rule-wide and emitted at the first time option (the
    # statistic/hashlimit precedent).
    time_opts: dict[str, RenderedOption] = {
        o.name: o for o in rule.options if o.module == "time"
    }

    # mod connbytes' value/dir/mode options depend on each other and fold
    # into one `ct` counter match, so they are collected rule-wide and
    # emitted at the first connbytes option (the statistic/time precedent).
    connbytes_opts: dict[str, RenderedOption] = {
        o.name: o for o in rule.options if o.module == "connbytes"
    }

    # mod policy / ipv6header / ipv4options: interdependent sibling options
    # the per-name match path structurally cannot see (`header` without
    # `soft`, `pol` without `dir`, `flags` next to `any` all flip the
    # semantics), so each is collected rule-wide and its builder actively
    # refuses on an incompatible sibling rather than translating a wider
    # match (fail-open guard).
    policy_opts: dict[str, RenderedOption] = {
        o.name: o
        for o in rule.options
        if o.module == "policy" and o.kind is not OptionKind.MATCH_MODULE
    }
    ipv6header_opts: dict[str, RenderedOption] = {
        o.name: o
        for o in rule.options
        if o.module == "ipv6header" and o.kind is not OptionKind.MATCH_MODULE
    }
    ipv4options_opts: dict[str, RenderedOption] = {
        o.name: o
        for o in rule.options
        if o.module == "ipv4options" and o.kind is not OptionKind.MATCH_MODULE
    }

    # mod osf's genre/ttl fold into one `osf [ttl X] name Y` match, so they
    # are collected rule-wide and emitted at the first osf option (the
    # policy precedent), module-qualified to exclude the bare -m marker.
    osf_opts: dict[str, RenderedOption] = {
        o.name: o
        for o in rule.options
        if o.module == "osf" and o.kind is not OptionKind.MATCH_MODULE
    }

    # mod rpfilter / mod socket: the BARE load already is the match (a fib
    # route check, a socket lookup) and the no-arg flags only modulate its
    # shape, so presence sets suffice and the match emits at the module
    # marker (keeping `-m X` source order).
    rpfilter_names: frozenset[str] = frozenset(
        o.name
        for o in rule.options
        if o.module == "rpfilter" and o.kind is not OptionKind.MATCH_MODULE
    )
    socket_names: frozenset[str] = frozenset(
        o.name
        for o in rule.options
        if o.module == "socket" and o.kind is not OptionKind.MATCH_MODULE
    )

    # Second pass: emit matches in source order; verdict appended last.
    matches: list[NftStatement] = []
    comment: str | None = None
    target_name: str | None = None
    target_value: str | None = None
    companions: dict[str, RenderedOption] = {}
    statistic_emitted = False
    nth_emitted = False
    recent_emitted = False
    hashlimit_emitted = False
    time_emitted = False
    connbytes_emitted = False
    connlimit_emitted = False
    policy_emitted = False
    ipv6header_emitted = False
    ipv4options_emitted = False
    osf_emitted = False
    rpfilter_emitted = False
    socket_emitted = False

    for option in rule.options:
        name, kind = option.name, option.kind
        if kind is OptionKind.MATCH_MODULE:
            module_name, _ = unwrap_value(option.value)
            # rpfilter/socket: the bare load IS the match, so it emits at
            # the marker (its flags, collected above, only modulate the
            # shape); every other module keeps the inert/refuse split.
            if module_name == "rpfilter":
                if not rpfilter_emitted:
                    matches.append(
                        NftMatch(_rpfilter_match(domain, rpfilter_names))
                    )
                    rpfilter_emitted = True
                continue
            if module_name == "socket":
                if not socket_emitted:
                    matches.extend(_socket_matches(domain, socket_names))
                    socket_emitted = True
                continue
            # The -m marker is implicit in nft only when the module's
            # options carry the semantics; a bare load of anything outside
            # the inert set is itself the match and must not drop.
            if module_name not in _BARE_INERT_MATCH_MODULES and not any(
                o.module == module_name
                and o.kind is not OptionKind.MATCH_MODULE
                for o in rule.options
            ):
                raise FermError(
                    f"bare 'mod {module_name}' (module load without any "
                    f"of its options) not yet supported by nft backend"
                )
            continue
        if name == "comment":
            comment, _ = unwrap_value(option.value)
            continue
        if kind is OptionKind.PROTO:
            scalar, neg = unwrap_value(option.value)
            scalar = _validate_protocol(scalar)
            # a port or icmp-type match already implies l4proto
            if not has_port and not has_implied_l4proto:
                l4 = _nft_l4proto(domain, scalar)
                expr = f"meta l4proto {_op(neg)}{l4}"
                if neg:
                    matches.append(NftMatch(expr))
                else:
                    matches.append(
                        NftMatch(expr, set_key="meta l4proto", element=l4)
                    )
            continue
        if kind is OptionKind.TARGET:
            target_value, _ = unwrap_value(option.value)
            target_name = name
            continue
        if (
            name in _TARGET_COMPANIONS
            or (option.module, name) in _MODULE_COMPANIONS
        ):
            companions[name] = option
            continue
        if option.module == "statistic":
            # Emitted once, at the position of the first statistic option, so
            # the match keeps its source order among the other matches.
            if not statistic_emitted:
                matches.append(NftMatch(_statistic_match(statistic_opts)))
                statistic_emitted = True
            continue
        if option.module == "nth":
            # One numgen match, emitted once at the first nth option so it
            # keeps source order (the statistic precedent).
            if not nth_emitted:
                matches.append(NftMatch(_nth_match(nth_opts)))
                nth_emitted = True
            continue
        if option.module == "time":
            # Up to three meta matches, emitted once at the first time option
            # so they keep source order among the other matches.
            if not time_emitted:
                matches.extend(_time_matches(time_opts))
                time_emitted = True
            continue
        if option.module == "recent":
            # One dynamic-set update per rule, at the first recent option so
            # it keeps source order; the limit spec comes from the pre-pass.
            if not recent_emitted:
                matches.append(_recent_update(domain, rule, recent_specs))
                recent_emitted = True
            continue
        if option.module == "hashlimit":
            if not hashlimit_emitted:
                matches.append(_hashlimit_update(domain, rule, protocol))
                hashlimit_emitted = True
            continue
        if option.module == "connbytes":
            # One `ct` counter match per rule, at the first connbytes option
            # so it keeps source order (the statistic/time precedent).
            if not connbytes_emitted:
                matches.append(_connbytes_match(connbytes_opts))
                connbytes_emitted = True
            continue
        if option.module == "connlimit":
            # One per-rule dynamic-set `add` per rule, at the first connlimit
            # option; its set name is finalized in a post-pass (render()).
            if not connlimit_emitted:
                matches.append(_connlimit_update(domain, rule))
                connlimit_emitted = True
            continue
        if option.module == "policy":
            if not policy_emitted:
                matches.append(NftMatch(_policy_match(policy_opts)))
                policy_emitted = True
            continue
        if option.module == "ipv6header":
            if not ipv6header_emitted:
                matches.extend(_ipv6header_matches(domain, ipv6header_opts))
                ipv6header_emitted = True
            continue
        if option.module == "ipv4options":
            if not ipv4options_emitted:
                matches.extend(_ipv4options_matches(domain, ipv4options_opts))
                ipv4options_emitted = True
            continue
        if option.module == "osf":
            # One `osf` match per rule, at the first osf option so it keeps
            # source order among the other matches (the policy precedent).
            if not osf_emitted:
                matches.append(NftMatch(_osf_match(domain, osf_opts)))
                osf_emitted = True
            continue
        if option.module == "rpfilter":
            # normally consumed at the module marker above; a marker-less
            # rendering still emits once at the first flag
            if not rpfilter_emitted:
                matches.append(
                    NftMatch(_rpfilter_match(domain, rpfilter_names))
                )
                rpfilter_emitted = True
            continue
        if option.module == "socket":
            if not socket_emitted:
                matches.extend(_socket_matches(domain, socket_names))
                socket_emitted = True
            continue
        if option.module == "quota":
            # A stateful quota statement, kept off NftMatch so collapse/vmap
            # never fold two rules onto one byte counter.
            matches.append(_quota_statement(option))
            continue
        if isinstance(option.value, SetRef):
            setref = option.value
            key = _setref_selector(domain, name, protocol)
            expr = f"{key} @{_validate_set_name(setref.name)}"
            matches.append(
                NftMatch(expr, set_key=None, setref=setref, set_selector=key)
            )
            continue
        if name == "match-set":
            matches.append(_translate_match_set(domain, option.value))
            continue
        if fib_capable and name in ("limit-iface-in", "limit-iface-out"):
            continue  # consumed as the fib selector modifier (first pass)
        if fib_capable and name in _FIB_SELECTOR:
            # Not set-eligible (set_key stays None): a bare route-type word
            # has no rank in sort_set_elements, so a folded set could not
            # converge under --plan; a comma-list is a single literal here.
            matches.append(
                NftMatch(_fib_type_match(name, option.value, fib_iface))
            )
            continue
        if name == "limit-burst":
            # consumed by the limit match; alone it keeps xt_limit's
            # default rate (emitted here to preserve source order)
            if not has_limit:
                matches.append(
                    NftMatch(
                        f"limit rate {_NFT_DEFAULT_LIMIT_RATE} "
                        f"burst {burst} packets"
                    )
                )
            continue
        expr, set_key, element = _translate_match_parts(
            domain, option, protocol
        )
        if name == "limit" and burst is not None:
            expr += f" burst {burst} packets"
        matches.append(NftMatch(expr, set_key=set_key, element=element))

    statements: list[NftStatement] = list(matches)
    if target_value == "TCPOPTSTRIP":
        # TCPOPTSTRIP appends a series of reset statements (one per stripped
        # option) and no verdict; build_verdict is typed for exactly one
        # verdict, so it is spelled here (the mangle-MARK precedent for a
        # verdict-less rule).
        statements.extend(_tcpoptstrip_resets(companions, protocol))
    elif target_value == "NETMAP" and domain in (Family.IP, Family.IP6):
        # NETMAP needs the rule's own address match (the map key) and the
        # chain's hook side, which build_verdict does not see; arp/eb fall
        # through to its registry refusal.
        statements.append(
            _netmap_verdict(domain, table, chain, companions, rule.options)
        )
    elif target_value == "SET" and domain in (Family.IP, Family.IP6):
        # -j SET is non-terminating in iptables and the nft set-mutation
        # statement is too: the rule ends without a verdict (TCPOPTSTRIP
        # precedent).  arp/eb fall through to the registry refusal.
        statements.append(_set_target_statement(domain, companions))
    elif target_value == "SECMARK" and domain in (Family.IP, Family.IP6):
        # SECMARK declares a table `secmark` object and references it; the
        # object rides `decls` off the NftObjectRef (the SET precedent for a
        # statement that carries a declaration).  arp/eb fall through to the
        # registry refusal.
        statements.append(_secmark_statement(companions))
    elif target_value == "CT":
        # CT's `helper` knob declares a table `ct helper` object and the rest
        # of its options are plain statements; one branch builds the ordered
        # list so a helper-plus-zone rule never splits across two dispatch
        # sites (the SECMARK object precedent).  No domain guard: CT is a
        # raw-table target the parser only emits for ip/ip6, matching the
        # previous build_verdict handling.
        statements.extend(_ct_target_statements(companions))
    elif target_value in _EB_NAT_TARGETS and domain is Family.EB:
        # ebtables snat/dnat are legal only in specific built-in nat chains
        # (the legacy kernel enforces the placement with hook masks), which
        # build_verdict does not see; the NETMAP precedent.  Non-eb domains
        # fall through: snat/dnat are eb-only target keywords, elsewhere
        # they are user-chain names.
        statements.append(
            _eb_nat_statement(table, chain, target_value, companions)
        )
    elif target_value is not None:
        statements.append(
            build_verdict(
                domain,
                table,
                target_name or "jump",
                target_value,
                companions,
                has_transport=has_transport,
            )
        )
    return NftRule(statements=statements, comment=comment)


def _elements_equal(a: list[str] | None, b: list[str] | None) -> bool:
    """
    Compare folded element lists by canonical order (order-insensitive).

    A second-dimension fold leaves siblings with already-merged element lists;
    comparing them order-sensitively would miss the fold when the first axis
    accumulated them in different orders ([c, d] vs [d, c]).  Canonical order
    makes the equality robust by construction.
    """
    if a is None or b is None:
        return a is None and b is None
    return sort_set_elements(a) == sort_set_elements(b)


def _stmt_equal(a: NftStatement, b: NftStatement) -> bool:
    """Return True if two statements are identical for collapse purposes."""
    if isinstance(a, NftMatch) and isinstance(b, NftMatch):
        if a.set_key is not None and b.set_key is not None:
            return (
                a.set_key == b.set_key
                and a.element == b.element
                and _elements_equal(a.elements, b.elements)
            )
        return a.expr == b.expr
    return type(a) is type(b) and a.to_text() == b.to_text()


def _collapse_axis(a: NftRule, b: NftRule) -> int | None:
    """Return the single differing eligible position, or None."""
    if a.comment != b.comment or len(a.statements) != len(b.statements):
        return None
    pairs = zip(a.statements, b.statements, strict=False)
    differing = [
        k for k, (sa, sb) in enumerate(pairs) if not _stmt_equal(sa, sb)
    ]
    if len(differing) != 1:
        return None
    k = differing[0]
    sa, sb = a.statements[k], b.statements[k]
    if (
        isinstance(sa, NftMatch)
        and isinstance(sb, NftMatch)
        and sa.set_key is not None
        and sa.set_key == sb.set_key
    ):
        return k
    return None


def _merge_run(
    rules: list[NftRule], start: int, end: int, axis: int
) -> NftRule:
    """Merge ``rules[start..end]`` into one rule with a set at *axis*."""
    base = rules[start]
    anchor = base.statements[axis]
    assert isinstance(anchor, NftMatch)
    elements: list[str] = []
    for rule in rules[start : end + 1]:
        match = rule.statements[axis]
        assert isinstance(match, NftMatch)
        if match.elements is not None:
            elements.extend(match.elements)
        elif match.element is not None:
            elements.append(match.element)
    statements = list(base.statements)
    statements[axis] = NftMatch(
        anchor.expr, set_key=anchor.set_key, elements=elements
    )
    return NftRule(statements=statements, comment=base.comment)


def _collapse_one_pass(rules: list[NftRule]) -> tuple[list[NftRule], bool]:
    """One left-to-right merge pass; returns (rules, changed)."""
    out: list[NftRule] = []
    changed = False
    count = len(rules)
    index = 0
    while index < count:
        axis = (
            _collapse_axis(rules[index], rules[index + 1])
            if index + 1 < count
            else None
        )
        if axis is None:
            out.append(rules[index])
            index += 1
            continue
        end = index + 1
        while (
            end + 1 < count
            and _collapse_axis(rules[index], rules[end + 1]) == axis
        ):
            end += 1
        out.append(_merge_run(rules, index, end, axis))
        changed = True
        index = end + 1
    return out, changed


#: Pure-verdict values our emitter produces that nft also accepts as a vmap
#: value.  'reject'/'log'/NAT/'counter' are statements nft rejects inside a
#: vmap, so a rule carrying one breaks the run and stays linear (verified on
#: nft v1.1.6).  'queue' is a verdict we emit but deliberately do not fold.
_VMAP_VERDICTS: Final[frozenset[str]] = frozenset({"accept", "drop", "return"})

#: A vmap leaf rule is exactly one set-eligible match plus its verdict.
_VMAP_LEAF_STATEMENTS: Final[int] = 2


def _is_vmap_verdict(statement: NftStatement) -> bool:
    """Return whether *statement* is a verdict nft allows as a vmap value."""
    if not isinstance(statement, NftVerdict):
        return False
    return statement.expr in _VMAP_VERDICTS or statement.expr.startswith(
        ("jump ", "goto ")
    )


def _vmap_candidate(rule: NftRule) -> tuple[str, str, str] | None:
    """
    Return ``(set_key, key, verdict)`` if *rule* is a single-key vmap leaf.

    A candidate is exactly ``[<set-eligible match>, <vmap verdict>]`` carrying
    a single (not already folded) operand and no comment; anything else returns
    ``None`` so the run breaks and the rule stays linear (safe-bias).
    """
    if (
        rule.comment is not None
        or len(rule.statements) != _VMAP_LEAF_STATEMENTS
    ):
        return None
    match, verdict = rule.statements
    if (
        not isinstance(match, NftMatch)
        or match.set_key is None
        or match.element is None
        or match.elements is not None
    ):
        return None
    if not _is_vmap_verdict(verdict):
        return None
    assert isinstance(verdict, NftVerdict)
    return match.set_key, match.element, verdict.expr


def _collapse_vmap(rules: list[NftRule]) -> list[NftRule]:
    """
    Fold a run of adjacent single-key rules into one verdict map.

    Runs after the set-collapse fixpoint, so any adjacent same-selector singles
    left here necessarily differ in verdict (equal-verdict singles already
    merged into a set).  A duplicate key ends the run (nft rejects a vmap with
    duplicate keys), and a run of length 1 is left linear.
    """
    out: list[NftRule] = []
    count = len(rules)
    index = 0
    while index < count:
        candidate = _vmap_candidate(rules[index])
        if candidate is None:
            out.append(rules[index])
            index += 1
            continue
        set_key, first_key, first_verdict = candidate
        pairs: list[tuple[str, str]] = [(first_key, first_verdict)]
        keys_seen = {first_key}
        end = index
        while end + 1 < count:
            following = _vmap_candidate(rules[end + 1])
            if (
                following is None
                or following[0] != set_key
                or following[1] in keys_seen
            ):
                break
            pairs.append((following[1], following[2]))
            keys_seen.add(following[1])
            end += 1
        if end > index:
            out.append(NftRule(statements=[NftVmap(set_key, pairs)]))
        else:
            out.append(rules[index])
        index = end + 1
    return out


def _collapse_chain_rules(rules: list[NftRule]) -> list[NftRule]:
    """
    Fold adjacent leaf rules into anonymous sets, then into verdict maps.

    The set pass iterates to a fixpoint: each pass strictly reduces the rule
    count, so the loop terminates.  Only adjacent rules merge (nft is
    order-sensitive); the predicate is the safety boundary, not array
    provenance.  The vmap pass runs once over the settled result.
    """
    changed = True
    while changed:
        rules, changed = _collapse_one_pass(rules)
    return _collapse_vmap(rules)
