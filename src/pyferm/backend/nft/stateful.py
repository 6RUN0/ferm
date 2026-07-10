"""Rule-wide stateful vocabulary (recent, hashlimit, time, and kin)."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from ...domains import (
    Family,
)
from ...errors import FermError, internal_error
from ...modules import PORT_PROTOCOLS
from ...scope import OptionKind
from ...streams import BYTE_ENCODING
from ...values import (
    Negated,
    PreNegated,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from ...rules import (
        RenderedOption,
        RenderedRule,
    )


from .matches import _NFT_BURST_RE
from .model import (
    NftMatch,
    NftQuota,
    NftRule,
    NftSetUpdate,
    _nft_time_canon,
    _op,
    _validate_set_name,
    first_scalar,
    unwrap_value,
)
from .sets import _CONNLIMIT_SENTINEL

#: xt stores ``--probability p`` as ``round(p * 2**31)`` and nft matches it
#: with ``meta random & <mask> < <threshold>`` where the mask is the top of
#: the 31-bit range the ``meta random`` expression yields.
_STATISTIC_RANDOM_MASK: Final[int] = 2**31 - 1


def _statistic_match(options: dict[str, RenderedOption]) -> str:
    """
    Translate a ``mod statistic`` match to its nft expression.

    ``mode random`` maps to ``meta random & <mask> < <threshold>`` (an
    average-probability sampler) and ``mode nth`` to ``numgen inc mod N P``
    (a deterministic every-Nth counter; ``P`` is xt's 0-based ``--packet``,
    which defaults to 0).  The options are collected rule-wide and
    module-qualified by the caller because ``every``/``packet`` collide with
    ``mod nth``'s own keywords.  A statistic match is a matcher, never a
    verdict, so it must not route through the target companion path (which
    would silently drop it and fail open).
    """
    mode_opt = options.get("mode")
    if mode_opt is None:
        raise FermError("mod statistic needs a 'mode' for the nft backend")
    mode, mode_neg = unwrap_value(mode_opt.value)
    if mode_neg:
        raise FermError(
            "mod statistic 'mode' cannot be negated for the nft backend"
        )
    if mode == "random":
        prob_opt = options.get("probability")
        if prob_opt is None:
            raise FermError(
                "mod statistic mode random needs a 'probability' for the "
                "nft backend"
            )
        scalar, _ = unwrap_value(prob_opt.value)
        try:
            probability = float(scalar)
        except ValueError:
            raise FermError(
                f"invalid statistic probability '{scalar}' for nft backend"
            ) from None
        if not 0.0 <= probability <= 1.0:
            raise FermError(
                f"statistic probability '{scalar}' is outside [0, 1] for "
                "the nft backend"
            )
        threshold = round(probability * 2**31)
        return f"meta random & {_STATISTIC_RANDOM_MASK} < {threshold}"
    if mode == "nth":
        every_opt = options.get("every")
        if every_opt is None:
            raise FermError(
                "mod statistic mode nth needs 'every' for the nft backend"
            )
        every_scalar, _ = unwrap_value(every_opt.value)
        if not every_scalar.isdigit() or int(every_scalar) == 0:
            raise FermError(
                f"invalid statistic every '{every_scalar}' for nft backend"
            )
        packet_opt = options.get("packet")
        # xt defaults --packet to 0 (0-based) when omitted; ferm passes the
        # bare `mode nth every N` through, so the nft offset defaults to 0.
        if packet_opt is None:
            packet_scalar = "0"
        else:
            packet_scalar, _ = unwrap_value(packet_opt.value)
            if not packet_scalar.isdigit():
                raise FermError(
                    f"invalid statistic packet '{packet_scalar}' for nft "
                    "backend"
                )
        if int(packet_scalar) >= int(every_scalar):
            raise FermError(
                f"statistic packet '{packet_scalar}' must be less than "
                f"every '{every_scalar}' for the nft backend"
            )
        return f"numgen inc mod {int(every_scalar)} {int(packet_scalar)}"
    raise FermError(f"unknown statistic mode '{mode}' for the nft backend")


#: rate unit spans in seconds, smallest first: the reducer picks the smallest
#: unit that renders ``T*H/S`` as an integer count, matching the readback
#: (``8/60s`` -> ``8/minute``, ``16/300s`` -> ``192/hour``).
_RATE_UNITS: Final[tuple[tuple[str, int], ...]] = (
    ("second", 1),
    ("minute", 60),
    ("hour", 3_600),
    ("day", 86_400),
)

#: xt rate-unit spelling (with abbreviations) -> nft rate unit.
_HASHLIMIT_UNIT: Final[dict[str, str]] = {
    "sec": "second",
    "second": "second",
    "min": "minute",
    "minute": "minute",
    "hour": "hour",
    "day": "day",
}

#: rate unit -> the period nft prints as the element ``timeout`` when a
#: hashlimit rule gives no explicit htable-expire (``/second`` stays
#: timeout-less: a bare ``flags dynamic`` element is legal, pinned live).
_HASHLIMIT_PERIOD_TIMEOUT: Final[dict[str, str]] = {
    "minute": "1m",
    "hour": "1h",
    "day": "1d",
}

#: hashlimit-mode token -> canonical emission order rank.  The readback keeps
#: our emission order verbatim, so a fixed rank makes concatenated keys stable.
_HASHLIMIT_MODE_ORDER: Final[tuple[str, ...]] = (
    "srcip",
    "dstip",
    "srcport",
    "dstport",
)


def _reduce_rate(numerator: int, seconds: int) -> tuple[int, str]:
    """
    Express ``numerator/seconds`` packets-per-second as ``N/<unit>``.

    Picks the smallest nft rate unit that yields an integer ``N >= 1``; an
    average rate that no unit renders whole (an irreducible ``T*H/S``)
    refuses.
    """
    for unit, span in _RATE_UNITS:
        product = numerator * span
        if product % seconds == 0 and product // seconds >= 1:
            return product // seconds, unit
    raise FermError(
        f"average rate {numerator}/{seconds}s has no integer nft rate unit "
        "for the nft backend"
    )


@dataclass(frozen=True)
class _RecentFacts:
    """Per-rule mod recent facts, structurally parsed once (fail-closed)."""

    name: str
    is_check: bool
    seconds: str | None
    hitcount: str | None
    direction: str
    has_verdict: bool


@dataclass(frozen=True)
class _RecentSpec:
    """Per-name aggregate: the uniform element spec every rule of it emits."""

    direction: str
    timeout: str
    limit: str | None


def _recent_scalar(opts: dict[str, RenderedOption], key: str) -> str | None:
    """Return a numeric recent option's scalar, or None when absent."""
    option = opts.get(key)
    if option is None:
        return None
    scalar, _ = unwrap_value(option.value)
    if not scalar.isdigit():
        raise FermError(f"invalid recent {key} '{scalar}' for the nft backend")
    return scalar


def _recent_facts(domain: Family, rule: RenderedRule) -> _RecentFacts | None:
    """
    Parse a rule's ``mod recent`` options into structured facts, or None.

    Refuses per-rule: a non-ip/ip6 family; a negated option; the unsupported
    ``remove``/``rttl``/``reap``/``mask`` verbs; a missing or multiple
    set/rcheck/update verb; a missing/invalid name; a hitcount without seconds;
    and a check verb lacking the seconds+hitcount the token-bucket needs.
    """
    recent_opts = [o for o in rule.options if o.module == "recent"]
    if not recent_opts:
        return None
    if domain not in (Family.IP, Family.IP6):
        raise FermError("mod recent needs the ip or ip6 family for nft")
    opts: dict[str, RenderedOption] = {}
    for option in recent_opts:
        if isinstance(option.value, (Negated, PreNegated)):
            raise FermError(
                f"mod recent '{option.name}' cannot be negated for the nft "
                "backend"
            )
        opts[option.name] = option
    for unsupported in ("remove", "rttl", "reap", "mask"):
        if unsupported in opts:
            raise FermError(
                f"mod recent '{unsupported}' is not supported by the nft "
                "backend"
            )
    verbs = [verb for verb in ("set", "rcheck", "update") if verb in opts]
    if len(verbs) != 1:
        raise FermError(
            "mod recent needs exactly one of set/rcheck/update for the nft "
            "backend"
        )
    is_check = verbs[0] in ("rcheck", "update")
    name_option = opts.get("name")
    if name_option is None:
        raise FermError("mod recent needs a 'name' for the nft backend")
    raw_name, _ = unwrap_value(name_option.value)
    try:
        _validate_set_name(f"recent_{raw_name}")
    except FermError:
        raise FermError(
            f"invalid recent name '{raw_name}' for the nft backend"
        ) from None
    if "rsource" in opts and "rdest" in opts:
        raise FermError(
            "mod recent cannot combine rsource and rdest for the nft backend"
        )
    direction = "daddr" if "rdest" in opts else "saddr"
    seconds = _recent_scalar(opts, "seconds")
    hitcount = _recent_scalar(opts, "hitcount")
    if hitcount is not None and seconds is None:
        raise FermError(
            "mod recent 'hitcount' needs 'seconds' for the nft backend"
        )
    if is_check and (seconds is None or hitcount is None):
        raise FermError(
            "mod recent rcheck/update needs 'seconds' and 'hitcount' for the "
            "nft backend"
        )
    has_verdict = any(o.kind is OptionKind.TARGET for o in rule.options)
    return _RecentFacts(
        raw_name, is_check, seconds, hitcount, direction, has_verdict
    )


def _build_recent_specs(
    domain: Family, rules: Iterable[RenderedRule]
) -> dict[str, _RecentSpec]:
    """
    Aggregate every mod recent rule of one family into per-name specs.

    A dynamic set's stateful (limit) expression is fixed when the element is
    created and every add/update touching it consumes a token, so all rules of
    a name MUST emit the identical element spec.  ``T`` counts the name's
    update-emitting rules; ``R = T*H/S`` (integer-reduced) and ``B = T*H - 1``
    are calibrated against real xt_recent (2026-07-10 live pin).  Refuses a
    name with conflicting seconds/direction/hitcount, a name with no seconds
    anywhere, or a bare ``set`` carrying a real verdict when the name also has
    check rules (the verdict would fire only on overflow, unlike xt).
    """
    facts_by_name: dict[str, list[_RecentFacts]] = {}
    for rule in rules:
        facts = _recent_facts(domain, rule)
        if facts is not None:
            facts_by_name.setdefault(facts.name, []).append(facts)
    specs: dict[str, _RecentSpec] = {}
    for name, facts_list in facts_by_name.items():
        seconds_values = {
            f.seconds for f in facts_list if f.seconds is not None
        }
        if len(seconds_values) > 1:
            raise FermError(
                f"mod recent '{name}' has conflicting seconds for the nft "
                "backend"
            )
        if not seconds_values:
            raise FermError(
                f"mod recent '{name}' has no seconds anywhere; the window is "
                "undefined for the nft backend"
            )
        directions = {f.direction for f in facts_list}
        if len(directions) > 1:
            raise FermError(
                f"mod recent '{name}' mixes rsource and rdest for the nft "
                "backend"
            )
        hitcounts = {f.hitcount for f in facts_list if f.hitcount is not None}
        if len(hitcounts) > 1:
            raise FermError(
                f"mod recent '{name}' has conflicting hitcounts for the nft "
                "backend"
            )
        has_check = any(f.is_check for f in facts_list)
        if has_check and any(
            not f.is_check and f.has_verdict for f in facts_list
        ):
            raise FermError(
                f"mod recent '{name}' set rule carries a verdict but the name "
                "has check rules for the nft backend"
            )
        seconds = int(next(iter(seconds_values)))
        timeout = _nft_time_canon(seconds * 1000)
        limit: str | None = None
        if has_check:
            hits = int(next(iter(hitcounts)))
            numerator = len(facts_list) * hits
            if numerator > 1:
                rate, unit = _reduce_rate(numerator, seconds)
                limit = (
                    f"rate over {rate}/{unit} burst {numerator - 1} packets"
                )
            # T*H == 1 degenerates to "match from the first in-window
            # packet"; the limitless update expresses that exactly, while
            # the formula's `burst 0` is rejected by nft outright.
        specs[name] = _RecentSpec(next(iter(directions)), timeout, limit)
    return specs


def _recent_update(
    domain: Family,
    rule: RenderedRule,
    recent_specs: dict[str, _RecentSpec] | None,
) -> NftSetUpdate:
    """Emit one rule's ``update @recent_<name> { ... }`` from its spec."""
    facts = _recent_facts(domain, rule)
    if facts is None:
        raise internal_error()  # caller gates on a recent option present
    if recent_specs is None or facts.name not in recent_specs:
        # The per-name spec is a whole-family pre-pass; a caller reaching
        # translate_rule for a recent rule without it is a wiring bug.
        raise internal_error(
            "recent rule reached translate_rule without its pre-pass spec"
        )
    spec = recent_specs[facts.name]
    set_type = "ipv4_addr" if domain == Family.IP else "ipv6_addr"
    return NftSetUpdate(
        f"recent_{facts.name}",
        f"{domain} {spec.direction}",
        set_type,
        spec.timeout,
        spec.limit,
    )


def _prefix_length_mask(domain: Family, length: str) -> str:
    """Render a hashlimit prefix length as the nft address mask literal."""
    if not length.isdigit():
        raise FermError(
            f"invalid hashlimit mask '{length}' for the nft backend"
        )
    bits = int(length)
    if domain == Family.IP:
        if bits > 32:  # noqa: PLR2004 - IPv4 prefix ceiling
            raise FermError(f"hashlimit mask '{length}' exceeds /32 for nft")
        return str(ipaddress.IPv4Network(f"0.0.0.0/{bits}").netmask)
    if bits > 128:  # noqa: PLR2004 - IPv6 prefix ceiling
        raise FermError(f"hashlimit mask '{length}' exceeds /128 for nft")
    return str(ipaddress.IPv6Network(f"::/{bits}").netmask)


def _hashlimit_rate(scalar: str) -> tuple[str, str]:
    """
    Parse an xt hashlimit rate ``N/unit`` into ``(N, nft-unit)``.

    Byte rates (``1kb/s`` and kin) leave ``N`` non-numeric and refuse, as do
    fractional counts and unknown units -- packet rates over time only.
    """
    number, _, unit = scalar.partition("/")
    if not number.isdigit() or int(number) < 1:
        raise FermError(
            f"unsupported hashlimit rate '{scalar}' for the nft backend"
        )
    nft_unit = _HASHLIMIT_UNIT.get(unit)
    if nft_unit is None:
        raise FermError(
            f"unsupported hashlimit rate unit in '{scalar}' for the nft "
            "backend"
        )
    return str(int(number)), nft_unit


def _hashlimit_key(
    domain: Family,
    mode_scalar: str,
    opts: dict[str, RenderedOption],
    protocol: str | None,
) -> tuple[str, str]:
    """
    Build the concatenated hashlimit key and its nft set type from the mode.

    Modes emit in the canonical order srcip, dstip, srcport, dstport;
    src/dstmask narrow the address key with an ``& <mask>``; a port mode
    without a tcp/udp protocol refuses.
    """
    tokens = mode_scalar.split(",")
    unknown = [t for t in tokens if t not in _HASHLIMIT_MODE_ORDER]
    if unknown:
        raise FermError(
            f"unsupported hashlimit mode '{mode_scalar}' for the nft backend"
        )
    addr_type = "ipv4_addr" if domain == Family.IP else "ipv6_addr"
    keys: list[str] = []
    types: list[str] = []
    for token in _HASHLIMIT_MODE_ORDER:
        if token not in tokens:
            continue
        if token in ("srcip", "dstip"):
            side = "saddr" if token == "srcip" else "daddr"
            mask = opts.get(
                "hashlimit-srcmask"
                if token == "srcip"
                else "hashlimit-dstmask"
            )
            key = f"{domain} {side}"
            if mask is not None:
                length, _ = unwrap_value(mask.value)
                key += f" & {_prefix_length_mask(domain, length)}"
            keys.append(key)
            types.append(addr_type)
        else:
            if protocol not in PORT_PROTOCOLS:
                raise FermError(
                    f"hashlimit mode '{token}' needs a tcp/udp protocol for "
                    "the nft backend"
                )
            port = "sport" if token == "srcport" else "dport"
            keys.append(f"{protocol} {port}")
            types.append("inet_service")
    return " . ".join(keys), " . ".join(types)


def _hashlimit_timeout(
    opts: dict[str, RenderedOption], unit: str
) -> str | None:
    """
    Resolve the element timeout for a hashlimit rule.

    htable-expire (milliseconds) wins; otherwise the rate period stands in
    (``/minute`` -> ``1m``), and a bare ``/second`` rate carries no timeout
    (a timeout-less element under ``flags dynamic`` is legal, pinned live).
    """
    expire = opts.get("hashlimit-htable-expire")
    if expire is not None:
        milliseconds, _ = unwrap_value(expire.value)
        if not milliseconds.isdigit():
            raise FermError(
                f"invalid hashlimit htable-expire '{milliseconds}' for the "
                "nft backend"
            )
        return _nft_time_canon(int(milliseconds))
    return _HASHLIMIT_PERIOD_TIMEOUT.get(unit)


def _hashlimit_update(
    domain: Family, rule: RenderedRule, protocol: str | None
) -> NftSetUpdate:
    """
    Emit one rule's ``update @hashlimit_<name> { ... }`` statement.

    Self-contained per rule (every parameter lives on the rule); the cross-rule
    "one name, one shape" invariant is the declaration-conflict guard in
    :func:`_collect_set_declarations`.  ``upto`` gives the conform rate,
    ``above`` the ``over`` rate; hashlimit takes no ``T`` compensation (xt
    taxes its shared htable identically).
    """
    opts = {o.name: o for o in rule.options if o.module == "hashlimit"}
    if domain not in (Family.IP, Family.IP6):
        raise FermError("mod hashlimit needs the ip or ip6 family for nft")
    for option in opts.values():
        if isinstance(option.value, (Negated, PreNegated)):
            raise FermError(
                f"mod hashlimit '{option.name}' cannot be negated for the nft "
                "backend"
            )
    if "hashlimit-htable-max" in opts:
        # The dynamic set's capacity is pinned to the kernel's implicit
        # `size 65535` for --plan readback parity; honouring a user cap
        # would need that convergence re-verified, so refuse instead of
        # silently overriding a deliberate memory/DoS ceiling.
        raise FermError(
            "mod hashlimit 'hashlimit-htable-max' has no nft equivalent "
            "for the nft backend"
        )
    # hashlimit-htable-size and hashlimit-htable-gcinterval are pure
    # performance-tuning knobs (initial bucket count, GC cadence) with no
    # match semantics; nft sizes and expires dynamic sets itself, so they
    # are deliberately ignored rather than refused.
    name_option = opts.get("hashlimit-name")
    if name_option is None:
        raise FermError(
            "mod hashlimit needs 'hashlimit-name' for the nft backend"
        )
    raw_name, _ = unwrap_value(name_option.value)
    try:
        _validate_set_name(f"hashlimit_{raw_name}")
    except FermError:
        raise FermError(
            f"invalid hashlimit name '{raw_name}' for the nft backend"
        ) from None
    # `hashlimit` is xt's legacy synonym for `hashlimit-upto`.
    upto = opts.get("hashlimit-upto") or opts.get("hashlimit")
    above = opts.get("hashlimit-above")
    if upto is not None and above is not None:
        raise FermError(
            "mod hashlimit cannot combine upto and above for the nft backend"
        )
    rate_option = upto if upto is not None else above
    if rate_option is None:
        raise FermError(
            "mod hashlimit needs an upto/above rate for the nft backend"
        )
    rate_scalar, _ = unwrap_value(rate_option.value)
    rate, unit = _hashlimit_rate(rate_scalar)
    burst = "5"
    burst_option = opts.get("hashlimit-burst")
    if burst_option is not None:
        burst, _ = unwrap_value(burst_option.value)
        if not _NFT_BURST_RE.match(burst):
            raise FermError(
                f"invalid hashlimit burst '{burst}' for the nft backend"
            )
    prefix = "rate over" if above is not None else "rate"
    limit = f"{prefix} {rate}/{unit} burst {burst} packets"
    mode_option = opts.get("hashlimit-mode")
    if mode_option is None:
        raise FermError(
            "mod hashlimit needs 'hashlimit-mode' for the nft backend"
        )
    mode_scalar, _ = unwrap_value(mode_option.value)
    key_expr, set_type = _hashlimit_key(domain, mode_scalar, opts, protocol)
    timeout = _hashlimit_timeout(opts, unit)
    return NftSetUpdate(
        f"hashlimit_{raw_name}", key_expr, set_type, timeout, limit
    )


def _hashlimit_key_implies_l4proto(options: Iterable[RenderedOption]) -> bool:
    """
    Report whether a hashlimit port mode puts a proto selector in the key.

    A ``srcport``/``dstport`` mode emits ``<proto> sport|dport`` inside the
    dynamic-set key, which -- like an explicit port match -- makes the kernel
    drop the ``meta l4proto`` prefix on readback; emitting it anyway would
    leave ``--plan`` diffing forever.
    """
    for option in options:
        if option.module == "hashlimit" and option.name == "hashlimit-mode":
            scalar, _ = unwrap_value(option.value)
            if any(
                token in ("srcport", "dstport") for token in scalar.split(",")
            ):
                return True
    return False


#: nft weekday index (Sunday=0) -> readback name.
_NFT_DAY_NAMES: Final[tuple[str, ...]] = (
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
)

#: xt weekday name/abbreviation -> nft index.  Numeric xt days (1..7,
#: Monday=1..Sunday=7) map with ``n % 7`` so Sunday's xt 7 becomes nft 0.
_XT_DAY_TO_NFT: Final[dict[str, int]] = {
    "monday": 1,
    "mon": 1,
    "tuesday": 2,
    "tue": 2,
    "wednesday": 3,
    "wed": 3,
    "thursday": 4,
    "thu": 4,
    "friday": 5,
    "fri": 5,
    "saturday": 6,
    "sat": 6,
    "sunday": 0,
    "sun": 0,
}

_TIME_OF_DAY_RE: Final[re.Pattern[str]] = re.compile(
    r"\A(\d{1,2}):(\d{2})(?::(\d{2}))?\Z"
)

_DATE_RE: Final[re.Pattern[str]] = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})\Z")

_CLOCK_HOUR_MAX: Final[int] = 23

_CLOCK_FIELD_MAX: Final[int] = 59

_DAYS_PER_WEEK: Final[int] = 7


def _clock_parts(
    match: re.Match[str], scalar: str, kind: str
) -> tuple[int, int, int]:
    """Return validated ``(hour, minute, second)`` from a clock match."""
    hour, minute = int(match.group(1)), int(match.group(2))
    second = int(match.group(3)) if match.group(3) is not None else 0
    if not (
        0 <= hour <= _CLOCK_HOUR_MAX
        and 0 <= minute <= _CLOCK_FIELD_MAX
        and 0 <= second <= _CLOCK_FIELD_MAX
    ):
        raise FermError(f"invalid {kind} '{scalar}' for nft backend")
    return hour, minute, second


def _time_of_day(scalar: str) -> str:
    """
    Normalize an xt ``HH:MM[:SS]`` clock value to the nft readback spelling.

    nft prints a ``meta hour`` bound as ``HH:MM``, appending ``:SS`` only
    when the seconds are non-zero (per boundary), so emission trims a zero
    seconds field to keep an applied rule diff-free under ``--plan``.
    """
    match = _TIME_OF_DAY_RE.match(scalar)
    if match is None:
        raise FermError(f"invalid time '{scalar}' for nft backend")
    hour, minute, second = _clock_parts(match, scalar, "time")
    if second:
        return f"{hour:02d}:{minute:02d}:{second:02d}"
    return f"{hour:02d}:{minute:02d}"


def _datetime_iso(scalar: str) -> str:
    """
    Normalize an xt ISO8601 ``date[Thh:mm[:ss]]`` to nft's full form.

    nft prints a ``meta time`` bound as ``YYYY-MM-DD hh:mm:ss`` (seconds
    always present, ``T`` rendered as a space), so a bare date gains a
    ``00:00:00`` clock and a ``T`` separator becomes a space.
    """
    date_part, sep, time_part = scalar.partition("T")
    if _DATE_RE.match(date_part) is None:
        raise FermError(f"invalid date '{scalar}' for nft backend")
    if not sep:
        clock = "00:00:00"
    else:
        match = _TIME_OF_DAY_RE.match(time_part)
        if match is None:
            raise FermError(f"invalid date '{scalar}' for nft backend")
        hour, minute, second = _clock_parts(match, scalar, "date")
        clock = f"{hour:02d}:{minute:02d}:{second:02d}"
    return f"{date_part} {clock}"


def _time_hour_match(options: dict[str, RenderedOption]) -> str | None:
    """Build ``meta hour "S"-"E"`` from timestart/timestop (xt defaults)."""
    start = options.get("timestart")
    stop = options.get("timestop")
    if start is None and stop is None:
        return None
    low = _time_of_day(first_scalar(start.value)) if start else "00:00"
    high = _time_of_day(first_scalar(stop.value)) if stop else "23:59:59"
    return f'meta hour "{low}"-"{high}"'


def _time_day_match(options: dict[str, RenderedOption]) -> str | None:
    """
    Build ``meta day`` from days/weekdays (aliases of one xt flag).

    Names are printed in nft's numeric order (Sunday first) and quoted; a
    single day drops the braces (kernel readback, negation included).  Both
    keys at once is an xt conflict, so it refuses.
    """
    days = options.get("days")
    weekdays = options.get("weekdays")
    if days is not None and weekdays is not None:
        raise FermError(
            "mod time cannot combine 'days' and 'weekdays' for the nft backend"
        )
    option = days if days is not None else weekdays
    if option is None:
        return None
    scalar, neg = unwrap_value(option.value)
    indices = sorted(
        {_xt_day_index(token) for token in scalar.split(",") if token.strip()}
    )
    names = [f'"{_NFT_DAY_NAMES[index]}"' for index in indices]
    body = names[0] if len(names) == 1 else f"{{ {', '.join(names)} }}"
    return f"meta day {_op(neg)}{body}"


def _xt_day_index(token: str) -> int:
    """Map one xt weekday (name/abbreviation/1..7) to its nft index."""
    lowered = token.strip().lower()
    if lowered in _XT_DAY_TO_NFT:
        return _XT_DAY_TO_NFT[lowered]
    if lowered.isdigit() and 1 <= int(lowered) <= _DAYS_PER_WEEK:
        return int(lowered) % _DAYS_PER_WEEK
    raise FermError(f"unknown weekday '{token.strip()}' for nft backend")


def _time_span_match(options: dict[str, RenderedOption]) -> str | None:
    """Build ``meta time`` from datestart/datestop (range / >= / <=)."""
    start = options.get("datestart")
    stop = options.get("datestop")
    low = _datetime_iso(first_scalar(start.value)) if start else None
    high = _datetime_iso(first_scalar(stop.value)) if stop else None
    if low is not None and high is not None:
        return f'meta time "{low}"-"{high}"'
    if low is not None:
        return f'meta time >= "{low}"'
    if high is not None:
        return f'meta time <= "{high}"'
    return None


def _time_matches(options: dict[str, RenderedOption]) -> list[NftMatch]:
    """
    Translate a rule's ``mod time`` options to 0-3 nft meta matches.

    hour/day/time are independent selectors emitted in a fixed order.
    monthday, kerneltz, and contiguous have no faithful nft equivalent
    (monthday has no meta selector; kerneltz/contiguous change the local-time
    and cross-midnight semantics nft's UTC-anchored evaluation cannot mirror),
    so they refuse.
    """
    for refused in ("monthday", "kerneltz", "contiguous"):
        if refused in options:
            raise FermError(
                f"mod time '{refused}' not yet supported by nft backend"
            )
    matches: list[NftMatch] = []
    for builder in (_time_hour_match, _time_day_match, _time_span_match):
        expr = builder(options)
        if expr is not None:
            matches.append(NftMatch(expr))
    return matches


#: ct byte/packet counters are 64-bit; the guard is wider than quota's 2^63-1.
_CONNBYTES_MAX: Final[int] = 2**64 - 1

_CONNBYTES_DIRS: Final[frozenset[str]] = frozenset(
    {"original", "reply", "both"}
)

_CONNBYTES_MODES: Final[frozenset[str]] = frozenset(
    {"bytes", "packets", "avgpkt"}
)


def _connbytes_u64(scalar: str) -> str:
    """Validate a connbytes bound as an unsigned 64-bit integer."""
    if not scalar.isdigit():
        raise FermError(
            f"invalid connbytes value '{scalar}' for the nft backend"
        )
    value = int(scalar)
    if value > _CONNBYTES_MAX:
        raise FermError(
            f"connbytes value '{scalar}' exceeds 2^64-1 for the nft backend"
        )
    return str(value)


def _connbytes_range(selector: str, value: str, neg: bool) -> str:
    """
    Spell a connbytes range operand in the kernel-readback form.

    xt's ``lo:hi`` window maps to the readback's comparison spelling:
    ``N:`` (or a bare ``N``, which xt reads as ``N:``) is ``>= N``, ``:M``
    is the closed ``0-M`` interval, and ``N:M`` is ``N-M``.  Negation flips
    ``>=`` to ``<`` for the open lower bound and prefixes ``!=`` for the
    interval forms -- the ``>=``/``<`` symbols are the readback spelling, not
    iptables-translate's ``ge``/``lt``.
    """
    low, sep, high = value.partition(":")
    if not sep:  # bare N -> N: (open upper bound)
        bound = _connbytes_u64(value)
        return f"{selector} {'<' if neg else '>='} {bound}"
    if low and not high:  # N:
        bound = _connbytes_u64(low)
        return f"{selector} {'<' if neg else '>='} {bound}"
    if not low and high:  # :M -> 0-M
        upper = _connbytes_u64(high)
        return f"{selector} {'!= ' if neg else ''}0-{upper}"
    if not low and not high:  # bare ':'
        raise FermError(
            f"invalid connbytes range '{value}' for the nft backend"
        )
    lower = _connbytes_u64(low)
    upper = _connbytes_u64(high)
    if int(low) > int(high):
        raise FermError(
            f"connbytes range '{value}' has lo > hi for the nft backend"
        )
    return f"{selector} {'!= ' if neg else ''}{lower}-{upper}"


def _connbytes_match(opts: dict[str, RenderedOption]) -> NftMatch:
    """
    Translate a rule's ``mod connbytes`` options to one ``ct`` counter match.

    The three options are collected rule-wide (the ``mod time`` precedent);
    ``connbytes-dir`` and ``connbytes-mode`` are both mandatory (xt refuses
    without them), and neither may be negated.  ``dir both`` drops the
    direction prefix; ``original``/``reply`` prefix the selector.
    """
    value_opt = opts.get("connbytes")
    if value_opt is None:
        raise FermError(
            "mod connbytes needs a 'connbytes' value for the nft backend"
        )
    dir_opt = opts.get("connbytes-dir")
    mode_opt = opts.get("connbytes-mode")
    if dir_opt is None or mode_opt is None:
        raise FermError(
            "mod connbytes needs both 'connbytes-dir' and 'connbytes-mode' "
            "for the nft backend"
        )
    direction, dir_neg = unwrap_value(dir_opt.value)
    mode, mode_neg = unwrap_value(mode_opt.value)
    if dir_neg or mode_neg:
        raise FermError(
            "mod connbytes dir/mode cannot be negated for the nft backend"
        )
    if direction not in _CONNBYTES_DIRS:
        raise FermError(
            f"invalid connbytes-dir '{direction}' for the nft backend"
        )
    if mode not in _CONNBYTES_MODES:
        raise FermError(f"invalid connbytes-mode '{mode}' for the nft backend")
    prefix = "" if direction == "both" else f"{direction} "
    selector = f"ct {prefix}{mode}"
    value, neg = unwrap_value(value_opt.value)
    return NftMatch(_connbytes_range(selector, value, neg))


#: nft rejects a quota >= 2^63 ("Value too large"); the ceiling is narrower
#: than connbytes' full u64.
_QUOTA_MAX: Final[int] = 2**63 - 1

#: The three quota units the kernel readback uses, largest first (there is no
#: ``gbytes``; the ladder tops out at ``mbytes``).
_QUOTA_UNITS: Final[tuple[tuple[int, str], ...]] = (
    (1024 * 1024, "mbytes"),
    (1024, "kbytes"),
)


def _quota_canon(value: int) -> str:
    """
    Spell a byte quota in the largest evenly-dividing kernel unit.

    The readback prints ``2 kbytes`` for 2048 and ``1 mbytes`` for 2^20 but
    keeps an indivisible count in bytes (1500000 stays ``1500000 bytes``).
    There is no ``gbytes``, so 2^30 reads back as ``1024 mbytes``.
    """
    for divisor, unit in _QUOTA_UNITS:
        if value and value % divisor == 0:
            return f"{value // divisor} {unit}"
    return f"{value} bytes"


def _quota_statement(option: RenderedOption) -> NftQuota:
    """
    Translate a ``mod quota --quota N`` match to the nft ``quota`` statement.

    The ferm ``quota=s`` keyword carries no ``!``, so the negated ``quota
    over`` readback form cannot arise here; the value is validated against
    nft's 2^63-1 ceiling and canonicalised to the kernel's printed unit.
    """
    scalar, _ = unwrap_value(option.value)
    if not scalar.isdigit():
        raise FermError(f"invalid quota '{scalar}' for the nft backend")
    value = int(scalar)
    if value > _QUOTA_MAX:
        raise FermError(
            f"quota '{scalar}' exceeds nft's 2^63-1 ceiling for the nft "
            "backend"
        )
    return NftQuota(f"quota {_quota_canon(value)}")


#: connlimit's connection count is a 32-bit value.
_CONNLIMIT_COUNT_MAX: Final[int] = 0xFFFFFFFF


def _connlimit_count(scalar: str) -> str:
    """Validate a connlimit connection count as an unsigned 32-bit integer."""
    if not scalar.isdigit():
        raise FermError(
            f"invalid connlimit count '{scalar}' for the nft backend"
        )
    value = int(scalar)
    if value > _CONNLIMIT_COUNT_MAX:
        raise FermError(
            f"connlimit count '{scalar}' exceeds 2^32-1 for the nft backend"
        )
    return str(value)


def _connlimit_update(domain: Family, rule: RenderedRule) -> NftSetUpdate:
    """
    Translate a rule's ``mod connlimit`` to a per-rule ``add @set { ... }``.

    xt_connlimit allocates one ``nf_conncount`` tree PER RULE, so every rule
    gets its own implicit dynamic set (never shared).  The set carries the
    address key (``ip|ip6 saddr|daddr``, narrowed by ``connlimit-mask`` to
    ``& <netmask>``) plus a ``ct count [over] N`` stateful expression on the
    element.  The name is a placeholder here; :func:`_finalize_connlimit_names`
    assigns the stable content-hash name once the full rule text is known.
    Exactly one of ``connlimit-upto``/``connlimit-above`` (upto = ``count N``,
    above = ``count over N``; each negates to the other); ``saddr`` and
    ``daddr`` flags together, or a zero/oversized mask, refuse.
    """
    if domain not in (Family.IP, Family.IP6):
        raise FermError("mod connlimit needs the ip or ip6 family for nft")
    opts = {o.name: o for o in rule.options if o.module == "connlimit"}
    upto = opts.get("connlimit-upto")
    above = opts.get("connlimit-above")
    if (upto is not None) == (above is not None):
        raise FermError(
            "mod connlimit needs exactly one of connlimit-upto/"
            "connlimit-above for the nft backend"
        )
    rate_option = upto if upto is not None else above
    assert rate_option is not None  # exactly one is set (checked above)
    count_scalar, neg = unwrap_value(rate_option.value)
    count = _connlimit_count(count_scalar)
    # upto = "not above"; a negated upto behaves like above and vice versa.
    over = (above is not None) != neg
    count_expr = f"ct count over {count}" if over else f"ct count {count}"
    if "connlimit-saddr" in opts and "connlimit-daddr" in opts:
        raise FermError(
            "mod connlimit cannot combine saddr and daddr for the nft backend"
        )
    side = "daddr" if "connlimit-daddr" in opts else "saddr"
    key = f"{domain} {side}"
    mask_option = opts.get("connlimit-mask")
    if mask_option is not None:
        length, _ = unwrap_value(mask_option.value)
        if not length.isdigit():
            raise FermError(
                f"invalid connlimit mask '{length}' for the nft backend"
            )
        bits = int(length)
        max_bits = 32 if domain == Family.IP else 128
        if bits == 0:
            raise FermError(
                "connlimit-mask 0 keys the whole address space as one "
                "bucket; refused for the nft backend"
            )
        if bits > max_bits:
            raise FermError(
                f"connlimit mask '{length}' exceeds /{max_bits} for the nft "
                "backend"
            )
        if bits < max_bits:  # a full mask needs no `& netmask`
            key += f" & {_prefix_length_mask(domain, length)}"
    set_type = "ipv4_addr" if domain == Family.IP else "ipv6_addr"
    return NftSetUpdate(
        _CONNLIMIT_SENTINEL, f"{key} {count_expr}", set_type, verb="add"
    )


def _finalize_connlimit_names(
    domain: Family, table: str, chain: str, rules: list[NftRule]
) -> None:
    """
    Assign each connlimit set a stable content-hash name, in place.

    Runs per chain in ``render()`` STRICTLY BEFORE the collapse pass: the
    name depends on the fully rendered rule text (unknown inside
    ``translate_rule``, where siblings are invisible), so the sentinel stands
    in until here.  The name hashes (family, table, chain, rule text with the
    sentinel still in place -- which breaks the name<->text cycle, and an
    ordinal that separates textually identical rules).  Ordering matters two
    ways: distinct names give collapse distinct ``NftSetUpdate`` texts, so it
    never folds two connlimit rules into one (which would merge their per-rule
    counters); and the ordinal guarantees two byte-identical rules still get
    separate sets, exactly as xt gives them separate conncount trees.
    """
    ordinals: dict[str, int] = {}
    for rule in rules:
        for stmt in rule.statements:
            if (
                isinstance(stmt, NftSetUpdate)
                and stmt.name == _CONNLIMIT_SENTINEL
            ):
                text = " ".join(s.to_text() for s in rule.statements)
                ordinal = ordinals.get(text, 0)
                ordinals[text] = ordinal + 1
                digest = hashlib.sha256(
                    "\x00".join(
                        (domain.value, table, chain, text, str(ordinal))
                    ).encode(BYTE_ENCODING)
                ).hexdigest()[:12]
                stmt.name = f"connlimit_{digest}"
