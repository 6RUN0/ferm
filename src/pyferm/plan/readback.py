"""Kernel readback parsers (iptables-save, nft) and rule canonicalizers."""

from __future__ import annotations

import re
import shlex
from typing import Final

from ..domains import (
    NFT_CT_STATES,
    NFT_PRIORITY_LANDMARKS,
    NFT_TABLE_NAME,
    apply_priority_offset,
)
from ..errors import FermError
from ..nftset import (
    canonicalize_element,
    canonicalize_set_elements,
    set_body,
    sort_vmap_pairs,
)
from .model import ParsedChain, ParsedObject, ParsedSet, ParsedTable

# ``:chain policy [pkts:bytes]`` has exactly 2 required fields + 1 optional.
_CHAIN_PARTS_MIN: Final[int] = 2

_CHAIN_PARTS_MAX: Final[int] = 3

# ``-c pkts bytes`` occupies the first 3 tokens of a rule body.
_COUNTER_TOKENS: Final[int] = 3


def _parse_error(lineno: int, line: str) -> FermError:
    """
    Build a sanitized parse error: line number + cleaned, truncated text.

    The dump is a trusted source (live kernel/mock), but it can carry
    comment text, log prefixes and internal addresses; the excerpt is
    length-capped and stripped of control bytes so a malformed line never
    dumps raw bytes (latin-1) to a terminal.
    """
    excerpt = "".join(c for c in line.rstrip("\n")[:80] if c.isprintable())
    return FermError(f"cannot parse save line {lineno}: {excerpt!r}")


def parse_save(text: str, *, host_mask: str) -> dict[str, ParsedTable]:
    """
    Parse one family's ``iptables-save`` dump into ``{table: ParsedTable}``.

    Fail-loud: every non-comment, non-blank line must match exactly one
    production (``*table`` / ``:chain policy`` / ``-A rule`` / ``COMMIT``);
    anything else raises :class:`FermError`.  Counters (``[pkts:bytes]`` on
    chain lines, ``-c pkts bytes`` on rule lines) are stripped.
    ``host_mask`` selects the family's host mask for rule canonicalization
    (added by the canonicalization pass).
    """
    tables: dict[str, ParsedTable] = {}
    current: ParsedTable | None = None
    lines = text.splitlines()

    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("*"):
            if current is not None:
                raise _parse_error(lineno, raw)  # previous table not COMMITted
            name = line[1:]
            if not name or " " in name or name in tables:
                raise _parse_error(lineno, raw)
            current = ParsedTable()
            tables[name] = current
            continue

        if line == "COMMIT":
            if current is None:
                raise _parse_error(lineno, raw)
            current = None
            continue

        if current is None:
            raise _parse_error(lineno, raw)  # :chain / -A outside a table

        if line.startswith(":"):
            parts = line[1:].split()
            # chain + policy are required; [pkts:bytes] counter is optional
            if len(parts) < _CHAIN_PARTS_MIN or len(parts) > _CHAIN_PARTS_MAX:
                raise _parse_error(lineno, raw)
            chain, policy = parts[0], parts[1]
            current.chains[chain] = ParsedChain(policy=policy)
            continue

        if line.startswith("-A "):
            body = line[len("-A ") :]
            chain, _, rest = body.partition(" ")
            if not chain or chain not in current.chains:
                # -A for an undeclared chain is malformed iptables-save
                raise _parse_error(lineno, raw)
            current.chains[chain].rules.append(
                _canonicalize_rule(rest, host_mask)
            )
            continue

        raise _parse_error(lineno, raw)

    if current is not None:
        raise _parse_error(len(lines), "<EOF: missing COMMIT>")

    return tables


#: Whole-token option aliases (source of truth: Makefile RESULT_SED, plus the
#: multiport long->short pair).  Matched as whole tokens, never as prefixes.
_OPTION_ALIASES: Final[dict[str, str]] = {
    "--protocol": "-p",
    "--source": "-s",
    "--destination": "-d",
    "--match": "-m",
    "--jump": "-j",
    "--goto": "-g",
    "--in-interface": "-i",
    "--out-interface": "-o",
    "--fragment": "-f",
    "--destination-ports": "--dports",
    "--source-ports": "--sports",
}

#: ``-m <proto>`` matches the kernel injects as implied by ``-p <proto>``.
_IMPLIED_MATCHES: Final[frozenset[str]] = frozenset(
    {"tcp", "udp", "icmp", "icmpv6"}
)


def _tokenize_rule(body: str) -> list[str]:
    """
    Split a rule body into tokens, keeping quoted comments intact.

    Safe bias: if the body cannot be lexed (unbalanced quote), fall back to
    a whitespace split.  Worst case is a phantom diff, never a hidden one.
    """
    try:
        return shlex.split(body, posix=False)
    except ValueError:
        return body.split()


def _proto_of(tokens: list[str]) -> str | None:
    """Return the value following ``-p`` (already alias-normalized), if any."""
    for index, token in enumerate(tokens):
        if token == "-p" and index + 1 < len(tokens):
            return tokens[index + 1]
    return None


def _strip_host_mask(operand: str, host_mask: str) -> str:
    """Strip the family host mask (``/32`` or ``/128``) from an address."""
    if operand.endswith(host_mask):
        return operand[: -len(host_mask)]
    return operand


def _canonicalize_rule(body: str, host_mask: str) -> str:
    """
    Normalize one rule body to canonical form via whitelisted transforms.

    Strips a leading ``-c pkts bytes`` counter, normalizes option aliases to
    their short form, collapses a repeated ``-m <module>`` to one, drops an
    injected ``-m <proto>`` implied by ``-p <proto>``, and strips the family
    host mask from ``-s``/``-d`` operands only.  Anything outside the
    whitelist is left untouched (safe bias).
    """
    tokens = _tokenize_rule(body)
    if tokens[:1] == ["-c"] and len(tokens) >= _COUNTER_TOKENS:
        tokens = tokens[_COUNTER_TOKENS:]
    tokens = [_OPTION_ALIASES.get(token, token) for token in tokens]

    proto = _proto_of(tokens)
    seen_modules: set[str] = set()
    out: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-m" and index + 1 < len(tokens):
            module = tokens[index + 1]
            if module in _IMPLIED_MATCHES and module == proto:
                index += 2
                continue
            if module in seen_modules:
                index += 2
                continue
            seen_modules.add(module)
            out.append(token)
            out.append(module)
            index += 2
            continue
        if token in ("-s", "-d") and index + 1 < len(tokens):
            out.append(token)
            out.append(_strip_host_mask(tokens[index + 1], host_mask))
            index += 2
            continue
        out.append(token)
        index += 1
    return " ".join(out)


#: Standard nft priority landmark names -> numeric, keyed by nft family.
#: Shared with the parser (which resolves config-side landmark priorities)
#: via ``domains`` so a single table is the source of truth; the
#: canonicalizer here keys it by nft family (``bridge``), the parser by ferm
#: domain (``eb``), both of which the table carries.
_NFT_PRIORITY_NAMES: Final[dict[str, dict[str, int]]] = NFT_PRIORITY_LANDMARKS

#: ip-family reject default: nft collapses to bare 'reject'.
_NFT_REJECT_DEFAULTS: Final[dict[str, str]] = {
    "ip": "icmp",
    "ip6": "icmpv6",
}

#: nft's default reject message type for both icmp families.
_NFT_REJECT_DEFAULT_TYPE: Final[str] = "port-unreachable"

#: One ``{ ... }`` operand run, with an optional ``vmap`` marker so a verdict
#: map is told apart from a plain anonymous set (no nesting in v1).  The marker
#: is required because an IPv6 set element carries ``:`` too, so the colon
#: alone cannot discriminate a vmap.
#: The ``vmap`` marker is anchored on its left (``(?<![\w@])``) so a token
#: that merely ends in ``vmap`` (an identifier, an ``@foovmap`` set reference)
#: is not misread as a verdict map on the untrusted kernel-readback side.
_NFT_SET_RE: Final[re.Pattern[str]] = re.compile(
    r"((?<![\w@])vmap\s*)?\{([^{}]*)\}"
)

#: A brace run is a ct-state operand when ``ct state`` (optionally negated)
#: immediately precedes it.  The brace run alone carries no context, so the
#: text to its left supplies it; this lets the braced form reorder to nft's
#: bitmask sequence like the unbraced ``ct state a,b`` form already does.
_CT_STATE_PREFIX_RE: Final[re.Pattern[str]] = re.compile(
    r"ct state\s*(?:!=)?\s*$"
)


def _normalize_set_run(match: re.Match[str]) -> str:
    """Rewrite one ``{ ... }`` operand run (set or vmap) to canonical form."""
    if match.group(1) is not None:
        return _normalize_vmap_run(match.group(2))
    inner = match.group(2)
    # A ``map { k : v }`` statement (e.g. ``... map { 1.2.3.4 : 0x1 }``)
    # carries ``" : "`` members but no ``vmap`` marker; it is not a set, so
    # splitting it would mangle it.  An anonymous set never holds a ``" : "``
    # member, so leave any such run verbatim (safe on both sides).
    if " : " in inner:
        return match.group(0)
    # Split on commas ONLY.  A member may be a multi-token operator
    # expression -- a concatenation (``1.1.1.1 . 20``) or a bitwise-OR flag
    # (``syn | ack``) -- which nft prints as one comma-separated member;
    # splitting on whitespace too would shatter it into bogus standalone
    # members (a stray ``.``/``|``).
    members = [" ".join(m.split()) for m in inner.split(",")]
    members = [m for m in members if m]
    if not members:
        return "{ }"
    # A ct-state set reorders to nft's fixed bitmask order -- the braced
    # counterpart of the unbraced ct-state transform.  The reorder applies only
    # when every member is a known state (an unknown member is safe-bias kept).
    if _CT_STATE_PREFIX_RE.search(match.string[: match.start()]) and all(
        m in NFT_CT_STATES for m in members
    ):
        ordered = sorted(members, key=NFT_CT_STATES.index)
        return set_body(ordered)
    # An operator-bearing member (concat / OR, recognised by an interior space)
    # is not a plain scalar: scalar dedup/sort and element canon do not model
    # it, so leave the run verbatim with normalized spacing (safe-bias -- a
    # noisy diff beats a false 'no changes').
    if any(" " in m for m in members):
        return set_body(members)
    return set_body(canonicalize_set_elements(members))


def _normalize_vmap_run(inner: str) -> str:
    """
    Rewrite a ``vmap { k : v, ... }`` run to canonical key order.

    Each member splits on the ``" : "`` separator into a key and a (possibly
    multi-token, e.g. ``jump foo``) verdict; the key is canonicalized to its
    kernel-readback form and the pairs are reordered by the key's canonical
    rank so a folded vmap converges on both diff sides.  Splitting on the bare
    ``:`` would mangle an IPv6 address key (``2001:db8::1``), which carries its
    own colons; the emitter always renders the separator with surrounding
    spaces and a verdict (``jump``/``goto`` target) can never contain ``" : "``
    (the chain-name grammar forbids it), so ``rpartition`` isolates the key
    cleanly.  A member that is not a well-formed pair leaves the whole run
    verbatim (safe-bias: a noisy diff beats a false 'no changes').
    """
    pairs: list[tuple[str, str]] = []
    for member in inner.split(","):
        key, sep, verdict = member.rpartition(" : ")
        if not sep:
            return "vmap {" + inner + "}"
        pairs.append((canonicalize_element(key.strip()), verdict.strip()))
    rendered = ", ".join(f"{k} : {v}" for k, v in sort_vmap_pairs(pairs))
    return "vmap { " + rendered + " }"


def _normalize_sets(body: str) -> str:
    """
    Rewrite every UNQUOTED ``{ ... }`` run to canonical ``{ a, b, c }``.

    Only braces outside quoted spans are anonymous-set operands.  Braces inside
    a quoted ``comment``/``log prefix`` value are free text: rewriting them
    would let two distinct comments (``"{ 80, 22 }"`` vs ``"{ 22, 80 }"``)
    canonicalize equal -- a false "no changes", the exact dishonesty the canon
    exists to prevent.  Both diff sides run this, so the quoted text stays
    byte-faithful on each side.

    A quote character only opens a protected (verbatim) span at brace depth
    zero, i.e. outside any ``{ ... }`` run; brace depth is tracked while
    outside a quote.  This tells a real ``comment``/``log prefix`` quote apart
    from a quoted set element (``iifname { "eth0", "wlan0" } accept``): the
    latter's quotes sit at depth one and stay inside the run ``_NFT_SET_RE``
    matches, so ``_normalize_set_run`` sees the whole ``{ ... }`` including its
    quoted members.
    """
    out: list[str] = []
    start = 0
    quote: str | None = None
    depth = 0
    for index, char in enumerate(body):
        if quote is None:
            if char in "{}":
                depth += 1 if char == "{" else -1
            elif char in "\"'" and depth == 0:
                out.append(
                    _NFT_SET_RE.sub(_normalize_set_run, body[start:index])
                )
                start = index
                quote = char
        elif char == quote:
            out.append(body[start : index + 1])  # quoted span, verbatim
            start = index + 1
            quote = None
    tail = body[start:]
    out.append(
        tail
        if quote is not None
        else _NFT_SET_RE.sub(_normalize_set_run, tail)
    )
    return "".join(out)


def canonicalize_nft_rule(body: str, *, family: str) -> str:
    """
    Normalize one nft rule body to canonical form (idempotent, both sides).

    Applies three whitelisted transforms to the tokenized rule body and
    rejoins with single spaces.  Everything not matched by a transform is
    left verbatim (safe-bias: a false 'no changes' is worse than a noisy
    diff for a firewall).

    Transforms applied:
    - ct state member reordering to nft's fixed bitmask order.
    - Removal of the literal word 'type' in 'reject with <fam> type <X>',
      then collapsing to bare 'reject' when the result is the family default.
    - Appending 'burst 5 packets' after 'limit rate <value>' when absent.
    """
    tokens = _tokenize_rule(body)
    out: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]

        # reorder ct state members to nft's fixed bitmask sequence
        if (
            token == "ct"
            and index + 1 < len(tokens)
            and tokens[index + 1] == "state"
        ):
            out.append(token)
            out.append(tokens[index + 1])
            index += 2
            # optional negation operator
            if index < len(tokens) and tokens[index] == "!=":
                out.append(tokens[index])
                index += 1
            if index < len(tokens):
                members_token = tokens[index]
                members = members_token.split(",")
                if all(m in NFT_CT_STATES for m in members):
                    ordered = sorted(members, key=NFT_CT_STATES.index)
                    out.append(",".join(ordered))
                else:
                    # unknown member -> safe-bias: leave verbatim
                    out.append(members_token)
                index += 1
            continue

        # normalize reject: drop the literal 'type' keyword,
        # collapse the family default to bare reject
        if (
            token == "reject"
            and index + 2 < len(tokens)
            and tokens[index + 1] == "with"
        ):
            fam_token = tokens[index + 2]
            # drop the literal word 'type' if present:
            # 'reject with <fam> type <X>' -> 'reject with <fam> <X>'
            if index + 4 < len(tokens) and tokens[index + 3] == "type":
                reject_type = tokens[index + 4]
                # check whether this is the family default
                default_fam = _NFT_REJECT_DEFAULTS.get(family)
                out.append("reject")
                if (
                    fam_token != default_fam
                    or reject_type != _NFT_REJECT_DEFAULT_TYPE
                ):
                    out.append("with")
                    out.append(fam_token)
                    out.append(reject_type)
                index += 5
                continue
            # already-normalized 'reject with <fam> <X>' (no 'type' word)
            # check whether it is the family default
            if index + 3 < len(tokens):
                reject_type = tokens[index + 3]
                default_fam = _NFT_REJECT_DEFAULTS.get(family)
                if (
                    fam_token == default_fam
                    and reject_type == _NFT_REJECT_DEFAULT_TYPE
                ):
                    out.append("reject")
                    index += 4
                    continue
            # not the default or not enough tokens:
            # leave 'reject with <fam> ...' verbatim
            out.append(token)
            index += 1
            continue

        # append nft's implicit burst default when not already present
        if (
            token == "limit"
            and index + 2 < len(tokens)
            and tokens[index + 1] == "rate"
        ):
            out.append(token)
            out.append(tokens[index + 1])
            out.append(tokens[index + 2])
            index += 3
            # only inject burst if it is not already present
            if not (index < len(tokens) and tokens[index] == "burst"):
                out.append("burst")
                out.append("5")
                out.append("packets")
            continue

        out.append(token)
        index += 1

    return _normalize_sets(" ".join(out))


def canonicalize_nft_header(header: str, *, family: str) -> str:
    """
    Normalize a base-chain header to the canonical policy-field string.

    Strips semicolons, collapses whitespace, maps priority landmark names
    to their numeric values for the given family, and appends 'policy accept'
    when no policy token is present.  Tokens not explicitly transformed are
    preserved verbatim (safe-bias).  The result is idempotent.
    """
    # Strip semicolons and normalize whitespace before splitting into tokens.
    clean = header.replace(";", " ")
    tokens = clean.split()

    out: list[str] = []
    has_policy = False
    # Unknown family -> empty map so priority tokens pass through verbatim.
    priority_map = _NFT_PRIORITY_NAMES.get(family, {})
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "policy":
            has_policy = True
            out.append(token)
            index += 1
            continue
        if token == "priority" and index + 1 < len(tokens):
            out.append(token)
            next_tok = tokens[index + 1]
            # nft pretty-prints a numeric priority near a landmark as an
            # offset, e.g. -1 -> 'filter - 1', 49 -> 'security - 1', 5 ->
            # 'filter + 5'.  Resolve both the exact-landmark and the offset
            # form to the integer so a config's numeric priority canonicalizes
            # identically to the kernel's display -- otherwise a reload that
            # changed nothing would diff and rebuild the chain every time.
            is_offset = index + 3 < len(tokens) and tokens[index + 2] in (
                "+",
                "-",
            )
            if next_tok in priority_map and is_offset:
                try:
                    magnitude = int(tokens[index + 3])
                except ValueError:
                    # malformed offset -> leave the name verbatim (safe-bias)
                    out.append(next_tok)
                    index += 2
                    continue
                value = apply_priority_offset(
                    priority_map[next_tok], tokens[index + 2], magnitude
                )
                out.append(str(value))
                index += 4
                continue
            if next_tok in priority_map:
                out.append(str(priority_map[next_tok]))
            else:
                # numeric or unrecognized name: leave verbatim
                out.append(next_tok)
            index += 2
            continue
        out.append(token)
        index += 1

    if not has_policy:
        out.append("policy")
        out.append("accept")

    return " ".join(out)


def _header_priority(header: str) -> str | None:
    """
    Extract the priority token from a canonical base-chain header.

    Both diff sides are canonicalized (named priorities resolved to integers
    by :func:`canonicalize_nft_header`), so a textual compare of the returned
    token is a correct numeric compare.  Returns ``None`` for a user chain's
    ``-`` placeholder or a header without a priority.
    """
    tokens = header.split()
    for index, token in enumerate(tokens):
        if token == "priority" and index + 1 < len(tokens):
            return tokens[index + 1]
    return None


# Exact token counts for the recognized table/flush productions.
# add table <fam> ferm  /  flush table <fam> ferm  -- exactly 4 tokens.
_NFT_TABLE_PARTS: Final[int] = 4

# add chain: add chain <fam> ferm <chain>
_NFT_CHAIN_MIN_PARTS: Final[int] = 5

# add rule: add rule <fam> ferm <chain> <body-token>
_NFT_RULE_MIN_PARTS: Final[int] = 6

# The verbs a render line can start with (table envelope productions).
_NFT_VERBS: Final[frozenset[str]] = frozenset({"add", "flush", "delete"})

# nft object-type words, shared between the parse-phase dispatch above and
# the desired-side indexer's dispatch (_build_desired_index) below.
_NFT_OBJ_CHAIN: Final[str] = "chain"

_NFT_OBJ_SET: Final[str] = "set"

_NFT_OBJ_ELEMENT: Final[str] = "element"

_NFT_OBJ_RULE: Final[str] = "rule"

#: Single-token object sub-verb.
_NFT_OBJ_SECMARK: Final[str] = "secmark"

#: The two-token ``ct helper`` object sub-verb, split across ``parts[1:3]``.
_NFT_OBJ_CT: Final[str] = "ct"

_NFT_OBJ_HELPER: Final[str] = "helper"

#: ``ParsedObject.kind`` for a conntrack-helper object (the nft keyword).
_NFT_OBJ_CT_HELPER: Final[str] = "ct helper"

#: Name-token index on an object line: ``add <kind> <fam> ferm <name>`` puts
#: the name at ``parts[4]`` for a one-word kind; ``ct helper`` shifts it to 5.
_NFT_OBJ_NAME_INDEX: Final[int] = 4

_NFT_CTHELPER_NAME_INDEX: Final[int] = 5

#: Minimum token count for ``add ct helper <fam> ferm <name> {`` (indices 0-6).
_NFT_CTHELPER_MIN_PARTS: Final[int] = 7


def _ensure_ferm_table(tables: dict[str, ParsedTable]) -> None:
    """Insert an empty ``ferm`` table entry if not already present."""
    if NFT_TABLE_NAME not in tables:
        tables[NFT_TABLE_NAME] = ParsedTable()


def _brace_body(line: str) -> str | None:
    """
    Return the raw text between the first ``{`` and the last ``}``.

    ``None`` when the braces are absent or malformed (close at or before
    open). The slice is returned verbatim; callers strip if they need to.
    """
    brace_open = line.find("{")
    brace_close = line.rfind("}")
    if brace_open == -1 or brace_close <= brace_open:
        return None
    return line[brace_open + 1 : brace_close]


def _store_table_object(
    tables: dict[str, ParsedTable], obj_name: str, kind: str, line: str
) -> None:
    """
    Record a table object (``secmark``/``ct helper``) under ``ferm``.

    Shared tail of the object-line handlers: ensure the table exists, take
    the stripped brace body, and store a :class:`ParsedObject`.
    """
    _ensure_ferm_table(tables)
    body = (_brace_body(line) or "").strip()
    tables[NFT_TABLE_NAME].objects[obj_name] = ParsedObject(
        obj_name, kind, body
    )


def _parse_set_header(inner: str) -> tuple[str | None, tuple[str, ...]]:
    """
    Extract ``(type, flags)`` from a set declaration's brace body.

    Accepts both the render form (``type ipv4_addr; flags interval;``) and the
    ``nft list`` form (``type ipv4_addr`` / ``flags interval`` on separate
    lines, pre-joined by the caller).  Tokens after ``type`` up to the next
    statement form the type; every token after a ``flags`` keyword is a flag.
    Unknown statements are ignored (safe-bias).
    """
    type_: str | None = None
    flags: list[str] = []
    for stmt in inner.replace("\n", ";").split(";"):
        tokens = stmt.split()
        if not tokens:
            continue
        if tokens[0] == "type" and len(tokens) > 1:
            type_ = tokens[1]
        elif tokens[0] == "flags":
            flags.extend(tokens[1:])
    return type_, tuple(flags)


def _check_family(
    current: str | None, seen: str, lineno: int, raw: str
) -> str:
    """
    Verify that ``seen`` matches ``current`` (if already set), return it.

    All lines in a single nft script share the same nft family; a mismatch
    signals a corrupted or mixed-family input and is a parse error.
    """
    if current is not None and seen != current:
        raise _parse_error(lineno, raw)
    return seen


def _parse_object_head(
    parts: list[str],
    family: str | None,
    lineno: int,
    raw: str,
    *,
    name_index: int = _NFT_OBJ_NAME_INDEX,
) -> tuple[str, str]:
    """
    Validate the shared ``add <kind> <family> ferm <name>`` line head.

    Every single-word object line carries the same 5-token head (name at
    ``parts[4]``); the two-word ``ct helper`` keyword shifts the family, table,
    and name one slot right (``name_index=5``).  The non-``ferm`` table check
    and the cross-line family consistency check are identical for all kinds.
    Returns the narrowed ``(family, name)``.
    """
    fam_tok = parts[name_index - 2]
    table_name = parts[name_index - 1]
    name = parts[name_index]
    if table_name != NFT_TABLE_NAME:
        raise _parse_error(lineno, raw)
    return _check_family(family, fam_tok, lineno, raw), name


def parse_nft_script(text: str) -> dict[str, ParsedTable]:
    """
    Parse a render().save nft script into {table: ParsedTable} (fail-loud).

    The input is a line-oriented nft -f script produced by the nft backend.
    Every non-blank, non-comment line must match exactly one of seven
    recognized productions; anything else raises :class:`FermError`.

    Productions recognized:

    - ``add table <fam> ferm``                           -- materializes table
    - ``flush table <fam> ferm``                         -- materializes table
    - ``delete table <fam> ferm``                        -- resets the table
    - ``add chain <fam> ferm <chain> { <header> }``     -- base chain
    - ``add chain <fam> ferm <chain>``                   -- user chain
    - ``add rule  <fam> ferm <chain> <body>``            -- rule
    - ``add set <fam> ferm <set> { ... }``             -- named set
    - ``add element <fam> ferm <set> { <e>, ... }``   -- set elements

    The family token is derived from the first line that carries one;
    all subsequent lines must use the same family or the parse fails.
    Rule bodies and base-chain headers are canonicalized on ingestion.
    """
    tables: dict[str, ParsedTable] = {}
    family: str | None = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        verb = parts[0]

        # -- table envelope / flush directive: declares (materializes) the
        # ferm table; see the _ensure_ferm_table call below for why. ---------
        # Exact 4-token match: any extra token is a parse error.
        if parts[1:2] == ["table"] and verb in _NFT_VERBS:
            if len(parts) != _NFT_TABLE_PARTS or parts[3] != NFT_TABLE_NAME:
                raise _parse_error(lineno, raw)
            family = _check_family(family, parts[2], lineno, raw)
            if verb == "delete":
                # `delete table` drops every object; a following `add table`
                # re-materializes it empty.  This models the atomic whole-table
                # replace (delete + re-add) the nft backend emits on a full
                # reload so a removed base chain cannot survive empty.
                tables.pop(NFT_TABLE_NAME, None)
                continue
            # Declaring the table materializes it even when the config
            # renders no chains: diff_tables iterates desired tables, so a
            # present-but-empty ferm table is what surfaces live foreign
            # chains as removals.
            _ensure_ferm_table(tables)
            continue

        if verb != "add":
            raise _parse_error(lineno, raw)

        sub = parts[1] if len(parts) > 1 else ""

        # -- add chain -------------------------------------------------------
        if sub == _NFT_OBJ_CHAIN and len(parts) >= _NFT_CHAIN_MIN_PARTS:
            family, chain_name = _parse_object_head(parts, family, lineno, raw)

            # parts[5:] is the payload after <chain>.  Valid shapes:
            #   [] (user chain) or ['{', ..., '}'] (base chain).
            # Any non-'{' first token is extra garbage -> parse error.
            tail = parts[5:]
            if not tail:
                # user chain: nothing after the chain name
                _ensure_ferm_table(tables)
                tables[NFT_TABLE_NAME].chains[chain_name] = ParsedChain(
                    policy="-"
                )
            elif tail[0] == "{":
                # base chain: closing brace must be present on the same line
                rest = line[len("add chain") :].strip()
                brace_start = rest.find("{")
                brace_end = rest.rfind("}")
                if brace_end == -1 or brace_end <= brace_start:
                    raise _parse_error(lineno, raw)
                header = rest[brace_start + 1 : brace_end].strip()
                canon = canonicalize_nft_header(header, family=family)
                _ensure_ferm_table(tables)
                tables[NFT_TABLE_NAME].chains[chain_name] = ParsedChain(
                    policy=canon
                )
            else:
                # extra token before the brace (or instead of it) is invalid
                raise _parse_error(lineno, raw)
            continue

        # -- add set ---------------------------------------------------------
        if sub == _NFT_OBJ_SET and len(parts) >= _NFT_CHAIN_MIN_PARTS:
            family, set_name = _parse_object_head(parts, family, lineno, raw)
            _ensure_ferm_table(tables)
            set_obj = tables[NFT_TABLE_NAME].sets.setdefault(
                set_name, ParsedSet(set_name)
            )
            body = _brace_body(line)
            if body is not None:
                set_obj.type_, set_obj.flags = _parse_set_header(body)
            continue

        # -- add secmark (a table object) ------------------------------------
        if sub == _NFT_OBJ_SECMARK and len(parts) >= _NFT_CHAIN_MIN_PARTS:
            family, obj_name = _parse_object_head(parts, family, lineno, raw)
            _store_table_object(tables, obj_name, _NFT_OBJ_SECMARK, line)
            continue

        # -- add ct helper (a two-word table object) -------------------------
        if (
            sub == _NFT_OBJ_CT
            and parts[2:3] == [_NFT_OBJ_HELPER]
            and len(parts) >= _NFT_CTHELPER_MIN_PARTS
        ):
            family, obj_name = _parse_object_head(
                parts,
                family,
                lineno,
                raw,
                name_index=_NFT_CTHELPER_NAME_INDEX,
            )
            _store_table_object(tables, obj_name, _NFT_OBJ_CT_HELPER, line)
            continue

        # -- add element -----------------------------------------------------
        if sub == _NFT_OBJ_ELEMENT and len(parts) >= _NFT_CHAIN_MIN_PARTS:
            family, set_name = _parse_object_head(parts, family, lineno, raw)
            body = _brace_body(line)
            if body is None:
                raise _parse_error(lineno, raw)
            elements = [e.strip() for e in body.split(",") if e.strip()]
            _ensure_ferm_table(tables)
            ps = tables[NFT_TABLE_NAME].sets.setdefault(
                set_name, ParsedSet(set_name)
            )
            # A named set is not anonymous: nft rejects a contained-interval
            # overlap rather than absorbing it, so keep every element.
            ps.elements = canonicalize_set_elements(
                ps.elements + elements, absorb_contained=False
            )
            continue

        # -- add rule --------------------------------------------------------
        if sub == _NFT_OBJ_RULE and len(parts) >= _NFT_RULE_MIN_PARTS:
            family, chain_name = _parse_object_head(parts, family, lineno, raw)

            # Body is everything after 'add rule <fam> ferm <chain>'.
            prefix = f"add rule {parts[2]} ferm {chain_name}"
            body = line[len(prefix) :].strip()
            ferm_table = tables.get(NFT_TABLE_NAME)
            if ferm_table is None or chain_name not in ferm_table.chains:
                raise _parse_error(lineno, raw)
            ferm_table.chains[chain_name].rules.append(
                canonicalize_nft_rule(body, family=family)
            )
            continue

        raise _parse_error(lineno, raw)

    return tables


# Depth levels for parse_nft_list's brace-state machine.
_NL_DEPTH_OUTSIDE: Final[int] = 0  # outside everything

_NL_DEPTH_TABLE: Final[int] = 1  # inside the table block

_NL_DEPTH_CHAIN: Final[int] = 2  # inside a chain block

_NL_DEPTH_SET: Final[int] = 3  # inside a set block

_NL_DEPTH_OBJECT: Final[int] = 4  # inside a table-object block (secmark/...)

# Regex anchors for the brace-delimited nft-list grammar.
# These match only the structural openers; rule bodies at chain depth are
# never tested against them (so a '{' inside a rule body is invisible).
_NFT_LIST_TABLE_RE: Final[re.Pattern[str]] = re.compile(
    r"^table\s+(\S+)\s+ferm\s*\{$"
)

_NFT_LIST_CHAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"^chain\s+(\S+)\s*\{$"
)

_NFT_LIST_SET_RE: Final[re.Pattern[str]] = re.compile(r"^set\s+(\S+)\s*\{$")

# Table-object openers: 'secmark <name> {' and the two-word 'ct helper
# <name> {'.  Kept distinct from the set opener so the block body is routed to
# ParsedTable.objects, never mistaken for set elements.
_NFT_LIST_SECMARK_RE: Final[re.Pattern[str]] = re.compile(
    r"^secmark\s+(\S+)\s*\{$"
)

_NFT_LIST_CTHELPER_RE: Final[re.Pattern[str]] = re.compile(
    r"^ct helper\s+(\S+)\s*\{$"
)

# A base-chain header starts with 'type' followed by the hook/priority tokens.
_NFT_LIST_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^type\s+\S+\s+hook\s+\S+\s+priority\b"
)

# nft bare-word identifier grammar (mirrors the backend's _NFT_CHAIN_RE /
# _NFT_SET_NAME_RE, which differ: a chain may carry an interior dash --
# fail2ban-style names -- while a ferm set name never can, since it comes
# from a ferm variable).  Names from a LIVE snapshot are synthesized back
# into 'delete chain'/'delete set' lines, so reject anything nft could not
# have legitimately created -- fail-closed defense-in-depth (no real
# injection vector: the grammar already forbids whitespace/metacharacters).
_NFT_LIST_CHAIN_IDENT_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[A-Za-z][A-Za-z0-9_-]*\Z"
)

_NFT_LIST_SET_IDENT_RE: Final[re.Pattern[str]] = re.compile(
    r"\A[A-Za-z][A-Za-z0-9_]*\Z"
)


def _join_multiline_elements(text: str) -> str:
    """
    Collapse a multi-line 'elements = { ... }' onto one line.

    When ``nft list`` emits a set whose elements span multiple lines, this
    preprocessor joins them before the main loop so the depth-3 branch always
    sees the ``elements`` assignment on a single line.  Text that contains no
    multi-line elements block is returned unchanged.
    """
    out: list[str] = []
    buf: str | None = None
    for line in text.splitlines():
        if buf is not None:
            buf += " " + line.strip()
            if "}" in line:
                out.append(buf)
                buf = None
            continue
        if line.lstrip().startswith("elements") and "}" not in line:
            buf = line.rstrip()
            continue
        out.append(line)
    if buf is not None:
        out.append(buf)
    result = "\n".join(out)
    if text.endswith("\n"):
        result += "\n"
    return result


def parse_nft_list(text: str, *, family: str) -> dict[str, ParsedTable]:
    """
    Parse ``nft list table <fam> ferm`` output into {table: ParsedTable}.

    Recognizes the brace-delimited block grammar emitted by ``nft list``.
    Block open/close is structural only: a ``{`` inside a rule body (e.g.
    an anonymous set) never changes the depth counter.  Any line at
    chain-body depth that is not a block-close anchor is treated as a rule
    body and passed verbatim to the canonicalizer (safe-bias).

    ``family`` is the nft family the snapshot was captured for; it must
    match the inline family token in the ``table`` header, and is forwarded
    to the canonicalizers.

    Empty input (genuine first-run "no table" case) returns ``{}``.
    """
    tables: dict[str, ParsedTable] = {}

    depth = _NL_DEPTH_OUTSIDE
    current_chain: ParsedChain | None = None
    current_set: ParsedSet | None = None
    current_object: ParsedObject | None = None
    # whether this chain's first non-blank body line has been seen
    chain_header_seen = False

    lines = _join_multiline_elements(text).splitlines()
    total = len(lines)

    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if depth == _NL_DEPTH_OUTSIDE:
            # Only valid production: 'table <fam> ferm {'
            m = _NFT_LIST_TABLE_RE.match(line)
            if not m:
                raise _parse_error(lineno, raw)
            inline_fam = m.group(1)
            if inline_fam != family:
                raise _parse_error(lineno, raw)
            _ensure_ferm_table(tables)
            depth = _NL_DEPTH_TABLE
            continue

        if depth == _NL_DEPTH_TABLE:
            # Inside the table: expect 'set <name> {', 'chain <name> {', or '}'
            if line == "}":
                depth = _NL_DEPTH_OUTSIDE
                continue
            m_sec = _NFT_LIST_SECMARK_RE.match(line)
            if m_sec:
                obj_name = m_sec.group(1)
                if not _NFT_LIST_SET_IDENT_RE.match(obj_name):
                    raise _parse_error(lineno, raw)
                current_object = ParsedObject(obj_name, _NFT_OBJ_SECMARK)
                tables[NFT_TABLE_NAME].objects[obj_name] = current_object
                depth = _NL_DEPTH_OBJECT
                continue
            m_cth = _NFT_LIST_CTHELPER_RE.match(line)
            if m_cth:
                obj_name = m_cth.group(1)
                if not _NFT_LIST_SET_IDENT_RE.match(obj_name):
                    raise _parse_error(lineno, raw)
                current_object = ParsedObject(obj_name, _NFT_OBJ_CT_HELPER)
                tables[NFT_TABLE_NAME].objects[obj_name] = current_object
                depth = _NL_DEPTH_OBJECT
                continue
            m_set = _NFT_LIST_SET_RE.match(line)
            if m_set:
                set_name = m_set.group(1)
                if not _NFT_LIST_SET_IDENT_RE.match(set_name):
                    raise _parse_error(lineno, raw)
                current_set = ParsedSet(set_name)
                tables[NFT_TABLE_NAME].sets[current_set.name] = current_set
                depth = _NL_DEPTH_SET
                continue
            m = _NFT_LIST_CHAIN_RE.match(line)
            if not m:
                raise _parse_error(lineno, raw)
            chain_name = m.group(1)
            if not _NFT_LIST_CHAIN_IDENT_RE.match(chain_name):
                raise _parse_error(lineno, raw)
            # policy will be set when the first body line arrives
            current_chain = ParsedChain(policy="-")
            tables[NFT_TABLE_NAME].chains[chain_name] = current_chain
            chain_header_seen = False
            depth = _NL_DEPTH_CHAIN
            continue

        if depth == _NL_DEPTH_CHAIN:
            # Inside a chain body.
            if line == "}":
                current_chain = None
                depth = _NL_DEPTH_TABLE
                continue

            # Any other line at this depth is a rule body (or the base-chain
            # header).  Never count braces here -- an anonymous set on one
            # line (e.g. 'tcp dport { 22, 80 } accept') must not be mistaken
            # for a block opener.
            assert current_chain is not None
            if not chain_header_seen:
                chain_header_seen = True
                if _NFT_LIST_HEADER_RE.match(line):
                    # Base chain: this line is the header, not a rule body.
                    current_chain.policy = canonicalize_nft_header(
                        line, family=family
                    )
                    continue
                # User chain: first line is a rule; fall through to append it.

            current_chain.rules.append(
                canonicalize_nft_rule(line, family=family)
            )
            continue

        if depth == _NL_DEPTH_OBJECT:
            # Inside a table-object body (secmark's quoted context, etc.).
            assert current_object is not None
            if line == "}":
                current_object = None
                depth = _NL_DEPTH_TABLE
                continue
            # Accumulate the body verbatim for rendering; it is NOT diff-
            # relevant (objects diff by content-addressed name), so a simple
            # space-join is enough and dodges normalizing the readback's
            # augmentations (a ct helper's l3proto).
            current_object.body = (
                f"{current_object.body} {line}".strip()
                if current_object.body
                else line
            )
            continue

        if depth == _NL_DEPTH_SET:
            # Inside a set body.
            assert current_set is not None
            if line == "}":
                current_set = None
                depth = _NL_DEPTH_TABLE
                continue
            if line.startswith("elements"):
                body = _brace_body(line)
                if body is not None:
                    members = [e.strip() for e in body.split(",") if e.strip()]
                    current_set.elements = canonicalize_set_elements(
                        current_set.elements + members, absorb_contained=False
                    )
                continue
            # 'type ...'/'flags ...' carry the set's type and flags.
            seen_type, seen_flags = _parse_set_header(line)
            if seen_type is not None:
                current_set.type_ = seen_type
            if seen_flags:
                current_set.flags = current_set.flags + seen_flags
            continue

    if depth != _NL_DEPTH_OUTSIDE:
        raise _parse_error(total or 1, "<EOF: unterminated block>")

    return tables
