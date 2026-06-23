"""
Read-only diff preview for ``ferm --plan``.

Provides three parsers that each produce a ``{table: ParsedTable}`` model:

- :func:`parse_save` -- parses an ``iptables-save`` dump (iptables backend,
  current side).
- :func:`parse_nft_script` -- parses a ``nft -f`` script produced by the
  nft backend (desired side).
- :func:`parse_nft_list` -- parses the output of ``nft list table <fam>
  ferm`` (nft backend, current side).

The diff engine (:func:`diff_tables`) and renderers
(:func:`render_structured`, :func:`render_unified`) are backend-agnostic and
consume whichever parser's output is passed to them.  Read-only by
construction: this module never runs a command -- the cli hands it text.
"""

from __future__ import annotations

import difflib
import re
import shlex
from dataclasses import dataclass, field

from pyferm.errors import FermError
from pyferm.nftset import canonicalize_set_elements, sort_vmap_pairs

# ``:chain policy [pkts:bytes]`` has exactly 2 required fields + 1 optional.
_CHAIN_PARTS_MIN = 2
_CHAIN_PARTS_MAX = 3

# ``-c pkts bytes`` occupies the first 3 tokens of a rule body.
_COUNTER_TOKENS = 3


@dataclass
class ParsedChain:
    """One parsed chain: its policy field and its ordered rule bodies."""

    policy: str
    rules: list[str] = field(default_factory=list[str])


@dataclass
class ParsedSet:
    """One parsed named set: its canonicalized, ordered elements."""

    name: str
    elements: list[str] = field(default_factory=list[str])


@dataclass
class ParsedTable:
    """One parsed table: its chains and named sets, insertion-ordered."""

    chains: dict[str, ParsedChain] = field(
        default_factory=dict[str, ParsedChain]
    )
    sets: dict[str, ParsedSet] = field(default_factory=dict[str, ParsedSet])


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

    for lineno, raw in enumerate(text.splitlines(), start=1):
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
        raise _parse_error(len(text.splitlines()), "<EOF: missing COMMIT>")

    return tables


#: Whole-token option aliases (source of truth: Makefile RESULT_SED, plus the
#: multiport long->short pair).  Matched as whole tokens, never as prefixes.
_OPTION_ALIASES = {
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
_IMPLIED_MATCHES = frozenset({"tcp", "udp", "icmp", "icmpv6"})


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


#: nft's fixed ct-state bitmask order (NOT alphabetical, NOT sorted()).
#: A rule's members are re-ordered to this sequence on both sides.
_NFT_CT_STATE_ORDER: tuple[str, ...] = (
    "invalid",
    "established",
    "related",
    "new",
    "untracked",
)

#: Standard nft priority landmark names -> numeric, keyed by nft family.
#: ip/ip6/arp share nft's inet-style landmarks; bridge has its own numbers.
#: The full table is kept per family so a hand-written foreign chain that hits
#: any landmark name canonicalizes too; for ferm-managed chains only a subset
#: is exercised (bridge: only dstnat).
_NFT_PRIORITY_NAMES_INET: dict[str, int] = {
    "raw": -300,
    "mangle": -150,
    "dstnat": -100,
    "filter": 0,
    "security": 50,
    "srcnat": 100,
}
_NFT_PRIORITY_NAMES_BRIDGE: dict[str, int] = {
    "dstnat": -300,
    "filter": -200,
    "out": 100,
    "srcnat": 300,
}
_NFT_PRIORITY_NAMES: dict[str, dict[str, int]] = {
    "ip": _NFT_PRIORITY_NAMES_INET,
    "ip6": _NFT_PRIORITY_NAMES_INET,
    "arp": _NFT_PRIORITY_NAMES_INET,
    "bridge": _NFT_PRIORITY_NAMES_BRIDGE,
}

#: ip-family reject default: nft collapses to bare 'reject'.
_NFT_REJECT_DEFAULTS: dict[str, str] = {
    "ip": "icmp",
    "ip6": "icmpv6",
}
#: nft's default reject message type for both icmp families.
_NFT_REJECT_DEFAULT_TYPE = "port-unreachable"


#: One ``{ ... }`` operand run, with an optional ``vmap`` marker so a verdict
#: map is told apart from a plain anonymous set (no nesting in v1).  The marker
#: is required because an IPv6 set element carries ``:`` too, so the colon
#: alone cannot discriminate a vmap.
_NFT_SET_RE = re.compile(r"(vmap\s*)?\{([^{}]*)\}")


def _normalize_set_run(match: re.Match[str]) -> str:
    """Rewrite one ``{ ... }`` operand run (set or vmap) to canonical form."""
    if match.group(1) is not None:
        return _normalize_vmap_run(match.group(2))
    raw = match.group(2).replace(",", " ").split()
    if not raw:
        return "{ }"
    return "{ " + ", ".join(canonicalize_set_elements(raw)) + " }"


def _normalize_vmap_run(inner: str) -> str:
    """
    Rewrite a ``vmap { k : v, ... }`` run to canonical key order.

    Each member splits on its first ``:`` into a key and a (possibly
    multi-token, e.g. ``jump foo``) verdict; the pairs are reordered by the
    key's canonical rank so a folded vmap converges on both diff sides.  A
    member that is not a well-formed pair leaves the whole run verbatim
    (safe-bias: a noisy diff beats a false 'no changes').
    """
    pairs: list[tuple[str, str]] = []
    for member in inner.split(","):
        key, sep, verdict = member.partition(":")
        if not sep:
            return "vmap {" + inner + "}"
        pairs.append((key.strip(), verdict.strip()))
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
    """
    out: list[str] = []
    start = 0
    quote: str | None = None
    for index, char in enumerate(body):
        if quote is None and char in "\"'":
            out.append(_NFT_SET_RE.sub(_normalize_set_run, body[start:index]))
            start = index
            quote = char
        elif quote is not None and char == quote:
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
                if all(m in _NFT_CT_STATE_ORDER for m in members):
                    ordered = sorted(members, key=_NFT_CT_STATE_ORDER.index)
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
                if (
                    fam_token == default_fam
                    and reject_type == _NFT_REJECT_DEFAULT_TYPE
                ):
                    out.append("reject")
                else:
                    out.append("reject")
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
            # Offset form: 'priority <name> +|- <n>' — leave all three verbatim
            # so we never partially map a compound priority expression.
            is_offset = index + 2 < len(tokens) and tokens[index + 2] in (
                "+",
                "-",
            )
            if next_tok in priority_map and not is_offset:
                out.append(str(priority_map[next_tok]))
            else:
                # numeric, unrecognized name, or offset form: leave verbatim
                out.append(next_tok)
            index += 2
            continue
        out.append(token)
        index += 1

    if not has_policy:
        out.append("policy")
        out.append("accept")

    return " ".join(out)


# Exact token counts for the recognized table/flush productions.
# add table <fam> ferm  /  flush table <fam> ferm  -- exactly 4 tokens.
_NFT_TABLE_PARTS = 4
# add chain: add chain <fam> ferm <chain>
_NFT_CHAIN_MIN_PARTS = 5
# add rule: add rule <fam> ferm <chain> <body-token>
_NFT_RULE_MIN_PARTS = 6


def _ensure_ferm_table(tables: dict[str, ParsedTable]) -> None:
    """Insert an empty ``ferm`` table entry if not already present."""
    if "ferm" not in tables:
        tables["ferm"] = ParsedTable()


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


def parse_nft_script(text: str) -> dict[str, ParsedTable]:
    """
    Parse a render().save nft script into {table: ParsedTable} (fail-loud).

    The input is a line-oriented nft -f script produced by the nft backend.
    Every non-blank, non-comment line must match exactly one of seven
    recognized productions; anything else raises :class:`FermError`.

    Productions recognized:

    - ``add table <fam> ferm``                           -- ignored
    - ``flush table <fam> ferm``                         -- ignored
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

        # -- table envelope / flush directive: both are silently ignored ----
        # Exact 4-token match: any extra token is a parse error.
        if parts[1:2] == ["table"] and verb in ("add", "flush"):
            if len(parts) != _NFT_TABLE_PARTS or parts[3] != "ferm":
                raise _parse_error(lineno, raw)
            family = _check_family(family, parts[2], lineno, raw)
            continue

        if verb != "add":
            raise _parse_error(lineno, raw)

        sub = parts[1] if len(parts) > 1 else ""

        # -- add chain -------------------------------------------------------
        if sub == "chain" and len(parts) >= _NFT_CHAIN_MIN_PARTS:
            fam_tok, table_name, chain_name = parts[2], parts[3], parts[4]
            if table_name != "ferm":
                raise _parse_error(lineno, raw)
            family = _check_family(family, fam_tok, lineno, raw)
            assert family is not None  # assigned by _check_family above

            # parts[5:] is the payload after <chain>.  Valid shapes:
            #   [] (user chain) or ['{', ..., '}'] (base chain).
            # Any non-'{' first token is extra garbage -> parse error.
            tail = parts[5:]
            if not tail:
                # user chain: nothing after the chain name
                _ensure_ferm_table(tables)
                tables["ferm"].chains[chain_name] = ParsedChain(policy="-")
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
                tables["ferm"].chains[chain_name] = ParsedChain(policy=canon)
            else:
                # extra token before the brace (or instead of it) is invalid
                raise _parse_error(lineno, raw)
            continue

        # -- add set ---------------------------------------------------------
        if sub == "set" and len(parts) >= _NFT_CHAIN_MIN_PARTS:
            fam_tok, table_name, set_name = parts[2], parts[3], parts[4]
            if table_name != "ferm":
                raise _parse_error(lineno, raw)
            family = _check_family(family, fam_tok, lineno, raw)
            _ensure_ferm_table(tables)
            tables["ferm"].sets.setdefault(set_name, ParsedSet(set_name))
            continue

        # -- add element -----------------------------------------------------
        if sub == "element" and len(parts) >= _NFT_CHAIN_MIN_PARTS:
            fam_tok, table_name, set_name = parts[2], parts[3], parts[4]
            if table_name != "ferm":
                raise _parse_error(lineno, raw)
            family = _check_family(family, fam_tok, lineno, raw)
            brace_open = line.find("{")
            brace_close = line.rfind("}")
            if brace_open == -1 or brace_close <= brace_open:
                raise _parse_error(lineno, raw)
            rest = line[brace_open + 1 : brace_close]
            elements = [e.strip() for e in rest.split(",") if e.strip()]
            _ensure_ferm_table(tables)
            ps = tables["ferm"].sets.setdefault(set_name, ParsedSet(set_name))
            ps.elements = canonicalize_set_elements(ps.elements + elements)
            continue

        # -- add rule --------------------------------------------------------
        if sub == "rule" and len(parts) >= _NFT_RULE_MIN_PARTS:
            fam_tok, table_name, chain_name = parts[2], parts[3], parts[4]
            if table_name != "ferm":
                raise _parse_error(lineno, raw)
            family = _check_family(family, fam_tok, lineno, raw)
            assert family is not None

            # Body is everything after 'add rule <fam> ferm <chain>'.
            prefix = f"add rule {fam_tok} ferm {chain_name}"
            body = line[len(prefix) :].strip()
            ferm_table = tables.get("ferm")
            if ferm_table is None or chain_name not in ferm_table.chains:
                raise _parse_error(lineno, raw)
            ferm_table.chains[chain_name].rules.append(
                canonicalize_nft_rule(body, family=family)
            )
            continue

        raise _parse_error(lineno, raw)

    return tables


# Depth levels for parse_nft_list's brace-state machine.
_NL_DEPTH_OUTSIDE = 0  # outside everything
_NL_DEPTH_TABLE = 1  # inside the table block
_NL_DEPTH_CHAIN = 2  # inside a chain block
_NL_DEPTH_SET = 3  # inside a set block

# Regex anchors for the brace-delimited nft-list grammar.
# These match only the structural openers; rule bodies at chain depth are
# never tested against them (so a '{' inside a rule body is invisible).
_NFT_LIST_TABLE_RE = re.compile(r"^table\s+(\S+)\s+ferm\s*\{$")
_NFT_LIST_CHAIN_RE = re.compile(r"^chain\s+(\S+)\s*\{$")
_NFT_LIST_SET_RE = re.compile(r"^set\s+(\S+)\s*\{$")
# A base-chain header starts with 'type' followed by the hook/priority tokens.
_NFT_LIST_HEADER_RE = re.compile(r"^type\s+\S+\s+hook\s+\S+\s+priority\b")


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
            m_set = _NFT_LIST_SET_RE.match(line)
            if m_set:
                current_set = ParsedSet(m_set.group(1))
                tables["ferm"].sets[current_set.name] = current_set
                depth = _NL_DEPTH_SET
                continue
            m = _NFT_LIST_CHAIN_RE.match(line)
            if not m:
                raise _parse_error(lineno, raw)
            chain_name = m.group(1)
            # policy will be set when the first body line arrives
            current_chain = ParsedChain(policy="-")
            tables["ferm"].chains[chain_name] = current_chain
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

        if depth == _NL_DEPTH_SET:
            # Inside a set body.
            assert current_set is not None
            if line == "}":
                current_set = None
                depth = _NL_DEPTH_TABLE
                continue
            if line.startswith("elements"):
                brace_open = line.find("{")
                brace_close = line.rfind("}")
                if brace_open != -1 and brace_close > brace_open:
                    inner = line[brace_open + 1 : brace_close]
                    members = [
                        e.strip() for e in inner.split(",") if e.strip()
                    ]
                    current_set.elements = canonicalize_set_elements(
                        current_set.elements + members
                    )
            # 'type ...'/'flags ...' lines carry no diff-relevant data; skip.
            continue

    if depth != _NL_DEPTH_OUTSIDE:
        raise _parse_error(total or 1, "<EOF: unterminated block>")

    return tables


@dataclass
class PolicyChange:
    """A built-in chain's default policy changed (``old`` -> ``new``)."""

    table: str
    chain: str
    old: str
    new: str


@dataclass
class RuleChange:
    """One rule added to (or removed from) a chain."""

    table: str
    chain: str
    rule: str


@dataclass
class ForeignChain:
    """A user chain present in the kernel but absent from the config."""

    table: str
    chain: str


@dataclass
class DesuetChain:
    """A base chain present in the kernel but absent from the config."""

    table: str
    chain: str


@dataclass
class SetChange:
    """A named set added, removed, or with changed elements."""

    table: str
    name: str
    kind: str  # "add" | "remove" | "modify"
    elements: list[str]


@dataclass
class PlanDiff:
    """The diff for one family: what applying the config would change."""

    policy_changes: list[PolicyChange] = field(
        default_factory=list[PolicyChange]
    )
    rules_added: list[RuleChange] = field(default_factory=list[RuleChange])
    rules_removed: list[RuleChange] = field(default_factory=list[RuleChange])
    foreign_chains: list[ForeignChain] = field(
        default_factory=list[ForeignChain]
    )
    desuet_chains: list[DesuetChain] = field(default_factory=list[DesuetChain])
    set_changes: list[SetChange] = field(default_factory=list[SetChange])
    noflush: bool = False
    current_empty: bool = False

    def has_changes(self) -> bool:
        """Return True if applying the config would change the kernel."""
        return bool(
            self.policy_changes
            or self.rules_added
            or self.rules_removed
            or self.foreign_chains
            or self.desuet_chains
            or self.set_changes
        )


@dataclass
class Plan:
    """The whole plan: a per-family diff plus any unsupported families."""

    families: dict[str, PlanDiff] = field(default_factory=dict[str, PlanDiff])
    unsupported: list[str] = field(default_factory=list[str])

    def has_changes(self) -> bool:
        """Return True if any family's diff carries a change."""
        return any(diff.has_changes() for diff in self.families.values())


def _is_builtin(chain: ParsedChain) -> bool:
    """
    Return True when the chain is built-in (carries a real policy).

    User chains carry ``-`` as their policy placeholder.
    """
    return chain.policy != "-"


def _diff_rules(
    current: list[str], desired: list[str]
) -> tuple[list[str], list[str]]:
    """
    Compute a positional multiset diff of two ordered rule lists.

    Uses :class:`difflib.SequenceMatcher` so order is significant and a
    duplicated rule body is not collapsed (a set-diff would silently
    under-count a removed copy).  Returns ``(added, removed)``.
    """
    added: list[str] = []
    removed: list[str] = []
    matcher = difflib.SequenceMatcher(a=current, b=desired, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in ("replace", "delete"):
            removed.extend(current[i1:i2])
        if tag in ("replace", "insert"):
            added.extend(desired[j1:j2])
    return added, removed


def diff_tables(
    current: dict[str, ParsedTable],
    desired: dict[str, ParsedTable],
    *,
    noflush: bool,
) -> PlanDiff:
    """
    Diff one family's current (kernel) model against the desired (config).

    Tables present in ``desired`` are diffed.  ferm's save text carries every
    table it read from the kernel (``rules_to_save`` iterates the dump-seeded
    ``domain_info.tables``), so an unmanaged kernel table (nat/mangle) appears
    in ``desired`` as an empty skeleton and its live rules diff as removals --
    there is no "untouched foreign table" case.  A table only in ``current``
    would genuinely not be in ferm's restore input, so it is not touched and
    produces no diff.  Within a table: built-in policies diff by chain name;
    rules diff positionally; a user chain only in ``current`` is a foreign
    chain (warning, flushed unless ``--noflush``).

    Under ``--noflush``: rule removals are suppressed for built-in and
    undeclared chains (their rules survive) but kept for declared user chains
    (those are flushed); policy changes and foreign-chain warnings follow the
    same survives/flushed split.
    """
    diff = PlanDiff(noflush=noflush, current_empty=not current)

    for table_name, desired_table in desired.items():
        current_table = current.get(table_name)
        current_chains = current_table.chains if current_table else {}

        for chain_name, desired_chain in desired_table.chains.items():
            current_chain = current_chains.get(chain_name)
            current_rules = current_chain.rules if current_chain else []

            if (
                current_chain is not None
                and _is_builtin(current_chain)
                and desired_chain.policy != current_chain.policy
            ):
                diff.policy_changes.append(
                    PolicyChange(
                        table_name,
                        chain_name,
                        current_chain.policy,
                        desired_chain.policy,
                    )
                )

            added, removed = _diff_rules(current_rules, desired_chain.rules)
            diff.rules_added.extend(
                RuleChange(table_name, chain_name, r) for r in added
            )
            # --noflush: only a declared user chain is flushed; built-in and
            # undeclared chains keep their rules, so suppress their removals.
            builtin = current_chain is not None and _is_builtin(current_chain)
            declared_user = current_chain is not None and not builtin
            # Always emit the removal, unless --noflush keeps the rules of a
            # chain that is not a declared user chain (built-in/undeclared
            # chains survive).
            emit_removal = not noflush or declared_user
            if emit_removal:
                diff.rules_removed.extend(
                    RuleChange(table_name, chain_name, r) for r in removed
                )

        # named set diff: sets added, modified, or removed
        current_sets = current_table.sets if current_table else {}
        for set_name, desired_set in desired_table.sets.items():
            current_set = current_sets.get(set_name)
            if current_set is None:
                diff.set_changes.append(
                    SetChange(
                        table_name, set_name, "add", desired_set.elements
                    )
                )
            elif current_set.elements != desired_set.elements:
                diff.set_changes.append(
                    SetChange(
                        table_name, set_name, "modify", desired_set.elements
                    )
                )
        for set_name in current_sets:
            if set_name not in desired_table.sets:
                diff.set_changes.append(
                    SetChange(table_name, set_name, "remove", [])
                )

        # foreign chains: user chains in the managed table absent from config
        for chain_name, current_chain in current_chains.items():
            if chain_name in desired_table.chains:
                continue
            if _is_builtin(current_chain):
                diff.desuet_chains.append(DesuetChain(table_name, chain_name))
                continue
            if noflush:
                continue  # undeclared user chains survive under --noflush
            diff.foreign_chains.append(ForeignChain(table_name, chain_name))

    return diff


def _summary_line(diff: PlanDiff) -> str:
    """
    Build the ``Plan: N to add, M to remove, K policy changes`` tail.

    When desuet or foreign chains are present an extra
    ``, C chain(s) removed`` clause is appended so the summary reflects
    every change that will be applied -- not just rule-level deltas.
    """
    adds = len(diff.rules_added)
    removes = len(diff.rules_removed)
    policies = len(diff.policy_changes)
    chains_removed = len(diff.desuet_chains) + len(diff.foreign_chains)
    pol_word = "change" if policies == 1 else "changes"
    summary = (
        f"Plan: {adds} to add, {removes} to remove,"
        f" {policies} policy {pol_word}"
    )
    if chains_removed:
        chain_word = "chain" if chains_removed == 1 else "chains"
        summary += f", {chains_removed} {chain_word} removed"
    sets_changed = len(diff.set_changes)
    if sets_changed:
        set_word = "set" if sets_changed == 1 else "sets"
        summary += f", {sets_changed} {set_word} changed"
    return summary


def render_structured(plan: Plan) -> str:
    """Render the default human-readable plan, deterministic by sort order."""
    lines: list[str] = [
        f"family {f}: plan not supported for this family"
        for f in plan.unsupported
    ]

    if not plan.has_changes() and not plan.unsupported:
        return "No changes. Live ruleset matches the configuration.\n"

    for family in sorted(plan.families):
        diff = plan.families[family]
        if not diff.has_changes():
            continue
        lines.append(f"family {family}")
        if diff.current_empty:
            lines.append("  note: current ruleset is empty")
        if diff.noflush:
            lines.append(
                "  note: noflush -- existing built-in/undeclared rules"
                " kept; declared user chains overwritten; policies applied"
            )
        lines.extend(
            f"  ~ policy {c.table}/{c.chain}: {c.old} -> {c.new}"
            for c in sorted(
                diff.policy_changes, key=lambda c: (c.table, c.chain)
            )
        )
        lines.extend(
            f"  - {r.rule}"
            for r in sorted(
                diff.rules_removed, key=lambda r: (r.table, r.chain)
            )
        )
        lines.extend(
            f"  + {r.rule}"
            for r in sorted(diff.rules_added, key=lambda r: (r.table, r.chain))
        )
        lines.extend(
            f"  warning: chain {fchain.table}/{fchain.chain} is not in"
            " the config and will be flushed"
            for fchain in sorted(
                diff.foreign_chains,
                key=lambda fchain: (fchain.table, fchain.chain),
            )
        )
        lines.extend(
            f"  ~ chain {dchain.table}/{dchain.chain} removed"
            " (base chain no longer declared)"
            for dchain in sorted(
                diff.desuet_chains,
                key=lambda dchain: (dchain.table, dchain.chain),
            )
        )
        for sc in sorted(diff.set_changes, key=lambda s: (s.table, s.name)):
            if sc.kind == "add":
                elems = ", ".join(sc.elements)
                lines.append(f"  + set {sc.table}/{sc.name} {{ {elems} }}")
            elif sc.kind == "remove":
                lines.append(f"  - set {sc.table}/{sc.name}")
            else:
                elems = ", ".join(sc.elements)
                lines.append(f"  ~ set {sc.table}/{sc.name} {{ {elems} }}")
        lines.append(f"  {_summary_line(diff)}")

    return "\n".join(lines) + "\n"


def _diff_blob(diff: PlanDiff) -> tuple[list[str], list[str]]:
    """
    Build current/desired line lists for one family, for the unified diff.

    Multiset-preserving (ordered lists, never ``set`` -- two identical removed
    rules must stay two lines) and complete: policy changes (``:CHAIN POLICY``
    on both sides) and foreign chains are emitted too, so a lock-out via a
    policy flip or a flushed foreign chain is never hidden from
    ``--plan-format=diff``.  Sorts are by table first, then chain within each
    table, so duplicate rule bodies within the same table keep their relative
    order and stay distinct lines.
    """
    tables = sorted(
        {c.table for c in diff.policy_changes}
        | {r.table for r in diff.rules_removed}
        | {r.table for r in diff.rules_added}
        | {f.table for f in diff.foreign_chains}
        | {d.table for d in diff.desuet_chains}
        | {s.table for s in diff.set_changes}
    )
    current: list[str] = []
    desired: list[str] = []
    for table in tables:
        current.append(f"*{table}")
        desired.append(f"*{table}")
        for change in sorted(
            (c for c in diff.policy_changes if c.table == table),
            key=lambda c: c.chain,
        ):
            current.append(f":{change.chain} {change.old}")
            desired.append(f":{change.chain} {change.new}")
        current.extend(
            f"# foreign chain {fchain.chain} will be flushed"
            for fchain in sorted(
                (fc for fc in diff.foreign_chains if fc.table == table),
                key=lambda fchain: fchain.chain,
            )
        )
        current.extend(
            f"# base chain {dchain.chain} removed (no longer declared)"
            for dchain in sorted(
                (dc for dc in diff.desuet_chains if dc.table == table),
                key=lambda dchain: dchain.chain,
            )
        )
        current.extend(
            f"-A {r.chain} {r.rule}"
            for r in sorted(
                (r for r in diff.rules_removed if r.table == table),
                key=lambda r: r.chain,
            )
        )
        desired.extend(
            f"-A {r.chain} {r.rule}"
            for r in sorted(
                (r for r in diff.rules_added if r.table == table),
                key=lambda r: r.chain,
            )
        )
        for sc in sorted(
            (s for s in diff.set_changes if s.table == table),
            key=lambda s: s.name,
        ):
            if sc.kind in ("add", "modify"):
                elems = ", ".join(sc.elements)
                desired.append(f"add set {table} {sc.name} {{ {elems} }}")
            if sc.kind in ("remove", "modify"):
                current.append(f"add set {table} {sc.name}")
    return current, desired


def render_unified(plan: Plan) -> str:
    """Render a unified diff of the canonicalized save sections per family."""
    out: list[str] = [
        f"family {f}: plan not supported for this family"
        for f in plan.unsupported
    ]
    for family in sorted(plan.families):
        current, desired = _diff_blob(plan.families[family])
        out.extend(
            difflib.unified_diff(
                current,
                desired,
                fromfile=f"{family} (current)",
                tofile=f"{family} (desired)",
                lineterm="",
            )
        )
    if not out:
        return "No changes. Live ruleset matches the configuration.\n"
    return "\n".join(out) + "\n"


def render_plan(plan: Plan, *, fmt: str) -> str:
    """Dispatch to the structured (default) or unified renderer."""
    if fmt == "diff":
        return render_unified(plan)
    return render_structured(plan)
