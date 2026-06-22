"""
Read-only diff preview for ``ferm --plan`` (iptables backend).

Parses an ``iptables-save`` dump into a structural model, canonicalizes
both the desired (ferm ``rules_to_save``, long-form options) and the current
(kernel ``iptables-save``, short-form) sides through a whitelist of
proven-equivalent transforms, diffs them, and renders the result.  The diff
engine is backend-agnostic; the parser is specific to the ``iptables-save``
grammar.  Read-only by construction: this module never
runs a command -- the cli hands it text.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field

from pyferm.errors import FermError

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
class ParsedTable:
    """One parsed table: its chains keyed by name, insertion-ordered."""

    chains: dict[str, ParsedChain] = field(
        default_factory=dict[str, ParsedChain]
    )


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
