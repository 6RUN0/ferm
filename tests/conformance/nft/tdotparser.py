"""
Parser for the upstream nftables ``tests/py/<family>/*.t`` format.

A ``.t`` file is one block: ``:`` chain-header lines, then ``*`` table
lines declaring the same chain across several families, then a block of
rule lines.  Headers and rules apply to *every* declared family, so the
parser collects families/headers/rules across the whole file and fans
out the cartesian product (real upstream files are single-block).

Recognized line forms (everything else is skipped, never fatal):

* ``# ...`` / blank            -- ignored
* ``-``/``!``/``?``/``%`` sigil -- ignored (broken/set-def/elem-add/object-def)
* ``:<chain>;<header>``        -- chain header (header = text after the ';')
* ``*<family>;<table>;<chain[,..]>`` -- table line (family = first field)
* ``<rule>;ok``                -- RuleCase(normalized=None)
* ``<rule>;ok;<normalized>``   -- RuleCase(normalized=<normalized>)
* ``<rule>;fail``              -- ignored (port does not mirror nft grammar)
"""

from __future__ import annotations

from dataclasses import dataclass

ALLOWED_FAMILIES: frozenset[str] = frozenset({"ip", "ip6", "inet"})


@dataclass(frozen=True)
class RuleCase:
    """One ``<rule>;ok[;<normalized>]`` line, bound to one family."""

    family: str
    rule: str
    normalized: str | None


@dataclass(frozen=True)
class HeaderCase:
    """One ``:<chain>;<header>`` line, bound to one family."""

    family: str
    header: str


Case = RuleCase | HeaderCase

_SKIP_SIGILS = ("-", "!", "?", "%")


def parse_t_file(text: str) -> list[Case]:
    """Parse a ``.t`` file body into a flat list of family-bound cases."""
    families: list[str] = []
    headers: list[str] = []
    rules: list[tuple[str, str | None]] = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(_SKIP_SIGILS):
            continue
        if line.startswith(":"):
            # ':input;type filter hook input priority 0' -> header text only
            parts = line[1:].split(";", 1)
            if len(parts) == 2:
                headers.append(parts[1].strip())
            continue
        if line.startswith("*"):
            family = line[1:].split(";", 1)[0].strip()
            if family in ALLOWED_FAMILIES and family not in families:
                families.append(family)
            continue
        # rule line: '<rule>;<verdict>[;<normalized>]'
        fields = line.split(";")
        if len(fields) < 2:
            continue
        verdict = fields[1].strip()
        if verdict != "ok":
            continue
        normalized = (
            fields[2] if len(fields) >= 3 and fields[2].strip() else None
        )
        rules.append((fields[0].strip(), normalized))

    cases: list[Case] = []
    for family in families:
        cases.extend(HeaderCase(family=family, header=h) for h in headers)
        cases.extend(
            RuleCase(family=family, rule=rule, normalized=normalized)
            for rule, normalized in rules
        )
    return cases
