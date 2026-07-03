"""
Human-readable introspection over the module registries (Phase 7).

Renders ``--list-modules`` / ``--describe NAME`` text from
:data:`pyferm.modules.PROTO_DEFS` / ``MATCH_DEFS`` / ``TARGET_DEFS``,
``SHORTCUTS``, ``DEPRECATED_KEYWORDS`` and the curated :data:`BUILTINS`
table.  Text-only and prose-free for modules by design (no JSON, no POD
extraction); built-in keywords carry curated one-line summaries.  A name
that is both a module/builtin/shortcut and an option of another module
shows only the former facet (the option fallback runs last; cross-module
collisions like ``set`` being also an option of ``connlabel``/``recent``
are an accepted limitation).

Read-only: never touches the kernel, the eval path or any config file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from pyferm.modules import Keyword, KeywordParams, ModuleDef, ParamFunction

#: Hard cap for every ``--list-modules`` output line.  A literal so the
#: golden tests are environment-independent (never COLUMNS/tty-derived).
MAX_WIDTH: Final = 79

_PARAM_FUNCTION_LABELS: Final[dict[str, str]] = {
    "address_magic": "<address[/mask]>",
}

_LETTER_LABELS: Final[dict[str, str]] = {
    "s": "<value>",
    "c": "<comma-separated list>",
}


def render_params(params: KeywordParams) -> str:
    """Describe one keyword's argument shape (see the spec's table)."""
    if params is None:
        return "(no argument)"
    if isinstance(params, ParamFunction):
        return _PARAM_FUNCTION_LABELS.get(
            params.name, f"<special: {params.name}>"
        )
    if params == "m":
        return "<value>... (repeatable)"
    if isinstance(params, str) and params.isdigit():
        params = int(params)
    if isinstance(params, int):
        return "<value>" if params == 1 else f"<{params} values>"
    return " ".join(_LETTER_LABELS.get(code, "<value>") for code in params)


_FAMILY_ORDER: Final[tuple[str, ...]] = ("ip", "arp", "eb")
_FAMILY_LABELS: Final[dict[str, str]] = {
    "ip": "ip/ip6",  # the parser folds ip6 into the ip registry family
    "arp": "arp",
    "eb": "eb",
}
_KIND_LABELS: Final[dict[str, str]] = {
    "proto": "protocol",
    "match": "match",
    "target": "target",
}


def _option_row(
    key: str, keyword: Keyword, module: ModuleDef
) -> tuple[str, str, str]:
    """One table row (name, argument shape, notes) for a canonical key."""
    notes: list[str] = []
    if keyword.pre_negation:
        notes.append("negatable (! before keyword)")
    elif keyword.negation:
        notes.append("negatable")
    aliases = [
        alias
        for alias, target in module.keywords.items()
        if target is keyword and alias != keyword.name
    ]
    if aliases:
        notes.append("(aliases: " + ", ".join(aliases) + ")")
    return key, render_params(keyword.params), " ".join(notes)


def _render_rows(rows: list[tuple[str, str, str]]) -> list[str]:
    if not rows:  # e.g. 'eui64': a flag-only match with no keywords at all
        return []
    name_width = max(len(row[0]) for row in rows) + 2
    arg_width = max(len(row[1]) for row in rows) + 2
    return [
        f"  {name.ljust(name_width)}{arg.ljust(arg_width)}{tail}".rstrip()
        for name, arg, tail in rows
    ]


def _render_module(  # pyright: ignore[reportUnusedFunction]
    # Only test_introspect.py calls this until Task 4's describe() wires
    # it into production code (slice-3 plan, worker split T1-T3/T4-T5);
    # remove this ignore once that caller lands.
    kind: str,
    name: str,
    family: str,
    module: ModuleDef,
) -> str:
    """Render one registry hit as a titled option table."""
    rows = [
        _option_row(key, keyword, module)
        for key, keyword in module.keywords.items()
        if key == keyword.name  # alias keys render on their canonical row
    ]
    lines = [
        f"{_KIND_LABELS[kind]} module '{name}' ({_FAMILY_LABELS[family]}):"
    ]
    lines.extend(_render_rows(rows))
    lines.append("  see iptables-extensions(8) and ferm(1)")
    return "\n".join(lines)


@dataclass(frozen=True)
class Builtin:
    """One built-in language keyword with a curated one-liner."""

    name: str
    category: str  # "location" | "structure" | "rule" | "function" | "target"
    signature: str
    summary: str


def _builtin(
    name: str, category: str, signature: str, summary: str
) -> tuple[str, Builtin]:
    return name, Builtin(name, category, signature, summary)


BUILTINS: Final[dict[str, Builtin]] = dict(
    (
        # -- location headers (_HEADER_KEYWORDS, parser.py:316)
        _builtin(
            "domain",
            "location",
            "domain (ip ip6 ...) { ... }",
            "select the netfilter domain(s) a block applies to",
        ),
        _builtin(
            "table",
            "location",
            "table NAME { ... }",
            "select the table (filter, nat, mangle, ...)",
        ),
        _builtin(
            "chain",
            "location",
            "chain NAME [NAME ...] { ... }",
            "select the chain(s) the rules go into",
        ),
        _builtin(
            "policy",
            "location",
            "policy (ACCEPT|DROP|...);",
            "set the built-in chain policy",
        ),
        _builtin(
            "priority",
            "location",
            "priority NUMBER;",
            "set the nft base-chain hook priority (port-only)",
        ),
        # -- structure
        _builtin(
            "@def",
            "structure",
            "@def $name = value; / @def &fn(...) = ...;",
            "define a variable or a function",
        ),
        _builtin(
            "def", "structure", "def ...", "deprecated spelling of '@def'"
        ),
        _builtin(
            "@include",
            "structure",
            "@include 'file'|'dir/'|'command|';",
            "include a file, a directory or a command's output",
        ),
        _builtin(
            "include",
            "structure",
            "include ...",
            "deprecated spelling of '@include'",
        ),
        _builtin(
            "@if",
            "structure",
            "@if condition { ... } [@else { ... }]",
            "conditional inclusion at evaluation time",
        ),
        _builtin(
            "@else",
            "structure",
            "@if ... @else { ... }",
            "alternative branch of '@if'",
        ),
        _builtin(
            "@hook",
            "structure",
            "@hook (pre|post|flush) 'command';",
            "run a shell command around rule application",
        ),
        _builtin(
            "hook", "structure", "hook ...", "deprecated spelling of '@hook'"
        ),
        _builtin(
            "@preserve",
            "structure",
            "@preserve;",
            "keep the kernel's current rules for this chain",
        ),
        _builtin(
            "@set",
            "structure",
            "@set NAME ...;",
            "define a named set (nft backend)",
        ),
        _builtin(
            "@subchain",
            "structure",
            "@subchain ['NAME'] { ... }",
            "move the enclosed rules into their own chain",
        ),
        _builtin(
            "subchain",
            "structure",
            "subchain ...",
            "deprecated spelling of '@subchain'",
        ),
        _builtin(
            "@gotosubchain",
            "structure",
            "@gotosubchain ['NAME'] { ... }",
            "like '@subchain' but enters the chain with goto",
        ),
        # -- rule keywords
        _builtin("jump", "rule", "jump CHAIN", "jump to a chain"),
        _builtin(
            "goto", "rule", "goto CHAIN", "go to a chain without returning"
        ),
        _builtin(
            "NOP", "rule", "NOP;", "emit the rule without any jump target"
        ),
        _builtin(
            "proto",
            "rule",
            "proto PROTOCOL",
            "match the protocol (alias: protocol)",
        ),
        _builtin("protocol", "rule", "protocol PROTOCOL", "alias of 'proto'"),
        _builtin(
            "mod",
            "rule",
            "mod MODULE [MODULE ...]",
            "load a match module (alias: module)",
        ),
        _builtin(
            "module", "rule", "module MODULE [MODULE ...]", "alias of 'mod'"
        ),
        # -- core targets (rules.py:52; manual entries, not scanned)
        _builtin(
            "ACCEPT",
            "target",
            "ACCEPT",
            "core netfilter target (no module required)",
        ),
        _builtin(
            "DROP",
            "target",
            "DROP",
            "core netfilter target (no module required)",
        ),
        _builtin(
            "RETURN",
            "target",
            "RETURN",
            "core netfilter target (no module required)",
        ),
        _builtin(
            "QUEUE",
            "target",
            "QUEUE",
            "core netfilter target (no module required)",
        ),
        # -- @-functions (signatures mirror functions.py literals)
        _builtin(
            "@defined",
            "function",
            "@defined($name) / @defined(&name)",
            "true if the variable or function is defined",
        ),
        _builtin("@eq", "function", "@eq(a, b)", "true if a equals b"),
        _builtin("@ne", "function", "@ne(a, b)", "true if a differs from b"),
        _builtin("@not", "function", "@not(a)", "boolean negation"),
        _builtin(
            "@cat",
            "function",
            "@cat(a, b, ...)",
            "concatenate values into one string",
        ),
        _builtin(
            "@join",
            "function",
            "@join(separator, ...)",
            "join values with a separator",
        ),
        _builtin(
            "@substr",
            "function",
            "@substr(string, num, num)",
            "extract a substring",
        ),
        _builtin(
            "@length", "function", "@length(string)", "length of a string"
        ),
        _builtin(
            "@basename",
            "function",
            "@basename(path)",
            "file name part of a path",
        ),
        _builtin(
            "@dirname",
            "function",
            "@dirname(path)",
            "directory part of a path",
        ),
        _builtin(
            "@glob", "function", "@glob(string)", "expand a filename glob"
        ),
        _builtin(
            "@resolve",
            "function",
            "@resolve((hostname ...), [type])",
            "resolve hostnames via DNS at evaluation time",
        ),
        _builtin(
            "@ipfilter",
            "function",
            "@ipfilter((ip1 ip2 ...))",
            "keep only addresses matching the current domain family",
        ),
    )
)

_CATEGORY_LABELS: Final[dict[str, str]] = {
    "location": "location keyword",
    "structure": "structure keyword",
    "rule": "rule keyword",
    "function": "function",
    "target": "core target",
}


def _render_builtin(  # pyright: ignore[reportUnusedFunction]
    # Only tests call this until Task 4's describe() wires it into
    # production code (slice-3 plan, worker split T1-T3/T4-T5); remove
    # this ignore once that caller lands.
    builtin: Builtin,
) -> str:
    """Render one BUILTINS hit: signature plus curated one-liner."""
    return (
        f"built-in {_CATEGORY_LABELS[builtin.category]} '{builtin.name}':\n"
        f"  {builtin.signature} -- {builtin.summary}"
    )
