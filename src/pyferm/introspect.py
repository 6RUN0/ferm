"""
Human-readable introspection over the module registries (Phase 7).

Renders ``--list-modules`` / ``--describe NAME`` text from
:data:`pyferm.modules.PROTO_DEFS` / ``MATCH_DEFS`` / ``TARGET_DEFS``,
``SHORTCUTS``, ``DEPRECATED_KEYWORDS`` and the curated :data:`BUILTINS`
table.  Text-only and prose-free for modules by design (no JSON, no POD
extraction); built-in keywords carry curated one-line summaries.  A name
that is both a module/builtin/shortcut and an option of another module
shows only the former facet (the option fallback runs last); there are
23 such collisions across the registries, almost all a module's option
sharing its own module's name (e.g. ``comment``, ``mark``) where the
suppression is harmless -- the module block already shows that option.
Cross-module collisions like ``set`` being also an option of
``connlabel``/``recent`` are an accepted limitation.

Read-only: never touches the kernel, the eval path or any config file.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Final, NamedTuple

from .errors import FermError
from .modules import (
    MATCH_DEFS,
    PROTO_DEFS,
    SHORTCUTS,
    TARGET_DEFS,
    Keyword,
    KeywordParams,
    ModuleDef,
    ParamFunction,
    Registry,
)
from .parser import DEPRECATED_KEYWORDS

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


class RegistryKind(enum.StrEnum):
    """Which module registry a def came from; the label is golden output."""

    PROTO = "proto"
    MATCH = "match"
    TARGET = "target"

    @property
    def label(self) -> str:
        """Display label for this registry kind."""
        return _KIND_LABELS[self]


class OptionRow(NamedTuple):
    """One table row (name, argument shape, notes) for a canonical key."""

    name: str
    arg: str
    notes: str


def _option_row(key: str, keyword: Keyword, module: ModuleDef) -> OptionRow:
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
    return OptionRow(key, render_params(keyword.params), " ".join(notes))


def _render_rows(rows: list[OptionRow]) -> list[str]:
    if not rows:  # e.g. 'eui64': a flag-only match with no keywords at all
        return []
    name_width = max(len(row.name) for row in rows) + 2
    arg_width = max(len(row.arg) for row in rows) + 2
    return [
        f"  {name.ljust(name_width)}{arg.ljust(arg_width)}{tail}".rstrip()
        for name, arg, tail in rows
    ]


def _render_module(
    kind: RegistryKind, name: str, family: str, module: ModuleDef
) -> str:
    """Render one registry hit as a titled option table."""
    kind = RegistryKind(kind)
    rows = [
        _option_row(key, keyword, module)
        for key, keyword in module.keywords.items()
        if key == keyword.name  # alias keys render on their canonical row
    ]
    lines = [f"{kind.label} module '{name}' ({_FAMILY_LABELS[family]}):"]
    lines.extend(_render_rows(rows))
    lines.append("  see iptables-extensions(8) and ferm(1)")
    return "\n".join(lines)


class BuiltinCategory(enum.StrEnum):
    """Category of a built-in language keyword; the label is golden output."""

    LOCATION = "location"
    STRUCTURE = "structure"
    RULE = "rule"
    FUNCTION = "function"
    TARGET = "target"

    @property
    def label(self) -> str:
        """Display label for this builtin category."""
        return _CATEGORY_LABELS[self]


@dataclass(frozen=True)
class Builtin:
    """One built-in language keyword with a curated one-liner."""

    name: str
    category: BuiltinCategory
    signature: str
    summary: str


def _builtin(
    name: str, category: BuiltinCategory, signature: str, summary: str
) -> tuple[str, Builtin]:
    return name, Builtin(name, category, signature, summary)


BUILTINS: Final[dict[str, Builtin]] = dict(
    (
        # -- location headers (the parser.STMT_TABLE HEADER rows)
        _builtin(
            "domain",
            BuiltinCategory.LOCATION,
            "domain (ip ip6 ...) { ... }",
            "select the netfilter domain(s) a block applies to",
        ),
        _builtin(
            "table",
            BuiltinCategory.LOCATION,
            "table NAME { ... }",
            "select the table (filter, nat, mangle, ...)",
        ),
        _builtin(
            "chain",
            BuiltinCategory.LOCATION,
            "chain NAME [NAME ...] { ... }",
            "select the chain(s) the rules go into",
        ),
        _builtin(
            "policy",
            BuiltinCategory.LOCATION,
            "policy (ACCEPT|DROP|...);",
            "set the built-in chain policy",
        ),
        _builtin(
            "priority",
            BuiltinCategory.LOCATION,
            "priority NUMBER;",
            "set the nft base-chain hook priority (port-only)",
        ),
        # -- structure
        _builtin(
            "@def",
            BuiltinCategory.STRUCTURE,
            "@def $name = value; / @def &fn(...) = ...;",
            "define a variable or a function",
        ),
        _builtin(
            "def",
            BuiltinCategory.STRUCTURE,
            "def ...",
            "deprecated spelling of '@def'",
        ),
        _builtin(
            "@include",
            BuiltinCategory.STRUCTURE,
            "@include 'file'|'dir/'|'command|';",
            "include a file, a directory or a command's output",
        ),
        _builtin(
            "include",
            BuiltinCategory.STRUCTURE,
            "include ...",
            "deprecated spelling of '@include'",
        ),
        _builtin(
            "@if",
            BuiltinCategory.STRUCTURE,
            "@if condition { ... } [@else { ... }]",
            "conditional inclusion at evaluation time",
        ),
        _builtin(
            "@else",
            BuiltinCategory.STRUCTURE,
            "@if ... @else { ... }",
            "alternative branch of '@if'",
        ),
        _builtin(
            "@hook",
            BuiltinCategory.STRUCTURE,
            "@hook (pre|post|flush) 'command';",
            "run a shell command around rule application",
        ),
        _builtin(
            "hook",
            BuiltinCategory.STRUCTURE,
            "hook ...",
            "deprecated spelling of '@hook'",
        ),
        _builtin(
            "@preserve",
            BuiltinCategory.STRUCTURE,
            "@preserve;",
            "keep the kernel's current rules for this chain",
        ),
        _builtin(
            "@set",
            BuiltinCategory.STRUCTURE,
            "@set NAME ...;",
            "define a named set (nft backend)",
        ),
        _builtin(
            "@subchain",
            BuiltinCategory.STRUCTURE,
            "@subchain ['NAME'] { ... }",
            "move the enclosed rules into their own chain",
        ),
        _builtin(
            "subchain",
            BuiltinCategory.STRUCTURE,
            "subchain ...",
            "deprecated spelling of '@subchain'",
        ),
        _builtin(
            "@gotosubchain",
            BuiltinCategory.STRUCTURE,
            "@gotosubchain ['NAME'] { ... }",
            "like '@subchain' but enters the chain with goto",
        ),
        # -- rule keywords
        _builtin(
            "jump", BuiltinCategory.RULE, "jump CHAIN", "jump to a chain"
        ),
        _builtin(
            "goto",
            BuiltinCategory.RULE,
            "goto CHAIN",
            "go to a chain without returning",
        ),
        _builtin(
            "NOP",
            BuiltinCategory.RULE,
            "NOP;",
            "emit the rule without any jump target",
        ),
        _builtin(
            "proto",
            BuiltinCategory.RULE,
            "proto PROTOCOL",
            "match the protocol (alias: protocol)",
        ),
        _builtin(
            "protocol",
            BuiltinCategory.RULE,
            "protocol PROTOCOL",
            "alias of 'proto'",
        ),
        # sport/dport are parser-level port switches (no module keyword
        # table carries them): they map to --sport/--dport of the active
        # tcp/udp protocol, so they are describable only here.
        _builtin(
            "sport",
            BuiltinCategory.RULE,
            "sport PORT[:PORT]",
            "match the source port (needs proto tcp/udp)",
        ),
        _builtin(
            "dport",
            BuiltinCategory.RULE,
            "dport PORT[:PORT]",
            "match the destination port (needs proto tcp/udp)",
        ),
        _builtin(
            "mod",
            BuiltinCategory.RULE,
            "mod MODULE [MODULE ...]",
            "load a match module (alias: module)",
        ),
        _builtin(
            "module",
            BuiltinCategory.RULE,
            "module MODULE [MODULE ...]",
            "alias of 'mod'",
        ),
        # -- core targets (rules.CORE_TARGETS)
        _builtin(
            "ACCEPT",
            BuiltinCategory.TARGET,
            "ACCEPT",
            "core netfilter target (no module required)",
        ),
        _builtin(
            "DROP",
            BuiltinCategory.TARGET,
            "DROP",
            "core netfilter target (no module required)",
        ),
        _builtin(
            "RETURN",
            BuiltinCategory.TARGET,
            "RETURN",
            "core netfilter target (no module required)",
        ),
        _builtin(
            "QUEUE",
            BuiltinCategory.TARGET,
            "QUEUE",
            "core netfilter target (no module required)",
        ),
        # -- @-functions (signatures mirror functions.py literals)
        _builtin(
            "@defined",
            BuiltinCategory.FUNCTION,
            "@defined($name) / @defined(&name)",
            "true if the variable or function is defined",
        ),
        _builtin(
            "@eq", BuiltinCategory.FUNCTION, "@eq(a, b)", "true if a equals b"
        ),
        _builtin(
            "@ne",
            BuiltinCategory.FUNCTION,
            "@ne(a, b)",
            "true if a differs from b",
        ),
        _builtin(
            "@not", BuiltinCategory.FUNCTION, "@not(a)", "boolean negation"
        ),
        _builtin(
            "@cat",
            BuiltinCategory.FUNCTION,
            "@cat(a, b, ...)",
            "concatenate values into one string",
        ),
        _builtin(
            "@join",
            BuiltinCategory.FUNCTION,
            "@join(separator, ...)",
            "join values with a separator",
        ),
        _builtin(
            "@substr",
            BuiltinCategory.FUNCTION,
            "@substr(string, num, num)",
            "extract a substring",
        ),
        _builtin(
            "@length",
            BuiltinCategory.FUNCTION,
            "@length(string)",
            "length of a string",
        ),
        _builtin(
            "@basename",
            BuiltinCategory.FUNCTION,
            "@basename(path)",
            "file name part of a path",
        ),
        _builtin(
            "@dirname",
            BuiltinCategory.FUNCTION,
            "@dirname(path)",
            "directory part of a path",
        ),
        _builtin(
            "@glob",
            BuiltinCategory.FUNCTION,
            "@glob(string)",
            "expand a filename glob",
        ),
        _builtin(
            "@resolve",
            BuiltinCategory.FUNCTION,
            "@resolve((hostname ...), [type])",
            "resolve hostnames via DNS at evaluation time",
        ),
        _builtin(
            "@ipfilter",
            BuiltinCategory.FUNCTION,
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


def _render_builtin(builtin: Builtin) -> str:
    """Render one BUILTINS hit: signature plus curated one-liner."""
    return (
        f"built-in {builtin.category.label} '{builtin.name}':\n"
        f"  {builtin.signature} -- {builtin.summary}"
    )


_REGISTRIES: Final[tuple[tuple[RegistryKind, Registry], ...]] = (
    (RegistryKind.PROTO, PROTO_DEFS),
    (RegistryKind.MATCH, MATCH_DEFS),
    (RegistryKind.TARGET, TARGET_DEFS),
)


def _implicit_base_label(family: str) -> str:
    return f"the implicit base match ({_FAMILY_LABELS[family]})"


def _option_fallback_blocks(name: str) -> list[str]:
    """Reverse lookup: which module's option table contains ``name``."""
    blocks: list[str] = []
    for kind, registry in _REGISTRIES:
        for family in _FAMILY_ORDER:
            for module_name, module in registry.get(family, {}).items():
                keyword = module.keywords.get(name)
                if keyword is None:
                    continue
                owner = (
                    _implicit_base_label(family)
                    if module_name == ""
                    else (
                        f"{kind.label} module '{module_name}' "
                        f"({_FAMILY_LABELS[family]})"
                    )
                )
                row = _option_row(keyword.name, keyword, module)
                tail = row.notes
                if name != keyword.name:
                    tail = f"{tail} alias of '{keyword.name}'".strip()
                lines = [f"option '{name}' of {owner}:"]
                lines.extend(
                    _render_rows([OptionRow(row.name, row.arg, tail)])
                )
                blocks.append("\n".join(lines))
    return blocks


def describe(name: str) -> str:
    """
    Render every hit for ``name``, blocks separated by blank lines.

    Raises :class:`FermError` when nothing matches (exit 1 via main's
    standard error contract).
    """
    blocks: list[str] = []
    if name:  # the implicit "" module is reachable via options only
        for kind, registry in _REGISTRIES:
            for family in _FAMILY_ORDER:
                module = registry.get(family, {}).get(name)
                if module is not None:
                    blocks.append(_render_module(kind, name, family, module))
    builtin = BUILTINS.get(name)
    if builtin is not None:
        blocks.append(_render_builtin(builtin))
    for family, shortcuts in SHORTCUTS.items():
        target = shortcuts.get(name)
        if target is not None:
            blocks.append(
                f"shortcut '{name}' ({_FAMILY_LABELS[family]}) = "
                f"match module '{target[0]}', option '{target[1]}'"
            )
    replacement = DEPRECATED_KEYWORDS.get(name)
    if replacement is not None:
        blocks.append(f"deprecated keyword '{name}': use '{replacement}'")
    if not blocks:
        blocks = _option_fallback_blocks(name)
    if not blocks:
        raise FermError(f"ferm --describe: unknown name '{name}'")
    return "\n\n".join(blocks) + "\n"


def _fold_columns(names: list[str], indent: int) -> list[str]:
    """Row-major column fold: column = longest name + 2, cap MAX_WIDTH."""
    if not names:  # e.g. arp/eb match families: only the implicit "" module
        return []
    column = max(len(name) for name in names) + 2
    count = max(1, (MAX_WIDTH - indent) // column)
    pad = " " * indent
    return [
        (
            pad + "".join(name.ljust(column) for name in names[i : i + count])
        ).rstrip()
        for i in range(0, len(names), count)
    ]


def list_modules() -> str:
    """Render the full ``--list-modules`` catalogue (deterministic)."""
    lines: list[str] = []
    for kind, registry in _REGISTRIES:
        for family in _FAMILY_ORDER:
            modules = registry.get(family)
            if not modules:
                continue
            names = sorted(name for name in modules if name)
            lines.append(f"{kind.label} modules ({_FAMILY_LABELS[family]}):")
            lines.extend(_fold_columns(names, 2))
            implicit = modules.get("") if kind == RegistryKind.MATCH else None
            if implicit is not None:
                lines.append("  implicit base options:")
                canonical = sorted(
                    key
                    for key, keyword in implicit.keywords.items()
                    if key == keyword.name
                )
                lines.extend(_fold_columns(canonical, 4))
            lines.append("")
    lines.append("built-in keywords:")
    lines.extend(_fold_columns(sorted(BUILTINS), 2))
    lines.append("")
    lines.append(
        "Use --describe NAME for details on a module, option or keyword."
    )
    return "\n".join(lines) + "\n"
