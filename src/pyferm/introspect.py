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
