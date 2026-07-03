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

from pyferm.modules import KeywordParams, ParamFunction

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
