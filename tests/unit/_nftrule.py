"""
Shared rendered-option/rule builders for the nft backend test modules.

``_opt`` / ``_rule`` / ``_target`` were defined byte-identically in the nft
vocabulary suites (match/target/object) and in the nft backend monolith.
They are pure ``RenderedOption``/``RenderedRule`` constructors -- no emission
text -- so sharing them cannot affect the readback-spelling assertions the
callers pin.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pyferm.rules import RenderedOption, RenderedRule
from pyferm.scope import OptionKind

if TYPE_CHECKING:
    from pyferm.values import Value


def _exact(message: str) -> str:
    """
    Anchor an exact expected message for ``pytest.raises(match=...)``.

    ``match=`` is ``re.search``, so an unanchored (or start-only) pattern
    still hits a message a mutant has wrapped or tail-appended; ``$`` is
    not enough either (it matches before a trailing newline), so only the
    full ``\\A...\\Z`` form kills those mutants.
    """
    return rf"\A{re.escape(message)}\Z"


def _opt(
    name: str,
    value: Value,
    kind: OptionKind = OptionKind.OPTION,
    module: str | None = None,
) -> RenderedOption:
    return RenderedOption(name=name, value=value, kind=kind, module=module)


def _rule(*options: RenderedOption) -> RenderedRule:
    return RenderedRule(options=list(options), script=None)


def _target(value: str) -> RenderedOption:
    return _opt("jump", value, kind=OptionKind.TARGET)
