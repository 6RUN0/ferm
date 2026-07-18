"""
Mutation-killing unit tests for the parser body/protocol/include cluster.

Each test pins one real behavioural gap left by a surviving mutant in
``_enter_body``, ``_parse_protocol``, ``_parse_include``, ``_include_file``
or ``collect_filenames``: the leaf-dispatch negation diagnostic, the
protocol module lookup default, the include scope write-back, the ``@glob``
name coercion and the relative-path prefix.  Companion to
``tests/unit/test_parser.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.parser import collect_filenames
from tests.unit._parse import parse_source

if TYPE_CHECKING:
    from pathlib import Path

    from pyferm.parser import Parser


def _parse(source: str) -> Parser:
    """Parse *source* through ``Parser.enter`` and return the parser."""
    return parse_source(source)


def test_enter_body_names_module_keyword_in_negation_error() -> None:
    """
    A leftover ``!`` on an in-``rule.keywords`` option names that keyword.

    ``mss`` is merged by ``proto tcp`` and is non-negatable, so it reaches
    the trailing "Doesn't support negation" check with ``shown_keyword``
    set only by the top of ``handle`` (the shortcut branch is skipped).
    """
    with pytest.raises(FermError, match="Doesn't support negation: mss"):
        _parse(
            "domain ip table filter chain INPUT proto tcp ! mss 1400 ACCEPT;"
        )


def test_enter_body_names_shortcut_keyword_in_negation_error() -> None:
    """
    A leftover ``!`` on a shortcut-resolved keyword names that keyword.

    ``ACCEPT`` is not in ``rule.keywords``, so it flows through the shortcut
    branch that re-stamps ``shown_keyword``; the negation diagnostic must
    still name ``ACCEPT`` rather than ``None``.
    """
    with pytest.raises(FermError, match="Doesn't support negation: ACCEPT"):
        _parse("domain ip table filter chain INPUT ! ACCEPT;")


def test_parse_protocol_lookup_defaults_to_empty_map_off_family() -> None:
    """
    A protocol on a family absent from ``PROTO_DEFS`` yields no module.

    ``arp`` has no proto registry entry, so the two-level ``PROTO_DEFS.get``
    must default the missing family to an empty map; a missing default would
    call ``.get`` on ``None`` and crash while parsing ``proto``.
    """
    parser = _parse("domain arp table filter chain INPUT proto foo NOP;")
    rules = parser.domains[Family.ARP].tables["filter"].chains["INPUT"].rules
    assert len(rules) == 1


def test_include_shares_variable_scope_with_caller(tmp_path: Path) -> None:
    """
    A variable defined inside an include is visible to its caller.

    The nested frame must alias the parent's ``vars`` dict so ``@def`` in the
    included file writes through; a fresh dict would drop ``$shared`` and the
    caller's ``saddr $shared`` would fail as undefined.
    """
    include = tmp_path / "inc.ferm"
    include.write_text('@def $shared = "192.0.2.5";\n', encoding="utf-8")
    parser = _parse(
        f'@include "{include}";\n'
        "domain ip table filter chain INPUT saddr $shared ACCEPT;\n"
    )
    rules = parser.domains[Family.IP].tables["filter"].chains["INPUT"].rules
    assert len(rules) == 1


def test_include_shares_function_scope_with_caller(tmp_path: Path) -> None:
    """
    A function defined inside an include is visible to its caller.

    The nested frame must alias the parent's ``functions`` dict; dropping the
    alias (or nulling it) loses ``&helper`` so the caller's ``&helper()``
    splice fails.
    """
    include = tmp_path / "inc.ferm"
    include.write_text(
        "@def &helper() = proto tcp dport 22;\n", encoding="utf-8"
    )
    parser = _parse(
        f'@include "{include}";\n'
        "domain ip table filter chain INPUT &helper() ACCEPT;\n"
    )
    rules = parser.domains[Family.IP].tables["filter"].chains["INPUT"].rules
    assert len(rules) == 1


def test_parse_include_glob_keeps_matched_filenames(tmp_path: Path) -> None:
    """
    ``@include @glob(...)`` stringifies each matched name, not ``None``.

    The globbed paths must be stringified individually; coercing the loop
    variable to ``None`` collapses every match to ``""`` and the include of
    an empty filename fails.
    """
    (tmp_path / "globbed.ferm").write_text(
        "# empty include\n", encoding="utf-8"
    )
    parser = _parse(
        f'@include @glob("{tmp_path}/*.ferm");\n'
        "domain ip table filter chain INPUT ACCEPT;\n"
    )
    rules = parser.domains[Family.IP].tables["filter"].chains["INPUT"].rules
    assert len(rules) == 1


def test_collect_filenames_prefixes_relative_name_with_dot_slash() -> None:
    """
    A parent filename with no directory resolves relatives against ``./``.

    ``_PARENT_DIR_RE`` does not match a bare name, so the fallback prefix
    must be exactly ``./``; a mangled prefix shows up verbatim in the
    "is not a file" diagnostic for the resolved path.
    """
    with pytest.raises(
        FermError, match=r"'\./ferm_mut_e_nope\.conf' is not a file"
    ):
        collect_filenames("noslashfile", ["ferm_mut_e_nope.conf"])
