"""
The ``cli_doc`` table vs the real parsers: spellings, choices, metavar.

The table cannot import the parsers (layering), so ``choices`` and
``metavar`` live in it as duplicated data; this gate walks
``parser._actions`` of both parsers -- NOT ``vars(parse_args())``,
which would miss the rollback parser's help action -- and fails on
any drift.  ``import-ferm`` has no parser and stays outside by design.
"""

from __future__ import annotations

import argparse
import re
from typing import TYPE_CHECKING

import pytest

from pyferm import cli_doc
from pyferm.cli import _build_parser, _build_rollback_parser
from tests.unit._packaging import find_repo_root

if TYPE_CHECKING:
    from collections.abc import Callable


def _grouped_actions(
    parser: argparse.ArgumentParser,
) -> dict[str, list[argparse.Action]]:
    """
    Group the parser's actions by ``dest``.

    ``--test``/``--remote`` share ``dest="test"`` and become one group;
    the rollback parser's ``add_help`` action maps onto ``help``
    regardless of its dest (argparse suppresses it in the namespace).
    """
    grouped: dict[str, list[argparse.Action]] = {}
    for action in parser._actions:  # the gate's whole point
        dest = (
            "help" if isinstance(action, argparse._HelpAction) else action.dest
        )
        grouped.setdefault(dest, []).append(action)
    return grouped


@pytest.mark.parametrize(
    ("build", "table"),
    [
        pytest.param(_build_parser, cli_doc.FERM_OPTIONS, id="ferm"),
        pytest.param(
            _build_rollback_parser, cli_doc.ROLLBACK_OPTIONS, id="rollback"
        ),
    ],
)
def test_table_matches_parser(
    build: Callable[[], argparse.ArgumentParser],
    table: tuple[cli_doc.OptionDoc, ...],
) -> None:
    grouped = _grouped_actions(build())
    docs = {opt.dest: opt for opt in table}
    assert set(grouped) == set(docs), (
        "cli_doc drift: options exist on exactly one side"
    )
    for dest, actions in grouped.items():
        doc = docs[dest]
        spellings = tuple(
            spelling
            for action in actions
            for spelling in action.option_strings
        )
        if spellings:
            assert doc.spellings == spellings, dest
            assert not doc.positional, dest
        else:
            assert doc.positional, dest
            assert doc.spellings == (dest,), dest
        for action in actions:
            choices = (
                None
                if action.choices is None
                else tuple(str(choice) for choice in action.choices)
            )
            assert choices == doc.choices, dest
            assert action.metavar == doc.metavar, dest


def test_table_dests_are_unique() -> None:
    for table in (cli_doc.FERM_OPTIONS, cli_doc.ROLLBACK_OPTIONS):
        dests = [opt.dest for opt in table]
        assert len(dests) == len(set(dests))


def test_summaries_are_argparse_safe() -> None:
    # argparse help= interpolates %-sequences; the table must stay free
    # of them so rollback_help() can be passed through verbatim.
    for table in (cli_doc.FERM_OPTIONS, cli_doc.ROLLBACK_OPTIONS):
        for opt in table:
            assert "%" not in opt.summary, opt.dest


# --- man ROLLBACK prose vs the real rollback grammar -----------------------

# find_repo_root, not parents[2]: the mutmut sandbox copies only
# src + tests into mutants/, so docs/ lives in the real checkout above.
_FERM_POD_TEMPLATE = find_repo_root() / "docs" / "templates" / "ferm.pod.j2"


def _rollback_section() -> str:
    """Slice the (static, jinja-free) ROLLBACK prose out of the template."""
    text = _FERM_POD_TEMPLATE.read_text(encoding="utf-8")
    _, _, tail = text.partition("=head1 ROLLBACK")
    section, _, _ = tail.partition("=head1")
    assert section.strip(), "ferm.pod.j2 lost its ROLLBACK section"
    return section


def test_man_rollback_synopsis_matches_help() -> None:
    # The man SYNOPSIS must carry the exact grammar line --help renders
    # (modulo the B<>/I<> POD markup); a form added or renamed on one
    # side only is drift.
    text = _FERM_POD_TEMPLATE.read_text(encoding="utf-8")
    lines = [
        re.sub(r"[BI]<([^<>]*)>", r"\1", line)
        for line in text.splitlines()
        if "rollback [" in line
    ]
    assert cli_doc.ROLLBACK_SYNOPSIS in lines


def test_man_rollback_prose_names_only_real_options() -> None:
    # The ROLLBACK section is hand-written prose (no generated flag
    # table), so a renamed/removed option could linger there unnoticed:
    # every B<-...> token it names must be a live rollback spelling.
    spellings = {
        spelling
        for opt in cli_doc.ROLLBACK_OPTIONS
        for spelling in opt.spellings
    }
    named = set(re.findall(r"B<(-[^<>]*)>", _rollback_section()))
    assert named, "the ROLLBACK prose stopped naming any option"
    assert named <= spellings, named - spellings
