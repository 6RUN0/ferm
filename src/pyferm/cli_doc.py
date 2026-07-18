"""
The single documentation source for the command-line parsers.

A curated metadata table in the ``BUILTINS`` / ``modules.py`` style:
one entry per argparse ``dest`` -- spellings, display placeholder,
choices, a one-line summary for ``--help``/completion and a POD
paragraph for the man page.  Consumed by the ``--help`` renderer, the
rollback parser's ``help=`` strings, the man templates
(``tools/gen_man.py``) and the completion generator
(``tools/gen_completion.py``).

This module sits BELOW ``pyferm.cli`` (shared with
``pyferm.import_ferm``) and never imports the parsers it documents, so
``choices``/``metavar`` are duplicated here as data; the unit gate
(``tests/unit/test_cli_doc.py``) walks ``parser._actions`` of both real
parsers and fails on any drift -- names, choices and metavar alike.

``import-ferm`` has no argparse parser (its argv handling ports the
oracle's ``-``-argument rejection, with a bare ``-`` deliberately
special-cased to mean stdin), so its tiny block
is curated by hand and stays outside the gate by design; its usage
banner renders from here so no second hand-written help remains.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class OptionDoc:
    """One documented command-line option, keyed by argparse ``dest``."""

    #: Every spelling in argparse declaration order (``-n``, ``--noexec``);
    #: a positional argument carries its ``dest`` as the only element.
    spellings: tuple[str, ...]
    dest: str
    #: One-line help/completion text; ``\n`` starts a continuation line.
    #: Must not contain ``%`` (argparse ``help=`` interpolates it).
    summary: str
    #: The OPTIONS paragraph for the man page (POD markup allowed).
    pod: str
    #: Display placeholder in ``--help`` (e.g. ``s``, ``'$name=v'``).
    arg: str | None = None
    #: argparse ``metavar``, exactly as declared (gate-checked).
    metavar: str | None = None
    #: argparse ``choices``, exactly as declared (gate-checked copy:
    #: this module must not import the parsers, so choices are data).
    choices: tuple[str, ...] | None = None
    positional: bool = False


FERM_OPTIONS: Final[tuple[OptionDoc, ...]] = (
    OptionDoc(
        spellings=("-n", "--noexec"),
        dest="noexec",
        summary="Do not execute the rules, just simulate",
        pod=(
            "Do not execute the netfilter commands, just simulate.  "
            "Combine with B<--lines> to inspect the generated rules."
        ),
    ),
    OptionDoc(
        spellings=("-F", "--flush"),
        dest="flush",
        summary="Flush all netfilter tables managed by ferm",
        pod=(
            "Clear the firewall rules and set the policy of every "
            "affected chain to ACCEPT.  B<ferm> still needs the "
            "configuration file to determine which domains and tables "
            "are affected."
        ),
    ),
    OptionDoc(
        spellings=("--noflush",),
        dest="noflush",
        summary="Do not flush the kernel tables before applying",
        pod=(
            "Apply without flushing first: rules in undeclared chains "
            "are kept, declared chains are overwritten and policies "
            "applied.  Re-running appends the declared rules again -- "
            "see the caveats B<--plan> prints for noflush diffs."
        ),
    ),
    OptionDoc(
        spellings=("-l", "--lines"),
        dest="lines",
        summary="Show all rules that were created",
        pod=(
            "Show the firewall lines generated from the rules, just "
            "before they are executed -- an iptables(8) error can then "
            "be matched to the rule that caused it."
        ),
    ),
    OptionDoc(
        spellings=("-i", "--interactive"),
        dest="interactive",
        summary="Interactive mode: revert if user does not confirm",
        pod=(
            "Apply the rules and ask for confirmation; revert to the "
            "previous ruleset when no valid response arrives within "
            "the timeout.  The safety net for remote administration."
        ),
    ),
    OptionDoc(
        spellings=("-t", "--timeout"),
        dest="timeout",
        arg="s",
        summary="Define interactive mode timeout in seconds",
        pod=(
            "Wait this many seconds for the B<--interactive> "
            "confirmation before reverting (default 30)."
        ),
    ),
    OptionDoc(
        spellings=("-h", "--help"),
        dest="help",
        summary="Look at this text",
        pod="Print the option summary and exit.",
    ),
    OptionDoc(
        spellings=("-V", "--version"),
        dest="version",
        summary="Show current version number",
        pod="Print the version banner and exit.",
    ),
    OptionDoc(
        spellings=("--test", "--remote"),
        dest="test",
        summary=(
            "Test mode; ignore host specific configuration.\n"
            "Implies --noexec and --lines (--remote is an alias)."
        ),
        pod=(
            "Test mode: parse and build everything while ignoring "
            "host-specific state (kernel readback, tool discovery).  "
            "Implies B<--noexec> and B<--lines>.  B<--remote> is an "
            "alias kept for compatibility."
        ),
    ),
    OptionDoc(
        spellings=("--test-mock-previous",),
        dest="test_mock_previous",
        arg="fam=path",
        summary=(
            "Simulation: use a saved dump as the family's\n"
            "previous state (offline what-if with --test --plan)"
        ),
        pod=(
            "Simulation: substitute a saved dump for the named "
            "family's previous kernel state.  Enables offline what-if "
            "planning without root: C<ferm --test --test-mock-previous "
            "ip=snap.save --plan ferm.conf>.  May repeat, one family "
            "per occurrence."
        ),
    ),
    OptionDoc(
        spellings=("--fast",),
        dest="fast",
        summary="Fast mode: use iptables-restore (the default)",
        pod=(
            "Use iptables-restore(8) for an atomic install.  This is "
            "the default; the switch exists for symmetry with "
            "B<--slow>."
        ),
    ),
    OptionDoc(
        spellings=("--slow",),
        dest="slow",
        summary="Slow mode, don't use iptables-restore",
        pod=(
            "Run one iptables(8) process per rule instead of an "
            "atomic iptables-restore(8) install."
        ),
    ),
    OptionDoc(
        spellings=("--shell",),
        dest="shell",
        summary="Generate a shell script which calls iptables-restore",
        pod=(
            "Print a shell script that feeds the generated rules to "
            "iptables-restore(8); implies B<--lines>."
        ),
    ),
    OptionDoc(
        spellings=("--domain",),
        dest="domain",
        arg="{ip|ip6}",
        summary="Handle only the specified domain",
        pod=(
            "Restrict processing to one domain.  The configuration is "
            "still parsed as a whole; other domains are skipped."
        ),
    ),
    OptionDoc(
        spellings=("--def",),
        dest="defs",
        arg="'$name=v'",
        summary="Override a variable",
        pod=(
            "Override a configuration variable from the command line; "
            "may repeat."
        ),
    ),
    OptionDoc(
        spellings=("--nolegacy",),
        dest="nolegacy",
        summary="Never use the iptables-legacy tools",
        pod=(
            "Skip the C<*-legacy> tool family during tool discovery "
            "-- for hosts where the legacy binaries exist but the "
            "nf_tables-based ones own the kernel state."
        ),
    ),
    OptionDoc(
        spellings=("--nft",),
        dest="nft",
        summary="Use the native nftables backend",
        pod=(
            "Install the ruleset natively through nft(8) instead of "
            "iptables-restore(8).  See the NFT BACKEND section."
        ),
    ),
    OptionDoc(
        spellings=("--full-reload",),
        dest="full_reload",
        summary="With --nft: full flush+reload instead of delta apply",
        pod=(
            "Opt out of the incremental delta apply under B<--nft>: "
            "flush the ferm-owned tables and reload from scratch "
            "(counters reset)."
        ),
    ),
    OptionDoc(
        spellings=("--no-etckeeper",),
        dest="no_etckeeper",
        summary="Skip the etckeeper history commit after apply",
        pod=(
            "Do not record the applied ruleset in the etckeeper(8) "
            "history.  See the ETCKEEPER INTEGRATION section."
        ),
    ),
    OptionDoc(
        spellings=("--plan",),
        dest="plan",
        summary="Read-only preview: report changes, apply nothing",
        pod=(
            "Compute the ruleset and report what would change against "
            "the running kernel, applying nothing.  Exit status 2 "
            "signals pending changes.  See the PLAN MODE section."
        ),
    ),
    OptionDoc(
        spellings=("--plan-format",),
        dest="plan_format",
        arg="F",
        choices=("structured", "diff"),
        summary="Plan renderer: structured or diff (default structured)",
        pod=(
            "Select the B<--plan> renderer: C<structured> (default, "
            "per-family change list) or C<diff> (a unified diff)."
        ),
    ),
    OptionDoc(
        spellings=("--lint",),
        dest="lint",
        summary="Static-analysis mode: report warnings, apply nothing",
        pod=(
            "Eval-free static analysis of the configuration: report "
            "findings and apply nothing.  See the LINT MODE section."
        ),
    ),
    OptionDoc(
        spellings=("--lint-strict",),
        dest="lint_strict",
        summary="With --lint: exit non-zero if any warning is found",
        pod=(
            "Gate B<--lint> at warning level: any finding at warning "
            "or above yields exit status 2."
        ),
    ),
    OptionDoc(
        spellings=("--lint-fail-level",),
        dest="lint_fail_level",
        arg="L",
        choices=("error", "warning", "info"),
        summary="Set the --lint gating threshold (error|warning|info)",
        pod=(
            "Gate B<--lint> at an explicit severity: findings at or "
            "above I<L> yield exit status 2."
        ),
    ),
    OptionDoc(
        spellings=("--list-modules",),
        dest="list_modules",
        summary="List supported netfilter modules and keywords",
        pod=(
            "Print every supported protocol/match/target module and "
            "keyword, then exit.  See the INTROSPECTION section."
        ),
    ),
    OptionDoc(
        spellings=("--describe",),
        dest="describe",
        arg="NAME",
        summary="Show the options of one module, option or keyword",
        pod=(
            "Describe one name -- a module, an option, a builtin, a "
            "shortcut or a deprecated keyword; unknown names get "
            "close-match suggestions."
        ),
    ),
    OptionDoc(
        spellings=("--graph",),
        dest="graph",
        summary="Print the chain control-flow graph (d2 or DOT)",
        pod=(
            "Print the configuration's chain control-flow graph "
            "without evaluating or applying it."
        ),
    ),
    OptionDoc(
        spellings=("--graph-format",),
        dest="graph_format",
        arg="F",
        choices=("dot", "d2"),
        summary="Graph renderer: dot or d2 (default d2)",
        pod="Select the B<--graph> renderer: C<d2> (default) or C<dot>.",
    ),
    OptionDoc(
        spellings=("files",),
        dest="files",
        summary="The configuration file to process",
        pod="The configuration file to process.",
        positional=True,
    ),
)


ROLLBACK_OPTIONS: Final[tuple[OptionDoc, ...]] = (
    OptionDoc(
        spellings=("--list",),
        dest="list",
        summary="Show the config's dated revision history",
        pod=(
            "Print the config's revision history -- abbreviated sha, "
            "local-time date, subject -- newest first; the first line "
            "is marked C<(current)>."
        ),
    ),
    OptionDoc(
        spellings=("--diff",),
        dest="diff",
        arg="[SHA]",
        metavar="SHA",
        summary=(
            "Print the diff against SHA (default: the previous\n"
            "revision); read-only, applies nothing"
        ),
        pod=(
            "Print the config diff against I<SHA> on stdout and exit; "
            "nothing is applied.  Without I<SHA> the previous ferm "
            "revision is used -- exactly what the bare rollback form "
            "would revert to.  Only a hex sha from B<--list> is "
            "accepted."
        ),
    ),
    OptionDoc(
        spellings=("--to",),
        dest="to",
        arg="SHA",
        metavar="SHA",
        summary="Revert to an exact revision and re-apply (no prompt)",
        pod=(
            "Revert the config directory to revision I<SHA> and "
            "re-apply it -- the scriptable form, no confirmation "
            "prompt."
        ),
    ),
    OptionDoc(
        spellings=("-n", "--limit"),
        dest="limit",
        arg="N",
        metavar="N",
        summary="With --list: show at most N entries",
        pod=(
            "Cap B<--list> at I<N> entries (an integer >= 1); an "
            "error without B<--list>."
        ),
    ),
    OptionDoc(
        spellings=("--nft",),
        dest="nft",
        summary="Re-apply with the native nftables backend",
        pod=(
            "Inherit the nft backend for the re-apply: an nft install "
            "must roll back under nft, not fall to iptables."
        ),
    ),
    OptionDoc(
        spellings=("--slow",),
        dest="slow",
        summary="Re-apply in slow mode (one iptables process per rule)",
        pod="Inherit slow mode for the re-apply.",
    ),
    OptionDoc(
        spellings=("--full-reload",),
        dest="full_reload",
        summary="With --nft: full flush+reload on re-apply",
        pod="Inherit the full-reload switch for the nft re-apply.",
    ),
    OptionDoc(
        spellings=("--nolegacy",),
        dest="nolegacy",
        summary="Never use the iptables-legacy tools on re-apply",
        pod="Inherit the legacy-tool exclusion for the re-apply.",
    ),
    OptionDoc(
        spellings=("-i", "--interactive"),
        dest="interactive",
        summary="Ask for confirmation on the re-apply",
        pod="Inherit interactive mode for the re-apply.",
    ),
    OptionDoc(
        spellings=("-t", "--timeout"),
        dest="timeout",
        arg="s",
        summary="Interactive confirmation timeout in seconds",
        pod="Inherit the interactive timeout for the re-apply.",
    ),
    OptionDoc(
        spellings=("--domain",),
        dest="domain",
        arg="{ip|ip6}",
        summary="Re-apply only the specified domain",
        pod="Inherit the domain restriction for the re-apply.",
    ),
    OptionDoc(
        spellings=("--def",),
        dest="defs",
        arg="'$name=v'",
        summary="Variable override for the re-apply",
        pod=(
            "Inherit a B<--def> override: a config referencing a "
            "command-line variable would otherwise fail to re-apply."
        ),
    ),
    OptionDoc(
        spellings=("--no-etckeeper",),
        dest="no_etckeeper",
        summary="Skip the history commit after the re-apply",
        pod="Skip recording the rollback as a new history commit.",
    ),
    OptionDoc(
        spellings=("-h", "--help"),
        dest="help",
        summary="Show the rollback usage and exit",
        pod="Print the rollback usage and exit.",
    ),
    OptionDoc(
        spellings=("config",),
        dest="config",
        summary="The config to roll back (default /etc/ferm/ferm.conf)",
        pod=(
            "The configuration to roll back; defaults to "
            "F</etc/ferm/ferm.conf>."
        ),
        positional=True,
    ),
)


IMPORT_FERM_USAGE_LINES: Final[tuple[str, ...]] = (
    "import-ferm > ferm.conf",
    "iptables-save | import-ferm > ferm.conf",
    "import-ferm inputfile > ferm.conf",
)

IMPORT_FERM_OPTIONS: Final[tuple[OptionDoc, ...]] = (
    OptionDoc(
        spellings=("-h", "--help"),
        dest="help",
        summary="Print the usage banner and exit",
        pod=(
            "Print the usage banner and exit.  Any other option-like "
            "argument (a dash followed by more characters) is a usage "
            "error: B<import-ferm> takes only input files."
        ),
    ),
    OptionDoc(
        spellings=("inputfile",),
        dest="files",
        summary="iptables-save dump(s) to import",
        pod=(
            "One or more iptables-save(8) dumps to import; a bare "
            "C<-> reads stdin.  Without arguments B<import-ferm> "
            "reads a dump from stdin, or runs F<iptables-save> "
            "itself when stdin is a terminal."
        ),
        positional=True,
    ),
)

IMPORT_FERM_ENVIRONMENT: Final[tuple[tuple[str, str], ...]] = (
    (
        "FERM_DOMAIN",
        "The domain the imported rules belong to: C<ip> (default) or "
        "C<ip6>.  Set C<FERM_DOMAIN=ip6> when feeding an "
        "ip6tables-save(8) dump.",
    ),
)


#: The rollback grammar in one spelling: ``--help`` renders it below the
#: option table, and the man page's SYNOPSIS must carry the same line
#: (gated by ``test_cli_doc``), so the two cannot drift apart.
ROLLBACK_SYNOPSIS: Final[str] = (
    "ferm rollback [--list [-n N] | --diff [SHA] | --to SHA] [config]"
)


_ROLLBACK_BY_DEST: Final[dict[str, OptionDoc]] = {
    opt.dest: opt for opt in ROLLBACK_OPTIONS
}

#: The historic pod2usage column layout of the Perl --help output.
_HELP_INDENT: Final[str] = "     "
_HELP_FLAGS_WIDTH: Final[int] = 17


def _help_flags(opt: OptionDoc) -> str:
    """Build the flags column: spellings plus the display placeholder."""
    flags = ", ".join(opt.spellings)
    return f"{flags} {opt.arg}" if opt.arg is not None else flags


def render_help() -> str:
    """
    Render the ``--help`` text from the table.

    Preserves the historic column layout (5-space indent, 17-column
    flags field); options render in table order, followed by a short
    pointer at the ``rollback`` subcommand, whose own parser prints
    the detailed help.
    """
    lines = ["Usage:", "    ferm options inputfiles", "", "Options:"]
    for opt in FERM_OPTIONS:
        if opt.positional:
            continue
        first, *rest = opt.summary.split("\n")
        flags = _help_flags(opt)
        if len(flags) <= _HELP_FLAGS_WIDTH:
            lines.append(f"{_HELP_INDENT}{flags:<{_HELP_FLAGS_WIDTH}} {first}")
        else:
            lines.append(f"{_HELP_INDENT}{flags}")
            rest = [first, *rest]
        pad = f"{_HELP_INDENT}{'':{_HELP_FLAGS_WIDTH}} "
        lines.extend(f"{pad}{cont}" for cont in rest)
    lines += [
        "",
        "Subcommand:",
        f"    {ROLLBACK_SYNOPSIS}",
        "                      Revert the config to a recorded revision and",
        "                      re-apply it (see 'ferm rollback --help')",
        "",
    ]
    return "\n".join(lines) + "\n"


def render_import_ferm_usage() -> str:
    """Render import-ferm's usage banner (the former ``_USAGE``)."""
    lines = ["Usage:", *(f"    {line}" for line in IMPORT_FERM_USAGE_LINES)]
    return "\n".join(lines) + "\n"


def rollback_help(dest: str) -> str:
    """Return the one-line ``help=`` string for a rollback option."""
    return _ROLLBACK_BY_DEST[dest].summary.replace("\n", " ")
