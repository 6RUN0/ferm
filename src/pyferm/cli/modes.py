"""
Terminal read-only modes: ``--lint``, introspection and ``--graph``.

All port-only and eval-free: the config is parsed structurally with
:meth:`pyferm.parser.Parser.parse_to_block` (or not read at all), so no
evaluation runs and no kernel, resolver, or previous-ruleset I/O is
touched.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Final

from ..analysis import run_analysis
from ..errors import ExitCode, FermError, internal_error
from ..graph import collect_graph, render_d2, render_dot
from ..introspect import describe, list_modules
from ..parser import Parser
from ..streams import escape_control_chars
from ..tokenizer import open_script
from .options import _build_parser

if TYPE_CHECKING:
    import argparse

    from ..analysis import Severity
    from ..tree import Block


def _parse_config_eval_free(config_path: str, *, mode: str) -> Block:
    """
    Open one config through ``open_script`` and parse it eval-free.

    Shared by ``--lint`` and ``--graph``: both advertise a read-only,
    subprocess-free contract meant to be pointed at untrusted files, so a
    trailing-``|`` pipe path is rejected rather than run through the shell
    (honouring it would be arbitrary command execution driven by a
    filename).  ``open_script`` supplies the input through the same
    boundary as apply/``--plan`` -- preserving ``-`` (stdin), the single
    ``FermError`` on a missing file, and the latin-1 byte model.
    """
    if config_path.endswith("|"):
        raise FermError(f"ferm {mode} cannot read from a pipe command")
    script = open_script(config_path, None)
    try:
        handle = script.handle
        if handle is None:  # open_script always sets it; guard for the type
            raise internal_error("open_script returned no handle")
        config = handle.read()
    finally:
        script.close()
    return Parser.parse_to_block(config)


def _run_lint(config_path: str, *, fail_level: Severity | None) -> int:
    """
    Run the eval-free static analysis for ``ferm --lint`` (port-only).

    Read-only like ``--plan`` but, unlike it, eval-free: the config is parsed
    into a structural tree with :meth:`Parser.parse_to_block` and handed to the
    analysers in :mod:`pyferm.analysis`, so no evaluation runs and no kernel,
    resolver, or previous-ruleset I/O is touched.  ``open_script`` supplies the
    input through the same boundary as apply/``--plan`` -- preserving ``-``
    (stdin), the single ``FermError`` on a missing file, and the latin-1 byte
    model -- so the analysis sees the exact config bytes.  The pipe-path
    rejection rationale lives on :func:`_parse_config_eval_free`.

    Findings print to stdout as ``<severity>: <message>`` lines in a
    fixed, deterministic order (severity tier, then analyzer
    registration order, then message; see analysis.run_analysis); the
    whole line passes through escape_control_chars.  Without a
    ``fail_level`` the exit code stays ``0`` even with findings
    (warnings must not break another project's CI on a heuristic); with
    one, any finding at or above the threshold exits ``2`` for opt-in
    CI gating.
    """
    block = _parse_config_eval_free(config_path, mode="--lint")

    findings = run_analysis(block)
    # The raw message is the sort key; escaping at print time is
    # byte-equivalent (the substitution is position-independent) and a
    # crafted name still cannot inject terminal-control bytes into CI
    # logs.
    for finding in findings:
        line = f"{finding.severity.name.lower()}: {finding.message}"
        sys.stdout.write(f"{escape_control_chars(line)}\n")

    if fail_level is None:
        return ExitCode.OK
    return (
        ExitCode.CHANGES
        if any(f.severity <= fail_level for f in findings)
        else ExitCode.OK
    )


#: Namespace attrs the introspection guard must not reject: its own two
#: flags, the earlier-dispatched help/version, and files (own guard).
_INTROSPECTION_EXEMPT: Final[frozenset[str]] = frozenset(
    {"list_modules", "describe", "help", "version", "files"}
)

#: dest -> user-facing flag, where the mechanical "--" + dest.replace()
#: derivation would lie (--remote/--test share dest="test").
_INTROSPECTION_FLAG_NAMES: Final[dict[str, str]] = {
    "defs": "--def",
    "test": "--test/--remote",
}


def _reject_other_flags(
    args: argparse.Namespace, *, mode: str, exempt: frozenset[str]
) -> None:
    """
    Reject every flag outside ``exempt`` via the default-Namespace diff.

    The diff (not a hand-kept flag list) is what keeps future flags
    auto-rejected instead of silently ignored; ``exempt`` names the
    mode's own flags plus attrs guarded separately by the caller.
    """
    defaults = vars(_build_parser().parse_args([]))
    for attr, default in defaults.items():
        if attr in exempt:
            continue
        if getattr(args, attr) != default:
            flag = _INTROSPECTION_FLAG_NAMES.get(
                attr, "--" + attr.replace("_", "-")
            )
            raise FermError(f"ferm {mode} cannot be combined with {flag}")


def _run_introspection(args: argparse.Namespace) -> int:
    """
    Run ``--list-modules`` / ``--describe`` (port-only, eval-free).

    Guard order is contractual: mode-XOR, then the no-input-file guard,
    then the default-Namespace diff -- the diff cannot see --describe
    (exempt) and would mislabel a stray input file, so the specific
    guards must fire first.  The diff (not a hand-kept flag list) is
    what keeps future flags auto-rejected instead of silently ignored.
    """
    mode = "--list-modules" if args.list_modules else "--describe"
    if args.list_modules and args.describe is not None:
        raise FermError(
            "ferm --list-modules cannot be combined with --describe"
        )
    if args.files:
        raise FermError(f"ferm {mode} takes no input file")
    _reject_other_flags(args, mode=mode, exempt=_INTROSPECTION_EXEMPT)
    if args.list_modules:
        text = list_modules()
    else:
        # _main only calls _run_introspection when list_modules or describe
        # is set, and the mode-XOR check above already ruled out
        # list_modules here, so describe is not None.
        assert args.describe is not None
        text = describe(args.describe)
    sys.stdout.write(text)
    return ExitCode.OK


#: Namespace attrs the --graph guard must not reject (its own flags,
#: earlier-dispatched help/version, and files -- guarded separately).
_GRAPH_EXEMPT: Final[frozenset[str]] = frozenset(
    {"graph", "graph_format", "help", "version", "files"}
)


def _run_graph(args: argparse.Namespace) -> int:
    """
    Run ``--graph`` (port-only, eval-free, read-only).

    Rejects any other flag via the default-Namespace diff (so future flags
    auto-reject), carries its own single-file guard -- it dispatches before
    _resolve_options and cannot inherit the generic len(files) check -- and
    refuses a trailing-``|`` pipe path like --lint. Parses one config with
    parse_to_block, builds the graph, and renders d2 (default) or DOT.
    """
    _reject_other_flags(args, mode="--graph", exempt=_GRAPH_EXEMPT)
    if len(args.files) != 1:
        raise FermError("ferm --graph requires exactly one input file")
    block = _parse_config_eval_free(args.files[0], mode="--graph")
    graph = collect_graph(block)
    fmt = args.graph_format or "d2"
    text = render_dot(graph) if fmt == "dot" else render_d2(graph)
    sys.stdout.write(text)
    return ExitCode.OK
