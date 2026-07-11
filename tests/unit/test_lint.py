"""
Unit tests for ``ferm --lint`` (Phase-7 DX slice).

The two analysers behind the mode (:func:`pyferm.analysis.find_unused_defs`,
:func:`pyferm.analysis.find_undefined_chain_jumps`) are unit-tested directly in
``tests/unit/test_analysis.py``; these tests drive only the stable public
surface (:func:`pyferm.cli.main`) and pin the wrapper's own contract: output
format, ordering, the two-tier exit-code convention, and flag-combination
validation -- per
``docs/superpowers/specs/2026-07-02-phase7-lint-design.md``.
"""

from __future__ import annotations

import io
import sys
from typing import TYPE_CHECKING

import pytest

from pyferm.cli import _build_parser, _resolve_options, main
from pyferm.errors import FermError

if TYPE_CHECKING:
    from pathlib import Path

    from pyferm.config import Options


def _write(tmp_path: Path, text: str) -> Path:
    """Write ``text`` to a fresh ``.ferm`` file under ``tmp_path``."""
    conf = tmp_path / "t.ferm"
    conf.write_text(text, encoding="utf-8")
    return conf


def _parse_and_resolve(argv: list[str]) -> Options:
    """
    Parse ``argv`` and derive Options.

    No tty patching: the ``--lint`` conflict guard now runs before the
    apply-path timeout/interactive-tty checks (hoisted to the top of
    ``_resolve_options``), so it never touches ``isatty()``.
    """
    return _resolve_options(_build_parser().parse_args(argv))


# FOO is declared and reached only via the deprecated `realgoto` keyword, so
# the deprecated-keyword info finding is the sole output across all three
# fail-level thresholds that exercise it.
_REALGOTO_INFO_CFG = (
    "table filter {\n"
    "  chain FOO { ACCEPT; }\n"
    "  chain INPUT { realgoto FOO; }\n"
    "}\n"
)


# --- mode behaviour: findings, ordering, exit codes -------------------------


def test_clean_config_has_no_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A config with no unused defs and no dangling jumps prints nothing."""
    conf = _write(
        tmp_path,
        "@def $x = 1;\ntable filter chain INPUT { saddr $x ACCEPT; }\n",
    )
    assert main(["--lint", str(conf)]) == 0
    assert capsys.readouterr().out == ""


def test_empty_file_has_no_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Boundary case: an empty Block yields ``[]`` from both analysers."""
    conf = _write(tmp_path, "")
    assert main(["--lint", str(conf)]) == 0
    assert capsys.readouterr().out == ""


def test_unused_def_warns_and_exits_zero_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The unused-def line carries the leading ``$`` and exits 0 by default."""
    conf = _write(tmp_path, "@def $foo = 1;\n")
    assert main(["--lint", str(conf)]) == 0
    assert capsys.readouterr().out == "warning: unused definition: $foo\n"


def test_unused_def_escalates_to_exit_two_under_strict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--lint-strict`` changes only the exit code, never the stdout."""
    conf = _write(tmp_path, "@def $foo = 1;\n")
    assert main(["--lint", "--lint-strict", str(conf)]) == 2
    assert capsys.readouterr().out == "warning: unused definition: $foo\n"


def test_undefined_chain_jump_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A jump to a chain declared nowhere prints the bare-name warning."""
    conf = _write(tmp_path, "table filter chain INPUT { jump MISSING; }\n")
    assert main(["--lint", str(conf)]) == 0
    out = capsys.readouterr().out
    assert out == "warning: jump to undefined chain: MISSING\n"


def test_mixed_findings_are_grouped_and_sorted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    Fixed order: ALL unused-definition lines (sorted) first, THEN all
    jump-to-undefined-chain lines (sorted) -- never interleaved."""
    conf = _write(
        tmp_path,
        "@def $zeta = 1;\n"
        "@def $alpha = 2;\n"
        "table filter chain INPUT {\n"
        "  jump ZULU;\n"
        "  jump ALPHA_CHAIN;\n"
        "}\n",
    )
    assert main(["--lint", str(conf)]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "warning: unused definition: $alpha",
        "warning: unused definition: $zeta",
        "warning: jump to undefined chain: ALPHA_CHAIN",
        "warning: jump to undefined chain: ZULU",
    ]


def test_nonexistent_file_exits_one_with_stderr_diagnostic(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The only reachable exit-1: a file-read failure, not a syntax error."""
    missing = tmp_path / "does-not-exist.ferm"
    assert main(["--lint", str(missing)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Failed to open" in captured.err


def test_stdin_dash_is_read_as_the_source(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``ferm --lint -`` reads the config from stdin like any other source."""
    monkeypatch.setattr(sys, "stdin", io.StringIO("@def $foo = 1;\n"))
    assert main(["--lint", "-"]) == 0
    assert capsys.readouterr().out == "warning: unused definition: $foo\n"


# --- accepted-but-ignored flags ----------------------------------------------


def test_lint_accepts_and_ignores_timeout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    ``--timeout`` is apply-path-only (needs ``--interactive`` there) but is
    accepted-and-ignored under ``--lint``, which never reaches that guard."""
    conf = _write(tmp_path, "chain INPUT ACCEPT;\n")
    assert main(["--lint", "--timeout", "5", str(conf)]) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    "flag", ["--noexec", "--lines", "--test", "--nolegacy", "--no-etckeeper"]
)
def test_lint_accepts_and_ignores_harmless_flags(
    flag: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    Spec's accepted-but-ignored list: harmless under eval-free analysis,
    so none of them may raise or otherwise disturb the lint result."""
    conf = _write(tmp_path, "chain INPUT ACCEPT;\n")
    assert main(["--lint", flag, str(conf)]) == 0
    assert capsys.readouterr().err == ""


# --- flag-combination validation ---------------------------------------------


def test_lint_strict_without_lint_is_rejected() -> None:
    """``--lint-strict`` is rejected outright without ``--lint``."""
    with pytest.raises(FermError, match="has no sense without --lint"):
        _parse_and_resolve(["--lint-strict", "f.ferm"])


@pytest.mark.parametrize(
    ("flag", "extra"),
    [
        ("--plan", []),
        ("--nft", []),
        ("--fast", []),
        ("--flush", []),
        ("--noflush", []),
        ("--def", ["$x=1"]),
        ("--domain", ["ip"]),
        ("--plan-format", ["diff"]),
        ("--full-reload", []),
        ("--shell", []),
    ],
)
def test_lint_rejects_incompatible_flags_via_main(
    flag: str,
    extra: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    Apply/plan modes and eval-dependent flags are rejected outright --
    accepting them would silently no-op under eval-free analysis. Covers all
    nine reject-loop switches (``--fast``/``--flush``/``--noflush`` included so
    a mutant swapping or dropping any tuple entry is caught), worker-1's
    dedicated ``--plan-format`` deviation (caught before the generic "no sense
    without --plan" message), and ``--full-reload``/``--shell`` regardless of
    ``--nft``."""
    conf = _write(tmp_path, "chain INPUT ACCEPT;\n")
    assert main(["--lint", flag, *extra, str(conf)]) == 1
    assert f"cannot be combined with {flag}" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--slow", "--interactive"])
def test_lint_rejects_other_apply_mode_flags(flag: str) -> None:
    """
    Same rejection for the remaining apply-mode-only switches -- no tty
    patching required now that the guard is hoisted above the tty checks."""
    with pytest.raises(FermError, match=f"cannot be combined with {flag}"):
        _parse_and_resolve(["--lint", flag, "f.ferm"])


def test_lint_interactive_rejected_in_non_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    Proves the hoist: even with neither stream a tty, ``--lint
    --interactive`` raises the LINT message, not the unrelated apply-path
    "not a tty" guard -- the two guards must never race."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False, raising=False)
    with pytest.raises(
        FermError, match="cannot be combined with --interactive"
    ):
        _parse_and_resolve(["--lint", "--interactive", "f.ferm"])


# --- known limitation: no syntax validation ---------------------------------


def test_malformed_config_never_raises_and_stays_exit_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    The structural parser is error-tolerant: an unbalanced ``{`` yields a
    partial tree, not a diagnostic, so ``--lint`` degrades to a best-effort
    result instead of raising or reporting a syntax error as exit 1. Default
    (non-strict) mode never returns 2, findings or not, so this pins exit 0
    exactly rather than the looser ``in (0, 2)``."""
    conf = _write(tmp_path, "table filter chain INPUT { jump MISSING;\n")
    assert main(["--lint", str(conf)]) == 0
    assert "Traceback" not in capsys.readouterr().err


# --- security: pipe path and control-char escaping ---------------------------


def test_lint_rejects_pipe_path_without_running_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    A trailing-``|`` path is a shell pipe-include on the apply/plan path;
    under ``--lint`` -- advertised read-only and subprocess-free -- it must be
    rejected before ``open_script`` runs it, and the side-effect must not
    happen."""
    marker = tmp_path / "PWNED"
    assert main(["--lint", f"touch {marker}|"]) == 1
    assert "cannot read from a pipe command" in capsys.readouterr().err
    assert not marker.exists()


def test_lint_escapes_control_chars_in_finding_names(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    A quoted chain name may carry an ESC byte (latin-1 admits any byte);
    the printed warning must escape it so a crafted config cannot inject a
    terminal-control sequence into a CI log line."""
    conf = _write(tmp_path, 'table filter chain INPUT { jump "A\x1bB"; }\n')
    assert main(["--lint", str(conf)]) == 0
    out = capsys.readouterr().out
    assert out == "warning: jump to undefined chain: A\\x1bB\n"
    assert "\x1b" not in out


# --- usage errors: not exactly one input file -> exit 1 ----------------------


@pytest.mark.parametrize("files", [[], ["a.ferm", "b.ferm"]])
def test_lint_with_wrong_file_count_prints_usage_and_exits_one(
    files: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """
    The whole-CLI ``exactly one file`` guard fires before the ``--lint``
    dispatch, so zero or multiple files print the usage text to stdout and
    exit 1 -- the documented usage-error tier, never a crash on
    ``args.files[0]``."""
    assert main(["--lint", *files]) == 1
    assert capsys.readouterr().out.startswith("Usage:")


# --- --lint-fail-level: настраиваемый порог гейтинга -------------------------


def test_fail_level_error_does_not_gate_warnings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A warning finding under ``--lint-fail-level=error`` stays exit 0."""
    conf = _write(tmp_path, "@def $foo = 1;\n")
    assert main(["--lint", "--lint-fail-level=error", str(conf)]) == 0
    assert capsys.readouterr().out == "warning: unused definition: $foo\n"


def test_fail_level_warning_gates_warnings(tmp_path: Path) -> None:
    """``--lint-fail-level=warning`` is the bare ``--lint-strict``."""
    conf = _write(tmp_path, "@def $foo = 1;\n")
    assert main(["--lint", "--lint-fail-level=warning", str(conf)]) == 2


def test_fail_level_info_gates_any_finding(tmp_path: Path) -> None:
    """The lowest threshold gates a warning finding too."""
    conf = _write(tmp_path, "@def $foo = 1;\n")
    assert main(["--lint", "--lint-fail-level=info", str(conf)]) == 2


def test_fail_level_wins_over_bare_strict(tmp_path: Path) -> None:
    """Both flags together: the explicit level overrides the shorthand."""
    conf = _write(tmp_path, "@def $foo = 1;\n")
    argv = ["--lint", "--lint-strict", "--lint-fail-level=error", str(conf)]
    assert main(argv) == 0


def test_fail_level_without_lint_is_rejected() -> None:
    """Same guard family as ``--lint-strict`` without ``--lint``."""
    with pytest.raises(FermError, match="has no sense without --lint"):
        _parse_and_resolve(["--lint-fail-level=warning", "f.ferm"])


def test_invalid_fail_level_literal_dies_in_argparse(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """
    Pinned, documented behaviour: a bogus level dies inside argparse
    (SystemExit 2) BEFORE the FermError exit-1 contract -- the same
    pre-existing pattern as ``--plan-format=bogus``. The stderr assert
    distinguishes the real cause (invalid choice) from the vacuous
    pre-implementation exit ("unrecognized arguments" is ALSO code 2)."""
    with pytest.raises(SystemExit) as excinfo:
        _build_parser().parse_args(
            ["--lint", "--lint-fail-level=bogus", "f.ferm"]
        )
    assert excinfo.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_unused_function_prints_with_sigil(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The & sigil disambiguates a function finding from a $var one."""
    conf = _write(tmp_path, "@def &noop($a) = ACCEPT;\n")
    assert main(["--lint", str(conf)]) == 0
    assert capsys.readouterr().out == "warning: unused definition: &noop\n"


def test_info_finding_prints_with_info_prefix(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    FOO is declared and reached via realgoto, so the deprecated info
    line is the ONLY output -- pinned exactly."""
    conf = _write(tmp_path, _REALGOTO_INFO_CFG)
    assert main(["--lint", str(conf)]) == 0
    out = capsys.readouterr().out
    assert out == "info: deprecated keyword: realgoto (use goto)\n"


def test_info_does_not_gate_under_bare_strict(tmp_path: Path) -> None:
    """--lint-strict thresholds at warning; an info finding passes."""
    conf = _write(tmp_path, _REALGOTO_INFO_CFG)
    assert main(["--lint", "--lint-strict", str(conf)]) == 0


def test_info_gates_under_fail_level_info(tmp_path: Path) -> None:
    conf = _write(tmp_path, _REALGOTO_INFO_CFG)
    assert main(["--lint", "--lint-fail-level=info", str(conf)]) == 2


def test_error_finding_prints_error_prefix_and_gates_on_error_level(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    A self-loop is the minimal error finding: FOO is declared and
    self-reached, so the cycle line is the only output."""
    conf = _write(tmp_path, "table filter chain FOO { jump FOO; }\n")
    assert main(["--lint", "--lint-fail-level=error", str(conf)]) == 2
    assert capsys.readouterr().out == "error: jump cycle: FOO -> FOO\n"


def test_error_finding_still_exits_zero_by_default(tmp_path: Path) -> None:
    """No gating flag -> exit 0 even for the error tier."""
    conf = _write(tmp_path, "table filter chain FOO { jump FOO; }\n")
    assert main(["--lint", str(conf)]) == 0


def test_cross_scope_duplicates_print_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    Messages carry no positions, so two REAL same-name duplicates in
    two different scopes collapse into one printed line -- the accepted,
    documented dedup collision."""
    conf = _write(
        tmp_path,
        "table filter {\n"
        "  chain A { @def $x = 1; @def $x = 2; ACCEPT; }\n"
        "  chain B { @def $x = 3; @def $x = 4; ACCEPT; }\n"
        "}\n",
    )
    assert main(["--lint", str(conf)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines.count("warning: duplicate definition: $x") == 1


def test_severity_order_error_then_warning_then_info(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """
    One finding of each tier on one config: the output order is the
    severity order, regardless of source order."""
    conf = _write(
        tmp_path,
        "@def $unused = 1;\n"
        "table filter {\n"
        "  chain A { jump B; }\n"
        "  chain B { realgoto A; }\n"
        "}\n",
    )
    assert main(["--lint", str(conf)]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "error: jump cycle: A -> B -> A",
        "warning: unused definition: $unused",
        "info: deprecated keyword: realgoto (use goto)",
    ]
