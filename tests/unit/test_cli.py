"""Unit tests for :mod:`pyferm.cli` (option derivation and main-flow seams)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from pyferm.cli import _build_parser, _resolve_options, _setup_streams
from pyferm.config import Options
from pyferm.errors import FermError


def _resolve(
    argv: list[str], *, tty: bool, monkeypatch: pytest.MonkeyPatch
) -> Options:
    """Parse ``argv`` and derive options with stdin/stderr tty-ness forced."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: tty, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: tty, raising=False)
    return _resolve_options(_build_parser().parse_args(argv))


def test_noexec_suppresses_interactive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    options = _resolve(
        ["--noexec", "--interactive", "f"], tty=False, monkeypatch=monkeypatch
    )
    # Perl: $option{interactive} = $opt_interactive && !$opt_noexec (:679);
    # with interactive derived false the tty checks never fire.
    assert options.interactive is False


def test_test_does_not_suppress_interactive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # --test implies noexec for execution, but the oracle derives
    # interactive from the RAW --noexec switch, so --test --interactive
    # keeps interactive mode (and its tty requirements) active.
    options = _resolve(
        ["--test", "--interactive", "f"], tty=True, monkeypatch=monkeypatch
    )
    assert options.interactive is True

    with pytest.raises(FermError, match="not a tty"):
        _resolve(
            ["--test", "--interactive", "f"],
            tty=False,
            monkeypatch=monkeypatch,
        )


def test_def_is_evaluated_without_script_context(tmp_path: Path) -> None:
    # Perl evaluates --def inside GetOptions, before open_script: plain
    # values work, while script-context built-ins ($LINE, @glob, anything
    # reading the token stream) abort the run.
    from pyferm.cli import main

    conf = tmp_path / "t.ferm"
    conf.write_text("chain INPUT ACCEPT;\n")
    assert main(["--test", "--def", "$x=(1 2)", str(conf)]) == 0
    assert main(["--test", "--def", "$x=$LINE", str(conf)]) == 1
    assert main(["--test", "--def", "$x=@glob(x*)", str(conf)]) == 1


def test_setup_streams_without_shell_is_passthrough() -> None:
    lines_stream, restore = _setup_streams(Options(lines=True))
    assert lines_stream is sys.stdout
    restore()


def test_shell_redirect_keeps_script_stdout_clean(
    capfd: pytest.CaptureFixture[str],
) -> None:
    # Perl dups LINES from stdout and redirects STDOUT to STDERR under
    # --shell (:738-739): children (hooks, *-save tools) inherit fd 1 =
    # stderr, so their output cannot corrupt the generated script.
    lines_stream, restore = _setup_streams(Options(shell=True, lines=True))
    try:
        subprocess.run("echo child-noise", shell=True, check=False)
        lines_stream.write("script-line\n")
        lines_stream.flush()
    finally:
        restore()
    out, err = capfd.readouterr()
    assert "script-line" in out
    assert "child-noise" not in out
    assert "child-noise" in err
