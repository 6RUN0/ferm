"""Unit tests for :mod:`pyferm.cli` (option derivation and main-flow seams)."""

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from pyferm.cli import _build_parser, _resolve_options, _setup_streams
from pyferm.config import Options
from pyferm.errors import FermError

if TYPE_CHECKING:
    from pathlib import Path


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
    conf.write_text("chain INPUT ACCEPT;\n", encoding="utf-8")
    assert main(["--test", "--def", "$x=(1 2)", str(conf)]) == 0
    assert main(["--test", "--def", "$x=$LINE", str(conf)]) == 1
    assert main(["--test", "--def", "$x=@glob(x*)", str(conf)]) == 1


def test_invalid_domain_keeps_perl_blank_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # check_domain re-raises through error(): Perl's $@ keeps the die's
    # trailing newline and error() appends its own, so the oracle prints
    # a blank line after the message (found by the config fuzzer).
    from pyferm.cli import main

    conf = tmp_path / "t.ferm"
    conf.write_text(
        "domain p { table filter { chain INPUT { } } }\n", encoding="utf-8"
    )
    assert main(["--test", "--noexec", str(conf)]) == 1
    assert capsys.readouterr().err.endswith("Invalid domain 'p'\n\n")


def test_hooks_echo_under_lines_without_execution(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # @hook commands echo under --lines and are skipped under --noexec
    # (Perl :777-794); their status never feeds the rollback decision.
    from pyferm.cli import main

    conf = tmp_path / "t.ferm"
    conf.write_text(
        '@hook pre "echo pre-marker";\n'
        '@hook post "echo post-marker";\n'
        "chain INPUT ACCEPT;\n",
        encoding="utf-8",
    )
    assert main(["--test", str(conf)]) == 0
    out = capsys.readouterr().out
    assert "echo pre-marker" in out
    assert "echo post-marker" in out


def test_interactive_shell_emits_confirmation_block(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Under --shell the interactive safety net is woven into the emitted
    # script (Perl :806-813): a confirm prompt, a sleep, and one
    # *-restore line per domain reading the mktemp'd previous ruleset.
    # capfd, not capsys: the LINES sink dups fd 1 below sys.stdout.
    from pyferm.cli import main

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
    conf = tmp_path / "t.ferm"
    conf.write_text("chain INPUT ACCEPT;\n", encoding="utf-8")
    assert main(["--test", "--interactive", "--shell", str(conf)]) == 0
    out = capfd.readouterr().out
    assert "echo 'Please press Ctrl-C to confirm.'\n" in out
    assert "sleep 30\n" in out
    assert "iptables-restore <$ip_tmp\n" in out


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


def test_main_restores_streams_after_shell(
    capfd: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # After an in-process --shell run fd 1 must point at the original
    # stdout again (and the duplicated fd must be closed), or every
    # later write of the caller (and its children) lands on stderr.
    import os

    from pyferm.cli import main

    conf = tmp_path / "t.ferm"
    conf.write_text(
        "domain ip table filter chain INPUT ACCEPT;\n", encoding="utf-8"
    )
    assert main(["--shell", "--test", str(conf)]) == 0
    os.write(1, b"after-marker\n")
    assert "after-marker" in capfd.readouterr().out


def test_confirm_rules_timeout_interrupts_read() -> None:
    # PEP 475: a SIGALRM handler that returns normally makes os.read
    # restart transparently, so the alarm must abort the read by raising
    # (Perl's sysread returns on EINTR).  Run in a child process: with
    # the bug this blocks until the subprocess timeout kills it.
    code = (
        "import os, sys\n"
        "r, w = os.pipe()\n"
        "os.dup2(r, 0)\n"
        "from pyferm.cli import _confirm_rules\n"
        "from pyferm.config import Options\n"
        "ok = _confirm_rules(Options(interactive=True, timeout=1))\n"
        "sys.stdout.write('RESULT=%r' % ok)\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        encoding="utf-8",
        timeout=10,
        check=False,
    )
    assert "RESULT=False" in completed.stdout


def test_read_save_keeps_output_on_nonzero_exit(tmp_path: Path) -> None:
    # Perl reads the *-save pipe and never checks the exit status
    # (:950-955): a partial dump still becomes {previous}, keeping
    # @preserve and rollback working.
    from pyferm.cli import _make_io

    tool = tmp_path / "save-tool"
    tool.write_text("#!/bin/sh\necho '*filter'\nexit 1\n", encoding="utf-8")
    tool.chmod(0o755)
    _execute, _emit, read_save, _restore = _make_io(Options(), sys.stdout)
    assert read_save(str(tool)) == "*filter\n"


def test_read_save_unexecutable_tool_reads_empty() -> None:
    # Perl's pipe-open forks fine and the child's exec fails: the parent
    # reads EOF, so {previous} is set to the empty string, not unset.
    from pyferm.cli import _make_io

    _execute, _emit, read_save, _restore = _make_io(Options(), sys.stdout)
    assert read_save("/nonexistent/ferm-no-such-tool") == ""


def test_execute_exec_failure_is_fatal(
    capfd: pytest.CaptureFixture[str],
) -> None:
    # Perl system() execs a metachar-free command directly; when that
    # exec fails it prints 'failed to execute: ...' and exits 1 at once
    # (:2903-2905) -- no status bookkeeping, no rollback.
    from pyferm.cli import _make_io

    execute, _emit, _read, _restore = _make_io(Options(), sys.stdout)
    with pytest.raises(SystemExit) as excinfo:
        execute("/nonexistent/ferm-no-such-tool -A INPUT")
    assert excinfo.value.code == 1
    assert "failed to execute:" in capfd.readouterr().err


def test_execute_returns_status_of_plain_command() -> None:
    from pyferm.cli import _make_io

    execute, _emit, _read, _restore = _make_io(Options(), sys.stdout)
    assert execute("true") is None
    assert execute("false") == 1


HELP_SNIPPET = " --domain {ip|ip6} Handle only the specified domain"


def test_help_prints_full_options_block(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Perl's pod2usage(-exitstatus => 0) prints the whole OPTIONS table
    # from the POD to stdout (:666-668).
    from pyferm.cli import main

    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "-t, --timeout s" in out
    assert "--def '$name=v'" in out
    assert HELP_SNIPPET in out


def test_wrong_argument_count_prints_usage_to_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # pod2usage(-exitstatus => 1) writes to STDOUT too (status < 2).
    from pyferm.cli import main

    assert main([]) == 1
    captured = capsys.readouterr()
    assert HELP_SNIPPET in captured.out
    assert captured.err == ""
