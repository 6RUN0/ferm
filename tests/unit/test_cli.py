"""Unit tests for :mod:`pyferm.cli` (option derivation and main-flow seams)."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from typing import TYPE_CHECKING, cast

import pytest

from pyferm import etckeeper
from pyferm.backend.iptables import IptablesBackend
from pyferm.cli import (
    _build_parser,
    _main,
    _make_io,
    _resolve_options,
    _setup_streams,
    main,
)
from pyferm.config import Options
from pyferm.errors import FermError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path

    from pyferm.backend.base import (
        Backend,
        ExecuteCommand,
        LineEmitter,
        Rendered,
        RestoreDomain,
    )
    from pyferm.domains import DomainInfo, ShellSnapshot


def _resolve(
    argv: list[str], *, tty: bool, monkeypatch: pytest.MonkeyPatch
) -> Options:
    """Parse ``argv`` and derive options with stdin/stderr tty-ness forced."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: tty, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: tty, raising=False)
    return _resolve_options(_build_parser().parse_args(argv))


@pytest.fixture
def trivial_conf(tmp_path: Path) -> Path:
    """A minimal config: one ACCEPT rule in the builtin INPUT chain."""
    conf = tmp_path / "t.ferm"
    conf.write_text("chain INPUT ACCEPT;\n", encoding="utf-8")
    return conf


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


# -- argument validation ---------------------------------------------------
#
# The option-resolution guards (timeout shape, timeout-needs-interactive,
# --test-mock-previous shape, --def shape) had no negative coverage.


def test_timeout_must_be_an_integer(monkeypatch: pytest.MonkeyPatch) -> None:
    # --interactive keeps the earlier no-sense guard quiet so the shape
    # guard itself is exercised.
    with pytest.raises(FermError, match="invalid timeout"):
        _resolve(
            ["--interactive", "--timeout", "abc", "f"],
            tty=True,
            monkeypatch=monkeypatch,
        )


def test_timeout_guard_order_matches_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # oracle order (ferm:691-698): the no-sense guard fires BEFORE the
    # integer-shape guard, so a malformed timeout without --interactive
    # reports the missing mode, not the shape.
    with pytest.raises(FermError, match="no sense without interactive"):
        _resolve(["--timeout", "abc", "f"], tty=True, monkeypatch=monkeypatch)


def test_timeout_requires_interactive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A well-formed timeout without --interactive is a usage error.
    with pytest.raises(FermError, match="no sense without interactive"):
        _resolve(["--timeout", "5", "f"], tty=True, monkeypatch=monkeypatch)


def test_invalid_mock_previous_spec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FermError, match="Invalid --test-mock-previous"):
        _resolve(
            ["--test-mock-previous=garbage", "f"],
            tty=True,
            monkeypatch=monkeypatch,
        )


def test_invalid_def_specification(
    trivial_conf: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--test", "--def", "noequalssign", str(trivial_conf)]) == 1
    assert "Invalid --def specification" in capsys.readouterr().err


def test_extra_tokens_after_def(
    trivial_conf: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--test", "--def", "$x=1 2", str(trivial_conf)]) == 1
    assert "Extra tokens after --def" in capsys.readouterr().err


def test_def_is_evaluated_without_script_context(trivial_conf: Path) -> None:
    # Perl evaluates --def inside GetOptions, before open_script: plain
    # values work, while script-context built-ins ($LINE, @glob, anything
    # reading the token stream) abort the run.
    assert main(["--test", "--def", "$x=(1 2)", str(trivial_conf)]) == 0
    assert main(["--test", "--def", "$x=$LINE", str(trivial_conf)]) == 1
    assert main(["--test", "--def", "$x=@glob(x*)", str(trivial_conf)]) == 1


def test_invalid_domain_keeps_perl_blank_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # check_domain re-raises through error(): Perl's $@ keeps the die's
    # trailing newline and error() appends its own, so the oracle prints
    # a blank line after the message (found by the config fuzzer).
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
    trivial_conf: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Under --shell the interactive safety net is woven into the emitted
    # script (Perl :806-813): a confirm prompt, a sleep, and one
    # *-restore line per domain reading the mktemp'd previous ruleset.
    # capfd, not capsys: the LINES sink dups fd 1 below sys.stdout.
    #
    # The isatty patch stays inline (not a fixture): capfd swaps sys.stderr
    # for a fresh object between fixture setup and this call phase, so a
    # fixture-time patch would land on the pre-swap object and never apply.
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
    assert main(["--test", "--interactive", "--shell", str(trivial_conf)]) == 0
    out = capfd.readouterr().out
    assert "echo 'Please press Ctrl-C to confirm.'\n" in out
    assert "sleep 30\n" in out
    assert "iptables-restore <$ip_tmp\n" in out


def test_interactive_shell_nft_emits_anti_lockout_net(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # finding C2: under --nft the anti-lockout net was silently absent.  The
    # nft snapshot must now appear in the emitted script: a `list table` save
    # before, and a `delete table` + `nft -f` restore after the sleep.
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
    conf = tmp_path / "t.ferm"
    conf.write_text(
        "domain ip table filter { chain INPUT ACCEPT; }\n", encoding="utf-8"
    )
    assert (
        main(["--test", "--nft", "--interactive", "--shell", str(conf)]) == 0
    )
    out = capfd.readouterr().out
    assert "nft list table ip ferm >$ip_tmp 2>/dev/null || true\n" in out
    assert "nft delete table ip ferm 2>/dev/null || true\n" in out
    assert "nft -f $ip_tmp\n" in out
    # The nft restore commands above are silenced (`2>/dev/null`), so a
    # timed-out admin would otherwise be rolled back without a word.  The
    # generated script must announce the rollback on stderr after the
    # restores -- parity with the live path's "Firewall rules rolled back."
    assert out.index(
        "ferm: rolled back to the previous firewall rules."
    ) > out.index("nft -f $ip_tmp\n")
    assert ">&2" in out[out.index("ferm: rolled back") :]


def test_interactive_shell_iptables_has_no_rollback_notice(
    trivial_conf: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The notice is nft-only: the x_tables --shell script must stay
    # byte-identical to the Perl oracle (reference/src/ferm:803-814), which
    # emits no rollback announcement.
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
    assert main(["--test", "--interactive", "--shell", str(trivial_conf)]) == 0
    out = capfd.readouterr().out
    assert "rolled back" not in out


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
    tool = tmp_path / "save-tool"
    tool.write_text("#!/bin/sh\necho '*filter'\nexit 1\n", encoding="utf-8")
    tool.chmod(0o755)
    io = _make_io(Options(), sys.stdout)
    assert io.read_save(str(tool)) == "*filter\n"


def test_read_save_unexecutable_tool_reads_empty() -> None:
    # Perl's pipe-open forks fine and the child's exec fails: the parent
    # reads EOF, so {previous} is set to the empty string, not unset.
    io = _make_io(Options(), sys.stdout)
    assert io.read_save("/nonexistent/ferm-no-such-tool") == ""


def test_execute_exec_failure_is_fatal(
    capfd: pytest.CaptureFixture[str],
) -> None:
    # Perl system() execs a metachar-free command directly; when that
    # exec fails it prints 'failed to execute: ...' and exits 1 at once
    # (:2903-2905) -- no status bookkeeping, no rollback.
    io = _make_io(Options(), sys.stdout)
    with pytest.raises(SystemExit) as excinfo:
        io.execute("/nonexistent/ferm-no-such-tool -A INPUT")
    assert excinfo.value.code == 1
    assert "failed to execute:" in capfd.readouterr().err


def test_execute_returns_status_of_plain_command() -> None:
    io = _make_io(Options(), sys.stdout)
    assert io.execute("true") is None
    assert io.execute("false") == 1


def test_execute_signal_death_reports_and_returns_one(
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Perl maps a signal-killed child ($? & 0x7f) to 'child died with
    # signal N' and a status of 1 (:2906-2908); subprocess models the
    # same child as a negative returncode.
    monkeypatch.setattr(subprocess, "run", _RunRecorder(returncode=-9))
    io = _make_io(Options(), sys.stdout)
    assert io.execute("iptables -A INPUT") == 1
    assert capfd.readouterr().err == "child died with signal 9\n"


def test_execute_routes_metachar_commands_through_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Perl system() (:2901) hands a metachar command to /bin/sh verbatim
    # but execs a plain one directly: the shell branch must keep the raw
    # string, the direct branch must split the argv.
    recorder = _install_run(monkeypatch, returncode=0)
    io = _make_io(Options(), sys.stdout)
    assert io.execute("a | b") is None
    assert io.execute("iptables -L") is None
    (piped_argv,), piped_kwargs = recorder.calls[0]
    (plain_argv,), plain_kwargs = recorder.calls[1]
    assert piped_argv == "a | b"
    assert piped_kwargs["shell"] is True
    assert plain_argv == ["iptables", "-L"]
    assert plain_kwargs["shell"] is False


HELP_SNIPPET = " --domain {ip|ip6} Handle only the specified domain"


def test_help_prints_full_options_block(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Perl's pod2usage(-exitstatus => 0) prints the whole OPTIONS table
    # from the POD to stdout (:666-668).
    assert main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "-t, --timeout s" in out
    assert "--def '$name=v'" in out
    assert HELP_SNIPPET in out


def test_wrong_argument_count_prints_usage_to_stdout(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # pod2usage(-exitstatus => 1) writes to STDOUT too (status < 2).
    assert main([]) == 1
    captured = capsys.readouterr()
    assert HELP_SNIPPET in captured.out
    assert captured.err == ""


def test_version_prints_perl_banner(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Perl printversion: the banner is verbatim oracle output (stdout,
    # exit 0, nothing else runs), so it is pinned byte-exactly.
    from pyferm import __version__

    assert main(["--version"]) == 0
    assert capsys.readouterr().out == (
        f"ferm {__version__}\n"
        "Copyright 2001-2021 Max Kellermann, Auke Kok\n"
        "This program is free software released under GPLv2.\n"
        "See the included COPYING file for license details.\n"
    )


def test_list_modules_exits_zero_without_file(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--list-modules"]) == 0
    out = capsys.readouterr().out
    assert "protocol modules (ip/ip6):" in out


def test_describe_unknown_name_exits_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--describe", "no-such-xyzzy"]) == 1
    assert "unknown name" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["--list-modules", "--describe", "tcp"],
        ["--list-modules", "--lint"],
        ["--describe", "tcp", "--noexec"],
        ["--describe", "tcp", "--lines"],
        ["--describe", "tcp", "--remote"],
        ["--describe", "tcp", "--def", "$x=1"],
        ["--describe", "tcp", "--domain", "ip"],
        ["--describe", "tcp", "--slow"],
    ],
)
def test_introspection_rejects_other_switches(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(argv) == 1
    assert "cannot be combined" in capsys.readouterr().err


def test_introspection_rejects_input_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    conf = tmp_path / "f.ferm"
    conf.write_text("", encoding="utf-8")
    assert main(["--list-modules", str(conf)]) == 1
    assert "takes no input file" in capsys.readouterr().err


def test_help_wins_over_introspection(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--help", "--list-modules"]) == 0
    assert "Usage:" in capsys.readouterr().out


def test_rollback_wins_over_introspection(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The rollback subcommand is matched before argparse, so it never
    # reaches introspection dispatch; its own subparser has no
    # --list-modules, so argparse rejects it as an unrecognized
    # argument and exits 2 -- it must not print the module catalogue.
    with pytest.raises(SystemExit) as excinfo:
        main(["rollback", "--list-modules"])
    assert excinfo.value.code != 0
    assert "protocol modules" not in capsys.readouterr().out


def test_rollback_all_restores_enabled_domains_and_exits(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Perl rollback (:3147): every *active* family is restored, the
    # closing message goes to stderr and the process exits 1 -- the
    # admin must learn the new rules did NOT stay applied.
    from pyferm.backend.base import Backend
    from pyferm.cli import _rollback_all
    from pyferm.domains import DomainInfo as RealDomainInfo
    from pyferm.domains import Family

    class _RecordingBackend(Backend):
        def __init__(self) -> None:
            self.calls: list[tuple[object, ...]] = []

        def tool_names(self, domain: str) -> dict[str, str]:
            return {"tables": domain + "tables"}

        def render(
            self, domain: str, domain_info: DomainInfo, options: Options
        ) -> Rendered:
            raise NotImplementedError

        def commit(
            self,
            domain: str,
            domain_info: DomainInfo,
            rendered: Rendered,
            options: Options,
            *,
            execute: ExecuteCommand,
            emit_line: LineEmitter,
            restore: RestoreDomain,
        ) -> int | None:
            raise NotImplementedError

        def rollback(
            self,
            domain: str,
            domain_info: DomainInfo,
            options: Options,
            *,
            execute: ExecuteCommand,
            restore: RestoreDomain,
        ) -> None:
            self.calls.append((domain, domain_info, options, execute, restore))

        def capture_previous(
            self,
            domain: str,
            domain_info: DomainInfo,
            options: Options,
            *,
            execute: ExecuteCommand,
            read_save: object,
            capture: object,
        ) -> None:
            raise NotImplementedError

        def read_previous(
            self, lines: Iterable[str], domain_info: DomainInfo
        ) -> str:
            raise NotImplementedError

        def shell_snapshot(
            self, domain: str, domain_info: DomainInfo
        ) -> ShellSnapshot | None:
            del domain, domain_info
            return None

    backend = _RecordingBackend()
    domains = {
        Family.IP6: RealDomainInfo(enabled=True),
        Family.IP: RealDomainInfo(enabled=True),
        Family.ARP: RealDomainInfo(enabled=False),
    }
    options = Options()

    def execute(_command: str) -> int | None:
        return None

    def restore(_domain_info: DomainInfo, _text: str) -> None:
        return None

    with pytest.raises(SystemExit) as excinfo:
        _rollback_all(
            domains, options, backend, execute=execute, restore=restore
        )
    assert excinfo.value.code == 1
    # Deterministic (sorted) order; the unused family is left alone.
    assert [call[0] for call in backend.calls] == ["ip", "ip6"]
    # Each family gets its own state and the caller's I/O seams verbatim.
    assert backend.calls[0][1:] == (
        domains[Family.IP],
        options,
        execute,
        restore,
    )
    assert capsys.readouterr().err.endswith("Firewall rules rolled back.\n")


class _PipeStdin:
    """A minimal stdin stand-in exposing the pipe's read end."""

    def __init__(self, fd: int) -> None:
        self._fd = fd

    def fileno(self) -> int:
        return self._fd


def _confirm_with_input(data: bytes, monkeypatch: pytest.MonkeyPatch) -> bool:
    """Run ``_confirm_rules`` with ``data`` waiting on a pipe stdin."""
    from pyferm.cli import _confirm_rules

    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, data)
        os.close(write_fd)
        monkeypatch.setattr(sys, "stdin", _PipeStdin(read_fd))
        return _confirm_rules(Options())
    finally:
        os.close(read_fd)


def test_confirm_rules_requires_exact_yes(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    # Perl confirm_rules: sysread grabs 3 bytes and only the literal
    # 'yes' confirms; anything else -- including EOF (a closed stdin) --
    # must report "not confirmed" so the caller rolls back.
    assert _confirm_with_input(b"yes\n", monkeypatch) is True
    assert "type 'yes' to confirm" in capfd.readouterr().err
    assert _confirm_with_input(b"no\n", monkeypatch) is False
    assert _confirm_with_input(b"", monkeypatch) is False


# --- latin-1 byte round-trips through the CLI entry point ------------------

_BYTE_CONFIG = (
    b'table filter chain INPUT mod comment comment "h\xfc" ACCEPT;\n'
)


def test_cli_file_round_trips_high_bytes(tmp_path: Path) -> None:
    # Byte 0xfc in the config must survive end to end on stdout: latin-1
    # preserves the one-byte-per-char contract; utf-8 would encode it as
    # two bytes (0xc3 0xbc), breaking the verbatim round-trip.
    config = tmp_path / "bytes.ferm"
    config.write_bytes(_BYTE_CONFIG)
    result = subprocess.run(
        [sys.executable, "-m", "pyferm", "--test", str(config)],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    # fast mode: bare comment value is emitted unquoted; the byte 0xfc must
    # appear verbatim rather than as the utf-8 two-byte sequence 0xc3 0xbc
    assert b"h\xfc" in result.stdout
    assert b"h\xc3\xbc" not in result.stdout


def test_cli_stdin_round_trips_high_bytes() -> None:
    # Same round-trip via stdin ("-") so the stdin reconfigure path is hit.
    result = subprocess.run(
        [sys.executable, "-m", "pyferm", "--test", "-"],
        input=_BYTE_CONFIG,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert b"h\xfc" in result.stdout
    assert b"h\xc3\xbc" not in result.stdout


def test_cli_error_with_non_latin1_filename_does_not_crash() -> None:
    # argv decodes to U+20AC; the FermError text lands on the
    # backslashreplace stderr instead of raising UnicodeEncodeError
    result = subprocess.run(
        [sys.executable, "-m", "pyferm", "--test", "missing-\u20ac.ferm"],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1
    assert b"Traceback" not in result.stderr
    assert result.stderr  # a usable error message was printed


def test_cli_def_high_codepoint_is_byte_faithful(tmp_path: Path) -> None:
    # argv is the one input boundary Python decodes (utf-8 + surrogateescape)
    # before ferm runs, so a --def value with a codepoint above U+00FF (here
    # U+20AC, carried on the wire as the utf-8 bytes 0xe2 0x82 0xac) used to
    # reach iptables-restore's save.encode("latin-1") and raise a raw
    # UnicodeEncodeError -- while the same bytes in the config file round-trip
    # cleanly. Re-reading argv as raw bytes makes the two boundaries agree.
    config = tmp_path / "def.ferm"
    config.write_text(
        "table filter chain INPUT mod comment comment $x ACCEPT;\n",
        encoding="latin-1",
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyferm",
            "--test",
            "--def",
            '$x="€"',
            str(config),
        ],
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert b"Traceback" not in result.stderr
    # byte-faithful: the euro's three utf-8 bytes appear verbatim, exactly as
    # if they had been written into the config file and read back latin-1 --
    # not silently backslash-escaped to the literal text "€"
    assert b"\xe2\x82\xac" in result.stdout
    assert b"\\u20ac" not in result.stdout


# --- --plan / --plan-format flag plumbing ---------------------------------


def _resolve_plan(argv: list[str]) -> Options:
    """Parse ``argv`` and derive options (plan tests need no tty patching)."""
    args = _build_parser().parse_args(argv)
    return _resolve_options(args)


def test_plan_flag_defaults_off() -> None:
    opts = _resolve_plan(["a.ferm"])
    assert opts.plan is False
    assert opts.plan_format == "structured"


def test_plan_flag_sets_plan() -> None:
    opts = _resolve_plan(["--plan", "a.ferm"])
    assert opts.plan is True
    assert opts.plan_format == "structured"


def test_plan_format_diff() -> None:
    opts = _resolve_plan(["--plan", "--plan-format", "diff", "a.ferm"])
    assert opts.plan_format == "diff"


def test_plan_format_without_plan_is_error() -> None:
    with pytest.raises(FermError, match="plan-format"):
        _resolve_plan(["--plan-format", "diff", "a.ferm"])


# --- --no-etckeeper flag plumbing -----------------------------------------


def test_etckeeper_defaults_on() -> None:
    opts = _resolve_plan(["a.ferm"])
    assert opts.etckeeper is True


def test_no_etckeeper_flag_disables() -> None:
    opts = _resolve_plan(["--no-etckeeper", "a.ferm"])
    assert opts.etckeeper is False


# --- backend selection ----------------------------------------------------


def test_select_backend_defaults_to_iptables() -> None:
    from pyferm.backend.iptables import IptablesBackend
    from pyferm.cli import _select_backend

    assert isinstance(_select_backend(Options()), IptablesBackend)


def test_select_backend_nft_opt_in() -> None:
    from pyferm.backend.nft import NftBackend
    from pyferm.cli import _select_backend

    assert isinstance(_select_backend(Options(nft=True)), NftBackend)


def test_main_nft_end_to_end_resolves_and_emits(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = tmp_path / "e.ferm"
    cfg.write_text(
        "domain ip table filter chain INPUT { proto tcp dport 22 ACCEPT; }\n",
        encoding="utf-8",
    )
    rc = main(["--nft", "--test", "--noexec", "--lines", str(cfg)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "add table ip ferm" in out
    assert "tcp dport 22 accept" in out


def test_nft_with_nolegacy_is_noop(tmp_path: Path) -> None:
    cfg = tmp_path / "e.ferm"
    cfg.write_text(
        "domain ip table filter chain INPUT { ACCEPT; }\n",
        encoding="utf-8",
    )
    argv = ["--nft", "--nolegacy", "--test", "--noexec", "--lines", str(cfg)]
    assert main(argv) == 0


# --- nft cli applier and capture seams ------------------------------------


class _RunRecorder:
    """A ``subprocess.run`` stand-in recording its args and faking a result."""

    def __init__(
        self,
        *,
        returncode: int = 0,
        returncodes: Sequence[int] | None = None,
        stdout: str = "",
        stderr: str | bytes = "",
        raises: type[OSError] | None = None,
    ) -> None:
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self._returncode = returncode
        # Per-call codes (popped in order) model the nft applier's two
        # subprocesses: a `-c` pre-check followed by the real `-f -` apply.
        self._returncodes = (
            list(returncodes) if returncodes is not None else None
        )
        self._stdout = stdout
        self._stderr = stderr
        self._raises = raises

    def __call__(
        self, command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[object]:
        self.calls.append(((command,), kwargs))
        if self._raises is not None:
            raise self._raises("boom")
        if self._returncodes is not None:
            returncode = self._returncodes.pop(0)
        else:
            returncode = self._returncode
        return subprocess.CompletedProcess(
            command, returncode, stdout=self._stdout, stderr=self._stderr
        )


def _install_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    returncode: int = 0,
    returncodes: Sequence[int] | None = None,
    stdout: str = "",
    stderr: str | bytes = "",
    raises: type[OSError] | None = None,
) -> _RunRecorder:
    """Install a ``_RunRecorder`` on ``subprocess.run`` and return it."""
    recorder = _RunRecorder(
        returncode=returncode,
        returncodes=returncodes,
        stdout=stdout,
        stderr=stderr,
        raises=raises,
    )
    monkeypatch.setattr(subprocess, "run", recorder)
    return recorder


def _nft_domain_info() -> DomainInfo:
    """A ``DomainInfo`` whose nft tool resolves to a fixed bare path."""
    from pyferm.backend.nft import TOOL_NFT
    from pyferm.domains import DomainInfo as RealDomainInfo

    return RealDomainInfo(enabled=True, tools={TOOL_NFT: "nft"})


def test_make_nft_restore_checks_then_applies_as_latin1_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The applier first validates the ruleset with `nft -c -f -` (a netlink
    # check that touches nothing), then installs it with `nft -f -`.  Both
    # runs are fed the rendered save as one-byte-per-char latin-1 on stdin.
    from pyferm.cli import _make_nft_restore

    recorder = _install_run(monkeypatch, returncode=0)
    restore = _make_nft_restore(Options(nft=True))
    restore(_nft_domain_info(), "add table ip ferm\nh\xfc\n")
    assert [call[0][0] for call in recorder.calls] == [
        ["nft", "-c", "-f", "-"],
        ["nft", "-f", "-"],
    ]
    for (_argv, *_rest), kwargs in recorder.calls:
        assert kwargs["input"] == b"add table ip ferm\nh\xfc\n"


def test_make_nft_restore_failed_check_surfaces_nft_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A ruleset nft -c rejects aborts BEFORE the apply, surfacing nft's own
    # stderr diagnostic (early diagnostics) instead of a generic failure, and
    # never reaches `nft -f -` -- so the kernel is untouched.
    from pyferm.cli import _make_nft_restore

    recorder = _install_run(
        monkeypatch,
        returncode=1,
        stderr=b"Error: syntax error, unexpected newline\n",
    )
    restore = _make_nft_restore(Options(nft=True))
    with pytest.raises(FermError, match="syntax error, unexpected newline"):
        restore(_nft_domain_info(), "bogus\n")
    assert [call[0][0] for call in recorder.calls] == [
        ["nft", "-c", "-f", "-"],
    ]


def test_make_nft_restore_failed_check_without_stderr_is_generic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A non-zero `-c` with empty stderr still aborts with a FermError naming
    # the check, never a silent pass to the apply.
    from pyferm.cli import _make_nft_restore

    monkeypatch.setattr(
        subprocess, "run", _RunRecorder(returncode=1, stderr=b"")
    )
    restore = _make_nft_restore(Options(nft=True))
    with pytest.raises(FermError, match="Failed to run nft"):
        restore(_nft_domain_info(), "add table ip ferm\n")


def test_make_nft_restore_oserror_raises_ferm_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An unspawnable nft (OSError from subprocess.run) becomes a FermError,
    # the rollback trigger -- the nft analogue of restore_domain.
    from pyferm.cli import _make_nft_restore

    monkeypatch.setattr(
        subprocess, "run", _RunRecorder(raises=FileNotFoundError)
    )
    restore = _make_nft_restore(Options(nft=True))
    with pytest.raises(FermError, match="Failed to run nft"):
        restore(_nft_domain_info(), "add table ip ferm\n")


def test_make_nft_restore_apply_failure_after_check_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The apply guard survives the pre-check: a `-c` that passes (0) followed
    # by an `-f -` that fails (1) is still a rollback-triggering FermError.
    from pyferm.cli import _make_nft_restore

    recorder = _install_run(monkeypatch, returncodes=[0, 1])
    restore = _make_nft_restore(Options(nft=True))
    with pytest.raises(FermError, match="Failed to run nft"):
        restore(_nft_domain_info(), "add table ip ferm\n")
    assert [call[0][0] for call in recorder.calls] == [
        ["nft", "-c", "-f", "-"],
        ["nft", "-f", "-"],
    ]


def test_nft_subprocesses_pin_utc_timezone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # nft converts a meta hour/meta time literal by the process TZ on both
    # parse and print, so every nft subprocess ferm spawns is pinned to UTC:
    # the emitted clock keeps its xt (UTC) meaning and --plan stays diff-free
    # on any host.  All three spawn sites must carry env["TZ"] == "UTC" --
    # the apply path's `nft -c` and `nft -f -`, and the backend-agnostic
    # capture() snapshot closure whose body names no "nft" string.
    from pyferm.cli import _make_nft_restore

    recorder = _install_run(monkeypatch, returncode=0)
    restore = _make_nft_restore(Options(nft=True))
    restore(_nft_domain_info(), "add table ip ferm\n")
    io = _make_io(Options(nft=True, plan=True), sys.stdout)
    io.capture("nft list table ip ferm")
    commands = [call[0][0] for call in recorder.calls]
    assert ["nft", "-c", "-f", "-"] in commands
    assert ["nft", "-f", "-"] in commands
    assert ["nft", "list", "table", "ip", "ferm"] in commands
    for _args, kwargs in recorder.calls:
        env = kwargs["env"]
        assert isinstance(env, dict)
        assert env["TZ"] == "UTC"


def test_validate_desired_nft_skips_under_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # --test substitutes a fake nft path and must never spawn the real tool;
    # the --plan pre-validation is therefore a no-op in test mode.
    from pyferm.cli import _validate_desired_nft

    recorder = _install_run(monkeypatch, returncode=0)
    _validate_desired_nft(Options(nft=True, test=True), "nft", "add table\n")
    assert recorder.calls == []


def test_validate_desired_nft_runs_check_when_not_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # In a real run the desired script is validated with `nft -c -f -` before
    # the plan is trusted -- an un-appliable ruleset must not be advertised.
    from pyferm.cli import _validate_desired_nft

    recorder = _install_run(monkeypatch, returncode=0)
    _validate_desired_nft(Options(nft=True), "nft", "add table ip ferm\n")
    assert [call[0][0] for call in recorder.calls] == [
        ["nft", "-c", "-f", "-"]
    ]


def test_validate_desired_nft_rejected_surfaces_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A desired ruleset nft rejects (e.g. arp+tcp) aborts the plan with nft's
    # own diagnostic, so an un-appliable plan exits 1 instead of exit 2.
    from pyferm.cli import _validate_desired_nft

    _install_run(
        monkeypatch,
        returncode=1,
        stderr=b"Error: conflicting protocols specified: arp vs. tcp\n",
    )
    with pytest.raises(FermError, match="conflicting protocols"):
        _validate_desired_nft(Options(nft=True), "nft", "bad\n")


def test_restore_dispatch_routes_to_nft_applier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With --nft the restore closure routes to the nft applier: it spawns
    # `nft -c -f -` then `nft -f -`, never an iptables-restore call.
    recorder = _install_run(monkeypatch, returncode=0)
    io = _make_io(Options(nft=True), sys.stdout)
    io.restore(_nft_domain_info(), "add table ip ferm\n")
    assert [call[0][0] for call in recorder.calls] == [
        ["nft", "-c", "-f", "-"],
        ["nft", "-f", "-"],
    ]


def test_restore_dispatch_default_skips_nft_applier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The default (iptables) restore routes to restore_domain, never the
    # nft applier; we observe that restore_domain is the call target.
    from pyferm import cli

    calls: list[tuple[DomainInfo, str, Options]] = []

    def fake_restore_domain(
        domain_info: DomainInfo, save: str, options: Options
    ) -> None:
        calls.append((domain_info, save, options))

    monkeypatch.setattr(cli, "restore_domain", fake_restore_domain)
    nft_called = False

    def fail_run(*_args: object, **_kwargs: object) -> object:
        nonlocal nft_called
        nft_called = True
        raise AssertionError("nft applier must not run on the default path")

    monkeypatch.setattr(subprocess, "run", fail_run)
    options = Options()
    io = _make_io(options, sys.stdout)
    domain_info = _nft_domain_info()
    io.restore(domain_info, "*filter\n")
    assert calls == [(domain_info, "*filter\n", options)]
    assert nft_called is False


def test_capture_noexec_returns_none_without_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Under --noexec capture snapshots nothing and never spawns a child.
    def fail_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("capture must not spawn under --noexec")

    monkeypatch.setattr(subprocess, "run", fail_run)
    io = _make_io(Options(noexec=True), sys.stdout)
    assert io.capture("nft list ruleset") is None


def test_capture_oserror_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # finding C3: an unspawnable snapshot tool (OSError) must NOT collapse to
    # "no previous table" -- that would let the nft rollback delete an
    # existing table.  It aborts before any kernel change instead.
    monkeypatch.setattr(
        subprocess, "run", _RunRecorder(raises=FileNotFoundError)
    )
    io = _make_io(Options(), sys.stdout)
    with pytest.raises(FermError, match="failed to snapshot for rollback"):
        io.capture("nft list ruleset")


def test_capture_returns_stdout_or_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Non-empty stdout is the snapshot; empty stdout (exit 0) collapses to
    # None, splitting the command on whitespace for the child.
    recorder = _install_run(monkeypatch, returncode=0, stdout="X")
    io = _make_io(Options(), sys.stdout)
    assert io.capture("nft list ruleset") == "X"
    assert recorder.calls[0][0][0] == ["nft", "list", "ruleset"]

    monkeypatch.setattr(
        subprocess, "run", _RunRecorder(returncode=0, stdout="")
    )
    io2 = _make_io(Options(), sys.stdout)
    assert io2.capture("nft list ruleset") is None


def test_capture_absent_table_is_first_run_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # finding C3: a genuinely-absent table (nft exits 1 with ENOECT on
    # stderr) is the legitimate first run -> None, so rollback may delete
    # ferm's own freshly-created table.
    monkeypatch.setattr(
        subprocess,
        "run",
        _RunRecorder(
            returncode=1, stdout="", stderr="Error: No such file or directory"
        ),
    )
    io = _make_io(Options(), sys.stdout)
    assert io.capture("nft list table ip ferm") is None


def test_capture_genuine_failure_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # finding C3: a non-ENOENT failure (exit 1 with some other error) must
    # NOT masquerade as a first run -- it aborts so the destructive rollback
    # never deletes an existing populated table on a transient capture error.
    monkeypatch.setattr(
        subprocess,
        "run",
        _RunRecorder(
            returncode=1, stdout="", stderr="Error: Operation not permitted"
        ),
    )
    io = _make_io(Options(), sys.stdout)
    with pytest.raises(FermError, match="Operation not permitted"):
        io.capture("nft list table ip ferm")


def test_read_save_strict_under_plan_raises_on_missing_tool() -> None:
    # Under --plan a spawn failure must raise FermError rather than silently
    # returning empty: an empty current ruleset would under-count removals
    # and produce a falsely-clean plan.
    options = Options(plan=True)
    # local name avoids shadowing the `io` stdlib module used just above
    bound_io = _make_io(options, io.StringIO())
    with pytest.raises(FermError, match="current ruleset"):
        bound_io.read_save("/nonexistent/iptables-save")


def test_read_save_lenient_without_plan_returns_empty() -> None:
    # Outside --plan the Perl pipe-open semantics are preserved: an
    # unspawnable tool returns the empty string rather than aborting.
    options = Options(plan=False)
    # local name avoids shadowing the `io` stdlib module used just above
    bound_io = _make_io(options, io.StringIO())
    assert bound_io.read_save("/nonexistent/iptables-save") == ""


# ---------------------------------------------------------------------------
# --plan integration tests
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


_PREV = """\
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""


def test_plan_no_change_exit_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prev = _write(tmp_path, "prev.save", _PREV)
    cfg = _write(
        tmp_path,
        "c.ferm",
        "domain ip table filter chain INPUT proto tcp dport 22 ACCEPT;",
    )
    code = main(
        [
            "--plan",
            "--test",
            f"--test-mock-previous=ip={prev}",
            str(cfg),
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "No changes" in out


def test_plan_with_change_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prev = _write(tmp_path, "prev.save", _PREV)
    cfg = _write(
        tmp_path,
        "c.ferm",
        "domain ip table filter chain INPUT proto tcp dport 80 ACCEPT;",
    )
    code = main(
        [
            "--plan",
            "--test",
            f"--test-mock-previous=ip={prev}",
            str(cfg),
        ]
    )
    out = capsys.readouterr().out
    assert code == 2
    assert "+ -p tcp --dport 80 -j ACCEPT" in out
    assert "- -p tcp --dport 22 -j ACCEPT" in out


def test_plan_runs_no_hooks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prev = _write(tmp_path, "prev.save", _PREV)
    # a hook that would print if run; under --plan it must not execute
    cfg = _write(
        tmp_path,
        "c.ferm",
        '@hook pre "echo HOOK_RAN";\n'
        "domain ip table filter chain INPUT proto tcp dport 22 ACCEPT;",
    )
    code = main(
        ["--plan", "--test", f"--test-mock-previous=ip={prev}", str(cfg)]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "HOOK_RAN" not in out


# --- nft --plan wiring -----------------------------------------------------


def test_plan_nft_no_longer_raises() -> None:
    # The early --plan --nft reject is lifted; the combination is now valid.
    opts = _resolve_plan(["--plan", "--nft", "a.ferm"])
    assert opts.plan is True
    assert opts.nft is True


def test_plan_nft_noflush_raises() -> None:
    # --plan --nft --noflush is fail-closed until the append-only model is
    # implemented; mixing it silently would produce a wrong plan.
    with pytest.raises(FermError, match="noflush"):
        _resolve_plan(["--plan", "--nft", "--noflush", "a.ferm"])


def test_plan_noflush_iptables_still_works() -> None:
    # The noflush guard is nft-only; iptables --plan --noflush is unaffected.
    opts = _resolve_plan(["--plan", "--noflush", "a.ferm"])
    assert opts.noflush is True


def test_capture_not_short_circuited_under_plan_noexec() -> None:
    # Under plan=True + noexec=True, capture() must NOT return None early --
    # it proceeds to spawn so the nft snapshot can be read.  Verify via a
    # non-existent command: the strict FermError path fires, not silent None.
    io = _make_io(Options(plan=True, noexec=True), sys.stdout)
    with pytest.raises(FermError, match="failed to snapshot"):
        io.capture("__no_such_binary_ferm_test__")


def test_capture_still_short_circuits_when_noexec_no_plan() -> None:
    # Without plan, noexec=True still returns None immediately (no spawn).
    io = _make_io(Options(plan=False, noexec=True), sys.stdout)
    result = io.capture("__no_such_binary_ferm_test__")
    assert result is None


def test_run_plan_nft_render_error_propagates() -> None:
    # A FermError from backend.render() (e.g. @preserve unsupported under nft)
    # must propagate out of _run_plan uncaught so main() exits 1, not 0 or 2.
    from unittest.mock import MagicMock

    from pyferm.cli import _run_plan
    from pyferm.domains import DomainInfo, Family

    domain_info = DomainInfo(enabled=True, tools={})
    domains = {Family.IP: domain_info}

    backend = MagicMock()
    backend.render.side_effect = FermError("@preserve not yet supported")

    with pytest.raises(FermError, match="preserve"):
        _run_plan(domains, Options(nft=True), backend)


def test_build_plan_validate_false_skips_nft_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The commit-message path builds the plan after the rules are applied, so
    # it passes validate=False to skip the nft -c pre-check (a second check is
    # pointless and could raise post-apply).  --plan keeps validate=True.
    from unittest.mock import MagicMock

    import pyferm.cli as cli_mod
    from pyferm.backend.nft import TOOL_NFT
    from pyferm.cli import build_plan
    from pyferm.domains import DomainInfo, Family

    calls: list[object] = []
    monkeypatch.setattr(
        cli_mod,
        "_validate_desired_nft",
        lambda *args, **_kwargs: calls.append(args),
    )

    domain_info = DomainInfo(enabled=True, tools={TOOL_NFT: "nft"})
    rendered = MagicMock()
    rendered.save = ""
    backend = MagicMock()
    backend.render.return_value = rendered

    build_plan(
        {Family.IP: domain_info}, Options(nft=True), backend, validate=False
    )
    assert calls == []

    build_plan(
        {Family.IP: domain_info}, Options(nft=True), backend, validate=True
    )
    assert len(calls) == 1


def test_full_reload_flag_sets_option() -> None:
    from pyferm.cli import _build_parser, _resolve_options

    args = _build_parser().parse_args(["--nft", "--full-reload", "f.ferm"])
    options = _resolve_options(args)
    assert options.full_reload is True


def test_full_reload_without_nft_is_rejected() -> None:
    import pytest

    from pyferm.cli import _build_parser, _resolve_options
    from pyferm.errors import FermError

    args = _build_parser().parse_args(["--full-reload", "f.ferm"])
    with pytest.raises(FermError, match="full-reload"):
        _resolve_options(args)


def test_full_reload_defaults_false() -> None:
    from pyferm.cli import _build_parser, _resolve_options

    args = _build_parser().parse_args(["--nft", "f.ferm"])
    assert _resolve_options(args).full_reload is False


# --- etckeeper commit hook -------------------------------------------------


class _CommitSpy:
    """Capture the message passed to ``etckeeper.commit``."""

    def __init__(self) -> None:
        self.messages: list[str] = []

    def __call__(self, message: str) -> None:
        self.messages.append(message)


def _install_etckeeper(
    monkeypatch: pytest.MonkeyPatch,
    *,
    found: bool = True,
    dirty: bool = True,
) -> _CommitSpy:
    """Mock the etckeeper seam used by the commit hook and return the spy."""
    spy = _CommitSpy()
    monkeypatch.setattr(
        etckeeper,
        "find_etckeeper",
        lambda: "/usr/bin/etckeeper" if found else None,
    )
    monkeypatch.setattr(etckeeper, "working_tree_dirty", lambda *_a: dirty)
    monkeypatch.setattr(etckeeper, "commit", spy)
    return spy


def test_commit_hook_runs_on_normal_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _commit_history

    spy = _install_etckeeper(monkeypatch)
    _commit_history("a/f.conf", {}, Options(), IptablesBackend(), None)
    assert len(spy.messages) == 1
    assert spy.messages[0].startswith("ferm: applied f.conf")


def test_commit_hook_runs_under_shell_without_noexec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # --shell without --noexec really applies, so it must commit.
    from pyferm.cli import _commit_history

    spy = _install_etckeeper(monkeypatch)
    _commit_history("f.conf", {}, Options(shell=True), IptablesBackend(), None)
    assert len(spy.messages) == 1


@pytest.mark.parametrize(
    "options",
    [
        Options(noexec=True),
        Options(plan=True),
        Options(test=True),
        Options(etckeeper=False),
    ],
)
def test_commit_hook_gated_off(
    monkeypatch: pytest.MonkeyPatch, options: Options
) -> None:
    from pyferm.cli import _commit_history

    spy = _install_etckeeper(monkeypatch)
    _commit_history("f.conf", {}, options, IptablesBackend(), None)
    assert spy.messages == []


def test_commit_hook_skipped_when_etckeeper_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _commit_history

    spy = _install_etckeeper(monkeypatch, found=False)
    _commit_history("f.conf", {}, Options(), IptablesBackend(), None)
    assert spy.messages == []


def test_commit_hook_skipped_when_nothing_to_commit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from pyferm.cli import _commit_history

    spy = _install_etckeeper(monkeypatch, dirty=False)
    _commit_history("f.conf", {}, Options(), IptablesBackend(), None)
    assert spy.messages == []
    # Silent: a clean tree is the common reload/reboot path, not a warning.
    assert capsys.readouterr().err == ""


def test_commit_subject_variants() -> None:
    from pyferm.cli import _commit_subject

    assert _commit_subject("a/f.conf", {}, Options()) == (
        "applied f.conf (iptables)"
    )
    assert _commit_subject("a/f.conf", {}, Options(flush=True)) == (
        "flushed f.conf (iptables)"
    )
    assert (
        _commit_subject("a/f.conf", {}, Options(nft=True, fast=False))
        == "applied f.conf (nft, slow)"
    )


def test_commit_subject_override_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The rollback path passes an explicit subject; the hook must use it.
    spy = _install_etckeeper(monkeypatch)
    from pyferm.cli import _commit_history

    _commit_history(
        "f.conf", {}, Options(), IptablesBackend(), "rolled back to deadbeef"
    )
    assert spy.messages[0] == "ferm: rolled back to deadbeef"


def test_build_commit_message_degrades_on_plan_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If build_plan raises, the commit still happens with a subject-only body.
    import pyferm.cli as cli_mod
    from pyferm.cli import _build_commit_message

    def _boom(*_a: object, **_k: object) -> object:
        raise FermError("render exploded")

    monkeypatch.setattr(cli_mod, "build_plan", _boom)
    message = _build_commit_message(
        "f.conf", {}, Options(), IptablesBackend(), None
    )
    assert message == "ferm: applied f.conf (iptables)"
    assert "\n" not in message


class _FakeParser:
    """A parser stand-in: skips parsing, exposes a fixed domain set."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        from pyferm.domains import DomainInfo

        self.domains = {"ip": DomainInfo(enabled=True, tools={})}
        self.pre_hooks: list[str] = []
        self.post_hooks: list[str] = []
        self.flush_hooks: list[str] = []

    def enter(self, _depth: int, _node: object) -> None:
        """No-op: the apply block under test runs over ``domains``."""


class _ApplyBackend:
    """Minimal backend whose ``commit`` result is configurable."""

    def __init__(self, *, commit_result: int | None) -> None:
        self._commit_result = commit_result

    def tool_names(self, _domain: str) -> dict[str, str]:
        return {}

    def capture_previous(self, *_args: object, **_kwargs: object) -> None:
        pass

    def shell_snapshot(self, *_args: object, **_kwargs: object) -> None:
        return None

    def render(self, *_args: object, **_kwargs: object) -> object:
        from pyferm.backend.base import Rendered

        return Rendered(save="")

    def commit(self, *_args: object, **_kwargs: object) -> int | None:
        return self._commit_result

    def rollback(self, *_args: object, **_kwargs: object) -> None:
        pass


def _patch_apply_seam(
    monkeypatch: pytest.MonkeyPatch, *, commit_result: int | None
) -> list[object]:
    """Drive _apply_config over a fake parser/backend; spy the commit hook."""
    import pyferm.cli as cli_mod

    commit_calls: list[object] = []
    monkeypatch.setattr(
        cli_mod,
        "_select_backend",
        lambda _o: _ApplyBackend(commit_result=commit_result),
    )
    monkeypatch.setattr(cli_mod, "Parser", _FakeParser)
    monkeypatch.setattr(
        cli_mod, "_commit_history", lambda *a, **_k: commit_calls.append(a)
    )
    return commit_calls


def test_apply_rollback_path_never_reaches_commit(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When an apply rolls back (backend.commit returns non-None -> status set
    # -> _rollback_all raises SystemExit), the commit hook's call site is
    # never reached.  This is the feature's core safety invariant.
    from pyferm.cli import _apply_config

    commit_calls = _patch_apply_seam(monkeypatch, commit_result=1)
    with pytest.raises(SystemExit):
        _apply_config(str(trivial_conf), Options(), sys.stdout, defs=[])
    assert commit_calls == []


def test_apply_success_path_reaches_commit(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The counterpart: a clean apply (commit returns None) reaches the hook,
    # so the rollback test's emptiness is a real signal, not a dead call site.
    from pyferm.cli import _apply_config

    commit_calls = _patch_apply_seam(monkeypatch, commit_result=None)
    assert (
        _apply_config(str(trivial_conf), Options(), sys.stdout, defs=[]) == 0
    )
    assert len(commit_calls) == 1


# --- F1: interactive confirm/rollback composition ---------------------------


def test_interactive_decline_triggers_rollback(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When the admin declines confirmation _rollback_all fires and raises
    # SystemExit.  The commit hook must not be reached (the safety invariant).
    import pyferm.cli as cli_mod
    from pyferm.cli import _apply_config

    commit_calls = _patch_apply_seam(monkeypatch, commit_result=None)
    monkeypatch.setattr(cli_mod, "_confirm_rules", lambda _opts: False)
    with pytest.raises(SystemExit):
        _apply_config(
            str(trivial_conf), Options(interactive=True), sys.stdout, defs=[]
        )
    assert commit_calls == []


def test_interactive_confirm_skips_rollback(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Counterpart: confirming keeps the rules; no SystemExit, commit hook
    # reached exactly once (proving the decline test's assertion is real).
    import pyferm.cli as cli_mod
    from pyferm.cli import _apply_config

    commit_calls = _patch_apply_seam(monkeypatch, commit_result=None)
    monkeypatch.setattr(cli_mod, "_confirm_rules", lambda _opts: True)
    assert (
        _apply_config(
            str(trivial_conf), Options(interactive=True), sys.stdout, defs=[]
        )
        == 0
    )
    assert len(commit_calls) == 1


# --- F3: --flush clears pre/post hooks; normal apply clears flush hooks -----


class _SeededParser(_FakeParser):
    """Like _FakeParser but pre-loads sentinel values into every hook list."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.pre_hooks = ["echo pre"]
        self.post_hooks = ["echo post"]
        self.flush_hooks = ["echo flush"]


def test_flush_clears_pre_and_post_hooks(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # --flush clears pre_hooks and post_hooks so they are not executed;
    # flush_hooks are retained and run instead.
    import pyferm.cli as cli_mod
    from pyferm.cli import _apply_config

    _patch_apply_seam(monkeypatch, commit_result=None)
    monkeypatch.setattr(cli_mod, "Parser", _SeededParser)
    executed: list[str] = []
    monkeypatch.setattr(
        cli_mod, "_run_hook", lambda cmd, *_a, **_k: executed.append(cmd)
    )
    assert (
        _apply_config(
            str(trivial_conf), Options(flush=True), sys.stdout, defs=[]
        )
        == 0
    )
    assert "echo pre" not in executed
    assert "echo post" not in executed
    assert "echo flush" in executed


def test_no_flush_retains_pre_and_post_hooks(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without --flush, pre_hooks and post_hooks are executed; flush_hooks are
    # cleared and never run.
    import pyferm.cli as cli_mod
    from pyferm.cli import _apply_config

    _patch_apply_seam(monkeypatch, commit_result=None)
    monkeypatch.setattr(cli_mod, "Parser", _SeededParser)
    executed: list[str] = []
    monkeypatch.setattr(
        cli_mod, "_run_hook", lambda cmd, *_a, **_k: executed.append(cmd)
    )
    assert (
        _apply_config(
            str(trivial_conf), Options(flush=False), sys.stdout, defs=[]
        )
        == 0
    )
    assert "echo pre" in executed
    assert "echo post" in executed
    assert "echo flush" not in executed


class _TwoDomainParser(_SeededParser):
    """A _SeededParser exposing two enabled domains (ip and ip6)."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        from pyferm.domains import DomainInfo

        super().__init__(*args, **kwargs)
        self.domains = {
            "ip": DomainInfo(enabled=True, tools={}),
            "ip6": DomainInfo(enabled=True, tools={}),
        }


def test_post_hooks_run_after_all_domain_commits(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Perl runs @post_hooks only after the domain loop (:776-793): a post
    # hook (say, reloading fail2ban) must observe every family's new
    # ruleset, not just the first one committed.
    import pyferm.cli as cli_mod
    from pyferm.cli import _apply_config

    events: list[str] = []

    class _RecordingBackend(_ApplyBackend):
        def commit(self, *args: object, **kwargs: object) -> int | None:
            events.append(f"commit:{args[0]}")
            return super().commit(*args, **kwargs)

    def record_hook(command: str, *_args: object, **_kwargs: object) -> None:
        events.append(f"hook:{command}")

    _patch_apply_seam(monkeypatch, commit_result=None)
    monkeypatch.setattr(
        cli_mod,
        "_select_backend",
        lambda _o: _RecordingBackend(commit_result=None),
    )
    monkeypatch.setattr(cli_mod, "Parser", _TwoDomainParser)
    monkeypatch.setattr(cli_mod, "_run_hook", record_hook)
    assert (
        _apply_config(
            str(trivial_conf), Options(flush=False), sys.stdout, defs=[]
        )
        == 0
    )
    assert events == [
        "hook:echo pre",
        "commit:ip",
        "commit:ip6",
        "hook:echo post",
    ]


# --- ferm rollback subcommand ----------------------------------------------


class _RollbackSpy:
    """Record ``etckeeper.rollback`` calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, sha: str, subpath: str) -> None:
        self.calls.append((sha, subpath))


class _ApplySpy:
    """Stand in for ``_apply_config`` capturing the re-apply arguments."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Options, str | None]] = []
        self.defs: list[list[str]] = []

    def __call__(
        self,
        config: str,
        options: Options,
        _lines_stream: object,
        *,
        defs: list[str],
        subject: str | None = None,
    ) -> int:
        self.calls.append((config, options, subject))
        self.defs.append(defs)
        return 0


def _mock_rollback_seam(
    monkeypatch: pytest.MonkeyPatch,
    *,
    available: bool = True,
    dirty: bool = False,
    previous: str = "prev1234",
    history: str = "abc one\n",
    diff: str = "DIFFTEXT\n",
) -> tuple[_RollbackSpy, _ApplySpy]:
    import pyferm.cli as cli_mod

    rollback_spy = _RollbackSpy()
    apply_spy = _ApplySpy()
    monkeypatch.setattr(etckeeper, "rollback_available", lambda: available)
    monkeypatch.setattr(etckeeper, "repo_relative_subpath", lambda _c: "ferm")
    monkeypatch.setattr(etckeeper, "working_tree_dirty", lambda *_a: dirty)
    monkeypatch.setattr(etckeeper, "previous_revision", lambda _s: previous)
    monkeypatch.setattr(etckeeper, "list_history", lambda _s: history)
    monkeypatch.setattr(etckeeper, "diff_revision", lambda _sha, _s: diff)
    monkeypatch.setattr(etckeeper, "rollback", rollback_spy)
    monkeypatch.setattr(cli_mod, "_apply_config", apply_spy)
    return rollback_spy, apply_spy


def test_rollback_dispatch_via_production_main(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The production entry calls main()/_main(None); argv normalisation must
    # surface the rollback subcommand from sys.argv.
    _mock_rollback_seam(monkeypatch, history="abc only commit\n")
    monkeypatch.setattr(sys, "argv", ["ferm", "rollback", "--list"])
    assert main() == 0
    assert "abc only commit" in capsys.readouterr().out


def test_rollback_list_requires_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _rollback_main

    _mock_rollback_seam(monkeypatch, available=False)
    with pytest.raises(FermError, match="requires an etckeeper repository"):
        _rollback_main(["--list"])


def test_rollback_to_reapplies_inheriting_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _rollback_main

    rollback_spy, apply_spy = _mock_rollback_seam(monkeypatch)
    assert _rollback_main(["--to", "deadbeef", "--nft", "/etc/x.conf"]) == 0
    assert rollback_spy.calls == [("deadbeef", "ferm")]
    config, options, subject = apply_spy.calls[0]
    assert config == "/etc/x.conf"
    assert options.nft is True  # nft install stays nft, not iptables
    assert subject == "rolled back to deadbeef"


def test_rollback_bare_no_previous_revision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _rollback_main

    _mock_rollback_seam(monkeypatch)

    def _none(_s: str) -> str:
        raise FermError("no previous version to roll back to")

    monkeypatch.setattr(etckeeper, "previous_revision", _none)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    with pytest.raises(FermError, match="no previous version"):
        _rollback_main([])


def test_rollback_bare_declined_does_not_roll_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _rollback_main

    rollback_spy, apply_spy = _mock_rollback_seam(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdin, "readline", lambda: "n\n", raising=False)
    assert _rollback_main([]) == 0
    assert rollback_spy.calls == []
    assert apply_spy.calls == []


def test_rollback_bare_confirmed_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _rollback_main

    rollback_spy, apply_spy = _mock_rollback_seam(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdin, "readline", lambda: "yes\n", raising=False)
    assert _rollback_main([]) == 0
    assert rollback_spy.calls == [("prev1234", "ferm")]
    assert apply_spy.calls[0][2] == "rolled back to prev1234"


def test_rollback_bare_non_tty_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _rollback_main

    rollback_spy, _apply = _mock_rollback_seam(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(FermError, match="non-tty"):
        _rollback_main([])
    assert rollback_spy.calls == []


def test_rollback_dirty_tree_aborts_before_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _rollback_main

    rollback_spy, _apply = _mock_rollback_seam(monkeypatch, dirty=True)
    with pytest.raises(FermError, match="uncommitted changes"):
        _rollback_main(["--to", "deadbeef"])
    assert rollback_spy.calls == []


def test_rollback_full_reload_requires_nft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _rollback_main

    _mock_rollback_seam(monkeypatch)
    with pytest.raises(FermError, match="full-reload"):
        _rollback_main(["--to", "deadbeef", "--full-reload"])


def test_rollback_interactive_non_tty_stdin_refused_before_any_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Mirrors the apply path's tty guard (_resolve_options): --interactive
    # on a non-tty stdin must be refused before etckeeper or the kernel are
    # touched, for both rollback forms -- including --to, whose own
    # confirmation-prompt tty check (confirm=False) never runs.
    from pyferm.cli import _rollback_main

    rollback_spy, apply_spy = _mock_rollback_seam(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
    with pytest.raises(FermError, match="stdin is not a tty"):
        _rollback_main(["--to", "deadbeef", "--interactive"])
    assert rollback_spy.calls == []
    assert apply_spy.calls == []


def test_rollback_interactive_non_tty_stderr_refused_before_any_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pyferm.cli import _rollback_main

    rollback_spy, apply_spy = _mock_rollback_seam(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False, raising=False)
    with pytest.raises(FermError, match="stderr is not a tty"):
        _rollback_main(["--to", "deadbeef", "--interactive"])
    assert rollback_spy.calls == []
    assert apply_spy.calls == []


def test_rollback_interactive_tty_reaches_apply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Positive control: --interactive must still work when both streams are
    # a tty -- the new guard must not affect the unaffected case.
    from pyferm.cli import _rollback_main

    rollback_spy, apply_spy = _mock_rollback_seam(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
    assert _rollback_main(["--to", "deadbeef", "--interactive"]) == 0
    assert rollback_spy.calls == [("deadbeef", "ferm")]
    assert apply_spy.calls[0][1].interactive is True


def test_rollback_inherits_nolegacy_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A --nolegacy install must roll back --nolegacy too, or find_tool would
    # prefer the *-legacy binary and the re-apply could pick the wrong tool
    # family (and fail) after /etc was already reverted.
    from pyferm.cli import _rollback_main

    _rollback_spy, apply_spy = _mock_rollback_seam(monkeypatch)
    assert (
        _rollback_main(
            ["--to", "deadbeef", "--nolegacy", "-t", "5", "/etc/x.conf"]
        )
        == 0
    )
    _config, options, _subject = apply_spy.calls[0]
    assert options.nolegacy is True
    assert options.timeout == 5


def test_rollback_inherits_def_overrides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A config referencing a command-line --def variable would raise
    # "undefined variable" on re-apply (after /etc is reverted) unless the
    # rollback re-apply inherits the same --def overrides.
    from pyferm.cli import _rollback_main

    _rollback_spy, apply_spy = _mock_rollback_seam(monkeypatch)
    assert (
        _rollback_main(
            ["--to", "deadbeef", "--def", "X=1", "--def", "Y=2", "/etc/x.conf"]
        )
        == 0
    )
    assert apply_spy.defs[0] == ["X=1", "Y=2"]


def test_rollback_dirty_tree_aborts_before_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The dirty-worktree guard must run BEFORE the confirmation prompt so the
    # operator is never asked to confirm a rollback that is then refused; the
    # diff/prompt seam must not be reached at all.
    from pyferm.cli import _rollback_main

    rollback_spy, _apply = _mock_rollback_seam(monkeypatch, dirty=True)

    def _unreachable(*_a: object, **_k: object) -> str:
        raise AssertionError("prompt seam reached despite a dirty worktree")

    monkeypatch.setattr(etckeeper, "diff_revision", _unreachable)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdin, "readline", _unreachable, raising=False)
    with pytest.raises(FermError, match="uncommitted changes"):
        _rollback_main([])
    assert rollback_spy.calls == []


def test_rollback_help_prints_usage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # add_help=True: `ferm rollback --help` prints usage and exits 0, not an
    # "unrecognized arguments" error.
    from pyferm.cli import _rollback_main

    with pytest.raises(SystemExit) as excinfo:
        _rollback_main(["--help"])
    assert excinfo.value.code == 0
    assert "rollback" in capsys.readouterr().out


def test_commit_hook_swallows_failure_and_warns(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # A failure recording history must never propagate (the firewall is
    # already applied); it degrades to a single stderr warning.
    from pyferm.cli import _commit_history

    _install_etckeeper(monkeypatch)

    def _boom(*_a: object, **_k: object) -> bool:
        raise RuntimeError("git exploded")

    monkeypatch.setattr(etckeeper, "working_tree_dirty", _boom)
    # Must not raise.
    _commit_history("f.conf", {}, Options(), IptablesBackend(), None)
    assert "etckeeper commit skipped: git exploded" in capsys.readouterr().err


def test_graph_default_format_is_d2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "f.ferm"
    cfg.write_text("chain INPUT { policy DROP; }\n", encoding="latin-1")
    assert _main(["--graph", str(cfg)]) == 0
    out = capsys.readouterr().out
    assert out.startswith('ip__filter: "ip/filter" {')
    assert out.endswith("}\n")


def test_graph_dot_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "f.ferm"
    cfg.write_text("chain INPUT { policy DROP; }\n", encoding="latin-1")
    assert _main(["--graph", "--graph-format", "dot", str(cfg)]) == 0
    assert capsys.readouterr().out.startswith("digraph ferm {")


def test_graph_format_requires_graph(tmp_path: Path) -> None:
    with pytest.raises(FermError, match="requires --graph"):
        _main(["--graph-format", "dot", str(tmp_path / "f.ferm")])


def test_graph_rejects_extra_mode_and_pipe_and_filecount(
    tmp_path: Path,
) -> None:
    cfg = tmp_path / "f.ferm"
    cfg.write_text("chain INPUT {}\n", encoding="latin-1")
    with pytest.raises(FermError, match="cannot be combined with --lint"):
        _main(["--graph", "--lint", str(cfg)])
    with pytest.raises(FermError, match="requires exactly one input file"):
        _main(["--graph"])
    with pytest.raises(FermError, match="pipe command"):
        _main(["--graph", "cat foo |"])


def test_list_modules_wins_over_graph_format() -> None:
    # guard order: introspection dispatches first (spec §7)
    with pytest.raises(FermError, match="--list-modules cannot be combined"):
        _main(["--list-modules", "--graph-format", "dot"])


# ===========================================================================
# Mutation-kill coverage for pyferm.cli survivors.
# ===========================================================================


# --- _run_hook -------------------------------------------------------------


def test_run_hook_runs_command_via_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Outside --noexec the hook is executed with shell=True, check=False and
    # the command string is echoed under --lines (Perl :777-794).
    from pyferm.cli import _run_hook

    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: calls.append((a, k))
    )
    emitted: list[str] = []
    _run_hook("echo hi", Options(lines=True), emitted.append)
    assert calls == [(("echo hi",), {"shell": True, "check": False})]
    assert emitted == ["echo hi\n"]


def test_run_hook_noexec_echoes_but_does_not_run(
    tmp_path: Path,
) -> None:
    # Under --noexec (implied by --test) the hook echoes but must not run: a
    # side-effecting command leaves no trace.
    marker = tmp_path / "hook-ran"
    conf = tmp_path / "t.ferm"
    conf.write_text(
        f'@hook pre "touch {marker}";\nchain INPUT ACCEPT;\n',
        encoding="utf-8",
    )
    assert main(["--test", str(conf)]) == 0
    assert not marker.exists()


# --- _apply_def ------------------------------------------------------------


def test_def_binds_name_and_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # --def X=1234 binds group(1) as the name and the parsed group(2) as the
    # value; a hook interpolating $X echoes it under --test --lines.
    conf = tmp_path / "t.ferm"
    conf.write_text(
        '@hook pre "echo mark-$X-end";\nchain INPUT ACCEPT;\n',
        encoding="utf-8",
    )
    assert main(["--test", "--def", "X=1234", str(conf)]) == 0
    assert "mark-1234-end" in capsys.readouterr().out


# --- _apply_config auto path variables -------------------------------------


def test_apply_config_binds_path_auto_variables(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # FILENAME/FILEBNAME/DIRNAME are seeded on the script frame (Perl :751);
    # a hook echoing them under --test --lines shows the exact values.
    from pyferm.functions import splitpath_dir, splitpath_file

    sub = tmp_path / "sub"
    sub.mkdir()
    conf = sub / "my.ferm"
    conf.write_text(
        '@hook pre "echo F=$FILENAME B=$FILEBNAME D=$DIRNAME";\n'
        "chain INPUT ACCEPT;\n",
        encoding="utf-8",
    )
    assert main(["--test", str(conf)]) == 0
    name = str(conf)
    expected = (
        f"echo F={name} B={splitpath_file(name)} D={splitpath_dir(name)}"
    )
    assert expected in capsys.readouterr().out


# --- _build_parser short-flag aliases and choices --------------------------


@pytest.mark.parametrize(
    ("flag", "attr"),
    [
        ("-n", "noexec"),
        ("-F", "flush"),
        ("-l", "lines"),
        ("-i", "interactive"),
        ("-h", "help"),
        ("-V", "version"),
    ],
)
def test_short_flag_aliases_map_to_long(flag: str, attr: str) -> None:
    # A deleted or case-swapped single-letter alias would make argparse reject
    # the invocation (or bind the wrong dest), so each alias is pinned here.
    args = _build_parser().parse_args([flag, "f"])
    assert getattr(args, attr) is True


def test_short_timeout_alias_takes_value() -> None:
    assert _build_parser().parse_args(["-t", "5", "f"]).timeout == "5"


def test_remote_is_alias_for_test() -> None:
    # --remote shares --test's dest, so it toggles the same option.
    assert _build_parser().parse_args(["--remote", "f"]).test is True


def test_plan_format_rejects_unknown_choice() -> None:
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["--plan", "--plan-format", "bogus", "f"])


def test_graph_format_rejects_unknown_choice() -> None:
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["--graph", "--graph-format", "bogus", "f"])


def test_graph_format_accepts_d2_choice() -> None:
    args = _build_parser().parse_args(["--graph", "--graph-format", "d2", "f"])
    assert args.graph_format == "d2"


# --- _resolve_options passthrough ------------------------------------------


def test_resolve_flush_passthrough() -> None:
    assert _resolve_plan(["--flush", "a.ferm"]).flush is True


def test_resolve_domain_passthrough() -> None:
    assert _resolve_plan(["--domain", "ip", "a.ferm"]).domain == "ip"


def test_resolve_slow_sets_fast_false() -> None:
    assert _resolve_plan(["--slow", "a.ferm"]).fast is False
    assert _resolve_plan(["a.ferm"]).fast is True


def test_resolve_timeout_passthrough(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opts = _resolve(["-i", "-t", "5", "f"], tty=True, monkeypatch=monkeypatch)
    assert opts.timeout == 5


# --- build_plan host_mask --------------------------------------------------


def test_plan_bare_address_uses_ipv4_host_mask(tmp_path: Path) -> None:
    # A bare saddr is canonicalized with /32 under ip, comparing equal to a
    # masked /32 in the current ruleset -> no change.
    prev = _write(
        tmp_path,
        "p4.save",
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -s 1.2.3.4/32 -j ACCEPT\nCOMMIT\n",
    )
    cfg = _write(
        tmp_path,
        "c4.ferm",
        "domain ip table filter chain INPUT saddr 1.2.3.4 ACCEPT;\n",
    )
    code = main(
        ["--plan", "--test", f"--test-mock-previous=ip={prev}", str(cfg)]
    )
    assert code == 0


def test_plan_bare_address_uses_ipv6_host_mask(tmp_path: Path) -> None:
    # The else branch uses /128 under ip6; a bare saddr compares equal to a
    # masked /128 current rule.
    prev = _write(
        tmp_path,
        "p6.save",
        "*filter\n:INPUT ACCEPT [0:0]\n"
        "-A INPUT -s fe80::1/128 -j ACCEPT\nCOMMIT\n",
    )
    cfg = _write(
        tmp_path,
        "c6.ferm",
        "domain ip6 table filter chain INPUT saddr fe80::1 ACCEPT;\n",
    )
    code = main(
        ["--plan", "--test", f"--test-mock-previous=ip6={prev}", str(cfg)]
    )
    assert code == 0


# --- _run_plan format passthrough ------------------------------------------


def test_run_plan_uses_selected_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # --plan-format diff renders the unified diff (with @@ hunk headers); the
    # renderer receives the resolved format, not a hardcoded default.
    prev = _write(tmp_path, "prev.save", _PREV)
    cfg = _write(
        tmp_path,
        "c.ferm",
        "domain ip table filter chain INPUT proto tcp dport 80 ACCEPT;",
    )
    code = main(
        [
            "--plan",
            "--plan-format",
            "diff",
            "--test",
            f"--test-mock-previous=ip={prev}",
            str(cfg),
        ]
    )
    out = capsys.readouterr().out
    assert code == 2
    assert "@@" in out
    assert "--- ip (current)" in out


# --- _commit_subject / _build_commit_message / _commit_history -------------


def test_commit_subject_lists_enabled_families() -> None:
    # With enabled families the subject names them space-joined; the disabled
    # family is omitted.
    from pyferm.cli import _commit_subject
    from pyferm.domains import DomainInfo as RealDomainInfo
    from pyferm.domains import Family

    domains = {
        Family.IP: RealDomainInfo(enabled=True),
        Family.IP6: RealDomainInfo(enabled=True),
        Family.ARP: RealDomainInfo(enabled=False),
    }
    assert _commit_subject("a/f.conf", domains, Options()) == (
        "applied f.conf (ip ip6, iptables)"
    )


def _nft_body_backend() -> Backend:
    """A MagicMock nft backend rendering a save that diffs against empty."""
    from unittest.mock import MagicMock

    save = (
        "add table ip ferm\n"
        "add chain ip ferm INPUT { type filter hook input priority 0; }\n"
        "add rule ip ferm INPUT accept\n"
    )
    rendered = MagicMock()
    rendered.save = save
    backend = MagicMock()
    backend.render.return_value = rendered
    return cast("Backend", backend)


def test_build_commit_message_appends_family_body() -> None:
    # The body comes from build_plan(domains, options, backend); a dropped or
    # nulled options/backend argument would AttributeError, and a nulled body
    # would strip the per-family delta.
    from pyferm.backend.nft import TOOL_NFT
    from pyferm.cli import _build_commit_message
    from pyferm.domains import DomainInfo as RealDomainInfo
    from pyferm.domains import Family

    di = RealDomainInfo(enabled=True, tools={TOOL_NFT: "nft"})
    message = _build_commit_message(
        "f.conf", {Family.IP: di}, Options(nft=True), _nft_body_backend(), None
    )
    assert message.startswith("ferm: applied f.conf (ip, nft)")
    assert "\n\n  ip:" in message


def test_commit_history_forwards_backend_with_enabled_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With enabled nft domains build_plan uses the backend; a dropped backend
    # argument to _build_commit_message would AttributeError and the commit
    # would be silently skipped.
    from pyferm.backend.nft import TOOL_NFT
    from pyferm.cli import _commit_history
    from pyferm.domains import DomainInfo as RealDomainInfo
    from pyferm.domains import Family

    spy = _install_etckeeper(monkeypatch)
    di = RealDomainInfo(enabled=True, tools={TOOL_NFT: "nft"})
    _commit_history(
        "f.conf", {Family.IP: di}, Options(nft=True), _nft_body_backend(), None
    )
    assert len(spy.messages) == 1
    assert "\n\n  ip:" in spy.messages[0]


# --- _apply_config commit / rollback seams ---------------------------------


def test_apply_disabled_family_is_skipped_not_break(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A disabled family sorted before an enabled one must be skipped
    # (continue), not break the loop -- breaking would leave the enabled
    # family unapplied.
    import pyferm.cli as cli_mod
    from pyferm.cli import _apply_config
    from pyferm.domains import DomainInfo as RealDomainInfo
    from pyferm.domains import Family

    class _MultiParser(_FakeParser):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)
            self.domains = {
                Family.ARP: RealDomainInfo(enabled=False),
                Family.IP: RealDomainInfo(enabled=True),
            }

    committed: list[object] = []

    class _RecordingCommit(_ApplyBackend):
        def commit(self, *args: object, **_kwargs: object) -> int | None:
            committed.append(args[0])
            return None

    monkeypatch.setattr(
        cli_mod,
        "_select_backend",
        lambda _o: _RecordingCommit(commit_result=None),
    )
    monkeypatch.setattr(cli_mod, "Parser", _MultiParser)
    monkeypatch.setattr(cli_mod, "_commit_history", lambda *_a, **_k: None)
    assert (
        _apply_config(str(trivial_conf), Options(), sys.stdout, defs=[]) == 0
    )
    assert committed == [Family.IP]


class _SeamRecordingBackend(_ApplyBackend):
    """An _ApplyBackend whose rollback records the seams it is handed."""

    def __init__(self, *, commit_result: int | None) -> None:
        super().__init__(commit_result=commit_result)
        self.seen: dict[str, object] = {}

    def rollback(self, *args: object, **kwargs: object) -> None:
        self.seen = {
            "options": args[2],
            "execute": kwargs["execute"],
            "restore": kwargs["restore"],
        }


def _patch_seam_backend(
    monkeypatch: pytest.MonkeyPatch, backend: _SeamRecordingBackend
) -> None:
    import pyferm.cli as cli_mod

    monkeypatch.setattr(cli_mod, "_select_backend", lambda _o: backend)
    monkeypatch.setattr(cli_mod, "Parser", _FakeParser)
    monkeypatch.setattr(cli_mod, "_commit_history", lambda *_a, **_k: None)


def test_apply_status_rollback_receives_real_seams(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A non-None commit result triggers _rollback_all; it must be handed the
    # real options/execute/restore, not None.
    from pyferm.cli import _apply_config

    backend = _SeamRecordingBackend(commit_result=1)
    _patch_seam_backend(monkeypatch, backend)
    with pytest.raises(SystemExit):
        _apply_config(str(trivial_conf), Options(), sys.stdout, defs=[])
    assert backend.seen["options"] is not None
    assert backend.seen["execute"] is not None
    assert backend.seen["restore"] is not None


def test_apply_interactive_decline_receives_real_seams(
    trivial_conf: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Declining confirmation rolls back; _confirm_rules is passed the real
    # options and _rollback_all the real seams.
    import pyferm.cli as cli_mod
    from pyferm.cli import _apply_config

    backend = _SeamRecordingBackend(commit_result=None)
    _patch_seam_backend(monkeypatch, backend)
    confirm_args: list[object] = []

    def _decline(opts: object) -> bool:
        confirm_args.append(opts)
        return False

    monkeypatch.setattr(cli_mod, "_confirm_rules", _decline)
    with pytest.raises(SystemExit):
        _apply_config(
            str(trivial_conf), Options(interactive=True), sys.stdout, defs=[]
        )
    assert confirm_args
    assert confirm_args[0] is not None
    assert backend.seen["options"] is not None
    assert backend.seen["execute"] is not None
    assert backend.seen["restore"] is not None


# --- _make_io / _setup_streams ---------------------------------------------


def test_execute_emits_command_line_under_lines() -> None:
    # execute() echoes the command followed by a newline to the lines sink
    # before (not) running it.
    buf = io.StringIO()
    # local name avoids shadowing the `io` stdlib module used just above
    bound_io = _make_io(Options(lines=True, noexec=True), buf)
    assert bound_io.execute("iptables -A INPUT") is None
    assert buf.getvalue() == "iptables -A INPUT\n"


def test_setup_streams_passthrough_undo_returns_none() -> None:
    _lines, restore = _setup_streams(Options(lines=True))
    assert restore() is None


def test_setup_streams_shell_sink_writes_latin1(
    capfdbinary: pytest.CaptureFixture[bytes],
) -> None:
    # The --shell lines sink is line-buffered latin-1: a newline-terminated
    # write reaches the captured fd immediately (no explicit flush) as the
    # verbatim high byte, not its utf-8 two-byte encoding.
    lines_stream, restore = _setup_streams(Options(shell=True, lines=True))
    try:
        # No flush: line buffering must push the "\n"-terminated write through
        # on its own; block buffering would hold it back and read empty.
        lines_stream.write("h\xfc\n")
        out, _err = capfdbinary.readouterr()
    finally:
        restore()
    assert b"h\xfc\n" in out
    assert b"h\xc3\xbc" not in out


# --- _run_introspection ----------------------------------------------------


def test_describe_known_name_prints_module_doc(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # --describe forwards the requested name to describe(); a nulled argument
    # would fail the lookup and exit 1.
    assert main(["--describe", "tcp"]) == 0
    assert "tcp" in capsys.readouterr().out


# --- _rollback_main / _rollback_options ------------------------------------


def test_rollback_list_passes_config_derived_subpath(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # --list resolves the subpath from the config and lists that subpath; both
    # the config and the resolved subpath must flow through unchanged.
    from pyferm.cli import _rollback_main

    seen_config: list[object] = []
    seen_subpath: list[object] = []

    def _record_subpath(config: object) -> str:
        seen_config.append(config)
        return "the-subpath"

    def _record_history(subpath: object) -> str:
        seen_subpath.append(subpath)
        return "history\n"

    monkeypatch.setattr(etckeeper, "rollback_available", lambda: True)
    monkeypatch.setattr(etckeeper, "repo_relative_subpath", _record_subpath)
    monkeypatch.setattr(etckeeper, "list_history", _record_history)
    assert _rollback_main(["--list", "/etc/x.conf"]) == 0
    assert seen_config == ["/etc/x.conf"]
    assert seen_subpath == ["the-subpath"]


def test_rollback_bare_passes_subpath_config_and_defs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The bare form reads the previous revision of the subpath, then re-applies
    # the config with the inherited --def overrides.
    from pyferm.cli import _rollback_main

    seen_prev: list[object] = []
    _rollback_spy, apply_spy = _mock_rollback_seam(monkeypatch)

    def _record_previous(subpath: object) -> str:
        seen_prev.append(subpath)
        return "prevsha"

    monkeypatch.setattr(etckeeper, "previous_revision", _record_previous)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdin, "readline", lambda: "yes\n", raising=False)
    assert _rollback_main(["--def", "X=1", "/etc/x.conf"]) == 0
    assert seen_prev == ["ferm"]
    assert apply_spy.calls[0][0] == "/etc/x.conf"
    assert apply_spy.defs[0] == ["X=1"]


def test_rollback_bare_confirmed_with_bare_y(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A bare 'y' answer (not only 'yes') confirms the interactive rollback.
    from pyferm.cli import _rollback_main

    rollback_spy, _apply = _mock_rollback_seam(monkeypatch)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdin, "readline", lambda: "y\n", raising=False)
    assert _rollback_main([]) == 0
    assert rollback_spy.calls == [("prev1234", "ferm")]


def _rollback_opts(argv: list[str]) -> Options:
    from pyferm.cli import _build_rollback_parser, _rollback_options

    return _rollback_options(_build_rollback_parser().parse_args(argv))


def test_rollback_options_fast_from_slow() -> None:
    assert _rollback_opts(["--slow", "/etc/x"]).fast is False
    assert _rollback_opts(["/etc/x"]).fast is True


def test_rollback_options_domain_passthrough() -> None:
    assert _rollback_opts(["--domain", "ip", "/etc/x"]).domain == "ip"


def test_rollback_options_full_reload_passthrough() -> None:
    assert (
        _rollback_opts(["--nft", "--full-reload", "/etc/x"]).full_reload
        is True
    )


def test_rollback_options_etckeeper_from_no_etckeeper() -> None:
    assert _rollback_opts(["/etc/x"]).etckeeper is True
    assert _rollback_opts(["--no-etckeeper", "/etc/x"]).etckeeper is False


def test_def_name_rejects_non_ascii_word_chars(
    trivial_conf: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Perl matches --def in byte mode, where \w is [A-Za-z0-9_].  The
    # argv byte view of 'ª' is two latin-1 letters that Unicode \w would
    # accept as a name, so the pattern must stay pinned to re.ASCII.
    assert main(["--test", "--def", "ª=1", str(trivial_conf)]) == 1
    assert "Invalid --def specification" in capsys.readouterr().err
