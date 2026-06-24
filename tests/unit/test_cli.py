"""Unit tests for :mod:`pyferm.cli` (option derivation and main-flow seams)."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from pyferm.cli import (
    _build_parser,
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
    with pytest.raises(FermError, match="invalid timeout"):
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
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from pyferm.cli import main

    conf = tmp_path / "t.ferm"
    conf.write_text("chain INPUT ACCEPT;\n", encoding="utf-8")
    assert main(["--test", "--def", "noequalssign", str(conf)]) == 1
    assert "Invalid --def specification" in capsys.readouterr().err


def test_extra_tokens_after_def(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from pyferm.cli import main

    conf = tmp_path / "t.ferm"
    conf.write_text("chain INPUT ACCEPT;\n", encoding="utf-8")
    assert main(["--test", "--def", "$x=1 2", str(conf)]) == 1
    assert "Extra tokens after --def" in capsys.readouterr().err


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


def test_interactive_shell_nft_emits_anti_lockout_net(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # finding C2: under --nft the anti-lockout net was silently absent.  The
    # nft snapshot must now appear in the emitted script: a `list table` save
    # before, and a `delete table` + `nft -f` restore after the sleep.
    from pyferm.cli import main

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
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The notice is nft-only: the x_tables --shell script must stay
    # byte-identical to the Perl oracle (reference/src/ferm:803-814), which
    # emits no rollback announcement.
    from pyferm.cli import main

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
    conf = tmp_path / "t.ferm"
    conf.write_text("chain INPUT ACCEPT;\n", encoding="utf-8")
    assert main(["--test", "--interactive", "--shell", str(conf)]) == 0
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
    _execute, _emit, read_save, _restore, _capture = _make_io(
        Options(), sys.stdout
    )
    assert read_save(str(tool)) == "*filter\n"


def test_read_save_unexecutable_tool_reads_empty() -> None:
    # Perl's pipe-open forks fine and the child's exec fails: the parent
    # reads EOF, so {previous} is set to the empty string, not unset.
    from pyferm.cli import _make_io

    _execute, _emit, read_save, _restore, _capture = _make_io(
        Options(), sys.stdout
    )
    assert read_save("/nonexistent/ferm-no-such-tool") == ""


def test_execute_exec_failure_is_fatal(
    capfd: pytest.CaptureFixture[str],
) -> None:
    # Perl system() execs a metachar-free command directly; when that
    # exec fails it prints 'failed to execute: ...' and exits 1 at once
    # (:2903-2905) -- no status bookkeeping, no rollback.
    from pyferm.cli import _make_io

    execute, _emit, _read, _restore, _capture = _make_io(Options(), sys.stdout)
    with pytest.raises(SystemExit) as excinfo:
        execute("/nonexistent/ferm-no-such-tool -A INPUT")
    assert excinfo.value.code == 1
    assert "failed to execute:" in capfd.readouterr().err


def test_execute_returns_status_of_plain_command() -> None:
    from pyferm.cli import _make_io

    execute, _emit, _read, _restore, _capture = _make_io(Options(), sys.stdout)
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


def test_version_prints_perl_banner(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Perl printversion: the banner is verbatim oracle output (stdout,
    # exit 0, nothing else runs), so it is pinned byte-exactly.
    from pyferm import __version__
    from pyferm.cli import main

    assert main(["--version"]) == 0
    assert capsys.readouterr().out == (
        f"ferm {__version__}\n"
        "Copyright 2001-2021 Max Kellermann, Auke Kok\n"
        "This program is free software released under GPLv2.\n"
        "See the included COPYING file for license details.\n"
    )


def test_rollback_all_restores_enabled_domains_and_exits(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Perl rollback (:3147): every *active* family is restored, the
    # closing message goes to stderr and the process exits 1 -- the
    # admin must learn the new rules did NOT stay applied.
    from pyferm.backend.base import Backend
    from pyferm.cli import _rollback_all
    from pyferm.domains import DomainInfo as RealDomainInfo

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
        "ip6": RealDomainInfo(enabled=True),
        "ip": RealDomainInfo(enabled=True),
        "arp": RealDomainInfo(enabled=False),
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
    assert backend.calls[0][1:] == (domains["ip"], options, execute, restore)
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


# --- Task 1 (plan): --plan / --plan-format flag plumbing -------------------


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


# --- Task 15: backend selection --------------------------------------------


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
    from pyferm.cli import main

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
    from pyferm.cli import main

    cfg = tmp_path / "e.ferm"
    cfg.write_text(
        "domain ip table filter chain INPUT { ACCEPT; }\n",
        encoding="utf-8",
    )
    argv = ["--nft", "--nolegacy", "--test", "--noexec", "--lines", str(cfg)]
    assert main(argv) == 0


# --- Task 20: nft cli applier and capture seams ----------------------------


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
    # runs are fed the rendered save as one-byte-per-char latin-1 on stdin
    # (decision 1).
    from pyferm.cli import _make_nft_restore

    recorder = _RunRecorder(returncode=0)
    monkeypatch.setattr(subprocess, "run", recorder)
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

    recorder = _RunRecorder(
        returncode=1, stderr=b"Error: syntax error, unexpected newline\n"
    )
    monkeypatch.setattr(subprocess, "run", recorder)
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

    recorder = _RunRecorder(returncodes=[0, 1])
    monkeypatch.setattr(subprocess, "run", recorder)
    restore = _make_nft_restore(Options(nft=True))
    with pytest.raises(FermError, match="Failed to run nft"):
        restore(_nft_domain_info(), "add table ip ferm\n")
    assert [call[0][0] for call in recorder.calls] == [
        ["nft", "-c", "-f", "-"],
        ["nft", "-f", "-"],
    ]


def test_validate_desired_nft_skips_under_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # --test substitutes a fake nft path and must never spawn the real tool;
    # the --plan pre-validation is therefore a no-op in test mode.
    from pyferm.cli import _validate_desired_nft

    recorder = _RunRecorder(returncode=0)
    monkeypatch.setattr(subprocess, "run", recorder)
    _validate_desired_nft(Options(nft=True, test=True), "nft", "add table\n")
    assert recorder.calls == []


def test_validate_desired_nft_runs_check_when_not_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # In a real run the desired script is validated with `nft -c -f -` before
    # the plan is trusted -- an un-appliable ruleset must not be advertised.
    from pyferm.cli import _validate_desired_nft

    recorder = _RunRecorder(returncode=0)
    monkeypatch.setattr(subprocess, "run", recorder)
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

    recorder = _RunRecorder(
        returncode=1,
        stderr=b"Error: conflicting protocols specified: arp vs. tcp\n",
    )
    monkeypatch.setattr(subprocess, "run", recorder)
    with pytest.raises(FermError, match="conflicting protocols"):
        _validate_desired_nft(Options(nft=True), "nft", "bad\n")


def test_restore_dispatch_routes_to_nft_applier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With --nft the restore closure routes to the nft applier: it spawns
    # `nft -c -f -` then `nft -f -`, never an iptables-restore call.
    from pyferm.cli import _make_io

    recorder = _RunRecorder(returncode=0)
    monkeypatch.setattr(subprocess, "run", recorder)
    _execute, _emit, _read, restore, _capture = _make_io(
        Options(nft=True), sys.stdout
    )
    restore(_nft_domain_info(), "add table ip ferm\n")
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
    from pyferm.cli import _make_io

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
    _execute, _emit, _read, restore, _capture = _make_io(options, sys.stdout)
    domain_info = _nft_domain_info()
    restore(domain_info, "*filter\n")
    assert calls == [(domain_info, "*filter\n", options)]
    assert nft_called is False


def test_capture_noexec_returns_none_without_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Under --noexec capture snapshots nothing and never spawns a child.
    from pyferm.cli import _make_io

    def fail_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("capture must not spawn under --noexec")

    monkeypatch.setattr(subprocess, "run", fail_run)
    _execute, _emit, _read, _restore, capture = _make_io(
        Options(noexec=True), sys.stdout
    )
    assert capture("nft list ruleset") is None


def test_capture_oserror_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # finding C3: an unspawnable snapshot tool (OSError) must NOT collapse to
    # "no previous table" -- that would let the nft rollback delete an
    # existing table.  It aborts before any kernel change instead.
    from pyferm.cli import _make_io

    monkeypatch.setattr(
        subprocess, "run", _RunRecorder(raises=FileNotFoundError)
    )
    _execute, _emit, _read, _restore, capture = _make_io(Options(), sys.stdout)
    with pytest.raises(FermError, match="failed to snapshot for rollback"):
        capture("nft list ruleset")


def test_capture_returns_stdout_or_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Non-empty stdout is the snapshot; empty stdout (exit 0) collapses to
    # None, splitting the command on whitespace for the child.
    from pyferm.cli import _make_io

    recorder = _RunRecorder(returncode=0, stdout="X")
    monkeypatch.setattr(subprocess, "run", recorder)
    _execute, _emit, _read, _restore, capture = _make_io(Options(), sys.stdout)
    assert capture("nft list ruleset") == "X"
    assert recorder.calls[0][0][0] == ["nft", "list", "ruleset"]

    monkeypatch.setattr(
        subprocess, "run", _RunRecorder(returncode=0, stdout="")
    )
    _execute2, _emit2, _read2, _restore2, capture_empty = _make_io(
        Options(), sys.stdout
    )
    assert capture_empty("nft list ruleset") is None


def test_capture_absent_table_is_first_run_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # finding C3: a genuinely-absent table (nft exits 1 with ENOECT on
    # stderr) is the legitimate first run -> None, so rollback may delete
    # ferm's own freshly-created table.
    from pyferm.cli import _make_io

    monkeypatch.setattr(
        subprocess,
        "run",
        _RunRecorder(
            returncode=1, stdout="", stderr="Error: No such file or directory"
        ),
    )
    _execute, _emit, _read, _restore, capture = _make_io(Options(), sys.stdout)
    assert capture("nft list table ip ferm") is None


def test_capture_genuine_failure_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # finding C3: a non-ENOENT failure (exit 1 with some other error) must
    # NOT masquerade as a first run -- it aborts so the destructive rollback
    # never deletes an existing populated table on a transient capture error.
    from pyferm.cli import _make_io

    monkeypatch.setattr(
        subprocess,
        "run",
        _RunRecorder(
            returncode=1, stdout="", stderr="Error: Operation not permitted"
        ),
    )
    _execute, _emit, _read, _restore, capture = _make_io(Options(), sys.stdout)
    with pytest.raises(FermError, match="Operation not permitted"):
        capture("nft list table ip ferm")


def test_read_save_strict_under_plan_raises_on_missing_tool() -> None:
    # Under --plan a spawn failure must raise FermError rather than silently
    # returning empty: an empty current ruleset would under-count removals
    # and produce a falsely-clean plan.
    options = Options(plan=True)
    _execute, _emit, read_save, _restore, _capture = _make_io(
        options, io.StringIO()
    )
    with pytest.raises(FermError, match="current ruleset"):
        read_save("/nonexistent/iptables-save")


def test_read_save_lenient_without_plan_returns_empty() -> None:
    # Outside --plan the Perl pipe-open semantics are preserved: an
    # unspawnable tool returns the empty string rather than aborting.
    options = Options(plan=False)
    _execute, _emit, read_save, _restore, _capture = _make_io(
        options, io.StringIO()
    )
    assert read_save("/nonexistent/iptables-save") == ""


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


# --- Task 4 (nft --plan wiring) -------------------------------------------


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
    _execute, _emit, _read, _restore, capture = _make_io(
        Options(plan=True, noexec=True), sys.stdout
    )
    with pytest.raises(FermError, match="failed to snapshot"):
        capture("__no_such_binary_ferm_test__")


def test_capture_still_short_circuits_when_noexec_no_plan() -> None:
    # Without plan, noexec=True still returns None immediately (no spawn).
    _execute, _emit, _read, _restore, capture = _make_io(
        Options(plan=False, noexec=True), sys.stdout
    )
    result = capture("__no_such_binary_ferm_test__")
    assert result is None


def test_run_plan_nft_render_error_propagates() -> None:
    # A FermError from backend.render() (e.g. @preserve unsupported under nft)
    # must propagate out of _run_plan uncaught so main() exits 1, not 0 or 2.
    from unittest.mock import MagicMock

    from pyferm.cli import _run_plan
    from pyferm.domains import DomainInfo

    domain_info = DomainInfo(enabled=True, tools={})
    domains = {"ip": domain_info}

    backend = MagicMock()
    backend.render.side_effect = FermError("@preserve not yet supported")

    with pytest.raises(FermError, match="preserve"):
        _run_plan(domains, Options(nft=True), backend)


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
