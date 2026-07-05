"""Unit tests for :mod:`pyferm.backend.iptables`.

Covers the emit/execute layer ported from ``reference/src/ferm``
(``:1806-3183``): the value formatters and their bless-tag branches, the
family-specific ``ip6`` substitutions, the fast ``rules_to_save`` structure and
the dynamic-preserve helpers, the slow command list with its ``$status ||=``
guard flags and ``eb`` atomic framing, plus ``commit``/``rollback``.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from pyferm.backend.base import Command, Rendered
from pyferm.backend.iptables import (
    IptablesBackend,
    _validate_chain_name,
    _validate_policy,
    _validate_table_name,
    extract_chain_from_table_save,
    extract_table_from_save,
    format_option,
    format_rule,
    resolve_dynamic_preserve,
    restore_domain,
    rules_to_save,
    shell_escape,
    shell_format_option,
    table_to_save,
    validate_names,
)
from pyferm.config import Options
from pyferm.domains import (
    EB_TABLES,
    ChainInfo,
    DomainInfo,
    Family,
    ShellSnapshot,
    TableInfo,
)
from pyferm.errors import FermError
from pyferm.rules import RenderedOption, RenderedRule
from pyferm.scope import OptionKind
from pyferm.values import Multi, Negated, Params, PreNegated

# --- shell_escape ----------------------------------------------------------


def test_shell_escape_bare_word_unchanged() -> None:
    # /^[-_a-zA-Z0-9]+$/ short-circuits before any quoting (:1809)
    assert shell_escape("ACCEPT", fast=True) == "ACCEPT"
    assert shell_escape("eth0-1_2", fast=False) == "eth0-1_2"


def test_shell_escape_fast_double_quotes_specials() -> None:
    # fast mode escapes " and wraps tokens with whitespace/specials (:1816)
    assert shell_escape("a b", fast=True) == '"a b"'
    # " is escaped, then the backslash forces the whole token to be quoted
    assert shell_escape('say"hi"', fast=True) == '"say\\"hi\\""'


def test_shell_escape_slow_single_quotes() -> None:
    # slow mode single-quotes and escapes ' (:1822)
    assert shell_escape("a b", fast=False) == "'a b'"
    assert shell_escape("it's", fast=False) == "'it'\\''s'"


def test_shell_escape_slow_keeps_backticks() -> None:
    # an already-backticked command passes through untouched (:1820)
    assert shell_escape("`hostname`", fast=False) == "`hostname`"


def test_shell_escape_empty_is_quoted() -> None:
    assert shell_escape("", fast=True) == '""'
    assert shell_escape("", fast=False) == "''"


# --- shell_format_option ---------------------------------------------------


def test_shell_format_option_flag_scalar() -> None:
    assert shell_format_option("syn", None, fast=False) == " --syn"
    assert shell_format_option("dport", "ssh", fast=False) == " --dport ssh"


def test_shell_format_option_negation_prefix() -> None:
    # negated and pre_negated both render " !" before the keyword (:1837)
    assert (
        shell_format_option("dport", Negated("ssh"), fast=False)
        == " ! --dport ssh"
    )
    assert (
        shell_format_option("dport", PreNegated("ssh"), fast=False)
        == " ! --dport ssh"
    )


def test_shell_format_option_params_and_multi() -> None:
    # params: one --keyword with several args; multi: repeat per value
    assert (
        shell_format_option("dports", Params(["22", "80"]), fast=False)
        == " --dports 22 80"
    )
    assert (
        shell_format_option(
            "src-type", Multi(["LOCAL", "UNICAST"]), fast=False
        )
        == " --src-type LOCAL --src-type UNICAST"
    )


def test_shell_format_option_rejects_stray_ref() -> None:
    with pytest.raises(FermError):
        shell_format_option("x", ["a", "b"], fast=False)


# --- format_option (family substitutions) ----------------------------------


def test_format_option_ip6_icmp_protocol() -> None:
    # ip6: protocol icmp -> icmpv6 (:1866)
    assert format_option(Family.IP6, "protocol", "icmp", fast=False) == (
        " --protocol icmpv6"
    )
    # the ip family stays untouched
    assert format_option(Family.IP, "protocol", "icmp", fast=False) == (
        " --protocol icmp"
    )


def test_format_option_ip6_icmp_type_keyword() -> None:
    # ip6: icmp-type keyword becomes icmpv6-type (:1868)
    assert format_option(
        Family.IP6, "icmp-type", "echo-request", fast=False
    ) == (" --icmpv6-type echo-request")


def test_format_option_ip6_reject_with_map() -> None:
    # ip6: reject-with value translation (:1871)
    assert (
        format_option(
            Family.IP6, "reject-with", "icmp-host-prohibited", fast=False
        )
        == " --reject-with icmp6-adm-prohibited"
    )
    # an unmapped value passes through
    assert (
        format_option(Family.IP6, "reject-with", "tcp-reset", fast=False)
        == " --reject-with tcp-reset"
    )


def test_format_rule_joins_options() -> None:
    rule = RenderedRule(
        options=[
            RenderedOption("protocol", "tcp", OptionKind.PROTO, None),
            RenderedOption("dport", "ssh", OptionKind.OPTION, None),
            RenderedOption("jump", "ACCEPT", OptionKind.TARGET, None),
        ],
        script=None,
    )
    assert format_rule(Family.IP, rule, fast=False) == (
        " --protocol tcp --dport ssh --jump ACCEPT"
    )


# --- save-text helpers (preserve) ------------------------------------------

_SAVE = (
    "# Generated by iptables-save\n"
    "*filter\n"
    ":INPUT ACCEPT [0:0]\n"
    ":docker - [0:0]\n"
    "-A INPUT -j ACCEPT\n"
    "-A docker -j RETURN\n"
    "COMMIT\n"
    "*nat\n"
    ":PREROUTING ACCEPT [0:0]\n"
    "COMMIT\n"
)


def test_extract_table_from_save() -> None:
    body = extract_table_from_save(_SAVE, "filter")
    assert ":INPUT ACCEPT [0:0]\n" in body
    assert "-A docker -j RETURN\n" in body
    assert "PREROUTING" not in body  # stops at filter's COMMIT
    assert extract_table_from_save(_SAVE, "mangle") == ""


def test_extract_chain_from_table_save() -> None:
    body = extract_table_from_save(_SAVE, "filter")
    assert extract_chain_from_table_save(body, "docker") == (
        "-A docker -j RETURN\n"
    )
    assert extract_chain_from_table_save(body, "INPUT") == (
        "-A INPUT -j ACCEPT\n"
    )


def test_resolve_dynamic_preserve_returns_matching_chains() -> None:
    table_info = TableInfo(preserve_regexes=[re.compile(r"^docker")])
    body = extract_table_from_save(_SAVE, "filter")
    added = resolve_dynamic_preserve(table_info, body)
    # the docker chain matched and is returned with the preserve flag;
    # the table itself stays untouched (render purity)
    assert added["docker"].preserve is True
    assert "INPUT" not in added
    assert table_info.chains == {}


# --- rules_to_save (fast) --------------------------------------------------


def _domain_with_rule() -> DomainInfo:
    rule = RenderedRule(
        options=[
            RenderedOption("protocol", "tcp", OptionKind.PROTO, None),
            RenderedOption("dport", "ssh", OptionKind.OPTION, None),
            RenderedOption("jump", "ACCEPT", OptionKind.TARGET, None),
        ],
        script=None,
    )
    chains = {
        "INPUT": ChainInfo(builtin=True, policy="DROP", rules=[rule]),
        "forward_extra": ChainInfo(policy="ACCEPT"),
    }
    return DomainInfo(
        tools={"tables-save": "/sbin/iptables-save"},
        tables={"filter": TableInfo(chains=chains)},
    )


def test_rules_to_save_structure() -> None:
    domain_info = _domain_with_rule()
    save = rules_to_save(Family.IP, domain_info, Options(), now="WHEN")

    assert save.startswith("# Generated by ferm ")
    # path stripped from the tool name in the header
    assert "(iptables-save)" in save
    lines = save.splitlines()
    assert "*filter" in lines
    # builtin chain keeps its policy; chains emitted in sorted order
    assert ":INPUT DROP [0:0]" in lines
    assert ":forward_extra ACCEPT [0:0]" in lines
    assert lines.index(":INPUT DROP [0:0]") < lines.index(
        ":forward_extra ACCEPT [0:0]"
    )
    assert "-A INPUT --protocol tcp --dport ssh --jump ACCEPT" in lines
    assert lines[-1] == "COMMIT"


def test_rules_to_save_synthesizes_dash_policy() -> None:
    # a non-builtin chain with no policy gets '-' (:3087)
    domain_info = DomainInfo(
        tools={"tables-save": "iptables-save"},
        tables={"filter": TableInfo(chains={"custom": ChainInfo()})},
    )
    save = rules_to_save(Family.IP, domain_info, Options(), now="WHEN")
    assert ":custom - [0:0]" in save.splitlines()


def test_rules_to_save_builtin_default_accept() -> None:
    # a builtin chain with no explicit policy defaults to ACCEPT (:3084)
    chains = {"INPUT": ChainInfo(builtin=True)}
    domain_info = DomainInfo(
        tools={"tables-save": "iptables-save"},
        tables={"filter": TableInfo(chains=chains)},
    )
    save = rules_to_save(Family.IP, domain_info, Options(), now="WHEN")
    assert ":INPUT ACCEPT [0:0]" in save.splitlines()


# --- render (slow) ---------------------------------------------------------

_SLOW = Options(fast=False)


def _slow_texts(domain: Family, domain_info: DomainInfo) -> list[str]:
    rendered = IptablesBackend().render(domain, domain_info, _SLOW)
    return [command.text for command in rendered.commands]


def test_render_slow_builtin_walk_order() -> None:
    rule = RenderedRule(
        options=[RenderedOption("jump", "ACCEPT", OptionKind.TARGET, None)],
        script=None,
    )
    domain_info = DomainInfo(
        tools={"tables": "iptables"},
        tables={
            "filter": TableInfo(
                chains={"INPUT": ChainInfo(builtin=True, rules=[rule])}
            )
        },
    )
    texts = _slow_texts(Family.IP, domain_info)
    assert texts == [
        "iptables -t filter -P INPUT ACCEPT",
        "iptables -t filter -F",
        "iptables -t filter -X",
        "iptables -t filter -A INPUT --jump ACCEPT",
    ]


def test_render_slow_creates_custom_chain_with_policy() -> None:
    domain_info = DomainInfo(
        tools={"tables": "iptables"},
        tables={"filter": TableInfo(chains={"web": ChainInfo(policy="DROP")})},
    )
    texts = _slow_texts(Family.IP, domain_info)
    assert "iptables -t filter -N web -P DROP" in texts


def test_render_slow_noflush_skips_clear() -> None:
    domain_info = DomainInfo(
        tools={"tables": "iptables"},
        tables={
            "filter": TableInfo(chains={"INPUT": ChainInfo(builtin=True)})
        },
    )
    rendered = IptablesBackend().render(
        Family.IP, domain_info, Options(fast=False, noflush=True)
    )
    texts = [c.text for c in rendered.commands]
    assert not any(t.endswith(" -F") for t in texts)
    assert not any(t.endswith(" -P INPUT ACCEPT") for t in texts)


def test_render_slow_eb_atomic_framing_is_unguarded() -> None:
    domain_info = DomainInfo(
        tools={"tables": "ebtables"},
        tables={"filter": TableInfo(chains={})},
    )
    rendered = IptablesBackend().render(Family.EB, domain_info, _SLOW)
    try:
        # the atomic init/commit framing must run unconditionally
        framing = [c for c in rendered.commands if not c.guarded]
        assert any("--atomic-init" in c.text for c in framing)
        assert any("--atomic-commit" in c.text for c in framing)
        # one atomic tempfile per eb table, kept alive on the Rendered
        assert len(rendered.resources) == 3
    finally:
        rendered.close()


_PREVIOUS = (
    "*filter\n"
    ":INPUT ACCEPT [0:0]\n"
    ":docker - [0:0]\n"
    "-A docker -j RETURN\n"
    "COMMIT\n"
)


def test_render_fast_preserve_keeps_domain_state_intact() -> None:
    # render is the pure half of the seam (base.py): resolving @preserve
    # must not rewrite chain_info.preserve (True -> extracted text), and a
    # second render must produce the identical save.
    domain_info = DomainInfo(
        tools={
            "tables-save": "iptables-save",
            "tables-restore": "iptables-restore",
        },
        previous=_PREVIOUS,
        tables={
            "filter": TableInfo(
                chains={
                    "INPUT": ChainInfo(builtin=True),
                    "docker": ChainInfo(preserve=True),
                }
            )
        },
    )
    backend = IptablesBackend()
    first = rules_to_save(Family.IP, domain_info, Options(), now="WHEN")
    assert "-A docker -j RETURN" in first
    assert domain_info.tables["filter"].chains["docker"].preserve is True
    second = rules_to_save(Family.IP, domain_info, Options(), now="WHEN")
    assert first == second
    del backend


def test_render_fast_dynamic_preserve_leaves_chains_untouched() -> None:
    domain_info = DomainInfo(
        tools={
            "tables-save": "iptables-save",
            "tables-restore": "iptables-restore",
        },
        previous=_PREVIOUS,
        tables={
            "filter": TableInfo(
                preserve_regexes=[re.compile(r"^docker")],
                chains={"INPUT": ChainInfo(builtin=True)},
            )
        },
    )
    save = rules_to_save(Family.IP, domain_info, Options(), now="WHEN")
    # the dynamically preserved chain is emitted from the previous ruleset
    assert ":docker - [0:0]" in save
    assert "-A docker -j RETURN" in save
    # ...without inserting it into the parser-owned domain state
    assert "docker" not in domain_info.tables["filter"].chains


def test_render_slow_eb_rerender_keeps_first_tempfiles() -> None:
    domain_info = DomainInfo(
        tools={"tables": "ebtables"},
        tables={"filter": TableInfo(chains={})},
    )
    backend = IptablesBackend()
    rendered_one = backend.render(Family.EB, domain_info, _SLOW)
    try:
        names = {
            match.group(1)
            for command in rendered_one.commands
            for match in [re.search(r"--atomic-file (\S+)", command.text)]
            if match is not None
        }
        assert names
        assert all(Path(name).exists() for name in names)
        # a second render must not unlink the files the first Rendered's
        # commands reference (commit may still run them)
        rendered_two = backend.render(Family.EB, domain_info, _SLOW)
        try:
            assert all(Path(name).exists() for name in names)
        finally:
            rendered_two.close()
    finally:
        rendered_one.close()


def test_render_falls_back_to_slow_with_fast_escaping() -> None:
    # arp/eb own no *-restore tool, so under the default (fast) options
    # render must fall back to slow commands -- but the oracle formats the
    # values at parse time with the GLOBAL $option{fast}=1, so the escaping
    # stays fast-mode (double quotes), not slow-mode (single quotes).
    rule = RenderedRule(
        options=[
            RenderedOption("log-prefix", "a b", OptionKind.OPTION, None),
            RenderedOption("jump", "ACCEPT", OptionKind.TARGET, None),
        ],
        script=None,
    )
    domain_info = DomainInfo(
        tools={"tables": "arptables"},
        tables={
            "filter": TableInfo(
                chains={"INPUT": ChainInfo(builtin=True, rules=[rule])}
            )
        },
    )
    rendered = IptablesBackend().render(
        Family.ARP, domain_info, Options(fast=True)
    )
    assert rendered.save is None
    texts = [command.text for command in rendered.commands]
    assert any('--log-prefix "a b"' in text for text in texts)
    # an explicit --slow still escapes slow-mode
    rendered_slow = IptablesBackend().render(Family.ARP, domain_info, _SLOW)
    slow_texts = [command.text for command in rendered_slow.commands]
    assert any("--log-prefix 'a b'" in text for text in slow_texts)


def test_commit_dispatches_on_rendered_shape() -> None:
    # commit must follow the Rendered it was handed, not re-derive the
    # fast/slow decision from options (arp/eb fall back to slow even when
    # options.fast is true).
    calls: list[str] = []

    def execute(command: str) -> int | None:
        calls.append(command)
        return None

    status = IptablesBackend().commit(
        Family.ARP,
        DomainInfo(),
        Rendered(commands=[Command("a")]),
        Options(fast=True),
        execute=execute,
        emit_line=lambda _text: None,
        restore=lambda _domain_info, _save: None,
    )
    assert status is None
    assert calls == ["a"]


# --- commit ----------------------------------------------------------------


def test_commit_slow_guard_stops_after_failure() -> None:
    calls: list[str] = []

    def execute(command: str) -> int | None:
        calls.append(command)
        return 1 if command == "b" else None

    commands = [Command("a"), Command("b"), Command("c")]
    backend = IptablesBackend()
    status = backend._commit_slow(commands, execute=execute)
    # 'c' is skipped once 'b' failed (the $status ||= short-circuit)
    assert calls == ["a", "b"]
    assert status == 1


def test_commit_slow_unguarded_always_runs() -> None:
    calls: list[str] = []

    def execute(command: str) -> int | None:
        calls.append(command)
        return 1 if command == "fail" else None

    commands = [Command("fail"), Command("always", guarded=False)]
    IptablesBackend()._commit_slow(commands, execute=execute)
    assert "always" in calls


def test_commit_fast_emits_lines_and_skips_exec() -> None:
    emitted: list[str] = []

    def restore(_info: DomainInfo, _save: str) -> None:
        raise AssertionError("restore must not run under --noexec")

    domain_info = DomainInfo(tools={"tables-restore": "iptables-restore"})
    rendered = Rendered(save="*filter\nCOMMIT\n")
    status = IptablesBackend().commit(
        Family.IP,
        domain_info,
        rendered,
        Options(fast=True, lines=True, noexec=True),
        execute=lambda _c: None,
        emit_line=emitted.append,
        restore=restore,
    )
    assert status is None
    assert "".join(emitted) == "*filter\nCOMMIT\n"


def test_restore_domain_failure_message_lacks_trailing_newline() -> None:
    # errors.py contract: a FermError carries its message without the
    # trailing newline (the handler adds it); an embedded '\n' would
    # double-space the rollback path through cli.main.
    domain_info = DomainInfo(tools={"tables-restore": "false"})
    with pytest.raises(FermError) as excinfo:
        restore_domain(domain_info, "", Options())
    assert str(excinfo.value) == "Failed to run false"


def test_commit_fast_failure_prints_single_line(
    capfd: pytest.CaptureFixture[str],
) -> None:
    # The restore failure is reported once with exactly one newline; no
    # per-call-site end="" compensation.
    def restore(_info: DomainInfo, _save: str) -> None:
        raise FermError("Failed to run iptables-restore")

    domain_info = DomainInfo(tools={"tables-restore": "iptables-restore"})
    rendered = Rendered(save="*filter\nCOMMIT\n")
    status = IptablesBackend().commit(
        Family.IP,
        domain_info,
        rendered,
        Options(fast=True),
        execute=lambda _c: None,
        emit_line=lambda _t: None,
        restore=restore,
    )
    assert status == 1
    assert capfd.readouterr().err == "Failed to run iptables-restore\n"


def test_commit_fast_shell_wraps_heredoc() -> None:
    emitted: list[str] = []
    domain_info = DomainInfo(tools={"tables-restore": "iptables-restore"})
    rendered = Rendered(save="*filter\nCOMMIT\n")
    IptablesBackend().commit(
        Family.IP,
        domain_info,
        rendered,
        Options(fast=True, lines=True, noexec=True, shell=True),
        execute=lambda _c: None,
        emit_line=emitted.append,
        restore=lambda _i, _s: None,
    )
    text = "".join(emitted)
    assert text.startswith("iptables-restore <<EOT\n")
    assert text.endswith("EOT\n")


def test_commit_fast_noflush_prepends_restore_tool_in_heredoc() -> None:
    # Under --lines the restore command line is emitted only in the --shell
    # heredoc header; --noflush must *append* to the tool path ("iptables-
    # restore --noflush"), never replace it with a bare " --noflush".
    emitted: list[str] = []
    domain_info = DomainInfo(tools={"tables-restore": "iptables-restore"})
    rendered = Rendered(save="*filter\nCOMMIT\n")
    IptablesBackend().commit(
        Family.IP,
        domain_info,
        rendered,
        Options(fast=True, lines=True, noexec=True, shell=True, noflush=True),
        execute=lambda _c: None,
        emit_line=emitted.append,
        restore=lambda _i, _s: None,
    )
    assert "".join(emitted).startswith("iptables-restore --noflush <<EOT\n")


def test_commit_fast_forwards_domain_info_and_save_to_restore() -> None:
    # The execute path must hand the *real* domain_info and save text to
    # restore (not swap either for None); the rest of the suite stubs restore
    # with an arg-ignoring lambda, so pin the forwarding here.
    calls: list[tuple[object, object]] = []
    domain_info = DomainInfo(tools={"tables-restore": "iptables-restore"})
    rendered = Rendered(save="*filter\nCOMMIT\n")
    IptablesBackend().commit(
        Family.IP,
        domain_info,
        rendered,
        Options(fast=True),
        execute=lambda _c: None,
        emit_line=lambda _t: None,
        restore=lambda info, save: calls.append((info, save)),
    )
    assert calls == [(domain_info, "*filter\nCOMMIT\n")]


# --- rollback --------------------------------------------------------------


def test_rollback_skips_disabled_domain() -> None:
    def restore(_info: DomainInfo, _save: str) -> None:
        raise AssertionError("disabled domain must not be restored")

    IptablesBackend().rollback(
        Family.IP,
        DomainInfo(enabled=False),
        Options(),
        execute=lambda _c: None,
        restore=restore,
    )


def test_rollback_builds_reset_and_appends_previous() -> None:
    captured: list[str] = []

    domain_info = DomainInfo(
        enabled=True,
        tools={"tables-restore": "iptables-restore"},
        previous="*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
        tables={
            "filter": TableInfo(
                chains={
                    "INPUT": ChainInfo(builtin=True),
                    "custom": ChainInfo(),
                }
            )
        },
    )
    IptablesBackend().rollback(
        Family.IP,
        domain_info,
        Options(),
        execute=lambda _c: None,
        restore=lambda _i, save: captured.append(save),
    )
    reset = captured[0]
    # builtin chains reset to ACCEPT, custom chain skipped
    assert "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n" in reset
    assert "custom" not in reset.split("COMMIT")[0]
    # the captured previous ruleset is appended
    assert reset.endswith("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")


def test_rollback_without_restore_tool_warns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    IptablesBackend().rollback(
        Family.IP,
        DomainInfo(enabled=True, tools={"tables": "iptables"}),
        Options(),
        execute=lambda _c: None,
        restore=lambda _i, _s: None,
    )
    assert "Cannot rollback domain 'ip'" in capsys.readouterr().err


# --- read_previous (delegation) --------------------------------------------


def test_read_previous_delegates_to_domains() -> None:
    info = DomainInfo()
    save = IptablesBackend().read_previous(
        ["*filter\n", ":INPUT ACCEPT [0:0]\n", "COMMIT\n"], info
    )
    assert save == "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
    assert info.tables["filter"].chains["INPUT"].builtin is True


# --- restore_domain latin-1 encoding ---------------------------------------


def test_restore_domain_pipes_latin1_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # save.encode() with default utf-8 would turn U+00FF into two bytes
    # (0xc3 0xbf); latin-1 must preserve it as the single byte 0xff.
    sent: dict[str, object] = {}

    def fake_run(
        args: list[str],
        *,
        input: bytes,  # noqa: A002
        check: bool,  # noqa: ARG001
    ) -> subprocess.CompletedProcess[bytes]:
        sent["input"] = input
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("pyferm.backend.iptables.subprocess.run", fake_run)
    info = DomainInfo(tools={"tables-restore": "iptables-restore"})
    restore_domain(info, '-A INPUT --comment "\xff"\n', Options())
    assert sent["input"] == b'-A INPUT --comment "\xff"\n'


# --- capture_previous --------------------------------------------------------


def _fail_execute(_command: str) -> int | None:
    raise AssertionError("execute must not run on this branch")


def _fail_read_save(_tool: str) -> str | None:
    raise AssertionError("read_save must not run on this branch")


def test_capture_previous_reads_mock_previous(tmp_path: Path) -> None:
    mock = tmp_path / "ip.save"
    mock.write_bytes(b"*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")
    options = Options(test=True, mock_previous={"ip": str(mock)})
    info = DomainInfo(tools={"tables": "iptables"})

    IptablesBackend().capture_previous(
        Family.IP,
        info,
        options,
        execute=_fail_execute,
        read_save=_fail_read_save,
        capture=lambda _c: None,
    )

    assert info.previous == "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
    assert info.tables["filter"].chains["INPUT"].builtin is True


def test_capture_previous_mock_keeps_high_bytes(tmp_path: Path) -> None:
    mock = tmp_path / "ip.save"
    mock.write_bytes(b'*filter\n-A INPUT --comment "\xff"\nCOMMIT\n')
    options = Options(test=True, mock_previous={"ip": str(mock)})
    info = DomainInfo()

    IptablesBackend().capture_previous(
        Family.IP,
        info,
        options,
        execute=_fail_execute,
        read_save=_fail_read_save,
        capture=lambda _c: None,
    )

    assert info.previous is not None
    assert '"\xff"' in info.previous


def test_capture_previous_missing_mock_is_ferm_error() -> None:
    # Perl: `open ... or die $!` (:948) -- check_domain locates the
    # FermError; a raw OSError would escape as a traceback.
    options = Options(test=True, mock_previous={"ip": "/nonexistent/save"})
    with pytest.raises(FermError, match="No such file or directory"):
        IptablesBackend().capture_previous(
            Family.IP,
            DomainInfo(),
            options,
            execute=_fail_execute,
            read_save=_fail_read_save,
            capture=lambda _c: None,
        )


def test_capture_previous_live_reads_save_tool() -> None:
    seen: list[str] = []

    def read_save(tool: str) -> str | None:
        seen.append(tool)
        return "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"

    info = DomainInfo(
        tools={"tables": "iptables", "tables-save": "iptables-save"}
    )
    IptablesBackend().capture_previous(
        Family.IP,
        info,
        Options(),
        execute=_fail_execute,
        read_save=read_save,
        capture=lambda _c: None,
    )

    assert seen == ["iptables-save"]
    assert info.previous == "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n"
    assert info.tables["filter"].has_builtin is True


def test_capture_previous_live_unreadable_tool_leaves_previous_unset() -> None:
    info = DomainInfo(
        tools={"tables": "iptables", "tables-save": "iptables-save"}
    )
    IptablesBackend().capture_previous(
        Family.IP,
        info,
        Options(),
        execute=_fail_execute,
        read_save=lambda _tool: None,
        capture=lambda _c: None,
    )
    assert info.previous is None


def test_capture_previous_eb_snapshots_each_table_in_order() -> None:
    calls: list[str] = []

    def execute(command: str) -> int | None:
        calls.append(command)
        return None

    info = DomainInfo(tools={"tables": "ebtables"})
    # --test does NOT skip the eb snapshot (golden eb runs rely on it;
    # the random tempfile names are normalized by tests/golden/normalize.py)
    IptablesBackend().capture_previous(
        Family.EB,
        info,
        Options(test=True),
        execute=execute,
        read_save=_fail_read_save,
        capture=lambda _c: None,
    )
    try:
        assert list(info.ebt_previous) == list(EB_TABLES)
        assert [c.split(" -t ")[1].split()[0] for c in calls] == list(
            EB_TABLES
        )
        assert all("--atomic-save" in c for c in calls)
    finally:
        info.close()


def test_capture_previous_live_without_save_tool_skips_to_eb() -> None:
    calls: list[str] = []

    def execute(command: str) -> int | None:
        calls.append(command)
        return None

    info = DomainInfo(tools={"tables": "ebtables"})
    # live eb has no *-save tool: no read, straight to the atomic snapshot
    IptablesBackend().capture_previous(
        Family.EB,
        info,
        Options(),
        execute=execute,
        read_save=_fail_read_save,
        capture=lambda _c: None,
    )
    try:
        assert info.previous is None
        assert list(info.ebt_previous) == list(EB_TABLES)
    finally:
        info.close()


# --- tool_names --------------------------------------------------------------


def test_tool_names_ip_family_has_save_restore() -> None:
    names = IptablesBackend().tool_names(Family.IP)
    assert names == {
        "tables": "iptables",
        "tables-save": "iptables-save",
        "tables-restore": "iptables-restore",
    }


def test_tool_names_eb_family_tables_only() -> None:
    assert IptablesBackend().tool_names(Family.EB) == {"tables": "ebtables"}


# --- shell_snapshot (moved from test_domains, finding C2) -------------------


def test_shell_snapshot_embeds_the_save_and_restore_tools() -> None:
    # The x_tables snapshot pipes *-save into a tempfile and replays it
    # through *-restore; both tool paths come from the domain's tools.
    info = DomainInfo()
    info.tools = {
        "tables-save": "iptables-save",
        "tables-restore": "iptables-restore",
    }
    assert IptablesBackend().shell_snapshot(Family.IP, info) == ShellSnapshot(
        setup=(
            "ip_tmp=$(mktemp ferm.XXXXXXXXXX)\n",
            "iptables-save >$ip_tmp\n",
        ),
        restore="iptables-restore <$ip_tmp\n",
    )


def test_shell_snapshot_without_xtables_tooling_is_none() -> None:
    # arp/eb have no *-save/*-restore pair, so the snapshot is skipped
    # rather than built from a missing tool.
    info = DomainInfo()
    info.tools = {"tables": "ebtables"}
    assert IptablesBackend().shell_snapshot(Family.EB, info) is None


def test_shell_snapshot_needs_both_tools_not_just_one() -> None:
    # the guard is "save OR restore missing -> None"; one half present is
    # still not enough to snapshot (pins the boolean, not just both-absent).
    save_only = DomainInfo()
    save_only.tools = {"tables-save": "iptables-save"}
    assert IptablesBackend().shell_snapshot(Family.IP, save_only) is None
    restore_only = DomainInfo()
    restore_only.tools = {"tables-restore": "iptables-restore"}
    assert IptablesBackend().shell_snapshot(Family.IP, restore_only) is None


# --- capture_previous plan guard -------------------------------------------


def _noop_execute(_cmd: str) -> None:
    raise AssertionError("execute must not run under --plan for eb/arp")


@pytest.mark.parametrize("domain", [Family.EB, Family.ARP])
def test_capture_previous_plan_guard_marks_unsupported(domain: Family) -> None:
    # Under --plan, arp/eb families must not trigger the atomic-save side
    # effect and must set plan_unsupported so the cli can report them.
    backend = IptablesBackend()
    tool = "ebtables" if domain == "eb" else "arptables"
    info = DomainInfo(tools={"tables": tool})
    backend.capture_previous(
        domain,
        info,
        Options(plan=True),
        execute=_noop_execute,
        read_save=lambda _t: "",
        capture=lambda _c: None,
    )
    assert info.plan_unsupported is True
    assert info.ebt_previous == {}


def test_capture_previous_plan_leaves_ip_supported() -> None:
    # ip/ip6 have a *-save tool so they are fully supported under --plan;
    # plan_unsupported must remain False and previous must be populated.
    backend = IptablesBackend()
    info = DomainInfo(tools={"tables-save": "iptables-save"})
    backend.capture_previous(
        Family.IP,
        info,
        Options(plan=True),
        execute=lambda _c: None,
        read_save=lambda _t: "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n",
        capture=lambda _c: None,
    )
    assert info.plan_unsupported is False
    assert info.previous is not None


# ---------------------------------------------------------------------------
# _validate_chain_name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "good", ["INPUT", "fail2ban-ssh", "9foo", "_foo", "chain.x", "a+b"]
)
def test_validate_chain_name_accepts_iptables_legal(good: str) -> None:
    assert _validate_chain_name(good) == good


@pytest.mark.parametrize(
    "bad",
    ["evil chain", "Y DROP [0:0]", "a:b", "a*b", "a\tb", "a\nb", "", "x\x01y"],
)
def test_validate_chain_name_rejects_separators(bad: str) -> None:
    with pytest.raises(FermError):
        _validate_chain_name(bad)


#: Whitespace-free shell metacharacters: these slip past a save-grammar
#: blacklist but reach ``/bin/sh`` on the slow path (eb/arp are slow by
#: default), so a name like ``x;reboot`` is command injection as root.
@pytest.mark.parametrize(
    "bad",
    [
        "x;reboot",
        "x$(reboot)",
        "x`reboot`",
        "x|y",
        "x&y",
        "x#y",
        "x>y",
        "x(y)",
    ],
)
def test_validate_chain_name_rejects_shell_metachars(bad: str) -> None:
    with pytest.raises(FermError):
        _validate_chain_name(bad)


def _run_ipt(src: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # fixed argv, no shell
        [sys.executable, "-m", "pyferm", "--test", "--noexec", "--lines", "-"],
        input=src,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


# ---------------------------------------------------------------------------
# _validate_table_name


@pytest.mark.parametrize("good", ["filter", "nat", "mangle", "my-table"])
def test_validate_table_name_accepts(good: str) -> None:
    assert _validate_table_name(good) == good


@pytest.mark.parametrize(
    "bad", ["filter foo", "a*b", "a\nb", "", "filter;reboot", "f$(reboot)"]
)
def test_validate_table_name_rejects(bad: str) -> None:
    with pytest.raises(FermError):
        _validate_table_name(bad)


# ---------------------------------------------------------------------------
# _validate_policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "good", ["ACCEPT", "DROP", "RETURN", "QUEUE", "-", None]
)
def test_validate_policy_accepts_whitelist(good: str | None) -> None:
    assert _validate_policy(good) == good


@pytest.mark.parametrize("bad", ["accept", "DROP; drop", "EVIL", "DROP\n"])
def test_validate_policy_rejects_others(bad: str) -> None:
    with pytest.raises(FermError):
        _validate_policy(bad)


def test_table_name_injection_is_rejected_end_to_end() -> None:
    # Currently emits "*filter foo" with rc=0 (injection).
    # Table names had no check before this fix.
    proc = _run_ipt(
        'domain ip table "filter foo" chain INPUT { policy DROP; }\n'
    )
    assert proc.returncode != 0
    assert "filter foo" in proc.stderr


def test_chain_name_injection_is_rejected_end_to_end() -> None:
    # Currently emits ":evil chain DROP [0:0]" with rc=0 (injection).
    proc = _run_ipt(
        'domain ip table filter chain "evil chain" { policy DROP; }\n'
    )
    assert proc.returncode != 0
    assert "evil chain" in proc.stderr


def test_chain_name_shell_injection_rejected_end_to_end() -> None:
    # eb/arp own no -restore tool -> slow path by default -> the raw name
    # reaches /bin/sh.  A whitespace-free metacharacter name must be refused
    # before any command string is built.
    proc = _run_ipt(
        "domain eb table filter chain 'x;reboot' { policy ACCEPT; }\n"
    )
    assert proc.returncode != 0
    assert "x;reboot" in proc.stderr


def test_chain_name_injection_rejected_on_plan_path(
    tmp_path: Path,
) -> None:
    # The --plan path calls rules_to_save directly; validate_names must
    # guard it too so a spaced chain name is rejected before save-text is
    # built (defense-in-depth on the read-only preview path).
    cfg = tmp_path / "inject.ferm"
    cfg.write_text(
        'domain ip table filter chain "evil chain" { policy DROP; }\n',
        encoding="utf-8",
    )
    proc = subprocess.run(  # fixed argv, no shell
        [sys.executable, "-m", "pyferm", "--plan", "--test", str(cfg)],
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode != 0
    assert "evil chain" in proc.stderr


# ===========================================================================
# Mutation-kill coverage for the emit/execute corners the flat-input tests
# leave equivalent: the slow command list ordering + guard/atomic framing,
# the fast save's header/preserve/flush branches, family-sensitive value
# formatting, and the rollback/capture command shapes.
# ===========================================================================

_ATOMIC_FILE_RE = re.compile(r"--atomic-file \S+")


def _norm(text: str) -> str:
    """Collapse the random atomic-file tempname so commands compare stably."""
    return _ATOMIC_FILE_RE.sub("--atomic-file TMP", text)


def _target_rule(name: str = "jump", value: str = "ACCEPT") -> RenderedRule:
    return RenderedRule(
        options=[RenderedOption(name, value, OptionKind.TARGET, None)],
        script=None,
    )


# --- _render_slow: exact command list + guard/atomic framing ---------------


def test_render_slow_full_command_list_and_walk_order() -> None:
    # Two tables, builtin + custom chains: pins the reset walk (-P builtins,
    # -F, -X), the create walk (-P for a non-ACCEPT builtin, -N/-N -P for
    # custom chains) and the rule walk, in oracle order.
    domain_info = DomainInfo(
        tools={"tables": "iptables"},
        tables={
            "filter": TableInfo(
                chains={
                    "INPUT": ChainInfo(
                        builtin=True, policy="ACCEPT", rules=[_target_rule()]
                    ),
                    "FORWARD": ChainInfo(builtin=True, policy="DROP"),
                    "web": ChainInfo(policy="DROP"),
                    "misc": ChainInfo(),
                }
            ),
            "nat": TableInfo(chains={"PREROUTING": ChainInfo(builtin=True)}),
        },
    )
    rendered = IptablesBackend().render(Family.IP, domain_info, _SLOW)
    try:
        assert [(c.text, c.guarded) for c in rendered.commands] == [
            ("iptables -t filter -P INPUT ACCEPT", True),
            ("iptables -t filter -P FORWARD ACCEPT", True),
            ("iptables -t filter -F", True),
            ("iptables -t filter -X", True),
            ("iptables -t filter -P FORWARD DROP", True),
            ("iptables -t filter -N web -P DROP", True),
            ("iptables -t filter -N misc", True),
            ("iptables -t filter -A INPUT --jump ACCEPT", True),
            ("iptables -t nat -P PREROUTING ACCEPT", True),
            ("iptables -t nat -F", True),
            ("iptables -t nat -X", True),
        ]
    finally:
        rendered.close()


def test_render_slow_auto_detects_builtin_without_flag() -> None:
    # has_builtin is False and INPUT is not flagged builtin, so the
    # name-based auto-detect must still treat INPUT as a builtin: it is reset
    # to ACCEPT and its non-default policy is applied with -P (not -N).
    domain_info = DomainInfo(
        tools={"tables": "iptables"},
        tables={
            "filter": TableInfo(
                has_builtin=False,
                chains={
                    "INPUT": ChainInfo(
                        builtin=False, policy="DROP", rules=[_target_rule()]
                    ),
                    "custom": ChainInfo(),
                },
            )
        },
    )
    rendered = IptablesBackend().render(Family.IP, domain_info, _SLOW)
    try:
        assert [c.text for c in rendered.commands] == [
            "iptables -t filter -P INPUT ACCEPT",
            "iptables -t filter -F",
            "iptables -t filter -X",
            "iptables -t filter -P INPUT DROP",
            "iptables -t filter -N custom",
            "iptables -t filter -A INPUT --jump ACCEPT",
        ]
    finally:
        rendered.close()


def test_render_slow_resets_builtin_after_a_leading_custom_chain() -> None:
    # A non-builtin chain sorted/declared BEFORE a builtin one must not stop
    # the reset walk (continue, not break): the builtin's -P line survives.
    domain_info = DomainInfo(
        tools={"tables": "iptables"},
        tables={
            "filter": TableInfo(
                chains={
                    "achain": ChainInfo(),
                    "INPUT": ChainInfo(builtin=True),
                }
            )
        },
    )
    rendered = IptablesBackend().render(Family.IP, domain_info, _SLOW)
    try:
        reset = [c.text for c in rendered.commands if " -P " in c.text]
        assert reset == ["iptables -t filter -P INPUT ACCEPT"]
    finally:
        rendered.close()


def test_render_slow_ip6_reject_maps_to_icmp6() -> None:
    # The ip6 slow path (arp/eb-style: no *-restore tool) still formats each
    # rule with the family, so reject-with maps to the icmp6 name.
    domain_info = DomainInfo(
        tools={"tables": "ip6tables"},
        tables={
            "filter": TableInfo(
                chains={
                    "INPUT": ChainInfo(
                        builtin=True,
                        rules=[
                            _target_rule(
                                "reject-with", "icmp-port-unreachable"
                            )
                        ],
                    )
                }
            )
        },
    )
    rendered = IptablesBackend().render(Family.IP6, domain_info, _SLOW)
    try:
        rule_lines = [
            c.text for c in rendered.commands if "-A INPUT" in c.text
        ]
        assert rule_lines == [
            "ip6tables -t filter -A INPUT --reject-with icmp6-port-unreachable"
        ]
    finally:
        rendered.close()


def test_render_slow_flush_still_walks_every_table() -> None:
    # Under --flush each table emits only its reset/-F/-X then is skipped
    # (continue, not break): a second table must still be walked.
    domain_info = DomainInfo(
        tools={"tables": "iptables"},
        tables={
            "filter": TableInfo(
                chains={
                    "INPUT": ChainInfo(builtin=True, rules=[_target_rule()])
                }
            ),
            "nat": TableInfo(chains={"PREROUTING": ChainInfo(builtin=True)}),
        },
    )
    rendered = IptablesBackend().render(
        Family.IP, domain_info, Options(fast=False, flush=True)
    )
    try:
        assert [c.text for c in rendered.commands] == [
            "iptables -t filter -P INPUT ACCEPT",
            "iptables -t filter -F",
            "iptables -t filter -X",
            "iptables -t nat -P PREROUTING ACCEPT",
            "iptables -t nat -F",
            "iptables -t nat -X",
        ]
    finally:
        rendered.close()


def test_render_slow_eb_full_framing_and_guard_flags() -> None:
    # The eb atomic init/commit framing is unguarded; the per-table walk is
    # guarded.  Pins the exact command sequence (names normalized) and every
    # guard flag, so a mutant flipping a framing command to guarded, dropping
    # the "eb" branch, or nulling a command is caught.
    domain_info = DomainInfo(
        tools={"tables": "ebtables"},
        tables={
            "filter": TableInfo(
                chains={
                    "INPUT": ChainInfo(builtin=True, rules=[_target_rule()])
                }
            )
        },
    )
    rendered = IptablesBackend().render(Family.EB, domain_info, _SLOW)
    try:
        assert [(_norm(c.text), c.guarded) for c in rendered.commands] == [
            ("ebtables -t filter --atomic-file TMP --atomic-init", False),
            ("ebtables -t filter --atomic-file TMP --init-table", False),
            ("ebtables -t nat --atomic-file TMP --atomic-init", False),
            ("ebtables -t nat --atomic-file TMP --init-table", False),
            ("ebtables -t broute --atomic-file TMP --atomic-init", False),
            ("ebtables -t broute --atomic-file TMP --init-table", False),
            ("ebtables -t filter --atomic-file TMP -P INPUT ACCEPT", True),
            ("ebtables -t filter --atomic-file TMP -F", True),
            ("ebtables -t filter --atomic-file TMP -X", True),
            (
                "ebtables -t filter --atomic-file TMP -A INPUT --jump ACCEPT",
                True,
            ),
            ("ebtables -t filter --atomic-file TMP --atomic-commit", False),
            ("ebtables -t nat --atomic-file TMP --atomic-commit", False),
            ("ebtables -t broute --atomic-file TMP --atomic-commit", False),
        ]
    finally:
        rendered.close()


# --- rules_to_save: header, ip6 mapping, preserve + flush branches ----------


def _reject_ip6_domain() -> DomainInfo:
    return DomainInfo(
        tools={
            "tables-save": "ip6tables-save",
            "tables-restore": "ip6tables-restore",
        },
        tables={
            "filter": TableInfo(
                chains={
                    "INPUT": ChainInfo(
                        builtin=True,
                        rules=[
                            _target_rule(
                                "reject-with", "icmp-port-unreachable"
                            )
                        ],
                    )
                }
            )
        },
    )


def test_rules_to_save_header_carries_when_stamp() -> None:
    save = rules_to_save(
        Family.IP, _reject_ip6_domain(), Options(), now="WHEN"
    )
    from pyferm import __version__

    assert save.splitlines()[0] == (
        f"# Generated by ferm {__version__} (ip6tables-save) on WHEN"
    )


def test_rules_to_save_ip6_reject_maps_to_icmp6() -> None:
    save = rules_to_save(
        Family.IP6, _reject_ip6_domain(), Options(), now="WHEN"
    )
    assert "-A INPUT --reject-with icmp6-port-unreachable" in save.splitlines()


def test_render_fast_ip6_reject_maps_to_icmp6() -> None:
    # render() -> rules_to_save must pass the family through, so the fast save
    # carries the icmp6 name (a mutant nulling the family gives icmp-...).
    rendered = IptablesBackend().render(
        Family.IP6, _reject_ip6_domain(), Options()
    )
    try:
        assert rendered.save is not None
        assert "-A INPUT --reject-with icmp6-port-unreachable" in rendered.save
    finally:
        rendered.close()


_PREV_DISTINCT = (
    "*filter\n"
    ":INPUT ACCEPT [0:0]\n"
    ":docker DROP [7:8]\n"
    "-A docker -j RETURN\n"
    "COMMIT\n"
)


def test_rules_to_save_copies_preserve_policy_line_verbatim() -> None:
    # Two preserve chains: 'docker' exists in the previous dump with a
    # DISTINCTIVE policy line (DROP [7:8]) that is copied verbatim, and 'zzz'
    # is absent so it is synthesized to '-'.  Both must appear (no break after
    # the first), and the copied line must not be re-synthesized to
    # ':docker - [0:0]'.
    table_info = TableInfo(
        chains={
            "INPUT": ChainInfo(builtin=True),
            "docker": ChainInfo(preserve=True),
            "zzz": ChainInfo(preserve=True),
        }
    )
    table_info.preserve_regexes = [re.compile("docker"), re.compile("zzz")]
    domain_info = DomainInfo(
        tools={
            "tables-save": "iptables-save",
            "tables-restore": "iptables-restore",
        },
        previous=_PREV_DISTINCT,
        tables={"filter": table_info},
    )
    save = rules_to_save(Family.IP, domain_info, Options(), now="WHEN")
    # Assert the exact body (everything after the version header line): a
    # mutant that RESETS `result` at the copied line instead of appending
    # would silently drop the header/``*filter``/``:INPUT`` prefix, which a
    # membership check would miss.
    body = save.split("\n", 1)[1]
    assert body == (
        "*filter\n"
        ":INPUT ACCEPT [0:0]\n"
        ":docker DROP [7:8]\n"
        ":zzz - [0:0]\n"
        "-A docker -j RETURN\n"
        "COMMIT\n"
    )


def test_rules_to_save_flush_keeps_builtin_before_custom() -> None:
    # Under --flush a custom chain 'AAA' sorts before the builtin 'INPUT';
    # the policy walk must continue past the custom (which flush drops) so
    # INPUT's synthesized ACCEPT line survives (a break would lose it).
    domain_info = DomainInfo(
        tools={
            "tables-save": "iptables-save",
            "tables-restore": "iptables-restore",
        },
        tables={
            "filter": TableInfo(
                has_builtin=True,
                chains={"AAA": ChainInfo(), "INPUT": ChainInfo(builtin=True)},
            )
        },
    )
    save = rules_to_save(Family.IP, domain_info, Options(flush=True), now="W")
    chain_lines = [line for line in save.splitlines() if line.startswith(":")]
    assert chain_lines == [":INPUT ACCEPT [0:0]"]


# --- table_to_save: preserved text + rules, flush, ip6, fast quoting -------


def _dport_rule(port: str) -> RenderedRule:
    return RenderedRule(
        options=[RenderedOption("dport", port, OptionKind.OPTION, None)],
        script=None,
    )


def test_table_to_save_prepends_preserved_then_rules() -> None:
    chains = {
        "a": ChainInfo(rules=[_dport_rule("1")]),
        "b": ChainInfo(rules=[_dport_rule("2")]),
    }
    out = table_to_save(
        Family.IP, chains, Options(), {"a": "PA\n", "b": "PB\n"}
    )
    assert out == "PA\n-A a --dport 1\nPB\n-A b --dport 2\n"


def test_table_to_save_flush_keeps_preserved_drops_rules() -> None:
    chains = {
        "a": ChainInfo(rules=[_dport_rule("1")]),
        "b": ChainInfo(rules=[_dport_rule("2")]),
    }
    out = table_to_save(
        Family.IP, chains, Options(flush=True), {"a": "PA\n", "b": "PB\n"}
    )
    assert out == "PA\nPB\n"


def test_table_to_save_ip6_reject_maps_to_icmp6() -> None:
    chains = {
        "INPUT": ChainInfo(
            rules=[_target_rule("reject-with", "icmp-port-unreachable")]
        )
    }
    out = table_to_save(Family.IP6, chains, Options(), {})
    assert out == "-A INPUT --reject-with icmp6-port-unreachable\n"


def test_table_to_save_uses_fast_quoting_for_special_chars() -> None:
    # The save path always quotes fast-mode (double quotes), so a ';' in a
    # value is wrapped as "a;b" -- never slow-mode single quotes.
    chains = {
        "c": ChainInfo(
            rules=[
                RenderedRule(
                    options=[
                        RenderedOption(
                            "comment", "a;b", OptionKind.OPTION, None
                        )
                    ],
                    script=None,
                )
            ]
        )
    }
    out = table_to_save(Family.IP, chains, Options(), {})
    assert out == '-A c --comment "a;b"\n'


# --- shell_format_option: negation + fast-quoting corners ------------------


def test_shell_format_option_negated_array_takes_first_element() -> None:
    # A negated ARRAY (address_magic) collapses to its first element, kept
    # verbatim: " ! --k a", never a bare flag or the second element.
    assert (
        shell_format_option("k", Negated(["a", "b"]), fast=True) == " ! --k a"
    )


def test_shell_format_option_negated_flag_keeps_bang() -> None:
    # A negated None is a negated flag: the " !" prefix must survive.
    assert shell_format_option("k", Negated(None), fast=True) == " ! --k"


def test_shell_format_option_negated_params_keeps_bang() -> None:
    assert (
        shell_format_option("k", Negated(Params(["a", "b"])), fast=True)
        == " ! --k a b"
    )


def test_shell_format_option_params_special_chars_fast_quoted() -> None:
    assert shell_format_option("k", Params(["a;b"]), fast=True) == ' --k "a;b"'


def test_shell_format_option_multi_special_chars_fast_quoted() -> None:
    assert shell_format_option("k", Multi(["a;b"]), fast=True) == ' --k "a;b"'


# --- format_option / format_rule family guards -----------------------------


def test_format_option_ip_family_leaves_reject_with_unmapped() -> None:
    # The icmp6 reject map is gated on domain == "ip6" AND name; the ip family
    # must pass reject-with through untouched (a mutated OR would map it).
    assert (
        format_option(
            Family.IP, "reject-with", "icmp-port-unreachable", fast=True
        )
        == " --reject-with icmp-port-unreachable"
    )


def test_format_rule_ip6_maps_reject_with() -> None:
    rule = _target_rule("reject-with", "icmp-port-unreachable")
    assert (
        format_rule(Family.IP6, rule, fast=True)
        == " --reject-with icmp6-port-unreachable"
    )


# --- extract_chain_from_table_save: multi-match join -----------------------


def test_extract_chain_joins_matches_without_separator() -> None:
    # Two -A lines for the same chain are concatenated with no separator
    # between them (a mutated join would splice in stray text).
    body = "-A INPUT -j A\n-A OUTPUT -j B\n-A INPUT -j C\n"
    assert extract_chain_from_table_save(body, "INPUT") == (
        "-A INPUT -j A\n-A INPUT -j C\n"
    )


# --- validate_names: policy gate -------------------------------------------


def test_validate_names_rejects_bad_chain_policy() -> None:
    # validate_names must check each chain's OWN policy; a mutant validating
    # a constant None would silently accept a bogus policy.
    domain_info = DomainInfo(
        tools={},
        tables={
            "filter": TableInfo(
                chains={"INPUT": ChainInfo(builtin=True, policy="BOGUSPOL")}
            )
        },
    )
    with pytest.raises(FermError, match="BOGUSPOL"):
        validate_names(domain_info)


# --- rollback: full reset text + eb commits + capture ----------------------


def test_rollback_ip_resets_every_builtin_across_tables() -> None:
    captured: list[tuple[object, str]] = []
    domain_info = DomainInfo(
        enabled=True,
        tools={"tables-restore": "iptables-restore"},
        previous="PREVIOUS\n",
        tables={
            "filter": TableInfo(
                chains={
                    "INPUT": ChainInfo(builtin=True),
                    "OUTPUT": ChainInfo(builtin=True),
                    "custom": ChainInfo(),
                }
            ),
            "nat": TableInfo(chains={"PREROUTING": ChainInfo(builtin=True)}),
        },
    )
    IptablesBackend().rollback(
        Family.IP,
        domain_info,
        Options(),
        execute=lambda _c: None,
        restore=lambda info, save: captured.append((info, save)),
    )
    assert captured == [
        (
            domain_info,
            "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
            "*nat\n:PREROUTING ACCEPT [0:0]\nCOMMIT\n"
            "PREVIOUS\n",
        )
    ]


def test_rollback_eb_commits_each_previous_snapshot() -> None:
    calls: list[str] = []
    domain_info = DomainInfo(
        tools={"tables": "ebtables"},
        enabled=True,
        tables={"filter": TableInfo(chains={})},
    )
    for table in EB_TABLES:
        domain_info.ebt_previous[table] = tempfile.NamedTemporaryFile(  # noqa: SIM115
            prefix="ferm."
        )
    try:
        IptablesBackend().rollback(
            Family.EB,
            domain_info,
            Options(),
            execute=calls.append,
            restore=lambda _i, _s: pytest.fail("eb rollback must not restore"),
        )
        # Assert the exact per-table atomic-file path (from the snapshot the
        # rollback commits), not a normalized placeholder: a mutant that nulls
        # the name to ``None`` would still match a normalized ``TMP``.
        assert calls == [
            f"ebtables -t {table} "
            f"--atomic-file {domain_info.ebt_previous[table].name} "
            "--atomic-commit"
            for table in EB_TABLES
        ]
    finally:
        for handle in domain_info.ebt_previous.values():
            handle.close()


def test_capture_previous_eb_atomic_save_commands_are_ebtables() -> None:
    # The eb snapshot must name the ebtables tool (a mutant nulling the tool
    # command would emit "None -t ...").
    calls: list[str] = []
    info = DomainInfo(tools={"tables": "ebtables"}, enabled=True)
    try:
        IptablesBackend().capture_previous(
            Family.EB,
            info,
            Options(test=True),
            execute=lambda c: calls.append(_norm(c)),
            read_save=lambda _t: None,
            capture=lambda _c: None,
        )
        assert calls == [
            "ebtables -t filter --atomic-file TMP --atomic-save",
            "ebtables -t nat --atomic-file TMP --atomic-save",
            "ebtables -t broute --atomic-file TMP --atomic-save",
        ]
    finally:
        info.close()


# --- restore_domain: argv construction -------------------------------------


def test_restore_domain_appends_noflush_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # --noflush appends a distinct argv element to the restore tool path; the
    # command runs with check=False (ferm maps the exit code itself).
    seen: dict[str, object] = {}

    def fake_run(
        args: list[str],
        *,
        input: bytes,  # noqa: A002, ARG001
        check: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        seen["args"] = list(args)
        seen["check"] = check
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("pyferm.backend.iptables.subprocess.run", fake_run)
    info = DomainInfo(tools={"tables-restore": "iptables-restore"})
    restore_domain(info, "SAVE\n", Options(noflush=True))
    assert seen["args"] == ["iptables-restore", "--noflush"]
    assert seen["check"] is False


def test_restore_domain_without_noflush_is_bare_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_run(
        args: list[str],
        *,
        input: bytes,  # noqa: A002, ARG001
        check: bool,  # noqa: ARG001
    ) -> subprocess.CompletedProcess[bytes]:
        seen["args"] = list(args)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr("pyferm.backend.iptables.subprocess.run", fake_run)
    info = DomainInfo(tools={"tables-restore": "iptables-restore"})
    restore_domain(info, "SAVE\n", Options())
    assert seen["args"] == ["iptables-restore"]
