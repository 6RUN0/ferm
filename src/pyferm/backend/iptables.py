"""
The iptables family backend: format, render, commit, rollback.

Faithful port of ferm's emit/execute layer (``reference/src/ferm``) for the
``ip``/``ip6``/``arp``/``eb`` families: ``shell_escape`` (``:1806``),
``shell_format_option`` (``:1832``), ``format_option`` (``:1863``),
``rules_to_save``/``table_to_save`` and the dynamic-preserve helpers
(``:2997-3101``), ``execute_slow``/``execute_fast``/``rollback``
(``:2919-3183``).

**Render/commit split (sanctioned deviations #1 and #3).**  In the oracle the
per-value formatter is called *inside* rule assembly (``mkrules2``/
``unfold_rule`` write ``$option->[2]``) and execution is fused with command
building (``execute_slow`` runs each command as it walks the tables).  This
port moves both seams here: :func:`format_option` formats one value at
save/command-build time (the kernel keeps the value structural), and
:meth:`IptablesBackend.render` builds the artifact while
:meth:`IptablesBackend.commit` runs it.  Because formatting is deferred, the
save/command builders need the family (``domain``) the oracle did not -- it
formatted before this point.
"""

from __future__ import annotations

import re
import subprocess  # live-only: restore pipes a save to *-restore
import sys
import tempfile
import time
from pathlib import Path
from typing import IO, TYPE_CHECKING

from pyferm import __version__
from pyferm.backend.base import (
    Backend,
    Command,
    ExecuteCommand,
    LineEmitter,
    Rendered,
    RestoreDomain,
    SaveReader,
)
from pyferm.domains import (
    EB_TABLES,
    TOOL_RESTORE,
    TOOL_SAVE,
    TOOL_TABLES,
    ChainInfo,
    DomainInfo,
    TableInfo,
)
from pyferm.domains import (
    read_previous as _domains_read_previous,
)
from pyferm.errors import FermError, internal_error
from pyferm.rules import RenderedRule, is_netfilter_builtin_chain
from pyferm.streams import BYTE_ENCODING
from pyferm.values import Deferred, Multi, Negated, Params, PreNegated, Value

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pyferm.config import Options

#: A token needing no quoting (Perl ``:1809``); ``$`` allows a trailing
#: newline exactly as Perl's ``$`` does.
_PLAIN_TOKEN_RE = re.compile(r"[-_a-zA-Z0-9]+$")
#: An already-quoted backtick command (slow mode only, ``:1821``).
_BACKTICK_RE = re.compile(r"`.*`$")
#: Characters forcing double-quoting in fast (``iptables-restore``) mode
#: (``:1818``).  ``re.ASCII``: Perl's byte-mode ``\s`` is
#: ``[ \t\n\r\f\x0B]``; Python's Unicode ``\s`` would also match
#: ``\x1c``-``\x1f`` and quote tokens the oracle leaves bare (found by
#: the differential fuzzer).
_FAST_SPECIAL_RE = re.compile(r"[\s'\\;&]", re.ASCII)
#: Characters forcing single-quoting in slow (per-command) mode (``:1824``);
#: ``re.ASCII`` for the same reason as above.
_SLOW_SPECIAL_RE = re.compile(r'[\s"\\;<>&|]', re.ASCII)

#: ip6 ``reject-with`` value translation (``:1871-1878``); several IPv4 names
#: collapse onto ``icmp6-adm-prohibited``.
_ICMP6_REJECT_MAP = {
    "icmp-net-unreachable": "icmp6-no-route",
    "icmp-host-unreachable": "icmp6-addr-unreachable",
    "icmp-port-unreachable": "icmp6-port-unreachable",
    "icmp-net-prohibited": "icmp6-adm-prohibited",
    "icmp-host-prohibited": "icmp6-adm-prohibited",
    "icmp-admin-prohibited": "icmp6-adm-prohibited",
}


def _scalar(value: Value) -> str:
    """
    Narrow a ``params``/``multi`` element to a scalar string.

    The oracle treats these elements as plain scalars (``shell_escape`` is a
    string op); a non-scalar is an internal error (bare ``die``).
    """
    if not isinstance(value, str):
        raise internal_error()
    return value


def shell_escape(token: str, *, fast: bool) -> str:
    """
    Quote a token for a shell/restore command line (Perl ``:1806``).

    A bare word (``[-_a-zA-Z0-9]+``) is returned unchanged.  Otherwise the
    quoting differs by mode: fast (``iptables-restore``) double-quotes and
    escapes ``"``; slow (per-command) single-quotes, escapes ``'`` and leaves
    an already-backticked command untouched.  ``fast`` is the oracle's
    ``$option{fast}``.
    """
    if _PLAIN_TOKEN_RE.match(token):
        return token

    if fast:
        token = token.replace('"', '\\"')
        if _FAST_SPECIAL_RE.search(token) or len(token) == 0:
            token = '"' + token + '"'
    else:
        if _BACKTICK_RE.match(token):
            return token
        token = token.replace("'", "'\\''")
        if _SLOW_SPECIAL_RE.search(token) or len(token) == 0:
            token = "'" + token + "'"

    return token


def shell_format_option(keyword: str, value: Value, *, fast: bool) -> str:
    """
    Format one option as ``--keyword`` text (Perl ``:1832``).

    The single string builder.  A leading ``negated``/``pre_negated`` tag emits
    ``" !"`` (both render the same -- the distinction is parse-time only); the
    unwrapped value then branches: ``None`` -> a bare flag; ``params`` -> one
    ``--keyword`` with several escaped args; ``multi`` -> ``--keyword``
    repeated per value; a scalar -> ``--keyword`` plus the escaped value.  Any
    other ref is an internal error, exactly as the oracle's bare ``die``.
    """
    cmd = ""
    if isinstance(value, (Negated, PreNegated)):
        # Perl's negated/pre_negated is a blessed ARRAY ref unwrapped with
        # ``$value = $value->[0]`` (:1838).  ``negate_value`` blesses
        # ``[$value]`` so the payload is a scalar, but ``address_magic``
        # blesses the realized address array directly (:577); ``->[0]`` then
        # collapses it to its first element, silently dropping the rest
        # exactly as the oracle does.  An empty array yields undef -> a flag.
        inner = value.value
        if isinstance(inner, list):
            value = inner[0] if inner else None
        else:
            value = inner
        cmd = " !"

    if value is None:
        cmd += f" --{keyword}"
    elif isinstance(value, Params):
        cmd += f" --{keyword} "
        cmd += " ".join(
            shell_escape(_scalar(v), fast=fast) for v in value.values
        )
    elif isinstance(value, Multi):
        for item in value.values:
            cmd += f" --{keyword} " + shell_escape(_scalar(item), fast=fast)
    elif isinstance(value, (list, Negated, PreNegated, Deferred)):
        raise internal_error()
    else:
        cmd += f" --{keyword} " + shell_escape(value, fast=fast)

    return cmd


def format_option(domain: str, name: str, value: Value, *, fast: bool) -> str:
    """
    Apply family-specific substitutions, then format (Perl ``:1863``).

    For ``ip6`` only: protocol ``icmp`` becomes ``icmpv6``, the ``icmp-type``
    keyword becomes ``icmpv6-type``, and ``reject-with`` values are mapped via
    :data:`_ICMP6_REJECT_MAP`.  The reject map is consulted only for scalar
    values; a tagged value passes through unchanged (the oracle's ``exists
    $icmp_map{$value}`` never matches a stringified ref).
    """
    if domain == "ip6" and name == "protocol" and value == "icmp":
        value = "icmpv6"
    if domain == "ip6" and name == "icmp-type":
        name = "icmpv6-type"
    if domain == "ip6" and name == "reject-with" and isinstance(value, str):
        value = _ICMP6_REJECT_MAP.get(value, value)

    return shell_format_option(name, value, fast=fast)


def format_rule(domain: str, rule: RenderedRule, *, fast: bool) -> str:
    """
    Join a rule's options into one command tail (Perl ``append_rule``).

    The analog of the oracle's ``join('', map { $_->[2] } ...)`` (``:1888``),
    but it formats each option here (the value was kept structural in the
    kernel) instead of reading a pre-rendered slot.  Each option contributes a
    leading-space chunk, so the result appends cleanly after ``-A CHAIN``.
    """
    return "".join(
        format_option(domain, option.name, option.value, fast=fast)
        for option in rule.options
    )


def extract_table_from_save(save: str, table: str) -> str:
    r"""
    Return a table's body from a save dump, else ``""`` (Perl ``:3014``).

    Faithfully reproduces the oracle regex, including its
    ``${\}``-interpolates-to-nothing quirk that leaves a stray ``s*``
    (zero-or-more literal ``s``) after the header.  The body runs to
    ``^COMMIT``.
    """
    match = re.search(
        rf"^\*{table}\s*s*(.*?)^COMMIT\s*$", save, re.MULTILINE | re.DOTALL
    )
    return match.group(1) if match else ""


def extract_chain_from_table_save(table_save: str, chain: str) -> str:
    """Return every ``-A CHAIN ...`` line for ``chain`` (Perl ``:3021``)."""
    pattern = re.compile(r"^-A " + re.escape(chain) + r" .*\n", re.MULTILINE)
    return "".join(match.group(0) for match in pattern.finditer(table_save))


def resolve_dynamic_preserve(
    table_info: TableInfo, table_save: str
) -> dict[str, ChainInfo]:
    """
    Collect preserve-matched chains from a save dump (Perl ``:3030``).

    For each ``:CHAIN`` in ``table_save`` not already known, if it matches any
    of the table's ``preserve_regexes`` it is returned with the preserve flag
    set, so ``rules_to_save`` copies its rules verbatim.  The oracle writes
    the additions into the global ``%domains``; this port returns them so
    :meth:`Backend.render` stays pure (deviation #3).
    """
    added: dict[str, ChainInfo] = {}
    for match in re.finditer(r"^:([^ ]+) .*", table_save, re.MULTILINE):
        chain = match.group(1)
        if chain in table_info.chains:
            continue
        for regex in table_info.preserve_regexes:
            if regex.search(chain):
                added[chain] = ChainInfo(preserve=True)
    return added


def table_to_save(
    domain: str,
    chains: dict[str, ChainInfo],
    options: Options,
    preserved: dict[str, str],
) -> str:
    """
    Render one table's preserved + generated rules (Perl ``:2997``).

    Chains are emitted in sorted order; a chain's ``preserved`` text (the
    rules extracted from the previous ruleset) is prepended, then (unless
    ``--flush``) each rule as ``-A CHAIN <options>``.  The oracle stores the
    extracted text back into the chain's ``{preserve}`` slot (``:3073``);
    this port passes it alongside so the domain state stays untouched.
    """
    result = ""
    for chain in sorted(chains):
        chain_info = chains[chain]

        text = preserved.get(chain)
        if text is not None:
            result += text

        if options.flush:
            continue

        for rule in chain_info.rules:
            result += f"-A {chain}{format_rule(domain, rule, fast=True)}\n"

    return result


def rules_to_save(
    domain: str,
    domain_info: DomainInfo,
    options: Options,
    *,
    now: str | None = None,
) -> str:
    """
    Build the full ``*-restore`` save text for one family (Perl ``:3046``).

    Emits the recognizable ``# Generated by ferm ...`` header (the test harness
    strips it), then, per sorted table: resolve dynamic-preserve chains, select
    the table, emit each sorted chain's policy line (``ACCEPT`` for a built-in,
    a copied preserve line, or ``-`` for a synthesized chain), append the rules
    and ``COMMIT``.  ``now`` overrides the timestamp for tests.
    """
    tool = re.sub(r".*/", "", domain_info.tools[TOOL_SAVE])
    when = now if now is not None else time.asctime()
    result = f"# Generated by ferm {__version__} ({tool}) on {when}\n"

    for table in sorted(domain_info.tables):
        table_info = domain_info.tables[table]
        chains = table_info.chains
        table_save: str | None = None

        if table_info.preserve_regexes:
            table_save = extract_table_from_save(
                domain_info.previous or "", table
            )
            added = resolve_dynamic_preserve(table_info, table_save)
            if added:
                chains = {**chains, **added}

        result += f"*{table}\n"

        # chain -> previous-ruleset rules text, resolved here instead of
        # being written back into chain_info.preserve (render stays pure)
        preserved: dict[str, str] = {}

        for chain in sorted(chains):
            chain_info = chains[chain]

            if chain_info.preserve is not None:
                if table_save is None:
                    table_save = extract_table_from_save(
                        domain_info.previous or "", table
                    )
                preserved[chain] = extract_chain_from_table_save(
                    table_save, chain
                )

                line = re.search(
                    r"^:" + re.escape(chain) + r" .*\n",
                    table_save,
                    re.MULTILINE,
                )
                if line is not None:
                    result += line.group(0)
                    continue

            policy = None if options.flush else chain_info.policy
            if policy is None:
                if is_netfilter_builtin_chain(table, chain):
                    policy = "ACCEPT"
                else:
                    if options.flush:
                        continue
                    policy = "-"

            result += f":{chain} {policy} [0:0]\n"

        result += table_to_save(domain, chains, options, preserved)
        result += "COMMIT\n"

    return result


def restore_domain(
    domain_info: DomainInfo, save: str, options: Options
) -> None:
    """
    Pipe a save text to ``*-restore`` (Perl ``:3103``).

    The live execution seam; raises :class:`FermError` (Perl ``die``) if the
    tool cannot be run or exits non-zero.  Never reached under ``--noexec``.
    """
    path = domain_info.tools[TOOL_RESTORE]
    args = [path]
    if options.noflush:
        args.append("--noflush")

    try:
        # the path comes from find_tool; no shell is used
        # latin-1: one byte per char, reproducing the config bytes exactly
        # (default utf-8 would turn U+0080-U+00FF into two bytes each)
        completed = subprocess.run(
            args, input=save.encode(BYTE_ENCODING), check=False
        )
    except OSError as exc:
        raise FermError(f"Failed to run {path}: {exc}") from exc
    if completed.returncode != 0:
        raise FermError(f"Failed to run {path}")


class IptablesBackend(Backend):
    """The iptables/ip6tables/arptables/ebtables backend (Phase 1)."""

    def tool_names(self, domain: str) -> dict[str, str]:
        """The x_tables tool set: ip/ip6 own save/restore, arp/eb only tables."""
        names = {TOOL_TABLES: domain + TOOL_TABLES}
        if domain in ("ip", "ip6"):
            names[TOOL_SAVE] = domain + TOOL_SAVE
            names[TOOL_RESTORE] = domain + TOOL_RESTORE
        return names

    def render(
        self, domain: str, domain_info: DomainInfo, options: Options
    ) -> Rendered:
        """
        Build a fast save or the slow command list (``:3119``/``:2919``).

        A family without a ``*-restore`` tool (arp/eb) falls back to the
        slow command list even under ``--fast`` (Perl ``:773``).  The
        escaping mode stays ``options.fast``: the oracle formats values at
        parse time with the global ``$option{fast}``, so an arp/eb fallback
        under the default fast mode still double-quotes.
        """
        use_fast = options.fast and TOOL_RESTORE in domain_info.tools
        if use_fast:
            return Rendered(save=rules_to_save(domain, domain_info, options))
        return self._render_slow(domain, domain_info, options)

    def _render_slow(
        self, domain: str, domain_info: DomainInfo, options: Options
    ) -> Rendered:
        """
        Build the ordered ``-P/-F/-X/-N/-A`` command list (Perl ``:2919``).

        The execution-free half of ``execute_slow``: the table-walk commands
        are guarded (``$status ||=``); the ``eb`` atomic-init/atomic-commit
        framing is unguarded.  For ``eb`` the per-table atomic-file tempfiles
        are created here (as the oracle does, even under ``--noexec``) and
        carried on :attr:`Rendered.resources` -- their random names (the one
        nondeterminism in render, normalized by the test harness) are
        embedded in the commands, so the files must live until commit.
        """
        commands: list[Command] = []
        domain_cmd = domain_info.tools[TOOL_TABLES]
        ebt_current: dict[str, IO[bytes]] = {}

        if domain == "eb":
            for eb_table in EB_TABLES:
                # Long-lived like the rollback snapshots in domains.py: the
                # tempfile must outlive this call (its name is in the
                # commands) and auto-unlinks when the Rendered is dropped.
                current = tempfile.NamedTemporaryFile(  # noqa: SIM115
                    prefix="ferm."
                )
                ebt_current[eb_table] = current
                name = current.name
                commands.append(
                    Command(
                        f"{domain_cmd} -t {eb_table} "
                        f"--atomic-file {name} --atomic-init",
                        guarded=False,
                    )
                )
                commands.append(
                    Command(
                        f"{domain_cmd} -t {eb_table} "
                        f"--atomic-file {name} --init-table",
                        guarded=False,
                    )
                )

        for table, table_info in domain_info.tables.items():
            table_cmd = f"{domain_cmd} -t {table}"
            if domain == "eb":
                tablefile = ebt_current[table].name
                table_cmd = f"{table_cmd} --atomic-file {tablefile}"

            # reset chain policies
            for chain, chain_info in table_info.chains.items():
                builtin = chain_info.builtin or (
                    not table_info.has_builtin
                    and is_netfilter_builtin_chain(table, chain)
                )
                if not builtin:
                    continue
                if not options.noflush:
                    commands.append(Command(f"{table_cmd} -P {chain} ACCEPT"))

            # clear
            if not options.noflush:
                commands.append(Command(f"{table_cmd} -F"))
                commands.append(Command(f"{table_cmd} -X"))

            if options.flush:
                continue

            # create chains / set policy
            for chain, chain_info in table_info.chains.items():
                if is_netfilter_builtin_chain(table, chain):
                    if (
                        chain_info.policy is not None
                        and chain_info.policy != "ACCEPT"
                    ):
                        commands.append(
                            Command(
                                f"{table_cmd} -P {chain} {chain_info.policy}"
                            )
                        )
                elif chain_info.policy is not None:
                    commands.append(
                        Command(
                            f"{table_cmd} -N {chain} -P {chain_info.policy}"
                        )
                    )
                else:
                    commands.append(Command(f"{table_cmd} -N {chain}"))

            # dump rules (escaped with the GLOBAL fast mode, see render)
            for chain, chain_info in table_info.chains.items():
                chain_cmd = f"{table_cmd} -A {chain}"
                commands.extend(
                    Command(
                        chain_cmd
                        + format_rule(domain, rule, fast=options.fast)
                    )
                    for rule in chain_info.rules
                )

        if domain == "eb":
            for eb_table in EB_TABLES:
                name = ebt_current[eb_table].name
                commands.append(
                    Command(
                        f"{domain_cmd} -t {eb_table} "
                        f"--atomic-file {name} --atomic-commit",
                        guarded=False,
                    )
                )

        return Rendered(
            commands=commands, resources=list(ebt_current.values())
        )

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
        """
        Emit and run a rendered ruleset (Perl ``:3119``/``:2919``).

        Dispatches on the shape of ``rendered`` (a save text vs. a command
        list), so the arp/eb slow fallback :meth:`render` chose is honoured
        without re-deriving it from ``options``.
        """
        del domain  # parity with the interface; commit follows rendered
        if rendered.save is not None:
            return self._commit_fast(
                domain_info,
                rendered.save,
                options,
                emit_line=emit_line,
                restore=restore,
            )
        return self._commit_slow(rendered.commands, execute=execute)

    def _commit_slow(
        self, commands: list[Command], *, execute: ExecuteCommand
    ) -> int | None:
        """
        Run the slow list with the ``$status ||=`` guard (``:2935``).

        Guarded commands stop running once an earlier one has failed (faithful
        to ``$status ||= execute_command(...)``); unguarded commands (eb
        framing) always run.  Under ``--noexec`` every ``execute`` returns
        ``None``, so the guard never trips and all commands are emitted.
        """
        status: int | None = None
        for command in commands:
            if command.guarded:
                if not status:
                    status = execute(command.text)
            else:
                execute(command.text)
        return status

    def _commit_fast(
        self,
        domain_info: DomainInfo,
        save: str | None,
        options: Options,
        *,
        emit_line: LineEmitter,
        restore: RestoreDomain,
    ) -> int | None:
        """
        Emit the save under ``--lines`` and pipe it to restore (``:3119``).

        Under ``--shell`` the save is wrapped in a ``<<EOT`` heredoc; the save
        text is emitted verbatim (it already ends in newlines).  Returns
        ``None`` under ``--noexec``; otherwise pipes via ``restore`` and maps a
        :class:`FermError` to a non-zero status, as the oracle's ``eval`` does.
        """
        if save is None:
            raise internal_error()

        if options.lines:
            path = domain_info.tools[TOOL_RESTORE]
            if options.noflush:
                path += " --noflush"
            if options.shell:
                emit_line(f"{path} <<EOT\n")
            emit_line(save)
            if options.shell:
                emit_line("EOT\n")

        if options.noexec:
            return None

        try:
            restore(domain_info, save)
        except FermError as exc:
            print(exc, file=sys.stderr)
            return 1
        return None

    def rollback(
        self,
        domain: str,
        domain_info: DomainInfo,
        options: Options,
        *,
        execute: ExecuteCommand,
        restore: RestoreDomain,
    ) -> None:
        """
        Restore one family's previous ruleset (Perl ``:3147`` loop body).

        Skips a family no rule enabled.  For ``eb`` the previous atomic-save
        snapshots are committed back.  Otherwise a reset save is built that
        sets every built-in chain to ``ACCEPT`` and appends the captured
        previous ruleset, then piped to ``*-restore``.  The cross-domain loop,
        the closing message and ``exit 1`` live in the cli.
        """
        del options  # parity with the interface; rollback reads no options
        if not domain_info.enabled:
            return

        if domain == "eb":
            domain_cmd = domain_info.tools[TOOL_TABLES]
            for eb_table in EB_TABLES:
                name = domain_info.ebt_previous[eb_table].name
                execute(
                    f"{domain_cmd} -t {eb_table} "
                    f"--atomic-file {name} --atomic-commit"
                )
            return

        if TOOL_RESTORE not in domain_info.tools:
            print(
                f"Cannot rollback domain '{domain}' because there is no "
                f"{domain}{TOOL_RESTORE}",
                file=sys.stderr,
            )
            return

        reset = ""
        for table, table_info in domain_info.tables.items():
            reset_chain = ""
            for chain in table_info.chains:
                if is_netfilter_builtin_chain(table, chain):
                    reset_chain += f":{chain} ACCEPT [0:0]\n"
            if reset_chain:
                reset += f"*{table}\n{reset_chain}COMMIT\n"

        if domain_info.previous is not None:
            reset += domain_info.previous

        restore(domain_info, reset)

    def capture_previous(
        self,
        domain: str,
        domain_info: DomainInfo,
        options: Options,
        *,
        execute: ExecuteCommand,
        read_save: SaveReader,
    ) -> None:
        """
        Capture the previous x_tables state (Perl ``:946-952,963-970``).

        Moved from ``initialize_domain`` (verbatim except the mock file
        is read latin-1 per the byte model; the old utf-8 copy dies in
        the wiring change): the ``--test`` branch parses
        ``mock_previous``, the live branch reads the ``*-save`` tool (a
        partial dump on non-zero exit still becomes ``previous``, an
        unrunnable tool yields the empty string -- the injected
        ``read_save`` owns that contract), and ``eb`` snapshots each
        table with ``--atomic-save`` (also under ``--test``: the golden
        eb runs normalize the tempfile names).
        """
        if options.test:
            mock = options.mock_previous.get(domain)
            if mock is not None:
                # Perl: `open ... or die $!` (:948) -- the strerror
                # message is caught by check_domain and located; a raw
                # OSError would escape every FermError handler.
                try:
                    # The `with` follows immediately; the open is
                    # separate only so the OSError can be mapped.
                    handle = Path(mock).open(  # noqa: SIM115
                        encoding=BYTE_ENCODING
                    )
                except OSError as exc:
                    raise FermError(exc.strerror or str(exc)) from exc
                with handle:
                    domain_info.previous = self.read_previous(
                        handle, domain_info
                    )
        elif TOOL_SAVE in domain_info.tools:
            saved = read_save(domain_info.tools[TOOL_SAVE])
            if saved is not None:
                domain_info.previous = self.read_previous(
                    saved.splitlines(keepends=True), domain_info
                )

        if domain == "eb":
            domain_cmd = domain_info.tools[TOOL_TABLES]
            for eb_table in EB_TABLES:
                # Kept open deliberately (not a context manager): the
                # file must outlive this call, stored in ``ebt_previous``
                # for rollback and unlinked by ``DomainInfo.close()``,
                # mirroring Perl's ``File::Temp`` ``UNLINK => 1`` (:966).
                snapshot = tempfile.NamedTemporaryFile(  # noqa: SIM115
                    prefix="ferm."
                )
                execute(
                    f"{domain_cmd} -t {eb_table} "
                    f"--atomic-file {snapshot.name} --atomic-save"
                )
                domain_info.ebt_previous[eb_table] = snapshot

    def read_previous(
        self, lines: Iterable[str], domain_info: DomainInfo
    ) -> str:
        """
        Parse a previous save dump (delegates to :mod:`pyferm.domains`).

        The save-format parser lives in ``domains`` because
        ``initialize_domain`` also calls it; the backend exposes it on the
        interface for the Phase 2 seam (``nft`` parses a different format).
        """
        return _domains_read_previous(lines, domain_info)
