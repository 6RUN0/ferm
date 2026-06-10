"""Per-family domain state, tool discovery and previous-ruleset reads.

Faithful port of ferm's domain layer from ``reference/src/ferm``: the
``%domains`` state model (``:70-78``), ``find_tool`` (``:881-901``),
``read_previous`` (``:903-923``) and ``initialize_domain`` (``:925-974``).

``%domains`` is a hash-of-hashes keyed by family (``ip``/``ip6``/``arp``/
``eb``); this port models each node as a dataclass (:class:`DomainInfo` ->
:class:`TableInfo` -> :class:`ChainInfo`) so the structure is typed instead of
autovivified.  ``%option`` is passed in as a typed
:class:`pyferm.config.Options` (the module never reads global state), so
``domains`` stays a near-leaf of the
dependency graph.

The execution-coupled branches of ``initialize_domain`` -- running the live
``*-save`` pipe, emitting ``--shell``/``--interactive`` setup lines, and the
``eb`` atomic-save snapshot -- are reached through injected callables
(``execute``/``emit_line``/``read_save``) rather than importing the backend, so
no ``domains -> backend`` edge appears.  In ``--test`` mode (every golden run)
only the ``mock_previous`` path is taken, so those seams stay inert until the
ebtables (M7) and ``--interactive`` (M11) milestones wire them.
"""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING

from pyferm.config import Options
from pyferm.errors import FermError

if TYPE_CHECKING:
    from pyferm.rules import RenderedRule

#: The ebtables tables in their FIXED order (``:94``).  The order is a
#: deliberate literal, NOT sorted -- arp/eb output is byte-for-byte and not
#: canonicalized by ``sort.pl`` (design revision 3, the ``@eb_tables`` fix).
EB_TABLES = ("filter", "nat", "broute")

#: Valid domain (family) names (``initialize_domain``, ``:931``).
_DOMAIN_RE = re.compile(r"^(?:ip6?|arp|eb)$")
#: Families that own ``*-save``/``*-restore`` tools (``:934-935``).
_IP_DOMAIN_RE = re.compile(r"^ip6?$")
#: Split a tool name into ``(base ending in 'tables', suffix)`` (``:886``).
_LEGACY_RE = re.compile(r"^(.*tables)(.*)$")

#: Runs one shell command (the backend's ``execute_command``); returns its exit
#: status or ``None`` (Perl ``:2894``).
ExecuteCommand = Callable[[str], "int | None"]
#: Writes *raw* text to the ``--lines``/``--shell`` sink (Perl ``print
#: LINES``).  The caller supplies any trailing newline, mirroring Perl's
#: ``print`` -- ``execute_fast`` prints a multi-line save blob verbatim
#: (``:3129``) while line-oriented callers append ``\n`` themselves.
LineEmitter = Callable[[str], None]
#: Runs a ``*-save`` tool path and returns its output, or ``None`` if it could
#: not be run (the live branch of ``:951-952``).
SaveReader = Callable[[str], "str | None"]


@dataclass
class ChainInfo:
    """ferm state for one chain (``%domains`` ``chains{...}``, ``:77-78``).

    :attr:`preserve` models Perl's ``{preserve}`` flag: absent (``None``)
    means the chain is not preserved; ``True`` is set by ``@preserve``/
    ``resolve_dynamic_preserve`` (Perl ``preserve => 1``,
    ``:2420``/``:3040``).  The oracle additionally overwrites the slot with
    the extracted previous-ruleset text (``:3073``); this port keeps that
    text local to ``rules_to_save`` so render does not mutate domain state.
    """

    builtin: bool = False
    policy: str | None = None
    rules: list[RenderedRule] = field(default_factory=list)
    preserve: bool | None = None


@dataclass
class TableInfo:
    """ferm state for one table (``%domains`` ``tables{$name}``, ``:74-76``).

    ``has_builtin`` records whether built-in chains have been determined;
    ``preserve_regexes`` holds the ``@preserve`` patterns for dynamically
    preserved chains.
    """

    has_builtin: bool = False
    preserve_regexes: list[re.Pattern[str]] = field(default_factory=list)
    chains: dict[str, ChainInfo] = field(default_factory=dict)


@dataclass
class DomainInfo:
    """State for one family (``$domains{$domain}``, ``:70-78``).

    ``tools`` maps a bare tool key (``tables``/``tables-save``/
    ``tables-restore``) to its resolved path; ``previous`` is the prior save
    text kept for rollback; ``ebt_previous`` holds the per-table atomic-save
    tempfiles for rollback (``eb`` only, ``:969``); the atomic files for the
    *new* ruleset (``:2929``) live on the backend's ``Rendered.resources``,
    not here, so re-rendering cannot orphan them; ``enabled`` is set once a
    rule uses this family.
    """

    initialized: bool = False
    enabled: bool = False
    tools: dict[str, str] = field(default_factory=dict)
    previous: str | None = None
    ebt_previous: dict[str, IO[bytes]] = field(default_factory=dict)
    tables: dict[str, TableInfo] = field(default_factory=dict)


def find_tool(name: str, options: Options) -> str:
    """Resolve a tool name to an executable path (Perl ``:881``).

    In ``--test`` mode the bare name is returned unchanged (``:883``), which is
    why golden output is path-independent.  Otherwise the search path is
    ``/usr/sbin``, ``/sbin`` then ``$PATH``; unless :attr:`Options.nolegacy` is
    set, the ``*-legacy`` spelling is preferred first (``:886-889``) since the
    nft-based tools are incompatible with ferm.  Raises :class:`FermError`
    (Perl ``die``) when nothing executable is found.

    ``--nolegacy`` (sanctioned deviation #4) skips only the legacy preference;
    the default behaviour is unchanged, so golden runs stay green.
    """
    if options.test:
        return name

    path = ["/usr/sbin", "/sbin", *os.environ.get("PATH", "").split(":")]

    legacy = _LEGACY_RE.match(name)
    if legacy is not None and not options.nolegacy:
        legacy_name = legacy.group(1) + "-legacy" + legacy.group(2)
        for directory in path:
            candidate = f"{directory}/{legacy_name}"
            if os.access(candidate, os.X_OK):
                return candidate

    for directory in path:
        candidate = f"{directory}/{name}"
        if os.access(candidate, os.X_OK):
            return candidate

    raise FermError(f"{name} not found in PATH")


def read_previous(lines: Iterable[str], domain_info: DomainInfo) -> str:
    """Parse a previous save dump, recording its tables/chains (``:903``).

    Accumulates the raw text (returned verbatim for rollback) while noting each
    ``*table`` section and every ``:CHAIN POLICY`` line whose policy is not
    ``-`` -- those chains are the built-in ones, so the chain is flagged
    ``builtin`` and its table ``has_builtin``.  ``lines`` keep their newlines
    (the dump is reproduced byte-for-byte), mirroring reading a filehandle.
    """
    save = ""
    table_info: TableInfo | None = None
    for line in lines:
        save += line

        table_match = re.match(r"^\*(\w+)", line)
        if table_match is not None:
            table = table_match.group(1)
            table_info = domain_info.tables.setdefault(table, TableInfo())
            continue

        chain_match = re.match(r"^:(\w+)\s+(\S+)", line)
        if (
            table_info is not None
            and chain_match is not None
            and chain_match.group(2) != "-"
        ):
            chain = chain_match.group(1)
            table_info.chains.setdefault(chain, ChainInfo()).builtin = True
            table_info.has_builtin = True

    return save


def initialize_domain(
    domain: str,
    domains: dict[str, DomainInfo],
    options: Options,
    *,
    execute: ExecuteCommand,
    emit_line: LineEmitter | None = None,
    read_save: SaveReader | None = None,
) -> None:
    """Discover a family's tools and snapshot its current ruleset (``:925``).

    Idempotent (a second call is a no-op once ``initialized``).  Validates the
    family name, resolves the tool paths via :func:`find_tool`, then captures
    previous ruleset for rollback: from ``mock_previous`` under ``--test``,
    otherwise from the live ``*-save`` tool via the injected ``read_save``.
    The ``--shell``/``--interactive`` setup lines and the ``eb`` atomic-save
    snapshot are emitted through the injected ``emit_line``/``execute`` seams
    (see the module docstring); they are unused in ``--test`` mode.
    """
    domain_info = domains.setdefault(domain, DomainInfo())
    if domain_info.initialized:
        return

    if _DOMAIN_RE.match(domain) is None:
        raise FermError(f"Invalid domain '{domain}'")

    tool_keys = ["tables"]
    if _IP_DOMAIN_RE.match(domain) is not None:
        tool_keys += ["tables-save", "tables-restore"]
    tools = {key: find_tool(domain + key, options) for key in tool_keys}
    domain_info.tools = tools

    # Capture the previous ruleset (for rollback / @preserve).
    if options.test:
        mock = options.mock_previous.get(domain)
        if mock is not None:
            # Perl: `open ... or die $!` (:948) -- the strerror message is
            # caught by check_domain and located; a raw OSError would
            # escape every FermError handler as a traceback.
            try:
                # The `with` follows immediately; the open is separate
                # only so the OSError can be mapped.
                handle = Path(mock).open()  # noqa: SIM115
            except OSError as exc:
                raise FermError(exc.strerror or str(exc)) from exc
            with handle:
                domain_info.previous = read_previous(handle, domain_info)
    elif "tables-save" in tools and read_save is not None:
        saved = read_save(tools["tables-save"])
        if saved is not None:
            domain_info.previous = read_previous(
                saved.splitlines(keepends=True), domain_info
            )

    if (
        options.shell
        and options.interactive
        and "tables-save" in tools
        and emit_line is not None
    ):
        emit_line(f"{domain}_tmp=$(mktemp ferm.XXXXXXXXXX)\n")
        emit_line(f"{tools['tables-save']} >${domain}_tmp\n")

    if domain == "eb":
        domain_cmd = tools["tables"]
        for eb_table in EB_TABLES:
            # Kept open deliberately (not a context manager): the file must
            # outlive this call, stored in ``ebt_previous`` for rollback and
            # auto-unlinked when the DomainInfo is dropped, mirroring Perl's
            # ``File::Temp`` ``UNLINK => 1`` (``:966``).
            snapshot = tempfile.NamedTemporaryFile(prefix="ferm.")  # noqa: SIM115
            execute(
                f"{domain_cmd} -t {eb_table} "
                f"--atomic-file {snapshot.name} --atomic-save"
            )
            domain_info.ebt_previous[eb_table] = snapshot

    domain_info.initialized = True
