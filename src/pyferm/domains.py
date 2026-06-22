"""
Per-family domain state, tool discovery and previous-ruleset reads.

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

The previous-state capture of ``initialize_domain`` (the ``--test`` mock
branch, the live ``*-save`` pipe, the ``eb`` atomic-save snapshot) goes
through the injected ``capture_previous`` callable -- the cli's closure over
:meth:`pyferm.backend.base.Backend.capture_previous` -- and the ``--shell``/
``--interactive`` setup lines through ``emit_line``.  The ``--shell``
anti-lockout snapshot is backend-specific (x_tables saves a ``*-save`` pair,
nft a ``list table`` dump -- finding C2), so it too arrives through an
injected ``shell_snapshot`` callable over
:meth:`pyferm.backend.base.Backend.shell_snapshot`.  The module imports no
``backend`` symbol at all (not even under ``TYPE_CHECKING``): the
render/commit seam is reached only through injected callables, so the
"compiler core does not import the backend" contract holds; the
``CapturePrevious``/``ShellSnapshotBuilder`` aliases reference the backend
only in prose.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import IO, TYPE_CHECKING, Final

from pyferm.errors import FermError

# Runtime import, not TYPE_CHECKING: the parametrized default_factory
# expressions below (``list[RenderedRule]``) evaluate at class-body time.
from pyferm.rules import RenderedRule

if TYPE_CHECKING:
    from pyferm.config import Options

#: The ebtables tables in their FIXED order (``:94``).  The order is a
#: deliberate literal, NOT sorted -- arp/eb output is byte-for-byte and not
#: canonicalized by ``sort.pl`` (design revision 3, the ``@eb_tables`` fix).
EB_TABLES = ("filter", "nat", "broute")

#: ``DomainInfo.tools`` keys: the resolved netfilter command and, for the
#: x_tables families (ip/ip6), its save/restore pair (``:931-935``).
TOOL_TABLES: Final[str] = "tables"
TOOL_SAVE: Final[str] = "tables-save"
TOOL_RESTORE: Final[str] = "tables-restore"

#: Valid domain (family) names (``initialize_domain``, ``:931``).
_DOMAIN_RE = re.compile(r"^(?:ip6?|arp|eb)$")
#: Families that own ``*-save``/``*-restore`` tools (``:934-935``).
_IP_DOMAIN_RE = re.compile(r"^ip6?$")
#: Split a tool name into ``(base ending in 'tables', suffix)`` (``:886``).
_LEGACY_RE = re.compile(r"^(.*tables)(.*)$")

#: Captures a family's previous ruleset once its tools are resolved --
#: the cli's closure over :meth:`pyferm.backend.base.Backend.capture_previous`
#: (backend + options + execute + read_save folded at the wiring point).
CapturePrevious = Callable[[str, "DomainInfo"], None]
#: Builds a family's ``--shell`` anti-lockout snapshot -- the cli's closure
#: over :meth:`pyferm.backend.base.Backend.shell_snapshot`.  Injected (not
#: imported) so this module keeps no backend symbol (finding C2).
ShellSnapshotBuilder = Callable[[str, "DomainInfo"], "ShellSnapshot | None"]
#: Writes *raw* text to the ``--lines``/``--shell`` sink (Perl ``print
#: LINES``).  The caller supplies any trailing newline, mirroring Perl's
#: ``print`` -- ``execute_fast`` prints a multi-line save blob verbatim
#: (``:3129``) while line-oriented callers append ``\n`` themselves.
LineEmitter = Callable[[str], None]


@dataclass
class ChainInfo:
    """
    ferm state for one chain (``%domains`` ``chains{...}``, ``:77-78``).

    :attr:`preserve` models Perl's ``{preserve}`` flag: absent (``None``)
    means the chain is not preserved; ``True`` is set by ``@preserve``/
    ``resolve_dynamic_preserve`` (Perl ``preserve => 1``,
    ``:2420``/``:3040``).  The oracle additionally overwrites the slot with
    the extracted previous-ruleset text (``:3073``); this port keeps that
    text local to ``rules_to_save`` so render does not mutate domain state.
    """

    builtin: bool = False
    policy: str | None = None
    rules: list[RenderedRule] = field(default_factory=list[RenderedRule])
    preserve: bool | None = None


@dataclass
class TableInfo:
    """
    ferm state for one table (``%domains`` ``tables{$name}``, ``:74-76``).

    ``has_builtin`` records whether built-in chains have been determined;
    ``preserve_regexes`` holds the ``@preserve`` patterns for dynamically
    preserved chains.
    """

    has_builtin: bool = False
    preserve_regexes: list[re.Pattern[str]] = field(
        default_factory=list[re.Pattern[str]]
    )
    chains: dict[str, ChainInfo] = field(default_factory=dict[str, ChainInfo])


@dataclass
class DomainInfo:
    """
    State for one family (``$domains{$domain}``, ``:70-78``).

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
    tools: dict[str, str] = field(default_factory=dict[str, str])
    previous: str | None = None
    ebt_previous: dict[str, IO[bytes]] = field(
        default_factory=dict[str, IO[bytes]]
    )
    tables: dict[str, TableInfo] = field(default_factory=dict[str, TableInfo])
    #: Set by the plan guard in ``capture_previous`` for families that own
    #: no parser-supported ``*-save`` tool (arp/eb): ``--plan`` notes them as
    #: unsupported rather than producing a wrong diff.
    plan_unsupported: bool = False

    def close(self) -> None:
        """
        Release the eb rollback snapshots (idempotent).

        The cli calls this once no rollback can need them.  Perl leaves
        the tempfiles to ``File::Temp``'s destructor (``UNLINK => 1``,
        ``:966``); relying on gc finalization the same way raises
        ResourceWarning on Python 3.14+.
        """
        for snapshot in self.ebt_previous.values():
            snapshot.close()


def find_tool(name: str, options: Options) -> str:
    """
    Resolve a tool name to an executable path (Perl ``:881``).

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
    """
    Parse a previous save dump, recording its tables/chains (``:903``).

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

        # re.ASCII: Perl's byte-mode \s+ does not match \x1c-\x1f, so a
        # Unicode \s would accept a policy field the oracle rejects
        # (found by the differential fuzzer).
        table_match = re.match(r"^\*(\w+)", line, re.ASCII)
        if table_match is not None:
            table = table_match.group(1)
            table_info = domain_info.tables.setdefault(table, TableInfo())
            continue

        chain_match = re.match(r"^:(\w+)\s+(\S+)", line, re.ASCII)
        if (
            table_info is not None
            and chain_match is not None
            and chain_match.group(2) != "-"
        ):
            chain = chain_match.group(1)
            table_info.chains.setdefault(chain, ChainInfo()).builtin = True
            table_info.has_builtin = True

    return save


@dataclass
class ShellSnapshot:
    """
    The ``--shell --interactive`` snapshot contract for one domain.

    ``setup`` saves the running ruleset into a shell variable's tempfile
    at the top of the generated script (Perl ``:954-957``); ``restore``
    pipes it back if the admin never confirms (Perl ``:810-814``).  Both
    halves share the ``{domain}_tmp`` variable name, so they must come
    from the same place -- this dataclass is that place.
    """

    setup: tuple[str, str]
    restore: str


def initialize_domain(
    domain: str,
    domains: dict[str, DomainInfo],
    options: Options,
    *,
    resolve_tools: Callable[[str], dict[str, str]] | None = None,
    capture_previous: CapturePrevious | None = None,
    emit_line: LineEmitter | None = None,
    shell_snapshot: ShellSnapshotBuilder | None = None,
) -> None:
    """
    Discover a family's tools and snapshot its current ruleset (``:925``).

    Idempotent (a second call is a no-op once ``initialized``).  Validates
    the family name, resolves the tool paths via :func:`find_tool`, then
    hands the whole previous-state capture (the ``--test`` mock branch,
    the live ``*-save`` read, the ``eb`` atomic snapshot) to the injected
    ``capture_previous`` -- the cli's closure over
    :meth:`pyferm.backend.base.Backend.capture_previous`.  The ``--shell``/
    ``--interactive`` setup lines go through ``emit_line``.  ``None`` seams
    are a unit-test/fuzz convenience: no capture, no setup lines.
    """
    domain_info = domains.setdefault(domain, DomainInfo())
    if domain_info.initialized:
        return

    if _DOMAIN_RE.match(domain) is None:
        raise FermError(f"Invalid domain '{domain}'")

    if resolve_tools is not None:
        names = resolve_tools(domain)
    else:
        names = {TOOL_TABLES: domain + TOOL_TABLES}
        if _IP_DOMAIN_RE.match(domain) is not None:
            names[TOOL_SAVE] = domain + TOOL_SAVE
            names[TOOL_RESTORE] = domain + TOOL_RESTORE
    domain_info.tools = {
        key: find_tool(name, options) for key, name in names.items()
    }

    if capture_previous is not None:
        capture_previous(domain, domain_info)

    if (
        options.shell
        and options.interactive
        and emit_line is not None
        and shell_snapshot is not None
    ):
        snapshot_lines = shell_snapshot(domain, domain_info)
        if snapshot_lines is not None:
            for line in snapshot_lines.setup:
                emit_line(line)

    domain_info.initialized = True
