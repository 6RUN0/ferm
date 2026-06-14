"""
Backend interface seam: render/commit/rollback/capture_previous/read_previous.

The abstraction Phase 2 (native ``nft``) slots into.  The oracle fuses
building the firewall output with executing it (``execute_fast``/
``execute_slow``, ``reference/src/ferm:2919-3145``); this port splits that into
a pure :meth:`Backend.render` (deterministic output -- the golden oracle checks
exactly this) and an effectful :meth:`Backend.commit`, plus
:meth:`Backend.rollback`, :meth:`Backend.capture_previous` (snapshot the
family's previous state for rollback/``@preserve``) and
:meth:`Backend.read_previous`.  Splitting the slow/eb-atomic build out of
execution is sanctioned deviation #3 (design §"Backend-интерфейс"); the oracle
has no such seam.

Effectful I/O (running a command, emitting a ``--lines`` line, piping a save to
``*-restore``) is injected as callables rather than reached for directly, so
the backend stays pure and unit-testable -- the same seam ``domains`` uses.
The cli owns the real implementations and wires them in; orchestration across
domains (apply all -> ``confirm_rules`` -> roll back all) lives in the cli, not
here (design §"Backend-интерфейс", ``:782-817``).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from pyferm.config import Options
    from pyferm.domains import DomainInfo, ShellSnapshot


@runtime_checkable
class _SupportsClose(Protocol):
    """A resource :meth:`Rendered.close` knows how to release."""

    def close(self) -> None: ...


#: Runs one shell command (Perl ``execute_command``, ``:2894``): emits it under
#: ``--lines`` and runs it unless ``--noexec``, returning the exit status (or
#: ``None``).  Injected so the backend never calls ``system`` itself.
ExecuteCommand = Callable[[str], "int | None"]
#: Writes raw text to the ``--lines``/``--shell`` sink (Perl ``print LINES``);
#: the caller supplies any trailing newline.
LineEmitter = Callable[[str], None]
#: Pipes a save text to ``*-restore`` (Perl ``restore_domain``, ``:3103``),
#: raising :class:`pyferm.errors.FermError` on failure.
RestoreDomain = Callable[["DomainInfo", str], None]
#: Runs a ``*-save`` tool path and returns its output, or ``None`` if it
#: could not be run (the live branch of ``:951-952``).
SaveReader = Callable[[str], "str | None"]
#: Runs a command WITH ARGS and returns its stdout, or ``None`` if it
#: could not be run (or ``--noexec``).  Unlike :data:`ExecuteCommand`
#: (which returns only an exit status), this captures output: the nft
#: backend uses it to snapshot ``nft list table <family> ferm`` for
#: rollback (decision 10); the x_tables backend ignores it.
ExecuteCapture = Callable[[str], "str | None"]


@dataclass
class Command:
    """
    One slow-mode shell command plus its Perl ``$status ||=`` guard.

    ``guarded`` reproduces ``execute_slow``'s mix (``:2919``): the table-walk
    commands run under ``$status ||= execute_command(...)`` (skipped once an
    earlier one fails), while the ``eb`` atomic-init/atomic-commit framing runs
    unconditionally via bare ``execute_command`` (``:2930``/``:2990``).
    """

    text: str
    guarded: bool = True


@dataclass
class Rendered:
    """
    The output of :meth:`Backend.render`: a fast save-text or slow commands.

    Exactly one shape is populated; ``render`` selects it from
    :attr:`Options.fast` *and* the family's tooling (arp/eb own no
    ``*-restore``, so they fall back to commands), and ``commit`` dispatches
    on the populated shape.  ``save`` is the ``*-restore`` input built by
    ``rules_to_save`` (``:3046``); ``commands`` is the ordered
    ``-P/-F/-X/-N/-A`` sequence built from ``execute_slow`` (``:2919``) with
    execution split off.
    """

    save: str | None = None
    commands: list[Command] = field(default_factory=list[Command])
    #: Artifacts the commands reference that must stay alive until commit
    #: (the eb atomic tempfiles unlink on :meth:`close`).  Owned here, not
    #: on ``DomainInfo``, so re-rendering cannot orphan an earlier
    #: ``Rendered``'s files.
    resources: list[object] = field(default_factory=list[object])

    def close(self) -> None:
        """
        Release the rendered artifacts (idempotent).

        The cli calls this once the ``Rendered`` has been committed.  Perl
        leaves the eb atomic tempfiles to ``File::Temp``'s destructor
        (``UNLINK => 1``, ``:2929``); relying on gc finalization the same
        way raises ResourceWarning on Python 3.14+.
        """
        for resource in self.resources:
            if isinstance(resource, _SupportsClose):
                resource.close()


class Backend(ABC):
    """
    Abstract netfilter backend (the Phase 2 seam).

    Phase 1 ships one implementation,
    :class:`pyferm.backend.iptables.IptablesBackend`; Phase 2 adds an ``nft``
    backend behind the same four methods.  The kernel hands ``render`` the
    per-family :class:`pyferm.domains.DomainInfo` (whose chains already hold
    structural :class:`pyferm.rules.RenderedRule` lists) and the resolved
    :class:`pyferm.config.Options`.
    """

    @abstractmethod
    def tool_names(self, domain: str) -> dict[str, str]:
        """
        Map tool keys to the names ``find_tool`` should resolve.

        Lets the wiring (``initialize_domain``) resolve the right tools
        per backend without hardcoding x_tables names: iptables returns
        its ``*tables``/``*-save``/``*-restore`` set, nft returns a single
        family-independent ``nft`` (design §9, plan decision 2).
        """

    @abstractmethod
    def render(
        self, domain: str, domain_info: DomainInfo, options: Options
    ) -> Rendered:
        """Build the firewall output for one family without executing it."""

    @abstractmethod
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
        """Emit and execute a previously rendered ruleset for one family."""

    @abstractmethod
    def rollback(
        self,
        domain: str,
        domain_info: DomainInfo,
        options: Options,
        *,
        execute: ExecuteCommand,
        restore: RestoreDomain,
    ) -> None:
        """Restore one family's previous ruleset (cli loops over domains)."""

    @abstractmethod
    def capture_previous(
        self,
        domain: str,
        domain_info: DomainInfo,
        options: Options,
        *,
        execute: ExecuteCommand,
        read_save: SaveReader,
        capture: ExecuteCapture,
    ) -> None:
        """
        Snapshot the family's previous state for rollback/``@preserve``.

        Owns the whole capture phase of ``initialize_domain`` (Perl
        ``:946-952`` + the ``eb`` atomic block, ``:963-970``): the
        ``--test`` mock branch, the live ``*-save`` read and the ``eb``
        atomic-save snapshot.  ``execute``/``read_save`` are
        x_tables-affine seams injected for testability, NOT a contract
        obligation -- an nft backend may ignore ``read_save`` and capture
        via ``execute`` (``nft list ruleset``).  Call invariant: the
        caller resolves ``domain_info.tools`` before calling.
        """

    @abstractmethod
    def read_previous(
        self, lines: Iterable[str], domain_info: DomainInfo
    ) -> str:
        """Parse a previous save dump, recording its tables/chains."""

    @abstractmethod
    def shell_snapshot(
        self, domain: str, domain_info: DomainInfo
    ) -> ShellSnapshot | None:
        """
        Build the ``--shell`` anti-lockout snapshot lines for one family.

        ``--interactive --shell`` emits a save of the live ruleset before the
        new rules and a restore after the confirmation timeout, so an admin
        who never confirms is rolled back (Perl ``:810-814``).  The shape is
        backend-specific -- x_tables uses a ``*-save``/``*-restore`` pair, nft
        a ``list table``/``delete``+``-f`` pair -- so each backend owns it
        (finding C2).  ``None`` when the family has no snapshot tooling.
        """

    def shell_rollback_notice(self) -> str | None:
        """
        Return a shell line announcing the ``--interactive --shell`` rollback.

        The live ``--interactive`` path prints "Firewall rules rolled back."
        after reverting (Perl ``:3181``); the generated ``--shell`` script has
        no such announcement, so a timed-out admin can be rolled back without a
        word.  A backend whose shell restores are otherwise silent returns one
        line (emitted after the per-family restores) echoing the rollback to
        stderr.  The default ``None`` keeps the script byte-identical to the
        oracle -- the x_tables backend matches Perl ``:803-814`` exactly.
        """
        return None
