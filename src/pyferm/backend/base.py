"""
Backend interface seam: render / commit / rollback / read_previous.

The abstraction Phase 2 (native ``nft``) slots into.  The oracle fuses
building the firewall output with executing it (``execute_fast``/
``execute_slow``, ``reference/src/ferm:2919-3145``); this port splits that into
a pure :meth:`Backend.render` (deterministic output -- the golden oracle checks
exactly this) and an effectful :meth:`Backend.commit`, plus
:meth:`Backend.rollback` and :meth:`Backend.read_previous`.  Splitting the
slow/eb-atomic build out of execution is sanctioned deviation #3 (design
§"Backend-интерфейс"); the oracle has no such seam.

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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pyferm.config import Options
    from pyferm.domains import DomainInfo

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
    commands: list[Command] = field(default_factory=list)
    #: Artifacts the commands reference that must stay alive until commit
    #: (the eb atomic tempfiles auto-unlink when dropped).  Owned here, not
    #: on ``DomainInfo``, so re-rendering cannot orphan an earlier
    #: ``Rendered``'s files.
    resources: list[object] = field(default_factory=list)


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
    def read_previous(
        self, lines: Iterable[str], domain_info: DomainInfo
    ) -> str:
        """Parse a previous save dump, recording its tables/chains."""
