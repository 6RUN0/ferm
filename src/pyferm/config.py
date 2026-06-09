"""Resolved command-line options: the port's model of Perl's ``%option``.

Faithful stand-in for the ``%option`` hash that ``reference/src/ferm`` fills in
``GetOptions``/``main`` (``:644-721``).  ``%option`` holds the *derived* flag
values, not the raw switches: ``noexec`` is ``--noexec || --test``, ``lines``
is ``--lines || --test || --shell``, ``fast`` is ``not --slow``,
``interactive`` is ``--interactive and not noexec`` (``:675-683``).  That
derivation is the CLI's job (``cli.py``, the ``GetOptions`` port); this
dataclass only carries the settled result, so the rest of the program reads
one typed value object instead
of a global hash.

:class:`Options` is threaded explicitly as a parameter (``domains``/``backend``
take it as an argument), keeping the module dependency graph acyclic -- nothing
imports a global option state.  ``nolegacy`` is the one field with no oracle
counterpart: it is sanctioned deviation #4 (disable the ``*-legacy`` tool
preference), defaulting off so the oracle's behaviour is unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Options:
    """The resolved option set, mirroring ``%option`` (``:675-721``).

    Fields use the *derived* meanings from ``main``: e.g. ``test`` already
    forces ``noexec`` and ``lines`` true at construction time (in ``cli.py``),
    so consumers test these flags directly as the oracle does.
    """

    #: ``--test``: substitute fake tool paths, never touch the kernel.
    test: bool = False
    #: ``--noexec`` (or implied by ``--test``): build output but do not run it.
    noexec: bool = False
    #: ``--lines`` (or implied by ``--test``/``--shell``): echo commands.
    lines: bool = False
    #: ``not --slow``: use ``iptables-restore`` (atomic) rather than per-rule.
    fast: bool = True
    #: ``--flush``: tear down ferm-managed rules instead of installing.
    flush: bool = False
    #: ``--noflush``: keep existing rules, only append.
    noflush: bool = False
    #: ``--shell``: emit a shell script instead of executing.
    shell: bool = False
    #: ``--interactive`` (and not ``noexec``): confirm-or-rollback safety net.
    interactive: bool = False
    #: ``--timeout``: seconds before an unconfirmed ruleset is rolled back.
    timeout: int = 30
    #: ``--domain``: restrict processing to a single family, if set.
    domain: str | None = None
    #: ``--test-mock-previous=fam=path``: stand-in previous save per family.
    mock_previous: dict[str, str] = field(default_factory=dict)
    #: ``--nolegacy`` (port-only, deviation #4): skip the ``*-legacy`` tool
    #: preference in :func:`pyferm.domains.find_tool`.
    nolegacy: bool = False
