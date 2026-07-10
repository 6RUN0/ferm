"""The NftBackend render/commit implementation over the nft binary."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from pyferm.backend.base import (
    Backend,
    ExecuteCapture,
    ExecuteCommand,
    LineEmitter,
    Rendered,
    RestoreDomain,
    SaveReader,
)
from pyferm.domains import (
    NFT_TABLE_NAME,
    Family,
    ShellSnapshot,
)
from pyferm.errors import FermError, internal_error
from pyferm.plan import build_nft_delta, needs_full_reload
from pyferm.streams import BYTE_ENCODING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pyferm.config import Options
    from pyferm.domains import DomainInfo

from .assemble import _collapse_chain_rules, translate_rule
from .chains import build_chains, nft_chain_name
from .model import (
    TOOL_NFT,
    NftBaseChain,
    NftRegularChain,
    NftRule,
    NftTable,
)
from .sets import (
    _collect_set_declarations,
    _collect_set_target_names,
    _full_reload_text,
    _references_empty_named_set,
    serialize_table,
)
from .stateful import (
    _build_recent_specs,
    _finalize_connlimit_names,
)


class NftBackend(Backend):
    """The native nftables backend (Phase 2, all families via ``nft -f``)."""

    def tool_names(self, domain: Family) -> dict[str, str]:
        """Return the single family-independent ``nft`` binary."""
        del domain
        return {"nft": "nft"}

    def render(
        self, domain: Family, domain_info: DomainInfo, options: Options
    ) -> Rendered:
        """
        Build the atomic ``nft -f`` script for one family.

        nft is always save-shaped: no slow/eb command fallback, so
        ``Rendered.commands`` stays empty.  All ferm tables merge into ONE
        ``table <family> ferm``; chain names disambiguated via
        :func:`nft_chain_name` applied identically here and to
        jump/goto targets in :func:`build_verdict`.  ``@preserve`` is a
        plain error; a residual nft-name collision is a ferm
        error, NOT silent rule loss.
        """
        table = NftTable(family=domain.nft_name, name=NFT_TABLE_NAME)
        chains: list[NftBaseChain | NftRegularChain] = []
        rules: dict[str, list[NftRule]] = {}
        # mod recent's per-name element spec (timeout + calibrated rate) needs
        # facts spread across several rules of the family (the window lives on
        # the check rule, the bare `set` is target-less), so it is aggregated
        # in a whole-family pre-pass before any rule is translated.
        recent_specs = _build_recent_specs(
            domain,
            (
                rule
                for table_info in domain_info.tables.values()
                for chain_rules in table_info.chains.values()
                for rule in chain_rules.rules
            ),
        )
        # The SET target's runtime buckets must start empty, so their names
        # exempt both the mutating rules and lookups on them from the
        # empty-set drop below (the ban-list pattern).
        set_targets = _collect_set_target_names(
            rule
            for table_info in domain_info.tables.values()
            for chain_rules in table_info.chains.values()
            for rule in chain_rules.rules
        )
        for tbl in sorted(domain_info.tables):
            table_info = domain_info.tables[tbl]
            if table_info.preserve_regexes:
                raise FermError("@preserve not yet supported by nft backend")
            chains.extend(build_chains(domain, tbl, table_info))
            for original in sorted(table_info.chains):
                nft_name = nft_chain_name(tbl, original)
                if nft_name in rules:
                    raise FermError(
                        f"nft chain name collision '{nft_name}' in table "
                        f"{NFT_TABLE_NAME}"
                    )
                translated = [
                    translate_rule(
                        domain,
                        tbl,
                        rule,
                        chain=original,
                        recent_specs=recent_specs,
                        set_targets=set_targets,
                    )
                    for rule in table_info.chains[original].rules
                    if not _references_empty_named_set(rule, set_targets)
                ]
                # Assign connlimit set names from the final rule text BEFORE
                # collapse: distinct names keep collapse from folding two
                # connlimit rules into one (which would merge per-rule
                # conncount trees).  The order is load-bearing.
                _finalize_connlimit_names(domain, tbl, original, translated)
                rules[nft_name] = _collapse_chain_rules(translated)
        decls = _collect_set_declarations(domain, rules)
        save = serialize_table(
            table, chains, rules, decls, noflush=options.noflush
        )
        return Rendered(save=save)

    def commit(
        self,
        domain: Family,
        domain_info: DomainInfo,
        rendered: Rendered,
        options: Options,
        *,
        execute: ExecuteCommand,
        emit_line: LineEmitter,
        restore: RestoreDomain,
    ) -> int | None:
        """
        Apply one family: delta by default, full flush-replace as opt-out.

        Under ``--nft`` the default is an incremental delta against the
        captured ``domain_info.previous`` snapshot, so unchanged chains keep
        their packet/byte counters and unchanged named sets keep their kernel
        state.  ``--full-reload``, a first run / empty snapshot
        (:func:`needs_full_reload`), or a refcount-unsafe diff (any set
        ``remove``/retype -> ``build_nft_delta`` returns ``None``) fall back to
        the legacy ``flush table`` + full rebuild from ``render().save``.
        Inspection (``--lines``/``--shell``) shows exactly the text that will
        be applied.  An empty delta emits nothing and skips ``nft -f`` entirely
        (idempotency).
        """
        del execute  # nft is always save-shaped; no slow commands
        save = rendered.save
        if save is None:
            raise internal_error()
        family = domain.nft_name
        use_delta = not options.full_reload and not needs_full_reload(
            domain_info.previous
        )
        apply_text = save
        full_reload = True
        if use_delta:
            assert domain_info.previous is not None
            delta = build_nft_delta(domain_info.previous, save, family=family)
            if delta is not None:
                # None -> refcount-unsafe; keep apply_text == save (full
                # reload).  "" stays "" -> empty-delta no-op below.
                apply_text = delta
                full_reload = False
        if full_reload and not options.noflush:
            # Whole-table replace, not `flush table`: the latter keeps a
            # removed base chain's declaration (hook + policy) alive.
            # --noflush stays append-only (no flush line to rewrite).
            apply_text = _full_reload_text(save, family)
        if options.lines and apply_text:
            tool = domain_info.tools[TOOL_NFT]
            if options.shell:
                emit_line(f"{tool} -f - <<EOT\n")
            emit_line(apply_text)
            if options.shell:
                emit_line("EOT\n")
        if options.noexec:
            return None
        if not apply_text:
            return None  # empty delta: nothing to apply
        try:
            restore(domain_info, apply_text)
        except FermError as exc:
            print(exc, file=sys.stderr)
            return 1
        return None

    def capture_previous(
        self,
        domain: Family,
        domain_info: DomainInfo,
        options: Options,
        *,
        execute: ExecuteCommand,
        read_save: SaveReader,
        capture: ExecuteCapture,
    ) -> None:
        """
        Snapshot ONLY ferm's own table for rollback.

        Unlike x_tables, nft snapshots a single table via ``capture``
        (``nft list table <family> ferm``), not the whole ``*-save`` dump;
        ``read_save``/``execute`` are unused.  A first run (no ferm table
        yet) leaves ``previous`` ``None``.

        Under ``--test`` the mock path (``--test-mock-previous=fam=path``)
        is opened and read via :meth:`read_previous` -- the same contract
        as the iptables backend.  This makes ``read_previous``
        an active code path in test mode.
        """
        del read_save, execute
        family = domain.nft_name
        if options.test:
            mock = options.mock_previous.get(domain)
            if mock is not None:
                try:
                    handle = Path(mock).open(  # noqa: SIM115
                        encoding=BYTE_ENCODING
                    )
                except OSError as exc:
                    raise FermError(exc.strerror or str(exc)) from exc
                with handle:
                    domain_info.previous = self.read_previous(
                        handle, domain_info
                    )
            return
        snapshot = capture(
            f"{domain_info.tools[TOOL_NFT]} list table {family} "
            f"{NFT_TABLE_NAME}"
        )
        domain_info.previous = snapshot or None

    def rollback(
        self,
        domain: Family,
        domain_info: DomainInfo,
        options: Options,
        *,
        execute: ExecuteCommand,
        restore: RestoreDomain,
    ) -> None:
        """
        Restore ferm's own table, or delete it on a first-run snapshot.

        Skips a family no rule enabled.  With a captured snapshot the table
        is restored verbatim; without one (first run) the table is deleted,
        since there was nothing to restore.
        """
        del options
        if not domain_info.enabled:
            return
        family = domain.nft_name
        if domain_info.previous:
            restore(domain_info, domain_info.previous)
        else:
            execute(
                f"{domain_info.tools[TOOL_NFT]} delete table {family} "
                f"{NFT_TABLE_NAME}"
            )

    def read_previous(
        self, lines: Iterable[str], domain_info: DomainInfo
    ) -> str:
        """
        Return the raw nft snapshot verbatim.

        Invoked both by :meth:`capture_previous` under ``--test``
        (reading from the mock-previous file) and by the general
        ``--test-mock-previous`` path when the test harness opens the
        file directly.  ``domain_info`` is unused (nft needs no parse).
        """
        del domain_info
        return "".join(lines)

    def shell_snapshot(
        self, domain: Family, domain_info: DomainInfo
    ) -> ShellSnapshot | None:
        """
        Build the ``--shell`` anti-lockout snapshot for a family.

        Mirrors the live :meth:`rollback`: dump ferm's own table to a tempfile,
        and on restore delete the freshly-applied table before re-loading the
        dump.  A first run captures an empty file, so the delete alone removes
        ferm's table -- the same "nothing to restore" outcome as the live path.
        ``2>/dev/null`` + ``|| true`` keep a missing table (the first-run dump)
        or an already-gone table (the delete) from aborting the script.
        """
        nft = domain_info.tools[TOOL_NFT]
        family = domain.nft_name
        tmp = f"{domain}_tmp"
        return ShellSnapshot(
            setup=(
                f"{tmp}=$(mktemp ferm.XXXXXXXXXX)\n",
                f"{nft} list table {family} {NFT_TABLE_NAME} "
                f">${tmp} 2>/dev/null || true\n",
            ),
            restore=(
                f"{nft} delete table {family} {NFT_TABLE_NAME} "
                f"2>/dev/null || true\n"
                f"{nft} -f ${tmp}\n"
            ),
        )

    def shell_rollback_notice(self) -> str | None:
        """
        Announce the otherwise-silent ``--shell`` rollback on stderr.

        The per-family :meth:`shell_snapshot` restores swallow their output
        (``2>/dev/null``), so a timed-out admin would be reverted in silence.
        This line (emitted once, after every family's restore) mirrors the live
        path's "Firewall rules rolled back." message.
        """
        return "echo 'ferm: rolled back to the previous firewall rules.' >&2\n"
