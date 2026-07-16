"""
The read-only ``--plan`` mode and the etckeeper history commit.

Port-only (no oracle counterpart): :func:`build_plan` constructs the
desired-vs-kernel :class:`pyferm.plan.Plan` shared by ``--plan`` and the
etckeeper commit-message builder, so both describe the applied delta
identically.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from .. import etckeeper
from ..backend.iptables import rules_to_save, validate_names
from ..backend.nft import TOOL_NFT
from ..errors import ExitCode, FermError, internal_error
from ..functions import splitpath_file
from ..plan import (
    Plan,
    diff_tables,
    parse_nft_list,
    parse_nft_script,
    parse_save,
    render_plan,
    summary_line,
)
from .io import _enabled_domains, _validate_desired_nft

if TYPE_CHECKING:
    from ..backend.base import Backend
    from ..config import Options
    from ..domains import DomainInfo, Family


def build_plan(
    domains: dict[Family, DomainInfo],
    options: Options,
    backend: Backend,
    *,
    validate: bool = True,
) -> Plan:
    """
    Construct the desired-vs-kernel :class:`Plan` -- pure, no I/O.

    Shared by ``--plan`` (:func:`_run_plan`) and the etckeeper commit-message
    builder, so both describe the applied delta identically.  Runs no hooks
    and never prints or commits.

    Under iptables the desired side comes from ``rules_to_save`` and both
    sides are parsed with ``parse_save``.  Under nft the desired side is
    rendered by the backend and both sides are parsed with the nft parsers;
    ``noflush`` is always ``False`` under nft because the append-only model
    differs fundamentally from the iptables ``--noflush`` semantics.

    ``validate`` runs the ``nft -c`` pre-check on the rendered desired script;
    the commit-message path passes ``False`` because the rules are already
    applied, so a second check is pointless and could raise post-apply.
    """
    plan = Plan()
    for domain, domain_info in _enabled_domains(domains):
        if options.nft:
            # Reaching here with noflush is a logic error: _resolve_options
            # already rejects --plan --noflush --nft before this is called.
            if options.noflush:
                raise internal_error(
                    "build_plan: noflush set under --plan --nft"
                )
            family = domain.nft_name
            current = parse_nft_list(domain_info.previous or "", family=family)
            rendered = backend.render(domain, domain_info, options)
            try:
                desired_save = rendered.save
                if desired_save is None:
                    raise internal_error("nft render returned no save text")
                if validate:
                    _validate_desired_nft(
                        options, domain_info.tools[TOOL_NFT], desired_save
                    )
                desired = parse_nft_script(desired_save)
                plan.families[domain] = diff_tables(
                    current, desired, noflush=False
                )
            finally:
                rendered.close()
        else:
            if domain_info.plan_unsupported:
                plan.unsupported.append(domain)
                continue
            host_mask = "/32" if domain == "ip" else "/128"
            validate_names(domain_info)
            desired_text = rules_to_save(domain, domain_info, options)
            current_text = domain_info.previous or ""
            current = parse_save(current_text, host_mask=host_mask)
            desired = parse_save(desired_text, host_mask=host_mask)
            plan.families[domain] = diff_tables(
                current, desired, noflush=options.noflush
            )
    return plan


def _run_plan(
    domains: dict[Family, DomainInfo], options: Options, backend: Backend
) -> int:
    """
    Build and print the read-only plan; return the detailed exit code.

    Returns 0 (no changes) or 2 (changes); a ``FermError`` raised on the way
    (e.g. a strict save-read failure or an unsupported construct under nft)
    still exits 1 via :func:`main`.
    """
    plan = build_plan(domains, options, backend)
    sys.stdout.write(render_plan(plan, fmt=options.plan_format))
    return ExitCode.CHANGES if plan.has_changes() else ExitCode.OK


def _commit_subject(
    filename: str, domains: dict[Family, DomainInfo], options: Options
) -> str:
    """Build the default commit subject from the applied options."""
    verb = "flushed" if options.flush else "applied"
    families = " ".join(domain for domain, _ in _enabled_domains(domains))
    descriptors = [families] if families else []
    descriptors.append("nft" if options.nft else "iptables")
    if not options.fast:
        descriptors.append("slow")
    return f"{verb} {splitpath_file(filename)} ({', '.join(descriptors)})"


def _commit_body(plan: Plan) -> str:
    """Render the per-family semantic delta for the commit-message body."""
    lines = [
        f"  {family}: {summary_line(plan.families[family])}"
        for family in sorted(plan.families)
        if plan.families[family].has_changes()
    ]
    return "\n".join(lines)


def _build_commit_message(
    filename: str,
    domains: dict[Family, DomainInfo],
    options: Options,
    backend: Backend,
    subject: str | None,
) -> str:
    """
    Compose the etckeeper commit message (subject + semantic body).

    The body comes from :func:`build_plan` with ``validate=False`` -- the
    rules are already applied, so re-running ``nft -c`` is pointless and could
    raise post-apply.  If building the plan fails, degrade to a subject-only
    message rather than skipping the commit.
    """
    head = (
        subject
        if subject is not None
        else _commit_subject(filename, domains, options)
    )
    try:
        plan = build_plan(domains, options, backend, validate=False)
    except FermError:
        return f"ferm: {head}"
    body = _commit_body(plan)
    return f"ferm: {head}\n\n{body}" if body else f"ferm: {head}"


def _commit_history(
    filename: str,
    domains: dict[Family, DomainInfo],
    options: Options,
    backend: Backend,
    subject: str | None,
) -> None:
    """
    Commit the applied ruleset to ``/etc`` history via etckeeper (best-effort).

    Gated to a real apply that touched the kernel (not ``--noexec``/``--plan``/
    ``--test``) with etckeeper present and not disabled.  Skips silently when
    ``/etc`` has nothing to commit (a reboot/reload/idempotent re-run).  A
    failure here never disturbs the installed firewall.

    Scope caveat: etckeeper commits the WHOLE ``/etc`` tree, so an unrelated
    ``/etc`` edit left uncommitted at apply time is swept into this ferm-
    subjected commit.  The subject/body describe only the ferm delta; the
    recorded tree change may be broader.  This is inherent to etckeeper's
    "snapshot all of /etc" model, not a per-file commit.
    """
    if (
        options.noexec
        or options.plan
        or options.test
        or not options.etckeeper
        or etckeeper.find_etckeeper() is None
    ):
        return
    # Best-effort: the firewall is already applied, so no failure recording
    # history may propagate and flip the apply exit code.  A blanket guard
    # (Exception, not BaseException, so SystemExit/KeyboardInterrupt still
    # pass through) covers the status check, the plan rebuild and the commit.
    try:
        if not etckeeper.working_tree_dirty():
            return
        etckeeper.commit(
            _build_commit_message(filename, domains, options, backend, subject)
        )
    except Exception as exc:  # noqa: BLE001 -- never fail an applied firewall
        sys.stderr.write(f"ferm: etckeeper commit skipped: {exc}\n")
