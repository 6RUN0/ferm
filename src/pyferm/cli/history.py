"""
The read-only ``--plan`` mode and the etckeeper history commit.

Port-only (no oracle counterpart): :func:`build_plan` constructs the
desired-vs-kernel :class:`pyferm.plan.Plan` shared by ``--plan`` and the
etckeeper commit-message builder, so both describe the applied delta
identically.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .. import __version__, etckeeper
from ..backend.iptables import rules_to_save, validate_names
from ..backend.nft import TOOL_NFT
from ..errors import ExitCode, FermError, internal_error
from ..functions import splitpath_file
from ..plan import (
    DeltaCounts,
    Plan,
    count_changes,
    delta_phrase,
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
    """Build the default subject head: verb + config + context brace."""
    families = " ".join(domain for domain, _ in _enabled_domains(domains))
    descriptors = [families] if families else []
    descriptors.append("nft" if options.nft else "iptables")
    if not options.fast:
        descriptors.append("slow")
    name = splitpath_file(filename)
    head = f"flush {name} rules" if options.flush else f"apply {name}"
    return f"{head} ({', '.join(descriptors)})"


def _redact_def_operand(operand: str) -> str:
    """Keep the variable name of a ``--def`` operand, hide its value."""
    name, sep, _value = operand.partition("=")
    return f"{name}=<redacted>" if sep else operand


def _redacted_argv(argv: list[str]) -> list[str]:
    """
    Copy ``argv`` with every ``--def`` VALUE replaced by ``<redacted>``.

    ``allow_abbrev=False`` in the parser means only the exact spellings
    ``--def OPERAND`` and ``--def=OPERAND`` can carry a definition.
    """
    redacted: list[str] = []
    expect_operand = False
    for arg in argv:
        if expect_operand:
            redacted.append(_redact_def_operand(arg))
            expect_operand = False
        elif arg == "--def":
            redacted.append(arg)
            expect_operand = True
        elif arg.startswith("--def="):
            operand = arg.removeprefix("--def=")
            redacted.append(f"--def={_redact_def_operand(operand)}")
        else:
            redacted.append(arg)
    return redacted


def _trailer_block() -> str:
    """
    Forensic git trailers recorded with every history commit.

    ``Ferm-Command`` is the program basename plus the argv, with one
    exception: ``--def`` VALUES are redacted (the variable name stays
    for forensics).  A ``--def`` exists precisely to inject a value the
    versioned config does NOT contain (a secret from a vault or the
    environment), so recording it verbatim would write that secret into
    the durable, replicable /etc git history for the first time.
    """
    command = " ".join([Path(sys.argv[0]).name, *_redacted_argv(sys.argv[1:])])
    return f"Ferm-Version: {__version__}\nFerm-Command: {command}"


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
    Compose the etckeeper commit message: head, delta tail, body, trailers.

    The plan is built FIRST (``validate=False`` -- the rules are already
    applied) and feeds both the subject tail and the per-family body, so
    they cannot disagree.  ``subject`` overrides only the verb-phrase
    head (rollback passes ``roll back <config> to <sha>``); the single
    composer glues the ``: <delta>`` tail onto BOTH paths.  A failed
    plan degrades to the bare head -- no tail, no body -- but the
    trailers do not depend on the plan and are always the last block.
    """
    head = (
        subject
        if subject is not None
        else _commit_subject(filename, domains, options)
    )
    try:
        plan = build_plan(domains, options, backend, validate=False)
    except FermError:
        return f"ferm: {head}\n\n{_trailer_block()}"
    counts = sum(
        (count_changes(diff) for diff in plan.families.values()),
        DeltaCounts(),
    )
    message = f"ferm: {head}: {delta_phrase(counts)}"
    body = _commit_body(plan)
    if body:
        message += f"\n\n{body}"
    return f"{message}\n\n{_trailer_block()}"


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
