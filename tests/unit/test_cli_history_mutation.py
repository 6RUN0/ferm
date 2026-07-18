"""
Mutation-killing unit tests for :mod:`pyferm.cli.history`.

Each test pins the exact arguments a seam receives (an argument-agnostic
mock would let kwarg-zeroing / dropped-argument mutants survive) or the
exact diagnostic string an ``internal_error`` raises, so a mutated
``build_plan`` is observable rather than masked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock

import pytest

from pyferm.backend.iptables import IptablesBackend
from pyferm.backend.nft import TOOL_NFT
from pyferm.cli import build_plan
from pyferm.cli import history as cli_history
from pyferm.config import Options
from pyferm.domains import TOOL_SAVE, DomainInfo, Family
from pyferm.errors import FermError

if TYPE_CHECKING:
    from pyferm.backend.base import Backend


def test_build_plan_default_runs_nft_check_with_pinned_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--plan (no explicit ``validate``) must nft-check with the real args."""
    domain_info = DomainInfo(enabled=True, tools={TOOL_NFT: "nft-path"})
    rendered = MagicMock()
    rendered.save = ""
    backend = MagicMock()
    backend.render.return_value = rendered
    options = Options(nft=True)

    calls: list[tuple[Options, str, str]] = []

    def validate_spy(
        options_arg: Options, path_arg: str, save_arg: str
    ) -> None:
        calls.append((options_arg, path_arg, save_arg))

    monkeypatch.setattr(cli_history, "_validate_desired_nft", validate_spy)

    build_plan({Family.IP: domain_info}, options, cast("Backend", backend))

    assert calls == [(options, "nft-path", "")]


def test_build_plan_nft_render_receives_domain_info_and_options() -> None:
    """The backend render is called with (domain, domain_info, options)."""
    domain_info = DomainInfo(enabled=True, tools={TOOL_NFT: "nft-path"})
    options = Options(nft=True)
    rendered = MagicMock()
    rendered.save = ""

    render_calls: list[tuple[Family, DomainInfo, Options]] = []

    def render_spy(
        domain_arg: Family, info_arg: DomainInfo, options_arg: Options
    ) -> object:
        render_calls.append((domain_arg, info_arg, options_arg))
        return rendered

    backend = MagicMock()
    backend.render.side_effect = render_spy

    build_plan(
        {Family.IP: domain_info},
        options,
        cast("Backend", backend),
        validate=False,
    )

    assert render_calls == [(Family.IP, domain_info, options)]


def test_build_plan_parses_current_nft_list_with_the_domain_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The kernel-side nft list is parsed under the domain's own family."""
    domain_info = DomainInfo(enabled=True, tools={TOOL_NFT: "nft-path"})
    rendered = MagicMock()
    rendered.save = ""
    backend = MagicMock()
    backend.render.return_value = rendered

    families: list[str] = []

    def list_spy(_text: str, *, family: str) -> dict[str, object]:
        families.append(family)
        return {}

    monkeypatch.setattr(cli_history, "parse_nft_list", list_spy)

    build_plan(
        {Family.IP: domain_info},
        Options(nft=True),
        cast("Backend", backend),
        validate=False,
    )

    assert families == ["ip"]


def test_build_plan_nft_noflush_is_an_internal_error() -> None:
    """``noflush`` under --plan --nft is an internal error with fixed text."""
    domain_info = DomainInfo(enabled=True, tools={TOOL_NFT: "nft-path"})
    backend = MagicMock()

    with pytest.raises(FermError) as excinfo:
        build_plan(
            {Family.IP: domain_info},
            Options(nft=True, noflush=True),
            cast("Backend", backend),
        )

    assert str(excinfo.value) == (
        "internal error: build_plan: noflush set under --plan --nft"
    )


def test_build_plan_missing_nft_save_is_an_internal_error() -> None:
    """A ``None`` render save raises the fixed no-save-text internal error."""
    domain_info = DomainInfo(enabled=True, tools={TOOL_NFT: "nft-path"})
    rendered = MagicMock()
    rendered.save = None
    backend = MagicMock()
    backend.render.return_value = rendered

    with pytest.raises(FermError) as excinfo:
        build_plan(
            {Family.IP: domain_info},
            Options(nft=True),
            cast("Backend", backend),
            validate=False,
        )

    assert str(excinfo.value) == (
        "internal error: nft render returned no save text"
    )
    rendered.close.assert_called_once()


def test_build_plan_iptables_renders_save_with_the_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The iptables desired side is saved for (domain, info, options)."""
    domain_info = DomainInfo(enabled=True, tools={TOOL_SAVE: "iptables-save"})
    options = Options()

    save_calls: list[tuple[Family, DomainInfo, Options]] = []

    def save_spy(
        domain_arg: Family, info_arg: DomainInfo, options_arg: Options
    ) -> str:
        save_calls.append((domain_arg, info_arg, options_arg))
        return ""

    monkeypatch.setattr(cli_history, "rules_to_save", save_spy)
    monkeypatch.setattr(cli_history, "validate_names", lambda _info: None)

    build_plan({Family.IP: domain_info}, options, IptablesBackend())

    assert save_calls == [(Family.IP, domain_info, options)]


def test_build_plan_continues_past_an_unsupported_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unsupported domain is skipped without aborting the remaining ones."""
    arp_info = DomainInfo(enabled=True, plan_unsupported=True)
    ip_info = DomainInfo(enabled=True, tools={TOOL_SAVE: "iptables-save"})

    monkeypatch.setattr(cli_history, "rules_to_save", lambda *_a: "")
    monkeypatch.setattr(cli_history, "validate_names", lambda _info: None)

    # Family sorts arp before ip, so the unsupported domain is first: a
    # ``break`` instead of ``continue`` would drop the ip family entirely.
    plan = build_plan(
        {Family.ARP: arp_info, Family.IP: ip_info},
        Options(),
        IptablesBackend(),
    )

    assert plan.unsupported == [Family.ARP]
    assert Family.IP in plan.families
