"""Unit tests for :mod:`pyferm.modules` (the option-encoding DSL + tables).

Locks the encoding rules of ``add_*_def`` (``reference/src/ferm:154``):
the ``params`` forms, leading/trailing ``!`` negation, ``:=`` aliasing
(shared object + first-wins ``ferm_name``), the ``*0`` falsy-params quirk,
the per-family default ``params`` and a few real-registry spot checks.
"""

from __future__ import annotations

import pytest

from pyferm.errors import FermError
from pyferm.modules import (
    MATCH_DEFS,
    PROTO_DEFS,
    SHORTCUTS,
    TARGET_DEFS,
    Keyword,
    ModuleDef,
    ParamFunction,
    Registry,
    _add_def,
)


def _match(*specs: str) -> ModuleDef:
    """Register a throwaway match-style module (default params == 1)."""
    defs: Registry = {}
    return _add_def(defs, "ip", 1, "m", specs)


def test_plain_keyword_takes_one_argument() -> None:
    kw = _match("helper").keywords["helper"]
    assert kw == Keyword(name="helper", params=1)


def test_star_zero_means_no_argument() -> None:
    kw = _match("ashort*0").keywords["ashort"]
    # *0 yields a falsy "0"; Perl's "if $params" leaves params unset.
    assert kw.params is None
    assert kw.name == "ashort"


def test_equals_codes_become_param_string() -> None:
    keywords = _match("aaddr=s", "ctstate=c", "arp-htype=ss").keywords
    assert keywords["aaddr"].params == "s"
    assert keywords["ctstate"].params == "c"
    assert keywords["arp-htype"].params == "ss"


def test_multi_code_m() -> None:
    assert _match("u32=m").keywords["u32"].params == "m"


def test_ampersand_records_named_parser() -> None:
    kw = _match("source&address_magic").keywords["source"]
    assert kw.params == ParamFunction("address_magic")
    assert kw.name == "source"


def test_leading_bang_sets_negation_and_pre_negation() -> None:
    kw = _match("!mark").keywords["mark"]
    assert kw.negation is True
    assert kw.pre_negation is True
    assert kw.name == "mark"


def test_trailing_bang_sets_negation_only() -> None:
    kw = _match("ahspi!").keywords["ahspi"]
    assert kw.negation is True
    assert kw.pre_negation is False


def test_bang_combines_with_equals_and_star() -> None:
    keywords = _match("!ctstate=c", "!syn*0").keywords
    ctstate = keywords["ctstate"]
    assert (ctstate.params, ctstate.negation, ctstate.pre_negation) == (
        "c", True, True,
    )
    syn = keywords["syn"]
    assert (syn.params, syn.negation, syn.pre_negation) == (None, True, True)


def test_equals_zero_is_not_a_code_and_stays_in_the_name() -> None:
    # "=0" is not [acs]+/m, so it is never stripped: a faithful upstream
    # quirk where the keyword name literally keeps "=0" and takes one arg.
    kw = _match("!socket-exists=0").keywords["socket-exists=0"]
    assert kw.name == "socket-exists=0"
    assert kw.params == 1
    assert kw.pre_negation is True


def test_alias_shares_the_target_object_and_sets_ferm_name() -> None:
    keywords = _match("source!&address_magic", "saddr:=source").keywords
    assert keywords["saddr"] is keywords["source"]
    assert keywords["source"].ferm_name == "saddr"


def test_first_alias_wins_ferm_name() -> None:
    keywords = _match(
        "in-interface!", "interface:=in-interface", "if:=in-interface",
    ).keywords
    assert keywords["interface"] is keywords["in-interface"]
    assert keywords["if"] is keywords["in-interface"]
    assert keywords["in-interface"].ferm_name == "interface"


def test_alias_to_unknown_target_errors() -> None:
    with pytest.raises(FermError, match="alias target"):
        _match("x:=nope")


def test_target_default_params_is_scalar() -> None:
    defs: Registry = {}
    module = _add_def(defs, "ip", "s", "T", ("reject-with",))
    assert module.keywords["reject-with"].params == "s"


def test_duplicate_module_registration_errors() -> None:
    defs: Registry = {}
    _add_def(defs, "ip", 1, "dup", ())
    with pytest.raises(FermError, match="already defined"):
        _add_def(defs, "ip", 1, "dup", ())


def test_module_without_specs_has_empty_keywords() -> None:
    assert _match().keywords == {}


def test_real_registry_proto_tcp() -> None:
    tcp = PROTO_DEFS["ip"]["tcp"].keywords
    assert tcp["tcp-flags"].params == "cc"
    assert tcp["tcp-flags"].negation is True
    syn = tcp["syn"]
    assert syn.params is None
    assert syn.pre_negation is True


def test_real_registry_match_base_aliases() -> None:
    base = MATCH_DEFS["ip"][""].keywords
    assert base["source"].params == ParamFunction("address_magic")
    assert base["saddr"] is base["source"]
    assert base["if"] is base["in-interface"]


def test_real_registry_target_dnat_is_multi() -> None:
    dnat = TARGET_DEFS["ip"]["DNAT"].keywords
    assert dnat["to-destination"].params == "m"
    assert dnat["to"] is dnat["to-destination"]


def test_real_registry_other_families_present() -> None:
    assert "destination-ip" in MATCH_DEFS["arp"][""].keywords
    assert "ip-source" in PROTO_DEFS["eb"]["IPv4"].keywords
    assert "arpreply-mac" in TARGET_DEFS["eb"]["arpreply"].keywords


def test_shortcuts_table() -> None:
    assert SHORTCUTS["ip"]["sports"] == ["multiport", "source-ports"]
    assert SHORTCUTS["ip"]["comment"] == ["comment", "comment"]
