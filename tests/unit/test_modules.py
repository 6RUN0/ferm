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
    ModuleDef,
    ParamFunction,
    Registry,
    _add_def,
)


def _match(*specs: str) -> ModuleDef:
    """Register a throwaway match-style module (default params == 1)."""
    defs: Registry = {}
    return _add_def(defs, "ip", 1, "m", specs)


# The encoding DSL strips suffixes in a fixed order -- ``*N`` (star), then
# ``=code`` (eq), then ``&fn`` (amp), then a leading ``!`` (negation +
# pre_negation), then a trailing ``!`` (negation only) -- each anchored at the
# end of the progressively shortened keyword.  One table pins every decode,
# including the combinations the per-suffix tests never crossed.
_ENCODING = [
    # -- single suffix, no negation
    pytest.param("helper", "helper", 1, False, False, id="plain-one-arg"),
    pytest.param("ashort*0", "ashort", None, False, False, id="star-zero"),
    pytest.param("aaddr=s", "aaddr", "s", False, False, id="code-s"),
    pytest.param("ctstate=c", "ctstate", "c", False, False, id="code-c"),
    pytest.param(
        "arp-htype=ss", "arp-htype", "ss", False, False, id="code-ss"
    ),
    pytest.param("u32=m", "u32", "m", False, False, id="code-m"),
    pytest.param(
        "source&address_magic",
        "source",
        ParamFunction("address_magic"),
        False,
        False,
        id="amp-function",
    ),
    # -- negation
    pytest.param("!mark", "mark", 1, True, True, id="leading-bang"),
    pytest.param("ahspi!", "ahspi", 1, True, False, id="trailing-bang"),
    pytest.param(
        "!ctstate=c", "ctstate", "c", True, True, id="lead-bang-code"
    ),
    pytest.param("!syn*0", "syn", None, True, True, id="lead-bang-star-zero"),
    pytest.param(
        # "=0" is not [acs]+/m, so eq never strips it: a faithful upstream
        # quirk where the keyword name literally keeps "=0" and takes one arg.
        "!socket-exists=0",
        "socket-exists=0",
        1,
        True,
        True,
        id="eq-zero-stays-in-name",
    ),
    # -- combinations the per-suffix tests never exercised
    pytest.param(
        "opt=sac", "opt", "sac", False, False, id="multi-letter-code"
    ),
    pytest.param(
        "retry*5", "retry", "5", False, False, id="star-nonzero-kept"
    ),
    pytest.param("!u32=m", "u32", "m", True, True, id="lead-bang-multivalue"),
    pytest.param(
        "ctstate!=c", "ctstate", "c", True, False, id="trailing-bang-code"
    ),
    pytest.param(
        "!source&address_magic",
        "source",
        ParamFunction("address_magic"),
        True,
        True,
        id="lead-bang-function",
    ),
]


@pytest.mark.parametrize(
    ("spec", "name", "params", "negation", "pre_negation"), _ENCODING
)
def test_encoding_decodes_keyword(
    spec: str,
    name: str,
    params: object,
    negation: bool,
    pre_negation: bool,
) -> None:
    kw = _match(spec).keywords[name]
    assert kw.name == name
    assert kw.params == params
    assert kw.negation is negation
    assert kw.pre_negation is pre_negation


def test_alias_shares_the_target_object_and_sets_ferm_name() -> None:
    keywords = _match("source!&address_magic", "saddr:=source").keywords
    assert keywords["saddr"] is keywords["source"]
    assert keywords["source"].ferm_name == "saddr"


def test_first_alias_wins_ferm_name() -> None:
    keywords = _match(
        "in-interface!",
        "interface:=in-interface",
        "if:=in-interface",
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
