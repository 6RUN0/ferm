"""
Unit matrix for the batch-11b nft vocabulary (SECMARK) and the object infra.

SECMARK is the first target that declares a table *object*: the rule both
sets a security context (``meta secmark set "<name>"``) and implies a
``secmark`` object holding the context.  The object name is a content hash of
the context, so identical contexts dedup to one object and the plan differ
compares objects by NAME alone -- a fixed point without normalizing the body.
Every emitted spelling was captured from a live ``nft list ruleset`` readback
(nft v1.1.6); the refusal tests pin the fail-closed guards (a missing/injected
context, a non-ip/ip6 family) the dichotomy gate cannot see.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from pyferm.backend.nft import (
    NftMatch,
    NftObjectRef,
    NftRule,
    NftSetType,
    NftSetUpdate,
    NftTable,
    _DynSetDecl,
    _ObjectDecl,
    _SetDecl,
    serialize_table,
    translate_rule,
)
from pyferm.backend.nft.sets import (
    _collect_set_declarations,
    _merge_dynamic_decl,
    _merge_static_decl,
)
from pyferm.domains import Family
from pyferm.errors import FermError
from pyferm.plan import (
    ObjectChange,
    ParsedObject,
    ParsedTable,
    Plan,
    PlanDiff,
    build_nft_delta,
    diff_tables,
    parse_nft_list,
    parse_nft_script,
    render_structured,
    render_unified,
    summary_line,
)
from pyferm.rules import RenderedOption, RenderedRule
from pyferm.scope import OptionKind
from pyferm.streams import BYTE_ENCODING
from pyferm.values import SetRef

if TYPE_CHECKING:
    from pyferm.values import Value

_SSH_CTX = "system_u:object_r:ssh_port_t:s0"
_HTTP_CTX = "system_u:object_r:http_port_t:s0"


def _name(context: str) -> str:
    digest = hashlib.sha256(context.encode(BYTE_ENCODING)).hexdigest()[:12]
    return f"secmark_{digest}"


def _opt(
    name: str,
    value: Value,
    kind: OptionKind = OptionKind.OPTION,
    module: str | None = None,
) -> RenderedOption:
    return RenderedOption(name=name, value=value, kind=kind, module=module)


def _secmark_rule(context: str) -> RenderedRule:
    # No match options: the SECMARK object/dedup behavior is what this matrix
    # isolates; the golden pair exercises the realistic `proto tcp dport` path.
    return RenderedRule(
        options=[
            _opt("jump", "SECMARK", kind=OptionKind.TARGET),
            _opt("selctx", context),
        ],
        script=None,
    )


def _statement(context: str, *, domain: Family = Family.IP) -> NftObjectRef:
    nft = translate_rule(domain, "mangle", _secmark_rule(context))
    (obj,) = (s for s in nft.statements if isinstance(s, NftObjectRef))
    return obj


# -- SECMARK statement --------------------------------------------------


def test_secmark_object_ref() -> None:
    obj = _statement(_SSH_CTX)
    name = _name(_SSH_CTX)
    assert obj.kind == "secmark"
    assert obj.name == name
    assert obj.body == f'"{_SSH_CTX}"'
    assert obj.to_text() == f'meta secmark set "{name}"'


def test_secmark_ip6_identical() -> None:
    # the secmark move carries no family-prefixed selector, so ip6 emits the
    # identical statement -- pin it so a future domain-aware refactor stays
    # honest.
    assert (
        _statement(_SSH_CTX, domain=Family.IP6).to_text()
        == _statement(_SSH_CTX).to_text()
    )


def test_secmark_missing_selctx_refused() -> None:
    rule = RenderedRule(
        options=[
            _opt("jump", "SECMARK", kind=OptionKind.TARGET),
        ],
        script=None,
    )
    with pytest.raises(FermError, match=r"^SECMARK target needs 'selctx'"):
        translate_rule(Family.IP, "mangle", rule)


def test_secmark_empty_selctx_refused() -> None:
    # an empty context is rejected early (symmetric with the missing case),
    # not emitted as `{ "" }` for the kernel to reject at load.
    with pytest.raises(FermError, match=r"non-empty security context"):
        _statement("")


@pytest.mark.parametrize("domain", [Family.ARP, Family.EB])
def test_secmark_non_ip_family_is_bare_chain_jump(domain: Family) -> None:
    # SECMARK is registered only for the ip/ip6 mangle table, so a `jump
    # SECMARK` in arp/eb is parser-unreachable; the domain guard leaves such a
    # value to build_verdict, which reads it as a jump to a same-table chain
    # (the batch-10 CT/helper precedent).  Pin that it does NOT declare a
    # secmark object -- the object path is ip/ip6 only.
    nft = translate_rule(domain, "mangle", _secmark_rule(_SSH_CTX))
    assert not any(isinstance(s, NftObjectRef) for s in nft.statements)
    assert nft.statements[-1].to_text() == "jump mangle_SECMARK"


@pytest.mark.parametrize("bad", ['a"b', "a\\b", "a\nb"])
def test_secmark_context_injection_refused(bad: str) -> None:
    # _nft_quote_string rejects an embedded quote/backslash/control char (nft
    # would mis-store or the load would break); the context is not sanitized
    # silently.
    with pytest.raises(FermError):
        _statement(bad)


# -- object collection + emission ---------------------------------------


def test_secmark_dedup_and_distinct() -> None:
    # two rules with the same context share ONE object; a third context adds a
    # second.  Emission declares objects sorted by name, before chains.
    rules = {
        "mangle_OUTPUT": [
            translate_rule(Family.IP, "mangle", _secmark_rule(_SSH_CTX)),
            translate_rule(Family.IP, "mangle", _secmark_rule(_HTTP_CTX)),
            translate_rule(Family.IP, "mangle", _secmark_rule(_SSH_CTX)),
        ]
    }
    decls = _collect_set_declarations(Family.IP, rules)
    assert set(decls) == {_name(_SSH_CTX), _name(_HTTP_CTX)}
    save = serialize_table(
        NftTable("ip", "ferm"), [], rules, decls, noflush=False
    )
    assert f'add secmark ip ferm {_name(_SSH_CTX)} {{ "{_SSH_CTX}" }}' in save
    assert (
        f'add secmark ip ferm {_name(_HTTP_CTX)} {{ "{_HTTP_CTX}" }}' in save
    )
    # objects precede the (here absent) chains: exactly two decl lines.
    assert save.count("add secmark") == 2


def test_object_name_collision_refused() -> None:
    # two objects under one name with differing bodies is a genuine collision
    # (content-addressing makes it unreachable in practice, but the guard fails
    # loud rather than silently dropping one declaration).
    rules = {
        "c": [
            NftRule(
                statements=[
                    NftObjectRef(
                        "secmark", "dup", '"a"', 'meta secmark set "dup"'
                    )
                ]
            ),
            NftRule(
                statements=[
                    NftObjectRef(
                        "secmark", "dup", '"b"', 'meta secmark set "dup"'
                    )
                ]
            ),
        ]
    }
    with pytest.raises(FermError, match=r"conflicting declarations"):
        _collect_set_declarations(Family.IP, rules)


# -- plan differ: fixed point + change ----------------------------------


_READBACK = f"""table ip ferm {{
\tsecmark {_name(_HTTP_CTX)} {{
\t\t"{_HTTP_CTX}"
\t}}
\tsecmark {_name(_SSH_CTX)} {{
\t\t"{_SSH_CTX}"
\t}}
\tchain mangle_OUTPUT {{
\t\ttype route hook output priority mangle; policy accept;
\t\tmeta secmark set "{_name(_SSH_CTX)}"
\t\tmeta secmark set "{_name(_HTTP_CTX)}"
\t}}
}}
"""


def _desired_save() -> str:
    rules = {
        "mangle_OUTPUT": [
            translate_rule(Family.IP, "mangle", _secmark_rule(_SSH_CTX)),
            translate_rule(Family.IP, "mangle", _secmark_rule(_HTTP_CTX)),
        ]
    }
    decls = _collect_set_declarations(Family.IP, rules)
    from pyferm.backend.nft.model import NftBaseChain

    chain = NftBaseChain(
        name="mangle_OUTPUT",
        type="route",
        hook="output",
        priority=-150,
    )
    return serialize_table(
        NftTable("ip", "ferm"), [chain], rules, decls, noflush=False
    )


def test_secmark_plan_is_fixed_point() -> None:
    # the readback of an applied ruleset must diff clean against the emission
    # (else --plan phantoms the objects forever).
    desired = parse_nft_script(_desired_save())
    current = parse_nft_list(_READBACK, family="ip")
    diff = diff_tables(current, desired, noflush=False)
    assert not diff.has_changes()
    assert build_nft_delta(_READBACK, _desired_save(), family="ip") == ""


def test_secmark_object_add_and_remove_diff() -> None:
    # a stale live secmark absent from the config removes; a config secmark
    # absent live adds.  Both diverting the family to a full reload.
    stale = _READBACK.replace(
        f'\tsecmark {_name(_HTTP_CTX)} {{\n\t\t"{_HTTP_CTX}"\n\t}}\n',
        '\tsecmark secmark_deadbeef0000 {\n\t\t"ctx"\n\t}\n',
    ).replace(f'meta secmark set "{_name(_HTTP_CTX)}"\n\t', "")
    desired = parse_nft_script(_desired_save())
    current = parse_nft_list(stale, family="ip")
    diff = diff_tables(current, desired, noflush=False)
    added = {o.name for o in diff.object_changes if o.added}
    removed = {o.name for o in diff.object_changes if not o.added}
    assert _name(_HTTP_CTX) in added
    assert "secmark_deadbeef0000" in removed
    # any object change -> full reload (None), never a surgical delta.
    assert build_nft_delta(stale, _desired_save(), family="ip") is None


# a single object shared by both sides, a base chain, and one config-only rule:
# the object is UNCHANGED, so build_nft_delta must take the surgical path (not
# a full reload) and its script must never leak an `add secmark` decl line.
_STEADY_NAME = _name(_SSH_CTX)

_STEADY_READBACK = f"""table ip ferm {{
\tsecmark {_STEADY_NAME} {{
\t\t"{_SSH_CTX}"
\t}}
\tchain mangle_OUTPUT {{
\t\ttype route hook output priority mangle; policy accept;
\t\tmeta secmark set "{_STEADY_NAME}"
\t}}
}}
"""

_STEADY_DESIRED = f"""add table ip ferm
flush table ip ferm
add secmark ip ferm {_STEADY_NAME} {{ "{_SSH_CTX}" }}
add chain ip ferm mangle_OUTPUT {{ type route hook output priority mangle; \
policy accept; }}
add rule ip ferm mangle_OUTPUT meta secmark set "{_STEADY_NAME}"
add rule ip ferm mangle_OUTPUT ip saddr 10.0.0.1 drop
"""


def test_secmark_steady_state_delta_omits_object_decl() -> None:
    # the object is present and identical on both sides; only a rule changes.
    # the delta must be surgical (not a reload) and carry the new rule, but the
    # object declaration must NOT ride along -- an unchanged object is left be.
    delta = build_nft_delta(_STEADY_READBACK, _STEADY_DESIRED, family="ip")
    assert delta is not None
    assert delta != ""
    assert "add secmark" not in delta
    assert "ip saddr 10.0.0.1 drop" in delta


# -- decl-collector guards: object vs set name collision ----------------


def test_merge_static_decl_object_collision_refused() -> None:
    # a static (match) set whose name already holds an object decl: the guard
    # fails loud rather than reading `.elements` off an _ObjectDecl.  Content
    # addressing makes this unreachable in practice, so exercise it directly.
    decls: dict[str, _SetDecl | _DynSetDecl | _ObjectDecl] = {
        "dup": _ObjectDecl("secmark", '"ctx"')
    }
    stmt = NftMatch(
        expr="ip saddr @dup",
        setref=SetRef("dup", ["10.0.0.1"]),
        set_selector="ip saddr",
    )
    with pytest.raises(FermError, match=r"conflicting declarations"):
        _merge_static_decl(decls, {}, Family.IP, stmt)


def test_merge_dynamic_decl_object_collision_refused() -> None:
    # a user (SET-target) dynamic set colliding with an object name hits the
    # dedicated isinstance(_ObjectDecl) guard on the owned=False path -- fail
    # loud instead of reading `.owned` off an object decl.
    decls: dict[str, _SetDecl | _DynSetDecl | _ObjectDecl] = {
        "dup": _ObjectDecl("secmark", '"ctx"')
    }
    stmt = NftSetUpdate(
        name="dup",
        key_expr="ip saddr",
        set_type="ipv4_addr",
        owned=False,
    )
    with pytest.raises(FermError, match=r"conflicting declarations"):
        _merge_dynamic_decl(decls, stmt)


# -- mixed decl emission + pure add/remove diff + render ----------------


def test_object_and_named_set_coexist_in_emission() -> None:
    # a named set and a table object share the family's decl dict (nft keeps
    # them in separate namespaces); serialize_table emits both, sorted by name.
    decls: dict[str, _SetDecl | _DynSetDecl | _ObjectDecl] = {
        "aset": _SetDecl(NftSetType.IPV4_ADDR, False, ["10.0.0.1"]),
        "secmark_abc": _ObjectDecl("secmark", '"ctx"'),
    }
    save = serialize_table(
        NftTable("ip", "ferm"), [], {}, decls, noflush=False
    )
    assert "add set ip ferm aset { type ipv4_addr; }" in save
    assert "add element ip ferm aset { 10.0.0.1 }" in save
    assert 'add secmark ip ferm secmark_abc { "ctx" }' in save


def test_object_pure_add_and_pure_remove_diff() -> None:
    # a desired-only object adds; a current-only object removes.  Both require
    # the table present in `desired` (diff_tables iterates the desired side).
    name = _name(_SSH_CTX)
    obj = ParsedObject(name, "secmark", f'"{_SSH_CTX}"')

    add = diff_tables(
        {"mangle": ParsedTable()},
        {"mangle": ParsedTable(objects={name: obj})},
        noflush=False,
    )
    assert [(o.name, o.added) for o in add.object_changes] == [(name, True)]

    remove = diff_tables(
        {"mangle": ParsedTable(objects={name: obj})},
        {"mangle": ParsedTable()},
        noflush=False,
    )
    assert [(o.name, o.added) for o in remove.object_changes] == [
        (name, False)
    ]


def test_object_change_render_output() -> None:
    # object changes surface in all three renderers: the summary tail, the
    # structured +/- bullets, and the unified diff (desired side for an add,
    # current side for a remove).
    diff = PlanDiff(
        object_changes=[
            ObjectChange("mangle", "secmark_aaa", "secmark", added=True),
            ObjectChange("mangle", "secmark_bbb", "secmark", added=False),
        ]
    )
    assert "2 objects changed" in summary_line(diff)

    plan = Plan(families={"ip": diff})
    structured = render_structured(plan)
    assert "  + secmark mangle/secmark_aaa" in structured
    assert "  - secmark mangle/secmark_bbb" in structured

    unified = render_unified(plan)
    assert "+add secmark mangle secmark_aaa" in unified
    assert "-add secmark mangle secmark_bbb" in unified


def test_parse_captures_object_body() -> None:
    # both readers must capture ParsedObject.body: the render form (one-line
    # brace) and the `nft list` form (multi-line body).  The body is kept for
    # rendering only -- objects diff by content-addressed name.
    name = _name(_SSH_CTX)
    save = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        f'add secmark ip ferm {name} {{ "{_SSH_CTX}" }}\n'
    )
    scripted = parse_nft_script(save)["ferm"].objects[name]
    assert scripted.kind == "secmark"
    assert scripted.body == f'"{_SSH_CTX}"'

    listing = (
        f'table ip ferm {{\n\tsecmark {name} {{\n\t\t"{_SSH_CTX}"\n\t}}\n}}\n'
    )
    listed = parse_nft_list(listing, family="ip")["ferm"].objects[name]
    assert listed.kind == "secmark"
    assert listed.body == f'"{_SSH_CTX}"'
