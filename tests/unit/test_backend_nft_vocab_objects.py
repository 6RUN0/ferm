"""
Unit matrix for the nft table *objects*: the SECMARK and CT-helper targets.

These two targets are the ones that declare a table *object*: the rule both
sets state (``meta secmark set "<name>"`` / ``ct helper set "<name>"``) and
implies the object it references (a ``secmark`` holding a context, a
``ct helper`` holding a helper name + protocol).  The object name is content-
addressed -- a secmark hashes its context, a ct-helper name fixes its proto --
so identical uses dedup to one object and the plan differ compares objects by
NAME alone, a fixed point without normalizing the body (which the kernel
readback augments, e.g. a ct helper's ``l3proto``).  Every emitted spelling was
captured from a live ``nft list ruleset`` readback (nft v1.1.6); the refusal
tests pin the fail-closed guards the dichotomy gate cannot see.
"""

from __future__ import annotations

import hashlib

import pytest

from pyferm.backend.nft import (
    NftMatch,
    NftObjectRef,
    NftRule,
    NftSetType,
    NftSetUpdate,
    NftTable,
    NftVerdict,
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
from pyferm.rules import RenderedRule
from pyferm.scope import OptionKind
from pyferm.streams import BYTE_ENCODING
from pyferm.values import SetRef
from tests.unit._nftrule import _opt

_SSH_CTX = "system_u:object_r:ssh_port_t:s0"
_HTTP_CTX = "system_u:object_r:http_port_t:s0"


def _name(context: str) -> str:
    digest = hashlib.sha256(context.encode(BYTE_ENCODING)).hexdigest()[:12]
    return f"secmark_{digest}"


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
    # (the CT/helper same-name-chain precedent).  Pin that it does NOT declare
    # a secmark object -- the object path is ip/ip6 only.
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


# -- CT helper object ---------------------------------------------------
#
# The CT target's `helper` knob is the second table object: `CT helper ftp`
# emits a `ct helper cthelper_ftp { type "ftp" protocol tcp; }` object plus a
# `ct helper set "cthelper_ftp"` rule statement.  Every spelling and the
# helper->protocol map below were captured from a live `nft list` readback on
# kernel 6.18.38 (nft v1.1.6): each supported name loads with exactly that one
# transport, `sip` loads under BOTH (so a single-proto object would narrow it),
# and `h323`/unknown names are ENOENT.  The object name is content-addressed
# (the name fixes the proto), so the plan differ compares by name alone and
# never normalizes the `l3proto ip` line the kernel adds on readback.

#: helper -> the single L4 proto its object binds, mirrored from the backend.
_CT_HELPER_PROTO = {
    "ftp": "tcp",
    "irc": "tcp",
    "sane": "tcp",
    "pptp": "tcp",
    "tftp": "udp",
    "amanda": "udp",
    "snmp": "udp",
    "netbios-ns": "udp",
}


def _ct_rule(**companions: str) -> RenderedRule:
    # A bare `CT` target plus its module-qualified companions (the `helper`
    # name collides with the `mod helper` match, so it is a companion only
    # when introduced by the CT target).  No match options: the object/dedup
    # behavior is what this isolates; the golden pair covers the port path.
    return RenderedRule(
        options=[
            _opt("jump", "CT", kind=OptionKind.TARGET),
            *(
                _opt(name, value, module="CT")
                for name, value in companions.items()
            ),
        ],
        script=None,
    )


def _ct_object(**companions: str) -> NftObjectRef:
    nft = translate_rule(Family.IP, "raw", _ct_rule(**companions))
    (obj,) = (s for s in nft.statements if isinstance(s, NftObjectRef))
    return obj


def test_cthelper_object_ref() -> None:
    obj = _ct_object(helper="ftp")
    assert obj.kind == "ct helper"
    assert obj.name == "cthelper_ftp"
    assert obj.body == 'type "ftp" protocol tcp;'
    assert obj.to_text() == 'ct helper set "cthelper_ftp"'


@pytest.mark.parametrize(("helper", "proto"), sorted(_CT_HELPER_PROTO.items()))
def test_cthelper_proto_map(helper: str, proto: str) -> None:
    # every supported helper binds its live-verified transport; the object body
    # spells `type "<helper>" protocol <proto>;`.
    obj = _ct_object(helper=helper)
    assert obj.body == f'type "{helper}" protocol {proto};'


def test_cthelper_dash_folded_in_name() -> None:
    # the object NAME must satisfy the nft bare-identifier grammar (no dash),
    # so `netbios-ns` folds to `cthelper_netbios_ns`; the TYPE keeps the real
    # dashed helper name, quoted.
    obj = _ct_object(helper="netbios-ns")
    assert obj.name == "cthelper_netbios_ns"
    assert obj.body == 'type "netbios-ns" protocol udp;'
    assert obj.to_text() == 'ct helper set "cthelper_netbios_ns"'


@pytest.mark.parametrize("helper", ["sip", "h323", "nosuch", "FTP"])
def test_cthelper_unsupported_name_refused(helper: str) -> None:
    # sip registers both tcp+udp (a single-proto object would narrow it), h323
    # has no loadable ct-helper object, an unknown name is ENOENT, and the map
    # is case-sensitive -- all refuse cleanly rather than emit a rejected load.
    with pytest.raises(FermError, match=r"no single-protocol nft ct-helper"):
        _ct_object(helper=helper)


def test_cthelper_empty_name_refused() -> None:
    with pytest.raises(FermError, match=r"needs a helper name"):
        _ct_object(helper="")


def test_cthelper_with_zone_ordering() -> None:
    # a rule mixing helper with a translatable CT option: the non-helper parts
    # emit first as one verdict, the helper object-ref last, in a fixed order
    # so --plan converges.  Both statements are present.
    nft = translate_rule(Family.IP, "raw", _ct_rule(helper="ftp", zone="5"))
    tails = [s.to_text() for s in nft.statements]
    assert tails == ["ct zone set 5", 'ct helper set "cthelper_ftp"']
    # the helper part rides an object-ref (declares the object); the zone part
    # is a plain verdict (no declaration).
    kinds = [type(s).__name__ for s in nft.statements]
    assert kinds == ["NftVerdict", "NftObjectRef"]


@pytest.mark.parametrize("bad", ["expevents", "timeout"])
def test_ct_unsupported_option_refused_even_with_helper(bad: str) -> None:
    # expevents/timeout have no nft equivalent; a rule mixing one with a
    # translatable helper must refuse UP FRONT -- never emit the helper and
    # silently drop the unsupported half (a fail-open mangle).
    rule = _ct_rule(helper="ftp", **{bad: "new"})
    with pytest.raises(FermError, match=rf"CT target option '{bad}'"):
        translate_rule(Family.IP, "raw", rule)


def test_ct_notrack_still_translates_without_helper() -> None:
    # regression: the non-helper CT path (now living in _ct_target_statements)
    # still emits its verdict and declares no object.
    nft = translate_rule(Family.IP, "raw", _ct_rule(notrack=""))
    assert not any(isinstance(s, NftObjectRef) for s in nft.statements)
    assert nft.statements[-1] == NftVerdict("notrack")


def test_cthelper_dedup_and_emission() -> None:
    # two rules with the same helper share ONE object; emission declares the
    # two-word `add ct helper ...` line before chains, sorted by name.
    rules = {
        "raw_PREROUTING": [
            translate_rule(Family.IP, "raw", _ct_rule(helper="ftp")),
            translate_rule(Family.IP, "raw", _ct_rule(helper="ftp")),
            translate_rule(Family.IP, "raw", _ct_rule(helper="tftp")),
        ]
    }
    decls = _collect_set_declarations(Family.IP, rules)
    assert set(decls) == {"cthelper_ftp", "cthelper_tftp"}
    save = serialize_table(
        NftTable("ip", "ferm"), [], rules, decls, noflush=False
    )
    assert (
        'add ct helper ip ferm cthelper_ftp { type "ftp" protocol tcp; }'
        in save
    )
    assert (
        'add ct helper ip ferm cthelper_tftp { type "tftp" protocol udp; }'
        in save
    )
    assert save.count("add ct helper") == 2


def test_cthelper_parse_both_forms() -> None:
    # both readers capture the two-word `ct helper` object.  The render form is
    # one-line braces; the `nft list` form spans lines and carries the extra
    # `l3proto ip` the kernel augments -- the name-only diff must ignore it.
    save = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        'add ct helper ip ferm cthelper_ftp { type "ftp" protocol tcp; }\n'
    )
    scripted = parse_nft_script(save)["ferm"].objects["cthelper_ftp"]
    assert scripted.kind == "ct helper"
    assert scripted.body == 'type "ftp" protocol tcp;'

    listing = (
        "table ip ferm {\n"
        "\tct helper cthelper_ftp {\n"
        '\t\ttype "ftp" protocol tcp\n'
        "\t\tl3proto ip\n"
        "\t}\n}\n"
    )
    listed = parse_nft_list(listing, family="ip")["ferm"].objects[
        "cthelper_ftp"
    ]
    assert listed.kind == "ct helper"
    # the l3proto augmentation is accumulated into the body but never diffed.
    assert "l3proto ip" in listed.body


def test_cthelper_plan_is_fixed_point() -> None:
    # desired (save form) vs a live readback carrying the `l3proto ip`
    # augmentation must converge: the object name matches, so no object change.
    desired = parse_nft_script(
        "add table ip ferm\n"
        "flush table ip ferm\n"
        'add ct helper ip ferm cthelper_ftp { type "ftp" protocol tcp; }\n'
        "add chain ip ferm raw_PREROUTING { type filter hook prerouting "
        "priority -300; }\n"
        "add rule ip ferm raw_PREROUTING tcp dport 21 ct helper set "
        '"cthelper_ftp"\n'
    )
    current = parse_nft_list(
        "table ip ferm {\n"
        "\tct helper cthelper_ftp {\n"
        '\t\ttype "ftp" protocol tcp\n'
        "\t\tl3proto ip\n"
        "\t}\n"
        "\tchain raw_PREROUTING {\n"
        "\t\ttype filter hook prerouting priority -300;\n"
        '\t\ttcp dport 21 ct helper set "cthelper_ftp"\n'
        "\t}\n}\n",
        family="ip",
    )
    diff = diff_tables(current, desired, noflush=False)
    assert diff.object_changes == []
    assert not diff.has_changes()


def test_cthelper_steady_state_delta_recognizes_two_word_line() -> None:
    # an unchanged ct-helper object on both sides: the delta stays surgical and
    # the desired-side indexer must PARSE the two-word `add ct helper` line
    # (it is present on every reconcile) without an internal_error, yet never
    # leak the declaration into the surgical delta.
    readback = (
        "table ip ferm {\n"
        "\tct helper cthelper_ftp {\n"
        '\t\ttype "ftp" protocol tcp\n'
        "\t\tl3proto ip\n"
        "\t}\n"
        "\tchain raw_PREROUTING {\n"
        "\t\ttype filter hook prerouting priority -300;\n"
        '\t\ttcp dport 21 ct helper set "cthelper_ftp"\n'
        "\t}\n}\n"
    )
    desired = (
        "add table ip ferm\n"
        "flush table ip ferm\n"
        'add ct helper ip ferm cthelper_ftp { type "ftp" protocol tcp; }\n'
        "add chain ip ferm raw_PREROUTING { type filter hook prerouting "
        "priority -300; }\n"
        "add rule ip ferm raw_PREROUTING tcp dport 21 ct helper set "
        '"cthelper_ftp"\n'
        "add rule ip ferm raw_PREROUTING ip saddr 10.0.0.1 drop\n"
    )
    delta = build_nft_delta(readback, desired, family="ip")
    assert delta is not None
    assert "add ct helper" not in delta
    assert "ip saddr 10.0.0.1 drop" in delta


def test_cthelper_object_change_render_output() -> None:
    # a ct-helper object change surfaces in all three renderers with its
    # two-word kind intact.
    diff = PlanDiff(
        object_changes=[
            ObjectChange("raw", "cthelper_ftp", "ct helper", added=True),
            ObjectChange("raw", "cthelper_irc", "ct helper", added=False),
        ]
    )
    assert "2 objects changed" in summary_line(diff)
    plan = Plan(families={"ip": diff})
    structured = render_structured(plan)
    assert "  + ct helper raw/cthelper_ftp" in structured
    assert "  - ct helper raw/cthelper_irc" in structured
    unified = render_unified(plan)
    assert "+add ct helper raw cthelper_ftp" in unified
    assert "-add ct helper raw cthelper_irc" in unified
