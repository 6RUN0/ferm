"""Unit tests for :mod:`pyferm.scope`.

Locks the copy-on-write scoping semantics ported from
``reference/src/ferm`` (``:2033-2068``): ``new_level`` inheritance and what
it shares vs copies vs drops, ``copy_on_write`` detaching the shared
``keywords`` dict exactly once, ``merge_keywords`` triggering that detach,
and the ``@stack`` / ``$auto_chain`` primitives.
"""

from __future__ import annotations

from pyferm.modules import Keyword
from pyferm.scope import (
    Frame,
    Option,
    Rule,
    Scope,
    SourcePosition,
    copy_on_write,
    merge_keywords,
    new_level,
)


def test_new_level_without_parent_is_empty() -> None:
    rule = new_level(None)
    assert rule == Rule()
    assert rule.cow == set()
    assert rule.keywords == {}


def test_new_level_inherits_scalar_context() -> None:
    prev = Rule(
        domain="ip6",
        domain_family="ip",
        domain_both=True,
        table="nat",
        chain="INPUT",
        protocol="tcp",
        auto_protocol="udp",
        has_rule=True,
        has_action=True,
    )
    rule = new_level(prev)
    assert rule.domain == "ip6"
    assert rule.domain_family == "ip"
    assert rule.domain_both is True
    assert rule.table == "nat"
    assert rule.chain == "INPUT"
    assert rule.protocol == "tcp"
    assert rule.auto_protocol == "udp"
    assert rule.has_rule is True
    assert rule.has_action is True


def test_new_level_drops_transient_keys() -> None:
    prev = Rule(non_empty=True, script=SourcePosition("a.ferm", 7))
    rule = new_level(prev)
    assert rule.non_empty is False
    assert rule.script is None


def test_new_level_shares_keywords_but_marks_cow() -> None:
    helper = Keyword(name="helper", params=1)
    prev = Rule(keywords={"helper": helper})
    rule = new_level(prev)
    assert rule.keywords is prev.keywords  # shared object
    assert rule.cow == {"keywords"}


def test_new_level_copies_match_and_options() -> None:
    prev = Rule(match={"tcp"}, options=[Option("source", "1.2.3.4")])
    rule = new_level(prev)
    assert rule.match == {"tcp"}
    assert rule.match is not prev.match  # independent copy
    assert rule.options == prev.options
    assert rule.options is not prev.options
    # shallow copy: mutating the child's list must not touch the parent
    rule.options.append(Option("dport", "80"))
    assert len(prev.options) == 1


def test_copy_on_write_is_noop_when_not_marked() -> None:
    helper = Keyword(name="helper", params=1)
    rule = Rule(keywords={"helper": helper})
    copy_on_write(rule, "keywords")  # cow is empty
    assert rule.keywords["helper"] is helper


def test_copy_on_write_detaches_shared_keywords_once() -> None:
    shared = {"helper": Keyword(name="helper", params=1)}
    rule = new_level(Rule(keywords=shared))
    copy_on_write(rule, "keywords")
    assert rule.keywords is not shared  # detached
    assert rule.keywords == shared  # same contents
    assert "keywords" not in rule.cow
    # a second call is a no-op now that cow is cleared
    detached = rule.keywords
    copy_on_write(rule, "keywords")
    assert rule.keywords is detached


def test_merge_keywords_detaches_then_adds() -> None:
    shared = {"helper": Keyword(name="helper", params=1)}
    rule = new_level(Rule(keywords=shared))
    extra = Keyword(name="mark", params=1)
    merge_keywords(rule, {"mark": extra})
    assert rule.keywords["mark"] is extra
    assert "mark" not in shared  # parent untouched by the merge
    assert "keywords" not in rule.cow


def test_merge_keywords_later_definitions_win() -> None:
    first = Keyword(name="x", params=1)
    second = Keyword(name="x", params="s")
    rule = Rule(keywords={"x": first})
    merge_keywords(rule, {"x": second})
    assert rule.keywords["x"] is second


def test_frame_defaults_are_independent() -> None:
    a = Frame()
    b = Frame()
    a.vars["x"] = "1"
    assert b.vars == {}


def test_scope_push_pop_and_ends() -> None:
    scope = Scope()
    bottom = Frame(auto={"DOMAIN": "ip"})
    top = Frame(vars={"x": "1"})
    scope.push(bottom)
    scope.push(top)
    assert scope.top is top  # most recently pushed
    assert scope.globals is bottom  # outermost
    assert scope.pop() is top
    assert scope.top is bottom


def test_scope_next_auto_chain_preincrements() -> None:
    scope = Scope()
    assert scope.next_auto_chain() == "ferm_auto_1"
    assert scope.next_auto_chain() == "ferm_auto_2"
    assert scope.auto_chain == 2
