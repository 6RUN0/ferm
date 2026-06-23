"""parse_nft_script learns add-set / add-element."""

import pytest

from pyferm.errors import FermError
from pyferm.plan import parse_nft_script


def test_parse_add_set_and_element() -> None:
    text = (
        "add table ip ferm\n"
        "add set ip ferm ssh { type inet_service; }\n"
        "add element ip ferm ssh { 22, 2222 }\n"
        "add chain ip ferm INPUT\n"
        "add rule ip ferm INPUT tcp dport @ssh accept\n"
    )
    tables = parse_nft_script(text)
    assert "ssh" in tables["ferm"].sets
    assert tables["ferm"].sets["ssh"].elements == ["22", "2222"]


def test_multiple_add_element_accumulate_and_sort() -> None:
    text = (
        "add table ip ferm\n"
        "add set ip ferm ports { type inet_service; }\n"
        "add element ip ferm ports { 80, 443 }\n"
        "add element ip ferm ports { 8080, 22 }\n"
    )
    tables = parse_nft_script(text)
    ps = tables["ferm"].sets["ports"]
    # sort_set_elements sorts numerically; expect ascending numeric order
    assert ps.elements == ["22", "80", "443", "8080"]


def test_add_set_non_ferm_table_raises() -> None:
    text = "add table ip ferm\nadd set ip other ssh { type inet_service; }\n"
    with pytest.raises(FermError):
        parse_nft_script(text)


def test_add_element_non_ferm_table_raises() -> None:
    text = "add table ip ferm\nadd element ip other ssh { 22 }\n"
    with pytest.raises(FermError):
        parse_nft_script(text)


def test_add_element_no_braces_raises() -> None:
    text = (
        "add table ip ferm\n"
        "add set ip ferm ssh { type inet_service; }\n"
        "add element ip ferm ssh 22\n"
    )
    with pytest.raises(FermError):
        parse_nft_script(text)
