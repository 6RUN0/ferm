"""parse_nft_list learns the multi-line kernel set block."""

from pyferm.plan import parse_nft_list


def test_parse_inline_set_block() -> None:
    """Single-line elements in the kernel set block are parsed correctly."""
    text = (
        "table ip ferm {\n"
        "\tset ssh {\n"
        "\t\ttype inet_service\n"
        "\t\telements = { 22, 2222 }\n"
        "\t}\n"
        "\tchain INPUT {\n"
        "\t\ttype filter hook input priority 0; policy accept;\n"
        "\t\ttcp dport @ssh accept\n"
        "\t}\n"
        "}\n"
    )
    tables = parse_nft_list(text, family="ip")
    assert tables["ferm"].sets["ssh"].elements == ["22", "2222"]
    assert "INPUT" in tables["ferm"].chains


def test_parse_multiline_set_block() -> None:
    """Multi-line elements block is collapsed by the preprocessor."""
    text = (
        "table ip ferm {\n"
        "\tset ssh {\n"
        "\t\ttype inet_service\n"
        "\t\telements = {\n"
        "\t\t\t22,\n"
        "\t\t\t2222\n"
        "\t\t}\n"
        "\t}\n"
        "\tchain INPUT {\n"
        "\t\ttype filter hook input priority 0; policy accept;\n"
        "\t\ttcp dport @ssh accept\n"
        "\t}\n"
        "}\n"
    )
    tables = parse_nft_list(text, family="ip")
    assert tables["ferm"].sets["ssh"].elements == ["22", "2222"]
    assert "INPUT" in tables["ferm"].chains


def test_parse_set_only_no_chains() -> None:
    """Table with only a set and no chains parses without error."""
    text = (
        "table ip ferm {\n"
        "\tset hosts {\n"
        "\t\ttype ipv4_addr\n"
        "\t\tflags interval\n"
        "\t\telements = { 10.0.0.1, 192.168.1.1 }\n"
        "\t}\n"
        "}\n"
    )
    tables = parse_nft_list(text, family="ip")
    assert set(tables["ferm"].sets["hosts"].elements) == {
        "10.0.0.1",
        "192.168.1.1",
    }
    assert tables["ferm"].chains == {}


def test_join_multiline_elements_is_noop_on_plain_text() -> None:
    """
    _join_multiline_elements is a no-op on text with no multi-line elements.
    """
    from pyferm.plan import _join_multiline_elements

    text = (
        "table ip ferm {\n\tchain INPUT {\n\t\ttcp dport 22 accept\n\t}\n}\n"
    )
    assert _join_multiline_elements(text) == text


def test_join_multiline_elements_is_noop_on_inline_elements() -> None:
    """_join_multiline_elements is identity on a single-line elements line."""
    from pyferm.plan import _join_multiline_elements

    inline = (
        "table ip ferm {\n\tset ssh {\n\t\telements = { 22, 2222 }\n\t}\n}\n"
    )
    assert _join_multiline_elements(inline) == inline
