"""SetRef value type: dispatcher branches."""

import pytest

from pyferm.errors import FermError
from pyferm.values import (
    SetRef,
    cat,
    eval_bool,
    join_value,
    negate_value,
    to_array,
)


def test_setref_to_array_is_singleton() -> None:
    s = SetRef("ssh", ["22", "2222"])
    assert to_array(s) == [s]


def test_setref_eval_bool_nonempty_true() -> None:
    assert eval_bool(SetRef("ssh", ["22"])) is True


def test_setref_eval_bool_empty_false() -> None:
    assert eval_bool(SetRef("ssh", [])) is False


def test_setref_negate_raises() -> None:
    with pytest.raises(FermError, match="cannot negate"):
        negate_value(SetRef("ssh", ["22"]))


def test_setref_join_raises() -> None:
    with pytest.raises(FermError, match="set"):
        join_value(",", SetRef("ssh", ["22"]))


def test_setref_cat_raises() -> None:
    with pytest.raises(FermError):
        cat("x", SetRef("ssh", ["22"]))
