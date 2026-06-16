"""The Nuitka entry dispatcher routes by the invoked-name basename."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

_ENTRY = Path(__file__).resolve().parents[2] / "packaging" / "entry.py"


def _load_entry() -> ModuleType:
    spec = importlib.util.spec_from_file_location("packaging_entry", _ENTRY)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_import_ferm_basename_routes_to_import_ferm() -> None:
    from pyferm.import_ferm import main as import_main

    entry = _load_entry()
    assert entry.select_main("/opt/ferm/ferm.dist/import-ferm") is import_main


def test_plain_ferm_basename_routes_to_cli() -> None:
    from pyferm.cli import main as cli_main

    entry = _load_entry()
    assert entry.select_main("/opt/ferm/ferm.dist/ferm") is cli_main


def test_import_ferm_bak_does_not_route_to_import_ferm() -> None:
    # Exact basename match, not startswith: import-ferm.bak is NOT import-ferm.
    from pyferm.cli import main as cli_main

    entry = _load_entry()
    assert entry.select_main("/tmp/import-ferm.bak") is cli_main


def test_invoked_name_reads_proc_cmdline_field0() -> None:
    # The dispatcher keys on /proc/self/cmdline field 0 (the kernel-preserved
    # argv[0]) rather than sys.argv[0], which Nuitka rewrites in the frozen
    # binary. On the host under pytest this is the interpreter path; assert the
    # function returns exactly that field, decoded.
    raw = Path("/proc/self/cmdline").read_bytes()
    expected = raw.split(b"\x00", 1)[0]
    pytest.importorskip("dns.resolver")  # _load_entry imports pyferm.cli deps
    entry = _load_entry()
    # Reaching into the dispatcher's private helper is the point of this test.
    assert entry._invoked_name() == os.fsdecode(expected)  # noqa: SLF001


def test_selfcheck_imports_required_frozen_modules() -> None:
    # The frozen self-probe (condition 1) imports every load-bearing module
    # and returns 0; a missing one would raise ImportError -> non-zero.
    # dnspython is an optional dev dep (stdlib fallback exists), so skip the
    # host run when it is absent -- the real gate runs FERM_SELFCHECK=1 against
    # the binary, where dns is frozen in unconditionally.
    pytest.importorskip("dns.resolver")
    entry = _load_entry()
    assert entry.selfcheck_frozen() == 0
