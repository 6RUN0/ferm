"""The Nuitka entry dispatcher routes by the invoked-name basename."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType


def _find_repo_root() -> Path:
    # Anchor on the ``packaging/`` tree rather than a fixed parent depth: the
    # mutmut sandbox copies only ``src`` + ``tests`` into ``mutants/``, so the
    # test sits one level deeper there and ``packaging/`` lives in the real
    # checkout above it. Ascend to the nearest ancestor that actually has it.
    for parent in Path(__file__).resolve().parents:
        if (parent / "packaging").is_dir():
            return parent
    msg = "could not locate repo root (no ancestor contains packaging/)"
    raise RuntimeError(msg)


_ENTRY = _find_repo_root() / "packaging" / "entry.py"


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
    assert entry._invoked_name() == os.fsdecode(expected)


def test_selfcheck_imports_required_frozen_modules() -> None:
    # The frozen self-probe (condition 1) imports every load-bearing module
    # and returns 0; a missing one would raise ImportError -> non-zero.
    # dnspython is an optional dev dep (stdlib fallback exists), so skip the
    # host run when it is absent -- the real gate runs FERM_SELFCHECK=1 against
    # the binary, where dns is frozen in unconditionally.
    pytest.importorskip("dns.resolver")
    entry = _load_entry()
    assert entry.selfcheck_frozen() == 0


def _fake_stat(uid: int, mode: int) -> os.stat_result:
    # 10-field stat tuple: mode, ino, dev, nlink, uid, gid, size, atime,
    # mtime, ctime. Only mode and uid are inspected by the guard.
    return os.stat_result((mode, 0, 0, 1, uid, 0, 0, 0, 0, 0))


@pytest.mark.parametrize(
    ("uid", "mode"),
    [
        (0, 0o040755),  # root-owned, rwxr-xr-x
        (0, 0o040700),  # root-owned, rwx------
        (0, 0o042755),  # root-owned, setgid but no group/other write
    ],
)
def test_dist_dir_secure_accepts_root_owned_non_writable(
    uid: int, mode: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = _load_entry()
    monkeypatch.setattr(
        Path, "stat", lambda _self, *_a, **_k: _fake_stat(uid, mode)
    )
    # Returns None (no raise) for a correctly installed dist directory.
    assert entry._assert_dist_dir_secure(Path("/opt/ferm/ferm.dist")) is None


def test_dist_dir_secure_rejects_non_root_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = _load_entry()
    monkeypatch.setattr(
        Path, "stat", lambda _self, *_a, **_k: _fake_stat(1000, 0o040755)
    )
    with pytest.raises(SystemExit) as excinfo:
        entry._assert_dist_dir_secure(Path("/opt/ferm/ferm.dist"))
    assert "uid 1000" in str(excinfo.value)


@pytest.mark.parametrize("mode", [0o040757, 0o040775, 0o042777])
def test_dist_dir_secure_rejects_group_or_other_writable(
    mode: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = _load_entry()
    monkeypatch.setattr(
        Path, "stat", lambda _self, *_a, **_k: _fake_stat(0, mode)
    )
    with pytest.raises(SystemExit) as excinfo:
        entry._assert_dist_dir_secure(Path("/opt/ferm/ferm.dist"))
    assert "writable by group or other" in str(excinfo.value)


def test_dist_dir_secure_rejects_writable_shared_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A root-owned, non-writable dist dir holding a group/world-writable .so is
    # still an LPE vector: overwriting an existing file needs write permission
    # on the FILE, not the directory. The per-file sweep must catch it.
    entry = _load_entry()
    dist = Path("/opt/ferm/ferm.dist")
    shared_object = dist / "libcrypto.so.1"

    def _stat(self: Path, *_a: object, **_k: object) -> os.stat_result:
        if self == shared_object:
            return _fake_stat(0, 0o100666)  # root-owned but world-writable
        return _fake_stat(0, 0o040755)  # the dir itself is correct

    monkeypatch.setattr(Path, "stat", _stat)
    monkeypatch.setattr(Path, "glob", lambda _self, _pat: [shared_object])
    with pytest.raises(SystemExit) as excinfo:
        entry._assert_dist_dir_secure(dist)
    message = str(excinfo.value)
    assert "libcrypto.so.1" in message
    assert "writable by group or other" in message


def test_dist_dir_secure_rejects_non_root_shared_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A .so owned by a non-root uid inside a correct dir is also barred.
    entry = _load_entry()
    dist = Path("/opt/ferm/ferm.dist")
    shared_object = dist / "libssl.so.1"

    def _stat(self: Path, *_a: object, **_k: object) -> os.stat_result:
        if self == shared_object:
            return _fake_stat(1000, 0o100644)
        return _fake_stat(0, 0o040755)

    monkeypatch.setattr(Path, "stat", _stat)
    monkeypatch.setattr(Path, "glob", lambda _self, _pat: [shared_object])
    with pytest.raises(SystemExit) as excinfo:
        entry._assert_dist_dir_secure(dist)
    assert "libssl.so.1" in str(excinfo.value)
    assert "uid 1000" in str(excinfo.value)


def test_dist_dir_secure_accepts_root_owned_shared_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The per-file sweep must not red a correctly installed dist: dir and every
    # .so root-owned, non-writable.
    entry = _load_entry()
    dist = Path("/opt/ferm/ferm.dist")
    shared_objects = [dist / "libcrypto.so.1", dist / "libssl.so.1"]
    monkeypatch.setattr(
        Path, "stat", lambda _self, *_a, **_k: _fake_stat(0, 0o100644)
    )
    monkeypatch.setattr(Path, "glob", lambda _self, _pat: shared_objects)
    assert entry._assert_dist_dir_secure(dist) is None


def test_dist_dir_secure_treats_unstatable_dir_as_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A stat failure must never become a denial of service for a real install.
    def _raise(_self: Path, *_a: object, **_k: object) -> os.stat_result:
        raise OSError("vanished")

    entry = _load_entry()
    monkeypatch.setattr(Path, "stat", _raise)
    assert entry._assert_dist_dir_secure(Path("/opt/ferm/ferm.dist")) is None


def test_guard_is_noop_when_not_frozen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Loaded from source under pytest there is no __compiled__ marker, so the
    # guard must short-circuit before ever stat-ing anything.
    entry = _load_entry()

    def _boom(_dist_dir: Path) -> None:
        raise AssertionError("guard ran the check despite not being frozen")

    monkeypatch.setattr(entry, "_assert_dist_dir_secure", _boom)
    assert entry._guard_dist_dir_permissions() is None


def test_guard_is_noop_when_not_root(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = _load_entry()
    monkeypatch.setattr(entry, "__compiled__", object(), raising=False)
    monkeypatch.setattr(entry.os, "geteuid", lambda: 1000)

    def _boom(_dist_dir: Path) -> None:
        raise AssertionError("guard ran the check while unprivileged")

    monkeypatch.setattr(entry, "_assert_dist_dir_secure", _boom)
    assert entry._guard_dist_dir_permissions() is None


def test_guard_is_noop_when_opt_out_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = _load_entry()
    monkeypatch.setattr(entry, "__compiled__", object(), raising=False)
    monkeypatch.setattr(entry.os, "geteuid", lambda: 0)
    monkeypatch.setenv("FERM_SKIP_DIST_PERM_CHECK", "1")

    def _boom(_dist_dir: Path) -> None:
        raise AssertionError("guard ran the check despite the opt-out")

    monkeypatch.setattr(entry, "_assert_dist_dir_secure", _boom)
    assert entry._guard_dist_dir_permissions() is None


def test_guard_checks_resolved_binary_parent_when_frozen_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = _load_entry()
    monkeypatch.setattr(entry, "__compiled__", object(), raising=False)
    monkeypatch.setattr(entry.os, "geteuid", lambda: 0)
    monkeypatch.delenv("FERM_SKIP_DIST_PERM_CHECK", raising=False)
    monkeypatch.setattr(entry.sys, "executable", "/opt/ferm/ferm.dist/ferm")
    checked: list[Path] = []
    monkeypatch.setattr(entry, "_assert_dist_dir_secure", checked.append)
    entry._guard_dist_dir_permissions()
    assert checked == [Path("/opt/ferm/ferm.dist")]
