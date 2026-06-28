"""
Nuitka standalone entry point: one compiled main module, two CLIs.

Nuitka compiles a single main module; this dispatcher selects the real
entry by the basename of the invoked name:

* basename == ``import-ferm`` -> :func:`pyferm.import_ferm.main`
* otherwise                   -> :func:`pyferm.cli.main`

The invoked name comes from ``/proc/self/cmdline``, NOT ``sys.argv[0]``:
Nuitka's standalone bootstrap rewrites ``sys.argv[0]`` to the resolved real
binary path, so invoking the in-dist ``import-ferm`` symlink would otherwise
present as ``ferm`` and misroute. The kernel preserves the original
``argv[0]`` in ``/proc/self/cmdline``, which the symlink name survives in.

Exact basename comparison, not a prefix: ``[project.scripts]`` names the
script exactly ``import-ferm`` (``pyproject.toml``), and ``startswith``
would misroute ``import-ferm.bak``.

The dispatcher calls ``main()`` with NO argv argument: both
``cli.main(argv=None)`` (argparse) and ``import_ferm.main(argv=None)``
(re-reads ``sys.argv[1:]`` itself) read the whole, untouched ``sys.argv``.
It must NOT reconstruct or strip ``argv[0]``. The return code is forwarded
to ``sys.exit`` so exit codes (significant for diagnostics pairs) survive,
mirroring ``src/pyferm/__main__.py``.

``selfcheck_frozen`` is the integrity probe FROM the binary (condition 1 of
the frozen-import gate): triggered by ``FERM_SELFCHECK=1`` it imports every
module that is invisible to Nuitka's static analysis (function-local /
find_spec-gated) and exits non-zero if any failed to freeze in. This lives
in ``packaging/`` (NOT ``src/pyferm``), so the phase invariant holds: the
shipped CLIs never see this code path.

``_guard_dist_dir_permissions`` is a best-effort load-time safety net: ferm
runs as root and ``dlopen()``s sibling shared objects from its standalone
``*.dist/`` directory, so a dist directory writable by a non-root user lets
an attacker plant a malicious ``.so`` and gain root. The guard refuses to
dispatch when the dist directory is not root-owned or is group/world
writable. It is best-effort by construction -- it catches a writable
directory, not a payload already planted before the check (a
time-of-check/time-of-use gap) -- so it complements, never replaces, a
correct root-owned install. It runs ONLY from the frozen binary
(``__compiled__`` present) AND when running as root; a developer running
the dist tree unprivileged, or any non-frozen ``python`` run, is unaffected.
``FERM_SKIP_DIST_PERM_CHECK=1`` opts out for unusual but deliberate layouts.
This too lives in ``packaging/`` (NOT ``src/pyferm``), so the shipped CLIs
never carry it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

#: Modules that MUST be frozen into the dist but are invisible to Nuitka's
#: static import graph: ``signal``/``termios`` are imported function-locally
#: in the interactive path, ``dns``/``dns.rdtypes`` behind a ``find_spec``
#: gate + function-local import. A typo in ``--include-*`` silently no-ops;
#: this probe is what turns that into a red build.
_REQUIRED_FROZEN = ("signal", "termios", "dns.resolver", "dns.rdtypes")

#: Opt-out for the dist-directory permission guard, for deliberate non-standard
#: layouts (e.g. a container that runs from a bind mount it trusts).
_SKIP_DIST_PERM_CHECK_ENV = "FERM_SKIP_DIST_PERM_CHECK"

#: Group/other write bits. A dist directory carrying either is writable by a
#: principal other than its owner, which is the .so-planting LPE vector.
_NON_OWNER_WRITE_BITS = 0o022


def selfcheck_frozen() -> int:
    """
    Import every required frozen module; return 0 if all present.

    Raises ``ImportError`` (propagates non-zero) if a module is absent.
    """
    import importlib

    for module_name in _REQUIRED_FROZEN:
        importlib.import_module(module_name)  # ImportError propagates
    print("FROZEN-SELFCHECK-OK")
    return 0


def select_main(argv0: str) -> Callable[[], int]:
    """Return the CLI ``main`` for the invoked basename."""
    if Path(argv0).name == "import-ferm":
        from pyferm.import_ferm import main
    else:
        from pyferm.cli import main
    return main


def _invoked_name() -> str:
    """
    Return the name the binary was invoked under (symlink name preserved).

    Reads field 0 of ``/proc/self/cmdline`` because Nuitka rewrites
    ``sys.argv[0]`` to the resolved binary path, erasing the ``import-ferm``
    symlink name. Falls back to ``sys.argv[0]`` when ``/proc`` is unavailable
    or empty.
    """
    try:
        raw = Path("/proc/self/cmdline").read_bytes()
    except OSError:
        return sys.argv[0]
    argv0 = raw.split(b"\x00", 1)[0]
    return os.fsdecode(argv0) if argv0 else sys.argv[0]


def _path_write_problems(path: Path, *, label: str) -> list[str]:
    """
    Return permission problems for a path that must be root-only-writable.

    A path owned by a non-root uid or carrying the group/other write bits
    (:data:`_NON_OWNER_WRITE_BITS`) is reportable: either lets a non-root
    principal replace the code root loads. An unstatable path yields no
    problem -- a stat hiccup must never become a denial of service for a
    correct install.
    """
    try:
        info = path.stat()
    except OSError:
        return []
    problems: list[str] = []
    if info.st_uid != 0:
        problems.append(f"{label} is owned by uid {info.st_uid}, not root")
    if info.st_mode & _NON_OWNER_WRITE_BITS:
        problems.append(f"{label} is writable by group or other")
    return problems


def _assert_dist_dir_secure(dist_dir: Path) -> None:
    """
    Refuse to run from a dist directory writable by a non-root principal.

    Raises ``SystemExit`` with an actionable diagnostic when the dist
    directory OR any bundled ``*.so`` inside it is not root-owned or is
    group/other writable. The per-file sweep matters because overwriting an
    existing ``.so`` needs write permission on the *file*, not the directory,
    so a root-owned ``0755`` dist with a stray group-writable ``libcrypto.so``
    is still an LPE vector the directory check alone would miss. Returns
    ``None`` when everything is safe.

    Out of scope (still best-effort): a writable *parent* directory above the
    dist dir, and any payload planted before this runs (the documented
    time-of-check/time-of-use gap). Reinstall root-owned to close those.
    """
    problems = _path_write_problems(
        dist_dir, label=f"the standalone directory {dist_dir}"
    )
    try:
        shared_objects = sorted(dist_dir.glob("*.so*"))
    except OSError:
        shared_objects = []
    for shared_object in shared_objects:
        problems += _path_write_problems(
            shared_object, label=f"the shared object {shared_object.name}"
        )
    if not problems:
        return
    detail = "; ".join(problems)
    raise SystemExit(
        f"ferm: refusing to run: {detail}. ferm runs as root and loads\n"
        f"shared objects from {dist_dir}, so a non-root-writable location is\n"
        f"a privilege-escalation risk. Reinstall into a root-owned directory\n"
        f"(chown -R root:root and chmod -R go-w it), or set "
        f"{_SKIP_DIST_PERM_CHECK_ENV}=1 to override deliberately.",
    )


def _guard_dist_dir_permissions() -> None:
    """
    Run the dist-directory permission guard when, and only when, it applies.

    No-op unless this is the frozen standalone binary (Nuitka injects the
    module global ``__compiled__``) running as root, with the opt-out unset.
    The dist directory is the resolved parent of the running binary
    (``sys.executable``), whose siblings are the shared objects ferm loads.
    """
    if "__compiled__" not in globals():
        return
    if os.environ.get(_SKIP_DIST_PERM_CHECK_ENV) == "1":
        return
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    _assert_dist_dir_secure(Path(sys.executable).resolve().parent)


def main() -> int:
    """Dispatch to the CLI named by the invocation and return its exit code."""
    if os.environ.get("FERM_SELFCHECK") == "1":
        return selfcheck_frozen()
    _guard_dist_dir_permissions()
    return select_main(_invoked_name())()


if __name__ == "__main__":
    sys.exit(main())
