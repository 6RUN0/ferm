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


def main() -> int:
    """Dispatch to the CLI named by the invocation and return its exit code."""
    if os.environ.get("FERM_SELFCHECK") == "1":
        return selfcheck_frozen()
    return select_main(_invoked_name())()


if __name__ == "__main__":
    sys.exit(main())
