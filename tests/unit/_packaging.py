"""Shared repo-root anchor and source loaders for the packaging tests.

The ``packaging/`` scripts (build.py, entry.py, scan_image.py) live outside the
installed ``pyferm`` package, so the tests load them from source by path.  Both
the repo-root discovery and the importlib loader are shared here.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType


def find_repo_root() -> Path:
    """Return the checkout root: the nearest ancestor holding ``packaging/``.

    Anchor on the ``packaging/`` tree rather than a fixed parent depth: the
    mutmut sandbox copies only ``src`` + ``tests`` into ``mutants/``, so the
    test sits one level deeper there and ``packaging/`` lives in the real
    checkout above it.  Ascend to the nearest ancestor that actually has it.
    """
    for parent in Path(__file__).resolve().parents:
        if (parent / "packaging").is_dir():
            return parent
    msg = "could not locate repo root (no ancestor contains packaging/)"
    raise RuntimeError(msg)


def load_packaging_module(name: str, filename: str) -> ModuleType:
    """Load ``packaging/<filename>`` from source as a module named *name*."""
    path = find_repo_root() / "packaging" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
