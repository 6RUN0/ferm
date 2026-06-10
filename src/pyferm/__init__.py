"""
pyferm: a faithful Python port of ferm (Phase 1, iptables output).

The distribution is named ``ferm``; ``__version__`` is read from the
installed package metadata so the version has a single source of truth
(mirrors how the Perl ``ferm --version`` is the authority today).
"""

from importlib import metadata

try:
    __version__ = metadata.version("ferm")
except metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = "0+unknown"

__all__ = ["__version__"]
