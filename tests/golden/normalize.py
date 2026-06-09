"""Output normalizers ported from the Makefile and helper scripts.

Three independent transforms, applied exactly where the Makefile applies
them (see the per-category pipelines in :mod:`runner`):

* :func:`result_sed` - the ``RESULT_SED`` block: rewrite long iptables
  options to their short forms, then drop comment lines.  The short forms
  let the checked-in ``.result`` files stay terse while ferm still emits
  long options.
* :func:`eb_arp_sed` - the ``EB_ARP_RESULT_SED`` block: only
  ``--jump`` -> ``-j`` (arptables/ebtables have no short option set).
* :func:`ebtables_tempfile_rename` - normalize the random
  ``/tmp/ferm.XXXX`` atomic-file suffixes to stable names.
"""

from __future__ import annotations

import re

# Ordered literal substitutions; order matches the Makefile's RESULT_SED
# -e sequence.  Each is a global (sed ``g``) replacement, i.e. str.replace.
# The trailing spaces on destination/source/match are significant: they
# avoid touching e.g. "--source-mac".
_RESULT_SUBS: tuple[tuple[str, str], ...] = (
    ("--protocol", "-p"),
    ("--in-interface", "-i"),
    ("--out-interface", "-o"),
    ("--destination ", "-d "),
    ("--source ", "-s "),
    ("--match ", "-m "),
    ("--jump", "-j"),
    ("--goto", "-g"),
    ("--fragment", "-f"),
)


def result_sed(text: str) -> str:
    """Apply ``RESULT_SED``: long->short options, then ``/^#/d``."""
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        for old, new in _RESULT_SUBS:
            line = line.replace(old, new)
        if line.startswith("#"):
            continue
        out.append(line)
    return "".join(out)


def eb_arp_sed(text: str) -> str:
    """Apply ``EB_ARP_RESULT_SED``: only ``--jump`` -> ``-j``."""
    return text.replace("--jump", "-j")


# First-match (no ``g``) substitutions from ebtables_tempfile_rename.pl.
# The order matters: the bare-suffix rule is tried first per line, then
# the "--atomic-save" variant, exactly as the Perl script applies them.
_TMP_SUFFIX = re.compile(r"--atomic-file /tmp/ferm.(\w+) ")
_TMP_SAVE = re.compile(r"--atomic-file /tmp/ferm.(\w+) --atomic-save")


def ebtables_tempfile_rename(text: str) -> str:
    """Normalize random ebtables ``/tmp/ferm.XXXX`` atomic-file names."""
    out: list[str] = []
    for line in text.splitlines(keepends=True):
        line = _TMP_SUFFIX.sub("--atomic-file /tmp/ferm.1 ", line, count=1)
        line = _TMP_SAVE.sub(
            "--atomic-file /tmp/ferm.0 --atomic-save", line, count=1
        )
        out.append(line)
    return "".join(out)
