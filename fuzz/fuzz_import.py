#!/usr/bin/env python3
"""
Coverage-guided crash fuzzer for ``import-ferm`` (atheris).

``import-ferm`` is the port's only parser that consumes genuinely external,
untrusted text: the stdout of the system ``iptables-save``.  This harness
feeds :meth:`pyferm.import_ferm.Importer.run` arbitrary byte streams and
looks for any input that makes it raise an unhandled exception -- the
robustness counterpart to the differential round-trip tests, which only
cover dumps the port itself produced.

:meth:`Importer.run` is pure (it parses lines and writes ferm syntax to the
injected stream -- no shell, no filesystem, no network), so no guards are
needed; the CLI's ``iptables-save`` invocation is bypassed entirely.

The exception allow-list -- inputs that are *not* a finding -- is
:class:`FermError` (every ``_die``/``_fetch_token`` malformed-input error
plus the ``internal error: ...`` markers) and :class:`RecursionError`
(``_optimize`` recurses on common-prefix blocks, so a pathological dump can
nest deeply).  Anything else propagates to atheris as a crash.

Run via ``nox -s crashfuzz``; standalone::

    uv run --group crashfuzz python fuzz/fuzz_import.py \
        fuzz/corpus/import fuzz/seeds/import -max_total_time=60
"""

from __future__ import annotations

import contextlib
import io
import sys

import atheris

with atheris.instrument_imports():
    from pyferm.errors import FermError
    from pyferm.import_ferm import Importer


def test_one_input(data: bytes) -> None:
    """Fuzz one input: import a save dump, swallowing non-bug errors."""
    provider = atheris.FuzzedDataProvider(data)
    text = provider.ConsumeUnicodeNoSurrogates(len(data))
    sink = io.StringIO()
    importer = Importer(io.StringIO(), "ip")
    with contextlib.redirect_stderr(sink):
        try:
            importer.run(text.splitlines())
        except (FermError, RecursionError):
            return


def main() -> None:
    """Wire the harness into atheris and start fuzzing."""
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
