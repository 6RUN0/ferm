"""
Shared CLI-level differential helper: run one config through the port and
the Perl oracle with --test --noexec --lines and assert byte-parity under the
corpus contract (exit verdict + normalized stderr + canonicalized stdout).
Reuses the compilers of test_config_differential; used by the diagnostic-order
gate and the walk-slicing / header parity tests. NOT a self-snapshot.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from tests._oracle import assert_oracle_parity
from tests.corpus.canon import canonicalize
from tests.property.test_config_differential import (
    _compile_oracle,
    _compile_port,
    _normalize_stderr,
)


def assert_cli_parity(
    config: str, *, extra_args: tuple[str, ...] = ()
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "input.ferm"
        path.write_text(config, encoding="utf-8")
        args = ["--test", "--noexec", "--lines", *extra_args, str(path)]
        port = _compile_port(args)
        oracle = _compile_oracle(args)
    assert_oracle_parity(
        port,
        oracle,
        canonicalize,
        normalize_stderr=_normalize_stderr,
        context=f"config:\n{config}",
    )
