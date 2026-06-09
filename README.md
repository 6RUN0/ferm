# ferm (Python port)

`ferm` ("For Easy Rule Making") is a frontend for `iptables`: it reads
firewall rules from a structured configuration language and installs them
into the running kernel.

This repository is mid-migration from the original Perl implementation to
Python:

- **`src/pyferm/`** - the Python port (in progress). Phase 1 keeps emitting
  iptables and is validated byte-for-byte against the Perl oracle.
- **`reference/`** - the original Perl implementation, kept as the semantic
  oracle. Run its test suite with `make -C reference check`.

The porting strategy, phase breakdown, and detailed design live under
`docs/superpowers/specs/`.

## Development

The project is managed entirely with [uv](https://docs.astral.sh/uv/):

```sh
uv sync                 # create .venv from uv.lock
uv run nox -s lint tests typecheck
```

## License

GPL-2.0-or-later. See `reference/COPYING`.
