"""
Render docs/templates/*.pod.j2 -> docs/*.pod -> docs/man/*.1.

The intermediate .pod files are gitignored; the troff pages are
committed and guarded by a freshness gate
(tests/unit/test_man_pages.py).  pod2man's date/release/center are
pinned so the output is byte-deterministic for a given Pod::Man
version -- without the pins the date comes from the .pod mtime and the
release from the local perl, both unstable across checkouts.

Lives outside src/ on purpose: a tool may import anything
(import-linter does not check scripts) and jinja2 is a dev-only
dependency that must never reach the runtime package.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Final

import jinja2

from pyferm import __version__, cli_doc

_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
_TEMPLATES: Final[Path] = _ROOT / "docs" / "templates"

#: Fixed pod2man date: bump by hand when regenerating after a content
#: change (the freshness gate normalises the whole .TH line, so the
#: date never causes false staleness).
_MAN_DATE: Final[str] = "2026-07-17"
_MAN_CENTER: Final[str] = "ferm"

#: template name -> (render context, man page NAME).
_PAGES: Final[dict[str, tuple[dict[str, object], str]]] = {
    "ferm.pod": (
        # The ROLLBACK section is prose (the sub-parser is documented as
        # forms, not a flag table), so ROLLBACK_OPTIONS is not passed.
        {"options": cli_doc.FERM_OPTIONS},
        "FERM",
    ),
    "import-ferm.pod": (
        {
            "options": cli_doc.IMPORT_FERM_OPTIONS,
            "environment": cli_doc.IMPORT_FERM_ENVIRONMENT,
        },
        "IMPORT-FERM",
    ),
}


def _base_release() -> str:
    """
    Return the release string: base version sans hatch-vcs suffix.

    Raw ``git describe --long`` carries ``-N-g<hash>`` and changes with
    every commit -- a committed .1 would be perpetually "stale".  The
    base bumps only when a new tag moves the scm-guessed version; the
    release lives on the .TH line, which the freshness gate normalises
    away, so a stale release is cosmetic until the next regeneration.
    """
    return re.sub(r"(\.dev|\+).*$", "", __version__)


def build(pod_dir: Path, man_dir: Path) -> list[Path]:
    """Render both pages into the given dirs; return the .1 paths."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(_TEMPLATES),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
        # Swallow the newline/indent of {% %} tag lines: without these
        # every loop iteration leaks blank lines into the rendered POD
        # (valid but untidy; the explicit blank lines INSIDE the loop
        # body still separate the =item paragraphs).
        trim_blocks=True,
        lstrip_blocks=True,
    )
    pod_dir.mkdir(parents=True, exist_ok=True)
    man_dir.mkdir(parents=True, exist_ok=True)
    pages: list[Path] = []
    for pod_name, (context, man_name) in _PAGES.items():
        text = env.get_template(pod_name + ".j2").render(**context)
        pod = pod_dir / pod_name
        pod.write_text(text, encoding="utf-8")
        page = man_dir / (pod_name.removesuffix(".pod") + ".1")
        subprocess.run(
            [
                "pod2man",
                "--section=1",
                f"--name={man_name}",
                f"--center={_MAN_CENTER}",
                f"--release=ferm {_base_release()}",
                f"--date={_MAN_DATE}",
                str(pod),
                str(page),
            ],
            check=True,
            encoding="utf-8",
        )
        pages.append(page)
    return pages


def main() -> int:
    """Regenerate the committed pages in place."""
    pages = build(_ROOT / "docs", _ROOT / "docs" / "man")
    for page in pages:
        sys.stdout.write(f"generated {page.relative_to(_ROOT)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
