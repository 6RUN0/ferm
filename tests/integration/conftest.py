"""
Host integration fixtures: a real git-backed stand-in for etckeeper ``/etc``.

The :mod:`pyferm.etckeeper` rollback and history functions are *git-only* by
design (the production docstring says so: etckeeper has no portable
"restore path X to revision Y" verb, so those paths go through the
``etckeeper vcs`` git passthrough).  Real ``etckeeper vcs <args>`` is exactly
``cd <repo> && git <args>``, so exercising the production functions against a
real git repository tests the genuine behavior -- including the subtle
three-step clean-revert -- without the unsandboxable global
``/etc/etckeeper/commit.d`` metadata hooks that the real binary runs (those
need a real ``/etc`` and root, and are covered by the containerized e2e).

The seam is a PATH shim named ``etckeeper`` that the production code finds via
:func:`shutil.which` and spawns via a fixed ``subprocess`` argv:

* ``etckeeper vcs <args>``  -> ``git -C <repo> <args>``   (byte-faithful)
* ``etckeeper commit <msg>`` -> ``git -C <repo> add -A`` then
  ``git -C <repo> commit -m <msg>`` (etckeeper's "commit all of /etc"
  semantics minus the metadata hooks).  git reports nonzero on an empty
  commit, which :func:`pyferm.etckeeper.commit` swallows; production never
  reaches that path because :func:`cli._commit_history` gates on
  :func:`working_tree_dirty` first.

Git identity and config are pinned to a throwaway ``HOME`` and
``GIT_CONFIG_GLOBAL`` so the suite never reads or writes the developer's real
git configuration, and runs deterministically under xdist.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

#: A Python shim standing in for ``etckeeper``.  Reads the target repo from
#: an environment variable so the production code's fixed argv (which carries
#: no ``-d``) is transparently redirected to the sandbox.
_SHIM_SOURCE = '''\
#!/usr/bin/env python3
"""Test shim: forward etckeeper verbs to git in $FERM_TEST_ETC_REPO."""
import os
import subprocess
import sys

repo = os.environ["FERM_TEST_ETC_REPO"]
argv = sys.argv[1:]
if not argv:
    sys.exit(2)
verb, rest = argv[0], argv[1:]
if verb == "vcs":
    # Real `etckeeper vcs ARGS` is `cd <repo> && git ARGS`.
    done = subprocess.run(["git", "-C", repo, *rest], check=False)
    sys.exit(done.returncode)
if verb == "commit":
    message = rest[0] if rest else "etckeeper"
    subprocess.run(["git", "-C", repo, "add", "-A"], check=False)
    done = subprocess.run(
        ["git", "-C", repo, "commit", "-q", "-m", message], check=False
    )
    sys.exit(done.returncode)
sys.exit(0)
'''


@dataclass
class EtckeeperSandbox:
    """A real git repo posing as an etckeeper-managed ``/etc`` tree."""

    etc: Path
    config_path: str

    def write(self, relpath: str, content: str) -> None:
        """Write ``content`` to ``relpath`` under the fake ``/etc``."""
        target = self.etc / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def read(self, relpath: str) -> str:
        """Read the text of ``relpath`` under the fake ``/etc``."""
        return (self.etc / relpath).read_text(encoding="utf-8")

    def exists(self, relpath: str) -> bool:
        """Whether ``relpath`` exists under the fake ``/etc``."""
        return (self.etc / relpath).exists()

    def head(self) -> str:
        """Return the current commit sha of the repository."""
        completed = subprocess.run(
            ["git", "-C", str(self.etc), "rev-parse", "HEAD"],
            capture_output=True,
            encoding="utf-8",
            check=True,
        )
        return completed.stdout.strip()


@pytest.fixture
def etckeeper_sandbox(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> EtckeeperSandbox:
    """
    Return a fresh git-backed sandbox with the ``etckeeper`` shim on ``PATH``.

    Skips when ``git`` is absent.  A throwaway ``HOME``/``GIT_CONFIG_GLOBAL``
    isolates the test from the developer's git config; the per-test temp repo
    keeps the fixture safe under parallel execution.  No teardown: ``tmp_path``
    and ``monkeypatch`` undo themselves.
    """
    if shutil.which("git") is None:
        pytest.skip("git is not installed")

    home = tmp_path / "home"
    home.mkdir()
    gitconfig = home / ".gitconfig"
    gitconfig.write_text(
        "[user]\n\temail = ferm-test@example.invalid\n\tname = ferm test\n"
        "[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n",
        encoding="utf-8",
    )

    etc = tmp_path / "etc"
    (etc / "ferm").mkdir(parents=True)
    config_path = str(etc / "ferm" / "ferm.conf")

    bindir = tmp_path / "bin"
    bindir.mkdir()
    shim = bindir / "etckeeper"
    shim.write_text(_SHIM_SOURCE, encoding="utf-8")
    shim.chmod(0o755)

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("FERM_TEST_ETC_REPO", str(etc))
    monkeypatch.setenv(
        "PATH", f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"
    )

    subprocess.run(
        ["git", "-C", str(etc), "init", "-q"],
        capture_output=True,
        encoding="utf-8",
        check=True,
    )

    return EtckeeperSandbox(etc=etc, config_path=config_path)
