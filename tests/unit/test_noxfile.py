"""
Pin the nox meta-session queues to real session names.

``session.notify`` resolves a name only when the runner reaches it in
the queue, so a typo in ``_PREFLIGHT_QUEUE`` / ``_EVERYTHING_QUEUE``
would surface mid-run -- potentially an hour into ``everything``.
Importing the noxfile registers its sessions; check every queued name
up front.  Skipped under a mutmut sweep, whose sandbox copies only
``src`` and ``tests`` (no noxfile to import).
"""

from __future__ import annotations

import pytest

noxfile = pytest.importorskip("noxfile")


def test_meta_session_queues_name_real_sessions() -> None:
    from nox import registry

    sessions = registry.get()
    for queue in (noxfile._PREFLIGHT_QUEUE, noxfile._EVERYTHING_QUEUE):
        # A parametrized entry like ``matrix(python='3.11')`` registers
        # under its bare function name.
        bases = [name.split("(", 1)[0] for name in queue]
        unknown = [base for base in bases if base not in sessions]
        assert not unknown, f"queued names with no session: {unknown}"
        assert len(set(queue)) == len(queue), "duplicate queue entries"


def test_everything_queue_extends_preflight() -> None:
    """The heavy queue must never silently drop a push gate."""
    preflight = set(noxfile._PREFLIGHT_QUEUE)
    everything = set(noxfile._EVERYTHING_QUEUE)
    assert preflight <= everything, preflight - everything
