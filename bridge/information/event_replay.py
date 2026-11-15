"""Safe, read-only views used to rebuild interrupted event projections.

An event replay path is deliberately distinct from ordinary ``read`` and
``read_event``. Only an explicit provider ``replay_event`` hook may produce a
value; missing hooks return unknown fields instead of falling back to a live
read.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any


REPLAY_UNAVAILABLE = "EVENT_PROJECTION_INTERRUPTED_NOT_REPLAYED"


def unknown_event_projection(query: dict, source: Any = None) -> dict:
    """Return an explicit unknown result without calling the source."""
    fields = query.get("fields", []) if isinstance(query, dict) else []
    obj = query.get("object") if isinstance(query, dict) else None
    return {
        "query": deepcopy(query),
        "objects": [deepcopy(obj)] if isinstance(obj, dict) else [],
        "fields": {
            field: {"status": "unknown", "reason": REPLAY_UNAVAILABLE}
            for field in fields
        },
        "complete": False,
        "source": {
            "name": type(source).__name__ if source is not None else "EventReplay",
            "complete": False,
            "replay": "unsupported",
        },
    }


class EventReplayView:
    """Expose just enough of a provider to route a safe replay.

    There is intentionally no ``__getattr__`` and no ``read_event`` method:
    CompositeSource must not inherit the wrapped provider's ordinary read
    surface while rebuilding an interrupted projection.
    """

    def __init__(self, source: Any, event: dict):
        self._source = source
        self._event = deepcopy(event)

    def catalog(self) -> list[dict]:
        return deepcopy(self._source.catalog())

    def context(self) -> dict:
        return deepcopy(self._source.context())

    def read(self, query: dict, context: dict) -> dict:
        # CompositeSource's multi-owner path checks these scopes itself. Its
        # historical single-owner fast path assumes the query was validated
        # earlier, so repeat the owner scope guard here for frozen reports.
        from .composite import CompositeSource

        entries = [entry for entry in self._source.catalog()
                   if entry.get("topic_id") == query.get("topic")]
        selected = [entry for entry in entries
                    if set(query.get("fields", [])) & set(entry.get("fields", {}))]
        if len(selected) == 1:
            reason = CompositeSource._scope_reason(query, selected[0], context)
            if reason:
                return {
                    "query": deepcopy(query),
                    "objects": [deepcopy(query.get("object", {}))],
                    "fields": {field: {"status": "unavailable", "reason": reason}
                               for field in query.get("fields", [])},
                    "complete": False,
                    "source": {"name": type(self._source).__name__, "complete": False},
                }
        replay = getattr(self._source, "replay_event", None)
        if not callable(replay):
            return unknown_event_projection(query, self._source)
        return replay(deepcopy(query), deepcopy(context), deepcopy(self._event))


def replay_composite_event(source: Any, query: dict, context: dict, event: dict) -> dict:
    """Replay CompositeSource routes through short-lived safe owner views."""
    # Import lazily so event_replay can be used by CompositeSource without a
    # module import cycle.
    from .composite import CompositeSource

    replay_source = CompositeSource(
        EventReplayView(source.primary, event),
        [EventReplayView(adapter, event) for adapter in source.adapters],
    )
    return replay_source.read_event(
        deepcopy(query), deepcopy(context), deepcopy(event)
    )
