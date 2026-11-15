from __future__ import annotations

from copy import deepcopy

from bridge.information.composite import CompositeSource
from bridge.information.event_replay import REPLAY_UNAVAILABLE
from bridge.information.sources import RecordedSource
from bridge.tests.test_information_battles import (
    battle_query,
    event_id,
    make_source,
    _history_query,
)


def test_recorded_replay_event_uses_only_archive_projection():
    source = RecordedSource({
        "status": "ready",
        "session_id": "recorded-session",
        "game_version": "1.37.4",
        "observer": "FRA",
        "game_date": 56554848,
        "events": [{"event_id": "archive-event", "event_type": "fixture"}],
    })
    event = {"event_id": "archive-event", "event_type": "fixture", "payload": {"x": "untrusted"}}
    query = {
        "topic": "C01", "object": {"type": "session"},
        "fields": ["session_id", "game_date"], "parameters": {},
    }
    read_calls = []
    original_read = source.read

    def tracked_read(read_query, context=None):
        read_calls.append(deepcopy(read_query))
        return original_read(read_query, context)

    source.read = tracked_read
    source.poll_events = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("replay must not poll")
    )

    result = source.replay_event(query, source.context(), event)

    assert len(read_calls) == 1
    assert result["fields"]["session_id"] == {"status": "known", "value": "recorded-session"}
    assert result["fields"]["game_date"] == {"status": "known", "value": 56554848}


def test_battle_replay_is_direct_ro_and_preserves_binding_and_selector_guards(tmp_path):
    source, primary, fixture, _database, _payload = make_source(tmp_path)
    context = source.context()
    event = source.battles.poll_events(context, None)["events"][0]
    selected = event_id(fixture)
    refresh_calls = []

    class IngestProbe:
        def refresh(self):
            refresh_calls.append(True)
            raise AssertionError("event replay must not refresh ingestion")

    source.ingestor = IngestProbe()
    primary.read = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("battle replay must not use primary.read")
    )
    query = battle_query(["event_id", "name"], selected_event=selected)

    result = source.replay_event(query, context, event)
    assert result["fields"]["event_id"] == {"status": "known", "value": selected}
    assert result["fields"]["name"] == {"status": "known", "value": "蒂鲁吉拉帕利"}
    assert refresh_calls == []

    wrong_session = source.replay_event(
        query, dict(context, session_id="another-session"), event,
    )
    assert wrong_session["fields"]["name"]["status"] == "unavailable"
    assert wrong_session["fields"]["name"]["reason"] == "BATTLE_RECORD_NOT_AVAILABLE_IN_OBSERVER_SCOPE"

    wrong_selector = source.replay_event(
        battle_query(["name"], selected_event="battle-observation:wrong"), context, event,
    )
    assert wrong_selector["fields"]["name"]["reason"] == "BATTLE_EVENT_SELECTOR_MISMATCH"
    assert refresh_calls == []


def test_battle_history_replay_reads_durable_page_without_refresh(tmp_path):
    source, primary, _fixture, _database, _payload = make_source(tmp_path)
    context = source.context()
    event = source.battles.poll_events(context, None)["events"][0]
    refresh_calls = []

    class IngestProbe:
        def refresh(self):
            refresh_calls.append(True)

    source.ingestor = IngestProbe()
    primary.read = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        AssertionError("history replay must not use primary.read")
    )
    query = _history_query(
        "H01", ["battle_sequence"], {"type": "country", "country": "VIJ"}, limit=4,
    )

    result = source.replay_event(query, context, event)

    assert result["fields"]["battle_sequence"]["status"] == "known"
    assert result["fields"]["battle_sequence"]["value"]
    assert refresh_calls == []


class _Primary:
    def __init__(self):
        self.read_calls = 0

    def catalog(self):
        return [{
            "topic_id": "X01", "status": "available",
            "fields": {"safe": {"type": "string"}, "unsafe": {"type": "string"}},
            "object_types": ["session"], "parameters": {"type": "object", "properties": {}},
            "supported_versions": ["1.0"], "triggers": ["event"],
        }]

    def context(self):
        return {"status": "ready", "session_id": "session-a", "game_version": "1.0"}

    def read(self, _query, _context):
        self.read_calls += 1
        raise AssertionError("ordinary primary read is forbidden during replay")


def _adapter(field):
    return [{
        "topic_id": "X01", "status": "available",
        "fields": {field: {"type": "string"}},
        "object_types": ["session"], "parameters": {"type": "object", "properties": {}},
        "supported_versions": ["1.0"], "triggers": ["event"], "observer_roles": [],
    }]


class _SafeAdapter:
    def __init__(self):
        self.read_calls = 0
        self.replay_calls = 0

    def catalog(self):
        return _adapter("safe")

    def read(self, _query, _context):
        self.read_calls += 1
        raise AssertionError("ordinary adapter read is forbidden during replay")

    def replay_event(self, query, _context, event):
        self.replay_calls += 1
        return {
            "fields": {field: {"status": "known", "value": event["event_id"]}
                       for field in query["fields"]},
            "complete": True, "source": {"name": "SafeAdapter"},
        }


class _UnsafeAdapter:
    def __init__(self):
        self.read_calls = 0

    def catalog(self):
        return _adapter("unsafe")

    def read(self, _query, _context):
        self.read_calls += 1
        raise AssertionError("unsafe owner fallback must not run")


def test_composite_replay_mixes_safe_and_unknown_without_native_fallback():
    primary = _Primary()
    safe = _SafeAdapter()
    unsafe = _UnsafeAdapter()
    source = CompositeSource(primary, [safe, unsafe])
    event = {"event_id": "event-1", "event_type": "fixture"}
    query = {
        "topic": "X01", "object": {"type": "session", "session_id": "session-a"},
        "fields": ["safe", "unsafe"], "parameters": {},
    }

    result = source.replay_event(query, primary.context(), event)

    assert result["fields"]["safe"] == {"status": "known", "value": "event-1"}
    assert result["fields"]["unsafe"] == {"status": "unknown", "reason": REPLAY_UNAVAILABLE}
    assert primary.read_calls == 0
    assert safe.read_calls == 0
    assert safe.replay_calls == 1
    assert unsafe.read_calls == 0
    assert result["field_context_scopes"] == {"safe": "game", "unsafe": "game"}


def test_composite_replay_keeps_owner_scope_guard():
    primary = _Primary()
    safe = _SafeAdapter()
    unsafe = _UnsafeAdapter()
    source = CompositeSource(primary, [safe, unsafe])
    query = {
        "topic": "X01", "object": {"type": "session", "session_id": "other-session"},
        "fields": ["safe", "unsafe"], "parameters": {},
    }
    result = source.replay_event(query, primary.context(), {"event_id": "event-1"})
    assert result["fields"]["safe"]["status"] == "unavailable"
    assert result["fields"]["safe"]["reason"] == "session_scope_mismatch"
    assert result["fields"]["unsafe"]["reason"] == "session_scope_mismatch"
    assert safe.replay_calls == 0
    assert unsafe.read_calls == 0
