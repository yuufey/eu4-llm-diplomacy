"""C04 event registration, subscription delivery, and snapshot replay tests."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge import country_modifier_observation as observation
from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools


GAME_SHA = observation.GAME_SHA256
SESSION_ID = "modifier-events-316"
GAME_DATE = 56658312
COLLECTED_DATE = 56660000


def native_event(sequence=1, *, session_id=SESSION_ID, **changes):
    event = {
        "event": observation.NATIVE_EVENT,
        "schema_version": 1,
        "session_id": session_id,
        "sequence": sequence,
        "country": "FRA",
        "country_fullref": "0x100415246",
        "modifier_id": "test_modifier",
        "date_raw": GAME_DATE,
        "start_date_raw": 56658312,
        "end_date_raw": 56660000,
        "flags": [1, 0, 1, 0],
        "source": observation.SOURCE,
        "complete": True,
    }
    event.update(changes)
    return event


def native_ack(session_id=SESSION_ID, *, version=45, enabled=True, observer="FRA"):
    event = {
        "event": "diplomacy_observer_installed",
        "session_id": session_id,
        "observer": observer,
        "version": version,
        "native_country_modifier_add_wire": 1,
        "native_country_modifier_scope": observation.SCOPE,
    }
    if enabled:
        event[observation.CAPABILITY] = True
    return event


class LogSession(ObserverSession):
    observer = "FRA"

    def __init__(self, installation, game_exe, *, observer="FRA"):
        super().__init__(installation, game_exe, controlled_country=observer)
        self.observer = observer
        self.game_date = COLLECTED_DATE

    def health(self):
        return {
            "status": "ready",
            "date_raw": self.game_date,
            "complete": True,
            "observer": self.observer,
            "game_version": "1.37.4",
            "game_sha256": GAME_SHA,
            "world_id": "modifier-world-316",
            "reasons": [],
        }

    def information_health(self):
        return self.health()


def make_session(directory, events=(), *, session_id=SESSION_ID, game_sha=GAME_SHA,
                 ack=None, observer="FRA"):
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "experiment_id": "modifier-events-316",
        "session_id": session_id,
        "game_sha256": game_sha,
        "game_version": "1.37.4",
        "dll_sha256": "b" * 64,
        "observer": observer,
        "world_id": "modifier-world-316",
    }
    installation = directory / "installation.json"
    installation.write_text(json.dumps(record), encoding="utf-8")
    rows = [ack or native_ack(session_id, observer=observer), *events]
    (directory / "control-probe.jsonl").write_text(
        "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )
    return LogSession(installation, directory / "unused-game.exe", observer=observer)


def make_source(tmp_path, *, events=(), session_id=SESSION_ID, game_sha=GAME_SHA,
                ack=None, observer="FRA"):
    session_dir = tmp_path / "session"
    session = make_session(session_dir, events, session_id=session_id, game_sha=game_sha,
                           ack=ack, observer=observer)
    journal = DurableJournal(tmp_path / "journal.sqlite3", session.experiment_id, session.session_id)
    source = DiplomacySource(DiplomacyTools(journal, session))
    return session, journal, source


def c04_query():
    return {
        "topic": "C04",
        "object": {"type": "session"},
        "fields": ["event_id", "event_type", "event_date", "event_objects", "event_payload", "complete"],
        "parameters": {"event_type": observation.EVENT_TYPE},
    }


def test_event_type_requires_fra_and_literal_capability_and_has_narrow_catalog_scope(tmp_path):
    session, journal, source = make_source(tmp_path)
    try:
        assert observation.EVENT_TYPE in source.event_types
        c04 = next(topic for topic in source.catalog() if topic["topic_id"] == "C04")
        assert c04["native_country_modifier_addition"] == {
            "capture_available": True,
            "event_type": observation.EVENT_TYPE,
            "scope": observation.SCOPE,
            "mode": "live",
            "complete_scope": "single_added_record",
            "projection": "event_snapshot",
            "removal_or_expiry_available": False,
        }

        fake_caps = native_ack(enabled=False)
        fake_caps["caps"] = [observation.CAPABILITY]
        fake = DiplomacySource(DiplomacyTools(None, make_session(
            tmp_path / "fake", ack=fake_caps,
        )))
        assert observation.EVENT_TYPE not in fake.event_types

        other_country = DiplomacySource(DiplomacyTools(None, make_session(
            tmp_path / "por", observer="POR", ack=native_ack(observer="POR"),
        )))
        assert observation.EVENT_TYPE not in other_country.event_types
    finally:
        journal.close()


@pytest.mark.parametrize("role_filter", ["actors", "recipients"])
def test_country_modifier_subscription_rejects_unproven_diplomatic_roles(tmp_path, role_filter):
    session, journal, source = make_source(tmp_path)
    try:
        with pytest.raises(InformationError) as error:
            source.validate_event_filter({"types": [observation.EVENT_TYPE], role_filter: ["BUR"]})
        assert error.value.code == "unsupported_event_filter"
        source.validate_event_filter({"types": [observation.EVENT_TYPE]})
    finally:
        journal.close()


def test_poll_events_builds_valid_added_snapshot_and_advances_native_watermark(tmp_path):
    session, journal, source = make_source(tmp_path, events=[native_event(1)])
    try:
        batch = source.poll_events(source.context(), None)
        events = [event for event in batch["events"] if event["event_type"] == observation.EVENT_TYPE]
        assert len(events) == 1
        event = events[0]
        assert observation.valid_event_snapshot(event, source.context())
        assert event["game_date"] == GAME_DATE
        assert event["collected_game_date"] == COLLECTED_DATE
        assert event["objects"] == [{"type": "country", "country": "FRA"}]
        assert event["payload"] == {
            "country": "FRA",
            "modifier_id": "test_modifier",
            "change": "added",
            "start_date_raw": GAME_DATE,
            "end_date_raw": COLLECTED_DATE,
            "flags_raw": [1, 0, 1, 0],
            "scope": observation.SCOPE,
        }
        assert event["source"]["name"] == "ObserverSession.read_native_country_modifier_events"
        assert event["source"]["native_sequence"] == 1
        assert batch["cursor"]["country_modifier_sequence"] == 1
        assert batch["complete"] is True
    finally:
        journal.close()


def test_c04_report_subscription_tick_cancel_and_reopen_preserve_complete_result(tmp_path):
    session, journal, source = make_source(tmp_path, events=[native_event(1)])
    database = tmp_path / "information.sqlite3"
    try:
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            report = tools.call("information_manage_report", {
                "request_id": "modifier-report",
                "operation": "create",
                "config": {"name": "country modifier events", "queries": [c04_query()], "detail": "full"},
            })["report"]
            subscription = tools.call("information_manage_subscription", {
                "request_id": "modifier-subscription",
                "operation": "create",
                "config": {
                    "name": "country modifier additions",
                    "kind": "event",
                    "report_id": report["id"],
                    "enabled": True,
                    "event": {"types": [observation.EVENT_TYPE]},
                },
            })["subscription"]

            tick = tools.call("information_tick", {"view": "full"})
            assert tick["state"] == "processed"
            assert len(tick["results"]) == 1
            result = tick["results"][0]
            assert result["complete"] is True
            assert result["status"] == "complete"
            assert result["event_batch"] == {"complete": True, "gaps": []}
            assert result["event"]["event_type"] == observation.EVENT_TYPE
            assert result["event"]["game_date"] == GAME_DATE
            fields = result["items"][0]["fields"]
            assert fields["event_type"] == {"status": "known", "value": observation.EVENT_TYPE}
            assert fields["event_date"] == {"status": "known", "value": GAME_DATE}
            assert fields["complete"] == {"status": "known", "value": True}
            assert fields["event_payload"]["status"] == "known"
            assert fields["event_payload"]["value"]["modifier_id"] == "test_modifier"
            assert result["items"][0]["source"]["projection"] == "event_snapshot"
            saved_id = result["result_id"]

            cancelled = tools.call("information_manage_subscription", {
                "request_id": "modifier-cancel",
                "operation": "cancel",
                "subscription_id": subscription["id"],
                "expected_version": 1,
            })["subscription"]
            assert cancelled["state"] == "cancelled"

        with closing(InformationService(source, database)) as reopened:
            assert reopened.get_result(saved_id)["items"] == result["items"]
            assert reopened.manage_subscription(
                "modifier-get-cancelled", "get", subscription_id=subscription["id"]
            )["subscription"]["state"] == "cancelled"
    finally:
        journal.close()


@pytest.mark.parametrize("fixture_name,event_type,event_date,end_date", [
    ("information_country_modifier_FRA_power_to_provinces_live_1374.json",
     observation.EVENT_TYPE, "1470.12.19", "1480.12.19"),
    ("information_country_modifier_FRA_papal_removed_live_1374.json",
     observation.REMOVE_EVENT_TYPE, "1471.10.11", "1483.12.30"),
])
def test_live_modifier_change_default_c04_full_read_cold_reopen_and_dedup(
        tmp_path, fixture_name, event_type, event_date, end_date):
    fixture_root = Path(__file__).parent / "fixtures"
    fixture = json.loads((fixture_root / fixture_name).read_text(encoding="utf-8"))
    ack_fixture = fixture
    if "installation_ack_fixture" in fixture:
        ack_fixture = json.loads((fixture_root / fixture["installation_ack_fixture"]).read_text(encoding="utf-8"))
    event = fixture["event"]
    ack = ack_fixture["installation_ack"]
    assert fixture["evidence_kind"] == "observed_runtime"
    assert fixture["source_offset"] > 0 and fixture["source_line_bytes"] > 0
    assert len(fixture["source_line_sha256"]) == 64
    assert fixture["game_sha256"] == ack_fixture["game_sha256"]
    assert fixture["dll_sha256"] == ack_fixture["dll_sha256"]
    assert ack["session_id"] == event["session_id"]

    expected = observation.public_observation(event, event["session_id"])
    assert expected is not None
    session, journal, source = make_source(
        tmp_path,
        events=[event],
        session_id=event["session_id"],
        game_sha=fixture["game_sha256"],
        ack=ack,
    )
    session.game_date = event["date_raw"]
    query = c04_query()
    query["parameters"]["event_type"] = event_type
    database = tmp_path / "information.sqlite3"
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call("information_manage_report", {
                "request_id": "live-power-report",
                "operation": "create",
                "config": {
                    "name": "live country modifier addition",
                    "queries": [query],
                    "detail": "full",
                },
            })["report"]
            api.call("information_manage_subscription", {
                "request_id": "live-power-subscription",
                "operation": "create",
                "config": {
                    "name": "live modifier additions",
                    "kind": "event",
                    "report_id": report["id"],
                    "enabled": True,
                    "event": {"types": [event_type]},
                },
            })

            tick = api.call("information_tick", {})
            assert len(tick["results"]) == 1
            notification = tick["results"][0]
            assert notification["event"]["event_type"] == event_type
            default_payload = notification["items"][0]["event_payload"]
            assert default_payload["modifier_id"] == event["modifier_id"]
            assert default_payload["start_date"] is None
            assert default_payload["end_date"] == end_date
            assert notification["items"][0]["event_date"] == event_date
            assert "start_date_raw" not in default_payload and "end_date_raw" not in default_payload
            assert "flags_raw" not in default_payload
            result_id = notification["result_id"]

            full = api.call("information_get_result", {
                "result_id": result_id,
                "view": "full",
            })
            full_payload = full["items"][0]["fields"]["event_payload"]["value"]
            assert full_payload == expected["payload"]
            assert api.call("information_tick", {})["results"] == []

        with closing(InformationService(source, database)) as reopened:
            api = InformationTools(reopened)
            assert api.call("information_get_result", {
                "result_id": result_id,
                "view": "full",
            }) == full
            assert api.call("information_tick", {})["results"] == []
    finally:
        journal.close()


@pytest.mark.parametrize("gaps", [[], [{"stream": "battle", "reason": "FULL_DISPLAY_UNRESOLVED"}]])
def test_complete_event_retains_partial_batch_gaps_in_brief_and_cold_full_result(tmp_path, monkeypatch, gaps):
    gaps = deepcopy(gaps)
    session, journal, source = make_source(tmp_path, events=[native_event(1)])
    database = tmp_path / "information.sqlite3"
    original_poll = source.poll_events
    expected_batch = {"complete": False, "gaps": deepcopy(gaps)}

    def partial_batch(context, cursor):
        batch = original_poll(context, cursor)
        batch.update(complete=False, gaps=deepcopy(gaps))
        return batch

    monkeypatch.setattr(source, "poll_events", partial_batch)
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call("information_manage_report", {
                "request_id": "batch-gap-report", "operation": "create",
                "config": {"name": "modifier with batch coverage", "queries": [c04_query()], "detail": "brief"},
            })["report"]
            api.call("information_manage_subscription", {
                "request_id": "batch-gap-subscription", "operation": "create",
                "config": {"name": "batch coverage", "kind": "event", "report_id": report["id"],
                           "enabled": True, "event": {"types": [observation.EVENT_TYPE]}},
            })
            tick = api.call("information_tick", {"view": "full"})
            assert len(tick["results"]) == 1
            brief = tick["results"][0]
            assert brief["status"] == "partial" and brief["complete"] is False
            assert brief["event"]["complete"] is True
            assert brief["items"][0]["complete"] is True
            assert brief["event_batch"] == expected_batch
            full = api.call("information_get_result", {"result_id": brief["result_id"], "view": "full"})
            assert full["event_batch"] == expected_batch
            assert api.call("information_tick", {})["results"] == []

        # Later source state and caller mutation must not rewrite stored coverage.
        gaps.append({"reason": "later_gap"})
        brief["event_batch"]["gaps"].append({"reason": "caller_mutation"})
        with closing(InformationService(source, database)) as reopened:
            assert reopened.get_result(full["result_id"]) == full
    finally:
        journal.close()


def test_past_date_event_snapshot_replay_never_reads_fresh_native_state(tmp_path, monkeypatch):
    session, journal, source = make_source(tmp_path, events=[native_event(7)])
    try:
        batch = source.poll_events(source.context(), None)
        event = next(event for event in batch["events"] if event["event_type"] == observation.EVENT_TYPE)
        assert event["game_date"] < event["collected_game_date"]
        query = c04_query()
        current = source.context()

        def no_fresh_read(*args, **kwargs):
            pytest.fail("event snapshot replay attempted a fresh native read")

        monkeypatch.setattr(session, "read_native_alliance_inbound_offers", no_fresh_read)
        monkeypatch.setattr(session, "read_native_country_modifier_events", no_fresh_read)
        replay = source.read_event(query, current, event)
        assert replay["complete"] is True
        assert replay["game_date"] == GAME_DATE
        assert replay["fields"]["event_date"] == {"status": "known", "value": GAME_DATE}

        for change in (
            {"session_id": "wrong-session"},
            {"observer": "POR"},
            {"payload": {**event["payload"], "country": "POR"}},
            {"source": {**event["source"], "scope": "all_country_modifiers"}},
        ):
            invalid = deepcopy(event)
            invalid.update(change)
            projected = source.replay_event(query, current, invalid)
            assert projected["complete"] is False
            assert projected["source"]["complete"] is False
    finally:
        journal.close()
