"""Synthetic native callback copies delivered through the ordinary information tools."""
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from bridge.call_to_arms_observation import public_observation
from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools


ROOT = Path(__file__).resolve().parents[2]
GAME_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


@pytest.fixture(scope="module")
def native_fixture(tmp_path_factory):
    directory = tmp_path_factory.mktemp("call-native")
    executable = directory / "fixture.exe"
    compiler = shutil.which("g++")
    if compiler is None:
        pytest.skip("native fixture requires the existing C++ compiler")
    output = executable.relative_to(ROOT) if executable.is_relative_to(ROOT) else executable
    command = [compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-I", "work/native",
               "work/native/tests/call-to-arms-observer-fixture.cpp", "-o", str(output)]
    built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=45)
    assert built.returncode == 0, built.stderr
    return executable


@pytest.fixture(scope="module")
def native_events(native_fixture):
    executable = native_fixture
    result = subprocess.run([str(executable)], cwd=ROOT, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return [json.loads(line) for line in result.stdout.splitlines()]


@pytest.mark.parametrize(("mode", "expected", "lost"), [("full", 1, 0), ("overflow", 64, 1)])
def test_native_vector_limit_and_queue_overflow_are_preserved(native_fixture, mode, expected, lost):
    result = subprocess.run([str(native_fixture), mode], cwd=ROOT, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    events = [json.loads(line) for line in result.stdout.splitlines()]
    calls = [event for event in events if event["event"] == "native_call_to_arms_observed"]
    assert len(calls) == expected
    assert sum(event.get("dropped", 0) for event in events) == lost
    assert all(public_observation(event, event["session_id"]) is not None for event in calls)
    if mode == "full":
        assert calls[0]["specific_enemies_count"] == 128
        assert len(calls[0]["specific_enemies"]) == 128


class LogSession(ObserverSession):
    observer = "FRA"

    def health(self):
        return {"status": "ready", "date_raw": 56566584, "complete": True, "reasons": []}


def make_session(directory, events, *, version=41, enabled=True, top_level=True):
    session_id = events[0]["session_id"]
    record = {"experiment_id": "call-observation", "session_id": session_id,
              "game_sha256": GAME_SHA, "dll_sha256": "a" * 64}
    installation = directory / "installation.json"
    installation.write_text(json.dumps(record), encoding="utf-8")
    ack = {"event": "diplomacy_observer_installed", "session_id": session_id, "version": version,
           "native_inbound_alliance": True, "native_call_to_arms_ai_response_held": False}
    if top_level:
        ack["native_call_to_arms_observation"] = enabled
    else:
        ack["caps"] = ["native_call_to_arms_observation"]
    (directory / "control-probe.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in [ack] + events), encoding="utf-8")
    return LogSession(installation, directory / "unused-game.exe")


def test_native_fixture_keeps_each_observation_and_reports_copy_gaps(native_events):
    calls = [event for event in native_events if event["event"] == "native_call_to_arms_observed"]
    assert [event["observation_id"] for event in calls] == [1, 2, 3]
    assert all(event["recipient"] == "FRA" for event in calls)
    assert all(event["ai_response_held"] is False for event in calls)
    assert calls[0]["flags_raw"] == [0, 1, 1, 0, 0, 0, 1]
    assert calls[-1]["specific_enemies"] == []
    assert sum(event.get("dropped", 0) for event in native_events) == 2


def test_recorded_call_without_specific_opponent_reaches_query_and_subscription(tmp_path):
    fixture = ROOT / 'bridge/tests/fixtures/information_call_to_arms_SAV_FRA_live_1374.json'
    event = json.loads(fixture.read_text(encoding='utf-8'))['event']
    public = public_observation(event, event['session_id'])
    assert public is not None
    assert public['parameters']['versus'] == {'status': 'known', 'value': None}
    session = make_session(tmp_path, [event], version=61)
    session.health = lambda: {'status': 'ready', 'date_raw': event['date_raw'] + 24,
                              'complete': True, 'reasons': []}
    journal = DurableJournal(tmp_path / 'journal.sqlite3', session.experiment_id, session.session_id)
    source = DiplomacySource(DiplomacyTools(journal, session))
    database = tmp_path / 'information.sqlite3'
    query = {'topic': 'A04', 'object': {'type': 'session'},
             'fields': ['proposal_id', 'action_id', 'actor', 'recipient', 'proposal_status', 'parameters'],
             'parameters': {}}
    try:
        with closing(InformationService(source, database)) as service:
            api = InformationTools(service)
            report = api.call('information_manage_report', {
                'request_id': 'actual-call-report', 'operation': 'create',
                'config': {'name': 'actual call', 'queries': [query], 'detail': 'full'},
            })['report']
            api.call('information_manage_subscription', {
                'request_id': 'actual-call-subscription', 'operation': 'create', 'config': {
                    'name': 'actual call', 'kind': 'event', 'report_id': report['id'], 'enabled': True,
                    'event': {'types': ['diplomatic_proposal'], 'recipients': ['FRA']},
                },
            })
            results = api.call('information_tick', {})['results']
            assert len(results) == 1
            item = results[0]['items'][0]
            assert item['actor'] == 'SAV' and item['recipient'] == 'FRA'
            assert item['action_id'] == 'call_to_arms'
            assert item['parameters']['versus'] is None
            assert 'native_date_fields' not in item['parameters']
            assert 'date_raw' not in results[0]['event']['payload']
            assert item['parameters']['response_control']['ai_response_held'] is False
            full = api.call('information_get_result', {'result_id': results[0]['result_id'], 'view': 'full'})
            assert full['items'][0]['fields']['parameters']['value'] == public['parameters']
            assert api.call('information_tick', {})['results'] == []
            selected = deepcopy(query)
            selected['parameters']['proposal_id'] = public['proposal_id']
            direct = api.call('information_query', {'request_id': 'actual-call-query', 'queries': [selected]})
            assert direct['items'] == results[0]['items']
        with closing(InformationService(source, database)) as service:
            assert service.get_result(full['result_id']) == full
    finally:
        journal.close()


@pytest.mark.parametrize("changes", [
    {"recipient": "POR"}, {"actor": "FRA"}, {"recipient_verified": False},
    {"ai_response_held": True}, {"observation_id": True}, {"date_raw": -1},
    {"flags_raw": [0, 1]}, {"flags_raw": [0, 1, 1, 0, 0, 0, True]},
    {"specific_enemies_count": 2}, {"specific_enemies": ["bad-tag"]},
    {"capture_stage": "after_cleanup"}, {"call_type_raw": 2**31},
    {"versus": "--X"},
])
def test_malformed_or_out_of_scope_observation_is_rejected(native_events, changes):
    event = dict(native_events[0], **changes)
    assert public_observation(event, event["session_id"]) is None


def test_public_projection_preserves_inverse_flags_and_unknown_enum(native_events):
    event = native_events[0]
    public = public_observation(event, event["session_id"])
    params = public["parameters"]
    assert params["defensive_war_with"]["value"] is True
    assert params["replace"]["value"] is True
    assert params["autojoin"]["value"] is False
    assert params["promised_land"]["value"] is True
    assert params["ignore"]["value"] is False
    assert params["call_type"] == {"status": "unknown", "raw": 2, "reason": "CALL_TYPE_ENUM_UNRESOLVED"}
    assert public["identity_scope"] == "captured_observation"
    assert "native_token3c" not in json.dumps(public)
    unknown = public_observation(dict(event, versus_verified=False, specific_enemies_verified=False,
                                      specific_enemies=[]), event["session_id"])
    assert unknown["parameters"]["versus"]["status"] == "unknown"
    assert unknown["parameters"]["specific_enemies"]["native_count"] == 1


@pytest.mark.parametrize("options", [{"version": 40}, {"version": 41.0}, {"enabled": False}, {"top_level": False}])
def test_old_or_missing_top_level_ack_does_not_enable_capture(tmp_path, native_events, options):
    session = make_session(tmp_path, native_events, **options)
    assert session.read_native_inbound_offers() == []
    topic = next(topic for topic in DiplomacySource(DiplomacyTools(None, session)).catalog() if topic["topic_id"] == "A04")
    assert topic["inbound_observation_families"]["call_to_arms"]["capture_available"] is False


def test_single_bounded_reader_deduplicates_and_keeps_gaps(tmp_path, native_events):
    session = make_session(tmp_path, native_events)
    first = session.read_native_inbound_offers()
    assert len(first) == 3
    assert len({item["proposal_id"] for item in first}) == 3
    assert session.read_native_inbound_capture_gaps() == ["CALL_TO_ARMS_CAPTURE_DROPPED:2"]
    assert session.read_native_inbound_offers() == first
    assert session.read_native_inbound_capture_gaps() == ["CALL_TO_ARMS_CAPTURE_DROPPED:2"]
    assert session._native_alliance_inbound_context(first[0]["proposal_id"]) is None
    topic = next(topic for topic in DiplomacySource(DiplomacyTools(None, session)).catalog() if topic["topic_id"] == "A04")
    assert topic["inbound_observation_families"]["call_to_arms"] == {
        "capture_available": True, "capture_stage": "before_native_executor",
        "identity_scope": "captured_observation", "ai_response_held": False, "response_execution_supported": False,
    }


def test_query_and_each_event_use_their_own_snapshot_and_replay(tmp_path, native_events, monkeypatch):
    session = make_session(tmp_path, native_events)
    journal = DurableJournal(tmp_path / "journal.sqlite3", session.experiment_id, session.session_id)
    backend = DiplomacyTools(journal, session)
    source = DiplomacySource(backend)
    query = {"topic": "A04", "object": {"type": "session"},
             "fields": ["proposal_id", "action_id", "actor", "recipient", "proposal_status", "parameters"],
             "parameters": {}}
    context = source.context()
    database = tmp_path / "information.sqlite3"
    try:
        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            report = tools.call("information_manage_report", {
                "request_id": "call-report", "operation": "create",
                "config": {"name": "incoming calls", "queries": [query], "detail": "full"},
            })["report"]
            tools.call("information_manage_subscription", {
                "request_id": "call-subscribe", "operation": "create", "config": {
                    "name": "calls", "kind": "event", "report_id": report["id"], "enabled": True,
                    "event": {"types": ["diplomatic_proposal"], "recipients": ["FRA"]},
                },
            })
            tick = tools.call("information_tick", {"view": "full"})
            results = tick["results"]
            assert len(results) == 3
            assert len({result["items"][0]["fields"]["proposal_id"]["value"] for result in results}) == 3
            enemies = [result["items"][0]["fields"]["parameters"]["value"]["specific_enemies"]["value"]
                       for result in results]
            assert enemies == [["BUR"], ["BUR"], []]
            assert all(result["items"][0]["source"]["projection"] == "event_snapshot" for result in results)
            assert all(result["event"]["complete"] is False for result in results)
            assert tools.call("information_tick", {})["results"] == []
            selected = deepcopy(query)
            selected["parameters"]["proposal_id"] = results[-1]["event"]["payload"]["proposal_id"]
            direct = tools.call("information_query", {
                "request_id": "call-direct", "queries": [selected], "view": "full"})
            assert direct["items"][0]["fields"] == results[-1]["items"][0]["fields"]
            retained_id = results[-1]["result_id"]
        with closing(InformationService(source, database)) as reopened:
            assert reopened.get_result(retained_id)["items"] == results[-1]["items"]
        monkeypatch.setattr(session, "read_native_alliance_inbound_offers", lambda: pytest.fail("replay read native data"))
        replay = source.replay_event(query, context, results[-1]["event"])
        expected = deepcopy(results[-1]["items"][0]["fields"])
        for field in expected.values():
            field.pop("unit", None)
            field.pop("scale", None)
        assert replay["fields"] == expected
        selected["parameters"]["fresh_pending"] = True
        assert source.replay_event(selected, context, results[-1]["event"])["fields"]["proposal_status"]["reason"] == "CURRENT_PENDING_NOT_IN_EVENT_SNAPSHOT"
        wrong = deepcopy(results[-1]["event"])
        wrong["payload"]["recipient"] = "POR"
        assert not source.replay_event(query, context, wrong)["complete"]
    finally:
        journal.close()
