from __future__ import annotations

from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path

import pytest

from bridge.diplomacy import DiplomacyTools
from bridge.diplomacy_journal import DurableJournal
from bridge.information import InformationService
from bridge.information import diplomat_tasks_memory
from bridge.information.composite import CompositeSource
from bridge.information.country_state import NativeCountryStateSource
from bridge.information.diplomat_tasks import NativeDiplomatTasksSource, concise_diplomat_tasks
from bridge.information.model import InformationError
from bridge.information.sources import DiplomacySource
from bridge.information.tools import InformationTools
from bridge.tests import test_curry_favors_tools as curry_contract
from bridge.tests import test_improve_relations_tools as improve_contract
from bridge.tests import test_spy_network_tools as spy_contract


GAME_SHA256 = diplomat_tasks_memory.EXPECTED_EXE_SHA256
SESSION_ID = "session-diplomat-tasks-1"
CREATION_FILETIME = 134375498253940149
GAME_DATE = 56559408


# Necessary fields from the P3 FRA input captured on 1472.4.17.
P3_DIPLOMAT_TASKS = {
    "instance_count_observed": 4,
    "available_count_observed": 2,
    "instances": [
        {
            "state": "returning", "task": "unknown", "actor": "FRA", "recipient": "GEN",
            "status": "known", "state_status": "known", "state_raw_18": 1, "state_raw": 1,
            "action_token_raw": 10555, "actor_fullref_raw": 72058118028218950,
            "recipient_fullref_raw": 72058453036516679,
            "actor_resolution": {"role": "actor", "slot": 122, "tag_candidate": "FRA", "country_count": 1380, "tag": "FRA"},
            "recipient_resolution": {"role": "recipient", "slot": 200, "tag_candidate": "GEN", "country_count": 1380, "tag": "GEN"},
            "lifecycle_date_raw": {"raw_20": 56697264, "raw_24": 56697408, "semantics": "lifecycle_date_raw"},
            "task_family": None, "task_family_status": "unknown",
        },
        {
            "state": "active", "task": "build_spy_network", "actor": "FRA", "recipient": "BUR",
            "status": "known", "state_status": "known", "state_raw_18": 2, "state_raw": 2,
            "action_token_raw": 13176, "actor_fullref_raw": 72058118028218950,
            "recipient_fullref_raw": 72058096554497346,
            "task_family": "build_spy_network", "task_family_status": "known",
        },
        {"state": "idle", "status": "known", "state_raw": 0, "actor": None, "recipient": None, "task_family": None},
        {"state": "idle", "status": "known", "state_raw": 0, "actor": None, "recipient": None, "task_family": None},
    ],
}


def test_concise_diplomat_tasks_projects_actual_p3_fields_and_preserves_full_input():
    value = deepcopy(P3_DIPLOMAT_TASKS)
    original = deepcopy(value)
    projected = concise_diplomat_tasks(value)
    assert projected == {
        "instance_count_observed": 4,
        "available_count_observed": 2,
        "instances": [
            {"state": "returning", "task": "unknown", "actor": "FRA", "recipient": "GEN"},
            {"state": "active", "task": "build_spy_network", "actor": "FRA", "recipient": "BUR"},
            {"state": "idle"}, {"state": "idle"},
        ],
    }
    assert value == original
    projected["instances"][0]["recipient"] = "SAV"
    assert value == original


@pytest.mark.parametrize("value", [None, False, [], "unknown"])
def test_concise_diplomat_tasks_keeps_missing_values_unknown(value):
    assert concise_diplomat_tasks(value) is None


def test_concise_diplomat_tasks_keeps_known_empty_and_unknown_task_states():
    assert concise_diplomat_tasks({"instance_count_observed": 0, "available_count_observed": 0, "instances": []}) == {
        "instance_count_observed": 0, "available_count_observed": 0, "instances": [],
    }
    assert concise_diplomat_tasks({"instance_count_observed": 1, "available_count_observed": 0,
                                   "instances": [{"state": "unknown", "task": "unknown"}]})["instances"] == [
        {"state": "unknown", "task": "unknown"},
    ]


class _Session:
    def __init__(self, directory: Path):
        self.directory = directory
        self.creation_filetime = CREATION_FILETIME
        self.record = {
            "session_id": SESSION_ID,
            "creation_filetime": CREATION_FILETIME,
        }


class _Base:
    def __init__(self, directory: Path):
        self.session = _Session(directory)
        self.calls = 0
        self.after_context = None

    def context(self) -> dict:
        self.calls += 1
        value = {
            "status": "ready",
            "complete": True,
            "mode": "live",
            "session_id": SESSION_ID,
            "game_sha256": GAME_SHA256,
            "game_version": "1.37.4",
            "observer": "FRA",
            "game_date": GAME_DATE,
            "game_date_raw": GAME_DATE,
        }
        if self.after_context is not None and self.calls >= 3:
            value.update(deepcopy(self.after_context))
        return value


def _raw(value: int, width: int = 4) -> str:
    return (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little").hex()


def _row(index: int, state: int, token: int | None = None) -> dict:
    row = {
        "status": "known",
        "entry_address": hex(0x20010000 + index * 8),
        "entry_pointer_raw_hex": _raw(0x20010000 + index * 8, 8),
        "record_address": hex(0x20020000 + index * 0x100) if token is not None else None,
        "record_pointer_raw_hex": _raw(0x20020000 + index * 0x100 if token is not None else 0, 8),
        "state_raw_18": state,
        "state_raw_18_hex": _raw(state, 1),
        "state": diplomat_tasks_memory.KNOWN_STATE_NAMES.get(state),
        "state_status": "known" if state in diplomat_tasks_memory.KNOWN_STATE_NAMES else "unknown",
        "raw_id_44": index,
        "raw_id_44_hex": _raw(index),
    }
    if token is not None:
        row.update(
            raw_action_type_a8=token,
            raw_action_type_a8_hex=_raw(token),
            task_family=(
                diplomat_tasks_memory.KNOWN_SELECTOR_FAMILY
                if token == diplomat_tasks_memory.KNOWN_SELECTOR else None
            ),
            task_family_status="known" if token == diplomat_tasks_memory.KNOWN_SELECTOR else "unknown",
            actor="FRA",
            recipient="BUR",
            actor_fullref_raw_hex="465241007a000001",
            recipient_fullref_raw_hex="4255520075000001",
            lifecycle_date_raw={
                "raw_20": GAME_DATE - 100,
                "raw_20_hex": _raw(GAME_DATE - 100),
                "raw_24": GAME_DATE - 50,
                "raw_24_hex": _raw(GAME_DATE - 50),
                "semantics": "lifecycle_date_raw",
            },
            raw_2c=2,
            raw_2c_hex=_raw(2),
            raw_2c_semantics="unknown",
        )
    else:
        row.update(
            raw_action_type_a8=None,
            raw_action_type_a8_hex=None,
            task_family=None,
            task_family_status="unknown",
            actor=None,
            recipient=None,
            lifecycle_date_raw=None,
            raw_2c=None,
            raw_2c_hex=None,
            raw_2c_semantics="unknown",
        )
    return row


def _record(rows: list[dict]) -> dict:
    return {
        "status": "observed",
        "profile_id": diplomat_tasks_memory.EXPECTED_PROFILE_ID,
        "profile_sha256": diplomat_tasks_memory.EXPECTED_PROFILE_SHA256,
        "module_base": "0x7ff63fe30000",
        "country_pointer": "0x20001000",
        "static_contract_guard": {"status": "observed"},
        "runtime_code_guard": {"status": "observed"},
        "fields": {
            "diplomat_tasks": {
                "status": "known",
                "complete": False,
                "partial": True,
                "value": deepcopy(rows),
                "unit": diplomat_tasks_memory.UNIT,
                "scale": 1,
                "period": "current",
                "basis": diplomat_tasks_memory.BASIS,
                "value_origin": diplomat_tasks_memory.VALUE_ORIGIN,
            }
        },
        "values": {"diplomat_tasks": deepcopy(rows)},
        "raw_hex": {"diplomat_tasks": []},
        "raw_bytes_hex": {"diplomat_tasks": []},
        "basis": diplomat_tasks_memory.BASIS,
        "unit": diplomat_tasks_memory.UNIT,
        "scale": 1,
        "period": "current",
        "value_origin": diplomat_tasks_memory.VALUE_ORIGIN,
        "instance_count_observed": len(rows),
        "complete": False,
    }


def _report(rows: list[dict]) -> dict:
    record = _record(rows)
    snapshot = {
        "status": "observed",
        "country": "FRA",
        "country_pointer": record["country_pointer"],
        "game_date": {"value": GAME_DATE, "raw_hex": _raw(GAME_DATE)},
        "record": deepcopy(record),
    }
    return {
        "schema": "information_diplomat_tasks_runtime.v1",
        "status": "observed",
        "completed": True,
        "country": "FRA",
        "request": {"country": "FRA"},
        "identity": {
            "binding_verified": True,
            "installation_session_id": SESSION_ID,
            "installation_creation_filetime": CREATION_FILETIME,
            "process_creation_filetime": CREATION_FILETIME,
            "process_path_sha256_matches_expected": True,
            "process_creation_matches_installation": True,
        },
        "doublepass": {"performed": True, "consistent": True},
        "cleanup": {"handle_close": {"status": "closed", "success": True, "closed": True}},
        "before": deepcopy(snapshot),
        "after": deepcopy(snapshot),
    }


def _query(fields=None, *, country="FRA", parameters=None):
    return {
        "topic": "N05",
        "object": {"type": "country", "country": country},
        "fields": ["diplomat_tasks"] if fields is None else fields,
        "parameters": {} if parameters is None else parameters,
    }


def _source(tmp_path: Path, report: dict, calls: list):
    base = _Base(tmp_path)

    def capture(installation, country="FRA"):
        calls.append((installation, country))
        return deepcopy(report)

    return NativeDiplomatTasksSource(base, capture=capture), base


def test_catalog_and_query_scope_are_narrow(tmp_path: Path):
    source = NativeDiplomatTasksSource(_Base(tmp_path), capture=lambda *_args, **_kwargs: None)
    item = source.catalog()[0]
    assert item["topic_id"] == "N05"
    assert item["title"] == "本国外交官与关系容量"
    assert list(item["fields"]) == ["diplomat_tasks"]
    field = item["fields"]["diplomat_tasks"]
    assert field["coverage"] == "partial"
    assert field["complete"] is False
    assert field["unit"] == "diplomat_task_records"
    assert field["scale"] == 1
    assert field["period"] == "current"
    assert field["basis"] == "native_country_diplomat_task_records"
    assert item["object_types"] == ["country"]
    assert item["triggers"] == ["query", "periodic"]
    assert source.validate_query(_query(), _Base(tmp_path).context())["parameters"] == {}
    with pytest.raises(InformationError) as other_country:
        source.validate_query(_query(country="ENG"))
    assert other_country.value.code == "observer_scope_mismatch"
    with pytest.raises(InformationError) as extra_field:
        source.validate_query(_query(fields=["diplomat_tasks", "diplomats_total"]))
    assert extra_field.value.code == "unknown_field"
    with pytest.raises(InformationError) as extra_parameters:
        source.validate_query(_query(parameters={"reference_recipient": "FRA"}))
    assert extra_parameters.value.code == "invalid_parameters"


def test_projection_preserves_counts_raw_rows_states_and_unknown_tokens(tmp_path: Path, monkeypatch):
    rows = [_row(0, 2, 13176), _row(1, 1, 10559), _row(2, 0), _row(3, 9, 4242)]
    report = _report(rows)
    monkeypatch.setattr(diplomat_tasks_memory, "validate_capture", lambda *args: True)
    calls: list[tuple[Path, str]] = []
    source, base = _source(tmp_path, report, calls)
    result = source.read(_query(), base.context())
    field = result["fields"]["diplomat_tasks"]
    assert result["complete"] is False
    assert field["status"] == "known"
    assert field["unit"] == "diplomat_task_records"
    assert field["scale"] == 1
    assert field["complete"] is False
    value = field["value"]
    assert value["instance_count_observed"] == 4
    assert value["available_count_observed"] == 1
    assert [row["state"] for row in value["instances"]] == ["active", "returning", "idle", "unknown"]
    assert value["instances"][0]["task"] == "build_spy_network"
    assert value["instances"][1]["task"] == "unknown"
    assert value["instances"][3]["action_token_raw"] == 4242
    assert value["instances"][0]["lifecycle_date_raw"]["raw_20"] == GAME_DATE - 100
    assert calls == [(tmp_path / "installation.json", "FRA")]


def test_invalid_validator_or_cleanup_retracts_without_empty_known_value(tmp_path: Path, monkeypatch):
    rows = [_row(0, 2, 13176)]
    calls: list[tuple[Path, str]] = []
    monkeypatch.setattr(diplomat_tasks_memory, "validate_capture", lambda *args: False)
    source, base = _source(tmp_path, _report(rows), calls)
    rejected = source.read(_query(), base.context())
    assert rejected["fields"]["diplomat_tasks"]["status"] == "unknown"
    assert "value" not in rejected["fields"]["diplomat_tasks"]

    bad = _report(rows)
    bad["cleanup"]["handle_close"]["closed"] = False
    monkeypatch.setattr(diplomat_tasks_memory, "validate_capture", lambda *args: True)
    source, base = _source(tmp_path / "bad", bad, calls)
    rejected = source.read(_query(), base.context())
    assert rejected["fields"]["diplomat_tasks"]["status"] == "unknown"
    assert rejected["fields"]["diplomat_tasks"]["reason"] == "DIPLOMAT_TASKS_CLEANUP_INVALID"


def test_context_change_retracts_and_capture_is_still_single_attempt(tmp_path: Path, monkeypatch):
    rows = [_row(0, 2, 13176)]
    monkeypatch.setattr(diplomat_tasks_memory, "validate_capture", lambda *args: True)
    calls: list[tuple[Path, str]] = []
    source, base = _source(tmp_path, _report(rows), calls)
    base.after_context = {"game_date": GAME_DATE + 1, "game_date_raw": GAME_DATE + 1}
    result = source.read(_query(), base.context())
    assert result["fields"]["diplomat_tasks"]["status"] == "unknown"
    assert "CONTEXT_CHANGED_DURING_CAPTURE" in result["fields"]["diplomat_tasks"]["reason"]
    assert len(calls) == 1


def test_capture_failure_and_empty_vector_remain_unknown_or_known_empty(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(diplomat_tasks_memory, "validate_capture", lambda *args: True)
    calls: list[tuple[Path, str]] = []
    empty_source, base = _source(tmp_path, _report([]), calls)
    empty = empty_source.read(_query(), base.context())
    assert empty["fields"]["diplomat_tasks"]["status"] == "known"
    assert empty["fields"]["diplomat_tasks"]["value"] == {
        "instance_count_observed": 0,
        "available_count_observed": 0,
        "instances": [],
    }

    failing_base = _Base(tmp_path / "failed")
    def fail_capture(*_args, **_kwargs):
        raise RuntimeError("no process")
    source = NativeDiplomatTasksSource(failing_base, capture=fail_capture)
    result = source.read(_query(), failing_base.context())
    assert result["fields"]["diplomat_tasks"]["status"] == "unknown"
    assert "CAPTURE_FAILED" in result["fields"]["diplomat_tasks"]["reason"]


def test_poll_events_is_empty_and_does_not_invent_task_changes(tmp_path: Path):
    source = NativeDiplomatTasksSource(_Base(tmp_path), capture=lambda *_args, **_kwargs: None)
    assert source.poll_events({}, {"cursor": 1}) == {
        "events": [], "cursor": {"cursor": 1}, "complete": True, "gaps": [],
    }


def _composite(tmp_path: Path) -> CompositeSource:
    base = _Base(tmp_path)
    state = NativeCountryStateSource(base)
    tasks = NativeDiplomatTasksSource(base, capture=lambda *_args, **_kwargs: None)
    return CompositeSource(DiplomacySource(), [state, tasks])


def _composite_query(fields: list[str], parameters: dict | None = None) -> dict:
    return {
        "topic": "N05",
        "object": {"type": "country", "country": "FRA"},
        "fields": fields,
        "parameters": {} if parameters is None else parameters,
    }


def test_composite_n05_parameter_schema_separates_tasks_from_available(tmp_path: Path):
    composite = _composite(tmp_path)

    tasks_only = composite.validate_query(_composite_query(["diplomat_tasks"]))
    assert tasks_only["parameters"] == {}
    assert tasks_only["fields"] == ["diplomat_tasks"]

    with pytest.raises(InformationError) as missing_reference:
        composite.validate_query(_composite_query(["diplomats_available"]))
    assert missing_reference.value.code == "invalid_parameters"

    mixed = composite.validate_query(
        _composite_query(
            ["diplomat_tasks", "diplomats_available"],
            {"reference_recipient": "SAV"},
        )
    )
    assert mixed["parameters"] == {"reference_recipient": "SAV"}
    assert mixed["fields"] == ["diplomat_tasks", "diplomats_available"]


def test_public_concise_query_preserves_returning_and_idle_diplomats(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(diplomat_tasks_memory, "validate_capture", lambda *args: True)
    calls = []
    tasks, base = _source(tmp_path, _report([_row(0, 1, 13176), _row(1, 0)]), calls)
    primary = DiplomacySource()
    monkeypatch.setattr(primary, "context", base.context)
    source = CompositeSource(primary, [tasks])

    with closing(InformationService(source, tmp_path / "information.sqlite3")) as service:
        tools = InformationTools(service)
        result = tools.call("information_query", {
            "request_id": "returning-diplomat", "queries": [_query()],
        })
        value = result["items"][0]["diplomat_tasks"]
        assert value["available_count_observed"] == 1
        assert [row["state"] for row in value["instances"]] == ["returning", "idle"]
        assert value["instances"][0]["task"] == "build_spy_network"
        assert value["instances"] == [
            {"state": "returning", "task": "build_spy_network", "actor": "FRA", "recipient": "BUR"},
            {"state": "idle"},
        ]
        full = tools.call("information_get_result", {
            "result_id": result["result_id"], "view": "full",
        })
        assert full["items"][0]["fields"]["diplomat_tasks"]["complete"] is False
        assert full["items"][0]["fields"]["diplomat_tasks"]["value"]["instances"][0]["state_raw"] == 1
        assert len(calls) == 1


@pytest.mark.parametrize("action_id", [
    "stop_improving_relations", "stop_building_spy_network", "stop_curry_favors",
])
def test_stop_task_results_reach_public_queries_notifications_and_reopen(
        tmp_path: Path, monkeypatch, action_id: str):
    session_type, contract = {
        "stop_improving_relations": (
            improve_contract.ImproveExecutionSession, improve_contract.ImproveRelationsToolsTests),
        "stop_building_spy_network": (
            spy_contract.SpyNetworkExecutionSession, spy_contract.SpyNetworkToolsTests),
        "stop_curry_favors": (
            curry_contract.CurryExecutionSession, curry_contract.CurryFavorsToolsTests),
    }[action_id]
    event = contract._execution_event(action_id)
    if action_id == "stop_improving_relations":
        # The task transition is retained from the real R28 stop observation.
        fixture = Path(__file__).parent / "fixtures/improve_relations_r28_native_observations.json"
        event = json.loads(fixture.read_text(encoding="utf-8"))["cases"]["stop"]["native_result"]
    session = session_type(event)
    session.observer = "FRA"
    session.record.update(game_sha256=GAME_SHA256, dll_sha256="d" * 64)
    request_id = "recall-" + action_id
    database = tmp_path / "information.sqlite3"
    query = {
        "topic": "A05", "object": {"type": "country_pair", "actor": "FRA", "recipient": "SAV"},
        "fields": ["request_id", "action_id", "status", "game_outcome", "result"],
        "parameters": {"request_id": request_id},
    }
    event_query = dict(deepcopy(query), parameters={})
    changes = {
        "topic": "C04", "object": {"type": "session", "session_id": session.session_id},
        "fields": ["event_id", "event_type", "event_date", "event_payload"], "parameters": {},
    }

    with closing(DurableJournal(tmp_path / "journal.sqlite3", "recall-information", session.session_id)) as journal:
        journal.register(request_id, {
            "action_id": action_id, "actor": "FRA", "recipient": "SAV", "phase": "initiate", "parameters": {},
        })
        for status in ("queued", "consumed", "constructed"):
            journal.transition(request_id, status)
        claim = journal.claim_submission(request_id)
        journal.mark_submitted(request_id, claim.claim_token, contract._submission_receipt(request_id, action_id))
        backend = DiplomacyTools(journal, session)
        source = DiplomacySource(backend)

        with closing(InformationService(source, database)) as service:
            tools = InformationTools(service)
            report = tools.call("information_manage_report", {
                "request_id": "recall-report", "operation": "create", "config": {
                    "name": "外交任务停止", "queries": [event_query, changes], "detail": "brief",
                },
            })["report"]
            tools.call("information_manage_subscription", {
                "request_id": "recall-subscription", "operation": "create", "config": {
                    "name": "外交任务停止通知", "kind": "event", "report_id": report["id"], "enabled": True,
                    "event": {"types": ["diplomatic_request_result"], "actors": ["FRA"], "recipients": ["SAV"]},
                },
            })
            queried = tools.call("information_query", {"request_id": "recall-query", "queries": [query]})
            fields = queried["items"][0]
            assert fields["action_id"] == action_id
            assert fields["status"] == fields["game_outcome"] == "executed"
            assert fields["result"]["task_before"] is True
            assert fields["result"]["task_after"] is False

            first = tools.call("information_tick", {})["results"]
            assert len(first) == 1
            delivered = first[0]
            assert delivered["items"][0] == fields
            changed = delivered["items"][1]
            assert changed["event_type"] == "diplomatic_request_result"
            assert changed["event_payload"]["request"]["result"]["task_after"] is False
            assert changed["event_date"] is None
            assert tools.call("information_tick", {})["results"] == []
            full = service.get_result(delivered["result_id"])
            assert full["items"][0]["source"]["projection"] == "event_snapshot"

        monkeypatch.setattr(backend, "get_diplomatic_result", lambda *_: pytest.fail("terminal replay refreshed the request"))
        with closing(InformationService(source, database)) as reopened:
            tools = InformationTools(reopened)
            assert tools.call("information_get_result", {"result_id": delivered["result_id"]}) == delivered
            assert tools.call("information_tick", {})["results"] == []
            replayed = source.replay_event(event_query, source.context(), full["event"])
            assert replayed["fields"] == full["items"][0]["fields"]
        assert session.submit_calls == []
