"""Mission sampling allows forward time while retaining data and identity guards."""
from copy import deepcopy

import pytest

from bridge.information import mission_memory
from bridge.information import mission_trigger_profile
from bridge.information.observation_time import sampled_read
from bridge.tests.test_information_mission_memory import base_reader
from bridge.tests.test_information_mission_condition_change import (
    selected, set_progress, setup, subscribe, tick,
)


def test_current_mission_trigger_profile_validates_its_runtime_dependencies():
    profile = mission_trigger_profile.load_profile()
    assert profile['profile_revision'] == 11
    assert profile['executable_sha256'] == mission_trigger_profile.EXE_SHA256


def snapshots():
    reader, module, _country = base_reader()
    before = mission_memory._snapshot(reader, module, "FRA", True)
    assert before["status"] == "observed"
    after = deepcopy(before)
    after["game_date"].update(raw=before["game_date"]["raw"] + 24,
        raw_hex=(before["game_date"]["raw"] + 24).to_bytes(4, "little").hex())
    return before, after


def test_mission_doublepass_allows_only_clock_progress_in_a_macro_sampling_window():
    before, after = snapshots()
    retained = deepcopy(before)
    assert mission_memory._snapshot_mismatches(before, after)
    with sampled_read({"topic": "M02"}, {"mode": "live", "game_date": before["game_date"]["raw"]}) as window:
        assert mission_memory._snapshot_mismatches(before, after) == []
        assert window.metadata()["end_game_date"] == after["game_date"]["raw"]
    assert before == retained
    assert mission_memory._snapshot_mismatches(before, after)


@pytest.mark.parametrize("damage", ["rollback", "date_address", "country", "mission_data"])
def test_running_mission_capture_keeps_nonclock_guards(damage):
    before, after = snapshots()
    if damage == "rollback":
        after["game_date"]["raw"] = before["game_date"]["raw"] - 24
    elif damage == "date_address":
        after["game_date"]["address"]["va"] = "0x300000"
    elif damage == "country":
        after["country_scan"]["country_pointer"]["va"] = "0x900000"
    else:
        after["missions"]["slots"] = [{"changed": True}]
    with sampled_read({"topic": "M02"}, {"mode": "live", "game_date": before["game_date"]["raw"]}):
        assert mission_memory._snapshot_mismatches(before, after)


def test_running_mission_queries_and_changes_use_the_normal_public_path(tmp_path):
    service, state, _definitions, adapter = setup(tmp_path)

    def capture_running(country):
        state.current["game_date"] += 24
        state.current["game_day"] += 1
        state.sample["game_date"] = state.current["game_date"]
        return state.capture(country)

    adapter.reader = capture_running
    try:
        sub = subscribe(service)
        assert tick(service, state, 2) == []
        runtime = service.status(sub["id"])["subscriptions"][0]["runtime"]
        assert runtime["last_attempt"]["status"] == "baseline_created"
        assert tick(service, state, 4) == []
        runtime = service.status(sub["id"])["subscriptions"][0]["runtime"]
        assert runtime["last_attempt"]["status"] == "unchanged"
        result = service.query("running-query", queries=[selected()])
        item = result["items"][0]
        assert all(field["status"] == "known" for field in item["fields"].values())
        assert item["observation_window"]["end_game_date"] > item["observation_window"]["start_game_date"]
        set_progress(state, True)
        events = tick(service, state, 6)
        assert len(events) == 1 and events[0]["trigger"] == "change"
        assert service.get_result(events[0]["result_id"]) == events[0]
        assert tick(service, state, 8) == []
    finally:
        service.close()
