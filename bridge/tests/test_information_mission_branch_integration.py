"""Retained branch input observation, context guards and partial source behavior."""
import json
from pathlib import Path

import pytest

from bridge.information.missions import NativeMissionReader

FIXTURE = Path(__file__).parent / "fixtures/information_mission_branches_live_1374.json"


def sample():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_retained_observation_has_explicit_unknown_dlc_and_no_visibility_inference():
    fixture = sample()
    assert fixture["provenance"]["mode"] == "recorded"
    result = NativeMissionReader.normalize_branch_inputs(fixture["native_capture"], fixture["original_context"])
    assert result["map_setup"]["value"] == {"raw": 0, "name": "normal"}
    assert len(result["country_flags"]) == 4
    assert all(item == {"status": "known", "value": False} for item in result["country_flags"].values())
    assert result["dlc_loaded"]["status"] == "unknown"
    assert result["provenance"]["atomic_with_mission_slots"] is False


def test_domination_short_circuit_only_proves_true_and_not_a_full_dlc_inventory():
    fixture = sample()
    raw, context = fixture["native_capture"], fixture["original_context"]
    raw["inputs"]["has_domination"] = {"known": True, "value": True}
    result = NativeMissionReader.normalize_branch_inputs(raw, context)
    assert result["dlc_loaded"]["value"] == {"Domination": True}
    assert result["dlc_loaded"]["complete_inventory"] is False
    raw["inputs"]["has_domination"] = {"known": False, "value": None, "reason": "THREAD_LOCAL_DLC_OVERRIDE_UNRESOLVED"}
    result = NativeMissionReader.normalize_branch_inputs(raw, context)
    assert result["dlc_loaded"]["status"] == "unknown"
    raw["inputs"]["has_domination"] = {"known": True, "value": False}
    with pytest.raises(Exception) as error:
        NativeMissionReader.normalize_branch_inputs(raw, context)
    assert error.value.code == "branch_input_snapshot_incomplete"


def test_retained_domination_observation_confirms_the_actual_short_circuit_bytes():
    retained = sample()["domination_observation"]
    assert retained["provenance"]["mode"] == "recorded"
    raw = retained["native_capture"]
    observed = raw["inputs"]["has_domination"]
    assert (observed["raw_domination_byte"], observed["raw_override_byte"]) == (1, 0)
    assert observed["source"]["tls_read"] is False
    result = NativeMissionReader.normalize_branch_inputs(raw, retained["original_context"])
    assert result["dlc_loaded"]["value"] == {"Domination": True}
    assert result["dlc_loaded"]["derivation"] == "native_condition_short_circuit_without_TLS"


@pytest.mark.parametrize("change", ["session", "date", "hash", "guard", "cleanup", "mode", "flag"])
def test_context_or_value_mismatch_rejects_the_whole_input_claim(change):
    fixture = sample()
    raw, context = fixture["native_capture"], fixture["original_context"]
    if change == "session":
        context["session_id"] = "another"
    elif change == "date":
        context["game_date"] += 24
    elif change == "hash":
        context["game_sha256"] = "another"
    elif change == "guard":
        raw["runtime_code_guard"]["status"] = "unknown"
    elif change == "cleanup":
        raw["cleanup"]["handle_close"]["closed"] = False
    elif change == "mode":
        raw["inputs"]["map_setup"]["value"] = 99
    else:
        next(iter(raw["inputs"]["country_flags"].values()))["value"] = None
    with pytest.raises(Exception) as error:
        NativeMissionReader.normalize_branch_inputs(raw, context)
    assert error.value.code in {"branch_input_context_changed", "branch_input_snapshot_incomplete"}


def test_input_read_failure_preserves_captured_rules_and_mission_state(tmp_path):
    from bridge.tests.test_information_missions import State, Definitions, query
    from bridge.information import InformationService
    from bridge.information.composite import CompositeSource
    from bridge.information.missions import MissionInformationSource
    from bridge.information.model import InformationError
    state, definitions = State(), Definitions()

    class Reader:
        def __call__(self, country):
            return state.capture(country)

        def branch_inputs(self, country, context):
            raise InformationError("branch_input_snapshot_incomplete", "Failed input read")

    api = InformationService(CompositeSource(state, [MissionInformationSource(state, definitions, Reader())]), tmp_path / "info.db")
    try:
        result = api.query("failed-branch-input", queries=[query("M02", ["unlock_conditions", "completion_status"])])
        fields = result["items"][0]["fields"]
        assert fields["completion_status"]["value"]["completed_task_ids"] == ["first"]
        assert fields["unlock_conditions"]["value"]["roots"][0]["root_id"] == "loaded"
        assert fields["unlock_conditions"]["value"]["captured_inputs"]["status"] == "unavailable"
        assert fields["unlock_conditions"]["value"]["evaluated"] is False
    finally:
        api.close()
