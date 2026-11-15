"""Saved-file and authentic RPM mission records through public information tools."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.mission_definitions import MissionDefinitionIndex
from bridge.information.missions import MissionInformationSource, NativeMissionReader, SavedMissionContextSource
from bridge.information.saved_missions import SavedMissionSnapshot
from bridge.tests.test_information_missions import Definitions, State, query

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures/information_missions_live_1374.json"


def make_inputs(tmp_path, *, completed=False):
    game, user = tmp_path / "game", tmp_path / "user"
    (game / "missions").mkdir(parents=True)
    user.mkdir()
    (user / "dlc_load.json").write_text('{"enabled_mods":[]}', encoding="utf-8")
    (game / "launcher-settings.json").write_text('{"rawVersion":"v1.37.4.0"}', encoding="utf-8")
    (game / "missions/test.txt").write_text('''loaded={
 slot=1
 potential={tag=FRA}
 first={position=1 trigger={owns=1} effect={add_treasury=10}}
 second={position=2 required_missions={first} trigger={owns=2} effect={if={limit={tag=FRA} add_claim=2}}}
}''', encoding="utf-8")
    save = tmp_path / "snapshot.eu4"
    save.write_text('''EU4txt
date=1455.11.13
player=POR
savegame_version={
 first=1
 second=37
 third=4
 forth=0
}
countries={
 FRA={
  country_missions={
   mission_slot={
    loaded
   }
  }
''' + ('  completed_missions={first}\n' if completed else '') + ' }\n}\n', encoding="utf-8")
    return game, user, save


def test_saved_file_queries_have_no_fabricated_session_or_completed_empty(tmp_path):
    game, user, save = make_inputs(tmp_path)
    primary = SavedMissionContextSource(SavedMissionSnapshot(save, "FRA"))
    adapter = MissionInformationSource(primary, MissionDefinitionIndex(game, user), primary.capture, scheduling=False)
    service = InformationService(CompositeSource(primary, [adapter]), tmp_path / "info.db")
    try:
        result = service.query("saved", queries=[query("M01", ["task_id", "branches"]), query("M02", ["completion_status"])])
        assert result["context"]["mode"] == "recorded" and result["context"]["session_id"] is None
        assert result["context"]["game_day"] is None
        assert result["context"]["game_date"] == "1455.11.13"
        assert result["context"]["archive"]["sha256"] == hashlib.sha256(save.read_bytes()).hexdigest()
        assert result["items"][0]["complete"] is True
        assert result["items"][1]["fields"]["completion_status"]["reason"] == "COMPLETION_FIELD_ABSENT_IN_SAVE"
        assert {tuple(entry["triggers"]) for entry in adapter.catalog()} == {("query",)}
    finally:
        service.close()


def test_actual_cli_saved_mission_queries_and_unevaluated_rewards(tmp_path):
    game, user, save = make_inputs(tmp_path, completed=True)
    requests = [{"tool": "information_query", "arguments": {"view": "full", "request_id": "saved-cli", "queries": [
        query("M01", ["task_id", "branches"]), query("M02", ["completion_status"], task_id="first"),
        query("M04", ["rewards"], task_id="second")]}}]
    completed = subprocess.run([sys.executable, "tools/serve_information.py", "--jsonl", "--mission-game-data",
                                "--mission-save", str(save), "--observer", "FRA", "--static-game-root", str(game),
                                "--static-user-data", str(user), "--database", str(tmp_path / "cli.db")], cwd=ROOT,
                               input="\n".join(json.dumps(value) for value in requests)+"\n", capture_output=True,
                               text=True, encoding="utf-8", timeout=30)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["complete"] is True and result["context"]["session_id"] is None
    assert result["items"][1]["fields"]["completion_status"]["value"]["selected_task"]["completed"] is True
    rewards = result["items"][2]["fields"]["rewards"]["value"]
    assert rewards["evaluated"] is False and rewards["applied"] == "unknown"
    assert rewards["tasks"][0]["effect"]["children"][0]["key"] == "if"


def test_retained_live_mission_capture_normalization_preserves_recorded_provenance(tmp_path):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert fixture["provenance"]["mode"] == "recorded"
    raw = fixture["native_capture"]
    context = fixture["original_context"]
    state = NativeMissionReader.normalize(raw, context)
    assert len(state["mission_slots"]) == 5
    assert sum(len(slot["roots"]) for slot in state["mission_slots"]) == 18
    assert state["mission_slots"][-1]["roots"][-1] == "fra_missions_5_continuation"
    assert state["completed_missions"] == {"status": "known", "task_ids": []}
    assert state["game_date"] == 56553384


@pytest.mark.parametrize("change", ["identity", "static_guard", "doublepass", "game_hash"])
def test_native_capture_normalization_requires_identity_and_static_guards(change):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    raw, context = fixture["native_capture"], fixture["original_context"]
    if change == "identity":
        raw["identity"]["binding_verified"] = False
    elif change == "static_guard":
        raw["static_contract_guard"]["status"] = "unknown"
    elif change == "doublepass":
        raw["doublepass"]["consistent"] = False
    else:
        context["game_sha256"] = "different"
    with pytest.raises(Exception) as error:
        NativeMissionReader.normalize(raw, context)
    assert error.value.code == "mission_snapshot_incomplete"
