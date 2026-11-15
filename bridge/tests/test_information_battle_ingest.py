from __future__ import annotations

import json
from pathlib import Path
import shutil
import sqlite3

import pytest

from bridge.information.battle_ingest import LiveBattleIngestor
from bridge.information.model import InformationError


ROOT = Path(__file__).resolve().parents[2]
SEALED_RAW = ROOT / "bridge/tests/fixtures/information_battle_live_stream_1374.jsonl"
DLL_SHA = "c920495a2d61d91fffc7cbbcd026febcf56d29a352dfc07cc803c0be1034aecb"
SESSION = "15612-1dd64921da9212c"
CREATION = "134374142616609068"
INSTALLATION = "17951843146667052269"
GENERATION = "134374142616609068"
PLAYER_REF = "010000bd00524f50"


def _fixture(tmp_path: Path) -> Path:
    live = tmp_path / "installed"
    live.mkdir()
    shutil.copyfile(SEALED_RAW, live / "information-battle-raw.jsonl")
    (live / "installation.json").write_text(json.dumps({
        "pid": 15612,
        "creation_filetime": int(CREATION),
        "session_id": SESSION,
        "dll_sha256": DLL_SHA,
    }), encoding="utf-8")
    (live / "information-battle-binding.json").write_text(json.dumps({
        "schema": "EU4-BATTLE-CONTROL/1",
        "pid": 15612,
        "creation_filetime": CREATION,
        "session_id": SESSION,
        "dll_sha256": DLL_SHA,
        "installation": INSTALLATION,
        "generation": GENERATION,
        "player_ref": PLAYER_REF,
    }), encoding="utf-8")
    return live / "installation.json"


def test_sealed_fourteen_record_log_is_incremental_and_restart_safe(tmp_path, monkeypatch):
    assert SEALED_RAW.is_file()
    installation = _fixture(tmp_path)
    database = tmp_path / "raw.sqlite3"

    ingestor = LiveBattleIngestor(installation, database)
    first = ingestor.refresh()
    assert first["status"] == "advanced"
    assert first["tailer"]["poll"]["acked"] == 14
    assert first["reassembly"]["poll"]["completed"] == 14
    assert first["transport"]["received_count"] == 14
    assert first["complete"] is False

    # Force the documented short coalescing window to be visible in this
    # deterministic test; the production value remains 50 ms.
    monkeypatch.setattr("bridge.information.battle_ingest.COALESCE_SECONDS", 60.0)
    coalesced = ingestor.refresh()
    assert coalesced["coalesced"] is True
    assert coalesced["transport"]["received_count"] == 14
    ingestor.close()
    ingestor.close()

    reopened = LiveBattleIngestor(installation, database)
    second = reopened.refresh()
    assert second["status"] == "idle"
    assert second["tailer"]["poll"]["acked"] == 0
    assert second["reassembly"]["poll"]["processed"] == 0
    assert second["transport"]["received_count"] == 14
    reopened.close()

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM battle_records").fetchone()[0] == 14
        assert connection.execute("SELECT COUNT(*) FROM complete_messages").fetchone()[0] == 14


def test_invalid_source_binding_fails_before_opening_database(tmp_path):
    installation = tmp_path / "installation.json"
    installation.write_text(json.dumps({"pid": 1}), encoding="utf-8")
    ingestor = LiveBattleIngestor(installation, tmp_path / "raw.sqlite3")
    with pytest.raises(InformationError) as error:
        ingestor.refresh()
    assert error.value.code == "battle_ingest_binding_invalid"
    assert not (tmp_path / "raw.sqlite3").exists()
    ingestor.close()


def test_new_real_frames_are_ingested_by_tick_and_feed_fra_report_and_history(tmp_path, monkeypatch):
    from bridge.information.battles import BattleInformationSource
    from bridge.information.sources import RecordedSource
    from bridge.information.service import InformationService
    from bridge.information.tools import InformationTools

    fixture = json.loads((ROOT / "bridge/tests/fixtures/information_battle_FRA_live_v2_1374.json").read_text(encoding="utf-8"))
    installation = _fixture(tmp_path)
    log = installation.parent / "information-battle-raw.jsonl"
    lines = log.read_bytes().splitlines(keepends=True)
    # Real records 1..8 exclude FRA; the appended 9..14 contain the Paris
    # battle. No game action is repeated and no payload is manufactured.
    log.write_bytes(b"".join(lines[:9]))
    database = tmp_path / "raw.sqlite3"
    binding = {"session_id": SESSION, "installation": "f921c23a9c9ecced",
               "generation": "01dd64921da9212c", "observer_ref": fixture["recorded_observer_ref"],
               "game_sha256": fixture["provenance"]["game_sha256"], "mode": "recorded"}
    primary = RecordedSource({"context": {"status": "ready", "session_id": SESSION,
        "observer": "FRA", "game_sha256": binding["game_sha256"], "game_version": "1.37.4",
        "game_date": fixture["context_date"]}, "events": []})
    monkeypatch.setattr("bridge.information.battle_ingest.COALESCE_SECONDS", 0.0)

    def runtime():
        source = BattleInformationSource(primary, database, binding)
        source.ingestor = LiveBattleIngestor(installation, database, expected_binding=binding)
        return source, InformationService(source, tmp_path / "information.sqlite3")

    source, service = runtime()
    try:
        tools = InformationTools(service)
        report = tools.call("information_manage_report", {"request_id": "auto-report", "operation": "create",
            "config": {"name": "FRA land counts", "detail": "full", "queries": [
                {"topic": "B01", "object": {"type": "battle"}, "fields": ["name", "sides"]},
                {"topic": "B02", "object": {"type": "battle"}, "fields": ["initial_forces", "losses"]}]}})["report"]
        tools.call("information_manage_subscription", {"request_id": "auto-sub", "operation": "create",
            "config": {"name": "new captured battle", "kind": "event", "report_id": report["id"],
                       "enabled": True, "event": {"types": ["battle_observation"]}}})
        assert tools.call("information_tick", {"view": "full"})["results"] == []
        with log.open("ab") as stream:
            stream.write(b"".join(lines[9:]))
        tick = tools.call("information_tick", {"view": "full"})
        assert len(tick["results"]) == 1
        result = tick["results"][0]
        assert result["items"][0]["fields"]["name"]["value"] == "巴黎"
        sides = result["items"][0]["fields"]["sides"]["value"]
        assert sides[0]["representative"] == "FRA" and sides[0]["combat_side_index"] == 1
        assert sides[0]["participants"] == ["FRA", "FOI", "AUV"]
        assert sides[0]["observer_participated"] is True
        forces = result["items"][1]["fields"]
        assert forces["initial_forces"]["value"]["sides"][1]["component_sum"] == 40928
        assert forces["losses"]["value"]["sides"][1]["component_sum"] == 1806
        history = tools.call("information_query", {"view": "full", "request_id": "auto-history", "queries": [
            {"topic": "H01", "object": {"type": "session"}, "fields": ["battle_sequence"]}]})
        refs = history["items"][0]["fields"]["battle_sequence"]["value"]["event_refs"]
        assert [ref["event_id"] for ref in refs] == [result["event"]["event_id"]]
    finally:
        service.close()
        source.ingestor.close()
    source, service = runtime()
    try:
        assert service.tick()["results"] == []
        with sqlite3.connect(database) as connection:
            assert connection.execute("SELECT COUNT(*) FROM complete_messages").fetchone()[0] == 14
    finally:
        service.close()
        source.ingestor.close()


def test_wrong_log_header_is_rejected_before_transport_write(tmp_path):
    installation = _fixture(tmp_path)
    log = installation.parent / "information-battle-raw.jsonl"
    raw = log.read_bytes()
    log.write_bytes(raw.replace(
        b"f921c23a9c9ecced", b"f921c23a9c9eccee", 1
    ))
    database = tmp_path / "raw.sqlite3"
    ingestor = LiveBattleIngestor(installation, database)
    with pytest.raises(InformationError) as error:
        ingestor.refresh()
    assert error.value.code == "battle_ingest_header_binding_mismatch"
    assert not database.exists()
    ingestor.close()


def test_source_expected_binding_is_checked_before_log_or_database(tmp_path):
    installation = _fixture(tmp_path)
    database = tmp_path / "raw.sqlite3"
    ingestor = LiveBattleIngestor(
        installation,
        database,
        expected_binding={
            "session_id": SESSION,
            "installation": "f921c23a9c9eccee",
            "generation": GENERATION,
        },
    )
    with pytest.raises(InformationError) as error:
        ingestor.refresh()
    assert error.value.code == "battle_ingest_expected_binding_mismatch"
    assert not database.exists()
    ingestor.close()
