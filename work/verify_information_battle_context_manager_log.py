"""Archive and ingest the actual v24 self-fixture checked log, offline only."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from work.ingest_information_battle_raw_live import ingest_live_raw
from work.verify_information_battle_context_v23_compat import pin, read

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "work/runtime/information-battle-context-observer-20261025-001"
STAGE = BASE / "manager-log-ingest-001"


def write(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main() -> None:
    source_report = BASE / "manager-test-001/report-007.json"
    manager = read(source_report)
    assert manager["status"] == "passed" and manager["run"]["returncode"] == 0
    original = Path(manager["run"]["log_path"])
    before = pin(original)
    assert before["bytes"] == manager["log_reassembly"]["size_bytes"] < 2 * 1024 * 1024
    raw = original.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == before["sha256"]
    header = raw.splitlines()[0].split()
    assert len(header) == 3 and header[0] == b"EU4_OWNED_BATTLE_WIRE_V1"
    installation, generation = (int(item, 16) for item in header[1:])
    command = manager["compile"]["command"]
    executable = Path(command[command.index("-o") + 1])
    executable_pin = pin(executable)
    player = manager["wire_decode"]["decoded"]["observed"]["context"]["physical_player_full_ref"]
    STAGE.mkdir(parents=True, exist_ok=False)
    with (STAGE / "information-battle-raw.jsonl").open("xb") as stream:
        stream.write(raw)
    # This is explicit offline fixture metadata, never an installation in EU4.
    identity = {"pid": 1, "creation_filetime": generation,
                "session_id": "offline-owned-v24-manager-fixture",
                "dll_sha256": executable_pin["sha256"], "fixture_metadata": True}
    binding = {**identity, "schema": "EU4-BATTLE-CONTROL/1",
               "installation": str(installation), "generation": str(generation),
               "player_ref": f"{player:016x}"}
    write(STAGE / "installation.json", identity)
    write(STAGE / "information-battle-binding.json", binding)
    first = ingest_live_raw(STAGE / "installation.json", STAGE / "research.sqlite3", STAGE / "ingest-001.json")
    second = ingest_live_raw(STAGE / "installation.json", STAGE / "research.sqlite3", STAGE / "reopen-001.json")
    assert first["status"] == second["status"] == "passed"
    assert first["transport"]["received_count"] == 15 == len(first["messages"])
    assert first["decode_rejected_count"] == second["decode_rejected_count"] == 0
    assert second["tailer"]["poll"]["acked"] == 0
    assert len(second["messages"]) == 15
    hashes = {item["payload_sha256"] for item in first["messages"]}
    assert set(manager["wire_decode"]["wire_sha256"].values()) <= hashes
    assert [item["payload_sha256"] for item in first["messages"]] == [item["payload_sha256"] for item in second["messages"]]
    assert all(item["decode"]["status"] == "decoded_raw_context"
               and not item["business_complete"] and not item["visibility_verified"] for item in first["messages"])
    assert pin(original) == before and pin(STAGE / "information-battle-raw.jsonl") == before
    write(STAGE / "report.json", {
        "schema": "V24-MANAGER-CHECKED-LOG-INGEST/1", "status": "passed",
        "game_access": False, "fixture_metadata": True,
        "fixture_executable_used_as_local_binding_hash": True,
        "original_temp_log_changed": False, "original_temp_log": {"path": str(original), **before},
        "manager_report": {"path": source_report.relative_to(ROOT).as_posix(), **pin(source_report)},
        "fixture_executable": {"path": executable.relative_to(ROOT).as_posix(), **executable_pin},
        "transport_frames_durably_received": 15, "decoded_v2_messages": 15,
        "four_reported_context_cases_matched": True, "reopen_new_acks": 0,
        "strict_frame_crc_and_fragment_validation": True, "business_complete": False,
        "sources": {name: pin(ROOT / name) for name in (
            "work/verify_information_battle_context_manager_log.py",
            "work/ingest_information_battle_raw_live.py",
            "work/information_battle_context_wire.py")}})
    print(json.dumps({"status": "passed", "persisted_v2_messages": 15, "reopen_new_acks": 0}))


if __name__ == "__main__":
    main()
