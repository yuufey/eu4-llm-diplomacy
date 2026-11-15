"""Reprocess the sealed 18-record v23 capture in a fresh offline database."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from work.ingest_information_battle_raw_live import ingest_live_raw

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "work/runtime/information-battle-live-20261025-001"
STAGE = ROOT / "work/runtime/information-battle-context-observer-20261025-001/actual-v23-compatibility-001"


def pin(path: Path) -> dict:
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": path.stat().st_size, "sha256": sha}


def read(path: Path) -> dict:
    assert path.stat().st_size < 2 * 1024 * 1024
    return json.loads(path.read_text(encoding="utf-8-sig"))


def main() -> None:
    sealed = read(OLD / "development-summary-001.json")["pins"]
    inputs = {
        OLD / "natural-capture-snapshots-001/installation.json": "installation.json",
        OLD / "natural-capture-snapshots-001/binding.json": "information-battle-binding.json",
        OLD / "natural-capture-snapshots-001/raw.jsonl": "information-battle-raw.jsonl",
        OLD / "raw-reopen-001.json": None,
    }
    before = {}
    for source in inputs:
        name = source.relative_to(ROOT).as_posix()
        before[name] = pin(source)
        assert before[name] == sealed[name], name
    STAGE.mkdir(parents=True, exist_ok=False)
    for source, name in inputs.items():
        if name:
            assert source.stat().st_size < 2 * 1024 * 1024
            with (STAGE / name).open("xb") as stream:
                stream.write(source.read_bytes())
    first = ingest_live_raw(STAGE / "installation.json", STAGE / "fresh-research.sqlite3", STAGE / "ingest-001.json")
    second = ingest_live_raw(STAGE / "installation.json", STAGE / "fresh-research.sqlite3", STAGE / "reopen-001.json")
    old = read(OLD / "raw-reopen-001.json")
    assert first["status"] == second["status"] == "passed"
    assert first["transport"]["received_count"] == second["transport"]["received_count"] == 18
    assert first["tailer"]["poll"]["acked"] == 18 and second["tailer"]["poll"]["acked"] == 0
    previous = {row["message_id"]: row for row in old["messages"]}
    assert len(first["messages"]) == len(second["messages"]) == len(previous) == 18
    compared = []
    for row in first["messages"]:
        former = previous[row["message_id"]]
        assert row["payload_sha256"] == former["payload_sha256"]
        assert row["raw_payload_hex"] == former["raw_payload_hex"]
        assert row["decode"]["value"] == former["decode"]["value"]
        assert row["decode"]["wire_version"] == 1
        assert row["business_complete"] is False and row["visibility_verified"] is False
        compared.append({"message_id": row["message_id"], "payload_sha256": row["payload_sha256"]})
    assert [row["payload_sha256"] for row in first["messages"]] == [row["payload_sha256"] for row in second["messages"]]
    for source in inputs:
        name = source.relative_to(ROOT).as_posix()
        assert pin(source) == before[name], name
    report = {"schema": "BATTLE-CONTEXT-V23-ARCHIVE-COMPATIBILITY/1", "status": "passed",
              "game_access": False, "original_logs_or_databases_written": False,
              "fresh_offline_database": True, "business_complete": False,
              "matched_payloads_and_decoded_values": len(compared), "reopen_new_acks": 0,
              "original_inputs_before_and_after": before, "messages": compared,
              "sources": {name: pin(ROOT / name) for name in (
                  "work/verify_information_battle_context_v23_compat.py",
                  "work/ingest_information_battle_raw_live.py",
                  "work/information_battle_observation_wire.py",
                  "work/information_battle_context_wire.py")}}
    with (STAGE / "report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "matched": len(compared), "reopen_new_acks": 0}))


if __name__ == "__main__":
    main()
