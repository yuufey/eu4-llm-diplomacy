"""Derive professionalism from archived independent bytes and new unit proof."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-military-professionalism-20261027-001"
BASELINE = ROOT / "work/runtime/information-military-effective-20261027-001"
SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def read(path):
    assert 0 < path.stat().st_size <= 8 * 1024 * 1024
    return json.loads(path.read_bytes())


def pin(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": digest.hexdigest()}


def main():
    raw_path = BASELINE / "native-effective-inputs-003.json"
    frozen = read(BASELINE / "development-summary-001.json")
    saved_pin = next(item for item in frozen["artifact_pins"] if item["path"] == raw_path.relative_to(ROOT).as_posix())
    assert pin(raw_path) == saved_pin
    report = read(raw_path)
    assert report["status"] == "observed" and report["completed"] is True
    assert report["doublepass"]["consistent"] is True
    assert report["cleanup"]["handle_close"]["closed"] is True
    identity = report["identity"]
    assert identity["binding_verified"] is True and identity["process_path_sha256"] == SHA
    assert identity["installation_session_id"] == "31460-1dd653f69242d7b"
    assert identity["installation_creation_filetime"] == identity["process_creation_filetime"] == 134374886912306555
    inputs = report["military_effective_inputs"]
    assert len(inputs) == 2 and inputs[0] == inputs[1]
    source = inputs[0]
    assert source["date"]["value"] == 56557728
    country = source["country"]
    assert country["status"] == "observed" and country["requested_country"] == "FRA"
    assert len(country["matches"]) == 1
    match = country["matches"][0]
    assert match["tag"] == "FRA" and match["slot"] == match["index"] == 122
    assert match["handle_raw_hex"] == "465241007a000001"
    data = source["military_effective"]
    assert data["country_pointer"] == country["country_pointer"]["va"]
    reads = [item for item in data["reads"] if item["label"] == "professionalism_raw_unit_unresolved"]
    assert len(reads) == 1
    native = reads[0]
    raw = bytes.fromhex(native["raw_hex"])
    assert len(raw) == native["bytes"] == 8
    assert int(native["va"], 16) == int(data["country_pointer"], 16) + 0x50
    value = int.from_bytes(raw, "little", signed=True)
    assert data["professionalism_unit_unresolved"]["raw"] == value

    scale_path = STAGE / "professionalism-scale-source-001.json"
    scale_source = read(scale_path)
    contract = scale_source["contract"]
    wanted = {"width_bytes": 8, "signed": True, "unit": "ratio", "scale": 32768, "period": "current",
              "basis": "native_country_army_professionalism_cache",
              "value_origin": "copied_native_country_army_professionalism_cache"}
    assert all(contract[key] == item for key, item in wanted.items())
    assert int(str(contract["country_offset"]), 0) == 0x50
    result = {"schema": "information_military_professionalism_independent_reference.v1",
              "status": "observed", "reference_id": "expected-military-professionalism-001",
              "header": {"country": "FRA", "session_id": identity["installation_session_id"],
                         "creation_filetime": 134374886912306555, "game_date": 56557728,
                         "game_sha256": SHA, "country_fullref_raw_hex": match["handle_raw_hex"], "country_slot": 122},
              "fields": {"professionalism": {"status": "known", "complete": True, "value": value,
                         "raw": value, "raw_hex": raw.hex(), **{key: wanted[key] for key in
                         ("unit", "scale", "period", "basis", "value_origin")}}},
              "source_raw": pin(raw_path), "source_scale": pin(scale_path),
              "raw_source_address": native["va"], "raw_two_pass_equal": True,
              "native_game_calls": False, "new_RPM": False,
              "basis": "Offline signed-QWORD decode of independent batch50 RPM bytes with newly pinned type8 scale semantics; no production reader or MCP output imported."}
    output = STAGE / "expected-military-professionalism-001.json"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"reference": pin(output), "fields": result["fields"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
