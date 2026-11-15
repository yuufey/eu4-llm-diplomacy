"""Audit an evidence-reference transcription against bounded original PE bytes.

This performs ordinary file verification, not disassembly or process access.
Only --apply corrects the single source-reference typo after all checks pass.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget
from work.local_config import game_exe

STAGE = ROOT / "work/runtime/information-missions-20261024-001"
PROFILE = ROOT / "bridge/information/profiles/mission-memory-1374.json"
MODULE = ROOT / "bridge/information/mission_memory.py"
REFERENCE = "live-writer-thunk.json"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    old_raw = PROFILE.read_bytes()
    old = json.loads(old_raw)
    pe = PE(game_exe())
    executable_sha256 = sha(pe.data)
    assert executable_sha256 == old["executable"]["sha256"]
    assert pe.base == int(old["executable"]["image_base"], 0)
    audited = []
    discrepancies = []
    for name, expected in old["source_evidence"].items():
        raw = (STAGE / name).read_bytes()
        assert len(raw) < 1024 * 1024
        report = json.loads(raw)
        actual = sha(raw)
        assert report["game_sha256"] == executable_sha256
        assert report["address_kind"] == "RVA"
        assert report["evidence_kind"] == "ordinary_file_analysis_not_REA_Evidence"
        ranges = []
        for item in report["ranges"]:
            start, end = int(item["start_rva"], 0), int(item["end_rva_exclusive"], 0)
            assert 0 < end-start <= 65536
            data = pe.bytes_at(start, end-start)
            assert sha(data) == item["bytes_sha256"]
            for instruction in item["instructions"]:
                rva = int(instruction["rva"], 0)
                encoded = bytes.fromhex(instruction["bytes"])
                assert start <= rva < end and rva+len(encoded) <= end
                assert pe.bytes_at(rva, len(encoded)) == encoded
            ranges.append({"start_rva": hex(start), "end_rva_exclusive": hex(end),
                           "bytes_sha256": sha(data), "instruction_count": len(item["instructions"])})
        row = {"name": name, "recorded_sha256": expected, "file_sha256": actual,
               "file_hash_matches_reference": expected == actual, "ranges_verified_against_exe": ranges}
        audited.append(row)
        if expected != actual:
            discrepancies.append(row)
    assert len(discrepancies) == 1 and discrepancies[0]["name"] == REFERENCE
    before, after = discrepancies[0]["recorded_sha256"], discrepancies[0]["file_sha256"]
    difference = [{"index": i, "recorded": a, "actual": b}
                  for i, (a, b) in enumerate(zip(before, after)) if a != b]
    assert difference == [{"index": 32, "recorded": "a", "actual": "c"}]
    corrected = deepcopy(old)
    corrected["source_evidence"][REFERENCE] = after
    new_raw = (json.dumps(corrected, ensure_ascii=False, indent=2)+"\n").encode("utf-8")
    new_sha = sha(new_raw)
    module_before = MODULE.read_bytes()
    old_sha = sha(old_raw)
    pattern = rb'(EXPECTED_PROFILE_SHA256 = ")'+old_sha.encode("ascii")+rb'(")'
    module_after, count = re.subn(pattern, lambda m: m[1]+new_sha.encode("ascii")+m[2], module_before)
    assert count == 1
    report = {
        "status": "ordinary_file_byte_audit_passed", "applied": args.apply,
        "kind": "source_reference_transcription_correction", "read_only_game": True,
        "executable_sha256": executable_sha256, "reference": REFERENCE, "hex_digit_difference": difference,
        "source_reports": audited, "old_profile_sha256": old_sha, "new_profile_sha256": new_sha,
        "old_module_sha256": sha(module_before), "new_module_sha256": sha(module_after),
        "profile_change_only": ["source_evidence."+REFERENCE],
        "all_offsets_instructions_limits_and_runtime_guards_unchanged": True,
        "historical_reports_unchanged": True, "peak_committed_bytes": check_memory_budget(),
    }
    if args.apply:
        backup = STAGE / "profile-reference-before-001"
        backup.mkdir(exist_ok=False)
        shutil.copyfile(PROFILE, backup / PROFILE.name)
        shutil.copyfile(MODULE, backup / MODULE.name)
        PROFILE.write_bytes(new_raw)
        MODULE.write_bytes(module_after)
        assert sha(PROFILE.read_bytes()) == new_sha and sha(MODULE.read_bytes()) == sha(module_after)
    output = STAGE / ("profile-reference-correction-001.json" if args.apply else "profile-reference-audit-001.json")
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({key: value for key, value in report.items() if key != "source_reports"}))


if __name__ == "__main__":
    main()
