"""Compare saved pure-RPM observations with the independent binary save.

This verifier opens only evidence files.  The anchored date interval is not
a general native-calendar decoder or proof of complete event capture.
"""
from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-war-records-20261025-001"
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
SAVE_SHA = "ffa91dbd2a2d544b18d586a895bb9b0c2b90e94ece47b2c74507555b8f58c2e0"
DLL_SHA = "d80ef39d66d263788c0af4df0892b4ff781e5e3b3f9aea7ebe33759327e457db"


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pin(path: Path) -> dict:
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": sha(path)}


def load(relative: str) -> tuple[dict, Path]:
    path = STAGE / relative
    assert path.stat().st_size < 8 * 1024 * 1024
    return json.loads(path.read_text(encoding="utf-8")), path


def build() -> dict:
    positive, positive_path = load("live-fra-bur-002/report.json")
    negative, negative_path = load("live-fra-eng-001/report.json")
    baseline, baseline_path = load("save-bytes-fra-bur-001/report.json")
    oldsave, oldsave_path = load("save-crosscheck-fra-bur-001/report.json")
    tests, tests_path = load("memory-reader-test-001/report-003.json")
    preservation, preservation_path = load("production-preservation-001.json")
    checks = []

    def check(name: str, actual: object, expected: object) -> None:
        checks.append({"name": name, "actual": actual, "expected": expected,
                       "passed": actual == expected})

    reader_path = ROOT / "work/information_battle_war_memory.py"
    reader_sha = sha(reader_path)
    for source in tests["source_files"]:
        check("test_current_source:" + source["path"], sha(ROOT / source["path"]), source["sha256"])
    check("tests_passed", tests["status"], "passed")
    check("test_count", tests["verification"][1]["passed"], 18)
    for label, report in (("FRA/BUR", positive), ("FRA/ENG", negative)):
        check(label + ":status", report["status"], "observed")
        check(label + ":source", report["probe_script_sha256"], reader_sha)
        check(label + ":identity_before_after", report["identity_before"], report["identity_after"])
        check(label + ":identity_verified", report["identity_before"]["binding_verified"], True)
        check(label + ":exe_sha", report["identity_before"]["process_path_sha256"], EXE_SHA)
        check(label + ":doublepass", report["doublepass"]["consistent"], True)
        check(label + ":handle_closed", report["cleanup"]["handle_close"]["closed"], True)
        check(label + ":read_only_mask", report["access"]["open_process_mask_hex"], "0x410")
        check(label + ":rpm_bounded", 0 < report["access"]["rpm_bytes_requested"] <= 4 * 1024 * 1024, True)
        for flag in ("date_advance", "dll_injection", "native_game_calls", "target_memory_writes", "save_or_reload", "ui_control"):
            check(label + ":" + flag, report["access"][flag], False)
        for phase in ("before", "after"):
            check(label + ":" + phase + ":paused", report[phase]["control"]["paused"]["raw"], 1)
            check(label + ":" + phase + ":speed", report[phase]["control"]["speed"]["value"], 0)
            loaded = report["dll_installation"][phase]
            check(label + ":" + phase + ":dll", loaded["status"], "observed")
            check(label + ":" + phase + ":dll_sha", loaded["matching_modules"][0]["sha256"], DLL_SHA)
        check(label + ":overall_complete", report["complete"], False)
    check("same_live_identity", positive["identity_before"], negative["identity_before"])
    check("same_live_date", positive["before"]["game_date"]["raw"], negative["after"]["game_date"]["raw"])
    check("FRA/BUR:war_count", len(positive["wars"]), 1)
    check("FRA/BUR:result_count", len(positive["results"]), 1)
    check("FRA/ENG:war_count", len(negative["wars"]), 0)
    check("FRA/ENG:result_count", len(negative["results"]), 0)
    check("FRA/ENG:pair_sets_equal", negative["after"]["pair_references"]["sets_equal"], True)
    check("binary_save_status", baseline["status"], "passed_binary_save_crosscheck")
    check("binary_save_sha_before", baseline["save"]["sha256_before"], SAVE_SHA)
    check("binary_save_sha_after", baseline["save"]["sha256_after"], SAVE_SHA)
    battle = baseline["selection"]["battle"]
    observed = positive["results"][0]["result"]
    check("location", observed["province_id"]["raw"], int(battle["location"]["ascii_if_unambiguous"]))
    check("name_bytes", observed["name"]["bytes_hex"], battle["name"]["raw_unquoted_bytes_hex"])
    check("result_flag_raw_vs_serialized_boolean", observed["flag"]["raw"], {"no": 0, "yes": 1}[battle["result"]["ascii_if_unambiguous"]])
    live_sides = {observed[side]["country"]["tag"]: observed[side] for side in ("side_a", "side_b")}
    field_map = {"infantry": "infantry", "cavalry": "cavalry", "artillery": "artillery",
                 "heavy_ship": "heavy", "light_ship": "light", "galley": "galley",
                 "transport": "transport", "losses": "losses", "war_goal": "war_goal"}
    quantities = []
    for saved_role, side in battle["sides"].items():
        tag = side["country"]["ascii_if_unambiguous"]
        live_side = live_sides[tag]
        check(tag + ":commander_bytes", live_side["commander"]["bytes_hex"], side["commander"]["raw_unquoted_bytes_hex"])
        for saved_field, native_field in field_map.items():
            if saved_field in side:
                saved_value = int(side[saved_field]["ascii_if_unambiguous"])
                actual = live_side["fields"][native_field]["raw"]
                check(tag + ":" + saved_field, actual, saved_value)
                quantities.append({"country": tag, "saved_role": saved_role, "saved_field": saved_field,
                                   "native_field": native_field, "raw_value": actual})
    saved_date = date(*map(int, battle["date"]["ascii_if_unambiguous"].split(".")))
    anchor_date = date(*map(int, oldsave["save"]["date"].split(".")))
    assert saved_date.year == anchor_date.year == 1455  # no general calendar claim
    elapsed_days = (anchor_date - saved_date).days
    elapsed_ticks = positive["after"]["game_date"]["raw"] - observed["timeline_date"]["raw"]
    check("anchored_same_year_day_interval", elapsed_ticks, elapsed_days * 24)
    check("partial_history_preserved", positive["retained_observation_complete"], False)
    check("unknown_history_entries_preserved", bool(positive["wars"][0]["history"]["unknown_conditions"]), True)
    check("production_preservation", preservation["status"], "passed_read_only_source_audit")
    assert all(row["passed"] for row in checks), [row for row in checks if not row["passed"]]
    return {"schema": "information_battle_war_live_acceptance_v1",
            "status": "passed_read_only_retained_record_binary_comparison",
            "checks": checks, "check_count": len(checks),
            "observed": {"positive_pair": "FRA/BUR", "positive_records": 1, "negative_pair": "FRA/ENG",
                         "negative_records": 0, "location": observed["province_id"]["raw"],
                         "quantities": quantities, "name_bytes_equal": True, "commander_bytes_equal": True,
                         "timeline_raw": observed["timeline_date"]["raw"], "save_date": saved_date.isoformat(),
                         "date_check": "48-day interval anchored to the same saved/live1455.11.13; not a general native calendar decoder",
                         "elapsed_days": elapsed_days, "elapsed_native_ticks": elapsed_ticks},
            "scope": {"source": "native_retained_subset/query_only", "visibility_proven": False,
                      "battle_kind_proven_by_this_check": False, "native_units_generalized": False,
                      "text_decoded_for_display": False, "all_history_types_known": False,
                      "event_capture_or_subscription_connected": False, "B01_B04_available": False,
                      "overall_complete": False, "goal_complete": False},
            "evidence": [pin(path) for path in (positive_path, negative_path, baseline_path, oldsave_path,
                                                tests_path, preservation_path)],
            "reader": pin(reader_path), "script": pin(Path(__file__).resolve())}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    output = STAGE / "live-acceptance-001.json"
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if args.verify_existing:
        assert output.read_text(encoding="utf-8") == text
    else:
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
    print(json.dumps({"output": pin(output), "verified_existing": args.verify_existing}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
