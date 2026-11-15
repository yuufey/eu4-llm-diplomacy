"""Pin the completed research batch without changing the larger active goal."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-war-records-20261025-001"


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pin(path: Path) -> dict:
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": sha(path)}


def load(name: str) -> dict:
    path = STAGE / name
    assert path.stat().st_size <= 8 * 1024 * 1024
    return json.loads(path.read_text(encoding="utf-8"))


def build() -> dict:
    research = load("research-index-002.json")
    components = load("component-source-audit-001.json")
    preservation = load("production-preservation-001.json")
    acceptance = load("live-acceptance-001.json")
    tests = load("memory-reader-test-001/report-003.json")
    assert research["status"] == "static_research_frozen_runtime_unresolved"
    assert components["status"] == "passed_component_source_audit" and components["conclusion"]["mismatch_count"] == 0
    assert preservation["status"] == "passed_read_only_source_audit"
    assert acceptance["status"] == "passed_read_only_retained_record_binary_comparison"
    assert all(item["passed"] for item in acceptance["checks"])
    assert tests["verification"][1]["passed"] == 18 and tests["verification"][1]["failed"] == 0
    for item in tests["source_files"]:
        assert sha(ROOT / item["path"]) == item["sha256"]
    for item in acceptance["evidence"]:
        assert sha(ROOT / item["path"]) == item["sha256"]
    source_names = [
        "work/information_battle_war_memory.py", "work/tests/test_information_battle_war_memory.py",
        "work/extract_information_battle_war_evidence.py", "work/freeze_information_battle_war_research.py",
        "work/probe_information_battle_war_retention.py", "work/probe_information_battle_history_root.py",
        "work/probe_information_battle_war_acceptance.py", "work/crosscheck_information_battle_war_save.py",
        "work/crosscheck_information_battle_war_save_bytes.py", "work/audit_information_battle_war_preservation.py",
        "work/audit_information_battle_war_components.py",
        "work/survey_information_passive_hook_infrastructure.py",
        "HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md",
        "docs/信息导出开发进展.md", "docs/逐场战报历史读取与保留范围.md",
    ]
    files = [ROOT / name for name in source_names] + [Path(__file__).resolve()]
    files += [path for path in sorted(STAGE.rglob("*")) if path.is_file()
              and not path.name.startswith("development-summary-") and "__pycache__" not in path.parts]
    unique = sorted(set(files), key=lambda path: path.relative_to(ROOT).as_posix())
    pins = [pin(path) for path in unique]
    return {
        "schema": "information_battle_war_records_development_checkpoint_v1",
        "status": "passed_research_checkpoint_goal_incomplete",
        "goal": {"objective": "按照docs\\信息导出与订阅开发计划.md进行开发。",
                 "active": True, "complete": False, "topics": 74, "fields": 397,
                 "coverage": {"available": 54, "partial": 107, "planned": 236},
                 "B01_B04": "planned", "phases": [2, 3, 4]},
        "evidence": {"REA_queries": 4, "all_new_queries_terminal_with_receipts": True,
                     "new_REA_calls_by_finalizer": False, "offline_reader_tests_passed": 18,
                     "live_positive_retained_records": 1, "live_negative_pair_records": 0,
                     "binary_name_and_commander_comparison": "passed",
                     "anchored_date_interval_check": "passed", "acceptance_checks": acceptance["check_count"],
                     "component_mismatches": 0, "preservation": "127 distinct pins including82 production files matched"},
        "limits": {"source": "native_retained_subset/query_only", "unknown_history_entries_preserved": True,
                   "visibility_proven": False, "general_units_proven": False,
                   "new_hook_installed": False, "real_event_subscription_connected": False,
                   "overall_complete": False, "formal_delivery_archive_created": False},
        "validation": {"production_full_suite_rerun": False,
                       "historical_full_suite": {"passed": 2425, "failed": 107, "errors": 35,
                                                 "subtests": 1881, "all_passed": False}},
        "next": "Validate238620 natural entry ABI/unwind/thread/reentry/visibility and stable public identities, then complete owned source payload and event/subscription integration.",
        "pins": pins, "pin_count": len(pins), "pinned_bytes": sum(item["bytes"] for item in pins),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    output = STAGE / "development-summary-001.json"
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
