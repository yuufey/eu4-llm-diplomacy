"""Pin batch20 sources, measured fixture results and remaining goal scope."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-entry-20261025-001"
OWNED_STAGE = ROOT / "work/runtime/information-battle-owned-result-20261025-001"


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pin(path: Path) -> dict:
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": sha(path)}


def load(path: Path) -> dict:
    assert path.stat().st_size <= 8 * 1024 * 1024
    return json.loads(path.read_text(encoding="utf-8"))


def check_current_pins(value: object) -> int:
    count = 0
    if isinstance(value, dict):
        if isinstance(value.get("path"), str) and len(str(value.get("sha256", ""))) == 64:
            path = Path(value["path"])
            if not path.is_absolute():
                path = ROOT / path
            assert path.is_file(), path
            assert sha(path) == value["sha256"], path
            count += 1
        for key, item in value.items():
            if isinstance(key, str) and key.startswith("work/") and isinstance(item, dict) and "sha256" in item:
                assert sha(ROOT / key) == item["sha256"], key
                count += 1
            else:
                count += check_current_pins(item)
    elif isinstance(value, list):
        count += sum(check_current_pins(item) for item in value)
    return count


def build() -> dict:
    research = load(STAGE / "research-index-002.json")
    components = load(STAGE / "component-source-audit-002.json")
    preservation = load(STAGE / "production-preservation-002.json")
    assert research["status"] == "static_research_frozen_runtime_unresolved"
    assert components["status"] == "passed_current_entry_component_audit" and not components["errors"]
    assert preservation["status"] == "passed_current_entry_preservation" and not preservation["mismatch_paths"]
    reports = [STAGE / "unwind-test-001/report-003.json", STAGE / "abi-test-001/report-006.json",
               OWNED_STAGE / "owned-result-test-001/report-002.json",
               STAGE / "integration-test-001/report-008.json"]
    checked_pins = 0
    for path in reports:
        report = load(path)
        assert report["status"] == "passed", path
        run = report.get("run_receipt", report.get("run"))
        assert run["returncode"] == 0, path
        for key in ("source_pins", "sources", "artifact"):
            checked_pins += check_current_pins(report.get(key))
    integration = load(reports[-1])
    assert integration["read_only"] is False and integration["game_access"] is False
    result = integration["run_receipt"]["result"]
    assert result["body_count"] == 5 and result["callback_count"] == 3 and result["copy_failures"] == 1
    assert result["snapshot_retained"] and result["bytes_restored"]
    source_patterns = [
        "work/probe_information_battle_entry*.py", "work/survey_information_battle_entry*.py",
        "work/freeze_information_battle_entry_research*.py", "work/test_information_battle_entry*.py",
        "work/audit_information_battle_entry_components.py", "work/test_information_battle_owned_result.py",
        "work/native/information-battle-entry*", "work/native/information-battle-owned-result.h",
        "work/native/test-information-battle-entry*", "work/native/test-information-battle-owned-result.cpp",
    ]
    files = {Path(__file__).resolve()}
    for pattern in source_patterns:
        files.update(path for path in ROOT.glob(pattern) if path.is_file())
    for directory in (STAGE, OWNED_STAGE):
        files.update(path for path in directory.rglob("*") if path.is_file()
                     and not path.name.startswith("development-summary-") and "__pycache__" not in path.parts)
    files.update(ROOT / name for name in ("HANDOFF.md", "README(agent).md",
        "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md", "docs/逐场战报自然入口与复制.md"))
    misplaced = ROOT / "work/runtime/information-battle-war-records-20261025-001/entry-unwind-pe-001.json"
    files.add(misplaced)
    pins = [pin(path) for path in sorted(files, key=lambda p: p.relative_to(ROOT).as_posix())]
    return {
        "schema": "information_battle_entry_development_checkpoint_v1",
        "status": "passed_research_checkpoint_goal_incomplete",
        "goal": {"objective": "按照docs\\信息导出与订阅开发计划.md进行开发。", "active": True,
                 "complete": False, "topics": 74, "fields": 397, "phases": [2, 3, 4],
                 "coverage": {"available": 54, "partial": 107, "planned": 236}, "B01_B04": "planned"},
        "measured": {"new_static_REA_queries": 1, "query_terminal_with_receipt": True,
                     "trampoline_legal_PC_checks": 12, "shim_unwind_boundaries": 7,
                     "ABI_cases": 4, "nested_cases_included": 2, "owned_copy_checks": 79,
                     "integration_calls": 5, "integration_callbacks": 3, "copy_failure_cases": 1,
                     "current_test_pins_verified": checked_pins, "previous_source_pins_preserved": 127},
        "scope": {"game_access": False, "game_hook_installed": False, "game_function_calls": False,
                  "owned_fixture_code_patch": True, "owned_fixture_data_writes": True,
                  "business_dispatch": False, "event_subscription_connected": False,
                  "visibility_proven": False, "natural_game_ABI_verified": False,
                  "complete_business_battle_payload": False, "overall_complete": False},
        "history": {"unwind_failed_001_002_preserved": True,
                    "old_log_files_may_be_shared": True, "historical_report_embedded_stdout_authoritative": True,
                    "misplaced_new_PE_report_retained": pin(misplaced), "formal_delivery_archive_created": False},
        "tests": {"production_full_suite_rerun": False,
                  "historical_full_suite": {"passed": 2425, "failed": 107, "errors": 35,
                                            "subtests": 1881, "all_passed": False}},
        "next": "Integrate audited source identity/lifecycle controls, validate natural thread/reentry/visibility and stable IDs, then complete payload/text and actual event/subscription delivery.",
        "pins": pins, "pin_count": len(pins), "pinned_bytes": sum(row["bytes"] for row in pins),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    path = STAGE / "development-summary-001.json"
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if args.verify_existing:
        assert path.read_text(encoding="utf-8") == text
    else:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
    print(json.dumps({"output": pin(path), "verified_existing": args.verify_existing}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
