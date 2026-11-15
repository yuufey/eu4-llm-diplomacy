"""Freeze batch22 actual-game raw evidence without promoting business coverage."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STAGE = ROOT / "work/runtime/information-battle-live-20261025-001"
BUILD = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-live-001"
OUTPUT = STAGE / "development-summary-001.json"
DECLARED_DOCUMENT_UPDATES = {
    "HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md",
    "docs/信息导出开发进展.md",
}


def read(path: Path) -> dict:
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("JSON_SIZE_LIMIT:" + str(path))
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pin(path: Path) -> dict:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": path.stat().st_size, "sha256": digest}


def coverage() -> dict:
    from bridge.information.catalog import coverage_report
    from bridge.information.sources import DiplomacySource
    from bridge.information.composite import CompositeSource
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information.domestic_pressure import NativeDomesticPressureSource
    from bridge.information.subject_relations import NativeSubjectRelationSource
    from bridge.information.static_data import StaticTradeSource
    from bridge.information.missions import MissionInformationSource
    base = DiplomacySource(observer="FRA")
    class StaticCatalogOnly:
        def catalog(self):
            return StaticTradeSource.catalog(SimpleNamespace(
                _state=SimpleNamespace(game_version="1.37.4")))
    source = CompositeSource(base, [NativeCountryStateSource(base),
        NativeDomesticPressureSource(base), NativeSubjectRelationSource(base),
        StaticCatalogOnly(), MissionInformationSource(base, None, None)])
    catalog = coverage_report(source)
    fields = Counter(field["coverage"] for topic in catalog["topics"]
                     for field in topic["fields"].values())
    assert catalog["topic_count"] == 74 and catalog["field_count"] == 397
    assert dict(fields) == {"available": 54, "partial": 107, "planned": 236}
    assert all(topic["status"] == "planned" for topic in catalog["topics"]
               if topic["topic_id"] in {"B01", "B02", "B03", "B04"})
    return {"topics": 74, "fields": 397, **dict(fields), "battle_topics_status": "planned",
            "constructed_metadata_only": True, "game_or_service_opened": False}


def assemble() -> dict:
    capture = read(STAGE / "natural-capture-acceptance-001.json")
    assert capture["status"] == "passed_raw_capture_business_unverified"
    assert capture["captured"] == 18 and capture["capture_state"] == "disabled"
    assert capture["final_date_raw"] == 56554248 and capture["paused"] is True
    assert capture["business_battle_complete"] is False and capture["visibility_verified"] is False
    receipts = read(STAGE / "control-receipts-snapshots-001/manifest.json")
    assert receipts["receipt_count"] == 12 and receipts["nonce_count"] == 4
    assert all(receipts["checks"].values())
    analysis = read(STAGE / "payload-analysis-001.json")
    assert analysis["status"].startswith("passed")
    retained = read(STAGE / "retained-live-001/report.json")
    assert retained["read_only"] is True and retained["completed"] is True
    assert retained["status"] == "observed"
    assert retained["cleanup"]["handle_close"]["closed"] is True
    assert retained["doublepass"]["consistent"] is True
    matched = retained["raw_crosscheck"]["matched"]
    assert len(matched) == 1 and matched[0]["raw_index"] == 6
    assert all(item["equal"] is True for item in matched[0]["fields"].values())
    retained_tests = read(STAGE / "retained-reader-test-001/report-002.json")
    assert retained_tests["tests"]["passed"] == 14 and retained_tests["exit_code"] == 0
    runner_tests = read(STAGE / "natural-runner-test-001/report-002.json")
    assert runner_tests["command"]["passed"] == 14 and runner_tests["command"]["exit_code"] == 0
    baseline = read(ROOT / "work/runtime/information-battle-observer-20261025-001/development-summary-001.json")
    prior_pins = baseline["pins"]
    prior_differences = []
    for name, expected in prior_pins.items():
        actual = pin(ROOT / name)
        if actual != expected:
            assert name in DECLARED_DOCUMENT_UPDATES, (name, actual, expected)
            prior_differences.append({"path": name, "reason": "intentional batch22 current-state documentation",
                                      "before": expected, "current": actual})
    manifest = read(BUILD / "build-manifest.json")
    assert manifest["artifact_reuse"]["compiled_in_this_directory"] is False
    for item in manifest["sources"]:
        for path in (ROOT / "work/native" / item["name"], BUILD / item["name"]):
            assert pin(path)["sha256"] == item["sha256"], path
    paths = {path for path in STAGE.rglob("*") if path.is_file() and path != OUTPUT
             and path.name not in {"raw-research.sqlite3", "raw-research.sqlite3-wal", "raw-research.sqlite3-shm"}}
    # The closed, immutable SQLite backup is intentionally included separately.
    paths.add(STAGE / "natural-capture-snapshots-001/raw-research.sqlite3")
    paths.update(BUILD / item["name"] for item in manifest["sources"])
    paths.update((BUILD / "build-manifest.json", BUILD / "eu4_bridge_diplomacy_observer_v23.dll"))
    paths.update(ROOT / "work/native" / item["name"] for item in manifest["sources"])
    paths.update(ROOT / name for name in DECLARED_DOCUMENT_UPDATES)
    paths.update(ROOT / name for name in (
        "docs/信息计划验收清单.md", "docs/逐场战报实机启停与自然观测.md",
        "work/prepare_information_battle_live_install.py", "work/audit_information_battle_live_ownership.py",
        "work/probe_information_battle_v23.py", "work/test_probe_information_battle_v23.py",
        "work/validate_information_battle_live_lifecycle_revision002.py",
        "work/prepare_information_battle_natural_window.py",
        "work/run_information_battle_natural_window.py", "work/test_information_battle_natural_window.py",
        "work/ingest_information_battle_raw_live.py", "work/test_ingest_information_battle_raw_live.py",
        "work/analyze_information_battle_natural_payloads.py", "work/archive_information_battle_natural_capture.py",
        "work/archive_information_battle_live_receipts.py", "work/audit_information_battle_live_preservation.py",
        "work/crosscheck_information_battle_live_retained.py", "work/test_crosscheck_information_battle_live_retained.py",
    ))
    paths.add(Path(__file__).resolve())
    frozen = {path.relative_to(ROOT).as_posix(): pin(path) for path in sorted(paths)}
    return {"schema": "INFORMATION-BATTLE-LIVE-DEVELOPMENT/1",
            "status": "raw_capture_verified_business_export_incomplete",
            "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
            "previous_goal_turn": "no_progress_http_answer_only",
            "current_goal_turn": "progress_actual_game_capture_and_implementation_fixes",
            "goal_complete": False, "coverage": coverage(), "actual_natural_raw_records": 18,
            "independent_retained_matching_raw_sequences": [7],
            "independent_retained_unmatched_raw_records": 17,
            "natural_window_days": [1, 35], "final_date_raw": 56554248,
            "final_capture_state": "disabled", "final_paused": True,
            "game_process_identity_is_historical_observation_revalidate_before_reuse": True,
            "business_dispatches_by_tools": 0, "business_battle_export_complete": False,
            "current_full_suite_run": False,
            "latest_full_suite": {"passed": 2443, "failed": 107, "errors": 35,
                                  "subtests": 1888, "green": False},
            "prior_baseline": {"pins": len(prior_pins),
                "unchanged": len(prior_pins) - len(prior_differences),
                "declared_document_changes": prior_differences,
                "non_document_pin_changes": 0,
                "historical_extra_files": "preservation-audit-001 records raw-ingest-test files added outside prior 325-pin set"},
            "remaining_requirements": ["complete 74-topic 397-field scope and phases 2/3/4",
                "battle observer visibility and natural reentry/full ABI acceptance",
                "same-address same-date reload/world generation",
                "battle kind, roles, winner, final counts/units and complete result UI text",
                "stable public war/battle identity",
                "InformationService event persistence and actual LLM subscriptions/delivery",
                "full requirement-by-requirement live acceptance and regression failures"],
            "execution_sessions": [{"session_id": 7645, "collected_terminal_exit_code": 0}],
            "pin_count": len(frozen), "pins": frozen}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    if args.verify_existing:
        report = read(OUTPUT)
        assert report["goal_complete"] is False
        for name, expected in report["pins"].items():
            assert pin(ROOT / name) == expected, name
    else:
        report = assemble()
        with OUTPUT.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps({"status": report["status"], "pins": report["pin_count"],
                      "goal_complete": report["goal_complete"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
