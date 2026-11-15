"""Freeze batch21 evidence without promoting raw observations to business data."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
STAGE = ROOT / "work/runtime/information-battle-observer-20261025-001"
BUILD = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-v23-005"
OUTPUT = STAGE / "development-summary-001.json"


def read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pin(path: Path) -> dict:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": path.stat().st_size, "sha256": digest}


def assemble() -> dict:
    from types import SimpleNamespace
    from bridge.information.catalog import coverage_report
    from bridge.information.sources import DiplomacySource
    from bridge.information.composite import CompositeSource
    from bridge.information.country_state import NativeCountryStateSource
    from bridge.information.domestic_pressure import NativeDomesticPressureSource
    from bridge.information.subject_relations import NativeSubjectRelationSource
    from bridge.information.static_data import StaticTradeSource
    from bridge.information.missions import MissionInformationSource
    # Project the same optional adapter catalogs as the configured service.
    # This constructs metadata only: no context/read, static parsing, native
    # session, SQLite service, or game process is opened. The bare core catalog
    # deliberately has fewer available fields than the composed capability.
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
    assert dict(fields) == {"available": 54, "partial": 107, "planned": 236}, fields
    assert all(topic["status"] == "planned" for topic in catalog["topics"]
               if topic["topic_id"] in {"B01", "B02", "B03", "B04"})

    audit = read(STAGE / "source-audit-001.json")
    assert audit["status"] == "passed_with_declared_boundaries"
    manager = read(STAGE / "manager-test-001/report-008.json")
    assert manager["status"] == "passed" and manager["run"]["returncode"] == 0
    native_checks = [line for line in manager["run"]["stdout"].splitlines()
                     if line.startswith("CHECK ")]
    assert len(native_checks) == 68 and all(line.endswith(" PASS") for line in native_checks)
    assert manager["run"]["result"]["startup_hash_guard_rejected"] is True
    assert manager["run"]["result"]["game_access"] is False
    comparison = read(STAGE / "regression-comparison-002.json")
    assert comparison["current_occurrences"] == 142
    assert comparison["current_unique_nodes"] == 129
    assert comparison["new_failures"] == comparison["resolved_failures"] == []
    assert comparison["full_suite_green"] is False
    previous = read(STAGE / "previous-component-comparison-001.json")
    assert previous["count"] == 127 and previous["mismatches"] == []

    manifest = read(BUILD / "build-manifest.json")
    assert manifest["version"] == 23 and len(manifest["sources"]) == 103
    assert manifest["information_battle_research_lifecycle"] is True
    assert manifest["runtime_verified"] is False
    dll = BUILD / "eu4_bridge_diplomacy_observer_v23.dll"
    assert pin(dll)["sha256"] == manifest["dll_sha256"]
    for item in manifest["sources"]:
        for path in (ROOT / "work/native" / item["name"], BUILD / item["name"]):
            assert pin(path)["sha256"] == item["sha256"], path
    for name, expected in manager["source_pins"].items():
        assert pin(ROOT / name)["sha256"] == expected["sha256"], name

    documents = [ROOT / p for p in (
        "HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md",
        "docs/信息导出开发进展.md", "docs/逐场战报观察器生命周期.md")]
    for document in documents:
        for link in re.findall(r"\]\(([^)]+)\)", document.read_text(encoding="utf-8-sig")):
            if "://" in link or link.startswith("#"):
                continue
            # Historical sections may contain superseded links. Verify this
            # batch's new document, whose links form the current navigation.
            if document.name == "逐场战报观察器生命周期.md":
                target = document.parent / link.split("#", 1)[0]
                if target.resolve() != OUTPUT.resolve():
                    assert target.exists(), target

    paths = {path for path in STAGE.rglob("*") if path.is_file() and path != OUTPUT}
    paths.update(path for path in BUILD.iterdir() if path.is_file())
    paths.update(documents)
    paths.add(Path(__file__).resolve())
    for item in manifest["sources"]:
        paths.add(ROOT / "work/native" / item["name"])
    for name in (
        "work/preflight_information_battle_observer.py",
        "work/survey_information_battle_observer_integration.py",
        "work/test_information_battle_owned_summary.py",
        "work/native/test-information-battle-owned-summary.cpp",
        "work/information_battle_observation_wire.py",
        "work/test_information_battle_observation_wire.py",
        "work/native/test-information-battle-observation-wire.cpp",
        "work/test_information_battle_observer.py",
        "work/native/test-information-battle-observer.cpp",
        "work/review_information_battle_observer.py",
        "work/audit_information_battle_observer_sources.py",
        "tools/start_diplomacy_observer.py",
        "tools/control_information_battle_observer.py",
        "bridge/tests/test_start_diplomacy_observer.py",
        "bridge/tests/test_control_information_battle_observer.py",
        "work/native/build-diplomacy-observer.ps1",
    ):
        paths.add(ROOT / name)
    pins = {path.relative_to(ROOT).as_posix(): pin(path)
            for path in sorted(paths, key=lambda path: str(path).lower())}
    return {
        "schema": "INFORMATION-BATTLE-OBSERVER-DEVELOPMENT/1",
        "status": "implemented_and_synthetic_verified_runtime_unresolved",
        "goal_complete": False,
        "goal_scope": {"topics": 74, "fields": 397, "stages": [2, 3, 4],
                       "coverage": dict(fields), "B01_B04": "planned",
                       "coverage_basis": "current composed adapter metadata for fixed1374 FRA; no live query",
                       "partly_callable_topics": len(catalog["available_topics"])},
        "progress": "v23 source lifecycle, capture staging, raw wire, multipart log and bound control",
        "final_build": {"path": BUILD.relative_to(ROOT).as_posix(), "version": 23,
                        "sources": 103, "dll_sha256": manifest["dll_sha256"]},
        "validation": {"manager_checks": 68, "summary_checks": 24, "wire_checks": 21,
                       "final_python_targeted": "33 passed, 11 subtests passed",
                       "full_python": comparison["summary"], "full_suite_green": False,
                       "new_failures": 0, "resolved_failures": 0, "previous_pins_matched": 127},
        "scope": {"v23_installed_in_game": False, "game_function_calls": False,
                  "business_dispatch": False, "game_restarted": False,
                  "game_date_advanced": False, "new_natural_battles": False,
                  "owned_fixture_code_and_data_writes": True,
                  "game_access": "only fresh read-only preflight of existing v22",
                  "successful_production_identity_path_verified": False,
                  "event_subscriptions_connected": False,
                  "business_battle_payload_complete": False},
        "remaining": ["same-address same-date reload lifecycle", "natural thread/reentrancy/object validity",
                      "observer visibility", "kind/roles/final quantities/units/full displayed text",
                      "stable public war/battle identities", "event persistence and LLM subscriptions",
                      "real land/naval field acceptance", "remaining stage2 topics and stage4 acceptance"],
        "evidence_boundaries": ["manager private initialization follows required fixture identity rejection",
                                "resume in manager fixture is private restoration; command enable success unverified",
                                "old review003 is historical before terminal-latch fix; final008 pins current source",
                                "build002 had concurrent edits and is not final provenance",
                                "full suite collection precedes latest controller cases; targeted final covers them"],
        "root_shell_terminals": {"27941": 1, "99106": 0, "10593": 0, "7377": 0,
                                 "27129": 0, "66242": 1},
        "pin_count": len(pins), "pinned_bytes": sum(value["bytes"] for value in pins.values()),
        "pins": pins,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    result = assemble()
    if args.verify_existing:
        assert read(OUTPUT) == result, "current state differs from frozen summary"
    else:
        with OUTPUT.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps({key: result[key] for key in ("status", "goal_complete", "pin_count", "pinned_bytes")}))


if __name__ == "__main__":
    main()
