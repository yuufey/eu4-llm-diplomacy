"""Audit and freeze the offline v24 context-manager integration evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.finalize_information_battle_live import coverage

STAGE = ROOT / "work/runtime/information-battle-context-observer-20261025-001"
BUILD = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-v24-001"
OLD_BUILD = ROOT / "work/runtime/diplomacy-observer-20261025-information-battle-live-001"
AUDIT = STAGE / "source-audit-001.json"
SUMMARY = STAGE / "development-summary-001.json"
DOCS = {"HANDOFF.md", "README(agent).md", "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md"}
INTENTIONAL = DOCS | {"work/native/information-battle-observer.inc",
    "work/ingest_information_battle_raw_live.py", "work/test_ingest_information_battle_raw_live.py"}
CURRENT = (
    "work/native/information-battle-observer.inc", "work/native/build-diplomacy-observer.ps1",
    "tools/start_diplomacy_observer.py", "tools/control_information_battle_observer.py",
    "work/native/test-information-battle-observer-context.cpp", "work/test_information_battle_observer_context.py",
    "work/ingest_information_battle_raw_live.py", "work/test_ingest_information_battle_raw_live.py",
    "bridge/tests/test_information_battle_context_install.py",
    "work/verify_information_battle_context_v23_compat.py", "work/verify_information_battle_context_manager_log.py",
    "work/survey_information_battle_context_checkpoint.py", "work/finalize_information_battle_context_observer.py",
    "docs/逐场战报上下文观察器接入.md",
)


def pin(path: Path) -> dict:
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"bytes": path.stat().st_size, "sha256": sha}


def read(path: Path) -> dict:
    assert path.stat().st_size <= 2 * 1024 * 1024, path
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def verify_source_pins(value: object) -> int:
    count = 0
    if isinstance(value, dict):
        if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
            path = Path(value["path"])
            path = path if path.is_absolute() else ROOT / path
            assert pin(path)["sha256"] == value["sha256"], path
            count += 1
        for child in value.values():
            count += verify_source_pins(child)
    elif isinstance(value, list):
        for child in value:
            count += verify_source_pins(child)
    return count


def baseline(path: Path, expected_count: int, allowed: set[str]) -> dict:
    recorded = read(path)
    assert recorded["pin_count"] == len(recorded["pins"]) == expected_count
    changed = []
    for name, expected in recorded["pins"].items():
        actual = pin(ROOT / name)
        if actual != expected:
            assert name in allowed, name
            changed.append({"path": name, "previous": expected, "current": actual})
    return {"summary": path.relative_to(ROOT).as_posix(), "summary_pin": pin(path),
            "pins": expected_count, "unchanged": expected_count - len(changed),
            "intentional_changes": changed, "unexpected_changes": []}


def source_audit() -> dict:
    manifest = read(BUILD / "build-manifest.json")
    assert manifest["version"] == 24 and manifest["compiled"] is True and manifest["runtime_verified"] is False
    assert manifest["information_battle_context_wire"] == 2 and manifest["information_battle_owned_context"] is True
    from tools.start_diplomacy_observer import _validate_information_battle_manifest
    _validate_information_battle_manifest(manifest, BUILD)
    assert len(manifest["sources"]) == 105
    for row in manifest["sources"]:
        for path in (ROOT / "work/native" / row["name"], BUILD / row["name"]):
            assert pin(path)["sha256"] == row["sha256"], path
    dll = BUILD / "eu4_bridge_diplomacy_observer_v24.dll"
    assert pin(dll)["sha256"] == manifest["dll_sha256"]
    old_manifest = read(OLD_BUILD / "build-manifest.json")
    assert len(old_manifest["sources"]) == 103
    old_root_changed = []
    for row in old_manifest["sources"]:
        assert pin(OLD_BUILD / row["name"])["sha256"] == row["sha256"]
        if pin(ROOT / "work/native" / row["name"])["sha256"] != row["sha256"]:
            old_root_changed.append(row["name"])
    assert old_root_changed == ["information-battle-observer.inc"], old_root_changed
    assert pin(OLD_BUILD / "eu4_bridge_diplomacy_observer_v23.dll")["sha256"] == old_manifest["dll_sha256"]
    service = read(ROOT / "work/runtime/information-battle-business-20261025-001/service-integration-contract-001.json")
    assert len(service["source_pins"]) == 10
    service_changed = []
    for row in service["source_pins"]:
        actual = pin(ROOT / row["path"])
        if actual["sha256"] != row["sha256"]:
            assert row["path"] == "work/ingest_information_battle_raw_live.py", row["path"]
            original = STAGE / "ingest-tests-001/sources-before/ingest_information_battle_raw_live.py"
            assert pin(original)["sha256"] == row["sha256"]
            service_changed.append({"path": row["path"], "previous_sha256": row["sha256"], "current": actual})
    assert len(service_changed) == 1
    return {"schema": "BATTLE-CONTEXT-OBSERVER-SOURCE-AUDIT/1", "status": "passed",
            "batch22": baseline(ROOT / "work/runtime/information-battle-live-20261025-001/development-summary-001.json", 329, INTENTIONAL),
            "batch23": baseline(ROOT / "work/runtime/information-battle-business-20261025-001/development-summary-001.json", 103, DOCS),
            "old_native_copies_matched": 103, "old_root_intentional_changes": old_root_changed,
            "current_native_roots_and_copies_matched": 105, "service_integration_sources_unchanged": 9,
            "service_integration_intentional_changes": service_changed,
            "information_service_production_sources_unchanged": 5,
            "v24_dll": {"path": dll.relative_to(ROOT).as_posix(), **pin(dll)},
            "installed_v23_dll_unchanged": True, "v24_installed": False}


def assemble() -> dict:
    manager = read(STAGE / "manager-test-001/report-007.json")
    legacy = read(STAGE / "legacy-manager-test-001/report.json")
    for report in (manager, legacy):
        assert report["status"] == "passed"
        assert report["compile"]["returncode"] == report["run"]["returncode"] == 0
        verify_source_pins(report["source_pins"])
    stdout_path = STAGE / "manager-test-001/run-007.stdout.log"
    assert pin(stdout_path)["sha256"] == manager["run"]["stdout_sha256"]
    checks = [line for line in stdout_path.read_text(encoding="ascii").splitlines() if line.startswith("CHECK ")]
    assert len(checks) == 91 and all(line.endswith(" PASS") for line in checks)
    assert len(manager["wire_decode"]["checks"]) == 21 and all(manager["wire_decode"]["checks"].values())
    assert manager["log_reassembly"]["complete_groups"] == manager["log_reassembly"]["decoded_v2_groups"] == 15
    ingest = read(STAGE / "ingest-tests-002/report.json")
    assert ingest["status"] == "passed" and ingest["tests"]["case_count"] == 7
    assert ingest["tests"]["failures"] == ingest["tests"]["errors"] == 0
    verify_source_pins(ingest["source_pins"])
    install = read(STAGE / "v24-install-test-001/report.json")
    assert install["verification"]["pytest_exit_code"] == 0 and install["verification"]["pytest_passed"] == 8
    verify_source_pins(install["source_pins"])
    old_control = read(STAGE / "legacy-control-tests-001/report.json")
    assert old_control["returncode"] == 0
    for name, expected in old_control["source_pins"].items():
        assert pin(ROOT / name) == expected, name
    for name, count in (("actual-v23-compatibility-001/report.json", 18), ("manager-log-ingest-001/report.json", 15)):
        report = read(STAGE / name)
        assert report["status"] == "passed" and report["game_access"] is False and report["reopen_new_acks"] == 0
        assert report.get("matched_payloads_and_decoded_values", report.get("decoded_v2_messages")) == count
        for source, expected in report["sources"].items():
            assert pin(ROOT / source) == expected, source
    for target in re.findall(r"\]\(([^)]+)\)", (ROOT / "docs/逐场战报上下文观察器接入.md").read_text(encoding="utf-8")):
        assert (ROOT / "docs" / target).resolve().exists(), target
    write(AUDIT, source_audit())
    paths = {path for parent in (STAGE, BUILD) for path in parent.rglob("*") if path.is_file() and path != SUMMARY}
    paths.update(ROOT / name for name in set(CURRENT) | DOCS)
    pins = {path.relative_to(ROOT).as_posix(): pin(path) for path in sorted(paths)}
    return {"schema": "BATTLE-CONTEXT-OBSERVER-DEVELOPMENT/1", "status": "offline_integration_verified_live_v24_pending",
            "goal_complete": False, "goal_turn_classification": "progress", "coverage": coverage(),
            "v24_compiled": True, "v24_installed": False, "game_access_this_batch": False,
            "save_restart_date_advance_or_business_dispatch": False, "native_checks": 91, "wire_checks": 21,
            "actual_self_fixture_v2_messages_persisted": 15, "archived_actual_v23_payloads_compatible": 18,
            "ingest_tests": 7, "legacy_controller_tests": 33, "legacy_controller_subtests": 11,
            "v24_install_tests": 8, "v24_install_subtests": 4, "full_pytest_run": False,
            "latest_full_suite": {"passed": 2443, "failed": 107, "errors": 35, "green": False},
            "collected_root_shell_sessions": {"96764": 0}, "business_complete": False,
            "remaining": ["fresh artifact-versus-source preflight and new checkpoint before restart",
                "real v24 type/context capture and independent validation", "same-address same-date load generation",
                "natural ABI/reentrancy/lifetime and observer visibility", "stable war/battle identities",
                "final roles/counts/units/full UI text", "actual InformationService battle events and LLM subscription delivery",
                "full original 74-topic 397-field scope and phases 2/3/4"],
            "pin_count": len(pins), "pins": pins}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    if args.verify_existing:
        report = read(SUMMARY)
        for name, expected in report["pins"].items():
            assert pin(ROOT / name) == expected, name
    else:
        report = assemble()
        write(SUMMARY, report)
    print(json.dumps({"status": report["status"], "pins": report["pin_count"], "goal_complete": False}))


if __name__ == "__main__":
    main()
