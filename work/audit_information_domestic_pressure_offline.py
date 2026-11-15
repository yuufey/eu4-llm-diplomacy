"""Audit N04 offline development while explicitly withholding live acceptance."""
from __future__ import annotations

import json
from pathlib import Path
import py_compile
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.verify_information_domestic_pressure import (
    validate_static_profiles, build_catalog, bounded_file, digest, read_json,
)
from bridge.information.domestic_pressure_memory import _static_contract_guard

STAGE = ROOT / "work/runtime/information-domestic-pressure-20261025-001"


def record(path: Path):
    source = bounded_file(path)
    return {"path": source.relative_to(ROOT).as_posix(), "bytes": source.stat().st_size,
            "sha256": digest(source)}


def write_new(path: Path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    profile_groups = validate_static_profiles()
    guard = _static_contract_guard()
    if guard["status"] != "observed" or guard["unknown_conditions"]:
        raise ValueError("native_reader_static_contract_not_observed")
    tests = read_json(STAGE / "test-summary.json")
    for info in (tests["information"], tests["targeted_domestic_pressure_checkpoint"]):
        statuses = info["case_element_statuses"]
        if statuses["passed"] != 545 or any(statuses[key] for key in ("failure", "error", "skipped")):
            raise ValueError("offline_information_tests_not_clean")
    for item in tests["source_files"].values():
        if digest(ROOT / item["path"]) != item["sha256"]:
            raise ValueError(f"production_source_changed_after_tests:{item['path']}")
    process = read_json(STAGE / "live-preflight-unavailable-001.json")
    if process["status"] != "runtime_unavailable" or process["processes"]:
        raise ValueError("preflight_unavailable_evidence_changed")
    catalog = build_catalog()
    sources = set((ROOT / "bridge/information").glob("*.py"))
    sources.update((ROOT / "bridge/tests").glob("test_information*.py"))
    sources.update((ROOT / "work").glob("*domestic_pressure*.py"))
    sources.update((ROOT / "work").glob("*religious_unity*.py"))
    sources.add(ROOT / "tools/serve_information.py")
    compiled = []
    with tempfile.TemporaryDirectory(prefix="n04-offline-compile-") as temp:
        for index, path in enumerate(sorted(sources)):
            py_compile.compile(str(path), cfile=str(Path(temp) / f"{index}.pyc"), doraise=True)
            compiled.append(record(path))
    preserved = []
    for path, expected in (
        ("work/runtime/information-country-scalars-20261024-001/delivery/manifest.json", "01bf780b08d13dab03c5c3de166fa9eb06114063ef5ac895face01a32e5e78b1"),
        ("work/runtime/information-country-relations-20261024-001/delivery/manifest.json", "b24cf0c61c56a95e36621d764080a4f9c22025649970c9cfdfafe96927e2e6f7"),
        ("work/runtime/information-dynamic-text-20261024-001/delivery/manifest.json", "c2feea2e334fb1796541956d440c55237451cf32d49d486b34c7ce06b8b6aafe"),
    ):
        item = record(ROOT / path)
        if item["sha256"] != expected:
            raise ValueError(f"sealed_manifest_changed:{path}")
        preserved.append(item)
    report = {
        "schema": "information_domestic_pressure_offline_source_audit_v1",
        "status": "offline_checks_passed_live_pending", "goal_complete": False,
        "native_capture_available": False, "live_mcp_accepted": False,
        "delivery_created": False,
        "profiles": profile_groups, "profile_count": len(profile_groups),
        "profile_reference_occurrences": sum(len(group["references"]) for group in profile_groups),
        "native_reader_static_contract": guard,
        "compiled_sources": compiled, "compiled_source_count": len(compiled),
        "catalog_counts": {key: catalog[key] for key in ("topic_count", "field_count", "available_topic_count", "field_counts")},
        "tests": record(STAGE / "test-summary.json"),
        "http_recheck": record(STAGE / "http-focused-recheck-audit-001.json"),
        "preflight_unavailable": record(STAGE / "live-preflight-unavailable-001.json"),
        "failed_preflight": record(STAGE / "independent-native-001/report.json"),
        "preserved_manifests": preserved,
        "limitations": [
            "Fake-kernel tests and static files do not replace a fresh game-process capture or live MCP acceptance.",
            "N04 coverage stays partial and runtime_validation pending until that evidence is obtained.",
            "The full suite remains failed:108 failures/35 errors, including one additional HTTP connection-aborted node; isolated recheck passed without a fix.",
            "The exited process/session must not be made current by changing its PID or reusing its creation binding.",
        ],
    }
    write_new(STAGE / "coverage-pending-001.json", catalog)
    write_new(STAGE / "offline-source-audit-001.json", report)
    print(json.dumps({key: report[key] for key in ("status", "profile_count", "profile_reference_occurrences", "compiled_source_count", "catalog_counts")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
