"""Freeze the recorded M04 development batch after final offline checks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-mission-rewards-20261025-001"
UNITY = ROOT / "work/runtime/information-religious-unity-20261025-001"
MAX_JSON = 16 * 1024 * 1024
MAX_ARCHIVE = 180 * 1024 * 1024


def read(path):
    if path.stat().st_size > MAX_JSON:
        raise ValueError(f"JSON exceeds bounded read budget: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def record(path):
    path = path.resolve(strict=True)
    if not path.is_relative_to(ROOT.resolve()) or not path.is_file():
        raise ValueError(f"not a workspace file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": path.relative_to(ROOT.resolve()).as_posix(),
            "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def check_pin(item):
    actual = record(ROOT / item["path"])
    if actual["sha256"] != item["sha256"] or actual["bytes"] != item["bytes"]:
        raise ValueError(f"current source differs from final proof: {item['path']}")


def write_new(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    delivery = STAGE / "delivery"
    if delivery.exists():
        raise FileExistsError("delivery already exists; never overwrite an archive")
    audit = read(STAGE / "offline-source-audit-002.json")
    tests = read(STAGE / "test-summary-002.json")
    acceptance = read(STAGE / "recorded-mcp-003/report.json")
    fixture_path = ROOT / "bridge/tests/fixtures/information_mission_reward_rules_recorded_1374.json"
    fixture = read(fixture_path)
    if audit.get("goal_complete") is not False or audit.get("profile_count") != 7:
        raise ValueError("final seven-profile audit missing")
    if audit.get("profile_reference_occurrences") != 80:
        raise ValueError("profile dependency set changed")
    if audit["coverage"]["field_counts"] != {"available": 51, "partial": 110, "planned": 236}:
        raise ValueError("coverage changed")
    if tests["information"]["case_element_statuses"]["failure"] or tests["information"]["case_element_statuses"]["error"]:
        raise ValueError("information tests failed")
    if tests.get("full_suite_passed") is not False:
        raise ValueError("review changed full-suite result before freezing")
    comparison = tests["stable_baseline_comparison"]
    if comparison["persistent_nodes"] != 142 or comparison["message_changed_nodes"]:
        raise ValueError("old failure/error baseline changed")
    allowed_http = {
        "bridge.tests.test_diplomacy_observer_service.ObserverHTTPTests::test_malformed_request_ids_are_refused_before_observation [failure]",
        "bridge.tests.test_diplomacy_observer_service.ObserverHTTPTests::test_unauthenticated_write_methods_are_refused_without_observation [failure]",
    }
    if any(item["id"] not in allowed_http for item in comparison["added_nodes"]):
        raise ValueError("unreviewed additional full-suite failure")
    if acceptance.get("status") != "passed" or acceptance.get("mode") != "recorded" or acceptance.get("native_query_invoked") is not False:
        raise ValueError("authentic recorded MCP acceptance required")
    if (fixture.get("mode") != "recorded" or fixture.get("live_state") is not False
            or fixture.get("native_query_invoked") is not False):
        raise ValueError("fixture must explicitly be recorded")
    source = fixture["source"]
    for path_key, hash_key in (
        ("recorded_mcp_report_path", "recorded_mcp_report_sha256"),
        ("fixture_inputs_path", "fixture_inputs_sha256"),
        ("independent_ast_expected_path", "independent_ast_expected_sha256"),
    ):
        if record(ROOT / source[path_key])["sha256"] != source[hash_key]:
            raise ValueError("fixture provenance differs from authentic evidence")
    if source["recorded_mcp_report_path"] != (STAGE / "recorded-mcp-003/report.json").relative_to(ROOT).as_posix():
        raise ValueError("fixture must use the final MCP acceptance")
    if source["helper_module_sha256"] != record(ROOT / "bridge/information/mission_reward_rules.py")["sha256"]:
        raise ValueError("fixture helper pin is stale")
    pins = list(audit["compiled_sources"]) + list(tests["source_files"])
    pins += acceptance["fingerprints"]["source_files"]
    for group in audit["profiles"]:
        pins += [group] + group["references"]
    pins += audit["preserved_manifests"]
    for item in pins:
        check_pin(item)

    paths = {ROOT / item["path"] for item in pins if "delivery/manifest.json" not in item["path"]}
    paths.add(fixture_path)
    paths.update((ROOT / "bridge/information").glob("*.py"))
    paths.update((ROOT / "bridge/information/profiles").glob("*.json"))
    paths.update((ROOT / "bridge/tests").glob("test_information_mission_reward_rules*.py"))
    for name in (
        "HANDOFF.md", "README(agent).md", "work/AGENTS.md",
        "work/archive_information_mission_reward_rules_recorded.py",
        "work/audit_information_mission_rewards_tests.py",
        "work/audit_information_country_powers_tests.py",
        "work/audit_information_mission_reward_rules_offline.py",
        "work/validate_information_mission_reward_rules_recorded.py",
        "work/freeze_information_religious_unity_research.py",
        "work/verify_information_unity_ui_constant.py",
        "work/finalize_information_mission_reward_rules.py",
        "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md",
        "docs/信息接口使用说明.md", "docs/信息字段覆盖.json",
        "docs/任务信息接口.md", "docs/任务奖励规则接口.md",
        "docs/国内压力原生来源.md", "docs/宗教统一计算路径.md",
    ):
        paths.add(ROOT / name)
    for prefix in ("information-pytest-002", "full-pytest-002", "http-recheck-001"):
        paths.update(STAGE.glob(prefix + ".*"))
    for name in ("test-summary-002.json", "offline-source-audit-002.json", "coverage-002.json"):
        paths.add(STAGE / name)
    # Exact current acceptance files only. SQLite and previous batches are not traversed.
    paths.update((STAGE / "recorded-mcp-003").glob("*.json"))
    paths.add(STAGE / "recorded-mcp-003/mcp-stderr.txt")
    research = read(UNITY / "effective-unity-paths-001.json")
    for source in research["source_records"]:
        path = ROOT / source["evidence_path"]
        if record(path)["sha256"] != source["evidence_sha256"]:
            raise ValueError("unity evidence changed")
        paths.add(path)
    for name in ("effective-unity-paths-001.json", "caller-candidates-001.json",
                 "ui-percent-suffix-001.json", "ui-float-constant-001.json"):
        paths.add(UNITY / name)
    records = [record(path) for path in sorted(paths)]
    if sum(item["bytes"] for item in records) > MAX_ARCHIVE:
        raise ValueError("bounded archive budget exceeded")
    summary = {
        "schema": "information_mission_reward_rules_development_summary_v1",
        "status": "recorded_rule_inventory_accepted",
        "goal_complete": False, "complete_M04": False,
        "live_acceptance": False, "n04_live_acceptance_pending": True,
        "religious_unity_coverage": "planned",
        "coverage": audit["coverage"],
        "literal_rule_counts": {name: value["actual_count"] for name, value in
            acceptance["checks"]["full_root_effect_occurrences"]["field_checks"].items()},
        "information_tests": tests["information"]["reported_result"],
        "full_tests": tests["full"]["reported_result"],
        "stable_baseline_persistent_nodes": comparison["persistent_nodes"],
        "additional_full_failures": comparison["added_nodes"],
        "fixture": record(fixture_path),
        "recorded_acceptance": record(STAGE / "recorded-mcp-003/report.json"),
        "test_summary": record(STAGE / "test-summary-002.json"),
        "source_audit": record(STAGE / "offline-source-audit-002.json"),
        "evidence_boundaries": [
            "M04 is current-definition literal rule inventory linked to recorded save roots; conditions, target scope and actual rewards remain unknown.",
            "Unity paths are static REA/file-byte research. No unity field was enabled and no game function was invoked.",
            "No game process, native capture, live subscription or new business action is evidenced by this batch.",
        ],
    }
    write_new(STAGE / "development-summary-001.json", summary)
    records.append(record(STAGE / "development-summary-001.json"))
    delivery.mkdir()
    for item in records:
        source = ROOT / item["path"]
        target = delivery / "workspace" / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    manifest = {"schema": "information_mission_reward_rules_archive_v1",
                "mode": "recorded", "goal_complete": False,
                "file_count": len(records), "total_bytes": sum(item["bytes"] for item in records),
                "files": records, "preserved_prior_manifests": audit["preserved_manifests"]}
    write_new(delivery / "manifest.json", manifest)
    for item in records:
        target = delivery / "workspace" / item["path"]
        actual = record(target)
        if actual["bytes"] != item["bytes"] or actual["sha256"] != item["sha256"]:
            raise ValueError(f"archive copy mismatch: {item['path']}")
    verified = {"status": "passed", "file_count": len(records),
                "total_bytes": manifest["total_bytes"], "manifest": record(delivery / "manifest.json")}
    write_new(STAGE / "archive-verification.json", verified)
    print(json.dumps(verified, ensure_ascii=False))


if __name__ == "__main__":
    main()
