"""Freeze limited custom-text derivation and separately typed evidence."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
STAGE = ROOT / "work/runtime/information-dynamic-text-20261024-001"
PREVIOUS = ROOT / "work/runtime/information-localization-20261024-001/delivery/manifest.json"
PREVIOUS_SHA = "44719eb3df331d7032b8c60cc09a397e42dd1cde969dd5db514b43893f6e49ed"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_BYTES = 64 * 1024
CUSTOM_PROFILE_REL = "bridge/information/profiles/custom-localization-memory-1374.json"
CONTRACT2_REL = "work/runtime/information-dynamic-text-20261024-001/dynamic-localization-contract-002.json"
CONTRACT2_SHA = "ea13b783902b9a5410aa808ae7956e03732fe57376383cd0d4ea094ac9f1a5f7"
INSTALLATION = ROOT / "work/runtime/diplomacy-observer-20261024-information-a/installation.json"


def bounded_file(path, *, max_bytes=MAX_ARCHIVE_BYTES):
    """Resolve and validate a regular workspace file before any read."""
    candidate = Path(path)
    try:
        resolved = candidate.resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"Cannot resolve path: {candidate}") from exc
    if not resolved.is_relative_to(ROOT_RESOLVED):
        raise ValueError(f"Path is outside workspace: {candidate}")
    if not resolved.is_file():
        raise ValueError(f"Expected regular file: {candidate}")
    size = resolved.stat().st_size
    if size > max_bytes:
        raise ValueError(f"File exceeds archival budget: {resolved}")
    return resolved


def digest(path):
    path = bounded_file(path)
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def read(path):
    path = bounded_file(path)
    return json.loads(path.read_text(encoding="utf-8"))


def read_profile(path):
    path = bounded_file(path, max_bytes=MAX_PROFILE_BYTES)
    return json.loads(path.read_text(encoding="utf-8"))


def require_mapping(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def require_equal(mapping, key, expected, label):
    if mapping.get(key) != expected:
        raise ValueError(f"{label}.{key} does not match expected value")


def require_true(mapping, key, label):
    if mapping.get(key) is not True:
        raise ValueError(f"{label}.{key} must be true")


def check_contract2(profile_path, profile):
    relative = profile_path.relative_to(ROOT_RESOLVED).as_posix()
    if relative != CUSTOM_PROFILE_REL:
        return False
    require_equal(profile, "contract_sha256", CONTRACT2_SHA, "custom profile")
    evidence = require_mapping(profile.get("source_evidence"), "custom profile source_evidence")
    contract = require_mapping(evidence.get("dynamic_localization_contract"), "dynamic contract reference")
    require_equal(contract, "path", CONTRACT2_REL, "dynamic contract reference")
    require_equal(contract, "sha256", CONTRACT2_SHA, "dynamic contract reference")
    return True


def validate_capture(capture, installation, profile_path, profile):
    """Validate the observed capture's identity and read-only boundaries."""
    identity = require_mapping(capture.get("identity"), "capture identity")
    target = require_mapping(capture.get("target_build"), "capture target_build")
    access = require_mapping(capture.get("access"), "capture access")
    query_scope = require_mapping(capture.get("query_scope"), "capture query_scope")
    cleanup = require_mapping(capture.get("cleanup"), "capture cleanup")
    doublepass = require_mapping(capture.get("doublepass"), "capture doublepass")
    profile_record = require_mapping(capture.get("profile"), "capture profile")
    expected_installation = bounded_file(INSTALLATION)
    reported_installation = identity.get("installation_path")
    if not isinstance(reported_installation, str):
        raise ValueError("Capture installation path is missing")
    if bounded_file(reported_installation) != expected_installation:
        raise ValueError("Capture installation path does not match the recorded installation")
    installation = require_mapping(installation, "installation manifest")
    required_installation = ("pid", "creation_filetime", "game_sha256", "session_id")
    if any(field not in installation for field in required_installation):
        raise ValueError("Installation manifest is missing an identity field")
    for field in ("pid", "creation_filetime", "session_id"):
        require_equal(identity, f"installation_{field}", installation.get(field), "capture identity")
    require_equal(identity, "process_creation_filetime", installation.get("creation_filetime"), "capture identity")
    process_path = identity.get("process_path")
    module_path = identity.get("module_path")
    if not isinstance(process_path, str) or not process_path or module_path != process_path:
        raise ValueError("Capture process/module paths are not the same recorded executable")
    if not isinstance(identity.get("process_creation_utc"), str) or not identity["process_creation_utc"]:
        raise ValueError("Capture process creation timestamp is missing")
    require_true(identity, "process_creation_matches_installation", "capture identity")
    require_true(identity, "process_path_sha256_matches_expected", "capture identity")
    require_true(identity, "module_path_matches_process", "capture identity")
    require_true(identity, "binding_verified", "capture identity")
    expected_exe = str(profile["executable"]["sha256"]).lower()
    require_equal(target, "version", profile.get("game_version"), "capture target_build")
    require_equal(target, "expected_exe_sha256", expected_exe, "capture target_build")
    globals_ = require_mapping(profile.get("globals"), "custom profile globals")
    for field in ("database_rva", "game_rva", "custom_global_rva"):
        require_equal(target, field, globals_.get(field), "capture target_build")
    require_equal(identity, "process_path_sha256", expected_exe, "capture identity")
    require_equal(installation, "game_sha256", expected_exe, "installation manifest")
    if Path(str(profile_record.get("path", ""))).resolve() != profile_path:
        raise ValueError("Capture profile path does not match the archived profile")
    require_equal(profile_record, "sha256", digest(profile_path), "capture profile")
    if query_scope.get("ui_root_scope_verified") is not False or query_scope.get("country") != "FRA":
        raise ValueError("Capture query scope is not the explicit FRA observer scope")
    handle_close = require_mapping(cleanup.get("handle_close"), "capture cleanup.handle_close")
    require_true(handle_close, "closed", "capture cleanup.handle_close")
    require_true(doublepass, "performed", "capture doublepass")
    require_true(doublepass, "consistent", "capture doublepass")
    if doublepass.get("mismatches") != []:
        raise ValueError("Capture doublepass contains mismatches")
    limits = require_mapping(profile.get("limits"), "custom profile limits")
    require_equal(access, "open_process_mask", "QUERY_INFORMATION|VM_READ", "capture access")
    require_equal(access, "open_process_mask_hex", "0x410", "capture access")
    require_equal(access, "rpm_total_limit", limits.get("max_total_rpm"), "capture access")
    require_equal(access, "rpm_single_read_limit", limits.get("max_single_rpm"), "capture access")
    if not isinstance(access.get("rpm_bytes_requested"), int) or access["rpm_bytes_requested"] < 0 or access["rpm_bytes_requested"] > limits.get("max_total_rpm"):
        raise ValueError("Capture RPM byte count exceeds its profile budget")
    if not isinstance(access.get("rpm_calls"), int) or access["rpm_calls"] < 0:
        raise ValueError("Capture RPM call count is invalid")
    for field in ("native_game_calls", "target_memory_writes", "dll_injection", "private_heap_scan", "ui_control", "date_advance", "save_or_reload"):
        if access.get(field) is not False:
            raise ValueError(f"Capture access.{field} is not false")
    reference = require_mapping(capture.get("static_contract_reference"), "capture static_contract_reference")
    if reference.get("native_functions_invoked") is not False:
        raise ValueError("Capture static contract permits native function invocation")
    if capture.get("errors") != [] or capture.get("evidence_kind") != "pure_runtime_observation_not_static_evidence":
        raise ValueError("Capture contains errors or has the wrong evidence type")
    require_true(capture, "completed", "capture")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    live = STAGE / "live-acceptance-003"
    acceptance = read(live / "report.json")
    capture = read(live / "custom-methods.json")
    tests = read(STAGE / "test-summary.json")
    coverage = read(STAGE / "coverage.json")
    installation = read(INSTALLATION)
    custom_profile_path = bounded_file(ROOT / CUSTOM_PROFILE_REL, max_bytes=MAX_PROFILE_BYTES)
    custom_profile = read_profile(custom_profile_path)
    if (acceptance["status"] != "passed" or not all(require_mapping(acceptance.get("checks"), "acceptance checks").values())
            or acceptance["derived_count"] != 14 or acceptance["known_count"] != 116
            or acceptance["unresolved_count"] != 6 or acceptance["periodic_results"] < 2
            or acceptance["custom_capture_sha256"] != digest(live / "custom-methods.json")
            or acceptance["native_cache_sha256"] != digest(live / "native-cache.json")):
        raise ValueError("Real MCP acceptance is incomplete")
    if (capture["status"] != "observed" or capture["read_only"] is not True
            or not capture["doublepass"]["consistent"]
            or not capture["cleanup"]["handle_close"]["closed"]
            or capture["query_scope"]["ui_root_scope_verified"] is not False):
        raise ValueError("Native method capture lacks its guarded query scope")
    if not check_contract2(custom_profile_path, custom_profile):
        raise ValueError("custom localization profile is missing contract2")
    validate_capture(capture, installation, custom_profile_path, custom_profile)
    for key in ("static_contract_guard", "file_code_guard", "runtime_code_guard"):
        if capture[key]["status"] != "observed":
            raise ValueError(f"Native guard failed: {key}")
    if (digest(ROOT / "bridge/information/custom_localization_memory.py") != capture["probe_script_sha256"]
            or digest(ROOT / "bridge/information/profiles/custom-localization-memory-1374.json") != capture["profile"]["sha256"]):
        raise ValueError("Captured native reader changed after acceptance")
    if (tests["information"]["case_element_statuses"]["failure"] != 0
            or tests["information"]["case_element_statuses"]["error"] != 0):
        raise ValueError("Information regression is not clean")
    previous_file = bounded_file(PREVIOUS)
    if digest(previous_file) != PREVIOUS_SHA:
        raise ValueError("Previous immutable archive changed")

    paths = set((ROOT / "bridge/information").glob("*.py"))
    profiles = list((ROOT / "bridge/information/profiles").glob("*.json"))
    paths.update(profiles)
    paths.add(previous_file)
    references = []
    contract2_seen = False
    for profile in profiles:
        profile = bounded_file(profile, max_bytes=MAX_PROFILE_BYTES)
        profile_data = read_profile(profile)
        contract2_seen = check_contract2(profile, profile_data) or contract2_seen
        for name, record in require_mapping(profile_data.get("source_evidence"), f"{profile.name} source_evidence").items():
            if isinstance(record, str):
                source = ROOT / "work/runtime/information-missions-20261024-001" / name
                expected = record
            else:
                source, expected = ROOT / record["path"], record["sha256"]
            source = bounded_file(source)
            if digest(source) != expected:
                raise ValueError(f"Profile reference changed: {profile.name}/{name}")
            paths.add(source)
            references.append({"profile": profile.relative_to(ROOT).as_posix(), "name": name,
                               "path": source.relative_to(ROOT).as_posix(), "sha256": expected})
    if not contract2_seen:
        raise ValueError("custom localization profile contract2 reference was not found")
    paths.update((ROOT / "bridge/tests").glob("test_information*.py"))
    paths.update((ROOT / "bridge/tests/fixtures").glob("information_*.json"))
    paths.update(ROOT / name for name in (
        "HANDOFF.md", "README(agent).md", "tools/serve_information.py",
        "docs/信息导出与订阅开发计划.md", "docs/信息导出开发进展.md", "docs/信息字段覆盖.json",
        "docs/信息接口使用说明.md", "docs/信息服务合同.md", "docs/任务信息接口.md",
        "docs/任务原生读取合同.md", "docs/任务实际子任务接口.md", "docs/任务本地化来源.md",
        "docs/任务本地化接口.md", "docs/任务动态本地化研究.md",
        "work/validate_information_live.py", "work/validate_information_custom_texts.py", "work/verify_information_custom_texts.py",
        "work/audit_information_custom_text_tests.py",
        "work/probe_information_common_promotions.py", "work/probe_information_country_builtin_text.py",
        "work/probe_information_country_builtin_text_complete.py", "work/probe_information_custom_localization.py",
        "work/probe_information_custom_localization_weights.py", "work/research_information_custom_localization.py",
        "work/research_information_custom_localization_root.py", "work/finalize_information_custom_texts.py",
        "work/runtime/diplomacy-observer-20261024-information-a/installation.json"))
    paths.update(path for path in STAGE.rglob("*") if path.is_file()
                 and path.suffix in {".json", ".xml", ".log", ".txt", ".py", ".md"}
                 and "delivery" not in path.relative_to(STAGE).parts)
    output = args.output.resolve()
    if not output.is_relative_to(STAGE.resolve()) or output.exists():
        raise ValueError("Archive must be a new directory inside this batch")
    paths = {bounded_file(path) for path in paths}
    output.mkdir(parents=True, exist_ok=False)
    entries = []
    for path in sorted(paths, key=str):
        relative = path.relative_to(ROOT_RESOLVED)
        destination = output / "files" / relative
        expected = digest(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        if digest(destination) != expected or digest(path) != expected:
            raise ValueError(f"Source changed during snapshot: {path}")
        entries.append({"path": relative.as_posix(), "bytes": path.stat().st_size, "sha256": expected})
    result = {"format": "information_custom_text_delivery_v1", "status": "source_and_evidence_snapshot_verified",
        "goal_complete": False, "file_count": len(entries), "files": entries,
        "tests": tests, "acceptance": acceptance, "profile_reference_checks": references,
        "previous_manifest": {"path": PREVIOUS.relative_to(ROOT).as_posix(), "sha256": PREVIOUS_SHA},
        "configured_coverage": {"topics": coverage["topic_count"], "fields": coverage["field_count"],
            "partly_routable_topics": len(coverage["available_topics"]),
            "field_counts": dict(Counter(f["coverage"] for t in coverage["topics"] for f in t["fields"].values())),
            "registration_is_not_full_live_acceptance": True},
        "evidence_types_separated": ["REA static", "ordinary bounded static", "runtime RPM",
                                     "conditional query-root derivation", "static files", "recorded fixture tests"],
        "scope": {"country": "FRA", "root_binding": "explicit_query_observer_country",
                  "ui_root_scope_verified": False, "native_function_invoked": False,
                  "single_supported_placeholder_with_literal_surroundings": True},
        "remaining": ["six other state-dependent localization entries", "actual UI Root and displayed branches",
                      "complete trigger evaluation and progress", "remaining country/relation/trade/modifier fields",
                      "positive live changes and new event capture", "complete per-battle contents",
                      "all target fields in 74-topic plan"]}
    (output / "manifest.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: result[key] for key in ("format", "status", "goal_complete", "file_count", "configured_coverage")}))


if __name__ == "__main__":
    main()
