"""Freeze batch-85 province resource-name sources and compare its sole full run.

This verifier inherits the batch-84 country-wars freeze and v33 build. It
records cached resource literal names; final UI text and full province
visibility remain explicitly unverified.
"""
from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from work import verify_information_country_wars as batch84  # noqa: E402


common = batch84.common
STAGE = ROOT / "work/runtime/information-province-resource-localization-20261029-001"
BASE = ROOT / "work/runtime/information-country-wars-20261029-001"
REVISION = "001"
BASE_BATCH = 84
BASE_COUNT = 821
BASE_BAD_OCCURRENCES = 141
BASELINE_SUMMARY = {"tests": 6503, "failures": 106, "errors": 35, "skipped": 0}
BASELINE_TERMINAL = "106 failed, 4348 passed, 35 errors, 2014 subtests passed"
BASELINE_ALLOWED_DELTAS = {
    "bridge/information/province_state.py": "batch-85 cached resource-name public projection",
    "bridge/information/province_state_capture.py": "batch-85 same-reader resource-name capture",
    "bridge/information/province_detail_memory.py": "batch-85 resource enrichment and nested name consistency",
    "bridge/tests/test_information_province_state.py": "batch-85 resource-name public projection tests",
    "bridge/tests/test_information_province_state_capture.py": "batch-85 trace/identity/subfield integration tests",
    "docs/信息字段覆盖.json": "batch-85 G02 source metadata; field coverage counts unchanged",
}
EXPECTED_PROFILE_PATH = "bridge/information/profiles/province-state-memory-1374-v4.json"
EXPECTED_PROFILE_SHA256 = "64eb0a2817ef8b82c40de13c641b73948d81270e0aebc473993d2cfbddddb3d2"
EXPECTED_CONFIGURED_FIELD_COUNTS = {"available": 62, "partial": 184, "planned": 151}
EXPECTED_LIVE_FIELD_COUNTS = {"available": 56, "partial": 148, "planned": 193}
EXPECTED_LIVE_CALLABLE_TOPICS = 42
NEW_SOURCES = (
    "bridge/information/province_resource_localization_memory.py",
    "bridge/tests/test_information_province_resource_localization_memory.py",
    EXPECTED_PROFILE_PATH,
    "work/create_information_province_resource_name_profile.py",
    "work/verify_information_province_resource_names.py",
    "work/update_information_province_resource_name_coverage.py",
    "work/finalize_information_province_resource_names.py",
    "work/runtime/information-province-resource-localization-20261029-001/probe_resource_names_001.py",
    "work/runtime/information-province-resource-localization-20261029-001/serve_archived_resource_names_001.py",
    "work/runtime/information-province-resource-localization-20261029-001/validate_resource_names_mcp_001.py",
    "work/runtime/information-province-resource-localization-20261029-001/independent_resource_name_audit_001.py",
)
BUILD_MANIFEST = ROOT / (
    "work/runtime/diplomacy-observer-20261028-battle-context-v33-001/build-manifest.json"
)
RESEARCH_PYTHON = common.PYTHON

pin = common.pin
read_json = common.read_json
write_new = common.write_new
copy_stream = common.copy_stream


def _baseline_paths() -> dict[str, Path]:
    return {
        "freeze": BASE / "source-freeze-001.json",
        "full": BASE / "regression-full-001.xml",
        "log": BASE / "regression-full-001.log",
        "comparison": BASE / "regression-comparison-001.json",
        "postverify": BASE / "source-post-run-verification-001.json",
        "reservation": BASE / "full-execution-reservation-001.json",
        "boundary": BASE / "full-execution-boundary-001.json",
    }


def _tail(path: Path, limit: int = 8192) -> str:
    path = common.workspace(path)
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - limit))
        return stream.read(limit).decode("utf-8", errors="replace")


def baseline_inputs() -> tuple[dict, list[dict], dict, dict[str, dict]]:
    """Validate batch-82 snapshots, full-run counter, and inherited build."""
    paths = _baseline_paths()
    frozen = read_json(paths["freeze"])
    if (frozen.get("schema") != "information.country_scale.source_freeze.v1"
            or frozen.get("batch") != BASE_BATCH or frozen.get("status") != "passed"
            or frozen.get("count") != BASE_COUNT
            or frozen.get("count") != len(frozen.get("files", []))):
        raise ValueError("batch84_freeze_schema_or_count_mismatch")

    changes: list[dict] = []
    seen: set[str] = set()
    for row in frozen["files"]:
        source, snapshot = row["source"], row["snapshot"]
        path = source["path"]
        if path in seen:
            raise ValueError(f"batch84_duplicate_source:{path}")
        seen.add(path)
        if pin(snapshot["path"]) != snapshot:
            raise ValueError(f"batch84_snapshot_pin_mismatch:{snapshot['path']}")
        if (source.get("bytes"), source.get("sha256")) != (
                snapshot.get("bytes"), snapshot.get("sha256")):
            raise ValueError(f"batch84_source_snapshot_pair_mismatch:{path}")
        current = pin(path)
        if current != source:
            if path not in BASELINE_ALLOWED_DELTAS:
                raise ValueError(f"unreviewed_batch84_source_change:{path}")
            changes.append({"path": path, "before": source, "after": current,
                            "reason": BASELINE_ALLOWED_DELTAS[path]})

    comparison = read_json(paths["comparison"])
    postverify = read_json(paths["postverify"])
    reservation = read_json(paths["reservation"])
    boundary = read_json(paths["boundary"])
    full_pin, log_pin = pin(paths["full"]), pin(paths["log"])
    if (comparison.get("schema") != "information.country_wars.regression_comparison.v1"
            or comparison.get("status") != "passed_no_new_bad"
            or comparison.get("batch") != BASE_BATCH
            or comparison.get("current") != full_pin or comparison.get("log") != log_pin
            or comparison.get("baseline_bad_occurrences") != BASE_BAD_OCCURRENCES
            or comparison.get("current_bad_occurrences") != BASE_BAD_OCCURRENCES
            or comparison.get("new_bad") != [] or comparison.get("no_new_bad") is not True
            or comparison.get("whole_suite_passed") is not False):
        raise ValueError("batch84_comparison_mismatch")
    if (postverify.get("status") != "passed_no_new_bad"
            or postverify.get("batch") != BASE_BATCH or postverify.get("count") != BASE_COUNT
            or postverify.get("freeze") != pin(paths["freeze"])
            or postverify.get("regression_comparison") != pin(paths["comparison"])
            or postverify.get("current_sources_match_snapshots") is not True
            or postverify.get("no_new_bad") is not True):
        raise ValueError("batch84_postverify_mismatch")
    if reservation.get("runs") != 1 or reservation.get("freeze") != pin(paths["freeze"]):
        raise ValueError("batch84_full_reservation_mismatch")
    argv = reservation.get("argv", [])
    if not ("pytest" in argv and "bridge/tests" in argv and "--junitxml" in argv
            and argv[-1] == str(paths["full"])):
        raise ValueError("batch84_full_argv_mismatch")
    if (boundary.get("returncode") != comparison.get("returncode")
            or boundary.get("xml") != full_pin or boundary.get("log") != log_pin):
        raise ValueError("batch84_full_boundary_mismatch")

    old_bad = common.bad_cases(paths["full"])
    summary = common.junit_summary(paths["full"])
    if (sum(old_bad.values()) != BASE_BAD_OCCURRENCES
            or summary != BASELINE_SUMMARY
            or comparison.get("junit_summary") != summary
            or BASELINE_TERMINAL not in _tail(paths["log"])):
        raise ValueError("batch84_full_baseline_counts_mismatch")

    build = common.manifest_inputs(BUILD_MANIFEST)
    common.validate_build_inheritance(frozen, build)
    if len(build["native"]) != 125 or len(build["copies"]) != 125:
        raise ValueError("inherited_v33_source_count_mismatch")
    pins = {name: pin(path) for name, path in paths.items()}
    return frozen, changes, build, pins


def _profile_inputs() -> dict:
    module = importlib.import_module("bridge.information.province_state_capture")
    profile_path = common.workspace(module.PROFILE_FILE)
    profile_pin = pin(profile_path)
    if (profile_pin["path"] != EXPECTED_PROFILE_PATH
            or profile_pin["sha256"] != EXPECTED_PROFILE_SHA256
            or module.PROFILE_SHA256 != EXPECTED_PROFILE_SHA256):
        raise ValueError("province_resource_name_profile_pin_mismatch")
    profile = module._load_profile()
    if not isinstance(profile, dict) or profile.get("profile_version") != 4:
        raise ValueError("province_resource_name_profile_load_invalid")
    return {"module": pin(module.__file__), "profile": profile_pin,
            "loaded_profile_version": profile.get("profile_version")}


def _coverage_inputs(discovery_path: Path) -> dict:
    doc_path = ROOT / "docs/信息字段覆盖.json"
    doc = read_json(doc_path)
    configured = common.coverage_counts(doc["topics"])
    if (configured["topic_count"] != 74 or configured["field_count"] != 397
            or configured["field_counts"] != EXPECTED_CONFIGURED_FIELD_COUNTS
            or doc.get("goal_complete") is not False):
        raise ValueError("resource_name_configured_coverage_mismatch")
    g02 = next(row for row in doc["topics"] if row["topic_id"] == "G02")
    expected = {"owner", "controller", "culture", "religion", "autonomy", "development", "resource", "center_of_trade"}
    if (set(g02["fields"]) != expected
            or any(row.get("coverage") != "partial" for row in g02["fields"].values())):
        raise ValueError("resource_name_g02_scope_mismatch")
    gaps = g02["fields"]["resource"]["gaps"]
    if ("TRANSLATED_RESOURCE_NAME_NOT_CAPTURED" in gaps
            or "NATIVE_FNV1_HASH_ONLY" not in gaps
            or "CACHED_LITERAL_NAME_IS_NOT_UI_VISIBILITY_OR_RENDER_PROOF" not in gaps):
        raise ValueError("resource_name_gap_metadata_mismatch")
    discovery = read_json(discovery_path)
    actual = common.coverage_counts(discovery["topics"])
    if (actual["topic_count"] != 74 or actual["field_count"] != 397
            or actual["field_counts"] != EXPECTED_LIVE_FIELD_COUNTS
            or actual["callable_topic_count"] != EXPECTED_LIVE_CALLABLE_TOPICS):
        raise ValueError("resource_name_actual_coverage_mismatch")
    configured_topics = {row["topic_id"]: row for row in doc["topics"]}
    live_topics = {row["topic_id"]: row for row in discovery["topics"]}
    if set(configured_topics) != set(live_topics):
        raise ValueError("resource_name_topic_set_changed")
    for topic_id, row in configured_topics.items():
        if set(row["fields"]) != set(live_topics[topic_id]["fields"]):
            raise ValueError("resource_name_field_set_changed:" + topic_id)
    return {"coverage_document": pin(doc_path), "discovery": pin(discovery_path),
            "configured_counts": configured, "actual_live_counts": actual,
            "goal_complete": False, "coverage_counts_unchanged": True,
            "resource_name_scope": "native_hash_cache_literal_only_not_rendered_UI"}


def _mcp_inputs(path: Path) -> dict:
    receipt = read_json(path)
    original_pin = receipt.get("original_mcp_receipt")
    if (receipt.get("acceptance_basis") != "saved_final_delivery_and_raw_capture_reconciliation"
            or receipt.get("original_attempt_status") != "failed"
            or not isinstance(original_pin, dict)
            or pin(original_pin["path"]) != original_pin
            or read_json(common.workspace(original_pin["path"])).get("status") != "failed"
            or "PERIODIC_DELIVERY_MINIMUM" not in str(receipt.get("retained_error", ""))):
        raise ValueError("resource_name_original_failed_attempt_not_retained")
    checks = receipt.get("checks", {})
    periodic = receipt.get("periodic_counts", {})
    archived = receipt.get("archived_captures")
    targets = receipt.get("targets", [])
    expected_archived = len(targets) * (2 + sum(periodic.values())) if isinstance(periodic, dict) else -1
    if (receipt.get("status") != "passed" or receipt.get("server_exit_code") != 0
            or receipt.get("source_pins_unchanged") is not True
            or checks.get("no_active_subscriptions") is not True
            or checks.get("capture_count_matches_delivery") is not True
            or targets != [183, 184, 236, 2000]
            or not isinstance(periodic, dict)
            or not all(type(value) is int and value >= 0 for value in periodic.values())
            or periodic.get("2", 0) < 2 or periodic.get("5", 0) < 1
            or receipt.get("archived_capture_count") != expected_archived
            or not isinstance(archived, list) or len(archived) != expected_archived
            or Path(str(receipt.get("final_results_file", ""))).name
            != "periodic-results-after-cancel.json"):
        raise ValueError("province_resource_name_mcp_receipt_mismatch")
    return {"receipt": pin(path), "status": receipt["status"],
            "acceptance_basis": receipt["acceptance_basis"],
            "original_failed_receipt": original_pin,
            "server_exit_code": receipt["server_exit_code"],
            "periodic_counts": periodic,
            "archived_capture_count": receipt["archived_capture_count"],
            "no_active_subscriptions": True,
            "source_pins_unchanged": True,
            "targets": targets, "raw_capture_count_formula": "len(targets)*(2+sum(periodic_counts))"}


def _audit_inputs(path: Path) -> dict:
    audit = read_json(path)
    if audit.get("status") != "passed":
        raise ValueError("province_resource_name_independent_audit_not_passed")
    return {"audit": pin(path), "status": "passed"}


def source_paths(baseline: dict, build: dict, cli_extra: list[str]) -> list[str]:
    paths = {row["source"]["path"] for row in baseline["files"]}
    paths.update(NEW_SOURCES)
    paths.update(build["native"])
    paths.update(build["copies"])
    paths.update(common.workspace(path).relative_to(ROOT).as_posix() for path in cli_extra)
    return sorted(paths)


def _outputs() -> list[Path]:
    return [
        STAGE / f"source-freeze-{REVISION}.json",
        STAGE / f"source-snapshots-{REVISION}",
        STAGE / f"regression-full-{REVISION}.xml",
        STAGE / f"regression-full-{REVISION}.log",
        STAGE / f"full-execution-reservation-{REVISION}.json",
        STAGE / f"full-execution-boundary-{REVISION}.json",
        STAGE / f"regression-comparison-{REVISION}.json",
        STAGE / f"source-post-run-verification-{REVISION}.json",
    ]


def preflight(mcp_path: Path, audit_path: Path, discovery_path: Path,
              cli_extra: list[str], *, check_outputs: bool) -> dict:
    baseline, changes, build, baseline_pins = baseline_inputs()
    profile = _profile_inputs()
    mcp = _mcp_inputs(mcp_path)
    audit = _audit_inputs(audit_path)
    coverage = _coverage_inputs(discovery_path)
    paths = source_paths(baseline, build, cli_extra)
    missing = [name for name in paths if not (ROOT / name).is_file()]
    if missing:
        raise FileNotFoundError(f"province_resource_name_source_missing:{missing}")
    if not RESEARCH_PYTHON.is_file():
        raise FileNotFoundError(f"research_python_missing:{RESEARCH_PYTHON}")
    if check_outputs and any(path.exists() for path in _outputs()):
        raise FileExistsError(f"province_resource_name_revision_{REVISION}_already_used")
    return {"baseline": baseline, "reviewed_deltas": changes,
            "baseline_pins": baseline_pins, "build": build, "profile": profile,
            "mcp": mcp, "audit": audit, "coverage": coverage, "sources": paths}


def freeze(mcp_path: Path, audit_path: Path, discovery_path: Path,
           cli_extra: list[str]) -> dict:
    ready = preflight(mcp_path, audit_path, discovery_path, cli_extra,
                      check_outputs=True)
    snapshot_dir = STAGE / f"source-snapshots-{REVISION}"
    target = STAGE / f"source-freeze-{REVISION}.json"
    before = {name: pin(name) for name in ready["sources"]}
    snapshot_dir.mkdir(parents=True, exist_ok=False)
    rows = []
    for name in ready["sources"]:
        snapshot = (snapshot_dir / Path(name)).resolve()
        snapshot.relative_to(snapshot_dir.resolve())
        copy_stream(name, snapshot)
        copied = pin(snapshot)
        if copied["sha256"] != before[name]["sha256"] or pin(name) != before[name]:
            raise RuntimeError(f"source_changed_during_freeze:{name}")
        rows.append({"source": before[name], "snapshot": copied})
    value = {
        "schema": "information.country_scale.source_freeze.v1",
        "batch": 85, "revision": REVISION, "status": "passed",
        "count": len(rows), "files": rows,
        "baseline_freeze": pin(BASE / "source-freeze-001.json"),
        "baseline_full": pin(BASE / "regression-full-001.xml"),
        "baseline_comparison": pin(BASE / "regression-comparison-001.json"),
        "baseline_postverify": pin(BASE / "source-post-run-verification-001.json"),
        "baseline_reviewed_deltas": ready["reviewed_deltas"],
        "baseline_pins": ready["baseline_pins"],
        "build_manifest": ready["build"]["manifest"],
        "build_dll": ready["build"]["dll"],
        "manifest_native_source_count": len(ready["build"]["native"]),
        "manifest_native_sources": ready["build"]["native"],
        "manifest_build_copies": ready["build"]["copies"],
        "manifest_source_names": ready["build"]["names"],
        "profile": ready["profile"], "mcp": ready["mcp"],
        "independent_audit": ready["audit"], "coverage": ready["coverage"],
        "resource_capability": "G02.resource.cached_literal_name_partial",
        "resource_name_lookup": "native_FNV1_hash_only_not_rendered_UI",
        "created_at": common.stamp(),
    }
    write_new(target, value)
    result = {"status": "passed", "phase": "freeze", "count": len(rows),
              "freeze": pin(target)}
    print(json.dumps(result, ensure_ascii=False))
    return result


def verify_sources(mcp_path: Path | None = None, audit_path: Path | None = None,
                   discovery_path: Path | None = None,
                   cli_extra: list[str] | None = None) -> dict:
    mcp_path = common.workspace(mcp_path or (STAGE / "mcp-live-001/offline-reconciliation-002.json"))
    audit_path = common.workspace(audit_path or (STAGE / "independent-live-audit-001.json"))
    discovery_path = common.workspace(
        discovery_path or (STAGE / "mcp-live-001/discovery.json"))
    cli_extra = cli_extra or []
    frozen = read_json(STAGE / f"source-freeze-{REVISION}.json")
    if (frozen.get("schema") != "information.country_scale.source_freeze.v1"
            or frozen.get("batch") != 85 or frozen.get("revision") != REVISION
            or frozen.get("status") != "passed"):
        raise ValueError("province_resource_name_source_freeze_invalid")
    ready = preflight(mcp_path, audit_path, discovery_path, cli_extra,
                      check_outputs=False)
    exact_fields = {
        "baseline_freeze": pin(BASE / "source-freeze-001.json"),
        "baseline_full": pin(BASE / "regression-full-001.xml"),
        "baseline_comparison": pin(BASE / "regression-comparison-001.json"),
        "baseline_postverify": pin(BASE / "source-post-run-verification-001.json"),
        "baseline_reviewed_deltas": ready["reviewed_deltas"],
        "baseline_pins": ready["baseline_pins"],
        "build_manifest": ready["build"]["manifest"],
        "build_dll": ready["build"]["dll"],
        "manifest_native_sources": ready["build"]["native"],
        "manifest_build_copies": ready["build"]["copies"],
        "manifest_source_names": ready["build"]["names"],
        "profile": ready["profile"], "mcp": ready["mcp"],
        "independent_audit": ready["audit"], "coverage": ready["coverage"],
        "resource_capability": "G02.resource.cached_literal_name_partial",
        "resource_name_lookup": "native_FNV1_hash_only_not_rendered_UI",
    }
    for key, expected in exact_fields.items():
        if frozen.get(key) != expected:
            raise ValueError(f"province_resource_name_freeze_{key}_changed")
    if frozen.get("manifest_native_source_count") != 125:
        raise ValueError("province_resource_name_inherited_native_count_changed")
    paths = ready["sources"]
    if (sorted(row["source"]["path"] for row in frozen.get("files", [])) != paths
            or frozen.get("count") != len(paths)
            or frozen.get("count") != len(frozen.get("files", []))):
        raise ValueError("province_resource_name_source_union_changed")
    for row in frozen["files"]:
        if pin(row["source"]["path"]) != row["source"]:
            raise ValueError(f"province_resource_name_current_source_changed:{row['source']['path']}")
        if pin(row["snapshot"]["path"]) != row["snapshot"]:
            raise ValueError(f"province_resource_name_snapshot_changed:{row['snapshot']['path']}")
        if (row["source"]["bytes"], row["source"]["sha256"]) != (
                row["snapshot"]["bytes"], row["snapshot"]["sha256"]):
            raise ValueError(f"province_resource_name_source_snapshot_mismatch:{row['source']['path']}")
    return frozen


def full(mcp_path: Path | None = None, audit_path: Path | None = None,
         discovery_path: Path | None = None, cli_extra: list[str] | None = None) -> int:
    cli_extra = cli_extra or []
    frozen = verify_sources(mcp_path, audit_path, discovery_path, cli_extra)
    xml = STAGE / f"regression-full-{REVISION}.xml"
    log = STAGE / f"regression-full-{REVISION}.log"
    reservation = STAGE / f"full-execution-reservation-{REVISION}.json"
    boundary = STAGE / f"full-execution-boundary-{REVISION}.json"
    comparison_path = STAGE / f"regression-comparison-{REVISION}.json"
    postverify_path = STAGE / f"source-post-run-verification-{REVISION}.json"
    if any(path.exists() for path in (xml, log, reservation, boundary,
                                      comparison_path, postverify_path)):
        raise FileExistsError("province_resource_name_full_001_already_started")
    argv = [str(RESEARCH_PYTHON), "-B", "-m", "pytest", "-q", "bridge/tests",
            "--junitxml", str(xml)]
    write_new(reservation, {"runs": 1, "argv": argv,
                            "freeze": pin(STAGE / f"source-freeze-{REVISION}.json"),
                            "started_at": common.stamp()})
    try:
        with log.open("xb") as stream:
            result = subprocess.run(argv, cwd=ROOT, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False)
    except Exception as exc:
        write_new(boundary, {"returncode": None, "log": pin(log),
                             "xml": pin(xml) if xml.is_file() else None,
                             "error": f"{type(exc).__name__}:{exc}",
                             "finished_at": common.stamp()})
        raise
    write_new(boundary, {"returncode": result.returncode, "log": pin(log),
                         "xml": pin(xml), "finished_at": common.stamp()})
    verify_sources(mcp_path, audit_path, discovery_path, cli_extra)
    old = common.bad_cases(BASE / "regression-full-001.xml")
    new = common.bad_cases(xml)
    added, resolved = new - old, old - new
    summary = common.junit_summary(xml)
    whole_suite_passed = result.returncode == 0 and not summary["failures"] and not summary["errors"]
    value = {
        "schema": "information.province_resource_name.regression_comparison.v1",
        "status": "passed_no_new_bad" if not added else "failed_new_bad",
        "batch": 85,
        "baseline": pin(BASE / "regression-full-001.xml"),
        "current": pin(xml), "log": pin(log),
        "baseline_bad_occurrences": sum(old.values()),
        "current_bad_occurrences": sum(new.values()),
        "new_bad": common.counter_rows(added),
        "resolved_bad": common.counter_rows(resolved),
        "no_new_bad": not added,
        "whole_suite_passed": whole_suite_passed,
        "returncode": result.returncode, "junit_summary": summary,
    }
    write_new(comparison_path, value)
    write_new(postverify_path, {
        "status": value["status"], "batch": 85, "count": frozen["count"],
        "freeze": pin(STAGE / f"source-freeze-{REVISION}.json"),
        "regression_comparison": pin(comparison_path),
        "current_sources_match_snapshots": True,
        "no_new_bad": not added, "whole_suite_passed": whole_suite_passed,
    })
    print(json.dumps(value, ensure_ascii=False))
    return 0 if not added else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("freeze", "verify", "full"))
    parser.add_argument("--mcp-receipt", default=str(STAGE / "mcp-live-001/offline-reconciliation-002.json"))
    parser.add_argument("--independent-audit", default=str(
        STAGE / "independent-live-audit-001.json"))
    parser.add_argument("--discovery-json", default=str(STAGE / "mcp-live-001/discovery.json"))
    parser.add_argument("--extra-source", action="append", default=[])
    args = parser.parse_args(argv)
    mcp_path = common.workspace(args.mcp_receipt)
    audit_path = common.workspace(args.independent_audit)
    discovery_path = common.workspace(args.discovery_json)
    if args.operation == "freeze":
        freeze(mcp_path, audit_path, discovery_path, args.extra_source)
        return 0
    if args.operation == "verify":
        frozen = verify_sources(mcp_path, audit_path, discovery_path, args.extra_source)
        print(json.dumps({"status": "passed", "count": frozen["count"]}))
        return 0
    return full(mcp_path, audit_path, discovery_path, args.extra_source)


if __name__ == "__main__":
    raise SystemExit(main())
