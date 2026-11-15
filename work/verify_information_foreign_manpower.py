"""Prepare and run the batch-86 manpower regression freeze.

The only baseline is batch 85's unique full run. This tool snapshots that
selected source union plus the explicitly supplied batch-86 live/operator
helpers; it never walks old snapshot directories. ``full`` reserves one
pytest run, emits the XML/log and compares normalized failure nodes against
the inherited 141 occurrences.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from work import verify_information_province_resource_names as batch85  # noqa: E402

common = batch85.common
STAGE = ROOT / "work/runtime/information-foreign-military-resources-20261029-001"
PREPARATION = STAGE / "full-harness-preparation-001"
BASE = ROOT / "work/runtime/information-province-resource-localization-20261029-001"
BUILD_MANIFEST = ROOT / (
    "work/runtime/diplomacy-observer-20261028-battle-context-v33-001/build-manifest.json"
)
REVISION = "001"
BASE_BATCH = 85
BASE_COUNT = 832
BASE_BAD_OCCURRENCES = 141
BASELINE_SUMMARY = {"tests": 6550, "failures": 106, "errors": 35, "skipped": 0}
BASELINE_TERMINAL = "106 failed, 4395 passed, 35 errors, 2014 subtests passed"
BASELINE_ALLOWED_DELTAS = {
    "bridge/information/foreign_technology.py":
        "batch-86 manpower capture integration into the existing F02 source",
    "docs/外国军事科技与观察方准入.md":
        "batch-86 documentation update for the combined F02 projection",
    "tools/serve_information.py":
        "batch-86 source-registration metadata, if changed",
    "docs/信息字段覆盖.json":
        "batch-86 F02 manpower coverage and metadata update",
}
EXPECTED_PROFILE_PATH = "bridge/information/profiles/foreign-manpower-memory-1374.json"
EXPECTED_PROFILE_SHA256 = "6911d974130d0f83a64ae041a5521038ef93b1128a95cc05a4f9c2dee7f608da"
PROFILE_ID = "foreign-manpower-memory-1374"
PROFILE_VERSION = 1
ACCEPTED_LIVE_SCHEMA = "information.foreign_manpower_mcp_acceptance.v1"
ACCEPTED_LIVE_BASIS = (
    "saved_mcp_delivery_and_capture_archive_reconciliation_after_result_id_field_correction"
)
RECONCILIATION_SCRIPT = (
    "work/runtime/information-foreign-military-resources-20261029-001/"
    "reconcile_manpower_mcp_001.py"
)

# Core new files known at harness preparation time. Live sampling, MCP, and
# audit scripts are supplied explicitly with --extra-source after they exist.
CORE_SOURCES = (
    "bridge/information/foreign_manpower_capture.py",
    "bridge/tests/test_information_foreign_manpower_capture.py",
    "bridge/information/foreign_manpower_memory.py",
    "bridge/tests/test_information_foreign_manpower_memory.py",
    "bridge/information/foreign_military_visibility_memory.py",
    "bridge/tests/test_information_foreign_military_visibility_memory.py",
    "bridge/tests/test_information_foreign_manpower.py",
    EXPECTED_PROFILE_PATH,
    "work/create_information_foreign_manpower_profile.py",
    "work/update_information_foreign_manpower_coverage.py",
    "work/finalize_information_foreign_manpower.py",
    "work/verify_information_foreign_manpower.py",
    "work/runtime/information-foreign-military-resources-20261029-001/probe_manpower_001.py",
    "work/runtime/information-foreign-military-resources-20261029-001/serve_archived_manpower_001.py",
    "work/runtime/information-foreign-military-resources-20261029-001/validate_manpower_mcp_001.py",
    "work/runtime/information-foreign-military-resources-20261029-001/ordinary-military-abi-001/audit_military_abi.py",
    RECONCILIATION_SCRIPT,
    "work/validate_information_live.py",
    "docs/外国人力查询.md",
    "docs/外国军事科技与观察方准入.md",
)
EXPECTED_CONFIGURED_FIELD_COUNTS = {"available": 62, "partial": 185, "planned": 150}
EXPECTED_LIVE_FIELD_COUNTS = {"available": 56, "partial": 149, "planned": 192}
EXPECTED_LIVE_CALLABLE_TOPICS = 42
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


def _reviewed_delta_map(items: list[str]) -> dict[str, str]:
    result = dict(BASELINE_ALLOWED_DELTAS)
    for item in items:
        path, separator, reason = item.partition("=")
        if not separator or not path.strip() or not reason.strip():
            raise ValueError("reviewed_baseline_delta_must_be_PATH_EQUALS_REASON")
        normalized = common.workspace(path.strip()).relative_to(ROOT).as_posix()
        result[normalized] = reason.strip()
    return result


def _extra_source_paths(items: list[str] | None) -> list[str]:
    return sorted({common.workspace(path).relative_to(ROOT).as_posix()
                   for path in (items or [])})


def baseline_inputs(reviewed_deltas: list[str]) -> tuple[dict, list[dict], dict, dict[str, dict]]:
    """Validate the immutable batch-85 freeze and normalized failure baseline."""
    paths = _baseline_paths()
    frozen = read_json(paths["freeze"])
    if (frozen.get("schema") != "information.country_scale.source_freeze.v1"
            or frozen.get("batch") != BASE_BATCH or frozen.get("revision") != "001"
            or frozen.get("status") != "passed" or frozen.get("count") != BASE_COUNT
            or frozen.get("count") != len(frozen.get("files", []))):
        raise ValueError("batch85_freeze_schema_or_count_mismatch")

    allowed = _reviewed_delta_map(reviewed_deltas)
    changes: list[dict] = []
    seen: set[str] = set()
    for row in frozen["files"]:
        source, snapshot = row["source"], row["snapshot"]
        source_path = source["path"]
        if source_path in seen:
            raise ValueError(f"batch85_duplicate_source:{source_path}")
        seen.add(source_path)
        if pin(snapshot["path"]) != snapshot:
            raise ValueError(f"batch85_snapshot_pin_mismatch:{snapshot['path']}")
        if (source.get("bytes"), source.get("sha256")) != (
                snapshot.get("bytes"), snapshot.get("sha256")):
            raise ValueError(f"batch85_source_snapshot_pair_mismatch:{source_path}")
        current = pin(source_path)
        if current != source:
            if source_path not in allowed:
                raise ValueError(f"unreviewed_batch85_source_change:{source_path}")
            changes.append({"path": source_path, "before": source, "after": current,
                            "reason": allowed[source_path]})

    comparison = read_json(paths["comparison"])
    postverify = read_json(paths["postverify"])
    reservation = read_json(paths["reservation"])
    boundary = read_json(paths["boundary"])
    full_pin, log_pin = pin(paths["full"]), pin(paths["log"])
    if (comparison.get("schema") != "information.province_resource_name.regression_comparison.v1"
            or comparison.get("status") != "passed_no_new_bad"
            or comparison.get("batch") != BASE_BATCH
            or comparison.get("current") != full_pin or comparison.get("log") != log_pin
            or comparison.get("baseline_bad_occurrences") != BASE_BAD_OCCURRENCES
            or comparison.get("current_bad_occurrences") != BASE_BAD_OCCURRENCES
            or comparison.get("new_bad") != [] or comparison.get("no_new_bad") is not True
            or comparison.get("whole_suite_passed") is not False):
        raise ValueError("batch85_comparison_mismatch")
    if (postverify.get("status") != "passed_no_new_bad"
            or postverify.get("batch") != BASE_BATCH or postverify.get("count") != BASE_COUNT
            or postverify.get("freeze") != pin(paths["freeze"])
            or postverify.get("regression_comparison") != pin(paths["comparison"])
            or postverify.get("current_sources_match_snapshots") is not True
            or postverify.get("no_new_bad") is not True):
        raise ValueError("batch85_postverify_mismatch")
    if reservation.get("runs") != 1 or reservation.get("freeze") != pin(paths["freeze"]):
        raise ValueError("batch85_full_reservation_mismatch")
    argv = reservation.get("argv", [])
    if ("pytest" not in argv or "bridge/tests" not in argv or "--junitxml" not in argv
            or argv[-1] != str(paths["full"])):
        raise ValueError("batch85_full_argv_mismatch")
    if (boundary.get("returncode") != comparison.get("returncode")
            or boundary.get("xml") != full_pin or boundary.get("log") != log_pin):
        raise ValueError("batch85_full_boundary_mismatch")

    old_bad = common.bad_cases(paths["full"])
    summary = common.junit_summary(paths["full"])
    if (sum(old_bad.values()) != BASE_BAD_OCCURRENCES
            or summary != BASELINE_SUMMARY
            or comparison.get("junit_summary") != summary
            or BASELINE_TERMINAL not in _tail(paths["log"])):
        raise ValueError("batch85_full_baseline_counts_mismatch")

    build = common.manifest_inputs(BUILD_MANIFEST)
    common.validate_build_inheritance(frozen, build)
    if len(build["native"]) != 125 or len(build["copies"]) != 125:
        raise ValueError("inherited_v33_source_count_mismatch")
    pins = {name: pin(path) for name, path in paths.items()}
    return frozen, changes, build, pins


def _profile_inputs() -> dict:
    module = importlib.import_module("bridge.information.foreign_manpower_capture")
    profile_path = common.workspace(module.PROFILE_FILE)
    profile_pin = pin(profile_path)
    if (profile_pin["path"] != EXPECTED_PROFILE_PATH
            or profile_pin["sha256"] != EXPECTED_PROFILE_SHA256
            or module.PROFILE_SHA256 != EXPECTED_PROFILE_SHA256):
        raise ValueError("foreign_manpower_profile_pin_mismatch")
    profile = module._load_profile()
    if (not isinstance(profile, dict) or profile.get("profile_id") != PROFILE_ID
            or profile.get("profile_version") != PROFILE_VERSION):
        raise ValueError("foreign_manpower_profile_load_invalid")
    dependencies = []
    for item in profile.get("source_evidence", []) + profile.get("layout_dependencies", []):
        path = common.workspace(ROOT / item["path"])
        path.relative_to(ROOT)
        dependencies.append(path.relative_to(ROOT).as_posix())
    return {"module": pin(module.__file__), "profile": profile_pin,
            "loaded_profile_version": profile.get("profile_version"),
            "dependencies": sorted(set(dependencies))}


def _topic(topics: list[dict], topic_id: str) -> dict:
    matches = [row for row in topics if row.get("topic_id") == topic_id]
    if len(matches) != 1:
        raise ValueError(f"topic_missing_or_ambiguous:{topic_id}")
    return matches[0]


def _coverage_inputs(discovery_path: Path, baseline: dict) -> dict:
    doc_path = ROOT / "docs/信息字段覆盖.json"
    doc = read_json(doc_path)
    baseline_doc_row = next((row for row in baseline["files"]
                             if row["source"]["path"] == "docs/信息字段覆盖.json"), None)
    if baseline_doc_row is None:
        raise ValueError("batch85_baseline_coverage_snapshot_missing")
    old_doc = read_json(baseline_doc_row["snapshot"]["path"])
    old_topics = {row["topic_id"]: row for row in old_doc["topics"]}
    current_topics = {row["topic_id"]: row for row in doc["topics"]}
    if set(old_topics) != set(current_topics):
        raise ValueError("configured_topic_set_changed")
    old_f02, current_f02 = old_topics.get("F02"), current_topics.get("F02")
    if not isinstance(old_f02, dict) or not isinstance(current_f02, dict):
        raise ValueError("f02_coverage_topic_missing")
    if set(old_f02["fields"]) != set(current_f02["fields"]):
        raise ValueError("f02_field_set_changed")
    topic_metadata = {key: value for key, value in old_f02.items() if key != "fields"}
    current_topic_metadata = {key: value for key, value in current_f02.items() if key != "fields"}
    if set(topic_metadata) != set(current_topic_metadata):
        raise ValueError("f02_topic_metadata_shape_changed")
    for key, value in topic_metadata.items():
        if key not in {"title", "scope_note"} and current_topic_metadata[key] != value:
            raise ValueError(f"unexpected_f02_topic_metadata_change:{key}")
    if (current_f02.get("title") != "外国军事技术、人力与字段准入条件"
            or current_f02.get("scope_note") !=
            "物理玩家与逻辑FRA观察方分开；不切国，不调用native/UI；军力质量和军队、海军准入未实现"):
        raise ValueError("f02_topic_title_or_scope_mismatch")
    if current_f02.get("status") != "available":
        raise ValueError("f02_route_not_available")
    for topic_id, old_topic in old_topics.items():
        if topic_id != "F02" and current_topics[topic_id] != old_topic:
            raise ValueError(f"unexpected_configured_topic_change:{topic_id}")
    for field_id, old_field in old_f02["fields"].items():
        current_field = current_f02["fields"][field_id]
        if field_id == "manpower":
            if current_field.get("coverage") != "partial":
                raise ValueError("f02_manpower_not_partial")
        elif field_id == "visibility":
            if current_field.get("coverage") != old_field.get("coverage"):
                raise ValueError("f02_visibility_coverage_changed")
            if set(current_field) != set(old_field) | {"paths"}:
                raise ValueError("f02_visibility_metadata_shape_changed")
            allowed_visibility_metadata = {"basis", "description", "gaps", "paths", "source"}
            for key, value in old_field.items():
                if (key not in allowed_visibility_metadata
                        and current_field[key] != value):
                    raise ValueError(f"unexpected_f02_visibility_change:{key}")
        elif field_id == "military_technology":
            if current_field.get("coverage") != old_field.get("coverage"):
                raise ValueError("f02_military_technology_coverage_changed")
            allowed_metadata = {"description", "paths", "source"}
            if set(current_field) != set(old_field):
                raise ValueError("f02_military_technology_metadata_shape_changed")
            for key, value in old_field.items():
                if key not in allowed_metadata and current_field[key] != value:
                    raise ValueError(f"unexpected_f02_military_technology_change:{key}")
        elif current_field != old_field:
            raise ValueError(f"unexpected_f02_field_change:{field_id}")
    configured = common.coverage_counts(doc["topics"])
    if (configured["topic_count"] != 74 or configured["field_count"] != 397
            or configured["field_counts"] != EXPECTED_CONFIGURED_FIELD_COUNTS
            or doc.get("goal_complete") is not False):
        raise ValueError("foreign_manpower_configured_coverage_mismatch")

    discovery = read_json(discovery_path)
    actual = common.coverage_counts(discovery["topics"])
    if (actual["topic_count"] != configured["topic_count"]
            or actual["field_count"] != configured["field_count"]
            or actual["field_counts"] != EXPECTED_LIVE_FIELD_COUNTS
            or actual["callable_topic_count"] != EXPECTED_LIVE_CALLABLE_TOPICS):
        raise ValueError("foreign_manpower_actual_coverage_shape_mismatch")
    live_topics = {row["topic_id"]: row for row in discovery["topics"]}
    if set(current_topics) != set(live_topics):
        raise ValueError("live_topic_set_changed")
    if current_topics["F02"] != live_topics["F02"]:
        raise ValueError("f02_configured_and_discovered_metadata_mismatch")
    for topic_id, row in current_topics.items():
        if set(row["fields"]) != set(live_topics[topic_id].get("fields", {})):
            raise ValueError("live_field_set_changed:" + topic_id)
    manpower_live = live_topics["F02"]["fields"]["manpower"]
    if (live_topics["F02"].get("status") != "available"
            or manpower_live.get("coverage") != "partial"
            or manpower_live.get("status", "available") != "available"):
        raise ValueError("f02_manpower_not_live_partial")
    return {"coverage_document": pin(doc_path), "discovery": pin(discovery_path),
            "configured_counts": configured, "actual_live_counts": actual,
            "goal_complete": False,
            "manpower_status": current_f02["fields"]["manpower"].get("coverage"),
            "live_topic_status": live_topics["F02"].get("status"),
            "live_manpower_coverage": manpower_live.get("coverage"),
            "live_manpower_status": manpower_live.get("status", "available")}


def _live_inputs(path: Path) -> dict:
    receipt = read_json(path)
    checks = receipt.get("checks", {})
    original_pin = receipt.get("original_mcp_receipt")
    if (receipt.get("schema") != ACCEPTED_LIVE_SCHEMA
            or receipt.get("mode") != "live" or receipt.get("observer") != "FRA"
            or receipt.get("projection_version") != 2
            or receipt.get("acceptance_basis") != ACCEPTED_LIVE_BASIS
            or receipt.get("original_attempt_status") != "failed"
            or not isinstance(original_pin, dict)
            or not isinstance(original_pin.get("path"), str)
            or pin(original_pin["path"]) != original_pin
            or read_json(common.workspace(original_pin["path"])).get("status") != "failed"):
        raise ValueError("foreign_manpower_original_failed_mcp_attempt_not_retained")
    reconciliation_pin = receipt.get("reconciliation_script")
    if (not isinstance(reconciliation_pin, dict)
            or reconciliation_pin.get("path") != RECONCILIATION_SCRIPT
            or pin(RECONCILIATION_SCRIPT) != reconciliation_pin):
        raise ValueError("foreign_manpower_reconciliation_script_pin_mismatch")
    before_pins = receipt.get("source_pins_before")
    after_pins = receipt.get("source_pins_after")
    if not isinstance(before_pins, list) or not isinstance(after_pins, list):
        raise ValueError("foreign_manpower_live_source_pin_lists_missing")
    if before_pins != after_pins or receipt.get("source_pins_unchanged") is not True:
        raise ValueError("foreign_manpower_live_source_pins_changed")
    source_paths = [row.get("path") for row in before_pins if isinstance(row, dict)]
    if (len(source_paths) != len(before_pins) or len(set(source_paths)) != len(source_paths)):
        raise ValueError("foreign_manpower_live_source_pin_shape_invalid")
    for row in before_pins:
        if (not isinstance(row, dict) or not isinstance(row.get("path"), str)
                or pin(row["path"]) != row):
            raise ValueError("foreign_manpower_live_source_pin_mismatch")
    periodic = receipt.get("periodic_counts")
    targets = receipt.get("targets")
    archives = receipt.get("archived_captures")
    if (not isinstance(periodic, dict) or not isinstance(targets, list) or not targets
            or any(not isinstance(tag, str) or not tag for tag in targets)
            or len(set(targets)) != len(targets)):
        raise ValueError("foreign_manpower_live_receipt_shape_invalid")
    if not all(type(value) is int and value >= 0 for value in periodic.values()):
        raise ValueError("foreign_manpower_live_periodic_counts_invalid")
    dual_verified = checks.get("additional_dual_capture_query_verified") is True
    if not dual_verified:
        raise ValueError("foreign_manpower_additional_dual_capture_not_verified")
    expected_archives = len(targets) * (2 + sum(periodic.values())) + 2
    if (type(receipt.get("expected_capture_count")) is not int
            or receipt.get("expected_capture_count") != expected_archives):
        raise ValueError("foreign_manpower_receipt_expected_capture_count_mismatch")
    archived_count = receipt.get("archived_capture_count")
    if archived_count is None and isinstance(archives, list):
        archived_count = len(archives)
    no_active = checks.get("no_active_subscriptions") is True
    all_checks_passed = bool(checks) and all(value is True for value in checks.values())
    if (receipt.get("status") != "passed" or type(receipt.get("server_exit_code")) is not int
            or receipt.get("server_exit_code") != 0
            or receipt.get("source_pins_unchanged") is not True
            or not no_active or not all_checks_passed
            or periodic.get("2", 0) < 2 or periodic.get("5", 0) < 1
            or archived_count != expected_archives
            or type(archived_count) is not int
            or receipt.get("public_capture_reference_count") != expected_archives
            or not isinstance(archives, list) or len(archives) != expected_archives
            or receipt.get("manual_result_copies_count_as_captures") is not False
            or type(receipt.get("manual_result_copy_count")) is not int
            or receipt.get("manual_result_copy_count") < 0
            or (receipt.get("native_game_calls") is not False)
            or (receipt.get("business_dispatched") is not False)
            or (receipt.get("game_controls") is not False)
            or (receipt.get("writes_to_game") is not False)
            or (receipt.get("date_advance") is not False)
            or (receipt.get("save_or_reload") is not False)
            or (receipt.get("UI_control") is not False)):
        raise ValueError("foreign_manpower_live_receipt_not_qualified")
    sequences = [row.get("sequence") for row in archives if isinstance(row, dict)]
    if sequences != list(range(1, expected_archives + 1)):
        raise ValueError("foreign_manpower_live_archive_sequence_mismatch")
    return {"receipt": pin(path), "status": "passed", "targets": targets,
            "acceptance_basis": receipt["acceptance_basis"],
            "original_failed_receipt": original_pin,
            "reconciliation_script": reconciliation_pin,
            "source_pin_count": len(before_pins),
            "periodic_counts": periodic, "archived_capture_count": archived_count,
            "expected_capture_count": expected_archives,
            "dual_capture_query_verified": dual_verified,
            "manual_result_copies_count_as_captures": False,
            "raw_capture_count_formula": "len(targets)*(2+sum(periodic_counts))+2 verified combined-query captures",
            "server_exit_code": 0, "no_active_subscriptions": True,
            "source_pins_unchanged": True}


def _audit_inputs(path: Path) -> dict:
    audit = read_json(path)
    if audit.get("status") != "passed":
        raise ValueError("foreign_manpower_independent_audit_not_passed")
    return {"audit": pin(path), "status": "passed"}


def source_paths(baseline: dict, build: dict, profile: dict,
                 cli_extra: list[str]) -> list[str]:
    paths = {row["source"]["path"] for row in baseline["files"]}
    paths.update(CORE_SOURCES)
    paths.update(profile["dependencies"])
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


def preflight(live_path: Path, audit_path: Path, discovery_path: Path,
              cli_extra: list[str] | None, reviewed_deltas: list[str] | None, *,
              check_outputs: bool) -> dict:
    if live_path is None or audit_path is None or discovery_path is None:
        raise ValueError("freeze_requires_live_audit_and_discovery_paths")
    cli_extra = _extra_source_paths(cli_extra)
    reviewed_deltas = reviewed_deltas or []
    baseline, changes, build, baseline_pins = baseline_inputs(reviewed_deltas)
    delta_policy = _reviewed_delta_map(reviewed_deltas)
    profile = _profile_inputs()
    live = _live_inputs(live_path)
    audit = _audit_inputs(audit_path)
    coverage = _coverage_inputs(discovery_path, baseline)
    paths = source_paths(baseline, build, profile, cli_extra)
    if not cli_extra:
        raise ValueError("freeze_requires_explicit_live_operator_source_paths")
    missing = [name for name in paths if not (ROOT / name).is_file()]
    if missing:
        raise FileNotFoundError(f"foreign_manpower_source_missing:{missing}")
    if not RESEARCH_PYTHON.is_file():
        raise FileNotFoundError(f"research_python_missing:{RESEARCH_PYTHON}")
    if check_outputs and any(path.exists() for path in _outputs()):
        raise FileExistsError(f"foreign_manpower_revision_{REVISION}_already_used")
    return {"baseline": baseline, "reviewed_deltas": changes,
            "reviewed_delta_policy": delta_policy,
            "baseline_pins": baseline_pins, "build": build, "profile": profile,
            "live": live, "audit": audit, "coverage": coverage, "sources": paths,
            "extra_sources": sorted(set(cli_extra)),
            "input_paths": {
                "live_receipt": common.workspace(live_path).relative_to(ROOT).as_posix(),
                "independent_audit": common.workspace(audit_path).relative_to(ROOT).as_posix(),
                "discovery_json": common.workspace(discovery_path).relative_to(ROOT).as_posix(),
            }}


def _freeze_inputs(ready: dict) -> dict:
    return {
        "baseline_freeze": pin(BASE / "source-freeze-001.json"),
        "baseline_full": pin(BASE / "regression-full-001.xml"),
        "baseline_comparison": pin(BASE / "regression-comparison-001.json"),
        "baseline_postverify": pin(BASE / "source-post-run-verification-001.json"),
        "baseline_reviewed_deltas": ready["reviewed_deltas"],
        "reviewed_delta_policy": ready["reviewed_delta_policy"],
        "baseline_pins": ready["baseline_pins"],
        "build_manifest": ready["build"]["manifest"],
        "build_dll": ready["build"]["dll"],
        "manifest_native_sources": ready["build"]["native"],
        "manifest_build_copies": ready["build"]["copies"],
        "manifest_source_names": ready["build"]["names"],
        "manifest_native_source_count": len(ready["build"]["native"]),
        "profile": ready["profile"], "live": ready["live"],
        "independent_audit": ready["audit"], "coverage": ready["coverage"],
        "extra_sources": ready["extra_sources"],
        "input_paths": ready["input_paths"],
        "baseline_bad_occurrences": BASE_BAD_OCCURRENCES,
        "baseline_junit_summary": BASELINE_SUMMARY,
        "source_snapshot_policy": "85-selected-source-paths-plus-explicit-86-sources; no snapshot recursion",
    }


def freeze(live_path: Path, audit_path: Path, discovery_path: Path,
           cli_extra: list[str], reviewed_deltas: list[str]) -> dict:
    ready = preflight(live_path, audit_path, discovery_path, cli_extra,
                      reviewed_deltas, check_outputs=True)
    snapshot_dir = STAGE / f"source-snapshots-{REVISION}"
    target = STAGE / f"source-freeze-{REVISION}.json"
    inputs = _freeze_inputs(ready)
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
        "schema": "information.foreign_manpower.source_freeze.v1",
        "batch": 86, "revision": REVISION, "status": "passed",
        "count": len(rows), "files": rows, **inputs,
        "created_at": common.stamp(),
    }
    write_new(target, value)
    result = {"status": "passed", "phase": "freeze", "count": len(rows),
              "freeze": pin(target)}
    print(json.dumps(result, ensure_ascii=False))
    return result


def verify_sources(live_path: Path | None = None, audit_path: Path | None = None,
                   discovery_path: Path | None = None, cli_extra: list[str] | None = None,
                   reviewed_deltas: list[str] | None = None) -> dict:
    frozen = read_json(STAGE / f"source-freeze-{REVISION}.json")
    if (frozen.get("schema") != "information.foreign_manpower.source_freeze.v1"
            or frozen.get("batch") != 86 or frozen.get("revision") != REVISION
            or frozen.get("status") != "passed"):
        raise ValueError("foreign_manpower_source_freeze_invalid")
    input_paths = frozen.get("input_paths", {})
    if not isinstance(input_paths, dict):
        raise ValueError("foreign_manpower_freeze_input_paths_invalid")
    live_path = common.workspace(live_path or (ROOT / input_paths["live_receipt"]))
    audit_path = common.workspace(audit_path or (ROOT / input_paths["independent_audit"]))
    discovery_path = common.workspace(discovery_path or (ROOT / input_paths["discovery_json"]))
    if cli_extra is None:
        cli_extra = list(frozen.get("extra_sources", []))
    if reviewed_deltas is None:
        policy = frozen.get("reviewed_delta_policy", {})
        if not isinstance(policy, dict):
            raise ValueError("foreign_manpower_baseline_delta_policy_invalid")
        reviewed_deltas = [f"{path}={reason}" for path, reason in policy.items()]
    ready = preflight(live_path, audit_path, discovery_path, cli_extra,
                      reviewed_deltas, check_outputs=False)
    inputs = _freeze_inputs(ready)
    for key, expected in inputs.items():
        if frozen.get(key) != expected:
            raise ValueError(f"foreign_manpower_freeze_{key}_changed")
    paths = ready["sources"]
    if (sorted(row["source"]["path"] for row in frozen.get("files", [])) != paths
            or frozen.get("count") != len(paths)
            or frozen.get("count") != len(frozen.get("files", []))):
        raise ValueError("foreign_manpower_source_union_changed")
    for row in frozen["files"]:
        if pin(row["source"]["path"]) != row["source"]:
            raise ValueError(f"foreign_manpower_current_source_changed:{row['source']['path']}")
        if pin(row["snapshot"]["path"]) != row["snapshot"]:
            raise ValueError(f"foreign_manpower_snapshot_changed:{row['snapshot']['path']}")
        if (row["source"]["bytes"], row["source"]["sha256"]) != (
                row["snapshot"]["bytes"], row["snapshot"]["sha256"]):
            raise ValueError(f"foreign_manpower_source_snapshot_mismatch:{row['source']['path']}")
    return frozen


def full(live_path: Path | None = None, audit_path: Path | None = None,
         discovery_path: Path | None = None, cli_extra: list[str] | None = None,
         reviewed_deltas: list[str] | None = None) -> int:
    frozen = verify_sources(live_path, audit_path, discovery_path,
                            cli_extra, reviewed_deltas)
    xml = STAGE / f"regression-full-{REVISION}.xml"
    log = STAGE / f"regression-full-{REVISION}.log"
    reservation = STAGE / f"full-execution-reservation-{REVISION}.json"
    boundary = STAGE / f"full-execution-boundary-{REVISION}.json"
    comparison_path = STAGE / f"regression-comparison-{REVISION}.json"
    postverify_path = STAGE / f"source-post-run-verification-{REVISION}.json"
    if any(path.exists() for path in (xml, log, reservation, boundary,
                                      comparison_path, postverify_path)):
        raise FileExistsError("foreign_manpower_full_001_already_started")
    argv = [str(RESEARCH_PYTHON), "-B", "-m", "pytest", "-q", "bridge/tests",
            "--junitxml", str(xml)]
    write_new(reservation, {
        "runs": 1, "argv": argv,
        "freeze": pin(STAGE / f"source-freeze-{REVISION}.json"),
        "orchestrator_pid": os.getpid(),
        "memory_cap_bytes": 1024 * 1024 * 1024,
        "monitoring_policy": "monitor only this orchestrator's exact pytest child; do not poll unrelated processes",
        "started_at": common.stamp(),
    })
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
    verify_sources(live_path, audit_path, discovery_path,
                   cli_extra, reviewed_deltas)
    old = common.bad_cases(BASE / "regression-full-001.xml")
    new = common.bad_cases(xml)
    added, resolved = new - old, old - new
    summary = common.junit_summary(xml)
    whole_suite_passed = result.returncode == 0 and not summary["failures"] and not summary["errors"]
    value = {
        "schema": "information.foreign_manpower.regression_comparison.v1",
        "status": "passed_no_new_bad" if not added else "failed_new_bad",
        "batch": 86,
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
        "status": value["status"], "batch": 86, "count": frozen["count"],
        "freeze": pin(STAGE / f"source-freeze-{REVISION}.json"),
        "regression_comparison": pin(comparison_path),
        "current_sources_match_snapshots": True,
        "no_new_bad": not added, "whole_suite_passed": whole_suite_passed,
    })
    print(json.dumps(value, ensure_ascii=False))
    return 0 if not added else 2


def _paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    return tuple(common.workspace(path) if path else None
                 for path in (args.live_receipt, args.independent_audit, args.discovery_json))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("freeze", "verify", "full"))
    parser.add_argument("--live-receipt")
    parser.add_argument("--independent-audit")
    parser.add_argument("--discovery-json")
    parser.add_argument("--extra-source", action="append", default=None,
                        help="Explicit batch-86 source/helper path; repeat for every live/operator script")
    parser.add_argument("--reviewed-baseline-delta", action="append", default=None,
                        help="Additional reviewed baseline change as PATH=REASON")
    args = parser.parse_args(argv)
    live_path, audit_path, discovery_path = _paths(args)
    if args.operation == "freeze":
        if not live_path or not audit_path or not discovery_path:
            parser.error("freeze requires --live-receipt, --independent-audit and --discovery-json")
        freeze(live_path, audit_path, discovery_path,
               args.extra_source, args.reviewed_baseline_delta)
        return 0
    if args.operation == "verify":
        frozen = verify_sources(live_path, audit_path, discovery_path,
                                args.extra_source, args.reviewed_baseline_delta)
        print(json.dumps({"status": "passed", "phase": "verify",
                          "count": frozen["count"],
                          "freeze": pin(STAGE / f"source-freeze-{REVISION}.json")},
                         ensure_ascii=False))
        return 0
    return full(live_path, audit_path, discovery_path,
                args.extra_source, args.reviewed_baseline_delta)


if __name__ == "__main__":
    raise SystemExit(main())
