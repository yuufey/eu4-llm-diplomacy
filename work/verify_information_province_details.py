"""Freeze and verify the batch-80 province-detail sources and one full run.

This verifier reads the batch-79 freeze directly. It deliberately does not
call verify_information_province_state.baseline(), whose coverage comparison
describes the pre-batch-80 document. All source hashing and copying use the
shared 1 MiB streaming helpers.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work import verify_information_foreign_technology as prior


STAGE = ROOT / "work/runtime/information-province-details-20261029-001"
BASE = ROOT / "work/runtime/information-next-sources-20261029-001"
REVISION = "001"
BATCH79 = 79
BATCH79_FREEZE_COUNT = 725
EXPECTED_BAD_OCCURRENCES = 141
EXPECTED_PROFILE = {
    "path": "bridge/information/profiles/province-state-memory-1374-v2.json",
    "bytes": 49420,
    "sha256": "70354c44fba340e52d6671595eb465dd0b74608439a2722877fcf58b06238a23",
}
EXPECTED_FIELD_COUNTS = {"available": 62, "partial": 176, "planned": 159}
PROMOTED_FIELDS = ("autonomy", "culture", "religion")
PRESERVED_PLANNED_FIELDS = ("development", "resource", "center_of_trade")
PREVIOUS_PARTIAL_FIELDS = ("owner", "controller")
EXPECTED_G02_FIELDS = set(PROMOTED_FIELDS + PRESERVED_PLANNED_FIELDS + PREVIOUS_PARTIAL_FIELDS)

REVIEWED_BASELINE_CHANGES = {
    "bridge/information/province_state_memory.py": "batch-80 reviewed state-reader extension",
    "bridge/information/province_state_capture.py": "batch-80 reviewed capture extension",
    "bridge/information/province_state.py": "batch-80 reviewed public projection extension",
    "bridge/tests/test_information_province_state_memory.py": "batch-80 reviewed state-reader tests",
    "bridge/tests/test_information_province_state_capture.py": "batch-80 reviewed capture tests",
    "bridge/tests/test_information_province_state.py": "batch-80 reviewed public tests",
    "docs/信息字段覆盖.json": "batch-80 G02 field coverage update",
}

EXTRA = (
    "bridge/information/province_detail_memory.py",
    "bridge/information/province_identity_memory.py",
    "bridge/information/province_scalar_memory.py",
    "bridge/tests/test_information_province_identity_memory.py",
    "bridge/tests/test_information_province_scalar_memory.py",
    EXPECTED_PROFILE["path"],
    "work/create_information_province_details_profile.py",
    "work/update_information_province_details_coverage.py",
    "work/finalize_information_province_details.py",
    "work/verify_information_province_details.py",
)

pin = prior.pin
read_json = prior.read_json
write_new = prior.write_new
copy_stream = prior.copy_stream


def _sha(path: Path) -> str:
    return pin(path)["sha256"]


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


def baseline_inputs() -> tuple[dict, list[dict], dict, dict, dict]:
    """Check all batch-79 snapshots, its sole full run, and reviewed source deltas."""
    paths = _baseline_paths()
    frozen = read_json(paths["freeze"])
    assert frozen["batch"] == BATCH79
    assert frozen["status"] == "passed"
    assert frozen["count"] == len(frozen["files"]) == BATCH79_FREEZE_COUNT

    changes: list[dict] = []
    baseline_doc_snapshot = None
    for row in frozen["files"]:
        source, snapshot = row["source"], row["snapshot"]
        assert pin(snapshot["path"]) == snapshot
        assert (source["bytes"], source["sha256"]) == (snapshot["bytes"], snapshot["sha256"])
        current = pin(source["path"])
        if current != source:
            assert source["path"] in REVIEWED_BASELINE_CHANGES, source["path"]
            changes.append({
                "before": source,
                "after": current,
                "reason": REVIEWED_BASELINE_CHANGES[source["path"]],
            })
        if source["path"] == "docs/信息字段覆盖.json":
            baseline_doc_snapshot = snapshot
    assert {item["before"]["path"] for item in changes} == set(REVIEWED_BASELINE_CHANGES)
    assert baseline_doc_snapshot is not None

    comparison = read_json(paths["comparison"])
    postverify = read_json(paths["postverify"])
    reservation = read_json(paths["reservation"])
    boundary = read_json(paths["boundary"])
    current_full = pin(paths["full"])
    current_log = pin(paths["log"])
    assert comparison["status"] == "passed_no_new_bad"
    assert comparison["batch"] == BATCH79
    assert comparison["current"] == current_full
    assert comparison["log"] == current_log
    assert comparison["current_bad_occurrences"] == EXPECTED_BAD_OCCURRENCES
    assert comparison["baseline_bad_occurrences"] == EXPECTED_BAD_OCCURRENCES
    assert comparison["new_bad"] == [] and comparison["no_new_bad"] is True
    assert postverify["status"] == "passed_no_new_bad"
    assert postverify["batch"] == BATCH79
    assert postverify["count"] == BATCH79_FREEZE_COUNT
    assert postverify["freeze"] == pin(paths["freeze"])
    assert postverify["regression_comparison"] == pin(paths["comparison"])
    assert postverify["current_sources_match_snapshots"] is True
    assert postverify["no_new_bad"] is True
    assert reservation["runs"] == 1
    assert reservation["freeze"] == pin(paths["freeze"])
    argv = reservation["argv"]
    assert "pytest" in argv and "bridge/tests" in argv and "--junitxml" in argv
    assert argv[-1] == str(paths["full"])
    assert boundary["returncode"] == comparison["returncode"]
    assert boundary["xml"] == current_full
    assert boundary["log"] == current_log
    old_bad = prior.bad_cases(paths["full"])
    assert sum(old_bad.values()) == EXPECTED_BAD_OCCURRENCES
    assert prior.junit_summary(paths["full"]) == comparison["junit_summary"]

    build = prior.manifest_inputs(prior.BUILD_MANIFEST)
    prior.validate_build_inheritance(frozen, build)
    baseline_pins = {name: pin(path) for name, path in paths.items()}
    baseline_pins["coverage_update"] = pin(BASE / "coverage-update-001.json")
    return frozen, changes, build, baseline_pins, baseline_doc_snapshot


def acceptance_inputs() -> dict[str, dict]:
    """Require successful private, MCP, and independent-audit records before freeze."""
    private_path = STAGE / "private-live-probe-001.json"
    mcp_path = STAGE / "mcp-live-001/receipt.json"
    audit_path = STAGE / "independent-live-audit-003.json"
    private = read_json(private_path)
    mcp = read_json(mcp_path)
    audit = read_json(audit_path)
    assert private["status"] == "passed"
    assert private["observer"] == "FRA"
    assert mcp["status"] == "passed"
    assert mcp["server_exit_code"] == 0
    assert mcp["source_pins_unchanged"] is True
    assert mcp["checks"]["no_active_subscriptions"] is True
    assert audit["status"] == "passed"
    assert audit["inputs_unchanged_during_audit"] is True
    audit_pins = {row["path"]: row for row in audit["input_pins"]}
    # The independent auditor consumes raw private captures, not the positive
    # producer's summary receipt. Bind that summary through its actual inputs.
    for source in (mcp_path,):
        source_pin = pin(source)
        assert audit_pins.get(source_pin["path"]) == source_pin
    for province_id in ('183','236'):
        row=private['objects'][province_id]['capture']
        assert row==pin(row['path']) and audit_pins.get(row['path'])==row
    negative_path=STAGE/'private-discovery-negative-001.json'
    negative=read_json(negative_path)
    assert negative['status']=='passed_negative'
    row=negative['capture']
    assert row==pin(row['path']) and audit_pins.get(row['path'])==row
    return {
        "private_probe": pin(private_path),
        "private_negative": pin(negative_path),
        "mcp_receipt": pin(mcp_path),
        "independent_audit": pin(audit_path),
    }


def coverage_inputs(baseline_doc_snapshot: dict) -> tuple[dict, dict, dict]:
    """Validate the exact G02 coverage delta while preserving the other 73 topics."""
    update_path = STAGE / "coverage-update-001.json"
    update = read_json(update_path)
    before_doc = read_json(baseline_doc_snapshot["path"])
    doc_path = ROOT / "docs/信息字段覆盖.json"
    current_doc = read_json(doc_path)
    assert update["status"] == "updated_partial"
    assert update["goal_complete"] is False
    assert update["before_sha256"] == baseline_doc_snapshot["sha256"]
    assert update["after_sha256"] == pin(doc_path)["sha256"]
    expected_changes = {
        f"G02.{name}": ["planned", "partial"] for name in PROMOTED_FIELDS
    }
    assert update["coverage_changes"] == expected_changes

    old_topics = {topic["topic_id"]: topic for topic in before_doc["topics"]}
    new_topics = {topic["topic_id"]: topic for topic in current_doc["topics"]}
    assert len(old_topics) == len(new_topics) == 74
    assert set(old_topics) == set(new_topics)
    for topic_id in old_topics.keys() - {"G02"}:
        assert new_topics[topic_id] == old_topics[topic_id]

    old_g02, new_g02 = old_topics["G02"], new_topics["G02"]
    discovery = read_json(STAGE / 'mcp-live-001/discovery.json')
    assert new_g02 == next(topic for topic in discovery['topics'] if topic['topic_id']=='G02')
    assert new_g02['title']=='省份状态与资源（部分）'
    old_fields, new_fields = old_g02["fields"], new_g02["fields"]
    assert set(old_fields) == set(new_fields) == EXPECTED_G02_FIELDS
    for name in PROMOTED_FIELDS:
        assert old_fields[name]["coverage"] == "planned"
        assert new_fields[name]["coverage"] == "partial"
        assert new_fields[name]["complete"] is False
    for name in PREVIOUS_PARTIAL_FIELDS:
        assert old_fields[name]["coverage"] == new_fields[name]["coverage"] == "partial"
        assert new_fields[name]["complete"] is False
    for name in PRESERVED_PLANNED_FIELDS:
        assert old_fields[name]["coverage"] == "planned"
        assert new_fields[name] == old_fields[name]
    for key in old_g02:
        if key not in {"fields", "source", "scope_note", "title"}:
            assert new_g02[key] == old_g02[key]

    assert set(current_doc["G02"]) == set(before_doc["G02"])
    for key in current_doc["G02"]:
        assert current_doc["G02"][key] == new_g02[key]
    assert current_doc["configuration"]["adapters"] == before_doc["configuration"]["adapters"]
    assert len(current_doc["configuration"]["adapters"]) == 20
    counts = prior.coverage_counts(current_doc["topics"])
    assert counts["topic_count"] == 74 and counts["field_count"] == 397
    assert counts["field_counts"] == EXPECTED_FIELD_COUNTS
    assert counts["callable_topic_count"] == 46
    assert counts["topic_status_counts"] == {
        "available": 46, "partial": 4, "planned": 24,
    }
    assert update["configured_counts"] == counts
    assert current_doc["counts"] == counts
    assert current_doc["expected_counts"] == counts
    assert current_doc["goal_complete"] is False

    expected_doc = deepcopy(before_doc)
    g02_index = next(index for index, topic in enumerate(expected_doc["topics"])
                     if topic["topic_id"] == "G02")
    expected_doc["topics"][g02_index] = deepcopy(new_g02)
    expected_doc["G02"] = deepcopy(current_doc["G02"])
    expected_doc["counts"] = counts
    expected_doc["expected_counts"] = deepcopy(counts)
    assert current_doc == expected_doc
    return update, current_doc, {
        "coverage_update": pin(update_path),
        "coverage_document": pin(doc_path),
    }


def source_paths(frozen: dict, build: dict) -> list[str]:
    stage_scripts = [
        path.relative_to(ROOT).as_posix()
        for path in STAGE.rglob("*.py")
        if not any(
            part.startswith(("source-snapshots-", "doc-mirrors-")) or part == "__pycache__"
            for part in path.parts
        )
    ]
    paths = set(row["source"]["path"] for row in frozen["files"])
    paths.update(EXTRA)
    paths.update(stage_scripts)
    paths.update(build["native"])
    paths.update(build["copies"])
    return sorted(paths)


def preflight() -> dict:
    frozen, changes, build, baseline_pins, baseline_doc_snapshot = baseline_inputs()
    acceptance = acceptance_inputs()
    update, current_doc, coverage_pins = coverage_inputs(baseline_doc_snapshot)
    profile_pin = pin(EXPECTED_PROFILE["path"])
    assert profile_pin == EXPECTED_PROFILE
    paths = source_paths(frozen, build)
    missing = [name for name in paths if not (ROOT / name).is_file()]
    if missing:
        raise FileNotFoundError(f"batch80_source_missing:{missing}")

    reserved = [
        STAGE / f"source-freeze-{REVISION}.json",
        STAGE / f"regression-full-{REVISION}.xml",
        STAGE / f"regression-full-{REVISION}.log",
        STAGE / f"full-execution-reservation-{REVISION}.json",
        STAGE / f"full-execution-boundary-{REVISION}.json",
        STAGE / f"regression-comparison-{REVISION}.json",
        STAGE / f"source-post-run-verification-{REVISION}.json",
        STAGE / f"source-snapshots-{REVISION}",
    ]
    if any(path.exists() for path in reserved):
        raise FileExistsError(f"batch80_revision_{REVISION}_already_used")
    return {
        "baseline_freeze": frozen,
        "baseline_reviewed_deltas": changes,
        "baseline_pins": baseline_pins,
        "build": build,
        "acceptance": acceptance,
        "coverage_update": update,
        "coverage_document": current_doc,
        "coverage_pins": coverage_pins,
        "profile": profile_pin,
        "sources": paths,
    }


def freeze() -> dict:
    ready = preflight()
    snapshot_dir = STAGE / f"source-snapshots-{REVISION}"
    target = STAGE / f"source-freeze-{REVISION}.json"
    originals = {name: pin(name) for name in ready["sources"]}
    snapshot_dir.mkdir(parents=True, exist_ok=False)
    rows = []
    for name in ready["sources"]:
        snapshot = (snapshot_dir / Path(name)).resolve()
        snapshot.relative_to(snapshot_dir.resolve())
        copy_stream(name, snapshot)
        copied = pin(snapshot)
        assert copied["sha256"] == originals[name]["sha256"]
        assert pin(name) == originals[name]
        rows.append({"source": originals[name], "snapshot": copied})

    value = {
        "schema": "information.province_details.source_freeze.v1",
        "batch": 80,
        "revision": REVISION,
        "status": "passed",
        "count": len(rows),
        "files": rows,
        "baseline": ready["baseline_pins"],
        "baseline_reviewed_deltas": ready["baseline_reviewed_deltas"],
        "acceptance": ready["acceptance"],
        "coverage_update": ready["coverage_pins"]["coverage_update"],
        "coverage_document": ready["coverage_pins"]["coverage_document"],
        "profile": ready["profile"],
        "build_manifest": ready["build"]["manifest"],
        "build_dll": ready["build"]["dll"],
        "manifest_native_source_count": len(ready["build"]["native"]),
        "manifest_native_sources": ready["build"]["native"],
        "manifest_build_copies": ready["build"]["copies"],
        "manifest_source_names": ready["build"]["names"],
        "coverage_counts": ready["coverage_update"]["configured_counts"],
        "created_at": prior.stamp(),
    }
    write_new(target, value)
    result = {"status": "passed", "phase": "freeze", "count": len(rows),
              "freeze": pin(target)}
    print(json.dumps(result, ensure_ascii=False))
    return result


def verify_sources() -> dict:
    frozen = read_json(STAGE / f"source-freeze-{REVISION}.json")
    ready = preflight_without_reservation()
    assert frozen["batch"] == 80 and frozen["revision"] == REVISION
    assert frozen["status"] == "passed"
    assert frozen["baseline"] == ready["baseline_pins"]
    assert frozen["baseline_reviewed_deltas"] == ready["baseline_reviewed_deltas"]
    assert frozen["acceptance"] == ready["acceptance"]
    assert frozen["coverage_update"] == ready["coverage_pins"]["coverage_update"]
    assert frozen["coverage_document"] == ready["coverage_pins"]["coverage_document"]
    assert frozen["profile"] == ready["profile"] == EXPECTED_PROFILE
    assert frozen["build_manifest"] == ready["build"]["manifest"]
    assert frozen["build_dll"] == ready["build"]["dll"]
    assert frozen["manifest_native_sources"] == ready["build"]["native"]
    assert frozen["manifest_build_copies"] == ready["build"]["copies"]
    assert frozen["manifest_source_names"] == ready["build"]["names"]
    assert frozen["manifest_native_source_count"] == 125
    assert frozen["coverage_counts"]["field_counts"] == EXPECTED_FIELD_COUNTS
    expected_paths = ready["sources"]
    assert sorted(row["source"]["path"] for row in frozen["files"]) == expected_paths
    assert frozen["count"] == len(frozen["files"])
    for row in frozen["files"]:
        assert pin(row["source"]["path"]) == row["source"]
        snapshot = pin(row["snapshot"]["path"])
        assert snapshot == row["snapshot"]
        assert (snapshot["bytes"], snapshot["sha256"]) == (
            row["source"]["bytes"], row["source"]["sha256"])
    return frozen


def preflight_without_reservation() -> dict:
    """Re-run evidence/source preconditions without requiring empty output slots."""
    frozen, changes, build, baseline_pins, baseline_doc_snapshot = baseline_inputs()
    acceptance = acceptance_inputs()
    update, current_doc, coverage_pins = coverage_inputs(baseline_doc_snapshot)
    profile_pin = pin(EXPECTED_PROFILE["path"])
    assert profile_pin == EXPECTED_PROFILE
    paths = source_paths(frozen, build)
    return {
        "baseline_freeze": frozen,
        "baseline_reviewed_deltas": changes,
        "baseline_pins": baseline_pins,
        "build": build,
        "acceptance": acceptance,
        "coverage_update": update,
        "coverage_document": current_doc,
        "coverage_pins": coverage_pins,
        "profile": profile_pin,
        "sources": paths,
    }


def full() -> int:
    frozen = verify_sources()
    xml = STAGE / f"regression-full-{REVISION}.xml"
    log = STAGE / f"regression-full-{REVISION}.log"
    reservation = STAGE / f"full-execution-reservation-{REVISION}.json"
    boundary = STAGE / f"full-execution-boundary-{REVISION}.json"
    comparison_path = STAGE / f"regression-comparison-{REVISION}.json"
    postverify_path = STAGE / f"source-post-run-verification-{REVISION}.json"
    if any(path.exists() for path in (xml, log, reservation, boundary, comparison_path, postverify_path)):
        raise FileExistsError(f"batch80_full_{REVISION}_already_started")

    argv = [str(prior.PYTHON), "-B", "-m", "pytest", "-q", "bridge/tests",
            "--junitxml", str(xml)]
    write_new(reservation, {
        "runs": 1,
        "argv": argv,
        "freeze": pin(STAGE / f"source-freeze-{REVISION}.json"),
        "started_at": prior.stamp(),
    })
    with log.open("xb") as stream:
        result = subprocess.run(argv, cwd=ROOT, stdout=stream,
                                stderr=subprocess.STDOUT, check=False)
    write_new(boundary, {
        "returncode": result.returncode,
        "log": pin(log),
        "xml": pin(xml),
        "finished_at": prior.stamp(),
    })

    verify_sources()
    old = prior.bad_cases(BASE / "regression-full-001.xml")
    new = prior.bad_cases(xml)
    added, resolved = new - old, old - new
    value = {
        "schema": "information.province_details.regression_comparison.v1",
        "status": "passed_no_new_bad" if not added else "failed_new_bad",
        "batch": 80,
        "baseline": pin(BASE / "regression-full-001.xml"),
        "current": pin(xml),
        "log": pin(log),
        "baseline_bad_occurrences": sum(old.values()),
        "current_bad_occurrences": sum(new.values()),
        "new_bad": prior.counter_rows(added),
        "resolved_bad": prior.counter_rows(resolved),
        "no_new_bad": not added,
        "whole_suite_passed": result.returncode == 0,
        "returncode": result.returncode,
        "junit_summary": prior.junit_summary(xml),
    }
    write_new(comparison_path, value)
    freeze_pin = pin(STAGE / f"source-freeze-{REVISION}.json")
    write_new(postverify_path, {
        "status": value["status"],
        "batch": 80,
        "count": frozen["count"],
        "freeze": freeze_pin,
        "regression_comparison": pin(comparison_path),
        "current_sources_match_snapshots": True,
        "no_new_bad": not added,
        "whole_suite_passed": result.returncode == 0,
    })
    print(json.dumps(value, ensure_ascii=False))
    return 0 if not added else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("freeze", "verify", "full"))
    args = parser.parse_args(argv)
    if args.operation == "freeze":
        freeze()
        return 0
    if args.operation == "verify":
        frozen = verify_sources()
        print(json.dumps({"status": "passed", "count": frozen["count"]}))
        return 0
    return full()


if __name__ == "__main__":
    raise SystemExit(main())
