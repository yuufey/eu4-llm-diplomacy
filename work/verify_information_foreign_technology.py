"""Freeze batch-76 foreign-technology sources and run/compare bridge tests once."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import start_diplomacy_observer as _start  # noqa: E402

STAGE = ROOT / "work/runtime/information-foreign-visibility-20261029-001"
BASE = ROOT / "work/runtime/information-battle-control-text-20261029-001"
BASE_FREEZE = BASE / "source-freeze-001.json"
BASE_FULL = BASE / "regression-full-001.xml"
BASE_COMPARE = BASE / "regression-comparison-001.json"
BASE_POST = BASE / "source-post-run-verification-001.json"
BUILD_MANIFEST = ROOT / "work/runtime/diplomacy-observer-20261028-battle-context-v33-001/build-manifest.json"
DOC_CURRENT = ROOT / "docs/信息字段覆盖.json"
PYTHON = Path(r"C:\Users\wangyufei\anaconda3\envs\research\python.exe")
CHUNK = 1024 * 1024
BASE_COUNT, V33_COUNT = 611, 125
BASE_SCHEMA = "information.battle.control_text.source_freeze.v1"
CURRENT_SCHEMA = "information.foreign_technology.source_freeze.v1"

# Reviewed edits to baseline files; any other baseline delta blocks the freeze.
REVIEWED = {
    "tools/serve_information.py": "register NativeForeignTechnologySource for batch-76 F02 fields",
    "docs/信息字段覆盖.json": "mark military_technology and visibility partial; add the F02 source/adapter",
}

# New batch-76 foreign-technology implementation, proof fixtures, and scripts.
EXTRA = (
    "bridge/information/country_reference_memory.py",
    "bridge/information/country_view_admission_memory.py",
    "bridge/information/foreign_technology_memory.py",
    "bridge/information/foreign_technology_capture.py",
    "bridge/information/foreign_technology.py",
    "bridge/tests/test_information_country_reference_memory.py",
    "bridge/tests/test_information_country_view_admission_memory.py",
    "bridge/tests/test_information_foreign_technology_memory.py",
    "bridge/tests/test_information_foreign_technology_capture.py",
    "bridge/tests/test_information_foreign_technology.py",
    "bridge/tests/test_information_battle_text.py",
    "bridge/information/profiles/foreign-technology-memory-1374.json",
    "bridge/information/profiles/foreign-technology-memory-1374-v2.json",
    "work/create_information_foreign_technology_profile.py",
    "work/update_information_foreign_technology_coverage.py",
    "work/runtime/information-foreign-visibility-20261029-001/create_role_profile_002.py",
    "work/runtime/information-foreign-visibility-20261029-001/serve_archived_foreign_001.py",
    "work/runtime/information-foreign-visibility-20261029-001/validate_foreign_mcp_001.py",
    "tools/control_information_current_country.py",
    "work/probe_information_battle_event_world.py",
    "tools/serve_information.py",
    "docs/信息字段覆盖.json",
    "work/verify_information_foreign_technology.py",
)


def stamp():
    return datetime.now(timezone.utc).isoformat()


def workspace(raw):
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    path.relative_to(ROOT.resolve())
    return path


def pin(path):
    path = workspace(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    before = path.stat()
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while block := stream.read(CHUNK):
            digest.update(block)
            size += len(block)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise RuntimeError(f"file_changed_while_hashing:{path}")
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": size,
            "sha256": digest.hexdigest()}


def read_json(path):
    path = workspace(path)
    if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError(f"missing_or_oversized_json:{path}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_new(path, value):
    path = workspace(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def copy_stream(source, target):
    source, target = workspace(source), workspace(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        while block := incoming.read(CHUNK):
            outgoing.write(block)


def bad_cases(path):
    tree = ET.parse(workspace(path))
    return Counter((case.get("classname", ""), case.get("name", ""), child.tag)
                   for case in tree.iter("testcase") for child in case
                   if child.tag in ("failure", "error"))


def junit_summary(path):
    root = ET.parse(workspace(path)).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    names = ("tests", "failures", "errors", "skipped")
    return {name: sum(int(suite.get(name, "0")) for suite in suites) for name in names}


def counter_rows(counter):
    return [{"node": list(key), "count": count}
            for key, count in sorted(counter.items()) if count]


def coverage_counts(topics):
    fields = Counter(field["coverage"] for topic in topics for field in topic["fields"].values())
    statuses = Counter(topic["status"] for topic in topics)
    return {"topic_count": len(topics), "field_count": sum(fields.values()),
            "topic_status_counts": {key: statuses[key] for key in ("available", "partial", "planned")},
            "field_counts": {key: fields[key] for key in ("available", "partial", "planned")},
            "available_topic_count": statuses["available"],
            "callable_topic_count": statuses["available"]}


def coverage_doc_inputs(baseline_doc_snapshot):
    baseline_snapshot = pin(baseline_doc_snapshot)
    before = read_json(baseline_doc_snapshot)
    current = read_json(DOC_CURRENT)
    stage = STAGE
    live_path = stage / "mcp-live-001/receipt.json"
    discovery_path = stage / "mcp-live-001/discovery.json"
    update_path = stage / "coverage-update-001.json"
    live, discovery, update = read_json(live_path), read_json(discovery_path), read_json(update_path)
    if (live.get("status") != "passed" or live.get("server_exit_code") != 0
            or live.get("source_pins_unchanged") is not True):
        raise ValueError("coverage_doc_live_receipt_not_passed")
    if (update.get("status") != "updated_partial" or update.get("goal_complete") is not False
            or update.get("coverage_changes") != {
                "F02.military_technology": ["planned", "partial"],
                "F02.visibility": ["planned", "partial"]}
            or update.get("before_sha256") != baseline_snapshot["sha256"]
            or update.get("after_sha256") != pin(DOC_CURRENT)["sha256"]
            or update.get("scope") != "Only military technology and its observer-reindexed country-view predicate; actual UI and other F02 fields remain incomplete"):
        raise ValueError("coverage_update_receipt_mismatch")

    old_topics = before.get("topics")
    discovery_topics = discovery.get("topics")
    current_topics = current.get("topics")
    if not all(isinstance(value, list) for value in (old_topics, discovery_topics, current_topics)):
        raise ValueError("coverage_topic_lists_invalid")
    if len(old_topics) != 74 or len(discovery_topics) != 74 or len(current_topics) != 74:
        raise ValueError("coverage_topic_count_invalid")
    old_indices = [i for i, row in enumerate(old_topics)
                   if isinstance(row, dict) and row.get("topic_id") == "F02"]
    discovery_rows = [row for row in discovery_topics
                      if isinstance(row, dict) and row.get("topic_id") == "F02"]
    if len(old_indices) != 1 or len(discovery_rows) != 1:
        raise ValueError("coverage_F02_source_row_missing_or_duplicate")
    index = old_indices[0]
    old_f02, new_f02 = old_topics[index], discovery_rows[0]
    old_fields, new_fields = old_f02.get("fields"), new_f02.get("fields")
    if not isinstance(old_fields, dict) or not isinstance(new_fields, dict) or set(old_fields) != set(new_fields):
        raise ValueError("coverage_F02_field_shape_changed")
    if any(new_fields[key] != old_fields[key]
           for key in set(old_fields) - {"military_technology", "visibility"}):
        raise ValueError("coverage_F02_unrelated_field_changed")
    if any(old_fields[key].get("coverage") != "planned" or new_fields[key].get("coverage") != "partial"
           for key in ("military_technology", "visibility")):
        raise ValueError("coverage_F02_partial_transition_invalid")

    expected = deepcopy(before)
    expected_topics = deepcopy(old_topics)
    expected_topics[index] = deepcopy(new_f02)
    if current_topics != expected_topics:
        raise ValueError("coverage_topics_differ_from_mcp_discovery_or_old_matrix")
    expected["topics"] = expected_topics
    expected["F02"] = {key: deepcopy(new_f02[key])
                        for key in ("fields", "context_scope", "source", "adapter_sources")
                        if key in new_f02}
    adapters = expected.get("configuration", {}).get("adapters")
    if not isinstance(adapters, list) or "NativeForeignTechnologySource" in adapters:
        raise ValueError("coverage_doc_adapter_boundary_invalid")
    adapters.append("NativeForeignTechnologySource")
    actual_counts = coverage_counts(expected_topics)
    reviewed_counts = {
        "topic_count": 74, "field_count": 397,
        "topic_status_counts": {"available": 43, "partial": 4, "planned": 27},
        "field_counts": {"available": 62, "partial": 166, "planned": 169},
        "available_topic_count": 43, "callable_topic_count": 43,
    }
    if actual_counts != reviewed_counts or update.get("configured_counts") != reviewed_counts:
        raise ValueError("coverage_doc_counts_not_reviewed_F02_delta")
    if update.get("actual_live_counts") != coverage_counts(discovery_topics):
        raise ValueError("coverage_live_counts_receipt_mismatch")
    expected["counts"] = actual_counts
    expected["expected_counts"] = deepcopy(actual_counts)
    if current != expected:
        raise ValueError("coverage_doc_has_unreviewed_changes")
    return {"baseline_snapshot": baseline_snapshot, "current": pin(DOC_CURRENT),
            "mcp_receipt": pin(live_path), "mcp_discovery": pin(discovery_path),
            "coverage_update": pin(update_path),
            "only_change": {"paths": ["/configuration/adapters", "/F02", "/topics/F02",
                                       "/counts", "/expected_counts"],
                            "adapter_added": "NativeForeignTechnologySource",
                            "F02_topic_source": pin(discovery_path),
                            "partial_fields": ["military_technology", "visibility"],
                            "counts": reviewed_counts}}


def baseline_inputs():
    freeze = read_json(BASE_FREEZE)
    files = freeze.get("files", [])
    if (freeze.get("schema") != BASE_SCHEMA
            or freeze.get("status") != "passed" or freeze.get("batch") != 75
            or freeze.get("revision") != "001"
            or freeze.get("count") != BASE_COUNT or len(files) != BASE_COUNT):
        raise ValueError("batch75_baseline_not_passed_611_source_freeze_001")
    old, changes = {}, []
    for item in files:
        source, snapshot = item["source"], item["snapshot"]
        name = source["path"]
        if name in old or (source["bytes"], source["sha256"]) != (
                snapshot["bytes"], snapshot["sha256"]):
            raise ValueError(f"batch75_source_record_invalid:{name}")
        if pin(snapshot["path"]) != snapshot:
            raise ValueError(f"batch75_snapshot_changed:{name}")
        current = pin(name)
        if current != source:
            if name not in REVIEWED:
                raise ValueError(f"unreviewed_batch75_source_change:{name}")
            changes.append({"path": name, "before": source,
                            "after": current, "reason": REVIEWED[name]})
        old[name] = source
    comparison = read_json(BASE_COMPARE)
    base_full_pin = pin(BASE_FULL)
    baseline_bad_count = sum(bad_cases(BASE_FULL).values())
    baseline_summary = junit_summary(BASE_FULL)
    if (comparison.get("status") != "passed_no_new_bad"
            or comparison.get("new_bad") != []
            or comparison.get("current") != base_full_pin
            or comparison.get("baseline_bad_occurrences") != baseline_bad_count
            or comparison.get("current_bad_occurrences") != baseline_bad_count
            or comparison.get("resolved_bad") != []
            or comparison.get("no_new_bad") is not True
            or comparison.get("whole_suite_passed") is not False
            or comparison.get("returncode") != 1
            or baseline_bad_count != 141
            or baseline_summary != {"tests": 5490, "failures": 106, "errors": 35, "skipped": 0}):
        raise ValueError("batch75_counter_comparison_not_pinned")
    post = read_json(BASE_POST)
    if (post.get("status") != "passed_no_new_bad"
            or post.get("revision") != "001" or post.get("count") != BASE_COUNT
            or post.get("freeze") != pin(BASE_FREEZE)
            or post.get("regression_comparison") != pin(BASE_COMPARE)
            or post.get("no_new_bad") is not True
            or post.get("whole_suite_passed") is not False):
        raise ValueError("batch75_postverify_mismatch")
    late_test = "bridge/tests/test_information_battle_text.py"
    if late_test in old:
        raise ValueError("batch75_late_test_was_not_pre_full_in_baseline")
    doc_source = next((item["snapshot"]["path"] for item in files
                       if item["source"]["path"] == "docs/信息字段覆盖.json"), None)
    if doc_source is None:
        raise ValueError("batch75_coverage_doc_snapshot_missing")
    coverage = coverage_doc_inputs(doc_source)
    pins = {"freeze": pin(BASE_FREEZE), "full": base_full_pin,
            "comparison": pin(BASE_COMPARE), "postverify": pin(BASE_POST),
            "source_count": BASE_COUNT, "no_new_bad": True,
            "whole_suite_passed": False, "baseline_bad_occurrences": baseline_bad_count,
            "baseline_junit_summary": baseline_summary,
            "postverify_recorded_batch": post.get("batch"),
            "late_test_present_in_pre_full_baseline": late_test in old,
            "coverage_doc": coverage}
    return freeze, old, sorted(changes, key=lambda row: row["path"]), pins


def manifest_inputs(path):
    path = workspace(path)
    manifest = read_json(path)
    if (manifest.get("version") != 33 or manifest.get("compiled") is not True
            or manifest.get("runtime_verified") is not False
            or manifest.get("native_war_participants_query") is not True
            or len(manifest.get("sources", [])) != V33_COUNT):
        raise ValueError("v33_manifest_version_or_source_count_mismatch")
    if (any(key.startswith("current_country_control") for key in manifest)
            or any("host_fixture" in key.lower() for key in manifest)):
        raise ValueError("country_control_or_fixture_manifest_forbidden")
    args = manifest.get("compiler_arguments", [])
    if (_start._has_compiler_define(args, "BRIDGE_CURRENT_COUNTRY_CONTROL")
            or _start._has_compiler_define(args, "INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE")):
        raise ValueError("country_control_or_fixture_macro_forbidden")
    rows, native, copies, names = manifest["sources"], [], [], set()
    build_dir = path.parent.resolve()
    for row in rows:
        name, sha = row.get("name"), row.get("sha256")
        if not isinstance(name, str) or Path(name).name != name or name in names:
            raise ValueError("v33_manifest_source_name_invalid")
        names.add(name)
        native_path, copy_path = workspace(ROOT / "work/native" / name), workspace(build_dir / name)
        if pin(native_path)["sha256"] != sha or pin(copy_path)["sha256"] != sha:
            raise ValueError(f"v33_source_or_build_copy_mismatch:{name}")
        native.append(native_path.relative_to(ROOT).as_posix())
        copies.append(copy_path.relative_to(ROOT).as_posix())
    required = set(_start.INFORMATION_BATTLE_DISPLAY_CONTEXT_REQUIRED_SOURCES)
    if (not required.issubset(names)
            or names.intersection(_start.INFORMATION_CURRENT_COUNTRY_CONTROL_ONLY_SOURCES)):
        raise ValueError("v33_required_or_forbidden_native_source_mismatch")
    try:
        _start._validate_information_battle_manifest(manifest, build_dir)
    except SystemExit as exc:
        raise ValueError("start_validator_rejected_v33_manifest") from exc
    dll = workspace(manifest.get("dll", ""))
    if dll.name != "eu4_bridge_diplomacy_observer_v33.dll" or dll.parent != build_dir:
        raise ValueError("v33_dll_path_mismatch")
    dll_pin = pin(dll)
    if dll_pin["sha256"] != manifest.get("dll_sha256"):
        raise ValueError("v33_dll_sha_mismatch")
    return {"manifest": pin(path), "dll": dll_pin, "native": native,
            "copies": copies, "names": [row["name"] for row in rows]}


def source_union(baseline, build):
    return sorted(set([row["source"]["path"] for row in baseline["files"]]
                      + list(EXTRA) + build["native"] + build["copies"]))


def preflight(manifest_path):
    missing = [name for name in EXTRA if not (ROOT / name).is_file()]
    if missing:
        raise FileNotFoundError(f"required_batch76_source_missing:{missing}")
    baseline, old, changes, baseline_pins = baseline_inputs()
    if {row["path"] for row in changes} != set(REVIEWED):
        raise ValueError("batch75_reviewed_delta_set_mismatch")
    build = manifest_inputs(manifest_path)
    validate_build_inheritance(baseline, build)
    paths = source_union(baseline, build)
    if "bridge/tests/test_information_battle_text.py" not in paths:
        raise ValueError("late_test_not_in_batch76_pre_full_union")
    if not PYTHON.is_file():
        raise FileNotFoundError(f"research_python_missing:{PYTHON}")
    reserved = [STAGE / f"{prefix}-001{suffix}" for prefix, suffix in (
        ("source-freeze", ".json"), ("regression-full", ".xml"),
        ("regression-full", ".log"), ("regression-comparison", ".json"),
        ("source-post-run-verification", ".json"),)]
    if any(path.exists() for path in reserved) or (STAGE / "source-snapshots-001").exists():
        raise FileExistsError("batch76_revision_001_already_used")
    return {"baseline_count": len(old), "baseline_pins": baseline_pins,
            "reviewed_baseline_deltas": changes, "build_manifest": build,
            "selected_source_count": len(paths), "selected_sources": paths}


def validate_build_inheritance(baseline, build):
    if (baseline.get("manifest_native_source_count") != V33_COUNT
            or baseline.get("build_manifest") != build["manifest"]
            or baseline.get("build_dll") != build["dll"]
            or baseline.get("manifest_native_sources") != build["native"]
            or baseline.get("manifest_build_copies") != build["copies"]
            or baseline.get("manifest_source_names") != build["names"]):
        raise ValueError("v33_build_or_125_sources_changed_since_batch74")


def freeze(revision, manifest_path):
    output, snapdir = STAGE / f"source-freeze-{revision}.json", STAGE / f"source-snapshots-{revision}"
    if output.exists() or snapdir.exists():
        raise FileExistsError("freeze_revision_already_used")
    missing = [name for name in EXTRA if not (ROOT / name).is_file()]
    if missing:
        raise FileNotFoundError(f"required_batch76_source_missing:{missing}")
    baseline, old, changes, baseline_pins = baseline_inputs()
    if {row["path"] for row in changes} != set(REVIEWED):
        raise ValueError("batch75_reviewed_delta_set_mismatch")
    if not PYTHON.is_file():
        raise FileNotFoundError(f"research_python_missing:{PYTHON}")
    build = manifest_inputs(manifest_path)
    validate_build_inheritance(baseline, build)
    coverage = baseline_pins["coverage_doc"]
    paths = source_union(baseline, build)
    before = {name: pin(name) for name in paths}
    snapdir.mkdir(parents=True, exist_ok=False)
    files = []
    for name in paths:
        target = (snapdir / Path(name)).resolve()
        target.relative_to(snapdir.resolve())
        copy_stream(name, target)
        snap = pin(target)
        if snap["sha256"] != before[name]["sha256"] or pin(name) != before[name]:
            raise ValueError(f"source_changed_during_freeze:{name}")
        files.append({"source": before[name], "snapshot": snap})
    baseline_names = set(old)
    value = {
        "schema": CURRENT_SCHEMA,
        "status": "passed", "batch": 76, "revision": revision,
        "count": len(files), "baseline": baseline_pins,
        "baseline_reviewed_deltas": changes,
        "coverage_doc_change": coverage,
        "build_manifest": build["manifest"], "build_dll": build["dll"],
        "manifest_native_source_count": len(build["native"]),
        "manifest_native_sources": build["native"], "manifest_build_copies": build["copies"],
        "manifest_source_names": build["names"], "required_batch76_sources": list(EXTRA),
        "late_source_boundary": {
            "path": "bridge/tests/test_information_battle_text.py",
            "in_batch75_pre_full_freeze": False,
            "in_batch76_pre_full_extra": True,
            "prior_pin_scope": "during_full_only",
        },
        "additional_sources": [name for name in paths if name not in baseline_names],
        "hash_chunk_bytes": CHUNK, "files": files,
    }
    write_new(output, value)
    print(json.dumps({"status": "passed", "phase": "freeze", "revision": revision,
                      "batch": 76, "count": len(files), "baseline_count": BASE_COUNT,
                      "reviewed_baseline_deltas": len(changes),
                      "v33_native_sources": len(build["native"]),
                      "build_source_copies": len(build["copies"])}))


def verify_sources(revision):
    frozen = read_json(STAGE / f"source-freeze-{revision}.json")
    if (frozen.get("schema") != CURRENT_SCHEMA or frozen.get("status") != "passed"
            or frozen.get("revision") != revision or frozen.get("batch") != 76):
        raise ValueError("invalid_batch76_freeze")
    baseline, old, changes, baseline_pins = baseline_inputs()
    if frozen.get("baseline") != baseline_pins or frozen.get("baseline_reviewed_deltas") != changes:
        raise ValueError("batch75_baseline_changed_since_freeze")
    manifest_path = frozen["build_manifest"]["path"]
    build = manifest_inputs(manifest_path)
    validate_build_inheritance(baseline, build)
    if (build["manifest"] != frozen["build_manifest"] or build["dll"] != frozen["build_dll"]
            or build["native"] != frozen["manifest_native_sources"]
            or build["copies"] != frozen["manifest_build_copies"]
            or build["names"] != frozen["manifest_source_names"]):
        raise ValueError("v33_manifest_or_build_changed_since_freeze")
    if frozen.get("coverage_doc_change") != baseline_pins["coverage_doc"]:
        raise ValueError("coverage_doc_change_pin_mismatch")
    expected = set(source_union(baseline, build))
    if frozen.get("required_batch76_sources") != list(EXTRA):
        raise ValueError("batch76_source_list_changed")
    if frozen.get("late_source_boundary") != {
            "path": "bridge/tests/test_information_battle_text.py",
            "in_batch75_pre_full_freeze": False,
            "in_batch76_pre_full_extra": True,
            "prior_pin_scope": "during_full_only"}:
        raise ValueError("late_source_boundary_changed")
    seen = set()
    for row in frozen["files"]:
        src, snap = row["source"], row["snapshot"]
        name = src["path"]
        if name in seen or pin(name) != src or pin(snap["path"]) != snap:
            raise ValueError(f"frozen_source_or_snapshot_changed:{name}")
        seen.add(name)
    if seen != expected or frozen.get("count") != len(expected):
        raise ValueError("batch76_source_union_mismatch")
    return frozen


def full(revision):
    frozen = verify_sources(revision)
    xml, log = STAGE / f"regression-full-{revision}.xml", STAGE / f"regression-full-{revision}.log"
    reservation = STAGE / f"full-execution-reservation-{revision}.json"
    boundary = STAGE / f"full-execution-boundary-{revision}.json"
    if any(path.exists() for path in (xml, log, reservation, boundary)):
        raise FileExistsError("full_revision_already_used")
    command = [str(PYTHON), "-B", "-m", "pytest", "-q", "bridge/tests", "--junitxml", str(xml)]
    write_new(reservation, {"revision": revision, "runs": 1, "command": command,
                            "freeze": pin(STAGE / f"source-freeze-{revision}.json"),
                            "frozen_source_count": frozen["count"], "started_at_utc": stamp()})
    with log.open("xb") as stream:
        result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, check=False)
    write_new(boundary, {"status": "completed", "revision": revision, "runs": 1,
                         "returncode": result.returncode, "command": command,
                         "reservation": pin(reservation), "xml": pin(xml), "log": pin(log),
                         "finished_at_utc": stamp()})
    verify_sources(revision)
    base, current = bad_cases(BASE_FULL), bad_cases(xml)
    new, resolved = current - base, base - current
    no_new = not new
    comparison = {
        "status": "passed_no_new_bad" if no_new else "failed_new_bad",
        "baseline": pin(BASE_FULL), "current": pin(xml), "log": pin(log),
        "baseline_bad_occurrences": sum(base.values()), "current_bad_occurrences": sum(current.values()),
        "new_bad": counter_rows(new), "resolved_bad": counter_rows(resolved),
        "no_new_bad": no_new, "whole_suite_passed": result.returncode == 0,
        "returncode": result.returncode,
    }
    compare_path = STAGE / f"regression-comparison-{revision}.json"
    write_new(compare_path, comparison)
    post = {"status": "passed_no_new_bad" if no_new else "failed_new_bad",
            "batch": 76, "revision": revision, "count": frozen["count"],
            "freeze": pin(STAGE / f"source-freeze-{revision}.json"),
            "current_sources_match_snapshots": True,
            "regression_comparison": pin(compare_path),
            "baseline_bad_occurrences": sum(base.values()),
            "current_bad_occurrences": sum(current.values()),
            "new_bad_occurrences": sum(new.values()), "no_new_bad": no_new,
            "whole_suite_passed": result.returncode == 0,
            "interpretation": "No added failure/error nodes versus baseline; this does not mean the suite is green.",
            "hash_chunk_bytes": CHUNK}
    write_new(STAGE / f"source-post-run-verification-{revision}.json", post)
    print(json.dumps({"phase": "full", "revision": revision,
                      "batch": 76, "status": comparison["status"], "new_bad_nodes": len(new),
                      "whole_suite_passed": result.returncode == 0,
                      "returncode": result.returncode}))
    return 0 if no_new else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preflight", "freeze", "full"))
    parser.add_argument("--revision", type=int, default=1)
    parser.add_argument("--build-manifest", type=Path, default=BUILD_MANIFEST)
    args = parser.parse_args(argv)
    if not 1 <= args.revision <= 999:
        parser.error("--revision must be in 1..999")
    revision = f"{args.revision:03d}"
    try:
        if args.operation == "preflight":
            result = preflight(workspace(args.build_manifest))
            print(json.dumps({"status": "passed", "phase": "preflight", "batch": 76,
                              "baseline_count": result["baseline_count"],
                              "selected_source_count": result["selected_source_count"],
                              "reviewed_baseline_deltas": result["reviewed_baseline_deltas"],
                              "v33_native_sources": len(result["build_manifest"]["native"]),
                              "build_source_copies": len(result["build_manifest"]["copies"]),
                              "late_test_in_pre_full_union": True}))
            return 0
        if args.operation == "freeze":
            freeze(revision, workspace(args.build_manifest))
            return 0
        return full(revision)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print(json.dumps({"status": "failed", "operation": args.operation,
                          "revision": revision, "error": f"{type(exc).__name__}:{exc}"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
