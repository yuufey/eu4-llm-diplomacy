"""Freeze batch-75 control-text sources and run/compare bridge tests once."""
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

STAGE = ROOT / "work/runtime/information-battle-control-text-20261029-001"
BASE = ROOT / "work/runtime/information-battle-event-context-20261028-001"
BASE_FREEZE = BASE / "source-freeze-002.json"
BASE_FULL = BASE / "regression-full-002.xml"
BASE_COMPARE = BASE / "regression-comparison-002.json"
BASE_POST = BASE / "source-post-run-verification-002.json"
BUILD_MANIFEST = ROOT / "work/runtime/diplomacy-observer-20261028-battle-context-v33-001/build-manifest.json"
DOC_REFERENCE = ROOT / "work/runtime/information-diplomacy-state-20261028-001/document-snapshots/docs/信息字段覆盖.json"
DOC_CURRENT = ROOT / "docs/信息字段覆盖.json"
PYTHON = Path(sys.executable)
CHUNK = 1024 * 1024
BASE_COUNT, V33_COUNT = 603, 125
BASE_SCHEMA = "information.battle.event_context.source_freeze.v1"
CURRENT_SCHEMA = "information.battle.control_text.source_freeze.v1"

# Reviewed edits to baseline files; any other baseline delta blocks the freeze.
REVIEWED = {
    "bridge/information/battle_display.py": "batch75 virtual frame request projection",
    "bridge/information/battles.py": "batch75 B04 projection integration",
    "bridge/tests/test_information_battle_display.py": "batch75 display projection coverage",
    "bridge/tests/test_information_battle_display_sides.py": "batch75 display sides coverage",
    "bridge/tests/test_information_battle_text.py": "batch75 native text projection coverage",
    "bridge/tests/test_information_battle_native_text.py": "batch75 native text coverage",
    "bridge/tests/test_information_battle_display_context_integration.py": "batch75 display context integration coverage",
}

# New batch-75 frame projection/assets/tests and owned CRT test sources.
EXTRA = (
    "bridge/information/battle_control_frames.py",
    "bridge/information/battle_control_frame_assets.py",
    "bridge/tests/test_information_battle_control_frames.py",
    "bridge/tests/test_information_battle_control_frames_integration.py",
    "work/native/tests/information-battle-frame-crt-test.cpp",
    "work/native/tests/information-battle-frame-crt-runner.py",
    "docs/信息字段覆盖.json",
    "work/verify_information_battle_control_text.py",
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


def counter_rows(counter):
    return [{"node": list(key), "count": count}
            for key, count in sorted(counter.items()) if count]


def coverage_doc_inputs():
    reference = read_json(DOC_REFERENCE)
    current = read_json(DOC_CURRENT)
    expected = deepcopy(reference)
    adapters = expected["configuration"]["adapters"]
    if "NativeCountryRivalsSource" in adapters:
        raise ValueError("coverage_reference_already_contains_batch75_adapter")
    adapters.insert(2, "NativeCountryRivalsSource")
    if current != expected:
        raise ValueError("coverage_doc_has_unreviewed_changes")
    return {"reference": pin(DOC_REFERENCE), "current": pin(DOC_CURRENT),
            "only_change": {"path": "/configuration/adapters",
                            "inserted_at": 2,
                            "value": "NativeCountryRivalsSource"}}


def baseline_inputs():
    freeze = read_json(BASE_FREEZE)
    files = freeze.get("files", [])
    if (freeze.get("schema") != BASE_SCHEMA
            or freeze.get("status") != "passed" or freeze.get("batch") != 74
            or freeze.get("revision") != "002"
            or freeze.get("count") != BASE_COUNT or len(files) != BASE_COUNT):
        raise ValueError("batch74_baseline_not_passed_603_source_freeze_002")
    old, changes = {}, []
    for item in files:
        source, snapshot = item["source"], item["snapshot"]
        name = source["path"]
        if name in old or (source["bytes"], source["sha256"]) != (
                snapshot["bytes"], snapshot["sha256"]):
            raise ValueError(f"batch74_source_record_invalid:{name}")
        if pin(snapshot["path"]) != snapshot:
            raise ValueError(f"batch74_snapshot_changed:{name}")
        current = pin(name)
        if current != source:
            if name not in REVIEWED:
                raise ValueError(f"unreviewed_batch74_source_change:{name}")
            changes.append({"path": name, "before": source,
                            "after": current, "reason": REVIEWED[name]})
        old[name] = source
    comparison = read_json(BASE_COMPARE)
    base_full_pin = pin(BASE_FULL)
    baseline_bad_count = sum(bad_cases(BASE_FULL).values())
    if (comparison.get("status") != "passed_no_new_bad"
            or comparison.get("new_bad") != []
            or comparison.get("current") != base_full_pin
            or comparison.get("baseline_bad_occurrences") != baseline_bad_count
            or comparison.get("current_bad_occurrences") != baseline_bad_count
            or comparison.get("no_new_bad") is not True
            or comparison.get("whole_suite_passed") is not False
            or comparison.get("returncode") == 0):
        raise ValueError("batch74_counter_comparison_not_pinned")
    post = read_json(BASE_POST)
    if (post.get("status") != "passed_no_new_bad" or post.get("batch") != 74
            or post.get("revision") != "002" or post.get("count") != BASE_COUNT
            or post.get("freeze") != pin(BASE_FREEZE)
            or post.get("regression_comparison") != pin(BASE_COMPARE)
            or post.get("no_new_bad") is not True
            or post.get("whole_suite_passed") is not False):
        raise ValueError("batch74_postverify_mismatch")
    coverage = coverage_doc_inputs()
    pins = {"freeze": pin(BASE_FREEZE), "full": base_full_pin,
            "comparison": pin(BASE_COMPARE), "postverify": pin(BASE_POST),
            "source_count": BASE_COUNT, "no_new_bad": True,
            "whole_suite_passed": False, "coverage_doc": coverage}
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
    baseline, old, changes, baseline_pins = baseline_inputs()
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
        "status": "passed", "batch": 75, "revision": revision,
        "count": len(files), "baseline": baseline_pins,
        "baseline_reviewed_deltas": changes,
        "coverage_doc_change": coverage,
        "build_manifest": build["manifest"], "build_dll": build["dll"],
        "manifest_native_source_count": len(build["native"]),
        "manifest_native_sources": build["native"], "manifest_build_copies": build["copies"],
        "manifest_source_names": build["names"], "required_batch75_sources": list(EXTRA),
        "additional_sources": [name for name in paths if name not in baseline_names],
        "hash_chunk_bytes": CHUNK, "files": files,
    }
    write_new(output, value)
    print(json.dumps({"status": "passed", "phase": "freeze", "revision": revision,
                      "batch": 75, "count": len(files), "baseline_count": BASE_COUNT,
                      "reviewed_baseline_deltas": len(changes),
                      "v33_native_sources": len(build["native"]),
                      "build_source_copies": len(build["copies"])}))


def verify_sources(revision):
    frozen = read_json(STAGE / f"source-freeze-{revision}.json")
    if (frozen.get("schema") != CURRENT_SCHEMA or frozen.get("status") != "passed"
            or frozen.get("revision") != revision or frozen.get("batch") != 75):
        raise ValueError("invalid_batch75_freeze")
    baseline, old, changes, baseline_pins = baseline_inputs()
    if frozen.get("baseline") != baseline_pins or frozen.get("baseline_reviewed_deltas") != changes:
        raise ValueError("batch74_baseline_changed_since_freeze")
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
    if frozen.get("required_batch75_sources") != list(EXTRA):
        raise ValueError("batch75_source_list_changed")
    seen = set()
    for row in frozen["files"]:
        src, snap = row["source"], row["snapshot"]
        name = src["path"]
        if name in seen or pin(name) != src or pin(snap["path"]) != snap:
            raise ValueError(f"frozen_source_or_snapshot_changed:{name}")
        seen.add(name)
    if seen != expected or frozen.get("count") != len(expected):
        raise ValueError("batch75_source_union_mismatch")
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
            "batch": 74, "revision": revision, "count": frozen["count"],
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
                      "status": comparison["status"], "new_bad_nodes": len(new),
                      "whole_suite_passed": result.returncode == 0,
                      "returncode": result.returncode}))
    return 0 if no_new else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("freeze", "full"))
    parser.add_argument("--revision", type=int, default=1)
    parser.add_argument("--build-manifest", type=Path, default=BUILD_MANIFEST)
    args = parser.parse_args(argv)
    if not 1 <= args.revision <= 999:
        parser.error("--revision must be in 1..999")
    revision = f"{args.revision:03d}"
    try:
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
