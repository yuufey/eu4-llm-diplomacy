"""Batch 70 freeze, full-suite, regression comparison, and post-run verification.

The 179 batch-69 sources are reused from freeze004, then the five country-rivals
runtime sources are added. Publication helpers are pinned separately and do not
become runtime-freeze members. No game, MCP, native, RPM, or live work occurs.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASELINE = (
    ROOT / "work/runtime/information-country-force-resources-20261027-001"
).resolve()
STAGE = (
    ROOT / "work/runtime/information-diplomacy-state-20261028-001"
).resolve()
BASELINE_FREEZE = BASELINE / "source-freeze-004.json"
BASELINE_FULL = BASELINE / "regression-full-004.xml"
BASELINE_COMPARISON = BASELINE / "regression-comparison-004.json"
CHUNK_BYTES = 1024 * 1024

ADDITIONAL_SOURCES = (
    "bridge/information/country_rivals.py",
    "bridge/information/country_rivals_memory.py",
    "bridge/information/profiles/country-rivals-memory-1374.json",
    "bridge/tests/test_information_country_rivals.py",
    "bridge/tests/test_information_country_rivals_memory.py",
)

SEPARATE_HELPERS = (
    "work/verify_information_country_rivals.py",
    "work/finalize_information_country_rivals.py",
    "work/archive_information_country_rivals.py",
)

# The prior snapshots remain immutable.  Two current files intentionally differ:
# the batch-70 route, and the separately recorded batch-69 archive-only repair.
EXPECTED_SOURCE_CHANGES = {
    "tools/serve_information.py": {
        "before": "b49682bb150fcb7d78ac948100d9a731e7410589ef8cc6f1eccc46dd3a7516c0",
        "after": "f8b85063127826e4a8d4e44abfe8357adf3e0b73a35798c1e84865f8b8243ea5",
        "reason": "batch70 adds NativeCountryRivalsSource to the existing service factory",
    },
    "work/archive_information_military_resources.py": {
        "before": "3f772cd1cca8b32c58f9f18715f7d4d91902558390641eb6a0d461fd8a292aa7",
        "after": "2225bf30bc6c257fe099bfab27316181047b901fb6564ee45561b5d25922a94e",
        "reason": "batch69 final-readback-001 records archive-helper-recovery-amendment-003",
    },
}


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def relative_path(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def normalize_source(raw: str) -> str:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    candidate = candidate.resolve()
    try:
        return candidate.relative_to(ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"source_outside_root:{raw}") from exc


def pin(path: Path) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return {"path": relative_path(path), "bytes": size, "sha256": digest.hexdigest()}


def write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _validated_baseline() -> tuple[dict, dict]:
    baseline = read_json(BASELINE_FREEZE)
    files = baseline.get("files")
    if baseline.get("status") != "passed" or baseline.get("batch") != 69:
        raise ValueError("invalid_batch69_freeze004")
    if not isinstance(files, list) or baseline.get("count") != 179 or len(files) != 179:
        raise ValueError("batch69_freeze004_expected_179_sources")

    seen: set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("invalid_batch69_freeze004_entry")
        source, snapshot = item.get("source"), item.get("snapshot")
        if not isinstance(source, dict) or not isinstance(snapshot, dict):
            raise ValueError("invalid_batch69_freeze004_pins")
        source_name = normalize_source(str(source.get("path", "")))
        if source_name in seen:
            raise ValueError("duplicate_batch69_freeze004_source:" + source_name)
        seen.add(source_name)
        if source.get("bytes") != snapshot.get("bytes") or source.get("sha256") != snapshot.get("sha256"):
            raise ValueError("batch69_freeze004_snapshot_mismatch:" + source_name)
        current = pin(ROOT / source_name)
        change = EXPECTED_SOURCE_CHANGES.get(source_name)
        if change is None:
            if current != source:
                raise ValueError("unreviewed_batch69_source_change:" + source_name)
        elif (source["sha256"] != change["before"] or current["sha256"] != change["after"]):
            raise ValueError("reviewed_source_change_pin_mismatch:" + source_name)
        snapshot_name = normalize_source(str(snapshot.get("path", "")))
        if pin(ROOT / snapshot_name) != snapshot:
            raise ValueError("batch69_snapshot_changed:" + snapshot_name)

    comparison = read_json(BASELINE_COMPARISON)
    if comparison.get("no_new_bad") is not True:
        raise ValueError("batch69_full004_baseline_not_no_new_bad")
    if not BASELINE_FULL.is_file():
        raise FileNotFoundError(BASELINE_FULL)
    return baseline, comparison


def _metadata_helper_pins() -> list[dict]:
    result = []
    for name in SEPARATE_HELPERS:
        path = ROOT / name
        if path.is_file():
            result.append(pin(path))
    return result


def _source_paths(extra_sources: list[str]) -> tuple[dict, dict, list[str]]:
    baseline, comparison = _validated_baseline()
    paths: list[str] = []
    seen: set[str] = set()
    for item in baseline["files"]:
        name = normalize_source(item["source"]["path"])
        seen.add(name)
        paths.append(name)

    fixed_names = [normalize_source(name) for name in ADDITIONAL_SOURCES]
    if len(set(fixed_names)) != len(fixed_names):
        raise ValueError("duplicate_batch70_fixed_source")
    overlap = seen.intersection(fixed_names)
    if overlap:
        raise ValueError("batch70_fixed_source_already_in_baseline:" + ",".join(sorted(overlap)))

    separate = set(SEPARATE_HELPERS)
    for raw_name in (*ADDITIONAL_SOURCES, *extra_sources):
        name = normalize_source(raw_name)
        if name in separate:
            raise ValueError("metadata_helper_excluded_from_runtime_freeze:" + name)
        if name in seen:
            continue
        if not (ROOT / name).is_file():
            raise FileNotFoundError(ROOT / name)
        seen.add(name)
        paths.append(name)
    return baseline, comparison, paths


def _copy_stream(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as src, target.open("xb") as dst:
        while True:
            chunk = src.read(CHUNK_BYTES)
            if not chunk:
                break
            dst.write(chunk)


def _verify_frozen(revision: str) -> tuple[dict, int]:
    freeze_path = STAGE / f"source-freeze-{revision}.json"
    frozen = read_json(freeze_path)
    files = frozen.get("files")
    if frozen.get("status") != "passed" or frozen.get("batch") != 70:
        raise ValueError("invalid_batch70_source_freeze")
    if not isinstance(files, list) or frozen.get("count") != len(files):
        raise ValueError("batch70_source_count_mismatch")

    separate_names = set(SEPARATE_HELPERS)
    mismatches = []
    for item in files:
        source, snapshot = item["source"], item["snapshot"]
        source_name = normalize_source(source["path"])
        if source_name in separate_names:
            raise ValueError("metadata_helper_in_runtime_freeze:" + source_name)
        if pin(ROOT / source_name) != source:
            mismatches.append(source_name + ":source")
        snapshot_name = normalize_source(snapshot["path"])
        if pin(ROOT / snapshot_name) != snapshot:
            mismatches.append(snapshot_name + ":snapshot")
    if mismatches:
        raise ValueError("frozen_source_changed:" + ",".join(mismatches))
    return frozen, len(files)


def freeze(revision: str, extra_sources: list[str]) -> int:
    output = STAGE / f"source-freeze-{revision}.json"
    if output.exists():
        raise FileExistsError(output)
    baseline, comparison, paths = _source_paths(extra_sources)
    metadata_pins = _metadata_helper_pins()
    files = []
    for name in paths:
        source = ROOT / name
        before = pin(source)
        snapshot = STAGE / f"source-snapshots-{revision}" / name
        _copy_stream(source, snapshot)
        copied = pin(snapshot)
        if copied["bytes"] != before["bytes"] or copied["sha256"] != before["sha256"]:
            raise ValueError("snapshot_hash_mismatch:" + name)
        if pin(source) != before:
            raise ValueError("source_changed_during_freeze:" + name)
        files.append({"source": before, "snapshot": copied})

    value = {
        "schema": "information.country_rivals.source_freeze.v1",
        "status": "passed",
        "batch": 70,
        "count": len(files),
        "baseline": {
            "freeze": pin(BASELINE_FREEZE),
            "full": pin(BASELINE_FULL),
            "comparison": pin(BASELINE_COMPARISON),
            "source_count": baseline["count"],
            "batch": baseline["batch"],
            "no_new_bad": comparison["no_new_bad"],
        },
        "additional_sources": list(ADDITIONAL_SOURCES),
        "reviewed_changes_to_existing_paths": EXPECTED_SOURCE_CHANGES,
        "extra_sources_requested": list(extra_sources),
        "deduplicated": True,
        "hash_chunk_bytes": CHUNK_BYTES,
        "separate_metadata_helpers": {
            "runtime_freeze_member": False,
            "snapshots_managed_by_root": True,
            "pins_scope": "observed_at_freeze_only; publication qualification is separate",
            "not_yet_present": [name for name in SEPARATE_HELPERS if not (ROOT / name).is_file()],
            "pins": metadata_pins,
        },
        "files": files,
    }
    write_new(output, value)
    print(json.dumps({"status": "passed", "phase": "freeze", "count": len(files)}))
    return 0


def full(revision: str) -> int:
    # A full run is one-shot per revision and requires an exact frozen source set.
    _verify_frozen(revision)
    xml = STAGE / f"regression-full-{revision}.xml"
    log = STAGE / f"regression-full-{revision}.log"
    receipt = STAGE / f"full-execution-boundary-{revision}.json"
    if any(path.exists() for path in (xml, log, receipt)):
        raise FileExistsError("refusing repeated full execution")
    command = [sys.executable, "-B", "-m", "pytest", "-q", "bridge/tests",
               "--junitxml", str(xml)]
    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    STAGE.mkdir(parents=True, exist_ok=True)
    with log.open("x", encoding="utf-8", newline="\n") as stream:
        result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
    write_new(receipt, {
        "schema": "information.country_rivals.full_execution_boundary.v1",
        "batch": 70,
        "command": command,
        "started_at": started_at,
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "returncode": result.returncode,
        "runs": 1,
        "xml": pin(xml) if xml.exists() else None,
        "log": pin(log),
    })
    print(json.dumps({"phase": "full", "returncode": result.returncode, "runs": 1}))
    return result.returncode


def compare(revision: str) -> int:
    current = STAGE / f"regression-full-{revision}.xml"
    log = STAGE / f"regression-full-{revision}.log"
    output = STAGE / f"regression-comparison-{revision}.json"
    if not BASELINE_FULL.is_file() or not current.is_file() or not log.is_file():
        raise FileNotFoundError("baseline/current XML and log are required")
    if output.exists():
        raise FileExistsError(output)
    baseline_comparison = read_json(BASELINE_COMPARISON)
    baseline_no_new_bad = baseline_comparison.get("no_new_bad")
    if not isinstance(baseline_no_new_bad, bool):
        raise ValueError("invalid_batch69_baseline_no_new_bad")

    from work.compare_information_battle_native_title_regression import compare as compare_xml

    value = compare_xml(BASELINE_FULL, current)
    value["schema"] = "information.country_rivals.regression_comparison.v1"
    value["batch"] = 70
    value["baseline_batch"] = 69
    value["baseline_full_path"] = relative_path(BASELINE_FULL)
    value["baseline_comparison_path"] = relative_path(BASELINE_COMPARISON)
    value["baseline_no_new_bad"] = baseline_no_new_bad
    value["no_new_bad"] = (
        baseline_no_new_bad
        and not value["new_failure_nodes"]
        and not value["new_test_failures"]
    )
    if not baseline_no_new_bad:
        value["status"] = "baseline_has_new_bad"
    write_new(output, value)
    print(json.dumps({
        "status": value["status"],
        "phase": "compare",
        "baseline_no_new_bad": baseline_no_new_bad,
        "new_failure_nodes": len(value["new_failure_nodes"]),
        "new_test_failures": len(value["new_test_failures"]),
    }))
    return 0 if value["no_new_bad"] else 2


def verify(revision: str) -> int:
    frozen, count = _verify_frozen(revision)
    output = STAGE / f"source-post-run-verification-{revision}.json"
    if output.exists():
        raise FileExistsError(output)
    value = {
        "schema": "information.country_rivals.source_post_run_verification.v1",
        "status": "passed",
        "batch": 70,
        "count": count,
        "freeze": pin(STAGE / f"source-freeze-{revision}.json"),
        "current_matches_snapshots": True,
        "hash_chunk_bytes": CHUNK_BYTES,
        "timing": "after batch70 full and acceptance processes have exited",
        "source_freeze_status": frozen["status"],
        "separate_metadata_helpers_in_runtime_freeze": False,
        "metadata_helper_snapshots_managed_by_root": True,
    }
    write_new(output, value)
    print(json.dumps({"status": "passed", "phase": "verify", "count": count}))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("freeze", "full", "compare", "verify"))
    parser.add_argument("--revision", type=int, choices=tuple(range(1, 10)), default=1,
                        help="use a new revision only after an actual source change")
    parser.add_argument("--extra-source", action="append", default=[], metavar="PATH",
                        help="repeatable required runtime source path; missing paths fail freeze")
    args = parser.parse_args()
    revision = f"{args.revision:03d}"
    extra_sources = [normalize_source(path) for path in args.extra_source]
    if args.phase == "freeze":
        return freeze(revision, extra_sources)
    if args.phase == "full":
        return full(revision)
    if args.phase == "compare":
        return compare(revision)
    return verify(revision)


if __name__ == "__main__":
    raise SystemExit(main())
