"""Prepare and run the batch-100 bridge suite in bounded serial pytest parts.

This runner inherits the accepted batch-97 source freeze and bad-case counter.
The suite may retain historical failures: no-new-bad and whole-suite-passed are
reported independently. Importing this module does not collect or execute tests.
"""
from __future__ import annotations

import argparse
import collections
import copy
import datetime as dt
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work import verify_information_war_income_bounded as monitor_runner  # noqa: E402

common = monitor_runner.common
RESEARCH_PYTHON = common.PYTHON

DEFAULT_STAGE = ROOT / "work/runtime/information-debt-quote-query-20261101-001"
BASELINE_STAGE = ROOT / "work/runtime/information-bankruptcy-visibility-20261101-001"
BASELINE_FREEZE = BASELINE_STAGE / "source-freeze-001.json"
BASELINE_COMPARISON = BASELINE_STAGE / "regression-comparison-001.json"
BASELINE_POSTVERIFY = BASELINE_STAGE / "source-post-run-verification-001.json"
BASELINE_XML = BASELINE_STAGE / "bounded-full-001/regression-full-001.xml"

RUNNER = "work/verify_information_debt_quote_bounded.py"
PLUGIN_NAME = "work.verify_information_debt_quote_bounded"
COLLECTION_ENV = "INFORMATION_DEBT_QUOTE_BOUNDED_NODEID_OUTPUT"
SOURCE_LIST_SCHEMA = "information.debt_quote_query.bounded_source_list.v1"
FREEZE_SCHEMA = "information.debt_quote_query.bounded_source_freeze.v1"
COLLECTION_SCHEMA = "information.debt_quote_query.bounded_collection.v1"
PART_SCHEMA = "information.debt_quote_query.bounded_part.v1"

MAX_BATCH_ITEMS = 50
MAX_DIRECT_COMMAND_CHARS = 26000
MEMORY_STOP_BYTES = 1_000_000_000
MONITOR_INTERVAL_SECONDS = 0.5

ROOT_BEFORE = "work/runtime/information-debt-quote-query-20261101-001/root-before-001"
IMPLEMENTATION_BEFORE = (
    "work/runtime/information-debt-quote-query-20261101-001/implementation-before-001"
)
REVIEWED_BEFORE_COPIES = {
    "bridge/diplomacy.py": f"{ROOT_BEFORE}/bridge/diplomacy.py",
    "work/native/alliance-query.inc": f"{ROOT_BEFORE}/work/native/alliance-query.inc",
    "work/native/diplomacy-observer-v10.cpp":
        f"{ROOT_BEFORE}/work/native/diplomacy-observer-v10.cpp",
    "tools/start_diplomacy_observer.py":
        f"{IMPLEMENTATION_BEFORE}/tools/start_diplomacy_observer.py",
    "work/native/build-diplomacy-observer.ps1":
        f"{IMPLEMENTATION_BEFORE}/work/native/build-diplomacy-observer.ps1",
}

REQUIRED_SOURCES = {
    RUNNER,
    "bridge/information/loan_interest_quote_math.py",
    "bridge/tests/test_loan_interest_quote_math.py",
    "bridge/tests/test_loan_interest_quote_dates.py",
    "bridge/tests/test_observer_debt_quote_manifest.py",
    "bridge/tests/test_debt_quote_bridge.py",
    "bridge/tests/test_debt_quote_query.py",
    "work/native/debt-quote-native-guards.h",
    "work/native/debt-quote-query.inc",
}
FOCUSED_SOURCE_DEPENDENCIES = REQUIRED_SOURCES | {
    "bridge/debt_quote_query.py",
    *REVIEWED_BEFORE_COPIES.keys(),
    "work/verify_information_war_income_bounded.py",
    "work/verify_information_foreign_forces.py",
    "work/verify_information_foreign_manpower.py",
    "work/verify_information_foreign_technology.py",
}
_SOURCE_LIST_ARGUMENT: str | None = None

BASELINE_PINS = {
    "baseline_freeze": {
        "path": "work/runtime/information-bankruptcy-visibility-20261101-001/source-freeze-001.json",
        "bytes": 1_254_673,
        "sha256": "9056301a4627479d95c2632fbbd57b12a1f6e48f9ae2ed9fe566d9aedf82977b",
    },
    "baseline_comparison": {
        "path": "work/runtime/information-bankruptcy-visibility-20261101-001/regression-comparison-001.json",
        "bytes": 22_131,
        "sha256": "0ea38c0e03b606432f6b6b706132bd0483b277ba583125fa071aae0955cee21a",
    },
    "baseline_postverify": {
        "path": "work/runtime/information-bankruptcy-visibility-20261101-001/source-post-run-verification-001.json",
        "bytes": 1_012,
        "sha256": "0ffa3c461d9ce094e116a94994a7203aa7ed1ad757cb5da48e9061e8fa116641",
    },
    "baseline_xml": {
        "path": "work/runtime/information-bankruptcy-visibility-20261101-001/bounded-full-001/regression-full-001.xml",
        "bytes": 1_151_960,
        "sha256": "e5f55c7bc6a3bf65d8d2a298f8836377911948579a053c42203a33b618988814",
    },
}

TERMINAL_PATTERNS = {
    "passed": re.compile(r"(?<![\w])([0-9]+) passed\b"),
    "failed": re.compile(r"(?<![\w])([0-9]+) failed\b"),
    "errors": re.compile(r"(?<![\w])([0-9]+) errors?\b"),
    "skipped": re.compile(r"(?<![\w])([0-9]+) skipped\b"),
    "subtests_passed": re.compile(r"(?<![\w])([0-9]+) subtests passed\b"),
}


def pytest_collection_finish(session) -> None:
    """Persist the real pytest-selected node IDs for this collection or part."""
    destination_text = os.environ.get(COLLECTION_ENV)
    if not destination_text:
        return
    nodeids = [item.nodeid for item in session.items]
    if (
        any(not isinstance(nodeid, str) or not nodeid for nodeid in nodeids)
        or len(set(nodeids)) != len(nodeids)
    ):
        raise RuntimeError("pytest_collected_invalid_or_duplicate_nodeid")
    destination = Path(destination_text)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(
            {"schema": COLLECTION_SCHEMA, "count": len(nodeids), "nodeids": nodeids},
            stream,
            ensure_ascii=False,
            indent=2,
        )
        stream.write("\n")


def _stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _workspace_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve()
    path.relative_to(ROOT)
    return path


def _relative(path: str | Path) -> str:
    return _workspace_path(path).relative_to(ROOT).as_posix()


def _pin(path: str | Path) -> dict:
    return common.pin(_workspace_path(path))


def _read_json(path: str | Path) -> dict:
    candidate = _workspace_path(path)
    if candidate.stat().st_size > 32 * 1024 * 1024:
        raise ValueError(f"json_input_exceeds_limit:{candidate.relative_to(ROOT)}")
    with candidate.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{candidate.relative_to(ROOT)}")
    return value


def _write_new(path: str | Path, value: dict) -> dict:
    candidate = _workspace_path(path)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    if candidate.exists():
        raise FileExistsError(f"refusing_to_overwrite:{candidate.relative_to(ROOT)}")
    with candidate.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    return _pin(candidate)


def _copy_stream(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"snapshot_already_exists:{destination.relative_to(ROOT)}")
    with source.open("rb") as src, destination.open("xb") as dst:
        while block := src.read(1024 * 1024):
            dst.write(block)


def _verify_parent() -> tuple[dict, dict, dict, dict]:
    paths = {
        "baseline_freeze": BASELINE_FREEZE,
        "baseline_comparison": BASELINE_COMPARISON,
        "baseline_postverify": BASELINE_POSTVERIFY,
        "baseline_xml": BASELINE_XML,
    }
    actual_pins = {key: _pin(path) for key, path in paths.items()}
    if actual_pins != BASELINE_PINS:
        raise ValueError("accepted_batch97_artifact_pin_mismatch")

    frozen = _read_json(BASELINE_FREEZE)
    comparison = _read_json(BASELINE_COMPARISON)
    postverify = _read_json(BASELINE_POSTVERIFY)
    if (
        frozen.get("schema") != "information.war_income_bounded.bounded_source_freeze.v1"
        or frozen.get("batch") != 97
        or frozen.get("revision") != "001"
        or frozen.get("status") != "passed"
        or frozen.get("count") != 2008
        or len(frozen.get("files", [])) != 2008
    ):
        raise ValueError("accepted_batch97_freeze_shape_invalid")
    rows = frozen["files"]
    paths_in_freeze = [row.get("source", {}).get("path") for row in rows]
    if (
        any(not isinstance(path, str) or not path for path in paths_in_freeze)
        or len(set(paths_in_freeze)) != 2008
        or any(
            not isinstance(row.get("source"), dict)
            or not isinstance(row.get("snapshot"), dict)
            for row in rows
        )
    ):
        raise ValueError("accepted_batch97_source_union_invalid")

    totals = comparison.get("terminal_totals", {})
    junit = comparison.get("junit_summary", {})
    coverage = comparison.get("collection_coverage", {})
    expected_freeze_pin = actual_pins["baseline_freeze"]
    expected_xml_pin = actual_pins["baseline_xml"]
    if (
        comparison.get("schema")
        != "information.war_income_bounded.bounded_regression_comparison.v1"
        or comparison.get("batch") != 97
        or comparison.get("revision") != "001"
        or comparison.get("status") != "passed_no_new_bad"
        or comparison.get("no_new_bad") is not True
        or comparison.get("whole_suite_passed") is not False
        or comparison.get("freeze") != expected_freeze_pin
        or comparison.get("current") != expected_xml_pin
        or comparison.get("baseline_bad_occurrences") != 141
        or comparison.get("current_bad_occurrences") != 141
        or comparison.get("nodeid_count") != 5079
        or comparison.get("part_count") != 102
        or totals != {"passed": 4957, "failed": 106, "errors": 35, "subtests": 2014}
        or junit != {"tests": 7112, "failures": 106, "errors": 35, "skipped": 0}
        or coverage.get("status") != "complete"
        or coverage.get("expected_node_count") != 5079
        or coverage.get("executed_node_count") != 5079
        or coverage.get("missing_node_ids") != []
        or coverage.get("duplicate_node_ids") != []
    ):
        raise ValueError("accepted_batch97_comparison_shape_invalid")
    if (
        postverify.get("schema")
        != "information.war_income_bounded.bounded_postverify.v1"
        or postverify.get("batch") != 97
        or postverify.get("revision") != "001"
        or postverify.get("status") != "passed_no_new_bad"
        or postverify.get("count") != 2008
        or postverify.get("freeze") != expected_freeze_pin
        or postverify.get("regression_comparison") != actual_pins["baseline_comparison"]
        or postverify.get("current_sources_match_snapshots") is not True
        or postverify.get("no_new_bad") is not True
        or postverify.get("whole_suite_passed") is not False
    ):
        raise ValueError("accepted_batch97_postverify_shape_invalid")
    bad = common.bad_cases(BASELINE_XML)
    if sum(bad.values()) != 141:
        raise ValueError("accepted_batch97_bad_case_counter_invalid")
    if common.junit_summary(BASELINE_XML) != junit:
        raise ValueError("accepted_batch97_xml_summary_invalid")
    return frozen, comparison, postverify, actual_pins


def _normalize_source(path: str) -> str:
    candidate = _workspace_path(path)
    relative = candidate.relative_to(ROOT).as_posix()
    parts = Path(relative).parts
    if (
        "source-snapshots-001" in parts
        or Path(relative).suffix.lower() in {".xml", ".log"}
    ):
        raise ValueError(f"prohibited_source_path:{relative}")
    return relative


def _normalize_focus_target(target: str) -> tuple[str, str]:
    """Return a pytest target and its safe workspace-relative source file."""
    if not isinstance(target, str) or not target:
        raise ValueError("focused_target_must_be_nonempty_text")
    source_part, separator, selector = target.partition("::")
    if (
        not source_part
        or source_part.startswith(("/", "\\"))
        or Path(source_part).is_absolute()
        or PureWindowsPath(source_part).is_absolute()
        or ".." in Path(source_part).parts
        or ".." in PureWindowsPath(source_part).parts
    ):
        raise ValueError(f"focused_target_must_be_relative_and_contained:{target}")
    if separator and not selector:
        raise ValueError(f"focused_nodeid_selector_missing:{target}")
    candidate = (ROOT / Path(source_part)).resolve()
    try:
        relative_source = candidate.relative_to(ROOT).as_posix()
    except ValueError as exc:
        raise ValueError(f"focused_target_escapes_workspace:{target}") from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"focused_test_file_missing:{relative_source}")
    if candidate.suffix.lower() != ".py":
        raise ValueError(f"focused_target_not_python_test_file:{relative_source}")
    normalized_target = relative_source + (f"::{selector}" if separator else "")
    return normalized_target, relative_source


def _load_source_list(
    path: str | Path, baseline: dict | None = None
) -> tuple[dict, dict, list[str], dict[str, str]]:
    source_list_path = _workspace_path(path)
    if source_list_path.stat().st_size > 1024 * 1024:
        raise ValueError("source_list_manifest_exceeds_1MiB")
    manifest = _read_json(source_list_path)
    if manifest.get("schema") != SOURCE_LIST_SCHEMA:
        raise ValueError("source_list_schema_invalid")
    sources = manifest.get("sources")
    reviewed_rows = manifest.get("reviewed_existing_changes")
    if (
        not isinstance(sources, list)
        or any(not isinstance(item, str) for item in sources)
        or not isinstance(reviewed_rows, list)
        or any(not isinstance(row, dict) for row in reviewed_rows)
    ):
        raise ValueError("source_list_fields_invalid")
    normalized = [_normalize_source(item) for item in sources]
    if len(set(normalized)) != len(normalized):
        raise ValueError("source_list_contains_duplicate_paths")
    if normalized != sorted(normalized):
        raise ValueError("source_list_sources_must_be_sorted")
    reviewed: dict[str, str] = {}
    for row in reviewed_rows:
        if set(row) != {"path", "before_copy_path"}:
            raise ValueError("reviewed_source_row_shape_invalid")
        source_path = _normalize_source(row["path"])
        before_path = _normalize_source(row["before_copy_path"])
        if source_path in reviewed:
            raise ValueError("reviewed_source_path_duplicate")
        reviewed[source_path] = before_path
    for source_path, before_copy_path in REVIEWED_BEFORE_COPIES.items():
        if reviewed.get(source_path) != before_copy_path:
            raise ValueError(f"required_reviewed_source_missing_or_changed:{source_path}")
    baseline_source_paths = None
    if baseline is not None:
        baseline_source_paths = {
            row.get("source", {}).get("path") for row in baseline.get("files", [])
        }
    stage_prefix = DEFAULT_STAGE.relative_to(ROOT).as_posix() + "/"
    for source_path, before_copy_path in reviewed.items():
        if source_path not in normalized:
            raise ValueError(f"reviewed_source_not_selected:{source_path}")
        if baseline_source_paths is not None and source_path not in baseline_source_paths:
            raise ValueError(f"reviewed_source_not_in_batch97:{source_path}")
        if not before_copy_path.startswith(stage_prefix) or not any(
            "before" in part.lower() or "backup" in part.lower()
            for part in Path(before_copy_path).parts
        ):
            raise ValueError(f"before_copy_outside_stage100_backup_area:{before_copy_path}")
    missing_required = sorted(REQUIRED_SOURCES - set(normalized))
    if missing_required:
        raise ValueError("required_source_paths_missing:" + ",".join(missing_required))
    for source_path in normalized:
        if not (ROOT / source_path).is_file():
            raise FileNotFoundError(f"source_list_path_missing:{source_path}")
    return manifest, _pin(source_list_path), normalized, reviewed


def _verify_baseline_snapshots(baseline: dict) -> None:
    for row in baseline["files"]:
        source = row["source"]
        snapshot = row["snapshot"]
        if _pin(snapshot["path"]) != snapshot:
            raise ValueError(f"baseline_snapshot_pin_mismatch:{source['path']}")
        if (source["bytes"], source["sha256"]) != (
            snapshot["bytes"],
            snapshot["sha256"],
        ):
            raise ValueError(f"baseline_source_snapshot_disagrees:{source['path']}")


def _snapshot_source(source_path: str, snapshot_root: Path) -> tuple[dict, dict]:
    source = ROOT / source_path
    destination = snapshot_root / Path(source_path)
    before = _pin(source)
    _copy_stream(source, destination)
    after = _pin(source)
    snapshot = _pin(destination)
    if before != after or (after["bytes"], after["sha256"]) != (
        snapshot["bytes"],
        snapshot["sha256"],
    ):
        raise RuntimeError(f"source_changed_during_snapshot:{source_path}")
    return after, snapshot


def _freeze(stage: Path, source_list_path: str) -> dict:
    baseline, comparison, _postverify, baseline_pins = _verify_parent()
    _verify_baseline_snapshots(baseline)
    manifest, manifest_pin, requested, reviewed_copy_map = _load_source_list(
        source_list_path, baseline
    )
    freeze_path = stage / "source-freeze-001.json"
    receipt_path = stage / "source-freeze-receipt-001.json"
    snapshot_root = stage / "source-snapshots-001"
    if freeze_path.exists() or receipt_path.exists() or snapshot_root.exists():
        raise FileExistsError("batch100_source_freeze_already_started")

    baseline_by_path = {row["source"]["path"]: row for row in baseline["files"]}
    requested_set = set(requested)
    current_changed = {
        path
        for path, old_row in baseline_by_path.items()
        if _pin(path) != old_row["source"]
    }
    if current_changed != set(reviewed_copy_map):
        raise ValueError(
            "changed_inherited_source_set_mismatch:"
            + ",".join(sorted(current_changed ^ set(reviewed_copy_map)))
        )
    if not set(reviewed_copy_map).issubset(requested_set):
        raise ValueError("reviewed_sources_not_in_source_list")

    for source_path, before_copy_path in reviewed_copy_map.items():
        original = baseline_by_path[source_path]["source"]
        if _pin(before_copy_path)["bytes"] != original["bytes"] or _pin(
            before_copy_path
        )["sha256"] != original["sha256"]:
            raise ValueError(f"before_copy_does_not_match_batch97:{source_path}")

    snapshot_root.mkdir(parents=True, exist_ok=False)
    rows: list[dict] = []
    changed_rows: list[dict] = []
    added_rows: list[dict] = []
    for path, original_row in baseline_by_path.items():
        if path not in current_changed:
            rows.append(original_row)
            continue
        source_pin, snapshot_pin = _snapshot_source(path, snapshot_root)
        new_row = {"source": source_pin, "snapshot": snapshot_pin}
        rows.append(new_row)
        changed_rows.append(
            {
                "path": path,
                "before": original_row,
                "before_copy": _pin(reviewed_copy_map[path]),
                "after": new_row,
            }
        )
    for path in requested:
        if path in baseline_by_path:
            continue
        source_pin, snapshot_pin = _snapshot_source(path, snapshot_root)
        new_row = {"source": source_pin, "snapshot": snapshot_pin}
        rows.append(new_row)
        added_rows.append(new_row)
    rows.sort(key=lambda row: row["source"]["path"])
    expected_paths = set(baseline_by_path) | (requested_set - set(baseline_by_path))
    if (
        len(rows) != len(expected_paths)
        or {row["source"]["path"] for row in rows} != expected_paths
        or len({row["source"]["path"] for row in rows}) != len(rows)
    ):
        raise ValueError("batch100_source_union_invalid")
    value = {
        "schema": FREEZE_SCHEMA,
        "batch": 100,
        "revision": "001",
        "status": "passed",
        "count": len(rows),
        "files": rows,
        "freeze_path": freeze_path.relative_to(ROOT).as_posix(),
        "baseline_freeze": baseline_pins["baseline_freeze"],
        "baseline_comparison": baseline_pins["baseline_comparison"],
        "baseline_postverify": baseline_pins["baseline_postverify"],
        "baseline_full_xml": baseline_pins["baseline_xml"],
        "inherited_file_count": len(baseline_by_path),
        "added_file_count": len(added_rows),
        "added_sources": added_rows,
        "reviewed_existing_source_changes": changed_rows,
        "required_sources": sorted(REQUIRED_SOURCES),
        "requested_source_paths": requested,
        "source_list_manifest": manifest_pin,
        "source_snapshot_policy": (
            "reuse unchanged accepted batch-97 rows; verify five approved before-copies "
            "against batch-97 and snapshot only those changed inherited sources plus "
            "explicit additions"
        ),
        "created_at": _stamp(),
    }
    freeze_pin = _write_new(freeze_path, value)
    receipt = {
        "schema": FREEZE_SCHEMA + ".receipt",
        "status": "passed",
        "batch": 100,
        "count": len(rows),
        "path": freeze_path.relative_to(ROOT).as_posix(),
        "freeze": freeze_pin,
        "added_file_count": len(added_rows),
        "reviewed_existing_changes": sorted(current_changed),
        "baseline": baseline_pins,
        "source_list_manifest": manifest_pin,
    }
    receipt_pin = _write_new(receipt_path, receipt)
    return {"freeze": freeze_pin, "receipt": receipt_pin, "added": len(added_rows)}


def _verify_frozen_sources(stage: Path) -> dict:
    baseline, _comparison, _postverify, baseline_pins = _verify_parent()
    freeze_path = stage / "source-freeze-001.json"
    frozen = _read_json(freeze_path)
    if (
        frozen.get("schema") != FREEZE_SCHEMA
        or frozen.get("batch") != 100
        or frozen.get("revision") != "001"
        or frozen.get("status") != "passed"
        or frozen.get("freeze_path") != freeze_path.relative_to(ROOT).as_posix()
        or frozen.get("baseline_freeze") != baseline_pins["baseline_freeze"]
        or frozen.get("baseline_comparison") != baseline_pins["baseline_comparison"]
        or frozen.get("baseline_postverify") != baseline_pins["baseline_postverify"]
        or frozen.get("baseline_full_xml") != baseline_pins["baseline_xml"]
    ):
        raise ValueError("batch100_freeze_metadata_invalid")
    _verify_baseline_snapshots(baseline)
    old_by_path = {row["source"]["path"]: row for row in baseline["files"]}
    rows = frozen.get("files")
    added_rows = frozen.get("added_sources")
    changed_rows = frozen.get("reviewed_existing_source_changes")
    requested = frozen.get("requested_source_paths")
    if (
        not isinstance(rows, list)
        or not isinstance(added_rows, list)
        or not isinstance(changed_rows, list)
        or not isinstance(requested, list)
        or requested != sorted(set(requested))
    ):
        raise ValueError("batch100_freeze_rows_invalid")
    row_by_path = {row.get("source", {}).get("path"): row for row in rows}
    added_by_path = {
        row.get("source", {}).get("path"): row for row in added_rows
    }
    changed_by_path = {row.get("path"): row for row in changed_rows}
    if (
        len(row_by_path) != len(rows)
        or len(added_by_path) != len(added_rows)
        or len(changed_by_path) != len(changed_rows)
        or len(rows) != len(old_by_path) + len(added_by_path)
        or frozen.get("count") != len(rows)
        or frozen.get("inherited_file_count") != len(old_by_path)
        or frozen.get("added_file_count") != len(added_by_path)
        or set(row_by_path) != set(old_by_path) | set(added_by_path)
        or not set(REVIEWED_BEFORE_COPIES).issubset(changed_by_path)
        or set(added_by_path) != set(requested) - set(old_by_path)
    ):
        raise ValueError("batch100_freeze_union_invalid")
    if set(frozen.get("required_sources", [])) != REQUIRED_SOURCES:
        raise ValueError("batch100_required_source_record_invalid")

    manifest_pin = frozen.get("source_list_manifest")
    if not isinstance(manifest_pin, dict) or _pin(manifest_pin["path"]) != manifest_pin:
        raise ValueError("batch100_source_list_pin_mismatch")
    _manifest, actual_manifest_pin, normalized, reviewed_map = _load_source_list(
        manifest_pin["path"], baseline
    )
    if (
        actual_manifest_pin != manifest_pin
        or normalized != requested
        or not set(REVIEWED_BEFORE_COPIES).issubset(reviewed_map)
        or set(reviewed_map) != set(changed_by_path)
    ):
        raise ValueError("batch100_source_list_freeze_mismatch")

    for path, old_row in old_by_path.items():
        row = row_by_path[path]
        if path not in changed_by_path:
            if row != old_row:
                raise ValueError(f"unreviewed_inherited_row_changed:{path}")
        else:
            delta = changed_by_path[path]
            if delta.get("before") != old_row or delta.get("after") != row:
                raise ValueError(f"reviewed_change_delta_mismatch:{path}")
            if _pin(reviewed_map[path]) != delta.get("before_copy"):
                raise ValueError(f"before_copy_pin_mismatch:{path}")
            if (
                delta["before_copy"]["bytes"] != old_row["source"]["bytes"]
                or delta["before_copy"]["sha256"] != old_row["source"]["sha256"]
            ):
                raise ValueError(f"before_copy_not_batch97:{path}")
    for path, row in added_by_path.items():
        if row_by_path.get(path) != row:
            raise ValueError(f"added_source_row_mismatch:{path}")

    for path, row in row_by_path.items():
        source, snapshot = row["source"], row["snapshot"]
        if _pin(source["path"]) != source or _pin(snapshot["path"]) != snapshot:
            raise ValueError(f"source_or_snapshot_pin_mismatch:{path}")
        if (source["bytes"], source["sha256"]) != (
            snapshot["bytes"],
            snapshot["sha256"],
        ):
            raise ValueError(f"source_snapshot_bytes_mismatch:{path}")
    return {
        "schema": FREEZE_SCHEMA + ".verification",
        "status": "passed",
        "count": len(rows),
        "freeze": _pin(freeze_path),
        "baseline": baseline_pins,
        "added_file_count": len(added_by_path),
        "reviewed_existing_changes": sorted(changed_by_path),
        "current_sources_match_snapshots": True,
    }


def _collection_command(paths: list[str]) -> list[str]:
    argv = [
        str(RESEARCH_PYTHON),
        "-B",
        "-m",
        "pytest",
        "-q",
        "--collect-only",
        "-p",
        PLUGIN_NAME,
        *paths,
    ]
    if len(subprocess.list2cmdline(argv)) > MAX_DIRECT_COMMAND_CHARS:
        raise ValueError("collection_command_exceeds_26000_chars")
    return argv


def _execution_command(nodeids: list[str], xml_path: Path) -> list[str]:
    argv = [
        str(RESEARCH_PYTHON),
        "-B",
        "-m",
        "pytest",
        "-q",
        "-p",
        PLUGIN_NAME,
        "--junitxml",
        str(xml_path),
        *nodeids,
    ]
    if len(nodeids) > MAX_BATCH_ITEMS:
        raise ValueError("part_exceeds_50_nodeids")
    if len(subprocess.list2cmdline(argv)) > MAX_DIRECT_COMMAND_CHARS:
        raise ValueError("part_command_exceeds_26000_chars")
    return argv


def _new_attempt(parent: Path, prefix: str) -> tuple[int, Path]:
    parent.mkdir(parents=True, exist_ok=True)
    for index in range(1, 1000):
        folder = parent / f"{prefix}-{index:03d}"
        if not folder.exists():
            folder.mkdir(parents=True, exist_ok=False)
            return index, folder
    raise RuntimeError(f"attempt_limit_reached:{prefix}")


def _collect(parent: Path, paths: list[str], label: str) -> tuple[list[str], dict]:
    index, folder = _new_attempt(parent, "collection")
    nodeids_path = folder / "actual-nodeids.json"
    log_path = folder / "pytest.log"
    monitor_path = folder / "memory-monitor.jsonl"
    argv = _collection_command(paths)
    env = os.environ.copy()
    env[COLLECTION_ENV] = str(nodeids_path)
    run = monitor_runner._run_monitored(
        argv,
        cwd=ROOT,
        log_path=log_path,
        sample_path=monitor_path,
        env=env,
    )
    receipt = {
        "schema": COLLECTION_SCHEMA + ".receipt",
        "batch": 100,
        "label": label,
        "attempt": index,
        "selected_paths": paths,
        "child": run,
        "collection_created": nodeids_path.is_file(),
    }
    if run["cap_hit"] or run["memory_query_error"] or run["returncode"] != 0:
        receipt["status"] = (
            "aborted_resource_threshold"
            if run["cap_hit"]
            else "aborted_memory_monitor_error"
            if run["memory_query_error"]
            else "failed_collection_process"
        )
        if nodeids_path.is_file():
            receipt["nodeids"] = _pin(nodeids_path)
        receipt["log"] = _pin(log_path)
        receipt["memory_monitor"] = _pin(monitor_path)
        _write_new(folder / "collection-receipt.json", receipt)
        raise RuntimeError(f"collection_failed:{receipt['status']}")
    if not nodeids_path.is_file():
        receipt["status"] = "failed_collection_receipt_missing"
        receipt["log"] = _pin(log_path)
        receipt["memory_monitor"] = _pin(monitor_path)
        _write_new(folder / "collection-receipt.json", receipt)
        raise RuntimeError("collection_nodeid_receipt_missing")
    selected = _read_json(nodeids_path)
    nodeids = selected.get("nodeids")
    if (
        selected.get("schema") != COLLECTION_SCHEMA
        or not isinstance(nodeids, list)
        or not nodeids
        or any(not isinstance(nodeid, str) or not nodeid for nodeid in nodeids)
        or selected.get("count") != len(nodeids)
        or len(set(nodeids)) != len(nodeids)
    ):
        receipt["status"] = "failed_collected_nodeids_invalid_or_duplicate"
        receipt["nodeids"] = _pin(nodeids_path)
        receipt["log"] = _pin(log_path)
        receipt["memory_monitor"] = _pin(monitor_path)
        _write_new(folder / "collection-receipt.json", receipt)
        raise RuntimeError("collected_nodeids_invalid_or_duplicate")
    receipt.update(
        {
            "status": "passed",
            "count": len(nodeids),
            "nodeids": _pin(nodeids_path),
            "log": _pin(log_path),
            "memory_monitor": _pin(monitor_path),
        }
    )
    _write_new(folder / "collection-receipt.json", receipt)
    return nodeids, receipt


def _chunks(nodeids: list[str], xml_parent: Path) -> list[list[str]]:
    chunks: list[list[str]] = []
    current: list[str] = []
    for nodeid in nodeids:
        candidate = current + [nodeid]
        xml_path = xml_parent / f"part-{len(chunks) + 1:04d}.xml"
        argv = [
            str(RESEARCH_PYTHON),
            "-B",
            "-m",
            "pytest",
            "-q",
            "-p",
            PLUGIN_NAME,
            "--junitxml",
            str(xml_path),
            *candidate,
        ]
        if len(current) and (
            len(candidate) > MAX_BATCH_ITEMS
            or len(subprocess.list2cmdline(argv)) > MAX_DIRECT_COMMAND_CHARS
        ):
            chunks.append(current)
            current = [nodeid]
        else:
            current = candidate
        if len(current) > MAX_BATCH_ITEMS:
            raise ValueError("single_nodeid_batch_limit_exceeded")
    if current:
        chunks.append(current)
    for chunk in chunks:
        _execution_command(chunk, xml_parent / "command-size-check.xml")
    return chunks


def _write_expected(path: Path, nodeids: list[str]) -> dict:
    return _write_new(
        path,
        {"schema": COLLECTION_SCHEMA, "count": len(nodeids), "nodeids": nodeids},
    )


def _run_part(index: int, nodeids: list[str], output: Path) -> dict:
    folder = output / "parts" / f"part-{index:04d}"
    folder.mkdir(parents=True, exist_ok=False)
    expected_path = folder / "expected-nodeids.json"
    actual_path = folder / "actual-nodeids.json"
    xml_path = folder / "part.xml"
    log_path = folder / "pytest.log"
    monitor_path = folder / "memory-monitor.jsonl"
    expected_pin = _write_expected(expected_path, nodeids)
    argv = _execution_command(nodeids, xml_path)
    env = os.environ.copy()
    env[COLLECTION_ENV] = str(actual_path)
    run = monitor_runner._run_monitored(
        argv,
        cwd=ROOT,
        log_path=log_path,
        sample_path=monitor_path,
        env=env,
    )
    receipt = {
        "schema": PART_SCHEMA,
        "index": index,
        "expected_count": len(nodeids),
        "expected_ids": expected_pin,
        "child": run,
        "actual_collection_created": actual_path.is_file(),
        "xml_created": xml_path.is_file(),
    }
    if run["cap_hit"] or run["memory_query_error"]:
        receipt["status"] = (
            "aborted_resource_threshold"
            if run["cap_hit"]
            else "aborted_memory_monitor_error"
        )
        if actual_path.is_file():
            receipt["actual_ids"] = _pin(actual_path)
        if xml_path.is_file():
            receipt["xml"] = _pin(xml_path)
        receipt["log"] = _pin(log_path)
        receipt["memory_monitor"] = _pin(monitor_path)
        _write_new(folder / "part-receipt.json", receipt)
        return receipt
    if not actual_path.is_file() or not xml_path.is_file():
        receipt["status"] = "failed_missing_xml_or_collection"
        receipt["log"] = _pin(log_path)
        receipt["memory_monitor"] = _pin(monitor_path)
        _write_new(folder / "part-receipt.json", receipt)
        return receipt
    actual = _read_json(actual_path)
    actual_ids = actual.get("nodeids")
    matches = (
        actual.get("schema") == COLLECTION_SCHEMA
        and isinstance(actual_ids, list)
        and actual.get("count") == len(actual_ids)
        and collections.Counter(actual_ids) == collections.Counter(nodeids)
    )
    if not matches:
        receipt.update(
            {
                "status": "failed_collected_ids_mismatch",
                "actual_ids": _pin(actual_path),
                "actual_count": len(actual_ids) if isinstance(actual_ids, list) else None,
                "xml": _pin(xml_path),
                "log": _pin(log_path),
                "memory_monitor": _pin(monitor_path),
            }
        )
        _write_new(folder / "part-receipt.json", receipt)
        return receipt
    root = ET.parse(xml_path).getroot()
    if root.tag not in {"testsuite", "testsuites"}:
        receipt["status"] = "failed_invalid_junit_root"
        receipt["xml"] = _pin(xml_path)
        receipt["log"] = _pin(log_path)
        receipt["memory_monitor"] = _pin(monitor_path)
        _write_new(folder / "part-receipt.json", receipt)
        return receipt
    receipt.update(
        {
            "status": "completed",
            "actual_ids": _pin(actual_path),
            "actual_count": len(actual_ids),
            "collection_multiset_matches": True,
            "xml": _pin(xml_path),
            "log": _pin(log_path),
            "memory_monitor": _pin(monitor_path),
            "junit_summary": common.junit_summary(xml_path),
            "returncode": run["returncode"],
        }
    )
    _write_new(folder / "part-receipt.json", receipt)
    return receipt


def _xml_suites(xml_path: Path) -> list[ET.Element]:
    root = ET.parse(xml_path).getroot()
    if root.tag == "testsuite":
        return [copy.deepcopy(root)]
    return [copy.deepcopy(child) for child in root if child.tag == "testsuite"]


def _merge_junit(receipts: list[dict], destination: Path) -> dict:
    totals = {name: 0 for name in ("tests", "failures", "errors", "skipped")}
    suites: list[ET.Element] = []
    for receipt in receipts:
        if receipt.get("status") != "completed":
            raise ValueError("cannot_merge_incomplete_part")
        for suite in _xml_suites(common.workspace(receipt["xml"]["path"])):
            suites.append(suite)
            for key in totals:
                totals[key] += int(suite.get(key, "0"))
    merged = ET.Element(
        "testsuites",
        {"name": "pytest bridge/tests bounded batch-100", **{k: str(v) for k, v in totals.items()}},
    )
    for suite in suites:
        merged.append(suite)
    ET.ElementTree(merged).write(destination, encoding="utf-8", xml_declaration=True)
    return {"summary": common.junit_summary(destination), "suite_count": len(suites), "xml": _pin(destination)}


def _combine_logs(receipts: list[dict], destination: Path) -> dict:
    with destination.open("xb") as output:
        for receipt in receipts:
            header = (
                f"\n===== PART {receipt['index']:04d} STATUS "
                f"{receipt['status']} RC {receipt.get('returncode')} =====\n"
            )
            output.write(header.encode("utf-8"))
            with common.workspace(receipt["log"]["path"]).open("rb") as source:
                while block := source.read(1024 * 1024):
                    output.write(block)
    return _pin(destination)


def _terminal_summary(path: Path) -> dict:
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(max(0, size - 65536))
        text = stream.read().decode("utf-8", errors="replace")
    summary_line = ""
    for line in text.splitlines():
        if " in " in line and any(
            term in line for term in (" passed", " failed", " error", " skipped", " subtests")
        ):
            summary_line = line.strip("= \t")
    values = {name: 0 for name in TERMINAL_PATTERNS}
    for name, pattern in TERMINAL_PATTERNS.items():
        match = pattern.search(summary_line)
        if match:
            values[name] = int(match.group(1))
    return {**values, "summary_line": summary_line}


def _positive_counter(counter: collections.Counter) -> list[dict]:
    return common.counter_rows(counter)


def _full_run(stage: Path) -> int:
    source_check = _verify_frozen_sources(stage)
    output = stage / "bounded-full-001"
    if output.exists():
        raise FileExistsError("batch100_full_run_output_exists")
    output.mkdir(parents=True, exist_ok=False)
    nodeids, collection_receipt = _collect(
        output, ["bridge/tests"], "full-bridge-tests"
    )
    plan_path = output / "collection-plan-001.json"
    chunks = _chunks(nodeids, output / "parts")
    plan = {
        "schema": "information.debt_quote_query.bounded_execution_plan.v1",
        "status": "passed",
        "batch": 100,
        "nodeid_count": len(nodeids),
        "unique_nodeid_count": len(set(nodeids)),
        "part_count": len(chunks),
        "max_batch_items": MAX_BATCH_ITEMS,
        "max_direct_command_chars": MAX_DIRECT_COMMAND_CHARS,
        "nodeids": nodeids,
        "chunks": [
            {"index": index, "start": start, "stop": start + len(chunk), "nodeid_count": len(chunk)}
            for index, (start, chunk) in enumerate(
                ( (sum(len(previous) for previous in chunks[:i]), chunk) for i, chunk in enumerate(chunks) ),
                start=1,
            )
        ],
        "collection_receipt": collection_receipt,
        "source_verification": source_check,
        "freeze": _pin(stage / "source-freeze-001.json"),
        "created_at": _stamp(),
    }
    _write_new(plan_path, plan)
    reservation = output / "full-execution-reservation-001.json"
    _write_new(
        reservation,
        {
            "schema": "information.debt_quote_query.bounded_full_reservation.v1",
            "batch": 100,
            "runs": 1,
            "nodeid_count": len(nodeids),
            "part_count": len(chunks),
            "max_batch_items": MAX_BATCH_ITEMS,
            "max_direct_command_chars": MAX_DIRECT_COMMAND_CHARS,
            "memory_stop_bytes": MEMORY_STOP_BYTES,
            "monitor_interval_seconds": MONITOR_INTERVAL_SECONDS,
            "execution": "serial pytest children; actual collected IDs exactly once; no filters, skips, or maxfail",
            "freeze": _pin(stage / "source-freeze-001.json"),
            "collection_plan": _pin(plan_path),
            "created_at": _stamp(),
        },
    )
    progress = output / "batch-progress-001.jsonl"
    with progress.open("x", encoding="utf-8", newline="\n"):
        pass
    receipts: list[dict] = []
    start = 0
    for index, chunk in enumerate(chunks, start=1):
        receipt = _run_part(index, chunk, output)
        receipts.append(receipt)
        with progress.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(
                json.dumps(
                    {
                        "at_utc": _stamp(),
                        "index": index,
                        "status": receipt["status"],
                        "returncode": receipt.get("returncode"),
                        "nodeid_count": receipt.get("expected_count"),
                        "peak_pagefile_usage_bytes": receipt.get("child", {}).get(
                            "peak_pagefile_usage_bytes"
                        ),
                        "peak_private_usage_bytes": receipt.get("child", {}).get(
                            "max_private_usage_bytes"
                        ),
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
            stream.flush()
        print(
            json.dumps(
                {
                    "phase": "part",
                    "index": index,
                    "part_count": len(chunks),
                    "status": receipt["status"],
                    "nodeid_count": receipt.get("expected_count"),
                    "returncode": receipt.get("returncode"),
                    "peak_pagefile_usage_bytes": receipt.get("child", {}).get(
                        "peak_pagefile_usage_bytes"
                    ),
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        if receipt["status"] != "completed":
            _write_new(
                output / "full-execution-boundary-001.json",
                {
                    "schema": "information.debt_quote_query.bounded_full_boundary.v1",
                    "status": receipt["status"],
                    "stopped_at_part": index,
                    "partial_parts": receipts,
                    "progress": _pin(progress),
                    "freeze": _pin(stage / "source-freeze-001.json"),
                    "finished_at": _stamp(),
                },
            )
            return 3 if receipt["status"].startswith("aborted_resource") else 4
        start += len(chunk)

    actual_lists: list[str] = []
    for receipt in receipts:
        actual = _read_json(receipt["actual_ids"]["path"])
        actual_lists.extend(actual["nodeids"])
    expected_counter = collections.Counter(nodeids)
    actual_counter = collections.Counter(actual_lists)
    missing = sorted(
        nodeid for nodeid, count in expected_counter.items() if actual_counter[nodeid] < count
    )
    duplicate = sorted(
        nodeid for nodeid, count in actual_counter.items() if actual_counter[nodeid] > count
    )
    if expected_counter != actual_counter or missing or duplicate:
        _write_new(
            output / "full-execution-boundary-001.json",
            {
                "schema": "information.debt_quote_query.bounded_full_boundary.v1",
                "status": "failed_nodeid_union_mismatch",
                "expected_nodeid_count": len(nodeids),
                "actual_nodeid_count": len(actual_lists),
                "missing_node_ids": missing,
                "duplicate_node_ids": duplicate,
                "partial_parts": receipts,
                "progress": _pin(progress),
                "finished_at": _stamp(),
            },
        )
        return 4
    coverage_path = output / "nodeid-coverage-001.json"
    coverage = {
        "schema": "information.debt_quote_query.bounded_nodeid_coverage.v1",
        "status": "complete",
        "expected_node_count": len(nodeids),
        "executed_node_count": len(actual_lists),
        "missing_node_ids": missing,
        "duplicate_node_ids": duplicate,
        "expected_multiset_matches_actual_union": True,
        "unique_expected_count": len(set(nodeids)),
        "part_count": len(receipts),
        "part_receipts": [
            _pin(output / "parts" / f"part-{row['index']:04d}" / "part-receipt.json")
            for row in receipts
        ],
        "collection_plan": _pin(plan_path),
        "created_at": _stamp(),
    }
    _write_new(coverage_path, coverage)

    xml_path = output / "regression-full-001.xml"
    merged = _merge_junit(receipts, xml_path)
    log_pin = _combine_logs(receipts, output / "regression-full-001.log")
    terminal = {key: 0 for key in TERMINAL_PATTERNS}
    terminal_parts = []
    for receipt in receipts:
        part_summary = _terminal_summary(common.workspace(receipt["log"]["path"]))
        terminal_parts.append({"index": receipt["index"], **part_summary})
        for key in terminal:
            terminal[key] += part_summary[key]

    baseline_bad = common.bad_cases(BASELINE_XML)
    current_bad = common.bad_cases(xml_path)
    added_bad = current_bad - baseline_bad
    resolved_bad = baseline_bad - current_bad
    nonzero = [receipt["index"] for receipt in receipts if receipt.get("returncode") != 0]
    frozen_check = _verify_frozen_sources(stage)
    comparison_path = stage / "regression-comparison-001.json"
    report = {
        "schema": "information.debt_quote_query.bounded_regression_comparison.v1",
        "status": "passed_no_new_bad" if not added_bad else "failed_new_bad",
        "batch": 100,
        "revision": "001",
        "parent_baseline_batch": 97,
        "parent_baseline_full": BASELINE_PINS["baseline_xml"],
        "freeze": _pin(stage / "source-freeze-001.json"),
        "current": _pin(xml_path),
        "log": log_pin,
        "nodeid_coverage": _pin(coverage_path),
        "nodeid_count": len(actual_lists),
        "part_count": len(receipts),
        "junit_summary": merged["summary"],
        "terminal_summary": terminal,
        "terminal_totals": {
            "passed": terminal["passed"],
            "failed": terminal["failed"],
            "errors": terminal["errors"],
            "subtests": terminal["subtests_passed"],
        },
        "collection_coverage": {
            "status": "complete",
            "expected_node_count": len(nodeids),
            "executed_node_count": len(actual_lists),
            "missing_node_ids": missing,
            "duplicate_node_ids": duplicate,
        },
        "terminal_part_summaries": terminal_parts,
        "baseline_bad_occurrences": sum(baseline_bad.values()),
        "current_bad_occurrences": sum(current_bad.values()),
        "new_bad": _positive_counter(added_bad),
        "resolved_bad": _positive_counter(resolved_bad),
        "no_new_bad": not added_bad,
        "whole_suite_passed": (
            not nonzero
            and merged["summary"]["failures"] == 0
            and merged["summary"]["errors"] == 0
        ),
        "part_returncode_nonzero": nonzero,
        "resource_policy": {
            "max_batch_items": MAX_BATCH_ITEMS,
            "max_direct_command_chars": MAX_DIRECT_COMMAND_CHARS,
            "memory_stop_bytes": MEMORY_STOP_BYTES,
            "monitor_interval_seconds": MONITOR_INTERVAL_SECONDS,
        },
        "bounded_execution": True,
        "source_verification_before": source_check,
        "source_verification_after": frozen_check,
        "finished_at": _stamp(),
    }
    comparison_pin = _write_new(comparison_path, report)
    postverify_path = stage / "source-post-run-verification-001.json"
    _write_new(
        postverify_path,
        {
            "schema": "information.debt_quote_query.bounded_postverify.v1",
            "status": report["status"],
            "batch": 100,
            "revision": "001",
            "count": frozen_check["count"],
            "freeze": _pin(stage / "source-freeze-001.json"),
            "regression_comparison": comparison_pin,
            "nodeid_coverage": _pin(coverage_path),
            "current_sources_match_snapshots": True,
            "no_new_bad": report["no_new_bad"],
            "whole_suite_passed": report["whole_suite_passed"],
            "created_at": _stamp(),
        },
    )
    _write_new(
        output / "full-execution-boundary-001.json",
        {
            "schema": "information.debt_quote_query.bounded_full_boundary.v1",
            "status": "completed",
            "returncode_nonzero_parts": nonzero,
            "part_count": len(receipts),
            "nodeid_count": len(actual_lists),
            "xml": _pin(xml_path),
            "log": log_pin,
            "nodeid_coverage": _pin(coverage_path),
            "finished_at": _stamp(),
        },
    )
    print(json.dumps({"phase": "full", "status": report["status"],
                      "no_new_bad": report["no_new_bad"],
                      "whole_suite_passed": report["whole_suite_passed"],
                      "nodeid_count": len(actual_lists), "part_count": len(receipts)},
                     ensure_ascii=False), flush=True)
    return 0


def _focused(stage: Path, selected_paths: list[str]) -> int:
    normalized_targets_and_sources = [
        _normalize_focus_target(value) for value in selected_paths
    ]
    test_targets = [row[0] for row in normalized_targets_and_sources]
    test_source_paths = sorted({row[1] for row in normalized_targets_and_sources})
    if not test_targets:
        raise ValueError("focused_requires_at_least_one_path")
    if len(set(test_targets)) != len(test_targets):
        raise ValueError("focused_targets_contain_duplicates")
    baseline, _comparison, _postverify, _baseline_pins = _verify_parent()
    snapshot_paths = set(FOCUSED_SOURCE_DEPENDENCIES)
    optional_manifest_pin = None
    if _SOURCE_LIST_ARGUMENT is not None:
        _manifest, optional_manifest_pin, extra_sources, _reviewed_map = _load_source_list(
            _SOURCE_LIST_ARGUMENT, baseline
        )
        snapshot_paths.update(extra_sources)
        snapshot_paths.add(_normalize_source(_SOURCE_LIST_ARGUMENT))
    snapshot_paths.update(test_source_paths)
    normalized_snapshots = sorted(snapshot_paths)
    attempt_index, attempt = _new_attempt(stage, "focused-attempt")
    snapshot_root = attempt / "source-snapshots"
    snapshot_root.mkdir(parents=True, exist_ok=False)
    snapshots = []
    for path in normalized_snapshots:
        if not (ROOT / path).is_file():
            raise FileNotFoundError(f"focused_source_missing:{path}")
        source_pin, snapshot_pin = _snapshot_source(path, snapshot_root)
        snapshots.append({"source": source_pin, "snapshot": snapshot_pin})
    source_list_pin = _write_new(
        attempt / "pre-snapshot-001.json",
        {
            "schema": "information.debt_quote_query.bounded_focused_presnapshot.v1",
            "status": "passed",
            "attempt": attempt_index,
            "files": snapshots,
            "selected_test_targets": test_targets,
            "selected_test_source_files": test_source_paths,
            "optional_source_list": optional_manifest_pin,
            "created_at": _stamp(),
        },
    )
    nodeids, collection = _collect(attempt, test_targets, "focused-selected-targets")
    chunks = _chunks(nodeids, attempt / "parts")
    receipts = []
    for index, chunk in enumerate(chunks, start=1):
        receipt = _run_part(index, chunk, attempt)
        receipts.append(receipt)
        if receipt["status"] != "completed":
            _write_new(
                attempt / "focused-result-001.json",
                {
                    "schema": "information.debt_quote_query.bounded_focused_result.v1",
                    "status": receipt["status"],
                    "attempt": attempt_index,
                    "selected_test_targets": test_targets,
                    "selected_test_source_files": test_source_paths,
                    "collection": collection,
                    "parts": receipts,
                    "pre_snapshot": source_list_pin,
                    "finished_at": _stamp(),
                },
            )
            return 3 if receipt["status"].startswith("aborted_resource") else 4
    after = []
    for path in normalized_snapshots:
        after.append(_pin(path))
    stable = after == [row["source"] for row in snapshots]
    actual_lists: list[str] = []
    for receipt in receipts:
        actual = _read_json(receipt["actual_ids"]["path"])
        actual_lists.extend(actual["nodeids"])
    expected_ids = collections.Counter(nodeids)
    actual_ids = collections.Counter(actual_lists)
    missing_ids = sorted(
        nodeid for nodeid, count in expected_ids.items() if actual_ids[nodeid] < count
    )
    duplicate_ids = sorted(
        nodeid for nodeid, count in actual_ids.items() if actual_ids[nodeid] > count
    )
    ids_complete = expected_ids == actual_ids and not missing_ids and not duplicate_ids
    all_returncodes_zero = all(receipt.get("returncode") == 0 for receipt in receipts)
    report = {
        "schema": "information.debt_quote_query.bounded_focused_result.v1",
        "status": (
            "passed"
            if stable and ids_complete and all_returncodes_zero
            else "failed_source_changed_during_focus"
            if not stable
            else "failed_nodeid_coverage"
            if not ids_complete
            else "failed_test_returncode"
        ),
        "attempt": attempt_index,
        "selected_test_targets": test_targets,
        "selected_test_source_files": test_source_paths,
        "collection": collection,
        "selected_nodeid_count": len(nodeids),
        "executed_nodeid_count": len(actual_lists),
        "missing_node_ids": missing_ids,
        "duplicate_node_ids": duplicate_ids,
        "nodeid_multiset_matches_collection": ids_complete,
        "part_count": len(receipts),
        "all_parts_returncode_zero": all_returncodes_zero,
        "parts": receipts,
        "pre_snapshot": source_list_pin,
        "snapshot_source_paths": normalized_snapshots,
        "source_pins_after": after,
        "source_pins_stable": stable,
        "no_final_freeze_required": True,
        "created_at": _stamp(),
    }
    _write_new(attempt / "focused-result-001.json", report)
    print(json.dumps({"phase": "focused", "status": report["status"],
                      "nodeid_count": len(nodeids), "part_count": len(receipts)},
                     ensure_ascii=False), flush=True)
    return 0 if report["status"] == "passed" else 4


def _prepare(stage: Path) -> dict:
    baseline, comparison, _postverify, baseline_pins = _verify_parent()
    available = [path for path in sorted(REQUIRED_SOURCES) if (ROOT / path).is_file()]
    missing = sorted(REQUIRED_SOURCES - set(available))
    preparation = {
        "schema": "information.debt_quote_query.bounded_harness_preparation.v1",
        "status": "prepared_inert" if not missing else "prepared_required_sources_pending",
        "batch": 100,
        "revision": "001",
        "baseline": baseline_pins,
        "baseline_source_count": len(baseline["files"]),
        "baseline_terminal_totals": comparison["terminal_totals"],
        "baseline_nodeid_count": comparison["nodeid_count"],
        "baseline_part_count": comparison["part_count"],
        "baseline_junit_summary": comparison["junit_summary"],
        "baseline_bad_occurrences": comparison["current_bad_occurrences"],
        "required_sources": sorted(REQUIRED_SOURCES),
        "present_required_sources": [_pin(path) for path in available],
        "missing_required_sources": missing,
        "limits": {
            "max_batch_items": MAX_BATCH_ITEMS,
            "max_direct_command_chars": MAX_DIRECT_COMMAND_CHARS,
            "memory_stop_bytes": MEMORY_STOP_BYTES,
            "monitor_interval_seconds": MONITOR_INTERVAL_SECONDS,
        },
        "execution_policy": "serial actual-ID batches; full run requires explicit final source freeze",
        "no_source_freeze_created": True,
        "no_collection_started": True,
        "no_test_bodies_started": True,
        "no_full_execution_started": True,
        "created_at": _stamp(),
    }
    destination = stage / "harness-preparation-001"
    if destination.exists():
        raise FileExistsError("harness_preparation_already_exists")
    destination.mkdir(parents=True, exist_ok=False)
    receipt_path = destination / "preparation-receipt-001.json"
    preparation["runner_source"] = _pin(RUNNER)
    preparation["preparation_receipt"] = receipt_path.relative_to(ROOT).as_posix()
    _write_new(receipt_path, preparation)
    return preparation


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--freeze", action="store_true")
    mode.add_argument("--focused", nargs="+", metavar="TEST_FILE_OR_NODEID")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--stage", default=DEFAULT_STAGE.relative_to(ROOT).as_posix())
    parser.add_argument(
        "--source-list",
        help="required by --freeze; optional extra snapshot sources for --focused",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    global _SOURCE_LIST_ARGUMENT
    args = _parser().parse_args(argv)
    _SOURCE_LIST_ARGUMENT = args.source_list
    stage = _workspace_path(args.stage)
    if not RESEARCH_PYTHON.is_file():
        raise FileNotFoundError(f"research_python_missing:{RESEARCH_PYTHON}")
    if args.prepare:
        result = _prepare(stage)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0
    if args.freeze:
        if not args.source_list:
            raise ValueError("--freeze_requires_--source-list")
        result = _freeze(stage, args.source_list)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        return 0
    if args.focused is not None:
        return _focused(stage, args.focused)
    if args.run:
        return _full_run(stage)
    raise AssertionError("unreachable_mode")


if __name__ == "__main__":
    raise SystemExit(main())
