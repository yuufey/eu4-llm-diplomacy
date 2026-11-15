"""One-shot source freeze, pytest, baseline comparison, and post-run verification.

This helper is metadata only and is deliberately excluded from the runtime
source set. It never builds a DLL or contacts the game, RPM, or MCP.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
STAGE = ROOT / "work/runtime/information-battle-recipient-20261028-001"
BASELINE_STAGE = ROOT / "work/runtime/information-diplomacy-state-20261028-001"
BASELINE_FREEZE = BASELINE_STAGE / "source-freeze-001.json"
BASELINE_FULL = BASELINE_STAGE / "regression-full-001.xml"
BASELINE_COMPARISON = BASELINE_STAGE / "regression-comparison-001.json"
CHUNK_BYTES = 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
DEFAULT_PYTHON = Path(r"C:\Users\wangyufei\anaconda3\envs\research\python.exe")

# Existing source paths whose current contents may intentionally differ from
# the batch-70 freeze. Any other baseline source must remain byte-identical.
REVIEWED_EXISTING_PATHS = {
    "work/native/diplomacy-observer-v10.cpp": "v31 frame-loop and startup integration",
    "work/native/automated-control.inc": "current-country-control policy integration",
    "work/native/build-diplomacy-observer.ps1": "v31 build-manifest and source registration",
    "tools/start_diplomacy_observer.py": "v31 manifest validation",
    "tools/control_information_battle_observer.py": "v31 controller validation",
    "work/probe_information_battle_installed.py": "v31 installed probe validation",
    "work/bootstrap_information_battle_subscription.py": "physical-player guard and control request",
    "work/run_information_battle_natural_window.py": "physical-player health guard",
    "work/run_information_battle_natural_window_installed.py": "physical-player argument forwarding",
    "work/validate_information_battle_capture_management_live.py": "physical-player argument forwarding",
    "work/validate_information_battle_capture_autonomous_live.py": "physical-player argument forwarding",
    "bridge/information/battles.py": "canonical B04 raw_text partial projection",
    "bridge/information/battle_native_text.py": "reuse only validated native Line1 text",
    "bridge/information/battle_display.py": "remove Line1 gap only when native text is observed",
    "bridge/tests/test_information_battles.py": "legacy raw_text now has an explicit unknown reason",
    "bridge/tests/test_information_battle_display.py": "validated native Line1 display section",
    "work/validate_information_battle_capture_management_corrective.py": "classify verified consumed country-control receipts",
    "work/prepare_information_battle_natural_window.py": "preserve closed country-control evidence without treating it as pending",
}

CURRENT_COUNTRY_NATIVE = (
    "work/native/information-current-country-control.inc",
    "work/native/information-current-country-control-plan.h",
    "work/native/information-current-country-control-policy.h",
)
CURRENT_COUNTRY_CPP_TESTS = (
    "work/native/tests/information-current-country-control-host-test.cpp",
    "work/native/tests/information-current-country-control-plan-test.cpp",
    "work/native/tests/information-current-country-control-policy-test.cpp",
)
CURRENT_COUNTRY_PYTHON_TESTS = (
    "bridge/tests/test_information_battle_physical_player_helpers.py",
    "bridge/tests/test_information_current_country_manifest.py",
    "bridge/tests/test_information_current_country_control.py",
    "bridge/tests/test_information_battle_raw_text.py",
    "bridge/tests/test_information_country_control_consumed_receipts.py",
)
CURRENT_COUNTRY_OPERATOR = "tools/control_information_current_country.py"
REQUIRED_BATCH_PATHS = tuple(dict.fromkeys((
    *REVIEWED_EXISTING_PATHS,
    CURRENT_COUNTRY_OPERATOR,
    *CURRENT_COUNTRY_NATIVE,
    *CURRENT_COUNTRY_CPP_TESTS,
    *CURRENT_COUNTRY_PYTHON_TESTS,
)))
SEPARATE_HELPERS = (
    "work/verify_information_country_rivals.py",
    "work/verify_information_battle_recipient.py",
    "work/finalize_information_country_rivals.py",
    "work/archive_information_country_rivals.py",
    "work/compare_information_battle_native_title_regression.py",
    "work/finalize_information_trade_transfer.py",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    pass


def _root_path(raw: str | Path) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise VerificationError(f"path_outside_workspace:{raw}") from exc
    return resolved


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def _pin(path: Path) -> dict[str, Any]:
    path = path.resolve(strict=True)
    if not path.is_file():
        raise VerificationError(f"not_a_file:{path}")
    before = path.stat()
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise VerificationError(f"file_changed_during_hash:{path}")
    return {"path": _relative(path), "bytes": size, "sha256": digest.hexdigest()}


def _read_json(path: Path) -> Any:
    if not path.is_file():
        raise VerificationError(f"missing_json:{path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise VerificationError(f"json_over_bound:{path}")
    try:
        with path.open("r", encoding="utf-8-sig") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid_json:{path}:{type(exc).__name__}") from exc


def _write_new(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except FileExistsError as exc:
        raise VerificationError(f"output_exists:{path}") from exc


def _copy_stream(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open("rb") as src, target.open("xb") as dst:
            while chunk := src.read(CHUNK_BYTES):
                dst.write(chunk)
    except FileExistsError as exc:
        raise VerificationError(f"snapshot_exists:{target}") from exc


def _baseline_inputs(freeze_path: Path, full_path: Path,
                     comparison_path: Path) -> tuple[dict, dict, dict[str, Any]]:
    freeze = _read_json(freeze_path)
    if (freeze.get("status") != "passed" or freeze.get("batch") != 70
            or freeze.get("count") != 184 or len(freeze.get("files", [])) != 184):
        raise VerificationError("batch70_baseline_must_be_passed_184_source_freeze")
    if freeze.get("schema") != "information.country_rivals.source_freeze.v1":
        raise VerificationError("batch70_baseline_freeze_schema_mismatch")

    seen: set[str] = set()
    changes: list[dict[str, Any]] = []
    for item in freeze["files"]:
        source, snapshot = item.get("source"), item.get("snapshot")
        if not isinstance(source, dict) or not isinstance(snapshot, dict):
            raise VerificationError("batch70_baseline_source_record_invalid")
        source_path = _root_path(source.get("path", ""))
        source_name = _relative(source_path)
        if source_name in seen:
            raise VerificationError(f"batch70_baseline_duplicate_source:{source_name}")
        seen.add(source_name)
        if (source.get("bytes") != snapshot.get("bytes")
                or source.get("sha256") != snapshot.get("sha256")):
            raise VerificationError(f"batch70_original_snapshot_pin_mismatch:{source_name}")

        snapshot_path = _root_path(snapshot.get("path", ""))
        if _pin(snapshot_path) != snapshot:
            raise VerificationError(f"batch70_original_snapshot_changed:{source_name}")
        current = _pin(source_path)
        if current != source:
            reason = REVIEWED_EXISTING_PATHS.get(source_name)
            if reason is None:
                raise VerificationError(f"unreviewed_batch70_source_change:{source_name}")
            changes.append({"path": source_name, "before": source,
                            "after": current, "reason": reason})

    baseline_comparison = _read_json(comparison_path)
    if baseline_comparison.get("no_new_bad") is not True:
        raise VerificationError("batch70_baseline_comparison_not_no_new_bad")
    full_pin = _pin(full_path)
    comp_xml = baseline_comparison.get("current_xml")
    if (not isinstance(comp_xml, dict)
            or comp_xml.get("sha256") != full_pin["sha256"]
            or comp_xml.get("bytes") != full_pin["bytes"]):
        raise VerificationError("batch70_baseline_comparison_xml_pin_mismatch")
    return freeze, baseline_comparison, {
        "freeze": _pin(freeze_path),
        "full": full_pin,
        "comparison": _pin(comparison_path),
        "reviewed_existing_changes": changes,
    }


def _validate_manifest(manifest_path: Path) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    manifest = _read_json(manifest_path)
    required_traits = {
        "version": 31,
        "compiled": True,
        "runtime_verified": False,
        "native_war_participants_query": True,
        "information_battle_research_lifecycle": True,
        "information_battle_context_wire": 2,
        "information_battle_owned_context": True,
        "information_battle_naval_wire": 3,
        "information_battle_owned_naval": True,
        "information_battle_template_wire": 4,
        "information_battle_owned_template": True,
        "information_battle_message_scope": True,
        "information_battle_formatter_container": True,
        "information_battle_template_extensions": [1, 2],
        "information_battle_war_identity": True,
        "information_battle_war_identity_wire": 5,
        "information_battle_war_identity_scope": "observer_session",
        "information_battle_war_identity_read_only": True,
        "information_battle_war_identity_complete": False,
        "information_battle_native_text": True,
        "information_battle_native_text_wire": 6,
        "information_battle_native_text_scope": "observer_session",
        "information_battle_native_text_read_only": True,
        "information_battle_native_text_complete": False,
        "information_battle_native_title_query": True,
        "information_battle_native_title_query_mode": "native_helper_owned_output",
        "information_battle_native_title_query_wire": 6,
        "information_battle_native_title_query_complete": False,
        "current_country_control_test_only": True,
        "current_country_control_protocol": "EU4COUNTRY1",
        "current_country_control_entry_rva": "0x779360",
    }
    for key, expected in required_traits.items():
        if manifest.get(key) != expected:
            raise VerificationError(f"build_manifest_trait_mismatch:{key}")
    if manifest.get("game_sha256") != EXPECTED_EXE_SHA256:
        raise VerificationError("build_manifest_game_sha_mismatch")
    dll_sha = manifest.get("dll_sha256")
    if not isinstance(dll_sha, str) or HEX64.fullmatch(dll_sha) is None:
        raise VerificationError("build_manifest_dll_sha_invalid")

    arguments = manifest.get("compiler_arguments")
    if not isinstance(arguments, list) or "-DBRIDGE_CURRENT_COUNTRY_CONTROL=1" not in arguments:
        raise VerificationError("build_manifest_current_country_macro_missing")
    if any("INFORMATION_CURRENT_COUNTRY_HOST_FIXTURE" in str(item) for item in arguments):
        raise VerificationError("host_fixture_macro_cannot_be_in_compiled_manifest")

    rows = manifest.get("sources")
    if not isinstance(rows, list) or len(rows) != 122:
        raise VerificationError("v31_manifest_expected_122_native_sources")
    source_paths: list[str] = []
    seen: set[str] = set()
    native_hashes: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise VerificationError("build_manifest_source_record_invalid")
        name, expected_sha = row.get("name"), row.get("sha256")
        if (not isinstance(name, str) or not name or Path(name).name != name
                or ".." in name or not isinstance(expected_sha, str)
                or HEX64.fullmatch(expected_sha) is None):
            raise VerificationError("build_manifest_source_path_or_hash_invalid")
        source_name = f"work/native/{name}"
        if source_name in seen:
            raise VerificationError(f"build_manifest_duplicate_source:{source_name}")
        seen.add(source_name)
        actual = _pin(_root_path(source_name))
        if actual["sha256"] != expected_sha:
            raise VerificationError(f"build_manifest_source_sha_mismatch:{source_name}")
        source_paths.append(source_name)
        native_hashes[source_name] = expected_sha
    missing = set(CURRENT_COUNTRY_NATIVE) - seen
    if missing:
        raise VerificationError("build_manifest_current_country_sources_missing:" + ",".join(sorted(missing)))

    dll_value = manifest.get("dll")
    if not isinstance(dll_value, str) or not dll_value:
        raise VerificationError("build_manifest_dll_path_missing")
    dll_path = _root_path(dll_value)
    if dll_path.name != "eu4_bridge_diplomacy_observer_v31.dll":
        raise VerificationError("build_manifest_dll_version_path_mismatch")
    dll_pin = _pin(dll_path)
    if dll_pin["sha256"] != dll_sha:
        raise VerificationError("build_manifest_dll_sha_mismatch")
    return manifest, source_paths, {
        "path": _pin(manifest_path),
        "source_count": len(source_paths),
        "dll": dll_pin,
        "native_hashes": native_hashes,
    }


def _metadata_pins() -> list[dict[str, Any]]:
    return [_pin(_root_path(name)) for name in SEPARATE_HELPERS]


def freeze(revision: str, manifest_path: Path,
           baseline_freeze: Path, baseline_full: Path,
           baseline_comparison: Path) -> int:
    output = STAGE / f"source-freeze-{revision}.json"
    snapshot_root = STAGE / f"source-snapshots-{revision}"
    if output.exists() or snapshot_root.exists():
        raise VerificationError("freeze_revision_already_used")
    baseline, old_comparison, baseline_pins = _baseline_inputs(
        baseline_freeze, baseline_full, baseline_comparison)
    _, native_paths, build_info = _validate_manifest(manifest_path)

    names: list[str] = []
    seen: set[str] = set()
    for item in baseline["files"]:
        name = _relative(_root_path(item["source"]["path"]))
        if name not in seen:
            names.append(name)
            seen.add(name)
    for name in (*native_paths, *REQUIRED_BATCH_PATHS):
        name = _relative(_root_path(name))
        if name in SEPARATE_HELPERS:
            raise VerificationError(f"metadata_helper_in_runtime_set:{name}")
        if name not in seen:
            _pin(ROOT / name)
            names.append(name)
            seen.add(name)

    native_hashes = build_info["native_hashes"]
    files: list[dict[str, Any]] = []
    for name in names:
        source = ROOT / name
        before = _pin(source)
        if name in native_hashes and before["sha256"] != native_hashes[name]:
            raise VerificationError(f"manifest_source_changed_before_snapshot:{name}")
        snapshot = snapshot_root / name
        _copy_stream(source, snapshot)
        copied = _pin(snapshot)
        after = _pin(source)
        if copied["sha256"] != before["sha256"] or after != before:
            raise VerificationError(f"source_snapshot_race_or_mismatch:{name}")
        files.append({"source": before, "snapshot": copied})

    metadata = _metadata_pins()
    baseline_paths = {
        _relative(_root_path(item["source"]["path"])) for item in baseline["files"]
    }
    value = {
        "schema": "information.battle_recipient.source_freeze.v1",
        "status": "passed",
        "batch": 71,
        "revision": revision,
        "count": len(files),
        "baseline": {
            **baseline_pins,
            "batch": 70,
            "source_count": len(baseline["files"]),
            "no_new_bad": old_comparison["no_new_bad"],
        },
        "build_manifest": {key: value for key, value in build_info.items()
                            if key != "native_hashes"},
        "manifest_native_sources": native_paths,
        "required_batch_paths": list(REQUIRED_BATCH_PATHS),
        "additional_sources": [name for name in names if name not in baseline_paths],
        "deduplicated": True,
        "hash_chunk_bytes": CHUNK_BYTES,
        "separate_metadata_helpers": {
            "runtime_freeze_member": False,
            "pins_scope": "pinned_separately_at_freeze_and_rechecked_post_run",
            "pins": metadata,
        },
        "files": files,
    }
    _write_new(output, value)
    print(json.dumps({"status": "passed", "phase": "freeze", "revision": revision,
                      "source_count": len(files)}, ensure_ascii=False))
    return 0


def _verify_frozen(revision: str, baseline_freeze: Path,
                   baseline_full: Path, baseline_comparison: Path) -> tuple[dict, dict]:
    freeze_path = STAGE / f"source-freeze-{revision}.json"
    frozen = _read_json(freeze_path)
    if (frozen.get("status") != "passed" or frozen.get("batch") != 71
            or frozen.get("revision") != revision):
        raise VerificationError("invalid_batch71_source_freeze")
    files = frozen.get("files")
    if not isinstance(files, list) or frozen.get("count") != len(files):
        raise VerificationError("batch71_source_count_mismatch")
    baseline, comparison, baseline_pins = _baseline_inputs(
        baseline_freeze, baseline_full, baseline_comparison)
    if frozen.get("baseline", {}).get("freeze", {}).get("sha256") != baseline_pins["freeze"]["sha256"]:
        raise VerificationError("baseline_freeze_changed_since_freeze")
    if frozen.get("baseline", {}).get("full", {}).get("sha256") != baseline_pins["full"]["sha256"]:
        raise VerificationError("baseline_full_changed_since_freeze")
    if frozen.get("baseline", {}).get("comparison", {}).get("sha256") != baseline_pins["comparison"]["sha256"]:
        raise VerificationError("baseline_comparison_changed_since_freeze")

    build_record = frozen.get("build_manifest")
    if not isinstance(build_record, dict) or not isinstance(build_record.get("path"), dict):
        raise VerificationError("build_manifest_pin_missing_from_freeze")
    manifest_path = _root_path(build_record["path"].get("path", ""))
    _, native_paths, current_build_record = _validate_manifest(manifest_path)
    if (current_build_record["path"] != build_record["path"]
            or current_build_record["dll"] != build_record.get("dll")
            or current_build_record["source_count"] != build_record.get("source_count")
            or native_paths != frozen.get("manifest_native_sources")):
        raise VerificationError("build_manifest_or_dll_changed_since_freeze")

    seen: set[str] = set()
    for item in files:
        source, snapshot = item.get("source"), item.get("snapshot")
        if not isinstance(source, dict) or not isinstance(snapshot, dict):
            raise VerificationError("batch71_source_record_invalid")
        source_path = _root_path(source.get("path", ""))
        name = _relative(source_path)
        if name in seen:
            raise VerificationError(f"batch71_duplicate_source:{name}")
        seen.add(name)
        if _pin(source_path) != source:
            raise VerificationError(f"frozen_source_changed:{name}")
        if _pin(_root_path(snapshot.get("path", ""))) != snapshot:
            raise VerificationError(f"frozen_snapshot_changed:{name}")
    frozen_paths = seen
    if any(name in frozen_paths for name in SEPARATE_HELPERS):
        raise VerificationError("metadata_helper_in_runtime_freeze")

    helpers = frozen.get("separate_metadata_helpers", {}).get("pins")
    if not isinstance(helpers, list) or len(helpers) != len(SEPARATE_HELPERS):
        raise VerificationError("metadata_helper_pins_missing")
    helper_paths = {item.get("path") for item in helpers if isinstance(item, dict)}
    if helper_paths != set(SEPARATE_HELPERS):
        raise VerificationError("metadata_helper_pin_set_mismatch")
    for expected in helpers:
        if _pin(_root_path(expected.get("path", ""))) != expected:
            raise VerificationError(f"metadata_helper_changed:{expected.get('path')}")
    return frozen, {"baseline": baseline, "comparison": comparison,
                    "baseline_pins": baseline_pins}


def full(revision: str, baseline_freeze: Path,
         baseline_full: Path, baseline_comparison: Path) -> int:
    frozen, _ = _verify_frozen(revision, baseline_freeze, baseline_full, baseline_comparison)
    python_exe = DEFAULT_PYTHON
    if not python_exe.is_file():
        raise VerificationError(f"research_python_missing:{python_exe}")
    xml = STAGE / f"regression-full-{revision}.xml"
    log = STAGE / f"regression-full-{revision}.log"
    reservation = STAGE / f"full-execution-reservation-{revision}.json"
    boundary = STAGE / f"full-execution-boundary-{revision}.json"
    if any(path.exists() for path in (xml, log, reservation, boundary)):
        raise VerificationError("full_revision_already_reserved_or_run")
    command = [str(python_exe), "-B", "-m", "pytest", "-q", "bridge/tests",
               "--junitxml", str(xml)]
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    _write_new(reservation, {"schema": "information.battle_recipient.full_reservation.v1",
                             "revision": revision, "runs": 1, "status": "started",
                             "frozen_source_count": frozen["count"], "command": command,
                             "started_at": started})
    returncode: int | None = None
    error: str | None = None
    try:
        with log.open("xb") as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream,
                                    stderr=subprocess.STDOUT, check=False)
        returncode = result.returncode
    except OSError as exc:
        error = f"{type(exc).__name__}:{exc}"
    receipt = {
        "schema": "information.battle_recipient.full_execution_boundary.v1",
        "revision": revision, "runs": 1,
        "status": "completed" if returncode is not None else "failed_to_start_or_collect",
        "command": command, "started_at": started,
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "returncode": returncode, "error": error,
        "xml": _pin(xml) if xml.is_file() else None,
        "log": _pin(log) if log.is_file() else None,
        "reservation": _pin(reservation),
    }
    _write_new(boundary, receipt)
    print(json.dumps({"phase": "full", "revision": revision,
                      "returncode": returncode, "runs": 1,
                      "xml_written": receipt["xml"] is not None}, ensure_ascii=False))
    return returncode if returncode is not None else 2


def compare(revision: str, baseline_freeze: Path,
            baseline_full: Path, baseline_comparison: Path) -> int:
    _verify_frozen(revision, baseline_freeze, baseline_full, baseline_comparison)
    xml = STAGE / f"regression-full-{revision}.xml"
    log = STAGE / f"regression-full-{revision}.log"
    boundary = _read_json(STAGE / f"full-execution-boundary-{revision}.json")
    if (boundary.get("status") != "completed" or boundary.get("runs") != 1
            or boundary.get("xml") != _pin(xml) or boundary.get("log") != _pin(log)):
        raise VerificationError("full_execution_receipt_or_artifact_mismatch")
    output = STAGE / f"regression-comparison-{revision}.json"
    if output.exists():
        raise VerificationError("comparison_revision_already_written")
    base_comparison = _read_json(baseline_comparison)
    from work.compare_information_battle_native_title_regression import compare as compare_xml

    value = compare_xml(baseline_full, xml)
    value.update({
        "schema": "information.battle_recipient.regression_comparison.v1",
        "revision": revision,
        "baseline_batch": 70,
        "baseline_full": _pin(baseline_full),
        "baseline_comparison": _pin(baseline_comparison),
        "baseline_no_new_bad": base_comparison["no_new_bad"],
    })
    value["no_new_bad"] = (
        base_comparison["no_new_bad"] is True
        and not value["new_failure_nodes"]
        and not value["new_test_failures"]
    )
    value["status"] = ("passed_no_new_bad" if value["no_new_bad"]
                        else "failed_new_bad_or_baseline_not_qualified")
    _write_new(output, value)
    print(json.dumps({"phase": "compare", "revision": revision,
                      "status": value["status"],
                      "new_failure_nodes": len(value["new_failure_nodes"]),
                      "new_test_failures": len(value["new_test_failures"])}, ensure_ascii=False))
    return 0 if value["no_new_bad"] else 2


def verify(revision: str, baseline_freeze: Path,
           baseline_full: Path, baseline_comparison: Path) -> int:
    frozen, info = _verify_frozen(revision, baseline_freeze, baseline_full, baseline_comparison)
    boundary = _read_json(STAGE / f"full-execution-boundary-{revision}.json")
    comparison_path = STAGE / f"regression-comparison-{revision}.json"
    comparison_value = _read_json(comparison_path)
    if boundary.get("status") != "completed" or boundary.get("runs") != 1:
        raise VerificationError("full_execution_not_completed_once")
    xml_pin = _pin(STAGE / f"regression-full-{revision}.xml")
    log_pin = _pin(STAGE / f"regression-full-{revision}.log")
    reservation_pin = _pin(STAGE / f"full-execution-reservation-{revision}.json")
    if (boundary.get("xml") != xml_pin or boundary.get("log") != log_pin
            or boundary.get("reservation") != reservation_pin):
        raise VerificationError("full_execution_artifact_pin_mismatch")
    if comparison_value.get("no_new_bad") is not True:
        raise VerificationError("regression_comparison_not_no_new_bad")
    if (comparison_value.get("baseline_full") != info["baseline_pins"]["full"]
            or comparison_value.get("baseline_comparison") != info["baseline_pins"]["comparison"]
            or comparison_value.get("current_xml") != _pin(STAGE / f"regression-full-{revision}.xml")):
        raise VerificationError("regression_comparison_input_pins_mismatch")
    output = STAGE / f"source-post-run-verification-{revision}.json"
    value = {
        "schema": "information.battle_recipient.source_post_run_verification.v1",
        "status": "passed",
        "revision": revision,
        "source_count": frozen["count"],
        "source_freeze": _pin(STAGE / f"source-freeze-{revision}.json"),
        "current_sources_match_snapshots": True,
        "baseline70_snapshots_match_original_pins": True,
        "baseline70_no_new_bad": info["comparison"]["no_new_bad"],
        "full_execution": _pin(STAGE / f"full-execution-boundary-{revision}.json"),
        "regression_comparison": _pin(comparison_path),
        "metadata_helpers_runtime_freeze_member": False,
        "metadata_helpers_match_separate_pins": True,
        "hash_chunk_bytes": CHUNK_BYTES,
    }
    _write_new(output, value)
    print(json.dumps({"phase": "verify", "revision": revision,
                      "status": value["status"], "source_count": frozen["count"]},
                     ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("freeze", "full", "compare", "verify"))
    parser.add_argument("--revision", type=int, default=1,
                        help="each revision has exclusive freeze/full/comparison outputs")
    parser.add_argument("--build-manifest", type=Path,
                        help="required only for freeze; the compiled v31 manifest")
    parser.add_argument("--baseline-freeze", type=Path, default=BASELINE_FREEZE)
    parser.add_argument("--baseline-full", type=Path, default=BASELINE_FULL)
    parser.add_argument("--baseline-comparison", type=Path, default=BASELINE_COMPARISON)
    args = parser.parse_args(argv)
    if args.revision < 1 or args.revision > 999:
        parser.error("--revision must be in 1..999")
    revision = f"{args.revision:03d}"
    try:
        baseline_freeze = _root_path(args.baseline_freeze)
        baseline_full = _root_path(args.baseline_full)
        baseline_comparison = _root_path(args.baseline_comparison)
        if args.phase == "freeze":
            if args.build_manifest is None:
                parser.error("freeze requires --build-manifest")
            return freeze(revision, _root_path(args.build_manifest),
                          baseline_freeze, baseline_full, baseline_comparison)
        if args.phase == "full":
            return full(revision, baseline_freeze, baseline_full, baseline_comparison)
        if args.phase == "compare":
            return compare(revision, baseline_freeze, baseline_full, baseline_comparison)
        return verify(revision, baseline_freeze, baseline_full, baseline_comparison)
    except (OSError, ValueError, VerificationError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "failed", "phase": args.phase,
                          "revision": revision,
                          "error": f"{type(exc).__name__}:{exc}"}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
