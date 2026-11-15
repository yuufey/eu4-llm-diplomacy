"""Re-analyse the archived military-quality capture without new RPM.

The archived report was marked ``doublepass_mismatch`` only because the child
reader recorded the parent's cumulative byte count at the start of each pass.
This script validates that accounting explanation from the saved JSON, removes
only that one bookkeeping member from deep copies of the two inputs, and
compares the resulting canonical records.  It never imports a production
military-quality reader, opens a process, calls the game, or uses MCP values.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-military-quality-20261027-001"
INPUT_REPORT = STAGE / "native-military-quality-inputs-001.json"
EXPECTED_OUTPUT = STAGE / "expected-military-quality-001.json"
REANALYSIS_OUTPUT = STAGE / "reference-accounting-reanalysis-001.json"

EXPECTED_REPORT_SHA256 = (
    "e69c35435cad35155843b0e028a4b5b78d66cf02b0ec48fbe54792941f2f6800"
)
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_SESSION_ID = "31460-1dd653f69242d7b"
EXPECTED_CREATION_FILETIME = 134374886912306555
EXPECTED_GAME_DATE = 56557728
EXPECTED_COUNTRY = "FRA"
EXPECTED_FULLREF_RAW_HEX = "465241007a000001"
EXPECTED_COUNTRY_SLOT = 122
EXPECTED_TECHNOLOGY_RAW_HEX = "04000000"
EXPECTED_TECHNOLOGY_VALUE = 4
EXPECTED_ARMY_TRADITION_RAW_HEX = "3c520000"
EXPECTED_ARMY_TRADITION_VALUE = 21052
EXPECTED_RPM_BYTES = 50710
EXPECTED_RPM_CALLS = 1080

SOURCE_PIN_SPECS = (
    ("archived_native_input_report", INPUT_REPORT, EXPECTED_REPORT_SHA256, "archived_independent_RPM_capture"),
    (
        "military_technology_source_002",
        STAGE / "military-technology-source-002.json",
        "fb642e67080996395f5b8e9568fb2de0465e203a28626c22d895147a26e4f5a4",
        "bounded_static_technology_source",
    ),
    (
        "military_technology_code_003",
        STAGE / "military-technology-code-003.json",
        "286b74fdb83da462ace8694bb27449c3e11366e7d401f7cf0e3356f15f625cc5",
        "bounded_static_technology_guard",
    ),
    (
        "military_technology_code_004",
        STAGE / "military-technology-code-004.json",
        "a1b3cf3b22b73cc6b0e9fe4b379ff4481c919a9a6e8b564205d11640cbf8c49f",
        "bounded_static_technology_guard",
    ),
    (
        "military_technology_code_005",
        STAGE / "military-technology-code-005.json",
        "742a0b6db8c7654ef69c836f94772d1cace88714bba7e6fdda66f55d09e2f9b9",
        "bounded_static_technology_guard",
    ),
    (
        "army_tradition_source_002",
        STAGE / "tradition-source-002.json",
        "fac0aa3393c5e23d1866a584f3ae9041da441d81667339ad60bab643f811776a",
        "direct_country_cache_getter",
    ),
    (
        "army_tradition_source_003",
        STAGE / "tradition-source-003.json",
        "64721bc7c80c8adfd9a4db99cc5a1aeeeec6c8a34e09ccee1dbdf67ade69b611",
        "bounded_static_scale_candidate",
    ),
    (
        "army_tradition_source_004",
        STAGE / "tradition-source-004.json",
        "df63aa6650d1d39e94f165ebd3b9f938cad1784eb0971a4360e30ab97446e1d1",
        "bounded_static_explicit_scale_1000",
    ),
    (
        "army_tradition_source_005",
        STAGE / "tradition-source-005.json",
        "f0bb93551e05ea8b75929613431e301a7c6d0d193ee47476575399619c8a480a",
        "bounded_static_serializer_width_no_hidden_scale",
    ),
    (
        "army_tradition_profile",
        ROOT / "bridge/information/profiles/military-tradition-memory-1374.json",
        "638f356e2244c903f9a82db6ce6a51a00662d73d9e14b4dd2d945c1c3b5ae20d",
        "pinned_runtime_child_profile",
    ),
)


class ReferenceError(RuntimeError):
    """The archived report does not satisfy the fixed re-analysis contract."""


def _sha256_file(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> str:
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ReferenceError(f"file_size_out_of_bound:{path}:{size}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if path.stat().st_size != size:
        raise ReferenceError(f"file_changed_during_hash:{path}")
    return digest.hexdigest()


def _load_json(path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ReferenceError(f"json_size_out_of_bound:{path}:{size}")
    with path.open("rb") as stream:
        raw = stream.read(size + 1)
    if len(raw) != size:
        raise ReferenceError(f"json_size_changed:{path}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReferenceError(f"json_invalid:{path}:{exc}") from exc
    if not isinstance(value, dict):
        raise ReferenceError(f"json_root_not_object:{path}")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256_bytes(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _diff_paths(left: Any, right: Any, path: str = "") -> list[dict[str, Any]]:
    if type(left) is not type(right):
        return [{"path": path or "$", "left": left, "right": right}]
    if isinstance(left, dict):
        differences: list[dict[str, Any]] = []
        for key in sorted(set(left) | set(right)):
            child_path = f"{path}.{key}" if path else key
            if key not in left:
                differences.append({"path": child_path, "left": "<missing>", "right": right[key]})
            elif key not in right:
                differences.append({"path": child_path, "left": left[key], "right": "<missing>"})
            else:
                differences.extend(_diff_paths(left[key], right[key], child_path))
        return differences
    if isinstance(left, list):
        differences = []
        if len(left) != len(right):
            differences.append({"path": f"{path}.length", "left": len(left), "right": len(right)})
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            differences.extend(_diff_paths(left_item, right_item, f"{path}[{index}]"))
        return differences
    if left != right:
        return [{"path": path or "$", "left": left, "right": right}]
    return []


def _strip_accounting_member(value: dict[str, Any]) -> dict[str, Any]:
    copy_value = copy.deepcopy(value)
    budget = copy_value.get("child_budget")
    if not isinstance(budget, dict) or "parent_bytes_before" not in budget:
        raise ReferenceError("missing_child_budget_parent_bytes_before")
    del budget["parent_bytes_before"]
    return copy_value


def _i32(raw_hex: str, label: str) -> int:
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ReferenceError(f"{label}_raw_hex_invalid") from exc
    if len(raw) != 4:
        raise ReferenceError(f"{label}_raw_width:{len(raw)}")
    return struct.unpack("<i", raw)[0]


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path.resolve())


def _source_pins() -> list[dict[str, Any]]:
    pins: list[dict[str, Any]] = []
    for name, path, expected_sha, role in SOURCE_PIN_SPECS:
        actual_sha = _sha256_file(path)
        if actual_sha != expected_sha:
            raise ReferenceError(f"source_sha256_mismatch:{name}")
        pins.append(
            {
                "name": name,
                "path": _relative(path),
                "bytes": path.stat().st_size,
                "sha256": actual_sha,
                "role": role,
                "status": "observed",
            }
        )
    return pins


def _identity(report: dict[str, Any], inputs: list[dict[str, Any]]) -> dict[str, Any]:
    identity = report.get("identity")
    if not isinstance(identity, dict):
        raise ReferenceError("identity_missing")
    expected_identity = {
        "installation_pid": 31460,
        "installation_creation_filetime": EXPECTED_CREATION_FILETIME,
        "installation_session_id": EXPECTED_SESSION_ID,
        "process_path_sha256": EXPECTED_EXE_SHA256,
        "process_creation_filetime": EXPECTED_CREATION_FILETIME,
    }
    for key, expected in expected_identity.items():
        if identity.get(key) != expected:
            raise ReferenceError(f"identity_mismatch:{key}")
    if report.get("country") != EXPECTED_COUNTRY:
        raise ReferenceError("report_country_mismatch")
    if report.get("target_build", {}).get("version") != "1.37.4":
        raise ReferenceError("game_version_mismatch")
    if len(inputs) != 2:
        raise ReferenceError(f"expected_two_inputs:{len(inputs)}")

    matches: list[dict[str, Any]] = []
    dates: list[int] = []
    for value in inputs:
        country = value.get("country")
        if not isinstance(country, dict):
            raise ReferenceError("input_country_missing")
        if country.get("requested_country") != EXPECTED_COUNTRY:
            raise ReferenceError("input_requested_country_mismatch")
        rows = country.get("matches")
        if not isinstance(rows, list) or len(rows) != 1:
            raise ReferenceError("input_country_match_shape")
        match = rows[0]
        if match.get("tag") != EXPECTED_COUNTRY or match.get("slot") != EXPECTED_COUNTRY_SLOT:
            raise ReferenceError("input_country_match_identity_mismatch")
        if match.get("handle_raw_hex") != EXPECTED_FULLREF_RAW_HEX:
            raise ReferenceError("input_country_fullref_mismatch")
        matches.append(match)
        date = value.get("date", {}).get("value")
        if date != EXPECTED_GAME_DATE:
            raise ReferenceError("input_game_date_mismatch")
        dates.append(date)
    if matches[0] != matches[1] or dates[0] != dates[1]:
        raise ReferenceError("input_identity_changed_between_passes")
    return {
        "session_id": identity["installation_session_id"],
        "creation_filetime": identity["installation_creation_filetime"],
        "game_date": EXPECTED_GAME_DATE,
        "country": EXPECTED_COUNTRY,
        "country_fullref_raw_hex": EXPECTED_FULLREF_RAW_HEX,
        "country_slot": EXPECTED_COUNTRY_SLOT,
        "game_version": report["target_build"]["version"],
        "exe_sha256": identity["process_path_sha256"],
        "pid": identity["installation_pid"],
    }


def _field_metadata(inputs: list[dict[str, Any]], pins: list[dict[str, Any]]) -> dict[str, Any]:
    technology_values: list[int] = []
    technology_raw: list[str] = []
    technology_addresses: list[dict[str, Any]] = []
    tradition_values: list[int] = []
    tradition_raw: list[str] = []
    tradition_addresses: list[dict[str, Any]] = []
    for value in inputs:
        selected = value.get("technology", {}).get("selected_level")
        if not isinstance(selected, dict):
            raise ReferenceError("selected_level_missing")
        raw_hex = selected.get("raw_hex")
        if raw_hex != EXPECTED_TECHNOLOGY_RAW_HEX:
            raise ReferenceError("technology_raw_mismatch")
        decoded = _i32(raw_hex, "military_technology")
        if decoded != EXPECTED_TECHNOLOGY_VALUE or selected.get("raw") != decoded:
            raise ReferenceError("technology_decoded_value_mismatch")
        technology_values.append(decoded)
        technology_raw.append(raw_hex)
        technology_addresses.append(selected.get("address"))

        tradition = value.get("army_tradition")
        if not isinstance(tradition, dict):
            raise ReferenceError("army_tradition_missing")
        tradition_hex = value.get("army_tradition_raw_hex")
        if tradition_hex != EXPECTED_ARMY_TRADITION_RAW_HEX:
            raise ReferenceError("army_tradition_raw_mismatch")
        tradition_value = _i32(tradition_hex, "army_tradition")
        if tradition_value != EXPECTED_ARMY_TRADITION_VALUE or value.get("army_tradition_raw") != tradition_value:
            raise ReferenceError("army_tradition_decoded_value_mismatch")
        tradition_values.append(tradition_value)
        tradition_raw.append(tradition_hex)
        tradition_addresses.append(tradition.get("address"))

    tradition_source_names = {
        pin["name"] for pin in pins if pin["name"].startswith("army_tradition_source_")
    }
    if not {"army_tradition_source_003", "army_tradition_source_004", "army_tradition_source_005"} <= tradition_source_names:
        raise ReferenceError("army_tradition_source_pin_missing")
    return {
        "military_technology": {
            "status": "observed",
            "raw": technology_values[0],
            "raw_hex": technology_raw[0],
            "width": 4,
            "signed": True,
            "unit": "technology_level",
            "scale": 1,
            "period": "current",
            "basis": "native_country_technology_cache",
            "value_origin": "copied_native_country_technology_cache",
            "source_path": "military_quality_inputs[*].technology.selected_level.raw_hex",
            "source_addresses": technology_addresses,
            "two_pass_raw_equal": technology_raw[0] == technology_raw[1],
            "two_pass_decoded_equal": technology_values[0] == technology_values[1],
        },
        "army_tradition": {
            "status": "observed",
            "raw": tradition_values[0],
            "raw_hex": tradition_raw[0],
            "width": 4,
            "signed": True,
            "unit": "army_tradition",
            "scale": 1000,
            "period": "current",
            "basis": "native_country_army_tradition_cache",
            "value_origin": "copied_native_country_army_tradition_cache",
            "source_path": "military_quality_inputs[*].army_tradition_raw_hex",
            "source_addresses": tradition_addresses,
            "two_pass_raw_equal": tradition_raw[0] == tradition_raw[1],
            "two_pass_decoded_equal": tradition_values[0] == tradition_values[1],
            "static_scale_evidence": {
                "source_reports": [
                    "army_tradition_source_003",
                    "army_tradition_source_004",
                    "army_tradition_source_005",
                ],
                "source_004_explicit_formatter_scale": 1000,
                "source_005_no_hidden_scale_in_serializer": True,
                "profile_sha256": next(
                    pin["sha256"] for pin in pins if pin["name"] == "army_tradition_profile"
                ),
            },
        },
    }


def _accounting(report: dict[str, Any], inputs: list[dict[str, Any]]) -> dict[str, Any]:
    access = report.get("access")
    if not isinstance(access, dict):
        raise ReferenceError("access_summary_missing")
    if access.get("rpm_bytes_requested") != EXPECTED_RPM_BYTES:
        raise ReferenceError("rpm_total_bytes_mismatch")
    if access.get("rpm_calls") != EXPECTED_RPM_CALLS:
        raise ReferenceError("rpm_total_calls_mismatch")
    if access.get("native_game_calls") is not False or access.get("target_memory_writes") is not False:
        raise ReferenceError("capture_not_read_only")

    passes: list[dict[str, Any]] = []
    for index, value in enumerate(inputs):
        budget = value.get("child_budget")
        if not isinstance(budget, dict):
            raise ReferenceError(f"child_budget_missing:{index}")
        if budget.get("reserved_bytes") != 65536 or budget.get("attempted_bytes") != 144 or budget.get("calls") != 10:
            raise ReferenceError(f"child_budget_shape_mismatch:{index}")
        parent_before = budget.get("parent_bytes_before")
        if not isinstance(parent_before, int):
            raise ReferenceError(f"child_parent_before_missing:{index}")
        passes.append(
            {
                "pass": index,
                "parent_bytes_before": parent_before,
                "child_attempted_bytes": budget["attempted_bytes"],
                "child_calls": budget["calls"],
                "parent_bytes_after_child": parent_before + budget["attempted_bytes"],
                "reserved_bytes": budget["reserved_bytes"],
                "remaining_reserved_bytes": budget["remaining_reserved_bytes"],
                "read_log_entries": len(value.get("child_read_log", [])),
            }
        )
    if passes != [
        {
            "pass": 0,
            "parent_bytes_before": 25211,
            "child_attempted_bytes": 144,
            "child_calls": 10,
            "parent_bytes_after_child": 25355,
            "reserved_bytes": 65536,
            "remaining_reserved_bytes": 65392,
            "read_log_entries": 10,
        },
        {
            "pass": 1,
            "parent_bytes_before": 50566,
            "child_attempted_bytes": 144,
            "child_calls": 10,
            "parent_bytes_after_child": 50710,
            "reserved_bytes": 65536,
            "remaining_reserved_bytes": 65392,
            "read_log_entries": 10,
        },
    ]:
        raise ReferenceError("child_accounting_values_mismatch")
    return {
        "rpm_bytes_requested": access["rpm_bytes_requested"],
        "rpm_calls": access["rpm_calls"],
        "passes": passes,
        "child_attempted_bytes_total": sum(item["child_attempted_bytes"] for item in passes),
        "child_calls_total": sum(item["child_calls"] for item in passes),
        "budget_member_used_for_mismatch": "child_budget.parent_bytes_before",
        "budget_member_is_cumulative_parent_counter": True,
        "report_status_not_rewritten": True,
    }


def build_reports(input_report: Path = INPUT_REPORT) -> tuple[dict[str, Any], dict[str, Any]]:
    if input_report.resolve() != INPUT_REPORT.resolve():
        raise ReferenceError("refusing_non_authoritative_input_report")
    report_sha = _sha256_file(input_report)
    if report_sha != EXPECTED_REPORT_SHA256:
        raise ReferenceError("archived_input_report_sha256_mismatch")
    report = _load_json(input_report)
    if report.get("status") != "doublepass_mismatch":
        raise ReferenceError("original_status_changed")
    if report.get("completed") is not False:
        raise ReferenceError("original_completed_changed")
    doublepass = report.get("doublepass")
    if doublepass != {"performed": True, "consistent": False, "atomic": False}:
        raise ReferenceError("original_doublepass_changed")
    errors = report.get("errors")
    if errors != []:
        raise ReferenceError("original_errors_not_empty")
    close = report.get("cleanup", {}).get("handle_close", {})
    if close.get("status") != "closed" or close.get("closed") is not True:
        raise ReferenceError("original_handle_not_closed")

    inputs = report.get("military_quality_inputs")
    if not isinstance(inputs, list) or len(inputs) != 2 or not all(isinstance(item, dict) for item in inputs):
        raise ReferenceError("original_input_shape_invalid")
    differences = _diff_paths(inputs[0], inputs[1])
    expected_difference_path = "[0?]"
    if len(differences) != 1 or differences[0]["path"] != "child_budget.parent_bytes_before":
        raise ReferenceError(f"unexpected_input_differences:{differences[:4]}")

    canonical_inputs = [_strip_accounting_member(item) for item in inputs]
    canonical_equal = canonical_inputs[0] == canonical_inputs[1]
    if not canonical_equal:
        raise ReferenceError("canonical_inputs_still_differ")
    identity = _identity(report, inputs)
    pins = _source_pins()
    fields = _field_metadata(inputs, pins)
    accounting = _accounting(report, inputs)
    script_sha = _sha256_file(Path(__file__).resolve())
    original_input_summary = {
        "path": _relative(input_report),
        "sha256": report_sha,
        "status": report["status"],
        "completed": report["completed"],
        "doublepass": copy.deepcopy(doublepass),
        "errors": [],
        "handle_close": copy.deepcopy(close),
        "original_report_unchanged": True,
    }
    comparison = {
        "raw_difference_count_before": len(differences),
        "raw_differences_before": differences,
        "removed_paths": ["military_quality_inputs[*].child_budget.parent_bytes_before"],
        "removed_member_count": 1,
        "canonical_equal_after_removal": canonical_equal,
        "canonical_sha256_pass0": _sha256_bytes(canonical_inputs[0]),
        "canonical_sha256_pass1": _sha256_bytes(canonical_inputs[1]),
        "all_non_accounting_fields_equal": canonical_equal,
        "raw_fields_equal": canonical_equal,
        "address_fields_equal": canonical_equal,
        "child_read_log_equal": canonical_equal,
        "only_excluded_field_is_cumulative_parent_byte_counter": True,
    }
    header = {
        **identity,
        "reference_basis": "failed_report_accounting_only_readonly_reanalysis",
        "new_rpm_calls": 0,
        "game_or_native_calls": False,
        "production_military_module_used": False,
        "public_mcp_values_used": False,
    }

    expected = {
        "schema": "information_independent_military_quality_expected.v1",
        "reference_id": "expected-military-quality-001",
        "stage": "information-military-quality-20261027-001",
        "status": "observed_reference",
        "complete": False,
        "basis": "failed_report_accounting_only_readonly_reanalysis",
        "header": header,
        "fields": fields,
        "original_report": original_input_summary,
        "comparison": comparison,
        "accounting": accounting,
        "source_pins": pins,
        "reference_script": {
            "path": _relative(Path(__file__).resolve()),
            "sha256": script_sha,
            "read_only": True,
            "new_rpm": 0,
        },
        "unimplemented_fields": ["morale", "discipline"],
    }
    reanalysis = {
        "schema": "information_independent_military_quality_accounting_reanalysis.v1",
        "reference_id": "reference-accounting-reanalysis-001",
        "stage": "information-military-quality-20261027-001",
        "status": "observed_reference",
        "basis": "failed_report_accounting_only_readonly_reanalysis",
        "header": header,
        "original_report": original_input_summary,
        "comparison": comparison,
        "accounting": accounting,
        "decoded_fields": fields,
        "source_pins": pins,
        "reference_script": {
            "path": _relative(Path(__file__).resolve()),
            "sha256": script_sha,
            "read_only": True,
            "new_rpm": 0,
        },
        "conclusion": {
            "original_report_status_preserved": True,
            "original_report_marked_passed": False,
            "canonical_two_pass_inputs_equal_after_accounting_member_removal": True,
            "all_raw_address_and_read_log_fields_compared": True,
            "runtime_values_are_archived_inputs_only": True,
            "moral_discipline_semantics_not_claimed": True,
        },
    }
    return expected, reanalysis


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=INPUT_REPORT)
    parser.add_argument("--output-dir", type=Path, default=STAGE)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    expected, reanalysis = build_reports(args.input.resolve())
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = (
        (output_dir / EXPECTED_OUTPUT.name, expected),
        (output_dir / REANALYSIS_OUTPUT.name, reanalysis),
    )
    if not args.overwrite:
        existing = [str(path) for path, _ in paths if path.exists()]
        if existing:
            raise SystemExit(f"refusing_to_overwrite:{','.join(existing)}")
    for path, value in paths:
        with path.open("w" if args.overwrite else "x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(
        json.dumps(
            {
                "status": expected["status"],
                "canonical_equal": expected["comparison"]["canonical_equal_after_removal"],
                "original_status": expected["original_report"]["status"],
                "rpm_bytes": expected["accounting"]["rpm_bytes_requested"],
                "rpm_calls": expected["accounting"]["rpm_calls"],
                "new_rpm": 0,
                "outputs": [str(path) for path, _ in paths],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
