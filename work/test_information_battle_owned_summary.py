"""Build and run the bounded raw summary-copy fixture.

The executable uses a synthetic sparse reader and an owned stack/value output.
It does not open EU4, access a game process, install a DLL or hook, invoke REA,
or call a game function.  The summary layout is admitted only when the
already-pinned batch20 field table still proves the exact 11 x int32 plus one
byte reads.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-observer-20261025-001" / "summary-test-001"
HEADER = NATIVE / "information-battle-owned-summary.h"
CPP = NATIVE / "test-information-battle-owned-summary.cpp"
SCRIPT = Path(__file__).resolve()
REPORT = STAGE / "report.json"
EXE = STAGE / "test-information-battle-owned-summary.exe"
COMPILE_STDOUT = STAGE / "compile.stdout.log"
COMPILE_STDERR = STAGE / "compile.stderr.log"
RUN_STDOUT = STAGE / "run.stdout.log"
RUN_STDERR = STAGE / "run.stderr.log"

SURVEY = ROOT / "work" / "runtime" / "information-battle-entry-20261025-001" / "payload-source-survey-001.json"
EXPECTED_SURVEY_SHA256 = "d9c40946a1d5df5df5b98951a9bfd13de627259c56626af8cb59a89fe357cce4"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_BUILD = "1.37.4"
EXPECTED_RVA = "0x238620"
MAX_SOURCE_JSON_BYTES = 10 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def file_pin(path: Path, *, expected_sha256: str | None = None) -> dict[str, Any]:
    if not path.is_file():
        return {
            "path": relative(path),
            "status": "missing",
            "exists": False,
            "size_bytes": None,
            "sha256": None,
            "expected_sha256": expected_sha256,
        }
    size, digest = sha256_file(path)
    return {
        "path": relative(path),
        "status": "passed" if expected_sha256 is None or digest == expected_sha256 else "mismatch",
        "exists": True,
        "size_bytes": size,
        "sha256": digest,
        "expected_sha256": expected_sha256,
        "sha256_matches_expected": expected_sha256 is None or digest == expected_sha256,
    }


def load_json(path: Path, max_bytes: int = MAX_SOURCE_JSON_BYTES) -> tuple[dict[str, Any], dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"json_over_bound:{relative(path)}:{size}")
    with path.open("rb") as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) != size:
        raise ValueError(f"file_changed_during_read:{relative(path)}")
    if len(raw) > max_bytes:
        raise ValueError(f"json_over_bound:{relative(path)}")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{relative(path)}")
    return value, {
        "path": relative(path),
        "size_bytes": size,
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def canonical_sha(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def resolve_source_path(raw_path: str) -> Path:
    path = Path(raw_path)
    return path if path.is_absolute() else ROOT / path


def inspect_survey() -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    survey, survey_meta = load_json(SURVEY)
    errors: list[str] = []
    if survey_meta["sha256"] != EXPECTED_SURVEY_SHA256:
        errors.append("survey_sha256_mismatch")
    if survey.get("schema") != "information_battle_entry_payload_survey_v1":
        errors.append("survey_schema_mismatch")
    if survey.get("status") != "passed_static_mechanical_survey":
        errors.append("survey_status_mismatch")
    target = survey.get("target")
    if not isinstance(target, dict) or target.get("build") != EXPECTED_BUILD or target.get("executable_sha256") != EXPECTED_EXE_SHA256:
        errors.append("survey_target_mismatch")
    entry = survey.get("entry")
    if not isinstance(entry, dict) or entry.get("rva") != EXPECTED_RVA:
        errors.append("entry_rva_mismatch")
    inventory = survey.get("field_inventory")
    if not isinstance(inventory, list):
        errors.append("field_inventory_missing")
        return survey, survey_meta, errors
    summary = next((item for item in inventory if isinstance(item, dict) and item.get("field") == "summary"), None)
    if not isinstance(summary, dict):
        errors.append("summary_field_missing")
        return survey, survey_meta, errors
    direct = summary.get("direct_owned_copy")
    if not isinstance(direct, dict) or direct.get("status") != "conditional_entry_snapshot_candidate":
        errors.append("summary_direct_status_mismatch")
    later = summary.get("later_change")
    table = later.get("field_table") if isinstance(later, dict) else None
    if not isinstance(table, list) or len(table) != 12:
        errors.append("summary_field_table_shape_mismatch")
        return survey, survey_meta, errors
    expected_offsets = [0x20 + 4 * index for index in range(11)] + [0x4C]
    for index, (row, expected_offset) in enumerate(zip(table, expected_offsets)):
        if not isinstance(row, dict):
            errors.append(f"summary_field_table_row_{index}_not_object")
            continue
        try:
            actual_offset = int(str(row.get("offset")), 16)
        except (TypeError, ValueError):
            actual_offset = None
        if actual_offset != expected_offset:
            errors.append(f"summary_offset_{index}_mismatch")
        width = str(row.get("decompiler_read_width", "")).lower()
        if index < 11:
            if "4 bytes" not in width or ("undefined4" not in width and "int" not in width):
                errors.append(f"summary_i32_width_{index}_unproven")
        elif "1 byte" not in width or "char" not in width:
            errors.append("summary_control_width_unproven")
    return survey, survey_meta, errors


def evidence_pins(survey: dict[str, Any], survey_meta: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    entry = survey.get("entry") if isinstance(survey.get("entry"), dict) else {}
    raw_source = entry.get("raw_source") if isinstance(entry.get("raw_source"), dict) else {}
    selected = entry.get("selected_report") if isinstance(entry.get("selected_report"), dict) else {}
    summary_row = next(
        (item for item in survey.get("field_inventory", [])
         if isinstance(item, dict) and item.get("field") == "summary"),
        {},
    )
    later = summary_row.get("later_change") if isinstance(summary_row, dict) else {}
    refs = later.get("refs", []) if isinstance(later, dict) else []
    land_ref = next(
        (item for item in refs if isinstance(item, dict) and item.get("source_id") == "land_field_ledger"),
        None,
    )
    pins: dict[str, Any] = {"survey": file_pin(SURVEY, expected_sha256=EXPECTED_SURVEY_SHA256)}
    for label, metadata in (("raw_source", raw_source), ("callback_selected", selected)):
        path_value = metadata.get("path") if isinstance(metadata, dict) else None
        if not isinstance(path_value, str):
            errors.append(f"{label}_path_missing")
            continue
        expected = metadata.get("sha256")
        pin = file_pin(resolve_source_path(path_value), expected_sha256=expected if isinstance(expected, str) else None)
        pins[label] = pin
        if pin.get("status") != "passed":
            errors.append(f"{label}_pin_mismatch")
    if not isinstance(land_ref, dict) or not isinstance(land_ref.get("path"), str):
        errors.append("land_field_ledger_ref_missing")
    else:
        expected = land_ref.get("sha256")
        pin = file_pin(resolve_source_path(land_ref["path"]), expected_sha256=expected if isinstance(expected, str) else None)
        pins["land_field_ledger"] = pin
        if pin.get("status") != "passed":
            errors.append("land_field_ledger_pin_mismatch")
    raw_size = pins.get("raw_source", {}).get("size_bytes")
    if isinstance(raw_size, int) and raw_size > MAX_SOURCE_JSON_BYTES:
        errors.append("raw_source_over_bound")
    return pins, errors


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def write_new_json(path: Path, value: dict[str, Any]) -> tuple[int, str]:
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError(f"report_over_bound:{len(raw)}")
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{relative(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    return len(raw), hashlib.sha256(raw).hexdigest()


def main() -> int:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "information_battle_owned_summary_test_v1",
        "status": "blocked",
        "scope": {
            "game_access": False,
            "rea_access": False,
            "remote_process_access": False,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "production_modified": False,
            "fixture_process_only": True,
            "component_allocates_or_does_io": False,
        },
        "contract": {
            "reader_signature": "bool read(uintptr_t,unsigned char*,size_t) noexcept",
            "canonical_min_address": 65536,
            "canonical_max_exclusive": 140737488355328,
            "max_single_read_bytes": 256,
            "max_total_read_bytes": 256,
            "read_span": {"start_offset": "0x20", "end_offset_exclusive": "0x4d", "bytes": 45},
            "raw_i32_offsets": [f"0x{offset:02x}" for offset in range(0x20, 0x4c, 4)],
            "control_byte_offset": "0x4c",
            "failure_output_unchanged": True,
            "output_contains_only_raw_values": True,
            "no_borrowed_pointer": True,
            "semantic_interpretation": {
                "units": "unknown",
                "side_role": "unknown",
                "visibility": "unknown",
                "kind": "unknown",
            },
        },
        "source_evidence": {},
        "source_pins": {
            "header": file_pin(HEADER),
            "test_cpp": file_pin(CPP),
            "python_runner": file_pin(SCRIPT),
        },
        "compile": {},
        "run": {},
        "observations": {},
    }
    try:
        survey, survey_meta, survey_errors = inspect_survey()
        pins, pin_errors = evidence_pins(survey, survey_meta)
        report["source_evidence"] = {
            "survey_status": survey.get("status"),
            "survey_schema": survey.get("schema"),
            "target": survey.get("target"),
            "entry_rva": survey.get("entry", {}).get("rva") if isinstance(survey.get("entry"), dict) else None,
            "summary_field_table": next(
                (item.get("later_change", {}).get("field_table")
                 for item in survey.get("field_inventory", [])
                 if isinstance(item, dict) and item.get("field") == "summary"),
                None,
            ),
            "field_table_sha256": canonical_sha(next(
                (item.get("later_change", {}).get("field_table")
                 for item in survey.get("field_inventory", [])
                 if isinstance(item, dict) and item.get("field") == "summary"),
                [])),
            "selected_evidence_only": True,
            "runtime_observed": False,
            "raw_source_loaded_into_memory": False,
        }
        report["source_pins"].update(pins)
        source_errors = survey_errors + pin_errors
    except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        source_errors = [f"source_inspection_error:{type(exc).__name__}:{exc}"]
    report["source_errors"] = source_errors
    report["contract"]["source_layout_admitted"] = not source_errors
    if source_errors:
        report["status"] = "blocked_source_evidence"
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return 1

    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return 1
    command = [
        compiler,
        "-std=c++17",
        "-fno-exceptions",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-O2",
        "-fstack-usage",
        "-I",
        str(NATIVE),
        str(CPP),
        "-o",
        str(EXE),
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90, check=False)
    compile_stdout = decode(compiled.stdout)
    compile_stderr = decode(compiled.stderr)
    COMPILE_STDOUT.write_text(compile_stdout, encoding="utf-8")
    COMPILE_STDERR.write_text(compile_stderr, encoding="utf-8")
    report["compile"] = {
        "command": command,
        "compiler": compiler,
        "returncode": compiled.returncode,
        "stdout": compile_stdout,
        "stderr": compile_stderr,
    }
    if compiled.returncode != 0:
        report["status"] = "failed_compile"
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return 1

    completed = subprocess.run([str(EXE)], cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90, check=False)
    run_stdout = decode(completed.stdout)
    run_stderr = decode(completed.stderr)
    RUN_STDOUT.write_text(run_stdout, encoding="utf-8")
    RUN_STDERR.write_text(run_stderr, encoding="utf-8")
    report["run"] = {
        "command": [str(EXE)],
        "returncode": completed.returncode,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "result_line": next((line for line in run_stdout.splitlines() if line.startswith("RESULT ")), None),
    }
    checks = [line for line in run_stdout.splitlines() if line.startswith("CHECK ")]
    summary_line = next((line for line in run_stdout.splitlines() if line.startswith("SUMMARY ")), None)
    report["observations"] = {
        "checks": checks,
        "check_count": len(checks),
        "summary": summary_line,
        "result": report["run"]["result_line"],
        "read_budget_bytes": 256,
        "read_span_bytes": 45,
    }
    if EXE.is_file():
        report["artifact"] = file_pin(EXE)
    stack_files = sorted(STAGE.glob("*.su"))
    report["stack_usage"] = [file_pin(path) for path in stack_files]
    report["status"] = "passed" if completed.returncode == 0 and report["run"]["result_line"] == "RESULT PASS" else "failed_runtime"
    report["elapsed_seconds"] = time.time() - started
    write_new_json(REPORT, report)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
