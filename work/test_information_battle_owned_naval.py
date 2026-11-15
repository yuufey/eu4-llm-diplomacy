"""Build and run the bounded raw naval-loss/type-row copy fixture.

This is an offline synthetic-reader test.  It does not start EU4, access a
process, install a DLL, invoke REA, or call a game function.  The static
initial-slot report is pinned only as the source-layout provenance; this
component deliberately exposes raw loss bytes and row type integers without
assigning ship, side, winner, visibility, or event semantics.
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
STAGE = ROOT / "work" / "runtime" / "information-battle-naval-losses-20261026-001" / "owned-naval-test-001"
HEADER = NATIVE / "information-battle-owned-naval.h"
CPP = NATIVE / "tests" / "information-battle-owned-naval-test.cpp"
SCRIPT = Path(__file__).resolve()
REPORT = STAGE / "report.json"
EXE = STAGE / "test-information-battle-owned-naval.exe"
COMPILE_STDOUT = STAGE / "compile.stdout.log"
COMPILE_STDERR = STAGE / "compile.stderr.log"
RUN_STDOUT = STAGE / "run.stdout.log"
RUN_STDERR = STAGE / "run.stderr.log"
INITIAL_BINDING = ROOT / "work" / "runtime" / "information-battle-naval-20261026-001" / "naval-initial-binding-001.json"
EXPECTED_INITIAL_BINDING_SHA256 = "8ba05e2349aecb35fe98365453e6a20c81556d3e59a6da7bad58457635f40538"
MAX_SOURCE_BYTES = 10 * 1024 * 1024
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
    matches = expected_sha256 is None or digest == expected_sha256
    return {
        "path": relative(path),
        "status": "passed" if matches else "mismatch",
        "exists": True,
        "size_bytes": size,
        "sha256": digest,
        "expected_sha256": expected_sha256,
        "sha256_matches_expected": matches,
    }


def load_json_bounded(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"json_over_bound:{relative(path)}:{size}")
    with path.open("rb") as stream:
        raw = stream.read(MAX_SOURCE_BYTES + 1)
    if len(raw) != size or len(raw) > MAX_SOURCE_BYTES:
        raise ValueError(f"file_changed_or_over_bound:{relative(path)}")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    return value, {"path": relative(path), "bytes": size,
                   "sha256": hashlib.sha256(raw).hexdigest()}


def write_report(report: dict[str, Any]) -> None:
    raw = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError(f"report_over_bound:{len(raw)}")
    STAGE.mkdir(parents=True, exist_ok=True)
    REPORT.write_bytes(raw)


def main() -> int:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "information_battle_owned_naval_test_v1",
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
            "max_rows": 256,
            "max_single_read_bytes": 65536,
            "max_total_read_bytes": 65536,
            "combat_side_pointer_offsets": ["0x20", "0x28"],
            "side_loss_offsets": ["0x140", "0x144", "0x148", "0x14c"],
            "side_gate_offset": "0x169",
            "summary_vector": {"begin": "0x0", "end": "0x8", "pointer_bytes": 8},
            "row_definition_offset": "0x20",
            "definition_type_offset": "0x10",
            "summary_base_guard": "summary[0x20:0x4d] equals supplied owned_summary::Snapshot",
            "two_pass_consistency": True,
            "failure_output_unchanged": True,
            "output_contains_only_raw_values": True,
            "no_borrowed_pointer": True,
            "semantic_interpretation": {
                "loss_units": "unknown",
                "row_type_meaning": "unknown",
                "side_role": "unknown",
                "ship_class": "unknown",
                "visibility": "unknown",
            },
        },
        "source_evidence": {},
        "source_pins": {
            "header": file_pin(HEADER),
            "test_cpp": file_pin(CPP),
            "python_runner": file_pin(SCRIPT),
            "initial_binding_report": file_pin(
                INITIAL_BINDING, expected_sha256=EXPECTED_INITIAL_BINDING_SHA256),
        },
        "compile": {},
        "run": {},
        "observations": {},
    }

    try:
        binding, binding_meta = load_json_bounded(INITIAL_BINDING)
        source_errors: list[str] = []
        if binding_meta["sha256"] != EXPECTED_INITIAL_BINDING_SHA256:
            source_errors.append("initial_binding_sha256_mismatch")
        if binding.get("schema") != "information_battle_naval_initial_binding_v1":
            source_errors.append("initial_binding_schema_mismatch")
        if binding.get("status") != "partial_static_binding":
            source_errors.append("initial_binding_status_mismatch")
        target = binding.get("target_build")
        if not isinstance(target, dict) or target.get("version") != "1.37.4":
            source_errors.append("initial_binding_target_mismatch")
        report["source_evidence"] = {
            "report_schema": binding.get("schema"),
            "report_status": binding.get("status"),
            "target_build": target,
            "source_report_sha256": binding_meta["sha256"],
            "selected_bounded_json_only": True,
            "runtime_observed": False,
            "layout_admitted": not source_errors,
        }
        report["source_errors"] = source_errors
    except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        report["source_errors"] = [f"source_inspection_error:{type(exc).__name__}:{exc}"]
        report["source_evidence"] = {"layout_admitted": False}

    source_errors = report.get("source_errors", [])
    if source_errors:
        report["status"] = "blocked_source_evidence"
        report["elapsed_seconds"] = time.time() - started
        write_report(report)
        return 1

    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        write_report(report)
        return 1

    command = [
        compiler, "-std=c++17", "-fno-exceptions", "-Wall", "-Wextra",
        "-Werror", "-O2", "-I", str(NATIVE), str(CPP), "-o", str(EXE),
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90, check=False)
    compile_stdout = compiled.stdout.decode("utf-8", errors="replace")
    compile_stderr = compiled.stderr.decode("utf-8", errors="replace")
    STAGE.mkdir(parents=True, exist_ok=True)
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
        write_report(report)
        return 1

    completed = subprocess.run([str(EXE)], cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90, check=False)
    run_stdout = completed.stdout.decode("utf-8", errors="replace")
    run_stderr = completed.stderr.decode("utf-8", errors="replace")
    RUN_STDOUT.write_text(run_stdout, encoding="utf-8")
    RUN_STDERR.write_text(run_stderr, encoding="utf-8")
    result_line = next((line for line in run_stdout.splitlines()
                        if line.startswith("RESULT ")), None)
    summary_line = next((line for line in run_stdout.splitlines()
                         if line.startswith("SUMMARY ")), None)
    checks = [line for line in run_stdout.splitlines()
              if line.startswith("CHECK ")]
    report["run"] = {
        "command": [str(EXE)],
        "returncode": completed.returncode,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "result_line": result_line,
    }
    report["observations"] = {
        "checks": checks,
        "check_count": len(checks),
        "summary": summary_line,
        "result": result_line,
        "read_budget_bytes": 65536,
        "max_rows_exercised": 256,
        "synthetic_reader_only": True,
    }
    if EXE.is_file():
        report["artifact"] = file_pin(EXE)
    report["status"] = (
        "passed" if completed.returncode == 0 and result_line == "RESULT PASS"
        else "failed_runtime"
    )
    report["elapsed_seconds"] = time.time() - started
    write_report(report)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
