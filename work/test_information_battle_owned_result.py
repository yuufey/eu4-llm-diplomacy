"""Build and run the bounded, allocation-free owned-result copy test.

The executable uses only a synthetic sparse reader.  It does not open EU4,
inspect a process, install a DLL, call REA, or invoke a native game function.
The FRA/BUR values are a recorded fixture copied from the prior read-only
report; they are not a new runtime observation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-owned-result-20261025-001" / "owned-result-test-001"
HEADER = NATIVE / "information-battle-owned-result.h"
CPP = NATIVE / "test-information-battle-owned-result.cpp"
SCRIPT = Path(__file__).resolve()
REPORT = STAGE / "report-002.json"
EXE = STAGE / "test-information-battle-owned-result-002.exe"
FIXTURE = STAGE / "recorded-fra-bur-fixture-002.json"
COMPILE_STDOUT = STAGE / "compile-002.stdout.log"
COMPILE_STDERR = STAGE / "compile-002.stderr.log"
RUN_STDOUT = STAGE / "run-002.stdout.log"
RUN_STDERR = STAGE / "run-002.stderr.log"
PREVIOUS_REPORT = STAGE / "report.json"
PREVIOUS_EXE = STAGE / "test-information-battle-owned-result.exe"
PREVIOUS_FIXTURE = STAGE / "recorded-fra-bur-fixture.json"
SOURCE_REPORT = ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001" / "live-fra-bur-002" / "report.json"
EXPECTED_SOURCE_SHA256 = "8e6cd850b7112cc5f52ea4ee5dd445e54fa45ca03a7626275a137dfb1b8d286f"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def file_pin(path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def write_recorded_fixture() -> dict[str, object]:
    result_raw_hex = ""
    if SOURCE_REPORT.is_file() and SOURCE_REPORT.stat().st_size <= 10 * 1024 * 1024:
        try:
            source_document = json.loads(SOURCE_REPORT.read_text(encoding="utf-8"))
            source_result = source_document["wars"][0]["results"]["results"][0]
            candidate_raw = source_result["raw_hex"]
            if isinstance(candidate_raw, str) and len(candidate_raw) <= 2 * 1024 * 1024:
                result_raw_hex = candidate_raw
        except (KeyError, IndexError, TypeError, ValueError, OSError):
            result_raw_hex = ""
    fixture: dict[str, object] = {
        "schema": "information_battle_owned_result_recorded_fixture_v1",
        "mode": "recorded",
        "source_report": {
            "path": SOURCE_REPORT.relative_to(ROOT).as_posix(),
            "sha256": EXPECTED_SOURCE_SHA256,
            "selection": "wars[0].results.results[0]",
            "report_semantics": "prior read-only pure-RPM observation; no new access",
            "result_raw_hex": result_raw_hex,
        },
        "target_build": {
            "version": "1.37.4",
            "exe_sha256": EXPECTED_EXE_SHA256,
        },
        "stage": "pre_participant_callback",
        "expected": {
            "raw_date": 56552232,
            "flag108": 0,
            "aux100": 142000,
            "aux104": 147000,
            "province_id": 1285,
            "name_raw_hex": "11315710544e10bb6c10776d12e153",
            "sides": [
                {
                    "country_raw_hex": "465241007a000001",
                    "raw_fields_by_offset": {
                        "0x38": 0,
                        "0x3c": 0,
                        "0x40": 0,
                        "0x44": 0,
                        "0x48": 3,
                        "0x4c": 0,
                        "0x50": 0,
                        "0x54": 3,
                        "0x74": 0,
                    },
                    "commander_raw_hex": "",
                },
                {
                    "country_raw_hex": "4255520075000001",
                    "raw_fields_by_offset": {
                        "0x38": 0,
                        "0x3c": 0,
                        "0x40": 0,
                        "0x44": 3,
                        "0x48": 6,
                        "0x4c": 0,
                        "0x50": 13,
                        "0x54": 0,
                        "0x74": 0,
                    },
                    "commander_raw_hex": "10819c105390102b592056616c6b656e737761617264",
                },
            ],
        },
        "limitations": [
            "recorded fixture only; no live process access",
            "raw fields remain uninterpreted and no kind/visibility/war/public battle identity is claimed",
        ],
    }
    FIXTURE.write_text(json.dumps(fixture, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
    return fixture


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def lines_with_prefix(text: str, prefix: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(prefix)]


def run() -> dict[str, object]:
    STAGE.mkdir(parents=True, exist_ok=True)
    started = time.time()
    fixture = write_recorded_fixture()
    report: dict[str, object] = {
        "schema": "information_battle_owned_result_test_v2",
        "status": "blocked",
        "scope": {
            "game_access": False,
            "rea_access": False,
            "remote_process_access": False,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "heap_allocation_in_component": False,
            "claim": "offline synthetic sparse-reader copy contract only",
        },
        "contract": {
            "stage": "pre_participant_callback",
            "canonical_min_address": 65536,
            "canonical_max_exclusive": 140737488355328,
            "module_and_expected_vtable_addresses_canonical": True,
            "result_pointer_alignment": 8,
            "raw_date_alignment": "4-byte read may be unaligned",
            "reader_signature": "bool read(uintptr_t,unsigned char*,size_t) noexcept",
            "max_single_read_bytes": 65536,
            "max_total_read_bytes": 65536,
            "max_owned_string_bytes": 4096,
            "max_string_capacity": 131072,
            "failure_output_unchanged": True,
            "source_object_and_heap_alias_rejected": True,
            "alias_guard": "each requested source interval is compared with the output object address range",
            "output_has_no_borrowed_pointer": True,
        },
        "source_pins": {
            "header": file_pin(HEADER),
            "test_cpp": file_pin(CPP),
            "python_runner": file_pin(SCRIPT),
            "recorded_fixture": file_pin(FIXTURE),
        },
        "previous_artifacts": {},
        "recorded_fixture": fixture,
        "compile": {},
        "stack_usage": {},
        "run": {},
        "observations": {},
    }

    if not SOURCE_REPORT.is_file() or SOURCE_REPORT.stat().st_size > 10 * 1024 * 1024:
        report["status"] = "blocked_missing_or_oversize_source_report"
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report
    if not all(path.is_file() for path in
               (PREVIOUS_REPORT, PREVIOUS_EXE, PREVIOUS_FIXTURE)):
        report["status"] = "blocked_previous_artifact_missing"
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report
    report["previous_artifacts"] = {
        "report": file_pin(PREVIOUS_REPORT),
        "executable": file_pin(PREVIOUS_EXE),
        "fixture": file_pin(PREVIOUS_FIXTURE),
    }
    source_sha = sha256_file(SOURCE_REPORT)
    report["source_report_current_sha256"] = source_sha
    if source_sha != EXPECTED_SOURCE_SHA256:
        report["status"] = "blocked_source_report_changed"
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report

    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report

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
    compiled = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
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
    stack_files = sorted(STAGE.glob("*.su"))
    if stack_files:
        stack_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in stack_files
        )
        capture_stack_bytes = None
        for line in stack_text.splitlines():
            if "owned_result::capture" not in line:
                continue
            fields = line.split("\t")
            if len(fields) >= 2:
                try:
                    capture_stack_bytes = int(fields[1])
                except ValueError:
                    pass
            break
        report["stack_usage"] = {
            "method": "g++ -fstack-usage",
            "files": [file_pin(path) for path in stack_files],
            "capture_stack_bytes": capture_stack_bytes,
            "capture_stack_bound_bytes": 17 * 1024,
        }
    else:
        report["stack_usage"] = {
            "method": "g++ -fstack-usage",
            "status": "not_emitted",
        }
    if compiled.returncode != 0 or not EXE.exists():
        report["status"] = "compile_failed"
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report

    report["artifact"] = file_pin(EXE)
    run_result = subprocess.run(
        [str(EXE)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
    run_stdout = decode(run_result.stdout)
    run_stderr = decode(run_result.stderr)
    RUN_STDOUT.write_text(run_stdout, encoding="utf-8")
    RUN_STDERR.write_text(run_stderr, encoding="utf-8")
    result_line = next(
        (line for line in run_stdout.splitlines() if line.startswith("RESULT ")),
        "",
    )
    report["run"] = {
        "command": [str(EXE)],
        "returncode": run_result.returncode,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "result_line": result_line,
    }
    report["observations"] = {
        "checks": lines_with_prefix(run_stdout, "CHECK "),
        "summary": lines_with_prefix(run_stdout, "SUMMARY "),
    }
    report["status"] = (
        "passed"
        if run_result.returncode == 0 and result_line == "RESULT PASS"
        else "failed"
    )
    report["elapsed_seconds"] = time.time() - started
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    return report


def main() -> int:
    report = run()
    print(json.dumps({
        "status": report["status"],
        "report": REPORT.relative_to(ROOT).as_posix(),
        "artifact": report.get("artifact"),
    }, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
