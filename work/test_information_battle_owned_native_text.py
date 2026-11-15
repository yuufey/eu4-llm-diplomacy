"""Build and run the bounded owned-native-text fixture.

The default and --help paths are lazy.  Only --run compiles and executes the
synthetic reader fixture; it never opens EU4, a process, REA, or a native game
function.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
HEADER = NATIVE / "information-battle-owned-native-text.h"
CPP = NATIVE / "tests" / "information-battle-owned-native-text-test.cpp"
SCRIPT = Path(__file__).resolve()
STAGE = (ROOT / "work" / "runtime"
         / "information-battle-native-text-20261027-001"
         / "owned-native-text-test-003")
REPORT = STAGE / "report.json"
EXE = STAGE / "information-battle-owned-native-text-test.exe"
COMPILE_STDOUT = STAGE / "compile.stdout.log"
COMPILE_STDERR = STAGE / "compile.stderr.log"
RUN_STDOUT = STAGE / "run.stdout.log"
RUN_STDERR = STAGE / "run.stderr.log"


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def file_pin(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": relative(path), "exists": False, "status": "missing"}
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
    return {
        "path": relative(path),
        "exists": True,
        "status": "passed",
        "size_bytes": size,
        "sha256": digest.hexdigest(),
    }


def write_receipt(value: dict[str, Any]) -> None:
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
           + "\n").encode("utf-8")
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("receipt_over_bound")
    with REPORT.open("xb") as stream:
        stream.write(raw)
        stream.flush()


def decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def run() -> int:
    started = time.time()
    if REPORT.exists() or STAGE.exists():
        raise FileExistsError(f"refusing_to_overwrite:{relative(STAGE)}")
    STAGE.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "schema": "information_battle_owned_native_text_test_v1",
        "artifact_id": "owned-native-text-test-003",
        "status": "blocked",
        "scope": {
            "fixture_process_only": True,
            "game_access": False,
            "remote_process_access": False,
            "rea_access": False,
            "native_game_function_invoked": False,
            "dll_installation": False,
            "production_modified": False,
            "reader_allocates_or_does_io": False,
        },
        "contract": {
            "reader_signature":
                "bool read(uintptr_t,unsigned char*,size_t) noexcept",
            "definition_pointer_offset": "0x08",
            "definition_key_object_offset": "0x38",
            "definition_key_length_offset": "0x48",
            "definition_key_capacity_offset": "0x50",
            "auxiliary_object_offset": "0x60",
            "native_date_offset": "0x88",
            "raw_flag_offsets": ["0x8c", "0x8d"],
            "title_and_line1_string_layout": {
                "object_bytes": 32,
                "length_offset": "0x10",
                "capacity_offset": "0x18",
                "inline_capacity": 15,
            },
            "max_key_bytes": 256,
            "max_text_bytes": 8192,
            "max_owned_arena_bytes": 24832,
            "max_per_pass_read_bytes": 32768,
            "max_total_read_bytes": 65536,
            "two_pass_value_compare": True,
            "failure_clears_output": True,
            "source_pointers_retained": False,
        },
        "source_pins": {
            "header": file_pin(HEADER),
            "test_cpp": file_pin(CPP),
            "python_runner": file_pin(SCRIPT),
        },
        "compile": {},
        "run": {},
    }

    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        write_receipt(report)
        return 1

    command = [
        compiler,
        "-std=c++17",
        "-fno-exceptions",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-O2",
        "-I",
        str(NATIVE),
        str(CPP),
        "-o",
        str(EXE),
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90,
                               check=False)
    compile_stdout = decode(compiled.stdout)
    compile_stderr = decode(compiled.stderr)
    COMPILE_STDOUT.write_text(compile_stdout, encoding="utf-8")
    COMPILE_STDERR.write_text(compile_stderr, encoding="utf-8")
    report["compile"] = {
        "command": command,
        "returncode": compiled.returncode,
        "stdout": compile_stdout,
        "stderr": compile_stderr,
    }
    if compiled.returncode != 0:
        report["status"] = "failed_compile"
        report["elapsed_seconds"] = time.time() - started
        write_receipt(report)
        return 1

    completed = subprocess.run([str(EXE)], cwd=ROOT,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90,
                               check=False)
    run_stdout = decode(completed.stdout)
    run_stderr = decode(completed.stderr)
    RUN_STDOUT.write_text(run_stdout, encoding="utf-8")
    RUN_STDERR.write_text(run_stderr, encoding="utf-8")
    checks = [line for line in run_stdout.splitlines()
              if line.startswith("CHECK ")]
    result_line = next((line for line in run_stdout.splitlines()
                        if line.startswith("RESULT ")), None)
    summary_line = next((line for line in run_stdout.splitlines()
                         if line.startswith("SUMMARY ")), None)
    report["run"] = {
        "command": [str(EXE)],
        "returncode": completed.returncode,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "check_count": len(checks),
        "checks": checks,
        "result_line": result_line,
        "summary_line": summary_line,
    }
    report["artifacts"] = {
        "header": file_pin(HEADER),
        "test_cpp": file_pin(CPP),
        "python_runner": file_pin(SCRIPT),
        "executable": file_pin(EXE),
    }
    report["status"] = (
        "passed" if completed.returncode == 0
        and result_line == "RESULT PASS" else "failed_runtime"
    )
    report["elapsed_seconds"] = time.time() - started
    write_receipt(report)
    return 0 if report["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=("Build/run the synthetic owned native text reader "
                     "fixture; --run is required for side effects."))
    parser.add_argument("--run", action="store_true",
                        help="compile and run the bounded C++ fixture")
    args = parser.parse_args()
    if not args.run:
        parser.print_help()
        return 0
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
