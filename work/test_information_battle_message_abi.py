"""Build and run the offline production message-hook ABI fixture.

The fixture compiles the real template-enabled production assembly together
with a self-owned caller and original.  It does not load EU4, attach to a
process, use REA/RPM, or install a DLL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-text-20261026-001" / "message-abi-test-001"
CPP = NATIVE / "tests" / "information-battle-message-abi-test.cpp"
CALLER = NATIVE / "tests" / "information-battle-message-abi.S"
STUB = NATIVE / "information-battle-entry-stub.S"
SCRIPT = Path(__file__).resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_pin(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def compiler_path(argument: str | None) -> str | None:
    if argument:
        return argument
    return shutil.which("g++") or os.environ.get("EU4_CXX") or r"C:\Strawberry\c\bin\g++.exe"


def parse_native(stdout: bytes) -> tuple[dict[str, Any], list[str]]:
    checks: list[str] = []
    result_line: str | None = None
    for line in stdout.decode("ascii", errors="strict").splitlines():
        if line.startswith("CHECK "):
            fields = line.split(" ", 2)
            if len(fields) != 3:
                raise ValueError("native_check_malformed")
            checks.append(line)
            if fields[2] != "PASS":
                raise ValueError(f"native_check_failed:{line}")
        elif line.startswith("{") and line.endswith("}"):
            if result_line is not None:
                raise ValueError("native_result_duplicate")
            result_line = line
    if result_line is None:
        raise ValueError("native_result_missing")
    result = json.loads(result_line)
    if not isinstance(result, dict):
        raise ValueError("native_result_not_object")
    expected = {
        "passed": True,
        "capture_calls": 1,
        "original_calls": 1,
        "production_stub_template": True,
        "game_access": False,
        "rea_or_rpm": False,
    }
    for key, value in expected.items():
        if result.get(key) != value:
            raise ValueError(f"native_result_mismatch:{key}:{result!r}")
    return result, checks


def run(revision: int = 1, output: Path | None = None) -> tuple[int, dict[str, Any]]:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    suffix = "report.json" if revision == 1 else f"report-{revision:03d}.json"
    report_path = (output or STAGE / suffix).resolve()
    executable = STAGE / f"information-battle-message-abi-{revision:03d}.exe"
    compile_stdout = STAGE / f"compile-{revision:03d}.stdout.log"
    compile_stderr = STAGE / f"compile-{revision:03d}.stderr.log"
    run_stdout = STAGE / f"run-{revision:03d}.stdout.log"
    run_stderr = STAGE / f"run-{revision:03d}.stderr.log"
    for path in (report_path, executable, compile_stdout, compile_stderr,
                 run_stdout, run_stderr):
        if path.exists():
            raise FileExistsError(f"refusing_to_overwrite:{path}")

    report: dict[str, Any] = {
        "schema": "information_battle_message_abi_test_v1",
        "status": "blocked",
        "mode": "offline_synthetic_process",
        "scope": {
            "game_access": False,
            "remote_process_access": False,
            "rea_or_rpm": False,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "production_modified": False,
        },
        "contract": {
            "production_stub": "work/native/information-battle-entry-stub.S",
            "template_macro": "INFORMATION_BATTLE_TEMPLATE=1",
            "capture_signature": [
                "message", "callback_function", "original_return", "original_rbp"
            ],
            "original_forwarding": "tail_jump_to_self_owned_native_original",
            "preserved_state": [
                "volatile GPR RAX/RCX/RDX/R8/R9/R10/R11",
                "XMM0-XMM5 full 128 bits",
                "RFLAGS", "MXCSR", "x87 control word", "GetLastError",
                "Win64 nonvolatile GPR/XMM caller state",
            ],
            "stack_contract": {
                "shadow_space_bytes": 32,
                "message_frame_bytes": "0x1e8",
                "native_original_entry_rsp_mod16": 8,
                "extra_stack_arguments": 2,
            },
            "unwind_boundaries": [
                "entry", "after pushfq", "after sub", "body",
                "before add", "after add/restore_flags", "after pop/tail",
            ],
        },
        "sources": {path.relative_to(ROOT).as_posix(): file_pin(path)
                    for path in (CPP, CALLER, STUB, SCRIPT)},
        "compile": {},
        "run": {},
        "limitations": [
            "Caller, callback, original, arguments, and memory are self-owned synthetic fixtures.",
            "The test proves the shipped assembly ABI/unwind shape only; it does not prove live EU4 callback lifetime or message semantics.",
        ],
    }

    compiler = compiler_path(None)
    if compiler is None or not Path(compiler).is_file():
        report["status"] = "blocked_missing_compiler"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 1, report

    command = [
        compiler, "-std=c++17", "-DINFORMATION_BATTLE_TEMPLATE=1",
        "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra", "-Werror",
        "-O2", "-fstack-usage", "-static-libgcc", "-static-libstdc++",
        "-Wl,--no-insert-timestamp", "-I", str(NATIVE), "-o", str(executable),
        str(STUB), str(CALLER), str(CPP), "-lkernel32",
    ]
    report["compile"]["command"] = command
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=120, check=False)
    compile_stdout.write_bytes(compiled.stdout)
    compile_stderr.write_bytes(compiled.stderr)
    report["compile"].update({
        "returncode": compiled.returncode,
        "stdout_sha256": hashlib.sha256(compiled.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(compiled.stderr).hexdigest(),
        "executable": file_pin(executable) if executable.is_file() else None,
    })
    if compiled.returncode != 0 or not executable.is_file():
        report["status"] = "failed_compile"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 1, report

    ran = subprocess.run([str(executable)], cwd=ROOT, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=120, check=False)
    run_stdout.write_bytes(ran.stdout)
    run_stderr.write_bytes(ran.stderr)
    report["run"].update({
        "returncode": ran.returncode,
        "stdout_sha256": hashlib.sha256(ran.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(ran.stderr).hexdigest(),
        "stdout_bytes": len(ran.stdout),
        "stderr_bytes": len(ran.stderr),
    })
    try:
        native_result, checks = parse_native(ran.stdout)
    except (ValueError, UnicodeDecodeError) as error:
        report["status"] = "failed_native_output"
        report["run"]["parse_error"] = str(error)
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 1, report
    report["run"]["result"] = native_result
    report["run"]["check_count"] = len(checks)
    if ran.returncode != 0:
        report["status"] = "failed_native_fixture"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return 1, report

    report["status"] = "passed"
    report["elapsed_seconds"] = time.time() - started
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0, {
        "report": report_path.relative_to(ROOT).as_posix(),
        "executable": executable.relative_to(ROOT).as_posix(),
        "result": native_result,
        "check_count": len(checks),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", type=int, default=1)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    if not 1 <= args.revision <= 999:
        parser.error("--revision must be between 1 and 999")
    try:
        code, receipt = run(args.revision, args.output)
    except (FileExistsError, FileNotFoundError, OSError, RuntimeError) as error:
        print(f"message ABI fixture runner failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
