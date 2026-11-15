"""Run the independent owned-RX ABI fixture for the production Line1 stub.

The default action is inert.  ``--run`` is required to compile and execute the
fixture process.  This runner does not open the game, use RPM/REA, or install
the observer/build scripts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
TESTS = NATIVE / "tests"
STAGE = (ROOT / "work" / "runtime" /
         "information-battle-native-observer-20261027-001" /
         "line1-observer-abi-002")
STUB = NATIVE / "information-battle-line1-observer-stub.S"
ABI = TESTS / "information-battle-line1-observer-abi-002.S"
CPP = TESTS / "information-battle-line1-observer-abi-002.cpp"
SCRIPT = Path(__file__).resolve()
EXE = STAGE / "information-battle-line1-observer-abi.exe"
REPORT = STAGE / "report.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def pin(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")


def static_stub_checks() -> dict[str, Any]:
    source = STUB.read_text(encoding="utf-8")
    forbidden = {
        "fixture_global_prefix": "g_line1_",
        "old_fixture_original": "line1_original_entry",
        "fixture_continuation": "observer_native_continuation",
        "fixture_callback_global": "observer_capture_",
        "old_fixture_hook": "line1_entry_hook",
    }
    findings = {name: token not in source
                for name, token in forbidden.items()}
    externs = sorted(set(re.findall(r"^\.extern\s+([A-Za-z0-9_]+)",
                                    source, flags=re.MULTILINE)))
    expected_externs = {
        "GetLastError",
        "SetLastError",
        "information_battle_line1_original",
        "information_battle_line1_capture",
    }
    return {
        "production_stub_has_no_fixture_symbols": all(findings.values()),
        "forbidden_symbol_checks": findings,
        "externs": externs,
        "externs_match_contract": set(externs) == expected_externs,
        "exports_hook": "information_battle_line1_hook:" in source,
        "tail_jumps_original": "jmp qword ptr [rip + information_battle_line1_original]"
        in source,
        "callback_passes_original_r13": (
            "mov rax, qword ptr [rsp + 0xe8]" in source
            and "mov qword ptr [rsp + 0x28], rax" in source
        ),
        "production_stub_restores_r13": "mov r13, qword ptr [rsp + 0xe8]" in source,
        "source_bytes_bounded": STUB.stat().st_size <= 64 * 1024,
    }


def parse_fixture_summary(stdout: str) -> dict[str, Any]:
    check_lines = [line for line in stdout.splitlines()
                   if line.startswith("CHECK ")]
    passed = sum(line.endswith(" PASS") for line in check_lines)
    failed = sum(line.endswith(" FAIL") for line in check_lines)
    summary = next((line for line in stdout.splitlines()
                    if line.startswith("SUMMARY ")), "")
    result = next((line for line in stdout.splitlines()
                   if line.startswith("RESULT ")), "")
    return {
        "check_count": len(check_lines),
        "check_passes": passed,
        "check_failures": failed,
        "summary_line": summary,
        "result_line": result,
        "result_pass": result == "RESULT PASS",
    }


def run_fixture() -> int:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    source_paths = (STUB, ABI, CPP, SCRIPT)
    report: dict[str, Any] = {
        "schema": "information_battle_line1_observer_abi_fixture_v1",
        "status": "blocked",
        "scope": {
            "game_access": False,
            "rpm": False,
            "rea": False,
            "remote_process_access": False,
            "production_stub": True,
            "fixture_process_only": True,
            "claim": "independent owned-RX ABI fixture; not an installed-game hook",
        },
        "source_pins": {},
        "static_stub_checks": {},
        "compile": {},
        "run": {},
        "contract": {
            "callback_abi": ["widget", "text", "flag_r8b", "return_pc",
                              "original_rbp", "original_r13"],
            "sixth_argument_stack_offset_at_callback": "0x30",
            "production_stub_saved_r13_offset": "0xe8",
            "production_stub_callback_r13_slot": "0x28",
            "fixture_asserts_original_r13_and_restoration": True,
        },
        "owned_rx": {
            "allocation": "VirtualAlloc MEM_COMMIT|MEM_RESERVE",
            "jump": "FF 25 00 00 00 00 + absolute continuation pointer",
            "protection": "PAGE_EXECUTE_READ",
            "cleanup": "VirtualFree(MEM_RELEASE), original pointer cleared",
        },
    }
    missing = [path.relative_to(ROOT).as_posix()
               for path in source_paths if not path.exists()]
    report["source_pins"] = {
        path.name: pin(path) for path in source_paths if path.exists()
    }
    if missing:
        report["status"] = "blocked_missing_source"
        report["missing_sources"] = missing
        report["elapsed_seconds"] = time.time() - started
        write_json(REPORT, report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 2

    report["static_stub_checks"] = static_stub_checks()
    if not (report["static_stub_checks"]["production_stub_has_no_fixture_symbols"]
            and report["static_stub_checks"]["externs_match_contract"]
            and report["static_stub_checks"]["exports_hook"]
            and report["static_stub_checks"]["tail_jumps_original"]
            and report["static_stub_checks"]["callback_passes_original_r13"]
            and report["static_stub_checks"]["production_stub_restores_r13"]):
        report["status"] = "failed_static_stub_contract"
        report["elapsed_seconds"] = time.time() - started
        write_json(REPORT, report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        write_json(REPORT, report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 2

    command = [
        compiler,
        "-std=c++17",
        "-fno-exceptions",
        "-fno-rtti",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-O2",
        str(CPP),
        str(STUB),
        str(ABI),
        "-o",
        str(EXE),
        "-lkernel32",
    ]
    compile_started = time.time()
    try:
        compile_result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            check=False,
        )
        compile_timeout = False
    except subprocess.TimeoutExpired as error:
        compile_result = None
        compile_timeout = True
        (STAGE / "compile.stdout.log").write_text(
            error.stdout or "", encoding="utf-8")
        (STAGE / "compile.stderr.log").write_text(
            error.stderr or "", encoding="utf-8")
    if compile_result is not None:
        (STAGE / "compile.stdout.log").write_text(
            compile_result.stdout, encoding="utf-8")
        (STAGE / "compile.stderr.log").write_text(
            compile_result.stderr, encoding="utf-8")
    report["compile"] = {
        "command": command,
        "returncode": None if compile_result is None else compile_result.returncode,
        "timeout": compile_timeout,
        "elapsed_seconds": time.time() - compile_started,
        "stdout_log": (STAGE / "compile.stdout.log").relative_to(ROOT).as_posix(),
        "stderr_log": (STAGE / "compile.stderr.log").relative_to(ROOT).as_posix(),
    }
    if compile_result is None or compile_result.returncode != 0:
        report["status"] = "compile_failed"
        report["elapsed_seconds"] = time.time() - started
        write_json(REPORT, report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    run_started = time.time()
    try:
        run_result = subprocess.run(
            [str(EXE)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            check=False,
        )
        run_timeout = False
    except subprocess.TimeoutExpired as error:
        run_result = None
        run_timeout = True
        (STAGE / "run.stdout.log").write_text(
            error.stdout or "", encoding="utf-8")
        (STAGE / "run.stderr.log").write_text(
            error.stderr or "", encoding="utf-8")
    if run_result is not None:
        (STAGE / "run.stdout.log").write_text(
            run_result.stdout, encoding="utf-8")
        (STAGE / "run.stderr.log").write_text(
            run_result.stderr, encoding="utf-8")
    run_stdout = "" if run_result is None else run_result.stdout
    report["run"] = {
        "returncode": None if run_result is None else run_result.returncode,
        "timeout": run_timeout,
        "elapsed_seconds": time.time() - run_started,
        "stdout_log": (STAGE / "run.stdout.log").relative_to(ROOT).as_posix(),
        "stderr_log": (STAGE / "run.stderr.log").relative_to(ROOT).as_posix(),
        **parse_fixture_summary(run_stdout),
    }
    report["source_pins"][EXE.name] = pin(EXE) if EXE.exists() else None
    passed = (run_result is not None and run_result.returncode == 0
              and report["run"]["result_pass"]
              and report["run"]["check_failures"] == 0)
    report["status"] = "passed" if passed else "failed"
    report["elapsed_seconds"] = time.time() - started
    write_json(REPORT, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build/run the independent Line1 observer owned-RX ABI fixture.")
    parser.add_argument(
        "--run", action="store_true",
        help="compile and execute the fixture; without this flag the runner is inert")
    args = parser.parse_args(argv)
    if not args.run:
        print("information-battle-line1-observer-abi: inert; pass --run to execute")
        return 0
    return run_fixture()


if __name__ == "__main__":
    sys.exit(main())
