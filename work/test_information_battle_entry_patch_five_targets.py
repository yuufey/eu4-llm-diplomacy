"""Build and run the isolated five-target entry-patch transaction fixture.

The default action is inert.  ``--run`` is required to compile and execute a
fixture process that owns five private RX target pages and exercises the
guarded transaction once.  It does not open the game or use RPM/REA.
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
INC = NATIVE / "entry-patch-transaction.inc"
CPP = NATIVE / "test-entry-patch-five-targets.cpp"
SCRIPT = Path(__file__).resolve()
STAGE = (ROOT / "work" / "runtime" /
         "information-battle-native-observer-20261027-001" /
         "patch-five-targets-001")
EXE = STAGE / "test-entry-patch-five-targets.exe"
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


def write_report(report: dict[str, Any]) -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")


def capacity_checks() -> dict[str, Any]:
    source = INC.read_text(encoding="utf-8")
    checks = {
        "native_text_branch_present": "#if defined(INFORMATION_BATTLE_NATIVE_TEXT)" in source,
        "native_text_max_targets_five": bool(re.search(
            r"#if defined\(INFORMATION_BATTLE_NATIVE_TEXT\).*?"
            r"kMaxTargets=5;", source, flags=re.DOTALL)),
        "legacy_max_targets_four": bool(re.search(
            r"#else.*?kMaxTargets=4;", source, flags=re.DOTALL)),
        "max_pages_derived_from_targets": "kMaxPages=2*kMaxTargets;" in source,
    }
    return {
        **checks,
        "native_text_capacity": 5,
        "legacy_capacity": 4,
        "derived_page_capacity": "2*kMaxTargets",
        "pass": all(checks.values()),
    }


def parse_fixture(stdout: str) -> dict[str, Any]:
    checks = [line for line in stdout.splitlines()
              if line.startswith("CHECK ")]
    json_line = next((line for line in reversed(stdout.splitlines())
                      if line.startswith("{")), "")
    fixture = json.loads(json_line) if json_line else {}
    result_line = next((line for line in stdout.splitlines()
                        if line.startswith("RESULT ")), "")
    return {
        "check_count": len(checks),
        "check_passes": sum(line.endswith(" PASS") for line in checks),
        "check_failures": sum(line.endswith(" FAIL") for line in checks),
        "summary_line": next((line for line in stdout.splitlines()
                               if line.startswith("SUMMARY ")), ""),
        "result_line": result_line,
        "result_pass": result_line == "RESULT PASS",
        "fixture_json": fixture,
    }


def run_fixture() -> int:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    source_paths = (INC, CPP, SCRIPT)
    report: dict[str, Any] = {
        "schema": "information_battle_entry_patch_five_targets_v1",
        "status": "blocked",
        "scope": {
            "game_access": False,
            "rpm": False,
            "rea": False,
            "remote_process_access": False,
            "fixture_process_only": True,
            "claim": "one guarded five-target transaction over private RX pages; not an installed-game patch",
        },
        "source_pins": {},
        "capacity": {},
        "compile": {},
        "run": {},
        "owned_memory": {
            "targets": 5,
            "target_pages": "private PAGE_EXECUTE_READ",
            "trampolines": "private PAGE_EXECUTE_READ",
            "transaction": "one guarded_patch_apply followed by one guarded_patch_rollback",
            "registry_lifetime": "RX allocations retained until fixture process exit after publication",
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
        write_report(report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 2

    report["capacity"] = capacity_checks()
    if not report["capacity"]["pass"]:
        report["status"] = "failed_capacity_contract"
        report["elapsed_seconds"] = time.time() - started
        write_report(report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        write_report(report)
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
        write_report(report)
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
        **parse_fixture(run_stdout),
    }
    report["source_pins"][EXE.name] = pin(EXE) if EXE.exists() else None
    fixture = report["run"].get("fixture_json", {})
    passed = (run_result is not None and run_result.returncode == 0
              and report["run"]["result_pass"]
              and report["run"]["check_failures"] == 0
              and fixture.get("target_count") == 5
              and fixture.get("max_targets") == 5
              and fixture.get("max_pages") == 10
              and fixture.get("apply_pending") == 0
              and fixture.get("rollback_pending") == 0
              and fixture.get("apply_threads_resumed") is True
              and fixture.get("rollback_threads_resumed") is True
              and fixture.get("apply_protection_restored") is True
              and fixture.get("rollback_protection_restored") is True)
    report["status"] = "passed" if passed else "failed"
    report["elapsed_seconds"] = time.time() - started
    write_report(report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build/run the isolated five-target entry-patch fixture.")
    parser.add_argument(
        "--run", action="store_true",
        help="compile and execute the fixture; without this flag the runner is inert")
    args = parser.parse_args(argv)
    if not args.run:
        print("information-battle-entry-patch-five-targets: inert; pass --run to execute")
        return 0
    return run_fixture()


if __name__ == "__main__":
    sys.exit(main())
