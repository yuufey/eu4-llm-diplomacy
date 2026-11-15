"""Build and run the isolated x64 prefix/trampoline unwind contract test.

The executable allocates only its own synthetic image and stack.  It does not
open EU4, inspect the installation, patch a process, or call REA/native tools.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-entry-20261025-001" / "unwind-test-001"
CPP = NATIVE / "test-information-battle-entry-unwind.cpp"
PLAN = NATIVE / "information-battle-entry-plan.h"
SCRIPT = Path(__file__).resolve()
EXE = STAGE / "test-information-battle-entry-unwind.exe"
REPORT = STAGE / "report.json"


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


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def lines_with_prefix(text: str, prefix: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(prefix)]


def run(label: str = "001") -> dict[str, object]:
    if not label or any(character not in "abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                        for character in label):
        raise ValueError("label must be a simple version identifier")
    STAGE.mkdir(parents=True, exist_ok=True)
    if label == "001":
        exe = EXE
        report_path = REPORT
        compile_stdout_path = STAGE / "compile.stdout.log"
        compile_stderr_path = STAGE / "compile.stderr.log"
        run_stdout_path = STAGE / "run.stdout.log"
        run_stderr_path = STAGE / "run.stderr.log"
    else:
        exe = STAGE / f"test-information-battle-entry-unwind-{label}.exe"
        report_path = STAGE / f"report-{label}.json"
        compile_stdout_path = STAGE / f"compile-{label}.stdout.log"
        compile_stderr_path = STAGE / f"compile-{label}.stderr.log"
        run_stdout_path = STAGE / f"run-{label}.stdout.log"
        run_stderr_path = STAGE / f"run-{label}.stderr.log"
    compiler = shutil.which("g++")
    started = time.time()
    report: dict[str, object] = {
        "schema": "information_battle_entry_prefix_unwind_test_v1",
        "status": "blocked",
        "revision": {
            "label": label,
            "previous_report": (file_pin(REPORT) if label != "001"
                                 and REPORT.exists() else None),
            "change_from_001": (
                "root changed projected UNWIND_INFO SizeOfProlog from 21 "
                "to the complete 35-byte code range (kCodeBytes)"
            ) if label != "001" else None,
            "expected_effect": (
                "keep FF25 at pc=21 inside the declared prologue so it is "
                "not classified as an epilog"
            ) if label != "001" else None,
            "expectations_relaxed": False,
        },
        "scope": {
            "game_access": False,
            "rea_access": False,
            "remote_process_access": False,
            "owned_virtualalloc_only": True,
            "claim": "offline synthetic image/function-table unwind only",
        },
        "source_pins": {
            "plan": file_pin(PLAN),
            "test_cpp": file_pin(CPP),
            "python_runner": file_pin(SCRIPT),
        },
        "compile": {},
        "run": {},
        "observations": {},
    }
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2)
                               + "\n", encoding="utf-8")
        return report

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
        str(exe),
        "-lkernel32",
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
    compile_stdout_path.write_text(compile_stdout, encoding="utf-8")
    compile_stderr_path.write_text(compile_stderr, encoding="utf-8")
    report["compile"] = {
        "command": command,
        "compiler": compiler,
        "returncode": compiled.returncode,
        "stdout": compile_stdout,
        "stderr": compile_stderr,
    }
    if compiled.returncode != 0 or not exe.exists():
        report["status"] = "compile_failed"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2)
                               + "\n", encoding="utf-8")
        return report

    report["artifact"] = file_pin(exe)
    run_result = subprocess.run(
        [str(exe)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
    run_stdout = decode(run_result.stdout)
    run_stderr = decode(run_result.stderr)
    run_stdout_path.write_text(run_stdout, encoding="utf-8")
    run_stderr_path.write_text(run_stderr, encoding="utf-8")
    result_line = next(
        (line for line in run_stdout.splitlines() if line.startswith("RESULT ")),
        "",
    )
    report["run"] = {
        "command": [str(exe)],
        "returncode": run_result.returncode,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "result_line": result_line,
    }
    report["observations"] = {
        "checks": lines_with_prefix(run_stdout, "CHECK "),
        "unwind_points": lines_with_prefix(run_stdout, "UNWIND "),
        "summary": lines_with_prefix(run_stdout, "SUMMARY "),
    }
    report["status"] = (
        "passed"
        if run_result.returncode == 0 and result_line == "RESULT PASS"
        else "failed"
    )
    report["elapsed_seconds"] = time.time() - started
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2)
                           + "\n", encoding="utf-8")
    return report


def main() -> int:
    label = "001"
    if len(sys.argv) == 2 and sys.argv[1].startswith("--label="):
        label = sys.argv[1][len("--label="):]
    elif len(sys.argv) != 1:
        print("usage: test_information_battle_entry_unwind.py [--label=002]",
              file=sys.stderr)
        return 2
    report = run(label)
    report_path = (REPORT if label == "001"
                   else STAGE / f"report-{label}.json")
    print(json.dumps({
        "status": report["status"],
        "report": report_path.relative_to(ROOT).as_posix(),
        "artifact": report.get("artifact"),
    }, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
