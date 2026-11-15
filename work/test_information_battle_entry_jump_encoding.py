"""Build/run the isolated old-vs-CS-prefix jump encoding experiment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-entry-20261025-001" / "unwind-jump-encoding-test-001"
CPP = NATIVE / "test-information-battle-entry-jump-encoding.cpp"
PLAN = NATIVE / "information-battle-entry-plan.h"
SCRIPT = Path(__file__).resolve()
EXE = STAGE / "test-information-battle-entry-jump-encoding.exe"
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


def pin(path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def run() -> dict[str, object]:
    STAGE.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which("g++")
    started = time.time()
    report: dict[str, object] = {
        "schema": "information_battle_entry_jump_encoding_test_v1",
        "status": "blocked",
        "scope": {
            "game_access": False,
            "rea_access": False,
            "remote_process_access": False,
            "owned_virtualalloc_only": True,
            "actual_cpu_execution": True,
            "claim": "candidate encoding experiment, not a production patch",
        },
        "experiment": {
            "legacy_jump": "ff25 00000000 <absolute64>, 14 bytes, code range 35",
            "candidate_jump": "2e ff25 00000000 <absolute64>, 15 bytes, code range 36",
            "candidate_prefix": "fixed 21-byte prefix only",
            "unsupported_diagnostic_pcs": [22, 23, 24, 25, 26],
            "unwind_expectations_relaxed": False,
        },
        "source_pins": {
            "plan": pin(PLAN),
            "test_cpp": pin(CPP),
            "python_runner": pin(SCRIPT),
        },
        "compile": {},
        "run": {},
        "observations": {},
    }
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
        "-I",
        str(NATIVE),
        str(CPP),
        "-o",
        str(EXE),
        "-lkernel32",
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=90, check=False)
    compile_stdout = text(compiled.stdout)
    compile_stderr = text(compiled.stderr)
    (STAGE / "compile.stdout.log").write_text(compile_stdout, encoding="utf-8")
    (STAGE / "compile.stderr.log").write_text(compile_stderr, encoding="utf-8")
    report["compile"] = {
        "command": command,
        "compiler": compiler,
        "returncode": compiled.returncode,
        "stdout": compile_stdout,
        "stderr": compile_stderr,
    }
    if compiled.returncode != 0 or not EXE.exists():
        report["status"] = "compile_failed"
        report["elapsed_seconds"] = time.time() - started
        REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")
        return report
    report["artifact"] = pin(EXE)
    executed = subprocess.run([str(EXE)], cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=90, check=False)
    run_stdout = text(executed.stdout)
    run_stderr = text(executed.stderr)
    (STAGE / "run.stdout.log").write_text(run_stdout, encoding="utf-8")
    (STAGE / "run.stderr.log").write_text(run_stderr, encoding="utf-8")
    result_line = next((line for line in run_stdout.splitlines()
                        if line.startswith("RESULT ")), "")
    report["run"] = {
        "command": [str(EXE)],
        "returncode": executed.returncode,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "result_line": result_line,
    }
    report["observations"] = {
        "checks": [line for line in run_stdout.splitlines()
                   if line.startswith("CHECK ")],
        "execution": [line for line in run_stdout.splitlines()
                      if line.startswith("EXEC ")],
        "unwind": [line for line in run_stdout.splitlines()
                   if line.startswith("UNWIND ")],
        "summary": [line for line in run_stdout.splitlines()
                    if line.startswith("SUMMARY ")],
    }
    report["status"] = ("passed" if executed.returncode == 0
                         and result_line == "RESULT PASS" else "failed")
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
