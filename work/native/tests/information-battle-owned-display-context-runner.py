"""One-shot, offline C++17 test runner for the owned display-context reader."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from work.local_config import load_local_env

NATIVE = ROOT / "work/native"
TEST_SOURCE = NATIVE / "tests/information-battle-owned-display-context-test.cpp"
HEADER = NATIVE / "information-battle-owned-display-context.h"
LAYOUT = NATIVE / "information-battle-display-context-layout.h"
CONTRACT = ROOT / "work/battle-display-context-wire7-contract.md"
DEFINITION_SOURCE = ROOT / "bridge/information/battle_definition_memory.py"
DEFINITION_PROFILE = ROOT / "bridge/information/profiles/battle-definition-memory-1374.json"
LOCALIZATION_SOURCE = ROOT / "bridge/information/localization_memory.py"
LOCALIZATION_PROFILE = ROOT / "bridge/information/profiles/localization-memory-1374.json"
RUNNER = Path(__file__).resolve()
STAGE = ROOT / "work/runtime/information-battle-body-source-20261028-001/owned-display-context-001"


def pin(path: Path) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return {
        "path": path.resolve().relative_to(ROOT).as_posix(),
        "bytes": size,
        "sha256": digest.hexdigest(),
    }


def write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def write_text_exclusive(path: Path, value: str) -> None:
    write_exclusive(path, value.encode("utf-8"))


def resolve_compiler() -> tuple[str, str]:
    had_process_override = bool(os.environ.get("EU4_CXX", "").strip())
    local_values = load_local_env()
    requested = os.environ.get("EU4_CXX", "").strip()
    if not requested:
        requested = local_values.get("EU4_CXX", "").strip()
    if requested:
        resolved = shutil.which(requested)
        if resolved is None and Path(requested).is_file():
            resolved = str(Path(requested).resolve())
        if resolved is None:
            raise FileNotFoundError("EU4_CXX_not_found:" + requested)
        return str(Path(resolved).resolve()), (
            "EU4_CXX_process_environment" if had_process_override
            else "work.local_config.load_local_env"
        )

    fallback = shutil.which("g++")
    if fallback is None:
        raise FileNotFoundError("EU4_CXX_unset_and_g++_not_found")
    return str(Path(fallback).resolve()), "g++_fallback_EU4_CXX_unset"


def next_attempt() -> tuple[int, Path]:
    for attempt in range(1, 1000):
        attempt_dir = STAGE / f"attempt-{attempt:03d}"
        if not attempt_dir.exists():
            return attempt, attempt_dir
    raise RuntimeError("no_unused_attempt_slot")


def run_test_only() -> int:
    source_paths = [
        HEADER, TEST_SOURCE, LAYOUT, CONTRACT,
        DEFINITION_SOURCE, DEFINITION_PROFILE,
        LOCALIZATION_SOURCE, LOCALIZATION_PROFILE, RUNNER,
    ]
    for path in source_paths:
        if not path.is_file():
            raise FileNotFoundError("required_source_missing:" + str(path))
    compiler, selected_by = resolve_compiler()
    attempt, attempt_dir = next_attempt()
    attempt_dir.mkdir(parents=True, exist_ok=False)

    executable = attempt_dir / "information-battle-owned-display-context-test.exe"
    compile_stdout = attempt_dir / "compile.stdout.log"
    compile_stderr = attempt_dir / "compile.stderr.log"
    run_stdout = attempt_dir / "run.stdout.log"
    run_stderr = attempt_dir / "run.stderr.log"
    receipt_path = attempt_dir / "receipt.json"
    source_pins_before = [pin(path) for path in source_paths]
    receipt = {
        "schema": "information.battle.owned_display_context_test.v1",
        "attempt": attempt,
        "status": "running",
        "started_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "execution_mode": "--test-only",
        "compiler": compiler,
        "compiler_selected_by": selected_by,
        "language_standard": "C++17",
        "compile_command": [
            compiler, "-std=c++17", "-O2", "-Wall", "-Wextra",
            "-Wpedantic", "-Werror", "-I", str(NATIVE),
            str(TEST_SOURCE), "-o", str(executable),
        ],
        "source_pins_before": source_pins_before,
        "scope": "offline bounded-reader fixture only; no game, RPM, REA, MCP, or native engine call",
        "reader_budget": {
            "total_calls": 4096,
            "total_bytes": 524288,
            "single_read_bytes": 8193,
            "two_pass": True,
        },
    }

    compile_result = None
    run_result = None
    error = None
    try:
        compile_result = subprocess.run(
            receipt["compile_command"], cwd=ROOT, capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=120,
            check=False,
        )
        write_text_exclusive(compile_stdout, compile_result.stdout)
        write_text_exclusive(compile_stderr, compile_result.stderr)
        if compile_result.returncode == 0:
            run_result = subprocess.run(
                [str(executable)], cwd=ROOT, capture_output=True,
                text=True, encoding="utf-8", errors="replace", timeout=30,
                check=False,
            )
            write_text_exclusive(run_stdout, run_result.stdout)
            write_text_exclusive(run_stderr, run_result.stderr)
        else:
            write_text_exclusive(run_stdout, "not_run_compile_failed\n")
            write_text_exclusive(run_stderr, "not_run_compile_failed\n")
    except Exception as exc:  # preserve one bounded attempt even on tool failure
        error = f"{type(exc).__name__}:{exc}"
        for path in (compile_stdout, compile_stderr, run_stdout, run_stderr):
            if not path.exists():
                write_text_exclusive(path, "execution_failed_before_log_capture\n")

    source_pins_after = [pin(path) for path in source_paths]
    receipt.update({
        "finished_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_pins_after": source_pins_after,
        "sources_unchanged": source_pins_before == source_pins_after,
        "compile_exit_code": None if compile_result is None else compile_result.returncode,
        "run_exit_code": None if run_result is None else run_result.returncode,
        "compile_stdout": pin(compile_stdout),
        "compile_stderr": pin(compile_stderr),
        "run_stdout": pin(run_stdout),
        "run_stderr": pin(run_stderr),
        "executable": pin(executable) if executable.is_file() else None,
    })
    if error is not None:
        receipt["failure"] = error
    if not receipt["sources_unchanged"]:
        receipt["status"] = "failed"
        receipt["failure"] = "source_changed_during_attempt"
    elif compile_result is not None and compile_result.returncode == 0 \
            and run_result is not None and run_result.returncode == 0:
        receipt["status"] = "passed"
    else:
        receipt["status"] = "failed"
        if "failure" not in receipt:
            receipt["failure"] = "compile_or_test_failed"
    write_text_exclusive(
        receipt_path,
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n",
    )
    print(json.dumps({
        "status": receipt["status"],
        "attempt": attempt,
        "receipt": receipt_path.resolve().relative_to(ROOT).as_posix(),
        "failure": receipt.get("failure"),
        "compile_exit_code": receipt["compile_exit_code"],
        "run_exit_code": receipt["run_exit_code"],
    }, ensure_ascii=False))
    return 0 if receipt["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-only", action="store_true", required=True)
    args = parser.parse_args()
    if not args.test_only:
        print(json.dumps({"status": "refused", "reason": "explicit_--test-only_required"}))
        return 2
    try:
        return run_test_only()
    except Exception as exc:
        print(json.dumps({"status": "refused", "reason": f"{type(exc).__name__}:{exc}"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
