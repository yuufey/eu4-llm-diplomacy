"""One-shot offline compiler and runner for the expansion-plan unit tests."""
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


CANDIDATE = Path(__file__).resolve().parent
ROOT = CANDIDATE.parents[2]
sys.path.insert(0, str(ROOT))
from work.local_config import load_local_env

STAGE = (
    ROOT
    / "work/runtime/information-battle-body-source-20261028-001/"
      "owned-expansion-001"
).resolve()
def attempt_paths(attempt: int) -> tuple[Path, Path, Path]:
    stem = f"format-expansion-plan-test-{attempt:03d}"
    return STAGE / f"{stem}.exe", STAGE / f"{stem}.log", STAGE / f"{stem}.json"

TEMPLATE_RECEIPT = (
    ROOT / "work/runtime/information-battle-body-source-20261028-001/"
          "current-templates-001.json"
).resolve()
REA_REPLACEMENT_EVIDENCE = (
    ROOT / "work/runtime/information-diplomacy-state-20261028-001/"
          "battle-body-query-source-001/rea-localized-replacement-001/evidence.json"
).resolve()
REA_OUTER_FORMAT_EVIDENCE = (
    ROOT / "work/runtime/information-battle-fragments-20261025-001/"
          "rea-localized-format-001/selected-evidence-001.json"
).resolve()


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


def write_exclusive(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def next_attempt() -> tuple[int, Path, Path, Path, list[dict]]:
    preserved: list[dict] = []
    for attempt in range(1, 1000):
        executable, log_path, receipt_path = attempt_paths(attempt)
        group = (executable, log_path, receipt_path)
        if not any(path.exists() for path in group):
            return attempt, executable, log_path, receipt_path, preserved
        for path in group:
            if path.exists():
                preserved.append(pin(path))
    raise RuntimeError("no_unused_attempt_slot")


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
        selected_by = (
            "EU4_CXX_process_environment"
            if had_process_override
            else "work.local_config.load_local_env"
        )
        return str(Path(resolved).resolve()), selected_by

    fallback = shutil.which("g++")
    if fallback is None:
        raise FileNotFoundError("EU4_CXX_unset_and_g++_not_found")
    return str(Path(fallback).resolve()), "g++_fallback_EU4_CXX_unset"


def run_test_only() -> int:
    try:
        attempt, executable, log_path, receipt_path, preserved_attempt_artifacts = next_attempt()
    except Exception as exc:
        print(json.dumps({"status": "refused", "reason": f"{type(exc).__name__}:{exc}"}))
        return 2

    STAGE.mkdir(parents=True, exist_ok=True)

    started = dt.datetime.now(dt.timezone.utc).isoformat()
    log_parts: list[str] = []
    receipt = {
        "schema": "information.battle.format_expansion_plan_test.v1",
        "status": "failed",
        "execution_mode": "--test-only",
        "attempt": attempt,
        "preserved_prior_attempt_artifacts": preserved_attempt_artifacts,
        "started_at_utc": started,
        "game_process_attached": False,
        "game_or_native_function_called": False,
        "native_calls": 0,
        "REA_run": False,
        "MCP_used": False,
        "boundary": {
            "component": "pure C++20 size planner; no formatter invocation",
            "template_evidence": (
                "current-templates-001 records eight requested keys; each of "
                "LANDBATTLEOVER_1 and NAVALBATTLEOVER_1 is only the 6-byte "
                "literal $NAME$ template. This plan does not supply the other "
                "controls or establish a complete B04 body."
            ),
            "future_native_call": (
                "not authorized by this planner; local template provenance and "
                "complete type-2 row binding remain separate prerequisites"
            ),
        },
    }

    try:
        source_paths = [
            CANDIDATE / "format_input_builder.h",
            CANDIDATE / "format_expansion_plan.h",
            CANDIDATE / "format_expansion_plan_test.cpp",
            CANDIDATE / "format_expansion_plan_runner.py",
            CANDIDATE / "README.md",
            TEMPLATE_RECEIPT,
            REA_REPLACEMENT_EVIDENCE,
            REA_OUTER_FORMAT_EVIDENCE,
        ]
        source_pins = [pin(path) for path in source_paths]
        receipt["source_and_evidence_pins"] = source_pins

        compiler, compiler_source = resolve_compiler()
        machine_result = subprocess.run(
            [compiler, "-dumpmachine"], capture_output=True, text=True,
            check=False, timeout=15,
        )
        if machine_result.returncode != 0:
            raise RuntimeError("compiler_target_query_failed")
        target = machine_result.stdout.strip()
        if not target.lower().startswith(("x86_64", "amd64")):
            raise RuntimeError("unexpected_compiler_target:" + target)
        version_result = subprocess.run(
            [compiler, "--version"], capture_output=True, text=True,
            check=False, timeout=15,
        )
        if version_result.returncode != 0:
            raise RuntimeError("compiler_version_query_failed")
        version = version_result.stdout.splitlines()[0] if version_result.stdout else "unknown"

        compile_command = [
            compiler,
            "-std=c++20",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            str(CANDIDATE / "format_expansion_plan_test.cpp"),
            "-o",
            str(executable),
        ]
        receipt["compiler"] = {
            "path": compiler,
            "selected_by": compiler_source,
            "target": target,
            "version": version,
            "compile_command": compile_command,
        }
        log_parts.append("$ " + subprocess.list2cmdline(compile_command))
        compiled = subprocess.run(
            compile_command, cwd=CANDIDATE, capture_output=True, text=True,
            check=False, timeout=90,
        )
        log_parts.extend((compiled.stdout, compiled.stderr))
        receipt["compile_returncode"] = compiled.returncode
        if compiled.returncode != 0:
            raise RuntimeError("compile_failed")

        run_command = [str(executable)]
        receipt["test_command"] = run_command
        log_parts.append("$ " + subprocess.list2cmdline(run_command))
        tested = subprocess.run(
            run_command, cwd=CANDIDATE, capture_output=True, text=True,
            check=False, timeout=20,
        )
        log_parts.extend((tested.stdout, tested.stderr))
        receipt["test_returncode"] = tested.returncode
        receipt["test_stdout"] = tested.stdout
        receipt["test_stderr"] = tested.stderr
        if tested.returncode != 0:
            raise RuntimeError("unit_tests_failed")

        post_pins = [pin(path) for path in source_paths]
        if post_pins != source_pins:
            raise RuntimeError("source_changed_during_test")
        receipt["post_test_source_pins"] = post_pins
        receipt["executable"] = pin(executable)
        receipt["status"] = "passed"
    except Exception as exc:  # Preserve a failure record without retrying the test.
        receipt["failure"] = f"{type(exc).__name__}:{exc}"

    receipt["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    log_text = "\n".join(part.rstrip("\n") for part in log_parts) + "\n"
    try:
        write_exclusive(log_path, log_text)
        receipt["log"] = pin(log_path)
        write_exclusive(receipt_path, json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    except FileExistsError:
        print(json.dumps({"status": "refused", "reason": "output_exists_no_overwrite"}))
        return 2

    print(json.dumps({
        "status": receipt["status"],
        "receipt": receipt_path.relative_to(ROOT).as_posix(),
        "failure": receipt.get("failure"),
    }, ensure_ascii=False))
    return 0 if receipt["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-only", action="store_true", required=True)
    args = parser.parse_args()
    if not args.test_only:
        return 2
    return run_test_only()


if __name__ == "__main__":
    sys.exit(main())
