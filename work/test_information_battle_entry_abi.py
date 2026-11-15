"""Build and run the offline natural-entry ABI fixture.

This runner only compiles the three task-owned native sources and executes the
resulting fixture process.  It does not inspect or attach to EU4, load an
installation, call REA/RPM, or modify the existing production entry stubs.
Each version is written with exclusive creation so a completed receipt cannot
be silently replaced by a later run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = (
    ROOT
    / "work"
    / "runtime"
    / "information-battle-entry-20261025-001"
    / "abi-test-001"
)
SOURCES = (
    ROOT / "work/native/information-battle-entry-stub.S",
    ROOT / "work/native/test-information-battle-entry-abi.cpp",
    ROOT / "work/native/test-information-battle-entry-abi.S",
)
FLAGS = (
    "-std=c++17",
    "-O2",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-fno-exceptions",
    "-fno-rtti",
    "-static-libgcc",
    "-static-libstdc++",
    "-Wl,--no-insert-timestamp",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def exclusive_path(path: Path) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing artifact: {path}")


def write_exclusive(path: Path, data: bytes) -> None:
    exclusive_path(path)
    with path.open("xb") as stream:
        stream.write(data)


def require_sources() -> None:
    for path in SOURCES:
        if not path.is_file():
            raise FileNotFoundError(path)


def compiler_path(argument: str | None) -> Path:
    if argument:
        path = Path(argument)
    else:
        path = Path(os.environ.get("EU4_CXX", r"C:\Strawberry\c\bin\g++.exe"))
    if not path.is_file():
        raise FileNotFoundError(f"C++ compiler not found: {path}")
    return path


def decode_output(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def parse_result(stdout: bytes) -> dict[str, Any]:
    lines = [line for line in decode_output(stdout).splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("fixture produced no JSON result")
    try:
        result = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise RuntimeError("fixture final output is not JSON") from error
    if not isinstance(result, dict):
        raise RuntimeError("fixture JSON result is not an object")
    expected = {
        "passed": True,
        "cases": 4,
        "nested_cases": 2,
        "original_pointer_published": True,
        "callback_is_observer_only": True,
    }
    for key, value in expected.items():
        if result.get(key) != value:
            raise RuntimeError(f"fixture result mismatch for {key}: {result!r}")
    return result


def build_and_run(output: Path, version: int, compiler: Path) -> dict[str, Any]:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    require_sources()
    executable = output / f"information-battle-entry-abi-{version:03d}.exe"
    compile_stdout = output / f"compile-{version:03d}.stdout.txt"
    compile_stderr = output / f"compile-{version:03d}.stderr.txt"
    run_stdout = output / f"run-{version:03d}.stdout.txt"
    run_stderr = output / f"run-{version:03d}.stderr.txt"
    report_path = output / f"report-{version:03d}.json"
    for path in (executable, compile_stdout, compile_stderr, run_stdout,
                 run_stderr, report_path):
        exclusive_path(path)

    command = [
        str(compiler),
        *FLAGS,
        "-o",
        str(executable),
        *(str(path) for path in SOURCES),
    ]
    compiled = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    write_exclusive(compile_stdout, compiled.stdout)
    write_exclusive(compile_stderr, compiled.stderr)
    if compiled.returncode != 0 or not executable.is_file():
        raise RuntimeError(f"native fixture compilation failed: {compiled.returncode}")

    ran = subprocess.run(
        [str(executable)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    write_exclusive(run_stdout, ran.stdout)
    write_exclusive(run_stderr, ran.stderr)
    result = parse_result(ran.stdout)
    if ran.returncode != 0:
        raise RuntimeError(f"native fixture returned {ran.returncode}")

    source_pins = {
        str(path.relative_to(ROOT)).replace("\\", "/"): {
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in (*SOURCES, Path(__file__).resolve())
    }
    report: dict[str, Any] = {
        "schema": "INFORMATION-BATTLE-ENTRY-ABI-FIXTURE/2",
        "status": "passed",
        "mode": "offline_fixture",
        "read_only": True,
        "game_access": False,
        "rea_or_rpm": False,
        "compiler": {
            "path": str(compiler),
            "flags": list(FLAGS),
        },
        "sources": source_pins,
        "artifact": {
            "path": str(executable.relative_to(ROOT)).replace("\\", "/"),
            "size_bytes": executable.stat().st_size,
            "sha256": sha256(executable),
        },
        "compile_receipt": {
            "returncode": compiled.returncode,
            "stdout_sha256": sha256(compile_stdout),
            "stderr_sha256": sha256(compile_stderr),
        },
        "run_receipt": {
            "returncode": ran.returncode,
            "stdout_sha256": sha256(run_stdout),
            "stderr_sha256": sha256(run_stderr),
            "result": result,
        },
        "contract": {
            "capture_arguments": [
                "combat",
                "summary",
                "result",
                "original_caller_return",
                "original_rbx",
            ],
            "callback_noexcept": True,
            "callback_is_observer_only": True,
            "stub_direct_original_call_count": 0,
            "original_target_invocations_per_case": {
                "non_nested": 1,
                "nested": 2,
            },
            "tail_jump_to_published_original": True,
            "original_pointer_immutable_after_publish": "caller_contract",
            "original_return_address_and_stack_arguments_untouched": True,
            "preserved_state": [
                "RFLAGS",
                "RAX/RCX/RDX/R8/R9/R10/R11",
                "XMM0-XMM5",
                "MXCSR",
                "x87_control_word",
                "GetLastError",
            ],
            "xmm_width_checked_bits": 128,
            "stack_contract": {
                "shadow_space_bytes": 32,
                "stub_frame_bytes_before_tail_jump": "0x1e8",
                "callback_rsp_mod16": 0,
                "original_entry_rsp_mod16": 8,
            },
            "unwind_metadata_verified": True,
            "unwind_boundary_points": [
                "entry",
                "after_pushfq",
                "after_sub",
                "before_callback_call",
                "before_add",
                "after_add_before_popfq",
                "after_popfq_before_jmp",
            ],
            "unwind_runtime_ranges": [
                {
                    "name": "main_frame",
                    "stack_model": "full_0x1e8_frame",
                    "covers": "entry_through_add_instruction",
                },
                {
                    "name": "restore_flags",
                    "stack_model": "remaining_8_byte_flags_slot",
                    "covers": "after_add_through_popfq",
                },
                {
                    "name": "tail_jump",
                    "stack_model": "caller_rsp_no_frame",
                    "covers": "after_popfq_through_jmp",
                },
            ],
            "direct_and_indirect_entry_tested": True,
            "nested_reentry_fixture_tested": True,
            "nested_reentry_proof_scope": "fixture_only_no_queue_or_production_guard",
        },
        "limitations": [
            "The callback and original are fixture functions, not EU4 code.",
            "No game process, injection, RPM, REA, or production frame stub was used.",
            "A callback may re-enter in this fixture; this does not prove a production reentry policy.",
            "The published original pointer must remain non-null and immutable for the caller lifetime.",
            "The fifth original_rbx value is an observed register argument, not a war or battle identity.",
        ],
    }
    write_exclusive(report_path, (json.dumps(report, indent=2) + "\n").encode())
    return {
        "report": str(report_path.relative_to(ROOT)).replace("\\", "/"),
        "executable": str(executable.relative_to(ROOT)).replace("\\", "/"),
        "report_sha256": sha256(report_path),
        "executable_sha256": report["artifact"]["sha256"],
        "result": result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--version", type=int, default=2)
    parser.add_argument("--compiler", type=str, default=None)
    args = parser.parse_args(argv)
    if not 1 <= args.version <= 999:
        parser.error("--version must be between 1 and 999")
    try:
        receipt = build_and_run(args.output_dir, args.version,
                                compiler_path(args.compiler))
    except (FileExistsError, FileNotFoundError, RuntimeError, OSError) as error:
        print(f"abi fixture runner failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
