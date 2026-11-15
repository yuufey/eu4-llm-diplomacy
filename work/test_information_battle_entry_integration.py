"""Build and run the offline natural-entry integration fixture.

The executable combines the repository's entry plan, patch transaction,
three-range observation stub, and owned-result copier against only private
VirtualAlloc buffers.  It never attaches to EU4, loads an installation, calls
REA/RPM, or invokes a game/native function.  Every output artifact is created
exclusively so a later run cannot silently replace a receipt.
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
    / "integration-test-001"
)

NATIVE_SOURCE = ROOT / "work/native/test-information-battle-entry-integration.cpp"
STUB_SOURCE = ROOT / "work/native/information-battle-entry-stub.S"
HEADER_SOURCES = (
    ROOT / "work/native/information-battle-entry-plan.h",
    ROOT / "work/native/entry-patch-transaction.inc",
    ROOT / "work/native/information-battle-owned-result.h",
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


def exclusive(path: Path) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing artifact: {path}")


def write_exclusive(path: Path, data: bytes) -> None:
    exclusive(path)
    with path.open("xb") as stream:
        stream.write(data)


def compiler_path(argument: str | None) -> Path:
    path = Path(argument) if argument else Path(
        os.environ.get("EU4_CXX", r"C:\Strawberry\c\bin\g++.exe")
    )
    if not path.is_file():
        raise FileNotFoundError(f"C++ compiler not found: {path}")
    return path


def require_inputs() -> None:
    for path in (NATIVE_SOURCE, STUB_SOURCE, *HEADER_SOURCES):
        if not path.is_file():
            raise FileNotFoundError(path)


def parse_result(stdout: bytes) -> dict[str, Any]:
    lines = [line for line in stdout.decode("utf-8", errors="replace").splitlines()
             if line.strip()]
    if not lines:
        raise RuntimeError("fixture produced no JSON result")
    try:
        result = json.loads(lines[-1])
    except json.JSONDecodeError as error:
        raise RuntimeError("fixture final output is not JSON") from error
    if not isinstance(result, dict):
        raise RuntimeError("fixture final output is not an object")
    expected = {
        "passed": True,
        "cases": 5,
        "install_success": True,
        "uninstall_success": True,
        "callback_count": 3,
        "body_count": 5,
        "copy_failures": 1,
        "snapshot_retained": True,
        "bytes_restored": True,
        "unwind_tables_registered": True,
        "published_original_immutable": True,
        "callback_caller_return_nonzero": True,
        "callback_original_rbx_nonzero": True,
        "native_body_is_fixture": True,
    }
    for key, value in expected.items():
        if result.get(key) != value:
            raise RuntimeError(f"fixture result mismatch for {key}: {result!r}")
    return result


def build_and_run(output: Path, version: int, compiler: Path) -> dict[str, Any]:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    require_inputs()
    executable = output / f"information-battle-entry-integration-{version:03d}.exe"
    compile_stdout = output / f"compile-{version:03d}.stdout.txt"
    compile_stderr = output / f"compile-{version:03d}.stderr.txt"
    run_stdout = output / f"run-{version:03d}.stdout.txt"
    run_stderr = output / f"run-{version:03d}.stderr.txt"
    report_path = output / f"report-{version:03d}.json"
    for path in (executable, compile_stdout, compile_stderr, run_stdout,
                 run_stderr, report_path):
        exclusive(path)

    command = [
        str(compiler), *FLAGS, "-o", str(executable), str(STUB_SOURCE),
        str(NATIVE_SOURCE),
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

    pin_paths = (NATIVE_SOURCE, STUB_SOURCE, *HEADER_SOURCES,
                 Path(__file__).resolve())
    source_pins = {
        str(path.relative_to(ROOT)).replace("\\", "/"): {
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for path in pin_paths
    }
    report: dict[str, Any] = {
        "schema": "INFORMATION-BATTLE-ENTRY-INTEGRATION-FIXTURE/1",
        "status": "passed",
        "mode": "offline_synthetic_process",
        "read_only": False,
        "game_access": False,
        "target_game_memory_writes": False,
        "owned_fixture_code_patch": True,
        "owned_fixture_data_mutated": True,
        "rea_or_rpm": False,
        "compiler": {"path": str(compiler), "flags": list(FLAGS)},
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
            "source_prefix_bytes": 36,
            "source_body_offset": 36,
            "source_body": "movabs_rax_native_body_call_rax_then_original_epilogue",
            "source_stack_contract": {
                "saved_push_count": 7,
                "allocation_bytes": "0x5a0",
                "call_rsp_mod16": 0,
                "callee_shadow_space_bytes": 32,
            },
            "patch_target": {
                "size": 21,
                "expected": "entry.kOriginalPrologue[0:21]",
                "replacement": "entry.Plan.patch",
                "original_trampoline": {
                    "code_bytes": 41,
                    "image_bytes": 96,
                    "source": "entry.Plan.image",
                },
            },
            "real_transaction": [
                "guarded_patch_apply",
                "private_source_call_direct",
                "private_source_call_indirect",
                "guarded_patch_rollback",
                "private_source_call_after_rollback",
            ],
            "owned_result_capture": {
                "reader": "bounded_private_region_only",
                "module_base": "0x140000000_synthetic_only",
                "copy_is_self_contained": True,
                "source_mutated_after_callback": True,
                "copy_failure_does_not_block_original": True,
            },
            "dynamic_unwind_tables": {
                "source": "original_11_code_no_handler_copy",
                "trampoline": "entry.Plan.projected_unwind",
                "separate_rx_allocations": True,
                "lookup_verified": True,
                "published_lifetime": "process_lifetime; OS reclaims at fixture exit",
            },
            "published_original_pointer": "immutable_after_publish",
            "callback_is_observer_only": True,
            "native_body_calls_per_source_call": 1,
            "lasterror_restored": True,
        },
        "limitations": [
            "All code and result objects are synthetic private-process buffers.",
            "The fixture writes its own code/data buffers and calls its own native body plus OS APIs; no game-native function was called.",
            "No game process, installation, injection, RPM, or REA was used.",
            "The transaction's published VEH/table/trampoline are intentionally not freed before process exit.",
            "The callback and native body do not prove production battle identity, visibility, or reentry policy.",
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
    parser.add_argument("--version", type=int, default=1)
    parser.add_argument("--compiler", type=str, default=None)
    args = parser.parse_args(argv)
    if not 1 <= args.version <= 999:
        parser.error("--version must be between 1 and 999")
    try:
        receipt = build_and_run(args.output_dir, args.version,
                                compiler_path(args.compiler))
    except (FileExistsError, FileNotFoundError, RuntimeError, OSError) as error:
        print(f"integration fixture runner failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

