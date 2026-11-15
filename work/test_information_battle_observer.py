"""Compile and exercise the real information-battle-observer include.

The native executable is a self-owned Windows fixture.  It includes
``information-battle-observer.inc`` in the same translation unit, installs its
real entry patch against a private 40 MiB ``VirtualAlloc`` region, and calls
only the fixture's native body.  The production fixed-EXE startup guard is
still exercised first and rejects the fixture hash.  No EU4 process, DLL
installation, REA/RPM call, or game function is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-observer-20261025-001" / "manager-test-001"
CPP = NATIVE / "test-information-battle-observer.cpp"
STUB = NATIVE / "information-battle-entry-stub.S"
INC = NATIVE / "information-battle-observer.inc"
DECODER = ROOT / "work" / "information_battle_observation_wire.py"
SCRIPT = Path(__file__).resolve()

DIRECT_SOURCES = (
    CPP,
    STUB,
    INC,
    NATIVE / "information-battle-entry-plan.h",
    NATIVE / "entry-patch-transaction.inc",
    NATIVE / "information-battle-observation-wire.h",
    NATIVE / "information-battle-drain.h",
    NATIVE / "information-battle-log-writer.h",
    NATIVE / "information-battle-fragment.h",
    NATIVE / "information-battle-buffer.h",
    NATIVE / "information-battle-wire.h",
    NATIVE / "information-battle-owned-result.h",
    NATIVE / "information-battle-owned-summary.h",
    DECODER,
    SCRIPT,
)


def sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def pin(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": relative(path), "status": "missing", "exists": False}
    size, digest = sha256_file(path)
    return {"path": relative(path), "status": "observed", "exists": True,
            "size_bytes": size, "sha256": digest}


def write_new(path: Path, value: dict[str, Any]) -> str:
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{relative(path)}")
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("report_over_bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def write_new_bytes(path: Path, raw: bytes) -> str:
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{relative(path)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()


def compiler_path() -> str | None:
    explicit = None
    if "EU4_CXX" in __import__("os").environ:
        explicit = __import__("os").environ["EU4_CXX"]
    return explicit or shutil.which("g++") or r"C:\Strawberry\c\bin\g++.exe"


def parse_native(stdout: str) -> tuple[dict[str, Any], str, str, Path | None]:
    encoded_line = next((line for line in stdout.splitlines()
                         if line.startswith("ENCODED_HEX ")), None)
    pointer_line = next((line for line in stdout.splitlines()
                         if line.startswith("SOURCE_POINTER_HEX ")), None)
    log_line = next((line for line in stdout.splitlines()
                     if line.startswith("LOG_PATH ")), None)
    result_line = next((line for line in stdout.splitlines()
                        if line.startswith("{") and line.endswith("}")), None)
    if encoded_line is None or pointer_line is None or result_line is None:
        raise RuntimeError("native fixture omitted encoded/result lines")
    result = json.loads(result_line)
    if not isinstance(result, dict):
        raise RuntimeError("native final result is not an object")
    encoded_hex = encoded_line.split(" ", 1)[1].strip()
    pointer_hex = pointer_line.split(" ", 1)[1].strip()
    log_path = Path(log_line.split(" ", 1)[1].strip()) if log_line else None
    return result, encoded_hex, pointer_hex, log_path


def decode_checks(encoded_hex: str, pointer_hex: str) -> dict[str, Any]:
    sys.path.insert(0, str(ROOT))
    from work.information_battle_observation_wire import decode

    wire = bytes.fromhex(encoded_hex)
    decoded = decode(wire)
    observation = decoded["observation"]
    result = observation["result"]
    sides = result["sides"]
    summary = observation["summary"]
    pointer_value = int(pointer_hex, 16)
    pointer_bytes = pointer_value.to_bytes(8, "little", signed=False)
    checks: dict[str, Any] = {
        "schema": decoded.get("schema") == "information_battle_observation_wire_v1",
        "wire_magic_version": decoded["wire"]["magic"] == "IBOW"
        and decoded["wire"]["version"] == 1
        and decoded["wire"]["trailing_bytes"] == 0,
        "first_captured_sequence": observation["sequence"] == 1,
        "thread_nonzero": observation["thread"] != 0,
        "known_router_false": observation["known_router"] is False,
        "raw_date": result["raw_date"] == 56553384,
        "raw_result_values": result["flag108"] == 1
        and result["aux100"] == -17 and result["aux104"] == 23
        and result["province_id"] == 1285,
        "raw_name": result["name"] == {
            "length": 21, "raw_hex": "73796e7468657469632d626174746c652d6e616d65"
        },
        "raw_side_countries": sides[0]["country"] == 0x465241
        and sides[1]["country"] == 0x454e47,
        "raw_side_fields": sides[0]["raw_fields"] == list(range(100, 109))
        and sides[1]["raw_fields"] == list(range(200, 209)),
        "raw_commanders": sides[0]["commander"] == {
            "length": 5, "raw_hex": "412d434d44"
        } and sides[1]["commander"] == {
            "length": 16, "raw_hex": "422d484541502d434f4d4d414e444552"
        },
        "raw_summary": summary["raw_i32"] == list(range(-300, -289))
        and summary["control_byte"] == 0xfe,
        "pointer_free_schema": "pointer" not in json.dumps(decoded)
        and pointer_bytes not in wire,
        "complete_false": decoded["complete"] is False,
        "visibility_false": decoded["visibility_verified"] is False,
        "public_identity_absent": decoded["public_identity"] == {
            "status": "absent", "war_id": None, "battle_id": None
        },
    }
    return {
        "status": "passed" if all(checks.values()) else "failed",
        "wire_bytes": len(wire),
        "wire_sha256": hashlib.sha256(wire).hexdigest(),
        "checks": checks,
        "decoded": decoded,
    }


def run(revision: int) -> tuple[int, dict[str, Any]]:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    suffix = f"-{revision:03d}"
    exe = STAGE / f"test-information-battle-observer-{revision:03d}.exe"
    compile_stdout_path = STAGE / f"compile{suffix}.stdout.log"
    compile_stderr_path = STAGE / f"compile{suffix}.stderr.log"
    run_stdout_path = STAGE / f"run{suffix}.stdout.log"
    run_stderr_path = STAGE / f"run{suffix}.stderr.log"
    report_path = STAGE / ("report.json" if revision == 1 else f"report-{revision:03d}.json")
    for path in (exe, compile_stdout_path, compile_stderr_path, run_stdout_path,
                 run_stderr_path, report_path):
        if path.exists():
            raise FileExistsError(f"refusing_to_overwrite:{relative(path)}")

    report: dict[str, Any] = {
        "schema": "information_battle_observer_manager_test_v1",
        "status": "blocked",
        "mode": "offline_synthetic_process",
        "scope": {
            "game_access": False,
            "remote_process_access": False,
            "rea_or_rpm": False,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "production_modified": False,
            "fixture_own_code_and_data_modified": True,
        },
        "contract": {
            "included_source": relative(INC),
            "fixture_region_bytes": 0x2800000,
            "fixed_entry_rva": hex(0x238620),
            "fixed_unwind_rva": hex(0x1DE6C98),
            "startup_hash_guard": "fixture EXE is intentionally rejected by kExeSha",
            "private_initialization_after_rejection": True,
            "capture_slots": 8,
            "disable_policy": "state only; published patch/trampoline/VEH/unwind retained",
            "resume_policy": "fixture-private state restoration; command enable remains guard-rejected",
            "wire_policy": "encoded pointer-free observation decoded by existing strict Python decoder",
        },
        "source_pins": {relative(path): pin(path) for path in DIRECT_SOURCES},
        "compile": {},
        "run": {},
        "wire_decode": {},
        "limitations": [
            "The real startup path cannot bind this synthetic EXE; its fixed SHA guard rejection is required and recorded.",
            "The private state initialization and source buffers are fixture-only and do not authorize production deployment.",
            "The test proves patch/capture/transport lifecycle against self-owned memory, not battle visibility, identity, or reentrancy in EU4.",
        ],
    }

    compiler = compiler_path()
    if not compiler or not Path(compiler).is_file():
        report["status"] = "blocked_missing_compiler"
        report["elapsed_seconds"] = time.time() - started
        digest = write_new(report_path, report)
        report["report_sha256"] = digest
        return 1, report

    command = [
        compiler, "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall",
        "-Wextra", "-Werror", "-O2", "-fstack-usage", "-static-libgcc",
        "-static-libstdc++", "-Wl,--no-insert-timestamp", "-I", str(NATIVE),
        "-o", str(exe), str(STUB), str(CPP), "-ladvapi32",
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=90, check=False)
    write_new_bytes(compile_stdout_path, compiled.stdout)
    write_new_bytes(compile_stderr_path, compiled.stderr)
    report["compile"] = {
        "command": command,
        "compiler": compiler,
        "returncode": compiled.returncode,
        "stdout": compiled.stdout.decode("utf-8", errors="replace"),
        "stderr": compiled.stderr.decode("utf-8", errors="replace"),
    }
    if compiled.returncode != 0 or not exe.is_file():
        report["status"] = "failed_compile"
        report["elapsed_seconds"] = time.time() - started
        write_new(report_path, report)
        return 1, report

    ran = subprocess.run([str(exe)], cwd=ROOT, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, timeout=90, check=False)
    write_new_bytes(run_stdout_path, ran.stdout)
    write_new_bytes(run_stderr_path, ran.stderr)
    stdout = ran.stdout.decode("utf-8", errors="replace")
    stderr = ran.stderr.decode("utf-8", errors="replace")
    report["run"] = {
        "command": [str(exe)],
        "returncode": ran.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "artifact": pin(exe),
    }
    try:
        native_result, encoded_hex, pointer_hex, log_path = parse_native(stdout)
    except (ValueError, RuntimeError, json.JSONDecodeError) as error:
        report["status"] = "failed_native_output"
        report["run"]["parse_error"] = f"{type(error).__name__}:{error}"
        report["elapsed_seconds"] = time.time() - started
        write_new(report_path, report)
        return 1, report
    report["run"]["result"] = native_result
    report["run"]["encoded_bytes_reported"] = len(encoded_hex) // 2
    report["run"]["source_pointer_hex"] = pointer_hex
    report["run"]["log_path"] = str(log_path) if log_path else None
    manager_checks = {
        "startup_hash_guard_rejected": native_result.get("startup_hash_guard_rejected") is True,
        "startup_leases_closed": native_result.get("startup_leases_closed") is True,
        "install_success": native_result.get("install_success") is True,
        "disable_retained_patch": native_result.get("disable_retained_patch") is True,
        "creation_generation": native_result.get("resume_sequence", 0) > 1,
        "date_regression": native_result.get("date_regression") is True,
        "source_changed_flush_preserved": native_result.get("source_changed_flush_preserved") is True,
        "disabled_flush_drained": native_result.get("disabled_flush_drained") is True,
        "terminal_quarantine": native_result.get("terminal_quarantine") is True,
        "terminal_disable_rejected": native_result.get("terminal_disable_rejected") is True,
        "nonce_receipt": native_result.get("nonce_receipt") is True,
        "final_response": native_result.get("final_response") is True,
        "unbound_disable_rejected": native_result.get("unbound_disable_rejected") is True,
        "unknown_nonce_rejected": native_result.get("unknown_nonce_rejected") is True,
        "duplicate_request": native_result.get("duplicate_request") is True,
        "wrong_player_rejected": native_result.get("wrong_player_rejected") is True,
        "status_fields": native_result.get("status_fields") is True,
        "terminal_latch": native_result.get("terminal_latch") is True,
        "sequence_exhaustion_fault": native_result.get("sequence_exhaustion_fault") is True,
        "writer_rejection_fault": native_result.get("writer_rejection_fault") is True,
        "checked_log_written": native_result.get("checked_log_written") is True,
        "copy_failure_count": native_result.get("copy_failures") == 2,
        "full_drop_count": native_result.get("full_drops", 0) >= 1,
        "foreign_thread_count": native_result.get("foreign_thread_drops") == 1,
        "native_body_count": native_result.get("native_body_calls") == 3,
        "fixture_scope": native_result.get("production_modified") is False
        and native_result.get("game_access") is False
        and native_result.get("fixture_private_initialization") is True,
    }
    report["manager_checks"] = {
        "status": "passed" if all(manager_checks.values()) else "failed",
        "checks": manager_checks,
    }
    if log_path and log_path.is_file():
        log_size = log_path.stat().st_size
        report["run"]["checked_log"] = {
            "status": "observed", "size_bytes": log_size,
            "bounded_read": False,
        }
    else:
        report["run"]["checked_log"] = {
            "status": "missing", "size_bytes": None,
            "bounded_read": False,
        }

    try:
        report["wire_decode"] = decode_checks(encoded_hex, pointer_hex)
    except Exception as error:  # decoder errors are recorded, not hidden
        report["wire_decode"] = {
            "status": "failed",
            "error": f"{type(error).__name__}:{error}",
        }
    native_ok = ran.returncode == 0 and native_result.get("passed") is True
    log_ok = bool(log_path and log_path.is_file() and log_path.stat().st_size > 0)
    report["status"] = (
        "passed"
        if native_ok and report["wire_decode"].get("status") == "passed"
        and log_ok and report["manager_checks"]["status"] == "passed"
        else "failed_contract"
    )
    report["elapsed_seconds"] = time.time() - started
    write_new(report_path, report)
    return (0 if report["status"] == "passed" else 1), report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", type=int, default=1)
    args = parser.parse_args(argv)
    if not 1 <= args.revision <= 999:
        parser.error("--revision must be between 1 and 999")
    try:
        code, report = run(args.revision)
    except (FileExistsError, OSError, RuntimeError, ValueError) as error:
        print(f"observer fixture runner failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps({
        "status": report["status"],
        "report": relative(STAGE / ("report.json" if args.revision == 1 else f"report-{args.revision:03d}.json")),
        "native_returncode": report.get("run", {}).get("returncode"),
        "wire_status": report.get("wire_decode", {}).get("status"),
    }, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
