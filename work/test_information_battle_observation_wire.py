"""Compile, run, and strictly decode the pointer-free observation wire fixture.

The C++ executable is a self-owned synthetic test process.  It does not open
EU4, access a remote process, install a DLL, call REA, or invoke a game
function.  The Python half consumes the native encoder's emitted frame and
then exercises the decoder's rejection paths, including arbitrary raw bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.information_battle_observation_wire import (
    MAX_WIRE_BYTES,
    ObservationWireError,
    decode,
)


NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-observer-20261025-001" / "observation-wire-test-001"
HEADER = NATIVE / "information-battle-observation-wire.h"
CPP = NATIVE / "test-information-battle-observation-wire.cpp"
DECODER = ROOT / "work" / "information_battle_observation_wire.py"
SCRIPT = Path(__file__).resolve()
REPORT = STAGE / "report.json"
EXE = STAGE / "test-information-battle-observation-wire.exe"
COMPILE_STDOUT = STAGE / "compile.stdout.log"
COMPILE_STDERR = STAGE / "compile.stderr.log"
RUN_STDOUT = STAGE / "run.stdout.log"
RUN_STDERR = STAGE / "run.stderr.log"


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


def file_pin(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": relative(path), "status": "missing", "exists": False}
    size, digest = sha256_file(path)
    return {"path": relative(path), "status": "observed", "exists": True,
            "size_bytes": size, "sha256": digest}


def write_new_json(path: Path, value: dict[str, Any]) -> tuple[int, str]:
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{relative(path)}")
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("report_over_bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    return len(raw), hashlib.sha256(raw).hexdigest()


def _expect_reject(label: str, data: bytes) -> dict[str, Any]:
    try:
        decode(data)
    except ObservationWireError as exc:
        return {"label": label, "status": "rejected", "error": str(exc)}
    except Exception as exc:  # The decoder must expose its own bounded error.
        return {"label": label, "status": "wrong_exception", "error": f"{type(exc).__name__}:{exc}"}
    return {"label": label, "status": "accepted_unexpectedly"}


def run() -> dict[str, Any]:
    started = time.time()
    STAGE.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "information_battle_observation_wire_test_v1",
        "status": "blocked",
        "scope": {
            "game_access": False,
            "remote_process_access": False,
            "rea_access": False,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "production_modified": False,
            "self_owned_fixture_process_only": True,
        },
        "contract": {
            "namespace": "information::battle::observation",
            "reader_interface": "encode(const Observation&,unsigned char*,size_t) noexcept",
            "result_type": "EncodeResult{size_t written_bytes; bool succeeded() const noexcept;}",
            "magic_ascii": "IBOW",
            "version": 1,
            "max_wire_bytes": MAX_WIRE_BYTES,
            "header_bytes": 19,
            "little_endian_integers": True,
            "canonical_bool_values": [0, 1],
            "string_policy": "u32 length followed by actual bytes; no capacity, padding, or native pointer",
            "failure_output_unchanged": True,
            "sequence_and_thread_nonzero": True,
            "decoder_strict_trailing_bytes": True,
            "decoder_complete": False,
            "decoder_visibility_verified": False,
            "public_war_battle_identity": "absent",
        },
        "source_pins": {
            "wire_header": file_pin(HEADER),
            "native_test": file_pin(CPP),
            "decoder": file_pin(DECODER),
            "python_runner": file_pin(SCRIPT),
        },
        "compile": {},
        "run": {},
        "python_decode": {},
        "malformed_inputs": [],
    }

    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return report

    command = [
        compiler,
        "-std=c++17",
        "-fno-exceptions",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-O2",
        "-fstack-usage",
        "-I",
        str(NATIVE),
        str(CPP),
        "-o",
        str(EXE),
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90, check=False)
    compile_stdout = compiled.stdout.decode("utf-8", errors="replace")
    compile_stderr = compiled.stderr.decode("utf-8", errors="replace")
    COMPILE_STDOUT.write_text(compile_stdout, encoding="utf-8")
    COMPILE_STDERR.write_text(compile_stderr, encoding="utf-8")
    report["compile"] = {
        "command": command,
        "compiler": compiler,
        "returncode": compiled.returncode,
        "stdout": compile_stdout,
        "stderr": compile_stderr,
    }
    if compiled.returncode != 0 or not EXE.is_file():
        report["status"] = "failed_compile"
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return report

    run_result = subprocess.run([str(EXE)], cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=90, check=False)
    run_stdout = run_result.stdout.decode("utf-8", errors="replace")
    run_stderr = run_result.stderr.decode("utf-8", errors="replace")
    RUN_STDOUT.write_text(run_stdout, encoding="utf-8")
    RUN_STDERR.write_text(run_stderr, encoding="utf-8")
    wire_lines = [line for line in run_stdout.splitlines() if line.startswith("WIRE_HEX ")]
    result_line = next((line for line in run_stdout.splitlines() if line.startswith("RESULT ")), None)
    report["run"] = {
        "command": [str(EXE)],
        "returncode": run_result.returncode,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "result_line": result_line,
        "wire_line_count": len(wire_lines),
        "artifact": file_pin(EXE),
    }
    if run_result.returncode != 0 or result_line != "RESULT PASS" or len(wire_lines) != 1:
        report["status"] = "failed_native_fixture"
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return report

    wire_hex = wire_lines[0].split(" ", 1)[1].strip()
    try:
        wire = bytes.fromhex(wire_hex)
        decoded = decode(wire)
    except (ValueError, ObservationWireError) as exc:
        report["status"] = "failed_python_roundtrip"
        report["python_decode"] = {"status": "error", "error": f"{type(exc).__name__}:{exc}"}
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return report

    observation = decoded["observation"]
    result = observation["result"]
    sides = result["sides"]
    summary = observation["summary"]
    decode_checks = {
        "schema": decoded.get("schema") == "information_battle_observation_wire_v1",
        "wire_magic_version": decoded["wire"] == {"magic": "IBOW", "version": 1, "bytes": len(wire), "trailing_bytes": 0},
        "sequence_uint64_max": observation["sequence"] == (1 << 64) - 1,
        "thread_uint32_max": observation["thread"] == (1 << 32) - 1,
        "known_router_true": observation["known_router"] is True,
        "raw_date_signed_min": result["raw_date"] == -(1 << 31),
        "raw_name_non_utf8_bytes": result["name"] == {"length": 5, "raw_hex": "ff0080c328"},
        "full_country_u64": sides[1]["country"] == (1 << 64) - 1,
        "raw_side_i32s": sides[0]["raw_fields"][0] == -(1 << 31) and sides[0]["raw_fields"][1] == (1 << 31) - 1,
        "raw_summary_i32s": summary["raw_i32"][0] == -(1 << 31) and summary["raw_i32"][-1] == 80,
        "raw_summary_control": summary["control_byte"] == 0xfe,
        "capacity_omitted": "capacity" not in result["name"] and "capacity" not in sides[1]["commander"],
        "complete_false": decoded["complete"] is False,
        "visibility_false": decoded["visibility_verified"] is False,
        "public_identity_absent": decoded["public_identity"] == {"status": "absent", "war_id": None, "battle_id": None},
        "memoryview_decode": decode(memoryview(wire))["observation"] == observation,
    }
    report["python_decode"] = {
        "status": "passed" if all(decode_checks.values()) else "failed",
        "wire_bytes": len(wire),
        "wire_sha256": hashlib.sha256(wire).hexdigest(),
        "checks": decode_checks,
        "decoded": decoded,
    }

    bad_magic = bytearray(wire)
    bad_magic[0] ^= 0x01
    bad_version = bytearray(wire)
    bad_version[4] = 0x02
    bad_bool = bytearray(wire)
    bad_bool[18] = 0x02
    oversized_string = bytearray(wire)
    oversized_string[36:40] = (MAX_WIRE_BYTES + 1).to_bytes(4, "little")
    report["malformed_inputs"] = [
        _expect_reject("truncated_header", wire[:3]),
        _expect_reject("truncated_body", wire[:-1]),
        _expect_reject("bad_magic", bytes(bad_magic)),
        _expect_reject("unsupported_version", bytes(bad_version)),
        _expect_reject("noncanonical_bool", bytes(bad_bool)),
        _expect_reject("oversized_string", bytes(oversized_string)),
        _expect_reject("trailing_byte", wire + b"\x00"),
        _expect_reject("wire_over_bound", b"\x00" * (MAX_WIRE_BYTES + 1)),
    ]
    report["status"] = (
        "passed"
        if report["python_decode"]["status"] == "passed"
        and all(item["status"] == "rejected" for item in report["malformed_inputs"])
        else "failed_python_contract"
    )
    report["elapsed_seconds"] = time.time() - started
    write_new_json(REPORT, report)
    return report


def main() -> int:
    report = run()
    print(json.dumps({
        "status": report["status"],
        "report": relative(REPORT),
        "native_returncode": report.get("run", {}).get("returncode"),
        "wire_bytes": report.get("python_decode", {}).get("wire_bytes"),
    }, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
