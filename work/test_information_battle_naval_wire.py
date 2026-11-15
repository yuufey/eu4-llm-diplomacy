"""Compile and validate the synthetic version-3 naval wire.

This runner uses only self-owned value fixtures.  It does not access EU4,
remote memory, REA, a DLL, or game functions.  It checks native encoding,
strict Python decoding, unchanged v2 compatibility, and malformed-frame
rejection without adding a business interpretation to raw naval fields.
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
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.information_battle_naval_wire import (  # noqa: E402
    BASE_VERSION,
    EXTENSION_MAGIC,
    EXTENSION_VERSION,
    MAX_ROWS,
    MAX_WIRE_BYTES,
    NavalWireError,
    decode,
)

NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-naval-losses-20261026-001" / "naval-wire-test-001"
HEADER = NATIVE / "information-battle-naval-wire.h"
OWNED_NAVAL = NATIVE / "information-battle-owned-naval.h"
CPP = NATIVE / "tests" / "information-battle-naval-wire-test.cpp"
PY_MODULE = ROOT / "work" / "information_battle_naval_wire.py"
PY_TEST = Path(__file__).resolve()
V2_HEADER = NATIVE / "information-battle-context-wire.h"
V2_MODULE = ROOT / "work" / "information_battle_context_wire.py"
CPP_EXE = STAGE / "test-information-battle-naval-wire.exe"
REPORT = STAGE / "report.json"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def file_pin(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def parse_wires(stdout: bytes) -> dict[str, bytes]:
    wires: dict[str, bytes] = {}
    for line in stdout.decode("ascii", errors="strict").splitlines():
        if not line.startswith("WIRE "):
            continue
        fields = line.split(" ", 2)
        if len(fields) != 3 or fields[1] in wires:
            raise ValueError("invalid_or_duplicate_wire_line")
        try:
            wires[fields[1]] = bytes.fromhex(fields[2])
        except ValueError as exc:
            raise ValueError("wire_hex_invalid") from exc
    expected = {"absent", "base_v2", "naval", "maximum"}
    if set(wires) != expected:
        raise ValueError(f"wire_cases_mismatch:{sorted(wires)}")
    return wires


def expect_error(function: Callable[[], Any], label: str,
                 checks: list[str], failures: list[str]) -> None:
    try:
        function()
    except NavalWireError:
        checks.append(label)
    except Exception as exc:  # pragma: no cover - diagnostic path
        failures.append(f"{label}:unexpected_{type(exc).__name__}")
    else:
        failures.append(label)


def _mutate(frame: bytes, start: int, payload: bytes) -> bytes:
    result = bytearray(frame)
    if start < 0 or start + len(payload) > len(result):
        raise ValueError("mutation_out_of_bounds")
    result[start:start + len(payload)] = payload
    return bytes(result)


def _u32(data: bytes, start: int) -> int:
    return int.from_bytes(data[start:start + 4], "little", signed=False)


def _v3_offsets(frame: bytes) -> dict[str, int]:
    base_bytes = _u32(frame, 6)
    base_start = 10
    base_end = base_start + base_bytes
    marker = base_end
    inner_length = _u32(frame, base_start + 6)
    context_marker = base_start + 10 + inner_length
    extension_magic = marker + 1
    extension_version = extension_magic + 4
    extension_bytes = extension_version + 2
    row_count = extension_bytes + 4 + 0  # body starts after the length field
    return {
        "base_start": base_start,
        "base_end": base_end,
        "naval_present": marker,
        "extension_magic": extension_magic,
        "extension_version": extension_version,
        "extension_bytes": extension_bytes,
        "extension_body": extension_bytes + 4,
        "row_count": row_count,
        "base_context_marker": context_marker,
        "base_raw_selector": context_marker + 2,
        "base_selector_code": context_marker + 6,
        "base_kind": context_marker + 13,
    }


def decoder_checks(wires: dict[str, bytes]) -> dict[str, Any]:
    checks: list[str] = []
    failures: list[str] = []
    absent = wires["absent"]
    base_v2 = wires["base_v2"]
    naval = wires["naval"]
    maximum = wires["maximum"]

    decoded_v2 = decode(base_v2)
    if (decoded_v2.get("schema") == "information_battle_context_wire_v2"
            and decoded_v2.get("wire", {}).get("version") == BASE_VERSION
            and "naval" not in decoded_v2):
        checks.append("direct_v2_decode_preserves_old_root")
    else:
        failures.append("direct_v2_decode_preserves_old_root")

    decoded_absent = decode(absent)
    if (decoded_absent["schema"] == "information_battle_naval_wire_v3"
            and decoded_absent["wire"]["version"] == 3
            and decoded_absent["naval"] is None
            and decoded_absent["wire"]["naval_present"] is False
            and decoded_absent["wire"]["bytes"] == len(absent)):
        checks.append("v3_absent_eof_roundtrip")
    else:
        failures.append("v3_absent_eof_roundtrip")

    decoded_naval = decode(naval)
    expected_types = [-500, -497, -494]
    expected_sides = [
        {"raw_loss_i32": [-200, -99, 2, 103], "raw_gate": 0x80},
        {"raw_loss_i32": [9800, 9901, 10002, 10103], "raw_gate": 0x81},
    ]
    if (decoded_naval["wire"]["version"] == 3
            and decoded_naval["wire"]["extension_version"] == EXTENSION_VERSION
            and decoded_naval["naval"] == {
                "row_types": expected_types,
                "sides": expected_sides,
            }
            and decoded_naval["context_present"] is True
            and decoded_naval["context"]["kind"] == 2):
        checks.append("v3_naval_raw_values_roundtrip")
    else:
        failures.append("v3_naval_raw_values_roundtrip")

    maximum_value = decode(maximum)
    maximum_rows = maximum_value.get("naval", {}).get("row_types", [])
    if (len(maximum_rows) == MAX_ROWS
            and maximum_rows[0] == -500
            and maximum_rows[-1] == -500 + 3 * (MAX_ROWS - 1)
            and maximum_value["wire"]["extension_bytes"]
            == 4 + 4 * MAX_ROWS + 2 * (16 + 1)):
        checks.append("v3_maximum_256_rows")
    else:
        failures.append("v3_maximum_256_rows")

    offsets = _v3_offsets(naval)
    expect_error(lambda: decode(naval + b"\x00"),
                 "v3_trailing_bytes_rejected", checks, failures)
    expect_error(lambda: decode(_mutate(naval, offsets["naval_present"], b"\x02")),
                 "v3_noncanonical_present_rejected", checks, failures)
    expect_error(lambda: decode(naval[: -1]),
                 "v3_truncated_extension_rejected", checks, failures)
    expect_error(lambda: decode(_mutate(naval, offsets["extension_magic"], b"NOPE")),
                 "v3_extension_magic_rejected", checks, failures)
    expect_error(lambda: decode(_mutate(naval, offsets["extension_version"], b"\x02\x00")),
                 "v3_extension_version_rejected", checks, failures)
    wrong_length = (_u32(naval, offsets["extension_bytes"]) + 1).to_bytes(4, "little")
    expect_error(lambda: decode(_mutate(naval, offsets["extension_bytes"], wrong_length)),
                 "v3_extension_length_rejected", checks, failures)
    over_rows = (MAX_ROWS + 1).to_bytes(4, "little")
    expect_error(lambda: decode(_mutate(naval, offsets["row_count"], over_rows)),
                 "v3_row_count_rejected", checks, failures)

    # The base must be exactly v2; a nested v3 frame is rejected by the v2
    # decoder rather than recursively consumed.
    nested = bytearray(b"IBOW")
    nested.extend((3).to_bytes(2, "little"))
    nested.extend(len(naval).to_bytes(4, "little"))
    nested.extend(naval)
    nested.append(0)
    expect_error(lambda: decode(bytes(nested)),
                 "v3_nested_v3_base_rejected", checks, failures)

    # Convert a valid naval v2 base to a valid land base while keeping the
    # extension.  The v3 decoder must reject the naval block on a land base.
    land = bytearray(naval)
    base_start = offsets["base_start"]
    land[offsets["base_raw_selector"]] = 1
    land[offsets["base_raw_selector"] + 1:offsets["base_raw_selector"] + 4] = b"\x00\x00\x00"
    land[offsets["base_selector_code"]:offsets["base_selector_code"] + 6] = (
        b"\xb8\x01\x00\x00\x00\xc3"
    )
    land[offsets["base_kind"]] = 1
    expect_error(lambda: decode(bytes(land)),
                 "v3_land_base_with_naval_rejected", checks, failures)

    # A v2 compatibility error is exposed as the new common exception type.
    expect_error(lambda: decode(_mutate(base_v2, 0, b"NOPE")),
                 "v2_error_wrapped_as_naval_error", checks, failures)
    expect_error(lambda: decode(b"X" * (MAX_WIRE_BYTES + 1)),
                 "v3_wire_budget_rejected", checks, failures)

    return {
        "reported": len(checks) + len(failures),
        "passed": len(checks),
        "failed": len(failures),
        "labels": checks,
        "failures": failures,
        "wire_bytes": {name: len(value) for name, value in wires.items()},
        "wire_sha256": {name: sha256_bytes(value) for name, value in wires.items()},
    }


def run(output: Path | None = None) -> dict[str, Any]:
    started = time.time()
    report_path = (output or REPORT).resolve()
    stage = report_path.parent
    stage.mkdir(parents=True, exist_ok=True)
    compile_stdout = stage / "compile.stdout.log"
    compile_stderr = stage / "compile.stderr.log"
    run_stdout = stage / "run.stdout.log"
    run_stderr = stage / "run.stderr.log"
    report: dict[str, Any] = {
        "schema": "information_battle_naval_wire_test_v1",
        "status": "blocked",
        "scope": {
            "synthetic_owned_values_only": True,
            "game_access": False,
            "remote_process_access": False,
            "rea_access": False,
            "rpm_access": False,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "business_complete_claimed": False,
        },
        "contract": {
            "magic": "IBOW",
            "version": 3,
            "base": "complete unchanged version-2 context wire only",
            "extension_magic": "NAVL",
            "extension_version": 1,
            "max_wire_bytes": MAX_WIRE_BYTES,
            "max_rows": MAX_ROWS,
            "little_endian_no_padding": True,
            "absent_requires_eof": True,
            "present_requires_complete_naval_context": True,
            "initial_lanes_reused_from_base_v1": True,
            "business_semantics": "none",
        },
        "source_pins": {},
        "compile": {},
        "run": {},
        "native_checks": {},
        "decoder_checks": {},
        "limitations": [
            "The NAVL block preserves raw loss/gate/row type values only; it does not assign ship classes, country roles, units, visibility, or remaining business semantics.",
            "The executable and all inputs are self-owned memory fixtures; no EU4 process, game function, REA, RPM, DLL, or production bridge is accessed.",
            "The base v1/v2 encoders and decoders are unchanged; v3 accepts only a complete v2 base and never recursively consumes a v3 base.",
        ],
    }
    pins = [HEADER, OWNED_NAVAL, CPP, PY_MODULE, PY_TEST, V2_HEADER, V2_MODULE]
    missing = [path for path in pins if not path.is_file()]
    if missing:
        report["status"] = "blocked_missing_source"
        report["missing_sources"] = [path.relative_to(ROOT).as_posix() for path in missing]
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    report["source_pins"] = {
        path.relative_to(ROOT).as_posix(): file_pin(path) for path in pins
    }
    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    command = [
        compiler, "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra",
        "-Werror", "-O2", "-fstack-usage", "-I", str(NATIVE), str(CPP), "-o", str(CPP_EXE),
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=90, check=False)
    compile_stdout.write_bytes(compiled.stdout)
    compile_stderr.write_bytes(compiled.stderr)
    report["compile"] = {
        "command": command,
        "returncode": compiled.returncode,
        "stdout_sha256": sha256_bytes(compiled.stdout),
        "stderr_sha256": sha256_bytes(compiled.stderr),
    }
    if compiled.returncode != 0:
        report["status"] = "compile_failed"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    native_run = subprocess.run([str(CPP_EXE)], cwd=ROOT,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, check=False)
    run_stdout.write_bytes(native_run.stdout)
    run_stderr.write_bytes(native_run.stderr)
    report["run"] = {
        "returncode": native_run.returncode,
        "stdout_sha256": sha256_bytes(native_run.stdout),
        "stderr_sha256": sha256_bytes(native_run.stderr),
        "stdout_bytes": len(native_run.stdout),
        "stderr_bytes": len(native_run.stderr),
    }
    native_lines = [
        line for line in native_run.stdout.decode("ascii", errors="replace").splitlines()
        if line.startswith("CHECK ")
    ]
    native_passed = [line[6:-5] for line in native_lines if line.endswith(" PASS")]
    native_failed = [line[6:-5] for line in native_lines if line.endswith(" FAIL")]
    report["native_checks"] = {
        "reported": len(native_lines),
        "passed": len(native_passed),
        "failed": len(native_failed),
        "labels": native_passed,
        "failures": native_failed,
    }
    if native_run.returncode != 0:
        report["status"] = "native_test_failed"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    try:
        wires = parse_wires(native_run.stdout)
        report["decoder_checks"] = decoder_checks(wires)
    except Exception as exc:  # preserve a typed failed report
        report["decoder_checks"] = {
            "reported": 0,
            "passed": 0,
            "failed": 1,
            "failures": [f"runner:{type(exc).__name__}:{exc}"],
        }
    report["executable"] = file_pin(CPP_EXE)
    report["status"] = "passed" if (
        report["native_checks"].get("failed", 1) == 0
        and report["native_checks"].get("reported", 0) > 0
        and report["decoder_checks"].get("failed", 1) == 0
        and report["decoder_checks"].get("passed", 0) > 0
    ) else "failed"
    report["elapsed_seconds"] = time.time() - started
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true",
                        help="compile and run the synthetic native fixture")
    parser.add_argument("--output", type=Path, default=REPORT,
                        help="独立报告路径；其父目录也承载本次exe和日志")
    args = parser.parse_args()
    if not args.run:
        print("naval-wire source ready; use --run after owned-naval.h is frozen")
        raise SystemExit(0)
    result = run(args.output)
    print(json.dumps({
        "status": result.get("status"),
        "report": str(args.output),
        "native": result.get("native_checks"),
        "decoder": result.get("decoder_checks"),
    }, ensure_ascii=False))
    raise SystemExit(0 if result.get("status") == "passed" else 1)
