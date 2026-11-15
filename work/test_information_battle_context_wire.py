"""Build and validate the synthetic version-2 IBOW context envelope.

The executable and all inputs are self-owned memory fixtures.  This runner
does not open EU4, access a remote process, call REA/RPM, install a DLL, or
invoke a game function.  It intentionally leaves the report ungenerated
until the context header is frozen by the owning integration task.
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
from work.information_battle_context_wire import ContextWireError

NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-context-wire-20261025-001" / "context-wire-test-001"
HEADER = NATIVE / "information-battle-context-wire.h"
CPP = NATIVE / "test-information-battle-context-wire.cpp"
PY_MODULE = ROOT / "work" / "information_battle_context_wire.py"
PY_TEST = Path(__file__).resolve()
V1_HEADER = NATIVE / "information-battle-observation-wire.h"
CONTEXT_HEADER = NATIVE / "information-battle-owned-context.h"
V1_DECODER = ROOT / "work" / "information_battle_observation_wire.py"
REPORT = STAGE / "report.json"
EXE = STAGE / "test-information-battle-context-wire.exe"
COMPILE_STDOUT = STAGE / "compile.stdout.log"
COMPILE_STDERR = STAGE / "compile.stderr.log"
RUN_STDOUT = STAGE / "run.stdout.log"
RUN_STDERR = STAGE / "run.stderr.log"


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


def expect_error(function: Callable[[], Any], label: str,
                 failures: list[str], checks: list[str]) -> None:
    try:
        function()
    except ContextWireError:
        checks.append(label)
    except Exception as exc:
        failures.append(f"{label}:unexpected_{type(exc).__name__}")
    else:
        failures.append(label)


_REF_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _expected_ref(index: int, opaque: bool = False) -> int:
    alphabet_size = len(_REF_ALPHABET)
    value = (
        _REF_ALPHABET[index % alphabet_size]
        | (_REF_ALPHABET[(index // alphabet_size) % alphabet_size] << 8)
        | (_REF_ALPHABET[(index // (alphabet_size * alphabet_size)) % alphabet_size]
           << 16)
        | ((index & 0xFF) << 32)
        | 0x0100000000000000
    )
    if opaque:
        value |= (0x5A << 24) | (0x02 << 56)
    return value


def _expected_inner() -> dict[str, Any]:
    return {
        "sequence": 0x1122334455667788,
        "thread": 0x12345678,
        "known_router": True,
        "result": {
            "raw_date": -1455113,
            "flag108": 0xA5,
            "aux100": -123456,
            "aux104": 654321,
            "province_id": 1275,
            "name": {"length": 5, "raw_hex": "426174746c"},
            "sides": [
                {
                    "country": _expected_ref(0),
                    "country_raw_hex": f"{_expected_ref(0):016x}",
                    "raw_fields": list(range(9)),
                    "commander": {"length": 0, "raw_hex": ""},
                },
                {
                    "country": _expected_ref(1),
                    "country_raw_hex": f"{_expected_ref(1):016x}",
                    "raw_fields": [100 + index for index in range(9)],
                    "commander": {"length": 0, "raw_hex": ""},
                },
            ],
        },
        "summary": {
            "raw_i32": [index * 7 - 30 for index in range(11)],
            "control_byte": 0x5A,
        },
    }


def _expected_context() -> dict[str, Any]:
    return {
        "known_router": True,
        "raw_selector": 1,
        "selector_code_hex": "b801000000c3",
        "selector_code_verified": True,
        "kind": 1,
        "physical_player_full_ref": _expected_ref(0, opaque=True),
        "sides": [
            {
                "present": True,
                "participants": {
                    "complete": True,
                    "count": 2,
                    "full_refs": [_expected_ref(0, opaque=True), _expected_ref(1)],
                },
                "raw_fields": [100, 101, 102, 103, 104, 105],
            },
            {
                "present": True,
                "participants": {
                    "complete": True,
                    "count": 1,
                    "full_refs": [_expected_ref(2)],
                },
                "raw_fields": [-200, -201, -202, -203, -204, -205],
            },
        ],
        "war_context_status": 1,
        "war_members": {
            "side_a_count": 2,
            "side_a_full_refs": [_expected_ref(0, opaque=True), _expected_ref(1)],
            "side_b_count": 1,
            "side_b_full_refs": [_expected_ref(2)],
            "vectors_complete": True,
            "physical_player_membership_known": True,
            "physical_player_is_war_member": True,
        },
    }


def _offsets(frame: bytes) -> dict[str, int]:
    """Return offsets for the fixed observed fixture without parsing semantics."""
    inner_length = int.from_bytes(frame[6:10], "little")
    cursor = 10 + inner_length
    result = {"context_present": cursor}
    if frame[cursor] != 1:
        return result
    result["known_router"] = cursor + 1
    result["raw_selector"] = cursor + 2
    result["selector_code"] = cursor + 6
    result["selector_verified"] = cursor + 12
    result["kind"] = cursor + 13
    result["physical_ref"] = cursor + 14
    cursor += 22
    for side in (0, 1):
        result[f"side{side}_present"] = cursor
        result[f"side{side}_complete"] = cursor + 1
        count = int.from_bytes(frame[cursor + 2:cursor + 6], "little")
        result[f"side{side}_count"] = cursor + 2
        result[f"side{side}_refs"] = cursor + 6
        cursor += 6 + count * 8 + 24
    result["war_status"] = cursor
    if frame[cursor] == 1:
        result["war_side_a_count"] = cursor + 1
        side_a_count = int.from_bytes(frame[cursor + 1:cursor + 5], "little")
        cursor += 5 + side_a_count * 8
        result["war_side_b_count"] = cursor
        side_b_count = int.from_bytes(frame[cursor:cursor + 4], "little")
        cursor += 4 + side_b_count * 8
        result["war_vectors_complete"] = cursor
        result["war_membership_known"] = cursor + 1
        result["war_is_member"] = cursor + 2
    return result


def _mutate(frame: bytes, start: int, payload: bytes) -> bytes:
    value = bytearray(frame)
    value[start:start + len(payload)] = payload
    return bytes(value)


def decoder_checks(wires: dict[str, bytes]) -> dict[str, Any]:
    from work.information_battle_context_wire import (  # noqa: PLC0415
        MAX_WIRE_BYTES,
        decode,
    )
    from work.information_battle_observation_wire import decode as decode_v1  # noqa: PLC0415

    checks: list[str] = []
    failures: list[str] = []
    observed = wires["observed"]
    no_context = wires["no_context"]
    maximum = wires["maximum"]
    decoded = decode(observed)
    context = decoded["context"]
    if decoded["schema"] == "information_battle_context_wire_v2":
        checks.append("observed_schema")
    else:
        failures.append("observed_schema")
    if (decoded["wire"]["version"] == 2
            and decoded["wire"]["inner_v1_length"]
            == int.from_bytes(observed[6:10], "little")):
        checks.append("observed_header")
    else:
        failures.append("observed_header")
    if (decoded["context_present"] is True and context["known_router"] is True
            and context["raw_selector"] == 1 and context["kind"] == 1
            and context["selector_code_hex"] == "b801000000c3"
            and context["selector_code_verified"] is True):
        checks.append("selector_roundtrip")
    else:
        failures.append("selector_roundtrip")
    if decoded["observation"] == _expected_inner():
        checks.append("inner_all_fields_roundtrip")
    else:
        failures.append("inner_all_fields_roundtrip")
    if context == _expected_context():
        checks.append("observed_all_context_fields")
    else:
        failures.append("observed_all_context_fields")
    if (len(context["sides"][0]["participants"]["full_refs"]) == 2
            and len(context["sides"][1]["participants"]["full_refs"]) == 1
            and context["war_context_status"] == 1
            and context["war_members"]["physical_player_membership_known"]
            and context["war_members"]["physical_player_is_war_member"]):
        checks.append("observed_context_fields")
    else:
        failures.append("observed_context_fields")
    physical_offset = _offsets(observed)["physical_ref"]
    physical_raw = int.from_bytes(
        observed[physical_offset:physical_offset + 8], "little"
    )
    if (observed[physical_offset + 3] == 0x5A
            and observed[physical_offset + 7] == 0x03
            and context["physical_player_full_ref"] == physical_raw
            and context["sides"][0]["participants"]["full_refs"][0] == physical_raw
            and context["war_members"]["side_a_full_refs"][0] == physical_raw):
        checks.append("opaque_ref_bytes_roundtrip")
    else:
        failures.append("opaque_ref_bytes_roundtrip")
    if (decoded["complete"] is False
            and decoded["business_complete"] is False
            and decoded["visibility_verified"] is False
            and decoded["overall_complete"] is False
            and decoded["public_identity"]["status"] == "absent"):
        checks.append("business_flags_remain_unknown")
    else:
        failures.append("business_flags_remain_unknown")

    without_context = decode(no_context)
    if (without_context["context_present"] is False
            and without_context["context"] is None
            and without_context["observation"]["known_router"] is True
            and without_context["business_complete"] is False):
        checks.append("context_absent_roundtrip")
    else:
        failures.append("context_absent_roundtrip")
    if without_context["wire"]["bytes"] == len(no_context):
        checks.append("context_absent_exact_eof")
    else:
        failures.append("context_absent_exact_eof")

    maximum_value = decode(maximum)
    if (maximum_value["context"]["sides"][0]["participants"]["count"] == 256
            and maximum_value["context"]["sides"][1]["participants"]["count"] == 256
            and maximum_value["context"]["war_members"]["side_a_count"] == 256
            and maximum_value["context"]["war_members"]["side_b_count"] == 256):
        checks.append("maximum_vectors_roundtrip")
    else:
        failures.append("maximum_vectors_roundtrip")
    expected_max_side_a = [_expected_ref(0, opaque=True)] + [
        _expected_ref(index) for index in range(1, 256)
    ]
    expected_max_side_b = [_expected_ref(index) for index in range(256, 512)]
    maximum_context = maximum_value["context"]
    if (
        maximum_context["sides"][0]["participants"]["full_refs"]
        == expected_max_side_a
        and maximum_context["sides"][1]["participants"]["full_refs"]
        == expected_max_side_b
        and maximum_context["war_members"]["side_a_full_refs"]
        == expected_max_side_a
        and maximum_context["war_members"]["side_b_full_refs"]
        == expected_max_side_b
    ):
        checks.append("maximum_all_vectors_roundtrip")
    else:
        failures.append("maximum_all_vectors_roundtrip")

    inner_length = int.from_bytes(observed[6:10], "little")
    inner = observed[10:10 + inner_length]
    legacy = decode_v1(inner)
    if legacy["wire"]["version"] == 1 and legacy["observation"] == decoded["observation"]:
        checks.append("legacy_v1_inner_decode")
    else:
        failures.append("legacy_v1_inner_decode")

    offsets = _offsets(observed)
    expect_error(lambda: decode(_mutate(observed, 4, b"\x01\x00")),
                 "bad_version_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, 6, (inner_length + 1).to_bytes(4, "little"))),
                 "inner_length_mismatch_rejected", failures, checks)
    expect_error(lambda: decode(observed + b"\x00"),
                 "trailing_context_bytes_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["context_present"], b"\x02")),
                 "context_bool_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["known_router"], b"\x02")),
                 "known_router_bool_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["known_router"], b"\x00")),
                 "inner_known_router_mismatch_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["selector_code"], b"\xb8\x02")),
                 "selector_code_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["selector_verified"], b"\x00")),
                 "unverified_selector_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["kind"], b"\x02")),
                 "kind_mismatch_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["physical_ref"], b"\x00" * 8)),
                 "physical_ref_rejected", failures, checks)
    lowercase_ref = b"aBC\x00\x00\x00\x00\x01"
    expect_error(lambda: decode(_mutate(observed, offsets["physical_ref"], lowercase_ref)),
                 "lowercase_ref_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["side0_present"], b"\x00")),
                 "absent_side_with_values_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["war_status"], b"\x03")),
                 "invalid_war_status_rejected", failures, checks)
    side_a_ref = offsets["war_status"] + 1 + 4
    side_b_ref = (offsets["war_status"] + 1 + 4
                  + int.from_bytes(observed[offsets["war_status"] + 1:offsets["war_status"] + 5], "little") * 8
                  + 4)
    expect_error(lambda: decode(_mutate(observed, side_b_ref,
                                        observed[side_a_ref:side_a_ref + 8])),
                 "war_cross_side_overlap_rejected", failures, checks)
    expect_error(lambda: decode(_mutate(observed, offsets["war_is_member"], b"\x00")),
                 "membership_flag_rejected", failures, checks)
    incomplete = _mutate(observed, offsets["war_vectors_complete"], b"\x00")
    expect_error(lambda: decode(incomplete), "incomplete_membership_rejected", failures, checks)
    unknown_membership = _mutate(observed, offsets["war_membership_known"], b"\x00")
    expect_error(lambda: decode(unknown_membership),
                 "observed_unknown_membership_rejected", failures, checks)
    incomplete_side = _mutate(observed, offsets["side0_complete"], b"\x00")
    expect_error(lambda: decode(incomplete_side),
                 "present_incomplete_side_rejected", failures, checks)
    expect_error(lambda: decode(no_context + b"\x00"),
                 "no_context_trailing_bytes_rejected", failures, checks)
    expect_error(lambda: decode(observed[:10]),
                 "short_context_prefix_rejected", failures, checks)
    expect_error(lambda: decode(b"X" * (MAX_WIRE_BYTES + 1)),
                 "wire_budget_rejected", failures, checks)
    bad_inner = _mutate(observed, 10, b"NOPE")
    expect_error(lambda: decode(bad_inner), "inner_v1_rejected", failures, checks)
    # Ensure the malformed-frame helper itself did not mutate its source.
    if observed[:4] == b"IBOW" and no_context[:4] == b"IBOW":
        checks.append("source_frames_unchanged")
    else:
        failures.append("source_frames_unchanged")
    return {
        "reported": len(checks) + len(failures),
        "passed": len(checks),
        "failed": len(failures),
        "labels": checks,
        "failures": failures,
        "wire_bytes": {name: len(value) for name, value in wires.items()},
        "wire_sha256": {name: sha256_bytes(value) for name, value in wires.items()},
    }


def _parse_wires(stdout: bytes) -> dict[str, bytes]:
    wires: dict[str, bytes] = {}
    for line in stdout.decode("ascii", errors="strict").splitlines():
        if not line.startswith("WIRE "):
            continue
        fields = line.split(" ", 2)
        if len(fields) != 3 or fields[1] in wires:
            raise ValueError("invalid_or_duplicate_wire_line")
        try:
            value = bytes.fromhex(fields[2])
        except ValueError as exc:
            raise ValueError("wire_hex_invalid") from exc
        wires[fields[1]] = value
    expected = {"observed", "no_context", "maximum"}
    if set(wires) != expected:
        raise ValueError(f"wire_cases_mismatch:{sorted(wires)}")
    return wires


def run(output: Path | None = None) -> dict[str, Any]:
    started = time.time()
    report_path = (output or REPORT).resolve()
    stage = report_path.parent
    exe = stage / "test-information-battle-context-wire.exe"
    compile_stdout = stage / "compile.stdout.log"
    compile_stderr = stage / "compile.stderr.log"
    run_stdout = stage / "run.stdout.log"
    run_stderr = stage / "run.stderr.log"
    stage.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "information_battle_context_wire_test_v2",
        "status": "blocked",
        "scope": {
            "synthetic_owned_context_only": True,
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
            "version": 2,
            "inner": "complete unchanged version-1 IBOW result/summary payload",
            "max_wire_bytes": 32768,
            "context_present_zero": "EOF immediately after marker; context remains unknown",
            "context_vector_bounds": 256,
            "little_endian_no_padding": True,
            "full_ref_validation": "three ASCII uppercase/digit bytes; remaining identity bytes opaque",
            "business_complete": False,
            "business_flags": {
                "complete": False,
                "business_complete": False,
                "visibility_verified": False,
                "overall_complete": False,
                "public_identity": "absent",
            },
        },
        "source_pins": {},
        "compile": {},
        "run": {},
        "decoder_checks": {},
        "limitations": [
            "The context envelope preserves bounded raw references and fields only; it does not prove battle identity, visibility, roles, units, or event completeness.",
            "The source fixture is synthetic and does not establish that context is stable or observable in a live game thread.",
            "The inner v1 encoder and decoder remain independently versioned and are not modified by this component.",
        ],
    }
    pins = [HEADER, CPP, PY_MODULE, PY_TEST, V1_HEADER, CONTEXT_HEADER, V1_DECODER]
    report["source_pins"] = {path.relative_to(ROOT).as_posix(): file_pin(path) for path in pins}
    snapshot = stage / "source-snapshot-before-002"
    if snapshot.is_dir():
        report["historical_snapshot_pins"] = {
            path.relative_to(ROOT).as_posix(): file_pin(path)
            for path in sorted(snapshot.iterdir()) if path.is_file()
        }
    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    command = [
        compiler, "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra",
        "-Werror", "-O2", "-fstack-usage", "-I", str(NATIVE), str(CPP), "-o", str(exe),
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
    run_result = subprocess.run([str(exe)], cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, check=False)
    run_stdout.write_bytes(run_result.stdout)
    run_stderr.write_bytes(run_result.stderr)
    report["run"] = {
        "returncode": run_result.returncode,
        "stdout_sha256": sha256_bytes(run_result.stdout),
        "stderr_sha256": sha256_bytes(run_result.stderr),
        "stdout_bytes": len(run_result.stdout),
        "stderr_bytes": len(run_result.stderr),
        "result_line": next((line for line in run_result.stdout.decode("ascii", errors="replace").splitlines()
                              if line.startswith("RESULT ")), None),
    }
    native_lines = [
        line for line in run_result.stdout.decode("ascii", errors="replace").splitlines()
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
        "capture_component_case": "owned_context_capture_input" in native_passed,
    }
    if run_result.returncode != 0:
        report["status"] = "native_test_failed"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report
    try:
        wires = _parse_wires(run_result.stdout)
        report["decoder_checks"] = decoder_checks(wires)
    except Exception as exc:  # preserve a typed failed report for malformed output
        report["decoder_checks"] = {"reported": 0, "passed": 0, "failed": 1,
                                     "failures": [f"runner:{type(exc).__name__}:{exc}"]}
    report["executable"] = file_pin(exe)
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
    parser.add_argument("--run", action="store_true", help="compile and run the synthetic native fixture")
    parser.add_argument("--output", type=Path, default=REPORT,
                        help="独立报告路径；其父目录也承载本次exe和日志")
    args = parser.parse_args()
    if not args.run:
        print("context-wire source ready; use --run after the context header is frozen")
        sys.exit(0)
    result = run(args.output)
    print(json.dumps({
        "status": result.get("status"),
        "report": str(args.output),
        "native": result.get("run"),
        "decoder": result.get("decoder_checks"),
    }, ensure_ascii=False))
