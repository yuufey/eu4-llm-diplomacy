"""Compile and cross-check the synthetic IBOW version-4 template wire.

The native executable owns all value fixtures and emits complete frames.  This
runner feeds those bytes through the Python decoder, checks legacy v2/v3
delegation, and exercises strict length/boundary rejection.  It never opens an
EU4 process or uses REA/RPM.
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

from work.information_battle_naval_wire import decode as decode_naval  # noqa: E402
from work.information_battle_template_wire import (  # noqa: E402
    BASE_VERSION,
    CONTAINER_EXTENSION_VERSION,
    CONTAINER_FIXED_BODY_BYTES,
    EXTENSION_MAGIC,
    EXTENSION_VERSION,
    MAX_ARENA_BYTES,
    MAX_AUXILIARY_TEXT_BYTES,
    MAX_KEY_BYTES,
    MAX_PAIRS,
    MAX_VALUE_BYTES,
    MAX_WIRE_BYTES,
    TemplateWireError,
    decode,
)

NATIVE = ROOT / "work" / "native"
STAGE = (ROOT / "work" / "runtime" / "information-battle-container-20261026-001"
         / "template-wire-test-001")
HEADER = NATIVE / "information-battle-template-wire.h"
OWNED_TEMPLATE = NATIVE / "information-battle-owned-template.h"
NAVAL_HEADER = NATIVE / "information-battle-naval-wire.h"
CPP = NATIVE / "tests" / "information-battle-template-wire-test.cpp"
PY_MODULE = ROOT / "work" / "information_battle_template_wire.py"
PY_TEST = Path(__file__).resolve()
V2_FIXTURE = ROOT / "bridge" / "tests" / "fixtures" / (
    "information_battle_naval_seq4_recorded_v2_1374.json"
)
CPP_EXE = STAGE / "test-information-battle-template-wire.exe"
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
    expected = {"absent", "template", "boundary", "maximum", "container"}
    if set(wires) != expected:
        raise ValueError(f"wire_cases_mismatch:{sorted(wires)}")
    return wires


def expect_error(function: Callable[[], Any], label: str,
                 checks: list[str], failures: list[str]) -> None:
    try:
        function()
    except TemplateWireError:
        checks.append(label)
    except Exception as exc:  # pragma: no cover - diagnostic path
        failures.append(f"{label}:unexpected_{type(exc).__name__}")
    else:
        failures.append(label)


def _u32(data: bytes, start: int) -> int:
    return int.from_bytes(data[start:start + 4], "little", signed=False)


def _mutate(frame: bytes, start: int, payload: bytes) -> bytes:
    result = bytearray(frame)
    if start < 0 or start + len(payload) > len(result):
        raise ValueError("mutation_out_of_bounds")
    result[start:start + len(payload)] = payload
    return bytes(result)


def _outer_offsets(frame: bytes) -> dict[str, int]:
    base_bytes = _u32(frame, 6)
    base_start = 10
    base_end = base_start + base_bytes
    marker = base_end
    extension_start = marker + 1
    extension_version = extension_start + 4
    extension_bytes = extension_start + 6
    body = extension_start + 10
    aux_length = body + 15
    aux_start = body + 19
    auxiliary_bytes = _u32(frame, aux_length)
    first_key_length = aux_start + auxiliary_bytes
    first_key_bytes = _u32(frame, first_key_length)
    first_value_length = first_key_length + 4 + first_key_bytes
    return {
        "base_start": base_start,
        "base_end": base_end,
        "marker": marker,
        "extension_start": extension_start,
        "extension_version": extension_version,
        "extension_bytes": extension_bytes,
        "body": body,
        "pair_count": body + 11,
        "aux_length": aux_length,
        "first_key_length": first_key_length,
        "first_value_length": first_value_length,
    }


def _body_with_arena_overflow() -> bytes:
    """Make a structurally valid body whose copied arena exceeds 64 KiB."""
    auxiliary = b"a" * MAX_AUXILIARY_TEXT_BYTES
    # Eight legal values of 8192 bytes plus the auxiliary blob exceed the
    # owned-template arena while keeping each individual field in bounds.
    pairs = b"".join(
        (0).to_bytes(4, "little")
        + (MAX_VALUE_BYTES).to_bytes(4, "little")
        + b"v" * MAX_VALUE_BYTES
        for _ in range(8)
    )
    # The key lengths are zero, so the body remains below the 256 KiB wire cap.
    fixed = (0).to_bytes(4, "little", signed=True)
    fixed += bytes((0, 0))
    fixed += (0).to_bytes(4, "little")
    fixed += bytes((0,))
    fixed += (8).to_bytes(4, "little")
    fixed += len(auxiliary).to_bytes(4, "little") + auxiliary
    return fixed + pairs


def _wrap_present(base: bytes, body: bytes) -> bytes:
    return (b"IBOW" + (4).to_bytes(2, "little")
            + len(base).to_bytes(4, "little") + base + b"\x01"
            + EXTENSION_MAGIC + EXTENSION_VERSION.to_bytes(2, "little")
            + len(body).to_bytes(4, "little") + body)


def decoder_checks(wires: dict[str, bytes]) -> dict[str, Any]:
    checks: list[str] = []
    failures: list[str] = []
    absent = wires["absent"]
    template = wires["template"]
    boundary = wires["boundary"]
    maximum = wires["maximum"]

    absent_decoded = decode(absent)
    base_bytes = _u32(absent, 6)
    base_raw = absent[10:10 + base_bytes]
    direct_base = decode_naval(base_raw)
    if (absent_decoded["schema"] == "information_battle_template_wire_v4"
            and absent_decoded["wire"]["version"] == 4
            and absent_decoded["wire"]["base_v3_version"] == BASE_VERSION
            and absent_decoded["wire"]["template_present"] is False
            and absent_decoded["message_template"] is None
            and absent_decoded["wire"]["trailing_bytes"] == 0):
        checks.append("v4_absent_metadata")
    else:
        failures.append("v4_absent_metadata")
    preserved = all(absent_decoded.get(key) == value
                    for key, value in direct_base.items()
                    if key not in {"schema", "wire"})
    if preserved and absent_decoded.get("observation") == direct_base.get("observation"):
        checks.append("v3_root_fields_preserved")
    else:
        failures.append("v3_root_fields_preserved")

    template_decoded = decode(template)
    message = template_decoded.get("message_template")
    expected_pairs = [
        {"key_raw_hex": "6b0080", "value_raw_hex": "0076fe"},
        {"key_raw_hex": "6b0080", "value_raw_hex": "6f6e6500"},
    ]
    if (template_decoded["wire"]["base_v3_bytes"]
            == _u32(template, 6)
            and template_decoded["wire"]["extension_version"] == 1
            and template_decoded["wire"]["template_present"] is True
            and isinstance(message, dict)
            and message["native_date"] == -1455113
            and message["raw_flag_8c"] == 0xa1
            and message["raw_flag_8d"] == 0x5e
            and message["raw_header_word_20"] == 0xfeedbeef
            and message["raw_header_flag_24"] == 0x7a
            and message["pair_count"] == 2
            and message["auxiliary_text_hex"] == "00ff8041"
            and message["pairs"] == expected_pairs):
        checks.append("template_raw_pair_order_and_bytes")
    else:
        failures.append("template_raw_pair_order_and_bytes")

    boundary_message = decode(boundary)["message_template"]
    boundary_ok = (isinstance(boundary_message, dict)
                    and boundary_message["pair_count"] == 1
                    and len(bytes.fromhex(boundary_message["auxiliary_text_hex"]))
                    == MAX_AUXILIARY_TEXT_BYTES
                    and len(bytes.fromhex(boundary_message["pairs"][0]["key_raw_hex"]))
                    == MAX_KEY_BYTES
                    and len(bytes.fromhex(boundary_message["pairs"][0]["value_raw_hex"]))
                    == MAX_VALUE_BYTES)
    if boundary_ok:
        checks.append("field_length_boundaries")
    else:
        failures.append("field_length_boundaries")

    maximum_message = decode(maximum)["message_template"]
    order_ok = (isinstance(maximum_message, dict)
                and maximum_message["pair_count"] == MAX_PAIRS
                and len(maximum_message["pairs"]) == MAX_PAIRS
                and maximum_message["pairs"][0] == {
                    "key_raw_hex": "41", "value_raw_hex": "30"
                }
                and maximum_message["pairs"][-1] == {
                    "key_raw_hex": "58", "value_raw_hex": "37"
                })
    if order_ok:
        checks.append("maximum_duplicate_order")
    else:
        failures.append("maximum_duplicate_order")

    container = wires["container"]
    container_decoded = decode(container)
    container_message = container_decoded.get("message_template")
    container_expected_pairs = [
        {"key_raw_hex": "630080", "value_raw_hex": "76fe"},
        {"key_raw_hex": "630080", "value_raw_hex": "0041"},
    ]
    container_ok = (
        container_decoded["wire"]["extension_version"]
            == CONTAINER_EXTENSION_VERSION
        and container_decoded["wire"]["template_present"] is True
        and isinstance(container_message, dict)
        and container_message["source_kind"]
            == "formatter_container_before_cleanup"
        and container_message["message_metadata_present"] is False
        and container_message["native_date"] is None
        and container_message["raw_flag_8c"] is None
        and container_message["raw_flag_8d"] is None
        and container_message["auxiliary_text_hex"] is None
        and container_message["raw_container_word_10"] == 0x10203040
        and container_message["raw_container_flag_14"] == 0x91
        and container_message["pair_count"] == 2
        and container_message["pairs"] == container_expected_pairs
    )
    if container_ok:
        checks.append("formatter_container_extension2")
    else:
        failures.append("formatter_container_extension2")

    container_base_bytes = _u32(container, 6)
    container_body = 10 + container_base_bytes + 1 + 10
    expect_error(
        lambda: decode(_mutate(container, container_body, b"\x01")),
        "formatter_container_source_kind_rejected", checks, failures)
    expect_error(
        lambda: decode(container + b"\x00"),
        "formatter_container_trailing_rejected", checks, failures)

    # Direct v3 input is still delegated to the existing decoder, with no
    # v4-only key inserted into its root.
    direct_v3 = decode(base_raw)
    if direct_v3 == direct_base and "message_template" not in direct_v3:
        checks.append("direct_v3_compatibility")
    else:
        failures.append("direct_v3_compatibility")

    fixture = json.loads(V2_FIXTURE.read_text(encoding="utf-8"))
    v2_raw = bytes.fromhex(fixture["payload_hex"])
    if decode(v2_raw) == decode_naval(v2_raw) and "message_template" not in decode(v2_raw):
        checks.append("direct_v2_compatibility")
    else:
        failures.append("direct_v2_compatibility")

    offsets = _outer_offsets(template)
    expect_error(lambda: decode(absent + b"\x00"),
                 "absent_trailing_rejected", checks, failures)
    expect_error(lambda: decode(template + b"\x00"),
                 "template_trailing_rejected", checks, failures)
    expect_error(lambda: decode(_mutate(template, offsets["marker"], b"\x02")),
                 "noncanonical_template_present_rejected", checks, failures)
    expect_error(lambda: decode(_mutate(template, offsets["extension_start"], b"NOPE")),
                 "extension_magic_rejected", checks, failures)
    expect_error(lambda: decode(_mutate(template, offsets["extension_version"], b"\x02\x00")),
                 "extension_version_rejected", checks, failures)
    wrong_length = (_u32(template, offsets["extension_bytes"]) + 1).to_bytes(4, "little")
    expect_error(lambda: decode(_mutate(template, offsets["extension_bytes"], wrong_length)),
                 "extension_length_rejected", checks, failures)
    over_pairs = (MAX_PAIRS + 1).to_bytes(4, "little")
    expect_error(lambda: decode(_mutate(template, offsets["pair_count"], over_pairs)),
                 "pair_count_rejected", checks, failures)
    over_key = (MAX_KEY_BYTES + 1).to_bytes(4, "little")
    expect_error(lambda: decode(_mutate(template, offsets["first_key_length"], over_key)),
                 "key_length_rejected", checks, failures)
    over_value = (MAX_VALUE_BYTES + 1).to_bytes(4, "little")
    expect_error(lambda: decode(_mutate(template, offsets["first_value_length"], over_value)),
                 "value_length_rejected", checks, failures)
    over_aux = (MAX_AUXILIARY_TEXT_BYTES + 1).to_bytes(4, "little")
    expect_error(lambda: decode(_mutate(template, offsets["aux_length"], over_aux)),
                 "auxiliary_length_rejected", checks, failures)
    base_v3 = template[10:10 + _u32(template, 6)]
    expect_error(lambda: decode(_wrap_present(base_v3, _body_with_arena_overflow())),
                 "arena_length_rejected", checks, failures)
    nested = (b"IBOW" + (4).to_bytes(2, "little")
              + len(template).to_bytes(4, "little") + template + b"\x00")
    expect_error(lambda: decode(nested), "nested_v4_base_rejected", checks, failures)
    expect_error(lambda: decode(b"X" * (MAX_WIRE_BYTES + 1)),
                 "wire_budget_rejected", checks, failures)

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
        "schema": "information_battle_template_wire_test_v1",
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
            "version": 4,
            "base": "complete unchanged version-3 naval wire only",
            "extension_magic": "BTXT",
            "message_extension_version": EXTENSION_VERSION,
            "formatter_container_extension_version": CONTAINER_EXTENSION_VERSION,
            "formatter_container_fixed_body_bytes": CONTAINER_FIXED_BODY_BYTES,
            "max_wire_bytes": MAX_WIRE_BYTES,
            "max_arena_bytes": MAX_ARENA_BYTES,
            "max_pairs": MAX_PAIRS,
            "little_endian_no_padding": True,
            "absent_requires_eof": True,
            "present_requires_complete_template_body": True,
            "raw_pair_bytes_and_order_preserved": True,
        },
        "source_pins": {},
        "compile": {},
        "run": {},
        "native_checks": {},
        "decoder_checks": {},
        "limitations": [
            "The native and Python inputs are self-owned value fixtures; no EU4 process, game function, REA, RPM, DLL, or production bridge is accessed.",
            "The embedded v3 bytes are preserved and delegated to the existing v3 decoder; v4 adds no business interpretation to template bytes.",
        ],
    }
    pins = [HEADER, OWNED_TEMPLATE, NAVAL_HEADER, CPP, PY_MODULE, PY_TEST, V2_FIXTURE]
    missing = [path for path in pins if not path.is_file()]
    if missing:
        report["status"] = "blocked_missing_source"
        report["missing_sources"] = [path.relative_to(ROOT).as_posix() for path in missing]
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        return report
    report["source_pins"] = {
        path.relative_to(ROOT).as_posix(): file_pin(path) for path in pins
    }
    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
        return report
    command = [
        compiler, "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra",
        "-Werror", "-O2", "-I", str(NATIVE), str(CPP), "-o", str(CPP_EXE),
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
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
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
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
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
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                           encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true",
                        help="compile and run the synthetic native fixture")
    parser.add_argument("--output", type=Path, default=REPORT,
                        help="独立报告路径；其父目录也承载本次exe和日志")
    args = parser.parse_args()
    if not args.run:
        print("template-wire source ready; use --run for native/Python cross-check")
        raise SystemExit(0)
    result = run(args.output)
    print(json.dumps({
        "status": result.get("status"),
        "report": str(args.output),
        "native": result.get("native_checks"),
        "decoder": result.get("decoder_checks"),
    }, ensure_ascii=False))
    raise SystemExit(0 if result.get("status") == "passed" else 1)
