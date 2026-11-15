"""One-shot owned C++17 test runner and v7 fixture exporter."""
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
TEST_DIR = NATIVE / "tests"
STAGE = (
    ROOT / "work/runtime/information-battle-display-context-wire-20261028-001/"
          "owned-wire7-001"
).resolve()
CPP_SOURCE = TEST_DIR / "information-battle-display-context-wire-test.cpp"
WIRE_HEADER = NATIVE / "information-battle-display-context-wire.h"
LAYOUT_HEADER = NATIVE / "information-battle-display-context-layout.h"
V6_HEADER = NATIVE / "information-battle-native-text-wire.h"
V6_VALUE_HEADER = NATIVE / "information-battle-owned-native-text.h"
CONTRACT = ROOT / "work/battle-display-context-wire7-contract.md"
BASE6_INPUT = (
    ROOT / "work/runtime/information-battle-event-context-20261028-001/"
          "fixture-inputs/base-v6-valid.bin"
)
GAME_VERSION = "1.37.4"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(value)


def next_attempt() -> tuple[int, Path, list[dict]]:
    preserved: list[dict] = []
    for attempt in range(1, 1000):
        attempt_dir = STAGE / f"attempt-{attempt:03d}"
        if not attempt_dir.exists():
            return attempt, attempt_dir, preserved
        for path in sorted(attempt_dir.rglob("*")):
            if path.is_file():
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


def expected_snapshot(base6: bytes, fixture: bytes) -> dict:
    key = b"LANDBATTLEOVER"
    language = b"l_english"
    body = b"$NAME$"
    button1 = bytes.fromhex("118b59108476")
    fields = [
        (1, 1, key),
        (2, 1, language),
        (3, 1, body),
        (4, 1, button1),
        (5, 1, b""),
        (6, 2, b""),
        (7, 0, b""),
    ]
    offsets = [0, len(key), len(key) + len(language),
               len(key) + len(language) + len(body),
               len(key) + len(language) + len(body) + len(button1), 0, 0]
    context_fields = []
    for (field_id, state, value), offset in zip(fields, offsets):
        context_fields.append({
            "id": field_id,
            "name": ["", "definition_key", "language", "body_template",
                     "button1", "button2", "button3",
                     "compact_losses_template"][field_id],
            "state": state,
            "state_name": {0: "unknown", 1: "observed", 2: "absent"}[state],
            "offset": offset if state == 1 else 0,
            "length": len(value),
            "bytes_hex": value.hex(),
        })
    base_length = int.from_bytes(fixture[6:10], "little")
    extension_start = 10 + base_length
    body_length = int.from_bytes(fixture[extension_start + 6:extension_start + 10],
                                 "little")
    return {
        "schema": "information.battle.display_context_wire7_fixture.v1",
        "synthetic_owned_fixture": True,
        "target_metadata": {
            "game_version": GAME_VERSION,
            "executable_sha256": EXE_SHA256,
            "metadata_is_not_serialized": True,
        },
        "fixture_v7": {
            "bytes": len(fixture),
            "sha256": hashlib.sha256(fixture).hexdigest(),
            "base6_bytes": base_length,
            "base6_sha256": hashlib.sha256(base6).hexdigest(),
            "base6_hex": base6.hex(),
            "extension_magic_ascii": "DCTX",
            "extension_version": 1,
            "body_bytes": body_length,
            "body_fixed_bytes": 27,
            "entry_header_bytes": 8,
            "entry_count": 7,
            "arena_used": 35,
        },
        "snapshot": {
            "context_state": 1,
            "context_state_name": "observed",
            "capture_stage": 3,
            "failure": 0,
            "sequence": 3,
            "raw_date": 56557272,
            "battle_kind": 1,
            "battle_kind_name": "land",
            "popup_kind_raw": 0,
            "layout_raw": 1,
            "button_flag_raw": 1,
            "fields": context_fields,
        },
        "wire_boundaries": {
            "base6_starts_at": 10,
            "extension_starts_at": extension_start,
            "body_starts_at": extension_start + 10,
            "body_ends_at": extension_start + 10 + body_length,
            "no_trailing_bytes": extension_start + 10 + body_length == len(fixture),
        },
        "provenance_limit": (
            "base6 and display snapshot are generated by an owned offline C++ fixture; "
            "no EU4 process or native engine function was used"
        ),
    }


def validate_export(base6: bytes, fixture: bytes) -> dict:
    if len(base6) < 10 or base6[:4] != b"IBOW" or base6[4:6] != b"\x06\x00":
        raise ValueError("owned_base6_header_mismatch")
    if len(fixture) > 512 * 1024 or fixture[:4] != b"IBOW" \
            or fixture[4:6] != b"\x07\x00":
        raise ValueError("owned_v7_outer_header_mismatch")
    declared_base = int.from_bytes(fixture[6:10], "little")
    if declared_base != len(base6) or fixture[10:10 + len(base6)] != base6:
        raise ValueError("embedded_base6_mismatch")
    extension = 10 + declared_base
    if fixture[extension:extension + 4] != b"DCTX" \
            or int.from_bytes(fixture[extension + 4:extension + 6], "little") != 1:
        raise ValueError("dctx_header_mismatch")
    body_length = int.from_bytes(fixture[extension + 6:extension + 10], "little")
    body = extension + 10
    if body_length != len(fixture) - body or body_length < 27 + 7 * 8:
        raise ValueError("dctx_body_length_mismatch")
    expected = expected_snapshot(base6, fixture)
    source_pin = pin(BASE6_INPUT)
    if len(base6) != source_pin["bytes"] \
            or hashlib.sha256(base6).hexdigest() != source_pin["sha256"]:
        raise ValueError("base6_fixture_source_pin_mismatch")
    expected["fixture_v7"]["base6_input_source_pin"] = source_pin
    snapshot = expected["snapshot"]
    fixed = fixture[body:body + 27]
    if (fixed[0] != snapshot["context_state"] or fixed[1] != snapshot["capture_stage"]
            or int.from_bytes(fixed[2:4], "little") != snapshot["failure"]
            or int.from_bytes(fixed[4:12], "little") != snapshot["sequence"]
            or int.from_bytes(fixed[12:16], "little", signed=True) != snapshot["raw_date"]
            or fixed[16] != snapshot["battle_kind"]
            or int.from_bytes(fixed[17:21], "little", signed=True) != snapshot["popup_kind_raw"]
            or int.from_bytes(fixed[21:25], "little", signed=True) != snapshot["layout_raw"]
            or fixed[25] != snapshot["button_flag_raw"] or fixed[26] != 7):
        raise ValueError("fixture_fixed_snapshot_mismatch")
    cursor = body + 27
    arena = bytearray()
    for field in snapshot["fields"]:
        field_id = fixture[cursor]
        field_state = fixture[cursor + 1]
        reserved = int.from_bytes(fixture[cursor + 2:cursor + 4], "little")
        length = int.from_bytes(fixture[cursor + 4:cursor + 8], "little")
        cursor += 8
        if (field_id != field["id"] or field_state != field["state"]
                or reserved != 0 or length != field["length"]):
            raise ValueError("fixture_entry_header_mismatch")
        actual = fixture[cursor:cursor + length]
        if actual.hex() != field["bytes_hex"]:
            raise ValueError("fixture_entry_payload_mismatch")
        if field_state == 1:
            if field["offset"] != len(arena):
                raise ValueError("fixture_snapshot_offset_mismatch")
            arena.extend(actual)
        cursor += length
    if cursor != len(fixture) or len(arena) != expected["fixture_v7"]["arena_used"]:
        raise ValueError("fixture_trailing_bytes_or_arena_mismatch")
    return expected


def run_test_only() -> int:
    attempt, attempt_dir, preserved = next_attempt()
    attempt_dir.mkdir(parents=True, exist_ok=False)
    executable = attempt_dir / "information-battle-display-context-wire-test.exe"
    log_path = attempt_dir / "run.log"
    receipt_path = attempt_dir / "receipt.json"
    fixture_path = attempt_dir / "fixture-v7.bin"
    expected_path = attempt_dir / "expected-snapshot.json"
    source_paths = [CPP_SOURCE, Path(__file__).resolve(), WIRE_HEADER,
                    LAYOUT_HEADER, V6_HEADER, V6_VALUE_HEADER, CONTRACT,
                    BASE6_INPUT]
    source_pins = [pin(path) for path in source_paths]
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    log_parts: list[str] = []
    receipt = {
        "schema": "information.battle.display_context_wire7_test.v1",
        "status": "failed",
        "execution_mode": "--test-only",
        "attempt": attempt,
        "preserved_prior_attempt_artifacts": preserved,
        "started_at_utc": started,
        "game_process_attached": False,
        "game_or_native_function_called": False,
        "native_calls": 0,
        "RPM_used": False,
        "REA_run": False,
        "MCP_used": False,
        "source_pins_before": source_pins,
        "boundary": {
            "component": "owned C++17 value-only IBOW v7 encoder fixture",
            "max_frame_bytes": 512 * 1024,
            "max_extension_arena_bytes": 32768,
            "metadata_game_version": GAME_VERSION,
            "metadata_executable_sha256": EXE_SHA256,
            "metadata_is_not_serialized": True,
            "native_engine_or_EU4_fixture_source": False,
        },
    }
    try:
        compiler, selected_by = resolve_compiler()
        version_result = subprocess.run(
            [compiler, "--version"], capture_output=True, text=True,
            check=False, timeout=15,
        )
        machine_result = subprocess.run(
            [compiler, "-dumpmachine"], capture_output=True, text=True,
            check=False, timeout=15,
        )
        if version_result.returncode != 0 or machine_result.returncode != 0:
            raise RuntimeError("compiler_identity_query_failed")
        target = machine_result.stdout.strip()
        if not target.lower().startswith(("x86_64", "amd64")):
            raise RuntimeError("unexpected_compiler_target:" + target)
        command = [compiler, "-std=c++17", "-O2", "-Wall", "-Wextra",
                   "-Wpedantic", "-Werror", str(CPP_SOURCE), "-o", str(executable)]
        receipt["compiler"] = {
            "path": compiler,
            "selected_by": selected_by,
            "version": version_result.stdout.splitlines()[0]
                if version_result.stdout else "unknown",
            "target": target,
            "compile_command": command,
        }
        log_parts.append("$ " + subprocess.list2cmdline(command))
        compiled = subprocess.run(command, cwd=TEST_DIR, capture_output=True,
                                  text=True, check=False, timeout=120)
        log_parts.extend((compiled.stdout, compiled.stderr))
        receipt["compile_returncode"] = compiled.returncode
        if compiled.returncode != 0:
            raise RuntimeError("compile_failed")

        run_command = [str(executable), "--base6", str(BASE6_INPUT.resolve())]
        receipt["test_command"] = run_command
        log_parts.append("$ " + subprocess.list2cmdline(run_command))
        tested = subprocess.run(run_command, cwd=attempt_dir, capture_output=True,
                                text=True, check=False, timeout=30)
        log_parts.extend((tested.stdout, tested.stderr))
        receipt["test_returncode"] = tested.returncode
        receipt["test_stdout"] = tested.stdout
        receipt["test_stderr"] = tested.stderr
        if tested.returncode != 0:
            raise RuntimeError("owned_unit_tests_failed")

        lines = tested.stdout.splitlines()
        base_lines = [line.removeprefix("FIXTURE_BASE6_HEX=")
                      for line in lines if line.startswith("FIXTURE_BASE6_HEX=")]
        v7_lines = [line.removeprefix("FIXTURE_V7_HEX=")
                    for line in lines if line.startswith("FIXTURE_V7_HEX=")]
        checks = [line for line in lines if line.startswith("PASS:")]
        if len(base_lines) != 1 or len(v7_lines) != 1 or not checks:
            raise RuntimeError("fixture_export_missing_or_ambiguous")
        base6 = bytes.fromhex(base_lines[0])
        fixture = bytes.fromhex(v7_lines[0])
        expected = validate_export(base6, fixture)
        write_exclusive(fixture_path, fixture)
        write_text_exclusive(expected_path,
                             json.dumps(expected, ensure_ascii=False, indent=2) + "\n")
        receipt["fixture"] = pin(fixture_path)
        receipt["expected_snapshot"] = pin(expected_path)
        receipt["fixture_base6"] = {
            "bytes": len(base6),
            "sha256": hashlib.sha256(base6).hexdigest(),
            "hex": base6.hex(),
        }
        receipt["test_check_count"] = len(checks)
        receipt["passed_check_names"] = [line[6:] for line in checks]
        receipt["status"] = "passed"
    except Exception as exc:
        receipt["failure"] = f"{type(exc).__name__}:{exc}"

    post_pins = [pin(path) for path in source_paths]
    receipt["source_pins_after"] = post_pins
    receipt["sources_unchanged"] = post_pins == source_pins
    if not receipt["sources_unchanged"]:
        receipt["status"] = "failed"
        receipt["failure"] = "source_changed_during_test"
    if executable.exists():
        receipt["executable"] = pin(executable)
    receipt["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    log = "\n".join(part.rstrip("\n") for part in log_parts) + "\n"
    write_text_exclusive(log_path, log)
    receipt["log"] = pin(log_path)
    write_text_exclusive(receipt_path,
                         json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({
        "status": receipt["status"],
        "attempt": attempt,
        "receipt": receipt_path.relative_to(ROOT).as_posix(),
        "fixture": receipt.get("fixture"),
        "expected_snapshot": receipt.get("expected_snapshot"),
        "failure": receipt.get("failure"),
    }, ensure_ascii=False))
    return 0 if receipt["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-only", action="store_true")
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
