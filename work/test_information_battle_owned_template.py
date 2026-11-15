"""Build and run the bounded owned-template message-copy fixture.

The fixture uses only a synthetic sparse reader.  It does not open EU4,
access a process, install a DLL, call REA, or invoke a game function.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-container-20261026-001" / "owned-template-test-001"
HEADER = NATIVE / "information-battle-owned-template.h"
CPP = NATIVE / "tests" / "information-battle-owned-template-test.cpp"
SCRIPT = Path(__file__).resolve()
REPORT = STAGE / "report.json"
EXE = STAGE / "information-battle-owned-template-test.exe"
COMPILE_STDOUT = STAGE / "compile.stdout.log"
COMPILE_STDERR = STAGE / "compile.stderr.log"
RUN_STDOUT = STAGE / "run.stdout.log"
RUN_STDERR = STAGE / "run.stderr.log"

MESSAGE_LEDGER = ROOT / "work" / "runtime" / "information-battle-message-20261025-001" / "message-lifetime-ledger-001.json"
POPUP_LEDGER = ROOT / "work" / "runtime" / "information-battle-popup-20261025-001" / "popup-field-ledger-001.json"
SELECTED_MESSAGE = ROOT / "work" / "runtime" / "information-battle-popup-20261025-001" / "rea-popup-message-copy-001" / "selected-evidence-001.json"
SELECTED_NODE = ROOT / "work" / "runtime" / "information-battle-popup-20261025-001" / "rea-template-node-copy-001" / "selected-evidence-001.json"
SELECTED_RESULT = ROOT / "work" / "runtime" / "information-battle-layout-20261025-001" / "rea-land-result-message-001" / "selected-evidence-001.json"
SELECTED_LAND = ROOT / "work" / "runtime" / "information-battle-popup-20261025-001" / "rea-land-popup-fields-001" / "selected-evidence-001.json"
SELECTED_NAVAL = ROOT / "work" / "runtime" / "information-battle-popup-20261025-001" / "rea-naval-popup-fields-001" / "selected-evidence-001.json"

TARGET_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_PINS = {
    MESSAGE_LEDGER: "1affeab5db5f76f0a3350a71596053ec3e0f1b72c1d3394e1e270c63b8fc777f",
    POPUP_LEDGER: "84d18633f9612129579d9b35a9a56faf4ecdcbbb341540fa3c53cff04b6ed007",
    SELECTED_MESSAGE: "ea2d284a4f3f7edab0d663bf823406aa7234f3bca53dd5fdc7ecc9b8afc797cb",
    SELECTED_NODE: "b265547e02ad0d9a9f35991074c6b7a03d972376f36ae1bd735bcb9000bc68b0",
    SELECTED_RESULT: "82455e0f1f9fe27bc3db a2e3bea176743ce21d89b076f5e789a8b7f5cef83242".replace(" ", ""),
    SELECTED_LAND: "7e2e3407706bcd49ac526fcf15f895370ae366e8d852f6c7f15adf2208fecb23",
    SELECTED_NAVAL: "19dc34efb678afb575115523dbcd4f5ab5a4f3872748af39fd473d0100dd97b3",
}
MAX_JSON_BYTES = 1 * 1024 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024


def relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


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


def file_pin(path: Path, expected: str | None = None) -> dict[str, Any]:
    if not path.is_file():
        return {
            "path": relative(path),
            "status": "missing",
            "exists": False,
            "size_bytes": None,
            "sha256": None,
            "expected_sha256": expected,
        }
    size, digest = sha256_file(path)
    return {
        "path": relative(path),
        "status": "passed" if expected is None or digest == expected else "mismatch",
        "exists": True,
        "size_bytes": size,
        "sha256": digest,
        "expected_sha256": expected,
        "sha256_matches_expected": expected is None or digest == expected,
    }


def load_json(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size > MAX_JSON_BYTES:
        raise ValueError(f"json_over_bound:{relative(path)}:{size}")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ValueError(f"file_changed_during_read:{relative(path)}")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{relative(path)}")
    return value


def inspect_evidence() -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    pins: dict[str, Any] = {}
    for path, expected in EXPECTED_PINS.items():
        pin = file_pin(path, expected)
        pins[relative(path)] = pin
        if pin.get("status") != "passed":
            errors.append(f"source_pin:{relative(path)}")

    try:
        lifetime = load_json(MESSAGE_LEDGER)
        facts = {item.get("id") for item in lifetime.get("facts", [])
                 if isinstance(item, dict)}
        required_facts = {
            "message_owns_moved_template_container",
            "delivery_moves_before_consume",
            "move_invalidates_source_headers",
        }
        if not required_facts.issubset(facts):
            errors.append("message_lifetime_facts_incomplete")

        popup = load_json(POPUP_LEDGER)
        claims = {item.get("id") for item in popup.get("claims", [])
                  if isinstance(item, dict)}
        required_claims = {
            "message-container-copy",
            "node-key-value-copy",
            "message-string-and-context",
            "land-line1-format",
            "naval-line1-format",
        }
        if not required_claims.issubset(claims):
            errors.append("popup_field_claims_incomplete")

        for path, expected_rva in (
            (SELECTED_MESSAGE, "0x598dc0"),
            (SELECTED_NODE, "0x5b29c0"),
        ):
            selected = load_json(path)
            identity = selected.get("identity_audit", {})
            if (identity.get("status") != "passed"
                    or identity.get("subject_sha256") != TARGET_EXE_SHA256
                    or identity.get("authorised_rva") != expected_rva):
                errors.append(f"selected_identity:{relative(path)}")

        selected_result = load_json(SELECTED_RESULT)
        result_identity = selected_result.get("identity_audit", {})
        if (result_identity.get("status") != "passed"
                or result_identity.get("subject_sha256") != TARGET_EXE_SHA256):
            errors.append("selected_result_identity")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"source_inspection:{type(exc).__name__}:{exc}")

    return pins, errors


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def write_new_json(path: Path, value: dict[str, Any]) -> tuple[int, str]:
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
           + "\n").encode("utf-8")
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError(f"report_over_bound:{len(raw)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
    return len(raw), hashlib.sha256(raw).hexdigest()


def main() -> int:
    started = time.time()
    if REPORT.exists():
        raise FileExistsError(f"refusing_to_overwrite:{relative(REPORT)}")
    STAGE.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "schema": "information_battle_owned_template_test_v1",
        "status": "blocked",
        "scope": {
            "game_access": False,
            "rea_access": False,
            "remote_process_access": False,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "production_modified": False,
            "fixture_process_only": True,
            "component_allocates_or_does_io": False,
        },
        "contract": {
            "reader_signature": "bool read(uintptr_t,unsigned char*,size_t) noexcept",
            "header_offsets": {
                "head": "0x10",
                "tail": "0x18",
                "raw_word_20": "0x20",
                "raw_flag_24": "0x24",
                "auxiliary_text": "0x60",
                "native_date": "0x88",
                "raw_flags": ["0x8c", "0x8d"],
            },
            "formatter_container_header_bytes": 24,
            "formatter_container_offsets": {
                "head": "0x00",
                "tail": "0x08",
                "raw_word_10": "0x10",
                "raw_flag_14": "0x14",
            },
            "formatter_container_metadata": "unavailable_and_zeroed",
            "node_offsets": {
                "key": "0x00",
                "value": "0x20",
                "next": "0x60",
                "node_bytes": 112,
            },
            "raw_word_20_semantics": "preserved_without_count_claim",
            "max_pairs": 128,
            "max_key_bytes": 128,
            "max_value_bytes": 8192,
            "max_auxiliary_text_bytes": 8192,
            "max_arena_bytes": 65536,
            "max_per_pass_read_bytes": 131072,
            "max_total_read_bytes": 262144,
            "two_pass_full_read_compare": True,
            "failure_output_unchanged": True,
            "ordered_duplicate_keys_preserved": True,
            "raw_bytes_no_decode": True,
            "no_borrowed_pointers": True,
        },
        "source_pins": {},
        "source_evidence": {},
        "compile": {},
        "run": {},
        "observations": {},
    }

    source_pins, source_errors = inspect_evidence()
    report["source_pins"] = source_pins
    report["source_evidence"] = {
        "fixed_exe_sha256": TARGET_EXE_SHA256,
        "runtime_observed": False,
        "static_evidence_only": True,
        "rea_inclusive_ranges_preserved": True,
        "message_copy_rva": "0x598dc0",
        "node_copy_rva": "0x5b29c0",
        "delivery_rva": "0x244630",
        "move_rva": "0x1af380",
        "source_errors": source_errors,
    }
    if source_errors:
        report["status"] = "blocked_source_evidence"
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return 1

    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return 1

    command = [
        compiler,
        "-std=c++17",
        "-fno-exceptions",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-O2",
        "-I",
        str(NATIVE),
        str(CPP),
        "-o",
        str(EXE),
    ]
    compiled = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90, check=False)
    compile_stdout = decode(compiled.stdout)
    compile_stderr = decode(compiled.stderr)
    COMPILE_STDOUT.write_text(compile_stdout, encoding="utf-8")
    COMPILE_STDERR.write_text(compile_stderr, encoding="utf-8")
    report["compile"] = {
        "command": command,
        "compiler": compiler,
        "returncode": compiled.returncode,
        "stdout": compile_stdout,
        "stderr": compile_stderr,
    }
    if compiled.returncode != 0:
        report["status"] = "failed_compile"
        report["elapsed_seconds"] = time.time() - started
        write_new_json(REPORT, report)
        return 1

    completed = subprocess.run([str(EXE)], cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=90, check=False)
    run_stdout = decode(completed.stdout)
    run_stderr = decode(completed.stderr)
    RUN_STDOUT.write_text(run_stdout, encoding="utf-8")
    RUN_STDERR.write_text(run_stderr, encoding="utf-8")
    result_line = next((line for line in run_stdout.splitlines()
                        if line.startswith("RESULT ")), None)
    summary_line = next((line for line in run_stdout.splitlines()
                         if line.startswith("SUMMARY ")), None)
    checks = [line for line in run_stdout.splitlines()
              if line.startswith("CHECK ")]
    report["run"] = {
        "command": [str(EXE)],
        "returncode": completed.returncode,
        "stdout": run_stdout,
        "stderr": run_stderr,
        "result_line": result_line,
        "summary_line": summary_line,
    }
    report["observations"] = {
        "check_count": len(checks),
        "checks": checks,
        "result": result_line,
        "summary": summary_line,
        "static_only": True,
    }
    report["artifact"] = file_pin(EXE)
    report["source_pins"].update({
        "header": file_pin(HEADER),
        "test_cpp": file_pin(CPP),
        "python_runner": file_pin(SCRIPT),
    })
    report["status"] = (
        "passed" if completed.returncode == 0 and result_line == "RESULT PASS"
        else "failed_runtime"
    )
    report["elapsed_seconds"] = time.time() - started
    write_new_json(REPORT, report)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
