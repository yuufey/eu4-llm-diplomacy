"""Run the offline native producer chain for a real v5 payload.

The default invocation and ``--help`` are inert.  Only an explicit ``--run``
compiles and executes the small C++ fixture.  The fixture reads a caller-
provided decoder-accepted v5 file, captures synthetic native text objects,
encodes the v6 NTXT envelope with the native C++ producer, and writes a new
output file exactly once.  No game, RPM, REA, or observer component is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = (ROOT / "work" / "runtime" /
         "information-battle-native-text-20261027-001" /
         "native-text-chain-001")
CPP = NATIVE / "tests" / "information-battle-native-text-chain.cpp"
HEADER = NATIVE / "information-battle-native-text-wire.h"
OWNED = NATIVE / "information-battle-owned-native-text.h"
RUNNER = Path(__file__).resolve()
EXECUTABLE = STAGE / "information-battle-native-text-chain.exe"
REPORT = STAGE / "report.json"

DEFINITION = b"LANDBATTLEOVER"
AUXILIARY = b""
TITLE = b"Fixture battle title"
LINE1 = b"Fixture line 1"
RAW_FLAG_8C = 0xA1
RAW_FLAG_8D = 0x5E


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def pin(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix()
        if path.is_relative_to(ROOT) else str(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _resolve_path(value: Path) -> Path:
    return value if value.is_absolute() else (ROOT / value).resolve()


def run(base_path: Path, raw_date: int, output_path: Path) -> dict[str, Any]:
    if not base_path.exists() or not base_path.is_file():
        raise FileNotFoundError(str(base_path))
    if output_path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{output_path}")
    if base_path.stat().st_size > 512 * 1024:
        raise ValueError("base_v5_over_bound")
    base = base_path.read_bytes()

    # Import the composed decoder only behind the explicit --run gate.
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from work.information_battle_native_text_wire import (  # type: ignore
        decode,
        decode_envelope,
        validate_base_v5,
    )

    checks: dict[str, bool] = {}
    checks["input_is_decoder_accepted_v5"] = validate_base_v5(base)
    if not checks["input_is_decoder_accepted_v5"]:
        raise ValueError("input_v5_payload_rejected_by_composed_decoder")

    STAGE.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which("g++") or shutil.which("clang++")
    if compiler is None:
        raise RuntimeError("no_cxx_compiler")
    command = [
        compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic",
        "-O2", "-I", str(NATIVE), str(CPP), "-o", str(EXECUTABLE),
    ]
    compiled = subprocess.run(command, cwd=ROOT, check=False,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=90)
    (STAGE / "compile.stdout.log").write_text(compiled.stdout,
                                                encoding="utf-8")
    (STAGE / "compile.stderr.log").write_text(compiled.stderr,
                                                encoding="utf-8")
    if compiled.returncode != 0 or not EXECUTABLE.exists():
        raise RuntimeError(f"native_compile_failed:{compiled.stderr[-4000:]}")

    run_command = [
        str(EXECUTABLE), "--base-v5", str(base_path),
        "--raw-date", str(raw_date), "--output", str(output_path),
    ]
    executed = subprocess.run(run_command, cwd=ROOT, check=False,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, timeout=90)
    (STAGE / "run.stdout.log").write_text(executed.stdout, encoding="utf-8")
    (STAGE / "run.stderr.log").write_text(executed.stderr, encoding="utf-8")
    native_checks = [line for line in executed.stdout.splitlines()
                     if line.startswith("CHECK ")]
    checks["native_result_pass"] = (
        executed.returncode == 0
        and "RESULT PASS" in executed.stdout
        and bool(native_checks)
        and all(line.endswith(" PASS") for line in native_checks)
    )
    if not checks["native_result_pass"]:
        result = {
            "schema": "information_battle_native_text_chain_fixture_v1",
            "status": "failed",
            "checks": checks,
            "native_stdout": executed.stdout,
            "native_stderr": executed.stderr,
            "command": run_command,
        }
        REPORT.write_text(json.dumps(result, indent=2) + "\n",
                          encoding="utf-8")
        return result

    if not output_path.exists():
        checks["output_file_created"] = False
        raise RuntimeError("native_output_missing")
    output = output_path.read_bytes()
    checks["output_within_wire_bound"] = len(output) <= 512 * 1024
    envelope = decode_envelope(output)
    composed = decode(output)
    base_hex = base.hex()
    checks["composed_decode_passed"] = True
    checks["embedded_v5_bytes_exact"] = envelope["base_v5_payload_hex"] == base_hex
    checks["composed_base_v5_bytes_exact"] = (
        composed.get("base_v5_payload_hex") == base_hex
    )
    checks["native_date_exact"] = (
        envelope["message_metadata"]["native_date"]["state"] == "observed"
        and envelope["message_metadata"]["native_date"]["value"] == raw_date
    )
    flags = envelope["message_metadata"]["raw_flags"]
    checks["raw_flags_exact"] = (
        flags["state"] == "observed"
        and flags["raw_flag_8c"] == RAW_FLAG_8C
        and flags["raw_flag_8d"] == RAW_FLAG_8D
    )
    fields = envelope["text_fields"]
    expected_fields = {
        "definition_key": ("message_metadata", DEFINITION.hex()),
        "auxiliary_text": ("message_metadata", AUXILIARY.hex()),
        "title_helper_candidate": ("title_helper_candidate", TITLE.hex()),
        "line1_text": ("native_line1", LINE1.hex()),
    }
    for name, (source, raw_hex) in expected_fields.items():
        value = fields[name]
        checks[f"{name}_raw_and_source_exact"] = (
            value["status"] == "known"
            and value["state"] == "observed"
            and value["source"] == source
            and value["raw_hex"] == raw_hex
        )
    checks["all_four_text_fields_observed"] = all(
        checks[f"{name}_raw_and_source_exact"] for name in expected_fields
    )
    checks["native_text_remains_partial"] = (
        composed["native_text"]["complete"] is False
        and composed["native_text"]["full_display_complete"] is False
    )
    checks["wire6_validated_by_composed_decoder"] = True
    result = {
        "schema": "information_battle_native_text_chain_fixture_v1",
        "status": "passed" if all(checks.values()) else "failed",
        "checks": checks,
        "base_v5": pin(base_path),
        "output_v6": pin(output_path),
        "output_v6_sha256": sha256_bytes(output),
        "raw_date": raw_date,
        "native_stdout": executed.stdout,
        "native_stderr": executed.stderr,
        "native_check_count": len(native_checks),
        "compile": {
            "compiler": compiler,
            "command": command,
            "returncode": compiled.returncode,
        },
        "run": {"command": run_command, "returncode": executed.returncode},
        "sources": {
            str(path.relative_to(ROOT)).replace("\\", "/"): pin(path)
            for path in (CPP, HEADER, OWNED, RUNNER)
        },
        "synthetic_inputs": {
            "definition_key": "LANDBATTLEOVER",
            "auxiliary_text": "",
            "title_helper_candidate": "Fixture battle title",
            "native_line1": "Fixture line 1",
            "all_values_are_synthetic": True,
            "native_offsets": {
                "definition_key_object": "0x38",
                "message_auxiliary_object": "0x60",
                "message_date": "0x88",
            },
        },
        "scope": {
            "game": False,
            "rpm": False,
            "rea": False,
            "observer_or_dll": False,
            "production_claim": False,
            "native_producer": True,
            "python_encode_used": False,
        },
    }
    REPORT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="compile/run the native producer fixture")
    parser.add_argument("--base-v5", type=Path,
                        help="caller-provided decoder-accepted v5 payload")
    parser.add_argument("--raw-date", type=int,
                        help="synthetic message +0x88 signed int32")
    parser.add_argument("--output", type=Path,
                        help="new v6 output path; existing files are rejected")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({
            "status": "idle",
            "hint": "pass --run with --base-v5, --raw-date and --output",
        }, ensure_ascii=False))
        return 0
    if args.base_v5 is None or args.raw_date is None or args.output is None:
        parser.error("--run requires --base-v5, --raw-date and --output")
    if not -(1 << 31) <= args.raw_date < (1 << 31):
        parser.error("--raw-date must be a signed int32")
    try:
        result = run(_resolve_path(args.base_v5), args.raw_date,
                     _resolve_path(args.output))
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)},
                         ensure_ascii=False))
        return 1
    print(json.dumps({"status": result["status"], "checks": result["checks"],
                      "output_v6": result.get("output_v6")},
                     ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
