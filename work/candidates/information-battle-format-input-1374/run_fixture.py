"""Inert-by-default runner for the owned fixed-byte leaf fixture."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


CANDIDATE = Path(__file__).resolve().parent
ROOT = CANDIDATE.parents[2]
STAGE = (
    ROOT
    / "work/runtime/information-diplomacy-state-20261028-001/"
      "battle-body-query-source-001/owned-input-fixture-001"
).resolve()
CONTRACT_PATH = (
    ROOT
    / "work/runtime/information-diplomacy-state-20261028-001/"
      "battle-body-query-source-001/format-input-contract-001.json"
).resolve()
INSTALLATION_PATH = (
    ROOT
    / "work/runtime/diplomacy-observer-20261028-information-resources-v30-005/"
      "installation.json"
).resolve()
def attempt_paths(attempt: int) -> tuple[Path, Path]:
    if attempt == 1:
        return (
            STAGE / "owned-input-fixture-result-001.json",
            STAGE / "owned-leaf-input-fixture.exe",
        )
    return (
        STAGE / f"owned-input-fixture-result-{attempt:03d}.json",
        STAGE / f"owned-leaf-input-fixture-{attempt:03d}.exe",
    )


EXPECTED_CONTRACT_SHA256 = (
    "e9e63128db261db57fbca890f0830371829825f451df602449da114649d65817"
)
EXPECTED_LEAF_HEX = (
    "33c04889114889410848894118488941304889414089415048894158"
    "488bc148c741200f000000c741280200000048c741480f000000"
    "4c894160c3"
)
EXPECTED_LEAF_SHA256 = (
    "1559e1ae0994c722e8a432c98ac6d9bbd85c4d66d6f96a492617b3629c06c75a"
)


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


def write_exclusive(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def verify_attempt_preservation(attempt: int) -> dict:
    index_path = STAGE / f"attempt-{attempt:03d}-preservation-001.json"
    index = json.loads(index_path.read_text(encoding="utf-8-sig"))
    if index.get("status") != "passed" or index.get("attempt") != attempt:
        raise ValueError(f"attempt_preservation_index_invalid:{attempt}")
    for expected in index.get("source_snapshots", []):
        if pin(ROOT / expected["path"]) != expected:
            raise ValueError(f"attempt_source_snapshot_changed:{attempt}:{expected['path']}")
    result_path, exe_path = attempt_paths(attempt)
    if pin(exe_path) != index["original_executable"]:
        raise ValueError(f"attempt_executable_changed:{attempt}")
    if pin(result_path) != index["original_result_receipt"]:
        raise ValueError(f"attempt_result_receipt_changed:{attempt}")
    previous = json.loads(result_path.read_text(encoding="utf-8-sig"))
    if previous.get("attempt", 1) != attempt:
        raise ValueError(f"attempt_result_identity_mismatch:{attempt}")
    return {
        "attempt": attempt,
        "preservation_index": pin(index_path),
        "executable": index["original_executable"],
        "result": index["original_result_receipt"],
        "leaf_invocations": previous.get("leaf_invocations"),
    }


def verify_inputs(attempt: int) -> tuple[dict, list[dict], dict, dict | None]:
    contract_pin = pin(CONTRACT_PATH)
    if contract_pin["sha256"] != EXPECTED_CONTRACT_SHA256:
        raise ValueError("format_input_contract_sha256_mismatch")
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8-sig"))
    if contract.get("status") != "static_contract_closed_pending_owned_fixture_and_live":
        raise ValueError("unexpected_format_input_contract_status")
    if contract.get("target", {}).get("sha256") != (
        "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
    ):
        raise ValueError("contract_target_sha_mismatch")

    constructor = contract.get("constructor", {})
    raw = bytes.fromhex(constructor.get("hex", ""))
    if (
        constructor.get("rva") != "0x6fbfa0"
        or constructor.get("range_exclusive") != "[0x6fbfa0,0x6fbfdb)"
        or constructor.get("bytes") != 59
        or constructor.get("sha256") != EXPECTED_LEAF_SHA256
        or constructor.get("hex") != EXPECTED_LEAF_HEX
        or len(raw) != 59
        or hashlib.sha256(raw).hexdigest() != EXPECTED_LEAF_SHA256
    ):
        raise ValueError("pinned_native_leaf_identity_mismatch")

    evidence_pins = []
    for expected in contract.get("source_pins", []):
        path = (ROOT / expected["path"]).resolve()
        actual = pin(path)
        if actual != expected:
            raise ValueError("contract_source_pin_mismatch:" + expected["path"])
        evidence_pins.append(actual)
    if len(evidence_pins) != 5:
        raise ValueError("contract_expected_five_evidence_source_pins")

    installation_pin = pin(INSTALLATION_PATH)
    installation = json.loads(INSTALLATION_PATH.read_text(encoding="utf-8-sig"))
    if installation.get("game_sha256") != contract["target"]["sha256"]:
        raise ValueError("current_installation_manifest_target_sha_mismatch")
    game_identity = {
        "installation_manifest": installation_pin,
        "recorded_game_sha256": installation["game_sha256"],
        "exe_disk_hash_performed": False,
        "exe_disk_hash_reason": (
            "installation.json records the image SHA but contains no executable path; "
            "the fixture does not inspect or call the game process"
        ),
    }
    preservation = [verify_attempt_preservation(old_attempt)
                    for old_attempt in range(1, attempt)]
    return contract_pin, evidence_pins, game_identity, preservation


def run_test_only(attempt: int) -> int:
    receipt_path, exe_path = attempt_paths(attempt)
    if receipt_path.exists() or exe_path.exists():
        print(json.dumps({"status": "refused", "reason": "output_exists_no_overwrite"}))
        return 2

    receipt = {
        "schema": "information.battle.owned_format_input_fixture.v1",
        "status": "failed",
        "batch": 70,
        "attempt": attempt,
        "execution_mode": "--test-only",
        "started_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "evidence_kind": "owned fixture replay of native leaf bytes",
        "game_or_native_helper_called": False,
        "game_process_attached": False,
        "formatter_called": False,
        "arbitrary_code_execution_interface": False,
        "leaf_invocations": 0,
    }
    try:
        contract_pin, evidence_pins, game_identity, preservation = verify_inputs(attempt)
        receipt["contract"] = contract_pin
        receipt["rea_evidence_source_pins"] = evidence_pins
        receipt["game_identity"] = game_identity
        receipt["preserved_prior_attempts"] = preservation
        receipt["candidate_source_pins"] = [
            pin(CANDIDATE / "format_input_builder.h"),
            pin(CANDIDATE / "owned_leaf_fixture.cpp"),
            pin(CANDIDATE / "run_fixture.py"),
            pin(CANDIDATE / "README.md"),
        ]
        compiler = shutil.which("g++")
        if compiler is None:
            raise FileNotFoundError("g++_not_found")
        compiler = str(Path(compiler).resolve())
        machine = subprocess.run(
            [compiler, "-dumpmachine"], capture_output=True, text=True,
            check=True, timeout=10,
        ).stdout.strip()
        if machine != "x86_64-w64-mingw32":
            raise ValueError("unexpected_owned_fixture_compiler_target:" + machine)
        version = subprocess.run(
            [compiler, "--version"], capture_output=True, text=True,
            check=True, timeout=10,
        ).stdout.splitlines()[0]
        compile_command = [
            compiler,
            "-std=c++20",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            str(CANDIDATE / "owned_leaf_fixture.cpp"),
            "-o",
            str(exe_path),
        ]
        receipt["compiler"] = {
            "path": compiler,
            "target": machine,
            "version": version,
            "command": compile_command,
        }
        compiled = subprocess.run(
            compile_command, cwd=ROOT, capture_output=True, text=True,
            errors="replace", timeout=60,
        )
        receipt["compile"] = {
            "returncode": compiled.returncode,
            "stdout": compiled.stdout[-3000:],
            "stderr": compiled.stderr[-5000:],
        }
        if compiled.returncode != 0:
            raise RuntimeError("owned_fixture_compile_failed")
        receipt["fixture_executable"] = pin(exe_path)

        ran = subprocess.run(
            [str(exe_path)], cwd=ROOT, capture_output=True, text=True,
            errors="replace", timeout=30,
        )
        receipt["run"] = {
            "returncode": ran.returncode,
            "stdout": ran.stdout[-5000:],
            "stderr": ran.stderr[-3000:],
        }
        if ran.returncode != 0:
            raise RuntimeError("owned_fixture_execution_failed")
        result = json.loads(ran.stdout.strip())
        if (
            result.get("status") != "passed"
            or result.get("evidence_kind") != "owned fixture replay of native leaf bytes"
            or result.get("leaf_calls") != 1
            or result.get("eu4_process_called") is not False
            or result.get("game_or_native_helper_called") is not False
            or result.get("formatter_called") is not False
            or result.get("builder_layout_bytes") != 104
            or result.get("checks", 0) < 1
            or result.get("virtual_alloc_rw_to_rx") is not True
            or result.get("virtual_free_verified") is not True
        ):
            raise ValueError("fixture_result_contract_mismatch")
        receipt["fixture_result"] = result
        receipt["leaf_invocations"] = result["leaf_calls"]
        receipt["status"] = "passed"
    except Exception as exc:  # noqa: BLE001 - preserve a one-shot failure receipt.
        receipt["error"] = f"{type(exc).__name__}:{exc}"
    receipt["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    write_exclusive(receipt_path, receipt)
    print(json.dumps({
        "status": receipt["status"],
        "attempt": attempt,
        "receipt": receipt_path.resolve().relative_to(ROOT).as_posix(),
        "fixture_executable": receipt.get("fixture_executable"),
        "leaf_invocations": receipt["leaf_invocations"],
        "error": receipt.get("error"),
    }, ensure_ascii=False))
    return 0 if receipt["status"] == "passed" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--test-only",
        action="store_true",
        help="compile and execute the fixed owned 59-byte leaf fixture once",
    )
    parser.add_argument(
        "--attempt",
        type=int,
        choices=tuple(range(1, 10)),
        default=1,
        help="use a fresh exclusive receipt and binary path; never overwrites an attempt",
    )
    args = parser.parse_args()
    if not args.test_only:
        print(json.dumps({
            "status": "inert",
            "hint": "pass --test-only to compile and execute the owned fixture",
            "compiled": False,
            "executed": False,
        }))
        return 0
    return run_test_only(args.attempt)


if __name__ == "__main__":
    raise SystemExit(main())
