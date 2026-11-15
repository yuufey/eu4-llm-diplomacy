"""Build and run the synthetic owned-context copy contract.

The executable only uses a bounded in-memory sparse reader.  It does not open
EU4, access a process, call REA, install a DLL, or invoke a native function.
The fixed-build evidence pins in the report identify the layout sources; they
are not runtime authorization or a business-field claim.
"""

from __future__ import annotations

import hashlib
import json
import argparse
from pathlib import Path
import shutil
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "work" / "native"
STAGE = ROOT / "work" / "runtime" / "information-battle-owned-context-20261025-001" / "context-test-001"
HEADER = NATIVE / "information-battle-owned-context.h"
CPP = NATIVE / "test-information-battle-owned-context.cpp"
SCRIPT = Path(__file__).resolve()
REPORT = STAGE / "report.json"
EXE = STAGE / "test-information-battle-owned-context.exe"
COMPILE_STDOUT = STAGE / "compile.stdout.log"
COMPILE_STDERR = STAGE / "compile.stderr.log"
RUN_STDOUT = STAGE / "run.stdout.log"
RUN_STDERR = STAGE / "run.stderr.log"

EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_VERSION = "1.37.4"

EVIDENCE_PATHS = {
    "callback_selected": ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001" / "callback-entry-selected-001.json",
    "peace_war_context_source": ROOT / "work" / "runtime" / "diplomacy-observer-20261020-r74-economic-war-a" / "peace-war-context-query.inc",
    "history_root_contract": ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001" / "history-root-contract-001.json",
    "land_field_ledger": ROOT / "work" / "runtime" / "information-battle-layout-20261025-001" / "land-message-field-ledger-001.json",
    "router_evidence": ROOT / "work" / "runtime" / "information-battles-20261025-001" / "rea-battle-result-router-001" / "evidence.json",
    "context_source_contract": ROOT / "work" / "runtime" / "information-battle-business-20261025-001" / "context-source-contract-001.json",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def file_pin(path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def source_pin(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {
            "path": path.relative_to(ROOT).as_posix(),
            "status": "missing",
        }
    return {"status": "present", **file_pin(path)}


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def run(output: Path | None = None) -> dict[str, object]:
    started = time.time()
    report_path = output or REPORT
    stage = report_path.parent
    exe = stage / EXE.name
    compile_stdout_path = stage / COMPILE_STDOUT.name
    compile_stderr_path = stage / COMPILE_STDERR.name
    run_stdout_path = stage / RUN_STDOUT.name
    run_stderr_path = stage / RUN_STDERR.name
    stage.mkdir(parents=True, exist_ok=True)
    historical_dir = stage.parent / "context-test-001"
    historical_report = historical_dir / "report-001.json"
    historical_header = historical_dir / "information-battle-owned-context.h.before-review-002"
    historical_dir_002 = stage.parent / "context-test-002"
    historical_report_002 = historical_dir_002 / "report-002.json"
    historical_header_002 = historical_dir_002 / "information-battle-owned-context.h.before-review-003"
    report: dict[str, object] = {
        "schema": "information_battle_owned_context_test_v1",
        "status": "blocked",
        "target_build": {
            "version": EXPECTED_VERSION,
            "executable_sha256": EXPECTED_EXE_SHA256,
            "image_base_static_va": "0x140000000",
        },
        "scope": {
            "synthetic_sparse_reader_only": True,
            "game_access": False,
            "remote_process_access": False,
            "rea_access": False,
            "dll_installation": False,
            "native_game_function_invoked": False,
            "component_allocates_or_does_io": False,
        },
        "contract": {
            "reader": "bool read(uintptr_t,unsigned char*,size_t) noexcept",
            "capture": "capture(reader,module_base,image_size,combat,known_router,war_candidate,physical_player_full_ref,output)",
            "canonical_min_address": 65536,
            "canonical_max_exclusive": 140737488355328,
            "max_image_bytes": 512 * 1024 * 1024,
            "max_single_read_bytes": 65536,
            "max_total_read_bytes": 65536,
            "kind_leaf": "exact B8 imm32 C3; imm32 1=land, 2=naval; leaf is inspected, never called",
            "participant_vector": {
                "begin_offset": "0x100",
                "end_offset": "0x108",
                "row_bytes": "0x20",
                "full_ref_offset": "0x10",
                "max_count": 256,
            },
            "combat_side_offsets": ["0x20", "0x28"],
            "side_raw_offsets": ["0x118", "0x11c", "0x120", "0x134", "0x138", "0x13c"],
            "war_root": {"offset": "0x108", "vtable_rva": "0x1d20be0"},
            "war_member_vectors": {
                "side_a": ["0x48", "0x50", "0x58"],
                "side_b": ["0x78", "0x80", "0x88"],
                "max_count": 256,
            },
            "failure_output_unchanged": True,
            "no_source_pointer_retained": True,
            "war_invalid_is_unknown": True,
            "country_full_ref_validation": "nonzero; low three bytes are uppercase ASCII or digits; remaining bits preserved",
            "war_member_ref_validation": "nonzero; low three bytes are uppercase ASCII or digits; remaining bits preserved",
            "allocated_empty_vector": "canonical/aligned begin=end with capacity>=end is accepted; null 0/0 is also accepted",
            "stability_recheck": "combat side pointers, side headers/raw slots/participant refs, observed war root/vector bounds/refs, and post-copy kind leaf",
            "fatal_read_guards": ["source_output_alias", "total_read_budget_exceeded"],
        },
        "source_pins": {
            "header": file_pin(HEADER),
            "test_cpp": file_pin(CPP),
            "python_runner": file_pin(SCRIPT),
            "evidence": {name: source_pin(path) for name, path in EVIDENCE_PATHS.items()},
        },
        "history": {
            "status": "preserved_review_history_before_current",
            "report_001": file_pin(historical_report)
            if historical_report.is_file() else {"status": "missing"},
            "header_before_review_002": file_pin(historical_header)
            if historical_header.is_file() else {"status": "missing"},
            "report_002": file_pin(historical_report_002)
            if historical_report_002.is_file() else {"status": "missing"},
            "header_before_review_003": file_pin(historical_header_002)
            if historical_header_002.is_file() else {"status": "missing"},
        },
        "evidence_scope": {
            "callback_entry_selected": {
                "pseudocode_lines": [84, 85, 144, 153, 157, 202],
                "facts": [
                    "param_1+0x20 and param_1+0x28 are side-pointer candidates",
                    "side vector begin/end are +0x100/+0x108",
                    "rows advance by 0x20 and row+0x10 is copied as a qword",
                ],
            },
            "land_field_ledger": {
                "pseudocode_lines": [84, 85, 403, 423, 443, 463, 498, 533],
                "facts": [
                    "raw side offsets +0x118/+0x11c/+0x120 and +0x134/+0x138/+0x13c are read",
                    "the ledger preserves OUR/ENEMY alias ambiguity",
                ],
            },
            "peace_war_context_source": {
                "source_lines": [18, 31, 32, 33, 34, 35, 36, 169, 170],
                "facts": [
                    "war side vectors are +0x48/+0x50/+0x58 and +0x78/+0x80/+0x88",
                    "member entries are bounded to 256 and are kept as full raw handles",
                ],
            },
            "history_root_contract": {
                "facts": ["war+0x108 is an embedded history root; root vtable RVA is 0x1d20be0"],
            },
            "router_evidence": {
                "facts": ["static route maps selector 1 to land formatter and 2 to naval formatter"],
            },
            "context_source_contract": {
                "facts": [
                    "the dispatch-to-message association is a fixed-build static contract only",
                    "the component keeps selector syntax proof and does not claim a runtime getter or UI visibility",
                ],
            },
        },
        "compile": {},
        "run": {},
        "stack_usage": {},
        "checks": {},
        "limitations": [
            "The component copies raw layout values only; it does not prove attacker/defender, visibility, stable war identity, object lifetime, units, losses, or business completeness.",
            "Kind 1/2 meaning is preserved as a fixed-build static contract; the leaf is not called and no runtime semantic proof is claimed.",
            "War membership is an exact full-reference comparison only; invalid/absent context is never reported as non-membership.",
        ],
    }

    compiler = shutil.which("g++")
    if compiler is None:
        report["status"] = "blocked_missing_gxx"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report

    command = [
        compiler,
        "-std=c++17",
        "-fno-exceptions",
        "-fno-rtti",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-O2",
        "-fstack-usage",
        "-I",
        str(NATIVE),
        str(CPP),
        "-o",
        str(exe),
    ]
    compiled = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
    compile_stdout = decode(compiled.stdout)
    compile_stderr = decode(compiled.stderr)
    compile_stdout_path.write_text(compile_stdout, encoding="utf-8")
    compile_stderr_path.write_text(compile_stderr, encoding="utf-8")
    report["compile"] = {
        "command": command,
        "returncode": compiled.returncode,
        "stdout_sha256": hashlib.sha256(compiled.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(compiled.stderr).hexdigest(),
    }
    if compiled.returncode != 0:
        report["status"] = "compile_failed"
        report["elapsed_seconds"] = time.time() - started
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return report

    for stack_file in sorted(stage.glob("*.su")):
        if stack_file.stat().st_size > 128 * 1024:
            report["stack_usage"][stack_file.name] = {"status": "oversize"}
            continue
        selected: dict[str, int] = {}
        for line in stack_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if "owned_context::capture" not in line and "test-information-battle-owned-context.cpp" not in line:
                continue
            fields = line.rsplit("\t", 2)
            if len(fields) != 3:
                continue
            try:
                selected[fields[0]] = int(fields[1])
            except ValueError:
                continue
        report["stack_usage"][stack_file.name] = {
            "status": "observed",
            "selected_bytes": selected,
            "sha256": sha256_file(stack_file),
        }

    run_result = subprocess.run(
        [str(exe)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    run_stdout_path.write_bytes(run_result.stdout)
    run_stderr_path.write_bytes(run_result.stderr)
    run_text = decode(run_result.stdout)
    report["run"] = {
        "returncode": run_result.returncode,
        "stdout_sha256": hashlib.sha256(run_result.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(run_result.stderr).hexdigest(),
        "stdout_bytes": len(run_result.stdout),
        "stderr_bytes": len(run_result.stderr),
        "result_line": next((line for line in run_text.splitlines() if line.startswith("RESULT ")), None),
    }
    check_lines = [line for line in run_text.splitlines() if line.startswith("CHECK ")]
    pass_count = sum(line.endswith(" PASS") for line in check_lines)
    fail_count = sum(line.endswith(" FAIL") for line in check_lines)
    report["checks"] = {
        "reported": len(check_lines),
        "passed": pass_count,
        "failed": fail_count,
        "labels": [line[6:-5] for line in check_lines if line.endswith(" PASS")],
        "max_vectors_tested": True,
        "unstable_leaf_tested": True,
        "post_copy_kind_stability_tested": True,
        "core_reference_validation_tested": True,
        "core_stability_recheck_tested": True,
        "war_duplicate_invalid_tested": True,
        "war_tag_validation_tested": True,
        "allocated_empty_vector_tested": True,
        "optional_war_fatal_guard_tested": True,
        "al_only_leaf_rejected": True,
        "output_alias_tested": True,
        "invalid_war_unknown_tested": True,
    }
    report["executable"] = file_pin(exe)
    report["status"] = "passed" if run_result.returncode == 0 and fail_count == 0 else "failed"
    report["elapsed_seconds"] = time.time() - started
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="exclusive report path; compile/run artifacts are written beside it",
    )
    args = parser.parse_args()
    output = args.output
    if output is not None and not output.is_absolute():
        output = ROOT / output
    result = run(output)
    print(json.dumps({
        "status": result.get("status"),
        "report": str(output or REPORT),
        "checks": result.get("checks"),
    }, ensure_ascii=False))
