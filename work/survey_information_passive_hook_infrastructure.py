"""Survey the existing Win64 entry-patch/trampoline/unwind infrastructure.

This is a bounded source survey.  It does not inspect the EU4 image, start a
process, call REA, or build/run native code.  The output deliberately keeps
source evidence, historical fixture results, and unresolved hook ABI choices
separate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 16 * 1024 * 1024
DEFAULT_OUTPUT = ROOT / "work" / "runtime" / "information-battle-war-records-20261025-001" / "passive-hook-infrastructure-001.json"


def _repo_path(relative: str) -> Path:
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:  # pragma: no cover - defensive output guard
        raise ValueError(f"path escapes workspace: {relative}") from exc
    return path


def _bounded_bytes(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"refusing {size} byte file above bounded limit: {path}")
    data = path.read_bytes()
    if len(data) != size:
        raise OSError(f"short read: {path}")
    return data


def _sha256(path: Path) -> tuple[int, str]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"refusing hash of oversized file: {path}")
    digest = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
    if count != size:
        raise OSError(f"short hash read: {path}")
    return size, digest.hexdigest()


def _text(path: Path) -> list[str]:
    return _bounded_bytes(path).decode("utf-8-sig").splitlines()


def _ranges_text(path: Path, ranges: Iterable[tuple[int, int]]) -> str:
    lines = _text(path)
    selected: list[str] = []
    for start, end in ranges:
        if start < 1 or end < start or end > len(lines):
            raise ValueError(f"invalid line range {start}-{end} for {path}")
        selected.extend(lines[start - 1 : end])
    return "\n".join(selected)


def _source_pin(relative: str, role: str, ranges: list[tuple[int, int]], tokens: list[str]) -> dict[str, Any]:
    path = _repo_path(relative)
    size, digest = _sha256(path)
    selected = _ranges_text(path, ranges)
    missing = [token for token in tokens if token not in selected]
    if missing:
        raise ValueError(f"source guard missing in {relative}: {missing}")
    return {
        "path": relative.replace("\\", "/"),
        "bytes": size,
        "sha256": digest,
        "line_count": len(_text(path)),
        "line_ranges": [[start, end] for start, end in ranges],
        "role": role,
    }


def _artifact_pin(relative: str) -> dict[str, Any]:
    path = _repo_path(relative)
    size, digest = _sha256(path)
    return {"path": relative.replace("\\", "/"), "bytes": size, "sha256": digest}


def _json(relative: str) -> dict[str, Any]:
    path = _repo_path(relative)
    try:
        value = json.loads(_bounded_bytes(path).decode("utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid bounded JSON: {relative}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {relative}")
    return value


def _current_hashes(source_pins: list[dict[str, Any]]) -> dict[str, str]:
    return {Path(item["path"]).name: item["sha256"] for item in source_pins}


def _historical_fixture(relative: str, source_pins: list[dict[str, Any]], summary_fields: list[str]) -> dict[str, Any]:
    report = _json(relative)
    current = _current_hashes(source_pins)
    historical: dict[str, str] = {}
    non_source_artifacts: dict[str, str] = {}
    for item in report.get("sources", []):
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("path")
        digest = item.get("sha256")
        if isinstance(name, str) and isinstance(digest, str):
            basename = Path(name).name
            if basename in current:
                historical[basename] = digest
            else:
                non_source_artifacts[basename] = digest
    comparison = {
        name: {"historical": digest, "current": current.get(name), "matches": current.get(name) == digest}
        for name, digest in sorted(historical.items())
    }
    selected = {field: report[field] for field in summary_fields if field in report}
    if isinstance(report.get("runtime"), dict):
        selected["runtime"] = report["runtime"]
    if isinstance(report.get("checks"), dict):
        selected["checks"] = report["checks"]
    if isinstance(report.get("caveat"), str):
        selected["caveat"] = report["caveat"]
    return {
        "report": _artifact_pin(relative),
        "reported_passed": report.get("passed"),
        "selected_result": selected,
        "historical_source_comparison": comparison,
        "historical_non_source_artifacts": non_source_artifacts,
        "current_source_match": bool(comparison) and all(item["matches"] for item in comparison.values()),
        "interpretation": (
            "historical fixture result; it is current-source evidence only when every listed source hash matches"
        ),
    }


def _build_report() -> dict[str, Any]:
    source_specs: list[tuple[str, str, list[tuple[int, int]], list[str]]] = [
        (
            "work/native/entry-patch-transaction.inc",
            "bounded Windows entry-patch transaction and INT3/VEH barrier",
            [(1, 101), (150, 229), (231, 337), (339, 404), (406, 569), (571, 620), (621, 772), (774, 919)],
            ["AddVectoredExceptionHandler", "entry_patch_publish_barrier", "entry_patch_enumerate_and_suspend", "guarded_patch_retry_pending"],
        ),
        (
            "work/native/test-entry-patch.cpp",
            "isolated transaction, ABI, and linked-stub unwind fixture",
            [(146, 194), (221, 332), (453, 568), (570, 768), (771, 829)],
            ["make_trampoline", "validate_frame_stub_unwind", "validate_wrapper_clone_abi", "signature_invalid_published"],
        ),
        (
            "work/native/test-entry-patch.S",
            "assembly ABI fixture and PE unwind directives",
            [(8, 45), (51, 72), (74, 97)],
            [".seh_proc bridge_direct_break_float_stub", ".seh_proc fixture_wrapper_clone_caller", ".seh_proc fixture_integer_target"],
        ),
        (
            "work/native/frame_stub.S",
            "existing production-style register-preserving/tail-jump shims",
            [(36, 46), (75, 112), (286, 317), (395, 497)],
            ["bridge_wrapper_clone_stub", "bridge_direct_break_stub", "bridge_wrapper_reader_original", "bridge_inbound_predicate_original"],
        ),
        (
            "work/native/test-generic-execution-entry.cpp",
            "standalone trampoline and dynamic RUNTIME_FUNCTION ABI fixture",
            [(145, 168), (209, 310), (341, 465)],
            ["make_trampoline", "RtlAddFunctionTable", "RtlVirtualUnwind", "RtlDeleteFunctionTable"],
        ),
        (
            "work/native/test-generic-execution-entry.S",
            "direct and virtual-table call paths for the generic ABI fixture",
            [(1, 48), (50, 126)],
            ["generic_entry_original", "generic_bridge_response_stub", "generic_call_virtual_checked"],
        ),
        (
            "work/native/alliance-inbound.inc",
            "source-specific near trampoline, unwind registration, and guarded install/rollback",
            [(453, 511), (719, 797), (836, 905), (1259, 1291), (1293, 1351), (1394, 1425)],
            ["inbound_register_unwind", "RtlAddFunctionTable", "inbound_release_unpublished", "guarded_patch_rollback"],
        ),
        (
            "work/native/alliance-reason-metadata.inc",
            "source-specific four-register wrapper, TLS scope, unwind registration, and rollback",
            [(1, 45), (192, 211), (360, 391), (393, 455), (462, 539)],
            ["reason_metadata_register_unwind", "RtlAddFunctionTable", "reason_metadata_release_unpublished", "bridge_alliance_reason_metadata_ctor"],
        ),
        (
            "work/native/alliance-entry-observer.inc",
            "direct-break install/rollback consumer of the common transaction",
            [(1, 22), (31, 54), (81, 120)],
            ["bridge_direct_break_observe", "guarded_patch_apply", "guarded_patch_retry_pending"],
        ),
        (
            "work/native/test-alliance-inbound.cpp",
            "standalone inbound ABI and dynamic unwind test source",
            [(133, 264), (266, 370), (372, 428), (430, 443)],
            ["test_classifier_abi", "test_dynamic_unwind", "RtlDeleteFunctionTable", "fixture PASS"],
        ),
        (
            "work/native/test-alliance-inbound.S",
            "standalone inbound call/return and unwind fixture assembly",
            [(1, 93)],
            [".seh_proc", "fixture_inbound_parent_frame"],
        ),
    ]
    source_pins = [_source_pin(path, role, ranges, tokens) for path, role, ranges, tokens in source_specs]
    source_hashes = _current_hashes(source_pins)

    generic_fixture = _historical_fixture(
        "work/runtime/fixture-generic-execution-entry-20261015-001/verification.json",
        source_pins,
        ["passed", "provenance", "executable"],
    )
    generic_fixture["run_log"] = _artifact_pin("work/runtime/fixture-generic-execution-entry-20261015-001/run.log")
    patch_fixture = _historical_fixture(
        "work/runtime/alliance-query-20261013-r17c/patch-fixture/verification.json",
        source_pins,
        ["passed", "provenance", "abi", "unwind", "runtime", "build"],
    )

    return {
        "schema": "information_battle_records/passive_hook_infrastructure_v1",
        "status": "source_only_complete_with_unresolved_hook_abi",
        "scope": {
            "purpose": "盘点现有 Windows 入口补丁事务、trampoline、展开注册/清理和可复用 ABI fixture，供未来 typed passive wrapper 评估",
            "performed": [
                "bounded source reads and streaming SHA-256",
                "line-range token guards for every cited source",
                "bounded inspection of two existing historical fixture reports",
            ],
            "not_performed": [
                "EU4 binary/whole-image disassembly",
                "REA, game process, RPM, injection, native call, or full test suite",
                "selection of a battle hook semantic or ABI for 237D80/244630",
            ],
            "static_runtime_separation": "source facts and historical fixture outcomes are kept separate; historical outcomes are not promoted when source hashes differ",
        },
        "source_pins": source_pins,
        "entry_patch_transaction": {
            "path": "work/native/entry-patch-transaction.inc",
            "source_sha256": source_hashes["entry-patch-transaction.inc"],
            "apis": [
                {"name": "guarded_patch_apply", "lines": [868, 873], "effect": "install replacement bytes through entry_patch_run(plan,false)"},
                {"name": "guarded_patch_rollback", "lines": [875, 880], "effect": "restore expected bytes through the same INT3 barrier; retained original trampoline"},
                {"name": "guarded_patch_retry_pending", "lines": [882, 919], "effect": "retry only failed ResumeThread/CloseHandle cleanup; gate remains serialized"},
                {"name": "entry_patch_vectored_handler", "lines": [204, 229], "effect": "redirect only EXCEPTION_BREAKPOINT at published target to its registered trampoline"},
                {"name": "entry_patch_run", "lines": [774, 866], "effect": "validation → reserve → VEH → page protection → recheck → INT3 → suspend/context check → body/commit → restore/resume"},
            ],
            "bounded_limits": {"max_targets": 4, "max_patch_bytes": 32, "max_registry_targets": 64, "max_pages": 8, "max_threads": 2048, "max_error_records": 256},
            "invariants": [
                "expected/replacement arrays and the executable original trampoline are caller-owned; this helper does not allocate, copy, or free the trampoline",
                "the process-local Interlocked gate rejects concurrent transactions as busy; pending thread cleanup also blocks a new transaction",
                "target and trampoline ranges/protection/signatures are validated before mutation; target overlaps and breakpoint signatures are rejected",
                "the immutable target→trampoline VEH registry is populated before the first INT3; first-byte CC is atomically published and instruction cache is flushed",
                "all non-current process threads are enumerated, suspended, context-read, and rejected if RIP is inside the patch body before body write",
                "page protection is restored and every suspended thread is resumed before success is reported",
            ],
            "rollback_and_cleanup": [
                "barrier-only failures restore source bytes under INT3 and restore page protection; source signatures are rechecked before commit",
                "a failed ResumeThread or CloseHandle is kept in bounded pending storage; retry_pending is required before another transaction",
                "a failure after any committed byte is restart_required and deliberately leaves the committed image rather than claiming safe rollback",
                "once any target emitted INT3, registry entries and trampolines are retained; removing the VEH/freeing a trampoline could redirect a stale cached breakpoint to invalid memory",
                "no logging or file I/O is performed while the barrier or thread suspension is active",
            ],
            "limitations": [
                "the helper has no dynamic RtlAddFunctionTable/RtlDeleteFunctionTable logic; source-specific owners must register a matching unwind recipe",
                "the helper guarantees transaction safety and byte-image state, not the future wrapper's native argument meaning or exactly-once original-call policy",
            ],
        },
        "trampoline_and_unwind": {
            "common_pattern": [
                {"path": "work/native/test-entry-patch.cpp", "lines": [169, 194], "facts": ["VirtualAlloc 29-byte RW block", "copy 15-byte prologue", "absolute jump to target+15", "VirtualProtect RX and FlushInstructionCache", "caller retains code"]},
                {"path": "work/native/frame_stub.S", "lines": [75, 112], "facts": [".seh_proc direct-break shim", "save volatile GPR/XMM", "callback", "restore registers", "tail-jump through bridge_direct_break_original"]},
                {"path": "work/native/frame_stub.S", "lines": [36, 46], "facts": ["wrapper clone leaf preserves original two arguments and forwards caller context in R8/R9", "tail-jump to observer"]},
            ],
            "dynamic_unwind_helpers": [
                {
                    "path": "work/native/alliance-inbound.inc",
                    "source_sha256": source_hashes["alliance-inbound.inc"],
                    "register_lines": [477, 498],
                    "cleanup_lines": [500, 511],
                    "install_lines": [1293, 1351],
                    "rollback_lines": [1394, 1425],
                    "facts": [
                        "RtlLookupFunctionEntry locates the parent executor recipe; the base must match",
                        "the prologue byte is read from parent.UnwindData+1; the registered range begins before the trampoline so body PCs use the copied parent recipe",
                        "RtlAddFunctionTable registers the runtime function before entry publication",
                        "pre-publication failures delete the dynamic table and VirtualFree the near block; after publication the release helper intentionally does not free it",
                        "the same source-specific install then calls guarded_patch_apply; rollback validates current bytes and requires success, threads_resumed, and protection_restored",
                    ],
                },
                {
                    "path": "work/native/alliance-reason-metadata.inc",
                    "source_sha256": source_hashes["alliance-reason-metadata.inc"],
                    "register_lines": [360, 379],
                    "cleanup_lines": [381, 391],
                    "install_lines": [462, 515],
                    "rollback_lines": [517, 539],
                    "facts": [
                        "RtlLookupFunctionEntry locates the row-constructor recipe and requires the image base to match",
                        "the dynamic RUNTIME_FUNCTION covers trampoline_rva through trampoline_rva+size and reuses source.UnwindData",
                        "pre-publication failure deletes the table and frees the near block; successful publication retains both for stale-breakpoint safety",
                        "bridge_alliance_reason_metadata_ctor has an explicit four-register Win64 type, calls the original trampoline once, captures only inside a thread-local depth scope, restores post-call LastError, and returns the native result",
                    ],
                },
            ],
            "standalone_unwind_tests": [
                {
                    "path": "work/native/test-generic-execution-entry.cpp",
                    "lines": [228, 310],
                    "facts": [
                        "constructs matching UNWIND_INFO in an allocated block",
                        "registers RUNTIME_FUNCTION with RtlAddFunctionTable",
                        "looks it up and calls RtlVirtualUnwind",
                        "checks return RIP/RSP and RBX/RBP/RSI/RDI/R14 restoration",
                        "caller deletes the function table before freeing the block",
                    ],
                },
                {
                    "path": "work/native/test-alliance-inbound.cpp",
                    "lines": [374, 428],
                    "facts": [
                        "copies a parent unwind recipe into a bounded test block",
                        "registers [0x100,0x120), unwinds a synthetic stack, checks return address/RSP/RBX, deletes the table, and frees both allocations",
                    ],
                },
                {
                    "path": "work/native/test-entry-patch.cpp",
                    "lines": [221, 297],
                    "facts": [
                        "checks four points in the actual linked PE stub with RtlLookupFunctionEntry/RtlVirtualUnwind",
                        "this validates emitted PE metadata, not dynamic registration of the caller-owned trampoline",
                    ],
                },
            ],
        },
        "reusable_abi_tests": [
            {
                "path": "work/native/test-entry-patch.cpp",
                "lines": [304, 332],
                "invariants": ["callback sees receiver/action/return-label/caller-marker", "two-argument original is called exactly once", "native return value is preserved", "bad counter remains zero"],
                "status": "historical_fixture_only_until_current_source_is_rebuilt",
            },
            {
                "path": "work/native/test-entry-patch.cpp",
                "lines": [512, 568],
                "invariants": ["multi-thread two-target apply/rollback stress", "invalid signature never publishes", "source bytes are restored", "pending cleanup is drained"],
                "status": "historical_fixture_only_until_current_source_is_rebuilt",
            },
            {
                "path": "work/native/test-generic-execution-entry.cpp",
                "lines": [170, 191],
                "invariants": ["direct and virtual-table calls each enter the gate once", "allowed call invokes original exactly once", "blocked call invokes original zero times", "nonvolatile register mask is preserved"],
                "status": "source_matches_historical_fixture_report",
            },
            {
                "path": "work/native/test-alliance-inbound.cpp",
                "lines": [153, 264],
                "invariants": ["classifier ABI forwards all tested registers and return point", "controlled path skips original and uses pending return", "noncontrolled integer and XMM paths call original once and preserve return", "source includes a separate dynamic-unwind test"],
                "status": "test_source_available_not_run_by_this_survey",
            },
        ],
        "historical_fixture_results": {
            "generic_execution_entry": generic_fixture,
            "entry_patch_transaction": patch_fixture,
            "interpretation": "The generic fixture source hashes match current source and its recorded run passed. The r17c entry-patch report is retained as historical evidence; its test-entry-patch.cpp/.S and frame_stub.S hashes do not match current source, so it is not a current-source pass claim.",
        },
        "future_typed_passive_wrapper_constraints": [
            "Prove the target's exact native Win64 signature and return/stack surface before choosing a shim; existing family shims are not a generic ABI.",
            "Call the original through one stable trampoline exactly once and tail-jump/return the native result unchanged; a callback counter in a fixture is not proof for a new target.",
            "Use the common transaction's expected/replacement signature checks and thread barrier; do not free a published trampoline or unregister its unwind/VEH route after an INT3 has existed.",
            "Register a source-matched RUNTIME_FUNCTION before publishing the patch and delete/free only on a pre-publication failure; the two existing production helpers use different registration ranges.",
            "Keep hook reentry policy explicit. Existing reason metadata uses TLS depth and bounded records, while inbound uses TLS scope plus exact caller/action/shape checks; entry_patch_transaction itself has no semantic reentry filter.",
            "Do not perform logging, file I/O, or game/native calls inside the patch barrier/suspended-thread window; queue/copy only after the original return under an independently proven lifetime contract.",
            "Treat restart_required, pending handles, failed protection restore, and failed rollback as operational failure requiring reconciliation, never as a successful passive capture.",
        ],
        "unresolved": [
            "No passive battle hook is selected here and no semantic meaning is assigned to 237D80 or 244630.",
            "No current-source run artifact exists for the latest test-entry-patch.cpp/.S/frame_stub.S combination; rebuild/run is outside this source-only survey.",
            "The source helpers do not prove cross-thread callback reentry safety, callback lifetime of game objects, or durable event delivery.",
            "The current entry patch table is bounded at 64 published targets and intentionally retains published entries; a future component needs an explicit capacity and shutdown policy.",
        ],
        "survey_controls": {
            "max_file_bytes": MAX_FILE_BYTES,
            "source_read_mode": "bounded UTF-8 source reads; SHA-256 streamed in <=1MiB chunks",
            "no_runtime_access": True,
            "no_binary_analysis": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output = output.resolve()
    try:
        output.relative_to(ROOT)
    except ValueError as exc:
        raise SystemExit(f"output escapes workspace: {output}") from exc
    output.parent.mkdir(parents=True, exist_ok=True)
    report = _build_report()
    script_rel = Path(__file__).resolve().relative_to(ROOT).as_posix()
    script_size, script_sha = _sha256(Path(__file__).resolve())
    report["generator"] = {"path": script_rel, "bytes": script_size, "sha256": script_sha}
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    output.write_text(encoded, encoding="utf-8", newline="\n")
    out_size, out_sha = _sha256(output)
    print(json.dumps({"output": output.relative_to(ROOT).as_posix(), "bytes": out_size, "sha256": out_sha, "status": report["status"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"survey failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
