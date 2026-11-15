"""Survey the existing Win64 entry-patch and trampoline/unwind infrastructure.

This is a bounded source-only survey for the natural battle-entry design.  It
does not inspect the EU4 image, start a process, call REA, read process memory,
inject a patch, or run native tests.  Source facts, the previous survey pin,
and unresolved ABI/lifetime questions remain separate in the output.
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
DEFAULT_OUTPUT = (
    ROOT
    / "work"
    / "runtime"
    / "information-battle-entry-20261025-001"
    / "infrastructure-survey-001.json"
)


def _repo_path(relative: str) -> Path:
    path = (ROOT / relative).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path escapes workspace: {relative}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def _sha256(path: Path) -> tuple[int, str]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"refusing oversized file ({size} bytes): {path}")
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


def _lines(path: Path) -> list[str]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"refusing oversized source ({size} bytes): {path}")
    return path.read_bytes().decode("utf-8-sig").splitlines()


def _selected_text(path: Path, ranges: Iterable[tuple[int, int]]) -> str:
    lines = _lines(path)
    selected: list[str] = []
    for start, end in ranges:
        if start < 1 or end < start or end > len(lines):
            raise ValueError(f"invalid line range {start}-{end} for {path}")
        selected.extend(lines[start - 1 : end])
    return "\n".join(selected)


def _source_pin(
    relative: str,
    role: str,
    ranges: list[tuple[int, int]],
    tokens: list[str],
) -> dict[str, Any]:
    path = _repo_path(relative)
    size, digest = _sha256(path)
    selected = _selected_text(path, ranges)
    missing = [token for token in tokens if token not in selected]
    if missing:
        raise ValueError(f"source guard missing in {relative}: {missing}")
    return {
        "path": relative.replace("\\", "/"),
        "bytes": size,
        "sha256": digest,
        "line_count": len(_lines(path)),
        "line_ranges_inclusive": [[start, end] for start, end in ranges],
        "role": role,
        "token_guards": tokens,
    }


def _artifact_pin(relative: str) -> dict[str, Any]:
    path = _repo_path(relative)
    size, digest = _sha256(path)
    return {"path": relative.replace("\\", "/"), "bytes": size, "sha256": digest}


def _build_report() -> dict[str, Any]:
    # These are deliberately narrow source regions.  They cover each cited
    # invariant without reading a disassembly or a large generated artifact.
    source_specs: list[tuple[str, str, list[tuple[int, int]], list[str]]] = [
        (
            "work/native/entry-patch-transaction.inc",
            "common bounded entry-patch transaction and INT3/VEH barrier",
            [
                (1, 18),
                (29, 107),
                (150, 164),
                (187, 240),
                (284, 337),
                (339, 404),
                (406, 569),
                (571, 619),
                (621, 760),
                (762, 919),
            ],
            [
                "kMaxPatchBytes=32",
                "Published entries are never cleared",
                "entry_patch_vectored_handler",
                "entry_patch_run",
                "entry_patch_enumerate_and_suspend",
                "guarded_patch_retry_pending",
            ],
        ),
        (
            "work/native/alliance-inbound.inc",
            "source-specific near relay/trampoline, dynamic unwind, and rollback",
            [(35, 55), (205, 223), (453, 511), (1293, 1351), (1394, 1425)],
            [
                "constexpr unsigned kPatchBytes=5;",
                "static SIZE_T inbound_trampoline_size=19;",
                "inbound_register_unwind",
                "RtlAddFunctionTable",
                "inbound_release_unpublished",
                "guarded_patch_apply",
                "guarded_patch_rollback",
            ],
        ),
        (
            "work/native/alliance-reason-metadata.inc",
            "source-specific row-constructor trampoline, four-register wrapper, and TLS scope",
            [(29, 46), (192, 211), (336, 391), (393, 455), (462, 539)],
            [
                "constexpr unsigned kPatchBytes=15;",
                "constexpr unsigned kAbsoluteJumpBytes=14;",
                "reason_metadata_register_unwind",
                "RtlAddFunctionTable",
                "reason_metadata_release_unpublished",
                "bridge_alliance_reason_metadata_ctor",
                "thread_local ScopeState",
                "returned=original(",
            ],
        ),
        (
            "work/native/frame_stub.S",
            "existing register-preserving and tail-jump assembly shims",
            [(1, 5), (24, 46), (75, 112), (116, 151), (238, 317), (319, 355), (436, 497)],
            [
                "movq %rcx",
                "movq %rdx",
                "movq %r8",
                "movdqu %xmm0",
                "jmp bridge_wrapper_clone_observe",
                "jmp *bridge_direct_break_original(%rip)",
                "bridge_inbound_predicate_classify",
            ],
        ),
        (
            "work/native/test-entry-patch.cpp",
            "entry transaction, linked-stub unwind, ABI, and concurrent stress fixture",
            [(146, 194), (221, 332), (453, 568), (570, 636), (638, 730), (733, 768)],
            [
                "kPatchSize=15",
                "kTrampolineSize=29",
                "make_trampoline",
                "validate_frame_stub_unwind",
                "validate_wrapper_clone_abi",
                "guarded_patch_apply",
                "guarded_patch_rollback",
                "signature_invalid_published",
            ],
        ),
        (
            "work/native/test-entry-patch.S",
            "assembly ABI fixture and emitted PE unwind directives",
            [(8, 45), (47, 72), (74, 97)],
            [
                ".seh_proc bridge_direct_break_float_stub",
                ".seh_proc fixture_wrapper_clone_caller",
                "copies these bytes",
            ],
        ),
        (
            "work/native/test-generic-execution-entry.cpp",
            "standalone dynamic RUNTIME_FUNCTION and VirtualUnwind fixture",
            [(228, 310), (341, 431)],
            [
                "RtlAddFunctionTable",
                "RtlVirtualUnwind",
                "RtlDeleteFunctionTable",
                "phase=unwind",
            ],
        ),
        (
            "work/native/test-generic-execution-entry.S",
            "direct and virtual-table caller paths for the generic fixture",
            [(1, 48), (50, 126)],
            [
                "generic_entry_original",
                "generic_bridge_response_stub",
                "generic_call_virtual_checked",
            ],
        ),
        (
            "work/native/test-alliance-inbound.cpp",
            "inbound ABI, XMM preservation, and parent-unwind fixture",
            [(110, 140), (153, 264), (374, 428), (430, 443)],
            [
                "fixture_pending_int",
                "test_xmm_restore",
                "test_dynamic_unwind",
                "RtlAddFunctionTable",
                "fixture PASS",
            ],
        ),
        (
            "work/native/test-alliance-inbound.S",
            "inbound call/return and unwind fixture assembly",
            [(1, 93)],
            [".seh_proc fixture_inbound_parent_frame"],
        ),
    ]
    source_pins = [
        _source_pin(path, role, ranges, tokens)
        for path, role, ranges, tokens in source_specs
    ]
    by_name = {Path(item["path"]).name: item["sha256"] for item in source_pins}

    previous = _artifact_pin(
        "work/runtime/information-battle-war-records-20261025-001/passive-hook-infrastructure-001.json"
    )
    previous_script = _artifact_pin("work/survey_information_passive_hook_infrastructure.py")

    return {
        "schema": "information_battle_entry_unwind/infrastructure_survey_v1",
        "status": "source_only_complete_with_entry_size_and_abi_limits",
        "scope": {
            "purpose": "盘点自然战报入口适配所需的既有入口补丁、trampoline、RUNTIME_FUNCTION/unwind、线程生命周期和ABI fixture",
            "performed": [
                "bounded UTF-8 source reads with line-range/token guards",
                "streamed SHA-256 for every cited source and prior survey",
                "machine-derived current source pins; line ranges are inclusive",
            ],
            "not_performed": [
                "EU4 image/disassembly, REA, game process, RPM, injection, or native test execution",
                "selection of a battle hook target or semantic interpretation of a native entry",
            ],
            "evidence_separation": "source facts are ordinary repository evidence; the prior survey is retained as an artifact pin and is not a runtime result",
        },
        "provenance": {
            "previous_survey": previous,
            "previous_survey_script": previous_script,
            "fixed_build_context": {
                "exe_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
                "version": "1.37.4",
                "kind": "handoff context only; no binary read in this survey",
            },
        },
        "source_pins": source_pins,
        "entry_patch_transaction": {
            "path": "work/native/entry-patch-transaction.inc",
            "source_sha256": by_name["entry-patch-transaction.inc"],
            "apis": [
                {
                    "name": "guarded_patch_apply",
                    "lines": [868, 873],
                    "effect": "entry_patch_run(plan,false) installs replacement bytes",
                },
                {
                    "name": "guarded_patch_rollback",
                    "lines": [875, 880],
                    "effect": "the same INT3 barrier restores expected bytes; the original trampoline is retained",
                },
                {
                    "name": "guarded_patch_retry_pending",
                    "lines": [882, 919],
                    "effect": "retries only failed ResumeThread/CloseHandle cleanup; it does not start a new patch transaction",
                },
                {
                    "name": "entry_patch_vectored_handler",
                    "lines": [207, 229],
                    "effect": "redirects only a published target breakpoint to its registered trampoline",
                },
                {
                    "name": "entry_patch_run",
                    "lines": [774, 866],
                    "effect": "validation -> registry/VEH reservation -> page protection -> signature recheck -> INT3 barrier -> suspend/context check -> body/commit -> restore/resume",
                },
            ],
            "bounded_limits": {
                "max_targets": 4,
                "max_patch_bytes": 32,
                "max_registry_targets": 64,
                "max_pages": 8,
                "max_threads": 2048,
                "max_error_records": 256,
            },
            "thread_lifecycle": {
                "suspend_lines": [628, 707],
                "behavior": [
                    "the current thread is excluded; other process threads are enumerated, opened, suspended, and context-read",
                    "a thread RIP inside the patch body is rejected before body write",
                    "ResumeThread and CloseHandle are retried/recorded in bounded pending storage; pending cleanup blocks a new transaction",
                ],
                "currently_executing_entry": "the INT3 VEH can redirect an owned breakpoint to the registered trampoline; this is a barrier mechanism, not proof that a future battle callback is reentrant-safe",
            },
            "publication_and_failure": {
                "prepare_lines": [284, 404],
                "publish_lines": [514, 523],
                "commit_lines": [539, 568],
                "failure_lines": [808, 865],
                "facts": [
                    "target/trampoline protection, range, signatures, overlap, and caller-owned lifetimes are checked before mutation",
                    "the target-to-trampoline registry is published before the first INT3; source bytes are rechecked immediately before the barrier",
                    "barrier-only failures can restore source/protection; a failure after any committed byte is restart_required and leaves the committed image",
                    "after any INT3, published registry entries and their trampolines are intentionally not cleared because a stale cached breakpoint may still redirect there",
                    "the helper performs no logging or file I/O while the barrier or suspended-thread window is active",
                ],
            },
            "common_helper_limit": "the common transaction has no RtlAddFunctionTable/RtlDeleteFunctionTable logic and does not allocate, copy, or free a trampoline; the source-specific owner must provide matching unwind and lifetime policy",
        },
        "trampoline_and_unwind": {
            "alliance_inbound": {
                "path": "work/native/alliance-inbound.inc",
                "source_sha256": by_name["alliance-inbound.inc"],
                "layout": {
                    "patch_bytes": 5,
                    "trampoline_size": 19,
                    "near_block_bytes": 4096,
                    "trampoline_offset": "0x200",
                    "relay_offset": "0x100",
                },
                "lines": {
                    "allocate_near": [460, 474],
                    "register_unwind": [477, 498],
                    "release_unpublished": [500, 511],
                    "install": [1293, 1351],
                    "rollback": [1394, 1425],
                },
                "construction": [
                    "allocates a near block, writes an absolute relay jump, copies a CALL to the original target and an absolute jump to the native return address",
                    "RtlLookupFunctionEntry finds the parent executor recipe and requires the image base to match; one prologue byte is read from parent.UnwindData+1",
                    "the dynamic BeginAddress starts before the trampoline by prologue+0x10 and EndAddress ends at trampoline+19, reusing parent.UnwindData",
                    "RtlAddFunctionTable runs before guarded_patch_apply publishes the entry patch",
                ],
                "lifetime": [
                    "before publication, registration failure or install failure deletes the dynamic table and VirtualFree's the near block",
                    "after publication, the release helper intentionally does not free the block/table; rollback restores bytes but keeps the published route",
                ],
            },
            "alliance_reason_metadata": {
                "path": "work/native/alliance-reason-metadata.inc",
                "source_sha256": by_name["alliance-reason-metadata.inc"],
                "layout": {
                    "patch_bytes": 15,
                    "absolute_jump_bytes": 14,
                    "trampoline_size": 29,
                    "near_block_bytes": 4096,
                    "trampoline_offset": "0x200",
                },
                "lines": {
                    "register_unwind": [360, 379],
                    "release_unpublished": [381, 391],
                    "typed_wrapper": [393, 429],
                    "install": [462, 515],
                    "rollback": [517, 539],
                },
                "construction": [
                    "looks up the row-constructor parent RUNTIME_FUNCTION and requires the image base to match",
                    "copies the 15-byte expected prefix, appends a 14-byte absolute jump to original+15, and registers Begin=trampoline RVA through End=trampoline RVA+29 with source.UnwindData",
                    "publishes the dynamic table before guarded_patch_apply",
                    "the wrapper has the explicit four-register Win64 signature, calls the original once, captures only inside a thread-local depth scope, restores LastError, and returns the native result",
                ],
                "lifetime": [
                    "prepublication failure deletes the table and frees the near block",
                    "once publication has occurred, rollback clears installed flags but does not release the registered trampoline/table",
                ],
            },
            "standalone_fixtures": [
                {
                    "path": "work/native/test-generic-execution-entry.cpp",
                    "source_sha256": by_name["test-generic-execution-entry.cpp"],
                    "lines": [228, 310],
                    "facts": [
                        "constructs matching UNWIND_INFO in an allocated block",
                        "registers a RUNTIME_FUNCTION with RtlAddFunctionTable, looks it up, and runs RtlVirtualUnwind",
                        "checks return RIP/RSP and RBX/RBP/RSI/RDI/R14 restoration",
                        "deletes the dynamic table before freeing the block in the main path",
                    ],
                },
                {
                    "path": "work/native/test-alliance-inbound.cpp",
                    "source_sha256": by_name["test-alliance-inbound.cpp"],
                    "lines": [374, 428],
                    "facts": [
                        "copies a parent unwind recipe into a bounded test block",
                        "registers [0x100,0x120), unwinds a synthetic stack, checks return address/RSP/RBX, then deletes the table and frees allocations",
                    ],
                },
                {
                    "path": "work/native/test-entry-patch.cpp",
                    "source_sha256": by_name["test-entry-patch.cpp"],
                    "lines": [221, 297],
                    "facts": [
                        "checks four points in the linked frame stub with RtlLookupFunctionEntry/RtlVirtualUnwind",
                        "this is a PE-emitted unwind check, not dynamic registration of the caller-owned trampoline",
                    ],
                },
            ],
        },
        "tailjump_abi": {
            "answer": "有可复用的家族级模式，但没有可直接套用于战斗入口的通用ABI证明。",
            "patterns": [
                {
                    "path": "work/native/frame_stub.S",
                    "lines": [36, 46],
                    "kind": "leaf_context_tailjump",
                    "facts": [
                        "RCX/RDX remain the two original arguments",
                        "R8 is replaced with the call return label and R9 with the native caller context",
                        "there is no XMM save in this leaf shim; it is only valid for the proved two-argument surface",
                    ],
                },
                {
                    "path": "work/native/frame_stub.S",
                    "lines": [75, 112],
                    "kind": "callback_then_tailjump",
                    "facts": [
                        "saves/restores volatile GPR RAX/RCX/RDX/R8/R9/R10/R11 and XMM0-XMM5 around the callback",
                        "tail-jumps through bridge_direct_break_original after restoring the caller frame",
                        "the shown code does not establish a promise about XMM6-XMM15 or a new target's argument meaning",
                    ],
                },
                {
                    "path": "work/native/frame_stub.S",
                    "lines": [280, 317],
                    "kind": "reader_callback_tailjump",
                    "facts": [
                        "the wrapper-reader shim saves/restores the same volatile GPR/XMM0-XMM5 set and tail-jumps to its independently captured original",
                        "this is the closest existing generic pass-through shape for a read-only observer",
                    ],
                },
                {
                    "path": "work/native/frame_stub.S",
                    "lines": [436, 497],
                    "kind": "conditional_forward_or_return",
                    "facts": [
                        "the inbound predicate shim saves/restores volatile GPR/XMM0-XMM5 and either returns a classified result or tail-jumps to the original",
                        "it is conditional control flow, not a transparent original-call wrapper for arbitrary battle arguments",
                    ],
                },
            ],
            "test_proof": {
                "path": "work/native/test-entry-patch.cpp",
                "lines": [304, 332],
                "facts": [
                    "the wrapper-clone fixture checks receiver/action/caller marker, exactly one original call, and native return preservation",
                    "the test is a source fixture and does not prove an unselected battle entry signature",
                ],
            },
        },
        "entry_patch_36_bytes": {
            "supported": False,
            "reason": "the common validation rejects input.size > kMaxPatchBytes at entry-patch-transaction.inc:304, while kMaxPatchBytes is 32 at line 32",
            "existing_source_specific_sizes": [
                {"path": "work/native/alliance-inbound.inc", "lines": [40, 40], "bytes": 5},
                {"path": "work/native/alliance-reason-metadata.inc", "lines": [33, 45], "bytes": 15},
                {"path": "work/native/test-entry-patch.cpp", "lines": [146, 194], "bytes": 15, "trampoline_bytes": 29},
            ],
            "limit_interpretation": [
                "a 36-byte target cannot be passed to the existing common transaction and there is no 36-byte test or source-specific unwind proof here",
                "raising the bound alone would not prove instruction-boundary copying, source-matched unwind metadata, near-relay reachability, or the barrier/rollback behavior for a new target",
            ],
        },
        "reusable_native_tests": [
            {
                "path": "work/native/test-generic-execution-entry.cpp",
                "lines": [228, 431],
                "closest_for": "dynamic RUNTIME_FUNCTION registration, lookup, VirtualUnwind, and delete-before-free ordering",
                "status": "source available; not run by this survey",
            },
            {
                "path": "work/native/test-alliance-inbound.cpp",
                "lines": [153, 264],
                "closest_for": "integer/XMM ABI forwarding, controlled versus pass-through behavior, and original return preservation",
                "status": "source available; not run by this survey",
            },
            {
                "path": "work/native/test-entry-patch.cpp",
                "lines": [453, 768],
                "closest_for": "two-target concurrent apply/rollback stress, thread creation race, invalid signature rejection, XMM path, wrapper clone, and pending cleanup",
                "status": "source available; current-source execution is outside this survey",
            },
            {
                "path": "work/native/test-entry-patch.cpp",
                "lines": [221, 297],
                "closest_for": "linked PE .seh/unwind behavior at entry/body/epilogue/tail-jump points",
                "status": "source available; validates emitted PE metadata rather than a dynamic battle trampoline",
            },
        ],
        "future_natural_entry_constraints": [
            "prove the exact native Win64 signature and return/stack/XMM surface before selecting a shim; the existing family wrappers are not a generic ABI",
            "register source-matched RUNTIME_FUNCTION metadata before publishing the patch and retain published trampoline/unwind routes after any INT3",
            "use the common transaction's source signatures, INT3 barrier, thread RIP check, protection restoration, and pending cleanup; treat restart_required as operational failure",
            "state reentry and callback lifetime explicitly: reason metadata has TLS depth, while the common transaction has no semantic reentry filter",
            "do not perform logging/file I/O or game/native calls during the barrier or suspended-thread window; queue only after an independently proven object lifetime",
        ],
        "unresolved": [
            "no battle entry is selected or semantically identified by this source survey",
            "no current-source native run artifact was generated here, so thread timing, unwind registration on the live build, and rollback under a natural entry remain unverified",
            "the source does not prove callback reentry safety, game-object lifetime after original return, or durable event delivery",
            "published VEH entries/trampolines are intentionally retained and bounded; a future owner still needs an explicit capacity and process-shutdown policy",
        ],
        "survey_controls": {
            "max_file_bytes": MAX_FILE_BYTES,
            "source_read_mode": "bounded source reads; SHA-256 streamed in <=1MiB chunks",
            "no_runtime_access": True,
            "no_binary_analysis": True,
            "no_native_test_execution": True,
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
    script = Path(__file__).resolve()
    script_size, script_sha = _sha256(script)
    report["generator"] = {
        "path": script.relative_to(ROOT).as_posix(),
        "bytes": script_size,
        "sha256": script_sha,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    output.write_text(encoded, encoding="utf-8", newline="\n")
    output_size, output_sha = _sha256(output)
    print(
        json.dumps(
            {
                "output": output.relative_to(ROOT).as_posix(),
                "bytes": output_size,
                "sha256": output_sha,
                "status": report["status"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"survey failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
