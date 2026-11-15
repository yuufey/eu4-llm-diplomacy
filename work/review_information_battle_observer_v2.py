#!/usr/bin/env python3
"""Second, bounded source review of the frozen v23 observer revision.

The first review is intentionally left reproducible and untouched.  This
revision records which findings are actually present in the newer source,
which fixes are visible in source, and which items remain an explicit runtime
or contract boundary.  It never loads a DLL, starts a game, calls REA, or
dispatches a control file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
MAX_READ = 4 * 1024 * 1024
OBSERVER = ROOT / "work/native/information-battle-observer.inc"
HOST = ROOT / "work/native/diplomacy-observer-v10.cpp"
DEPS = (
    ROOT / "work/native/information-battle-buffer.h",
    ROOT / "work/native/information-battle-drain.h",
    ROOT / "work/native/information-battle-log-writer.h",
    ROOT / "work/native/information-battle-observation-wire.h",
    ROOT / "work/native/information-battle-entry-plan.h",
)
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-battle-observer-20261025-001/"
    "manager-review-002.json"
)


def read(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_READ:
        raise ValueError(f"bounded read refused {path}: {size} bytes")
    return path.read_bytes()


def lines(path: Path) -> list[str]:
    return read(path).decode("utf-8", errors="strict").splitlines()


def pin(path: Path) -> dict[str, object]:
    data = read(path)
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def ref(path: Path, source: list[str], needle: str, occurrence: int = 1) -> dict[str, object]:
    count = 0
    for number, text in enumerate(source, 1):
        if needle in text:
            count += 1
            if count == occurrence:
                return {
                    "path": path.relative_to(ROOT).as_posix(),
                    "line": number,
                    "text": text.strip(),
                }
    raise RuntimeError(f"missing review anchor {path}:{needle!r} occurrence={occurrence}")


def item(
    ident: str,
    status: str,
    severity: str | None,
    title: str,
    consequence: str,
    minimum_fix: str,
    refs: Iterable[dict[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {
        "id": ident,
        "status": status,
        "title": title,
        "consequence": consequence,
        "minimum_fix": minimum_fix,
        "evidence": list(refs),
    }
    if severity is not None:
        result["severity"] = severity
    return result


def build() -> dict[str, object]:
    ob = lines(OBSERVER)
    host = lines(HOST)
    buf = lines(DEPS[0])
    drain = lines(DEPS[1])
    writer = lines(DEPS[2])
    wire = lines(DEPS[3])
    plan = lines(DEPS[4])

    # Fail closed if the source moves before this report is regenerated.
    anchors = [
        ref(OBSERVER, ob, "GetFileAttributesW(nonce_receipt)!=INVALID_FILE_ATTRIBUTES"),
        ref(OBSERVER, ob, "if (!identity.valid() || (source_state!=enabled && source_state!=disabled)) return;"),
        ref(OBSERVER, ob, "if (!code_guard() || !context(g,p,date) || g!=game || p!=player || date<last_date) {"),
        ref(OBSERVER, ob, "date<last_date || !code_guard())"),
        ref(OBSERVER, ob, "source_row->BeginAddress==kEntryRva"),
        ref(OBSERVER, ob, "status(\"\",\"startup\",true,\"awaiting_process_bound_enable\",false)"),
        ref(HOST, host, "information_battle_tick();"),
        ref(DEPS[0], buf, "result.consistent = false;"),
        ref(DEPS[1], drain, "DrainResult drain(Sink&& sink, std::size_t max_records) noexcept"),
        ref(DEPS[2], writer, "bool close() noexcept {"),
        ref(DEPS[3], wire, "constexpr std::size_t kMaxWireBytes = 16384u;"),
        ref(DEPS[4], plan, "inline bool valid_code_address"),
    ]

    resolved = [
        item(
            "FIX-001",
            "resolved_in_source",
            None,
            "terminal flush gate",
            "flush now refuses source_changed, fault, and restart_required at entry while retaining pending state; enabled/disabled remain the explicitly permitted delivery states.",
            "Keep the entry gate and add an epoch check if lifecycle calls can run concurrently; see remaining OBS2-002.",
            [
                ref(OBSERVER, ob, "const auto source_state=state.load(std::memory_order_acquire);"),
                ref(OBSERVER, ob, "if (!identity.valid() || (source_state!=enabled && source_state!=disabled)) return;"),
                ref(OBSERVER, ob, "if (drained.status==battle::DrainStatus::sink_rejected || writer.fault_latched())"),
            ],
        ),
        item(
            "FIX-002",
            "resolved_in_source",
            None,
            "bound status/disable player identity",
            "When identity is bound, command validation now requires the installation and expected player to match the bound player before writing the started receipt or mutating state.",
            "Retain the unbound-state policy as an explicit protocol rule.",
            [ref(OBSERVER, ob, "identity.valid()&&(identity.installation!=installation || expected_player!=player)")],
        ),
        item(
            "FIX-003",
            "resolved_in_source",
            None,
            "generation and old-log collision guard",
            "The stream generation is now the process creation FILETIME, and first enable refuses an existing raw log before resetting/opening the queue.",
            "Keep the creation value in the durable stream header and response contract.",
            [
                ref(OBSERVER, ob, "drain.reset({installation,creation})"),
                ref(OBSERVER, ob, "GetFileAttributesW(log_path)!=INVALID_FILE_ATTRIBUTES"),
                ref(OBSERVER, ob, "identity={installation,creation}"),
            ],
        ),
        item(
            "FIX-004",
            "resolved_in_source",
            None,
            "startup process/DLL lease and PE identity",
            "Startup holds read/share-read handles for the main EXE and observer DLL before hashing, and file_identity validates the main module base, PE64 image size, target .pdata row, creation time, and both SHA-256 values.",
            "Keep the lease-before-hash order and process-lifetime lease contract explicit; the failure-retention choice is recorded below.",
            [
                ref(OBSERVER, ob, "exe_lease=CreateFileW(exe,GENERIC_READ,FILE_SHARE_READ"),
                ref(OBSERVER, ob, "source_row->EndAddress==0x23a015 && source_row->UnwindData==kUnwindRva"),
                ref(OBSERVER, ob, "hash_file(exe,exe_hash) && !strcmp(exe_hash,kExeSha)"),
            ],
        ),
        item(
            "FIX-005",
            "resolved_in_source",
            None,
            "pre-publication status and failure fields",
            "The status schema now exposes publication_stage, patch_attempt_published, patch_failure_stage, and stats_consistent=false; startup status failure latches fault.",
            "Keep these fields tied to the actual immutable patch result.",
            [
                ref(OBSERVER, ob, r'\"publication_stage\":%u'),
                ref(OBSERVER, ob, r'\"published_resources_process_lifetime\":true'),
                ref(OBSERVER, ob, "state.store(fault,std::memory_order_release);return false;"),
            ],
        ),
        item(
            "FIX-006",
            "resolved_in_source",
            None,
            "capture commit guard",
            "The callback now checks context/date/code/state again after copying before publishing the slot, and flush faults on sink rejection or a latched writer fault.",
            "Serialize the lifecycle epoch with the final slot commit; see remaining OBS2-002.",
            [
                ref(OBSERVER, ob, "&& target.result.raw_date==date && code_guard()"),
                ref(OBSERVER, ob, "&& state.load(std::memory_order_acquire)==enabled;"),
                ref(OBSERVER, ob, "if (drained.status==battle::DrainStatus::sink_rejected || writer.fault_latched()) state.store(fault"),
            ],
        ),
        item(
            "FIX-007",
            "resolved_in_source",
            None,
            "host tick placement and date regression",
            "The host invokes information_battle_tick outside the legacy thread-gated work block; the observer latches source_changed on a thread change and rejects backwards dates.",
            "Keep same-address/same-date reload as an explicit unresolved load signal, not as an inferred success.",
            [
                ref(HOST, host, "information_battle_tick();"),
                ref(OBSERVER, ob, 'status("","heartbeat",false,"frame_thread_changed",false);'),
                ref(OBSERVER, ob, "date<last_date || !code_guard())"),
            ],
        ),
    ]

    remaining = [
        item(
            "OBS2-001",
            "remaining_bug",
            "high",
            "started receipt can permanently suppress an unfinished command",
            "command writes information-battle-started-N.json before disable/status/enable and never finalizes that receipt. If the process dies or response publication fails after the receipt but before the final response, a retry sees duplicate_request and is suppressed even when the mutation did not happen; the caller has no final result. The receipt text explicitly says started_outcome_requires_response.",
            "Make the receipt a durable state machine: atomically record started, then finalize it with the command result and response fingerprint. On replay, recover a started-only entry or expose its in-progress/final outcome instead of silently discarding the retry.",
            [
                ref(OBSERVER, ob, r'\"result\":\"started_outcome_requires_response\"'),
                ref(OBSERVER, ob, "!write_json(nonce_receipt,receipt,receipt_bytes,CREATE_NEW)"),
                ref(OBSERVER, ob, "if (!strcmp(verb,\"disable\")) {"),
                ref(OBSERVER, ob, "if (!status(nonce,verb,ok,reason,!duplicate) || !DeleteFileW(processing_path))"),
            ],
        ),
        item(
            "OBS2-002",
            "remaining_bug",
            "high",
            "state epoch is still racy with capture and fragment publication",
            "The final callback state/code check is inside capture_lock, but tick and command transition state without that lock. A concurrent wrong-thread lifecycle call can set source_changed after the final check and before count/publish. flush snapshots state only once; if state changes after that snapshot, it can still drain/push the old identity. The same owner-thread assumption is not encoded as a synchronization barrier for these lifecycle writes.",
            "Protect state transitions with capture_lock or a monotonically checked epoch. Recheck the epoch before incrementing count and before each fragment push; on invalidation quarantine the pending observation and stop the writer for that identity.",
            [
                ref(OBSERVER, ob, "state.store(source_changed,std::memory_order_release);", 3),
                ref(OBSERVER, ob, "&& state.load(std::memory_order_acquire)==enabled;"),
                ref(OBSERVER, ob, "const auto source_state=state.load(std::memory_order_acquire);"),
                ref(OBSERVER, ob, "auto pushed=drain.push(identity,fragment,part.written_bytes);"),
            ],
        ),
        item(
            "OBS2-004",
            "remaining_guard_gap",
            "medium",
            "runtime code_guard does not revalidate the target RUNTIME_FUNCTION row",
            "file_identity validates the .pdata row through RtlLookupFunctionEntry at startup/enable, but enabled ticks/captures call code_guard, which only compares 36 code bytes and 32 UNWIND_INFO bytes. An in-memory change to the .pdata row/handler ownership after enable can therefore leave the byte guard passing while the active unwind lookup no longer matches the pinned row.",
            "Cache the expected row fields and revalidate RtlLookupFunctionEntry/row ownership on the owner tick, or explicitly state that .pdata memory is immutable under the host and expose that assumption in the status contract.",
            [
                ref(OBSERVER, ob, "auto source_row=RtlLookupFunctionEntry(base+kEntryRva+1,&source_base,nullptr)"),
                ref(OBSERVER, ob, "if (!entry::valid_code_address(base,0x233fe60) || !reader.read(base+kEntryRva,code,sizeof(code))"),
                ref(OBSERVER, ob, "if (thread_changed || GetCurrentThreadId()!=bound_thread || !context(g,p,date)"),
            ],
        ),
    ]

    contract_choices = [
        item(
            "CHOICE-001",
            "explicit_contract_boundary",
            None,
            "process-lifetime patch/table/DLL retention",
            "The source explicitly retains published patch, VEH, unwind table, trampoline, and DLL until process exit, including after disable. This is a chosen lifecycle contract for the observer and is not treated as an unsafe-unload bug in this review.",
            "Keep disable documented as capture stop only and require process exit for resource reclamation.",
            [
                ref(OBSERVER, ob, "Published code, VEH routes, unwind rows and the"),
                ref(OBSERVER, ob, r'\"published_resources_process_lifetime\":true'),
            ],
        ),
        item(
            "CHOICE-004",
            "explicit_contract_boundary",
            None,
            "process-lifetime EXE/DLL identity leases",
            "Startup opens the main EXE and observer DLL with read/share-read handles before hashing and deliberately keeps those leases to process exit, including a failed fixed-hash startup. This prevents a validated file from being replaced during the source lifetime and is exercised by the fixture contract; it is not classified as a cleanup bug here.",
            "If retryable in-process startup is ever required, add an explicit lease-release/reset operation and revise the fixture contract; until then retain the fail-closed process-lifetime lease policy.",
            [
                ref(OBSERVER, ob, "// Leases live to process exit."),
                ref(OBSERVER, ob, "exe_lease=CreateFileW(exe,GENERIC_READ,FILE_SHARE_READ"),
                ref(OBSERVER, ob, "dll_lease=CreateFileW(dll,GENERIC_READ,FILE_SHARE_READ"),
            ],
        ),
        item(
            "CHOICE-002",
            "unresolved_runtime_boundary",
            None,
            "same-address same-date reload remains unverified",
            "The source rejects backwards dates but deliberately reports same_address_reload_verified=false; a reload that reuses game/player/date addresses still needs an explicit load/world generation signal.",
            "Require a separate load lifecycle/world generation before enabling or accepting the same-address case.",
            [
                ref(OBSERVER, ob, "Same-address reloads"),
                ref(OBSERVER, ob, r'\"same_address_reload_verified\":false'),
            ],
        ),
        item(
            "CHOICE-003",
            "unresolved_runtime_boundary",
            None,
            "natural object validity, visibility, and real thread proof remain unverified",
            "Status still declares visibility_verified=false and capture_complete=false. The callback copies owned bytes and checks context/date, but no runtime evidence here proves natural object validity, UI visibility, or full battle semantics.",
            "Keep these fields false until an authorized bounded runtime/fixture contract proves them; do not infer business completeness from source guards.",
            [
                ref(OBSERVER, ob, r'\"capture_complete\":false,\"visibility_verified\":false'),
                ref(OBSERVER, ob, "owned_result::capture(reader,base,reinterpret_cast<uintptr_t>(result)"),
            ],
        ),
    ]

    files = [OBSERVER, HOST, *DEPS]
    findings = remaining
    counts = {"high": 0, "medium": 0, "total": len(findings)}
    for entry in findings:
        severity = entry.get("severity")
        if severity in counts:
            counts[severity] += 1
    return {
        "schema": "information-battle-observer-manager-review/2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "source_review_complete_runtime_unresolved",
        "previous_review": {
            "path": "work/runtime/information-battle-observer-20261025-001/manager-review-001.json",
            "preserved": True,
            "comparison_note": "The prior 13-item report is not overwritten; this report only carries current-revision findings and explicit resolution/boundary states.",
        },
        "scope": {
            "method": "bounded UTF-8 source review only; no build, REA, game, DLL load, command dispatch, or full-suite test",
            "max_file_read_bytes": MAX_READ,
            "runtime_claim": False,
        },
        "source_files": {path.relative_to(ROOT).as_posix(): pin(path) for path in files},
        "anchors_checked": len(anchors),
        "resolved": resolved,
        "remaining": remaining,
        "contract_choices_and_boundaries": contract_choices,
        "finding_counts": counts,
        "required_next_step": "Resolve OBS2-001, OBS2-002, and OBS2-004 or explicitly accept their contract impact on a new pinned source revision before native enablement; runtime boundaries remain false.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        report = build()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    except FileExistsError:
        print(f"refusing to overwrite existing report: {args.output}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        print(f"review failed closed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"output": str(args.output), "finding_counts": report["finding_counts"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
