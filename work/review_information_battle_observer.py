#!/usr/bin/env python3
"""Bounded static review of the v23 information battle observer.

This review intentionally reads source text only.  It does not build, load a
DLL, inspect a running game, dispatch a command, or invoke REA.  The output is
an evidence report with source pins and line-local findings so a later source
revision cannot be confused with the revision reviewed here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


MAX_SOURCE_BYTES = 4 * 1024 * 1024
DEFAULT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = DEFAULT_ROOT / "work/native/information-battle-observer.inc"
DEFAULT_HOST = DEFAULT_ROOT / "work/native/diplomacy-observer-v10.cpp"
DEFAULT_DEPENDENCIES = (
    DEFAULT_ROOT / "work/native/information-battle-buffer.h",
    DEFAULT_ROOT / "work/native/information-battle-drain.h",
    DEFAULT_ROOT / "work/native/information-battle-log-writer.h",
    DEFAULT_ROOT / "work/native/information-battle-observation-wire.h",
    DEFAULT_ROOT / "work/native/information-battle-entry-plan.h",
)
DEFAULT_OUTPUT = (
    DEFAULT_ROOT
    / "work/runtime/information-battle-observer-20261025-001/manager-review-001.json"
)


def bounded_read(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"source exceeds bounded review limit: {path} ({size} bytes)")
    return path.read_bytes()


def pin(path: Path) -> dict[str, object]:
    data = bounded_read(path)
    return {
        "path": path.relative_to(DEFAULT_ROOT).as_posix(),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def source_lines(path: Path) -> list[str]:
    return bounded_read(path).decode("utf-8", errors="strict").splitlines()


def evidence(path: Path, lines: list[str], needle: str, occurrence: int = 1) -> dict[str, object]:
    """Return the requested source line, failing closed if it moved/disappeared."""

    seen = 0
    for number, text in enumerate(lines, 1):
        if needle in text:
            seen += 1
            if seen == occurrence:
                return {
                    "path": path.relative_to(DEFAULT_ROOT).as_posix(),
                    "line": number,
                    "text": text.strip(),
                }
    raise RuntimeError(f"review anchor not found ({occurrence}): {path}: {needle!r}")


def maybe_evidence(
    path: Path, lines: list[str], needle: str, occurrence: int = 1
) -> dict[str, object] | None:
    try:
        return evidence(path, lines, needle, occurrence)
    except RuntimeError:
        return None


def finding(
    finding_id: str,
    severity: str,
    area: str,
    title: str,
    consequence: str,
    minimum_fix: str,
    refs: Iterable[dict[str, object]],
) -> dict[str, object]:
    return {
        "id": finding_id,
        "severity": severity,
        "area": area,
        "title": title,
        "consequence": consequence,
        "minimum_fix": minimum_fix,
        "evidence": list(refs),
    }


def build_report(root: Path) -> dict[str, object]:
    source = root / "work/native/information-battle-observer.inc"
    host = root / "work/native/diplomacy-observer-v10.cpp"
    deps = [
        root / "work/native/information-battle-buffer.h",
        root / "work/native/information-battle-drain.h",
        root / "work/native/information-battle-log-writer.h",
        root / "work/native/information-battle-observation-wire.h",
        root / "work/native/information-battle-entry-plan.h",
    ]
    source_text = source_lines(source)
    host_text = source_lines(host)
    buffer_text = source_lines(deps[0])
    drain_text = source_lines(deps[1])
    writer_text = source_lines(deps[2])
    wire_text = source_lines(deps[3])
    plan_text = source_lines(deps[4])

    # These anchors make the report an executable, bounded audit rather than a
    # free-form summary.  If root edits the source, regeneration must fail and
    # the new revision must receive a new review.
    anchors = [
        (source, source_text, "constexpr unsigned kSlots = 8;"),
        (source, source_text, "static SRWLOCK capture_lock = SRWLOCK_INIT;"),
        (source, source_text, "state.store(source_changed,std::memory_order_release);"),
        (source, source_text, "drain.drain(writer,8);"),
        (source, source_text, "MoveFileExW(request_path,processing_path,MOVEFILE_WRITE_THROUGH)"),
        (source, source_text, "return write_json(target,json,size,CREATE_NEW);"),
        (source, source_text, "if (GetFileAttributesW(previous_response)!=INVALID_FILE_ATTRIBUTES) {reason=\"duplicate_request\";return false;}"),
        (source, source_text, "drain.reset({installation,1})"),
        (source, source_text, "writer.open(log_path,{installation,1})"),
        (source, source_text, "if (now-last_poll>=100) {last_poll=now;poll();}"),
        (source, source_text, "if (now-last_status>=1000) {last_status=now;if (!status(\"\",\"heartbeat\",true,\"observed\",false))"),
        (host, host_text, "if (!thread_changed && frame_thread==GetCurrentThreadId()) {"),
        (host, host_text, "information_battle_tick();"),
        (buffer := deps[0], buffer_text, "bool consistent = false;"),
        (drain := deps[1], drain_text, "DrainResult drain(Sink&& sink, std::size_t max_records) noexcept"),
        (writer := deps[2], writer_text, "if (Io::valid(handle_)) {"),
        (wire := deps[3], wire_text, "constexpr std::size_t kMaxWireBytes = 16384u;"),
        (plan := deps[4], plan_text, "inline bool valid_code_address"),
    ]
    anchored = []
    for path, lines, needle in anchors:
        ref = maybe_evidence(path, lines, needle)
        if ref is None:
            raise RuntimeError(f"source changed or anchor missing: {path}: {needle}")
        anchored.append(ref)

    def e(path: Path, lines: list[str], needle: str, occurrence: int = 1):
        return evidence(path, lines, needle, occurrence)

    findings = [
        finding(
            "OBS-001",
            "high",
            "state/queue",
            "flush continues after source_changed, fault, or restart_required",
            "information_battle_tick unconditionally calls flush after the enabled-only guard. A context/code guard failure can latch source_changed, yet an already queued observation and its fragments can still be encoded and written under the old identity. A writer fault or failed publication can likewise be retried without a state-specific policy. This can publish data after the source/session binding has been invalidated.",
            "Make flush take an explicit state snapshot and permit delivery only for enabled, plus a documented disabled-drain phase. On source_changed/fault/restart_required stop and quarantine the pending record/queue; expose the stopped reason. Recheck state and identity under capture_lock immediately before committing a slot.",
            [
                e(source, source_text, "static void flush() noexcept {"),
                e(source, source_text, "if (!identity.valid()) return;"),
                e(source, source_text, "if (now-last_poll>=100) {last_poll=now;poll();}"),
                e(source, source_text, "flush();"),
                e(source, source_text, "state.store(source_changed,std::memory_order_release);", 4),
            ],
        ),
        finding(
            "OBS-002",
            "high",
            "command/idempotency",
            "request nonce is not a durable idempotency key",
            "The response-file existence check now prevents an ordinary replay once a response was durably created, but it is not a durable command ledger. If the process crashes or the response write/close fails after enable/disable has changed state, no response file records the nonce; a later retry can apply the mutation again. A failed status write also leaves .processing because the delete is short-circuited, and the next poll latches fault.",
            "Persist a bounded nonce record (nonce, verb, request fingerprint, result) in the same durable acknowledgment protocol, or make mutation and response creation recoverable as one state machine. Reconcile an orphaned .processing file explicitly; do not rely only on response-file presence and do not leave an unobservable state-changing retry window.",
            [
                e(source, source_text, "return write_json(target,json,size,CREATE_NEW);"),
                e(source, source_text, "if (GetFileAttributesW(previous_response)!=INVALID_FILE_ATTRIBUTES) {reason=\"duplicate_request\";return false;}"),
                e(source, source_text, "const bool duplicate=!strcmp(reason,\"duplicate_request\");"),
                e(source, source_text, "if (!status(nonce,verb,ok,reason,!duplicate) || !DeleteFileW(processing_path)) state.store(fault,std::memory_order_release);"),
                e(source, source_text, "if (GetFileAttributesW(processing_path)!=INVALID_FILE_ATTRIBUTES) {state.store(fault,std::memory_order_release);return;}"),
                e(source, source_text, "if (!MoveFileExW(request_path,processing_path,MOVEFILE_WRITE_THROUGH)) return;"),
            ],
        ),
        finding(
            "OBS-003",
            "high",
            "command/identity",
            "status and disable bypass expected-player/source validation",
            "After PID, creation, DLL hash, and (when already bound) installation checks, status returns observed and disable mutates state before checking expected_player, current context, code guard, or player handle. A stale command for a different selected player can therefore disable the current capture, and status can attest to a source it never validated.",
            "For a bound observer require the command player to equal the bound player and revalidate context/file/code identity for status and disable as well as enable. If unbound, return an explicit unbound result instead of accepting a player-scoped mutation. Include a request fingerprint in the identity check.",
            [
                e(source, source_text, "if (!strcmp(verb,\"status\")) { reason=\"observed\";return true; }"),
                e(source, source_text, "if (!strcmp(verb,\"disable\")) {"),
                e(source, source_text, "if (current==enabled || current==ready || current==disabled) state.store(disabled,std::memory_order_release);"),
                e(source, source_text, "|| !context(current_game,current_player,date) || current_player!=expected_player", 1),
            ],
        ),
        finding(
            "OBS-005",
            "high",
            "concurrency/state",
            "state transitions are not synchronized with the final capture commit",
            "capture checks enabled and validates the context while holding capture_lock, but state.store(source_changed) can occur without that lock (tick and the guard branch). There is no final state/context/code check immediately before incrementing count. If a lifecycle call races the callback, a callback can publish after invalidation.",
            "Make lifecycle transitions take the same capture lock, or use a generation/epoch checked under the lock. Recheck state, bound thread, context, and code guard immediately before writing the slot and incrementing count; use an explicit callback ownership gate for information_battle_tick.",
            [
                e(source, source_text, "if (state.load(std::memory_order_acquire)==enabled) {"),
                e(source, source_text, "if (!code_guard() || !context(g,p,date) || g!=game || p!=player || date<last_date) {"),
                e(source, source_text, "else {target.sequence=next;target.thread=bound_thread;"),
                e(source, source_text, "if (thread_changed || GetCurrentThreadId()!=bound_thread || !context(g,p,date) || g!=game || p!=player || date<last_date || !code_guard())"),
            ],
        ),
        finding(
            "OBS-006",
            "high",
            "identity/restart",
            "every process run reuses generation 1 and the same log stream",
            "The queue and writer are reset/opened with `{installation,1}` on every first enable, while the process-local observation sequence starts at zero. A restart can append to an existing same-header log and reuse message/attempt identifiers. Receivers that use identity plus sequence will see collisions or indistinguishable records from different process/world generations.",
            "Allocate a persisted monotonic generation per installation (or fail closed if the existing log has the same generation), bind it to process creation/world generation, and pass it consistently to drain, writer, status, and the command identity. Never silently append a new process to an old generation-1 stream.",
            [
                e(source, source_text, "static std::atomic<uint64_t> sequence{0}"),
                e(source, source_text, "if (!drain.reset({installation,1}).succeeded() || !writer.open(log_path,{installation,1}))"),
                e(source, source_text, "identity={installation,1};game=current_game;player=current_player;bound_thread=frame_thread;"),
                e(writer, writer_text, "if (std::memcmp(expected.data(), actual.data(), actual.size()) != 0)"),
            ],
        ),
        finding(
            "OBS-007",
            "high",
            "process/DLL identity",
            "process and DLL SHA are checked at start/enable but not during an enabled tick",
            "file_identity checks process creation, EXE SHA, and DLL SHA, but information_battle_tick only rechecks context and code bytes. A file replacement or loaded-image identity change after enable is not reflected in state/status; code_guard alone does not prove the pinned process/DLL provenance.",
            "Recheck process creation and the pinned EXE/DLL identity on every owner tick (or hold a validated file/module identity lease with an explicit invalidation signal). On mismatch latch source_changed/restart_required before any flush and report the observed hashes.",
            [
                e(source, source_text, "static bool file_identity() noexcept {"),
                e(source, source_text, "&& hash_file(dll,own_hash) && !strcmp(own_hash,dll_sha);"),
                e(source, source_text, "if (thread_changed || GetCurrentThreadId()!=bound_thread || !context(g,p,date) || g!=game || p!=player || date<last_date || !code_guard())"),
                e(source, source_text, "if (!frame_thread || frame_thread!=GetCurrentThreadId() || thread_changed || !file_identity() || !code_guard()"),
            ],
        ),
        finding(
            "OBS-008",
            "high",
            "pointer/code guards",
            "RVA arithmetic and code/unwind checks do not validate the module base/PE ownership",
            "Reader validates the final address, but expressions such as base+RVA are formed before Reader sees them. The external base is not range/overflow checked or tied to the loaded self_module/PE image. code_guard compares fixed bytes at two addresses but does not verify the RUNTIME_FUNCTION row, unwind ownership, section bounds, or current module image identity. A wrapped or wrong base can turn a guard into a check of an unrelated readable address.",
            "Validate base and every RVA addition with checked range arithmetic before forming addresses; derive/verify the image base from self_module and the fixed EXE/module mapping. Validate the target .text/.pdata ranges and RUNTIME_FUNCTION/UNWIND_INFO ownership, then compare the expected bytes.",
            [
                e(source, source_text, "return address >= 0x10000 && address < 0x800000000000ull"),
                e(source, source_text, "if (!reader.read(base+kEntryRva,code,sizeof(code))"),
                e(source, source_text, "return read_value(base+0x233fe58,actual_game)"),
                e(plan, plan_text, "inline bool valid_code_address"),
            ],
        ),
        finding(
            "OBS-009",
            "high",
            "publication/failure",
            "install failures retain partially published resources without a cleanup or publication-state contract",
            "VirtualAlloc and the module pin happen before protection, function-table registration, lookup, and patch completion. Several failure returns leave trampoline, a registered RUNTIME_FUNCTION, or information_battle_entry_original set, and there is no RtlDeleteFunctionTable/VirtualFree path. The source deliberately keeps resources process-lifetime, but a failed install can still leave an orphan table/image and the status does not distinguish a valid published patch from a failed partial publication.",
            "Use a two-phase publication record: keep allocations/table unregistered until all checks pass, and delete/free only resources that were never reachable by VEH or the stub. If restart_required intentionally retains a published image, record the exact publication stage and make all later ticks/poll/flush terminal; never expose it as an ordinary installed resource.",
            [
                e(source, source_text, "trampoline=static_cast<unsigned char*>(VirtualAlloc"),
                e(source, source_text, "table_registered=RtlAddFunctionTable(&unwind,1"),
                e(source, source_text, "information_battle_entry_original=trampoline;"),
                e(source, source_text, "if (!result.success || !result.threads_resumed || !result.protection_restored || result.pending_count)"),
                e(source, source_text, "// Capture is disabled until a process/DLL/player-bound file command enables it."),
            ],
        ),
        finding(
            "OBS-010",
            "medium",
            "failure/state",
            "startup status failure leaves the state published as ready",
            "information_battle_start stores ready before the startup status write. If status JSON creation/flush/rename fails, the function returns false to BridgeStart while the static state remains ready; a retry is rejected by the cold-state check and the manager has no durable failure response.",
            "Write and verify startup status before publishing ready, or roll back to cold/fault with a durable startup failure. Make BridgeStart and the observer state agree on whether the instance is usable.",
            [
                e(source, source_text, "state.store(ready,std::memory_order_release);"),
                e(source, source_text, "return status(\"\",\"startup\",true,\"awaiting_process_bound_enable\",false);"),
                e(host, host_text, "if (!information_battle_start(module_path,observation_creation)) {"),
                e(host, host_text, "return 30;"),
            ],
        ),
        finding(
            "OBS-011",
            "medium",
            "queue/transport",
            "drain and writer failure results are ignored by flush",
            "Both drain calls discard DrainResult. A sink rejection, invalid budget, pending record, writer lock/flush/rollback fault, or remaining queue is not reflected in state or status; the code can continue reporting heartbeat accepted/observed while retrying an unbounded pending record. A full queue is explicit, but a transport fault has no terminal transition or reason.",
            "Inspect every DrainResult and writer status. On sink rejection/rollback/close faults latch a typed transport state, retain the pending record for an explicit bounded retry policy, and surface pending/error counters in status. Do not mark heartbeat accepted while the sink is faulted.",
            [
                e(source, source_text, "drain.drain(writer,8);", 1),
                e(source, source_text, "if (!pushed.accepted()) return;"),
                e(source, source_text, "drain.drain(writer,8);", 2),
                e(writer, writer_text, "status_ = LogStatus::rollback_fault;"),
            ],
        ),
        finding(
            "OBS-012",
            "medium",
            "observability",
            "status omits the queue snapshot consistency contract",
            "OwnedByteQueue explicitly reports Stats::consistent=false because its counters are independent atomics. status serializes queued/captured/drop values without that flag or a lock/epoch, so consumers can treat a mixed snapshot as a linearizable accounting result.",
            "Either take status stats under the owner/capture serialization point or include `stats_consistent:false` (and a snapshot epoch) in every status response. Keep capture/queue counts separate from accepted wire-fragment counts.",
            [
                e(buffer, buffer_text, "result.consistent = false;"),
                e(drain, drain_text, "Stats stats() const noexcept { return queue_.stats(); }"),
                e(source, source_text, "const auto stats=drain.stats();"),
                e(source, source_text, "last_sequence"),
            ],
        ),
        finding(
            "OBS-013",
            "medium",
            "shutdown/lifecycle",
            "disable and process shutdown have no final drain/close contract",
            "The source documents process-lifetime published resources and disable only changes state/ waits for capture_lock. It never closes the writer, drains a bounded final queue, unregisters a function table, or reports whether pending observations were discarded. Process exit or a host unload path can therefore lose queued raw values; a future in-process unload would be unsafe.",
            "Define an explicit quiescent shutdown operation: stop entry capture, finish or quarantine pending observations, close/flush the writer, and only then release the patch/table/module resources. If process-lifetime retention is mandatory, make it an explicit manager contract and report pending/discarded counts on disable.",
            [
                e(source, source_text, "// No game function is called. Published code, VEH routes, unwind rows and the"),
                e(source, source_text, "reason=\"capture_disabled_resources_retained\""),
                e(writer, writer_text, "bool close() noexcept {"),
                e(source, source_text, "static bool information_battle_start"),
            ],
        ),
        finding(
            "OBS-014",
            "medium",
            "source validity",
            "context validation lacks a world/session generation and object lease",
            "The binding now rejects a backwards date, but still compares only game pointer, player handle, thread, and current date; country_handle checks a slot/handle echo. It does not validate a world/session generation, country tag/object generation, or result/summary object lifetime. A reload that reuses addresses and date can pass the guard, and the callback can copy mutable result memory without an explicit source lease.",
            "Add a source generation/world identity supplied by the manager and validate it before and after the copy. Require a documented callback-owned lifetime for result/summary pointers, or copy only under the native object's stable read/epoch contract. Treat reused addresses with unknown generation as source_changed.",
            [
                e(source, source_text, "&& read_value(actual_game+0x1dd0,date);"),
                e(source, source_text, "&& read_value(country+0x20,actual) && actual==handle;"),
                e(source, source_text, "date<last_date"),
                e(source, source_text, "auto& target=slots[(head+count)%kSlots];"),
                e(source, source_text, "battle::owned_result::capture(reader,base,reinterpret_cast<uintptr_t>(result)"),
            ],
        ),
    ]

    # Static positive checks are deliberately modest: they document what the
    # review did establish without claiming runtime correctness.
    verified = [
        {
            "id": "V-QUEUE-LOCK",
            "statement": "kSlots is 8 and slot/head/count mutation is enclosed by capture_lock in capture/flush; the queue component owns bytes before publish.",
            "evidence": [
                e(source, source_text, "constexpr unsigned kSlots = 8;"),
                e(source, source_text, "AcquireSRWLockExclusive(&capture_lock);"),
                e(buffer, buffer_text, "std::memcpy(slot.payload, bytes, size);"),
            ],
        },
        {
            "id": "V-BOUNDS",
            "statement": "Reader limits a single read to 65536 bytes and canonical user addresses; wire/fragment components have independent bounded payload limits.",
            "evidence": [
                e(source, source_text, "&& size && size <= 65536 && size <= 0x800000000000ull-address"),
                e(wire, wire_text, "constexpr std::size_t kMaxWireBytes = 16384u;"),
                e(plan, plan_text, "inline bool valid_code_address"),
            ],
        },
        {
            "id": "V-COPY",
            "statement": "Capture publishes a slot only after owned result/summary copy and a post-copy game/player/date/raw-date check; failed copy does not increment count.",
            "evidence": [
                e(source, source_text, "bool copied=battle::owned_result::capture"),
                e(source, source_text, "if (!copied) copy_failed.fetch_add(1);"),
                e(source, source_text, "++count;accepted.fetch_add(1);"),
            ],
        },
        {
            "id": "V-FAIL-CLOSED-PATCH",
            "statement": "Patch failure is labeled restart_required and the existing patch helper result exposes thread/protection/pending failure fields; this is not evidence that cleanup is complete.",
            "evidence": [
                e(source, source_text, "state.store(restart_required,std::memory_order_release); return false;"),
                e(source, source_text, "result.pending_count"),
            ],
        },
    ]

    paths = [source, host, *deps]
    source_files = {p.relative_to(root).as_posix(): pin(p) for p in paths}
    return {
        "schema": "information-battle-observer-manager-review/1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "reviewed_with_blocking_findings",
        "scope": {
            "source": source.relative_to(root).as_posix(),
            "host_context": host.relative_to(root).as_posix(),
            "method": "bounded source-text review; no build, REA, game, DLL load, command dispatch, or full-suite test",
            "max_file_read_bytes": MAX_SOURCE_BYTES,
            "runtime_claim": False,
        },
        "source_files": source_files,
        "anchors_checked": len(anchored),
        "verified_properties": verified,
        "findings": findings,
        "finding_counts": {
            "critical": sum(x["severity"] == "critical" for x in findings),
            "high": sum(x["severity"] == "high" for x in findings),
            "medium": sum(x["severity"] == "medium" for x in findings),
            "low": sum(x["severity"] == "low" for x in findings),
            "total": len(findings),
        },
        "known_fixed_not_repeated": [
            {
                "id": "OBS-004",
                "status": "fixed_in_reviewed_revision",
                "detail": "The host now invokes information_battle_tick after the legacy thread-gated block; tick itself reports frame_thread_changed and returns. The former host-skip finding is therefore excluded from finding_counts.",
                "evidence": [
                    e(host, host_text, "#ifdef BRIDGE_INFORMATION_BATTLE"),
                    e(host, host_text, "information_battle_tick();"),
                    e(source, source_text, "status(\"\",\"heartbeat\",false,\"frame_thread_changed\",false);"),
                ],
            }
        ],
        "required_next_step": "Root should resolve or explicitly accept each remaining finding on a new pinned observer revision before any live/native enablement; this report does not authorize installation or game use.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        report = build_report(DEFAULT_ROOT)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Do not silently overwrite a prior review artifact.
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
