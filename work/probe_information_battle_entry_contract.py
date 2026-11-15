"""Retain source association, entry boundaries and measured unwind behavior."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-entry-20261025-001"
PREVIOUS = ROOT / "work/runtime/information-battle-war-records-20261025-001"
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pin(path: Path) -> dict:
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": sha(path)}


def load(path: Path, bound: int = 2 * 1024 * 1024) -> dict:
    assert path.stat().st_size <= bound
    return json.loads(path.read_text(encoding="utf-8"))


def near(lines: list[str], needle: str, before: int, after: int) -> dict:
    indexes = [i for i, line in enumerate(lines) if needle in line]
    assert len(indexes) == 1, (needle, indexes)
    start, end = max(0, indexes[0] - before), min(len(lines), indexes[0] + after + 1)
    return {"line_start": start + 1, "line_end": end, "lines": lines[start:end]}


def build() -> dict:
    query_path = STAGE / "rea-country-relation-war-001/evidence.json"
    query = load(query_path)
    assert query["subject"]["digest"]["sha256"] == EXE_SHA
    value = query["raw_result"]["value"]
    assert value == query["normalized_result"]
    assert value["procedure"]["address"] == "0x140a688b0"
    assert value["procedure"]["body"]["total_bytes"] == 53
    router_path = ROOT / "work/runtime/information-battles-20261025-001/rea-battle-result-router-001/evidence.json"
    router = load(router_path, 4 * 1024 * 1024)
    assert router["subject"]["digest"]["sha256"] == EXE_SHA
    assert router["raw_result"]["value"] == router["normalized_result"]
    machine = router["raw_result"]["value"]["assembly"]
    callback_path = PREVIOUS / "callback-entry-selected-001.json"
    callback = load(callback_path)
    callback_value = callback["raw_result_value"]
    assert all(callback_value[k]["value"] == callback["normalized_result"][k]["value"]
               for k in ("procedure", "pseudocode", "assembly", "callees"))
    pe_path = STAGE / "entry-unwind-pe-001.json"
    pe = load(pe_path)
    assert pe["status"] == "observed_static_pe_unwind_metadata"
    final_unwind_path = STAGE / "unwind-test-001/report-003.json"
    final_unwind = load(final_unwind_path)
    assert final_unwind["status"] == "passed"
    claims = [
        {"id": "native-relation-first-match", "evidence_kind": "static_REA",
         "evidence_id": query["evidence_id"], "rva": "0xa688b0",
         "Ghidra_body_inclusive": value["procedure"]["body"],
         "finding": "A688B0 reads owner=*view, owner50 row array and signed owner5C count. It compares each16-byte row's i32 key with signed16 bits32..47 of view10, returning the first row's qword8, or0. No calls or writes occur in the bounded function. This is slot-based first-match lookup, not full-handle identity or stable public war identity; do not actively call it as a query.",
         "proof": {"pseudocode": value["pseudocode"], "assembly": value["assembly"]}},
        {"id": "caller-private-context-candidate", "evidence_kind": "reused_static_REA_machine",
         "evidence_id": router["evidence_id"], "rva": "0x23a020",
         "finding": "The router stores A688B0's returned context in RBX. Before CALL238620 at23A408 it supplies RCX=combat/RDX=summary/R8=result, preserving RBX across the optional1DD3C0/D89A80 branch. Return address23A40D plus originalRBX can supply a private context candidate only for this exact caller. RBX is not a formal238620 argument. Attribution still requires current full-country references and war members; the pointer cannot be a publicID.",
         "proof": [near(machine, "0x14023a276:", 14, 7), near(machine, "0x14023a408:", 18, 4)]},
        {"id": "entry-before-settings-gate", "evidence_kind": "reused_static_REA",
         "evidence_id": callback["top_level"]["evidence_id"]["value"],
         "finding": "238620 body immediately returns when game7484 is zero. An entry shim precedes that gate and the participant body; the flag has no proven observer-visibility meaning. Capturing a private result does not authorize public delivery.",
         "proof": near(callback_value["pseudocode"]["value"].splitlines(), "DAT_14233fe58 + 0x7484", 0, 7)},
        {"id": "prefix-projected-unwind", "evidence_kind": "ordinary_PE_and_owned_process_unwind_test",
         "finding": "Use21 complete bytes through seven pushes, beforeLEA/SUB, within existing32-byte transaction limit. The41-byte trampoline has its own seven-push unwind projection and no original UHANDLER, allocation or delayedRBX save. A bareFF25 at21 fails even with expanded SizeOfProlog. The chosen20-byte tail writes continuation low/high halves to the callee-owned third home slot(entryRSP+18h), then uses JMP[RSP+50h] with mod01. It changes that home slot, not GPRs/flags/stack arguments5+. SizeOfProlog remains21 and actual operation offsets11..21. Native continuation executes the rest of the original prologue under original native metadata.",
         "PE_report": pin(pe_path),
         "failed_test": pin(STAGE / "unwind-test-001/report.json"),
         "second_failed_test": pin(STAGE / "unwind-test-001/report-002.json"),
         "jump_encoding_comparison": pin(STAGE / "unwind-jump-encoding-test-001/report.json"),
         "home_slot_candidate_test": pin(STAGE / "unwind-jump-encoding-test-002/report.json"),
         "corrected_test": pin(final_unwind_path)},
        {"id": "home-slot-ownership-and-bounded-check", "evidence_kind": "primary_ABI_documentation_and_reused_static_machine",
         "finding": "The standard Win64 callee owns all four register-home slots. For this prefix entryRSP+18h equals bodyRSP+5F0 or RBP+4F0; the selected238620 machine text has no direct reference to either address, and its only RSP adjustments are SUB5A0/ADD5A0. This is a bounded direct-reference check; it does not prove opaque callees cannot inspect caller stack memory.",
         "proof": {"third_home_direct_matches": {needle: [line for line in callback_value["assembly"]["value"] if needle.lower() in line.lower()]
                   for needle in ("RSP + 0x5f0", "RBP + 0x4f0")}},
         "references": ["https://learn.microsoft.com/en-us/cpp/build/stack-usage",
                        "https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog"]},
    ]
    return {
        "schema": "information_battle_entry_contract_v1", "status": "static_contract_with_owned_process_checks",
        "target": {"version": "1.37.4", "exe_sha256": EXE_SHA, "static_image_base": "0x140000000"},
        "claims": claims,
        "sources": [pin(path) for path in (query_path, query_path.parent / "request.json",
                    query_path.parent / "run.json", router_path, callback_path, pe_path,
                    STAGE / "infrastructure-survey-001.json", STAGE / "payload-source-survey-001.json")],
        "plan_header": pin(ROOT / "work/native/information-battle-entry-plan.h"),
        "script": pin(Path(__file__).resolve()),
        "references": [{"url": "https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64",
                        "role": "primary documentation for metadata semantics; runtime test independently checks Windows behavior"}],
        "unresolved": ["Actual natural game entry ABI, thread/reentry, world consistency and object lifetime.",
                       "Observer eligibility and visibility; game7484 is not a proven visibility predicate.",
                       "Stable public war/battle identity and all relevant caller coverage.",
                       "Complete source payload, displayed text and event/subscription integration.",
                       "Publication and process-lifetime ownership of executable image and dynamic unwind row."],
        "scope": {"new_REA_queries": 1, "new_game_access": False, "game_hook_installed": False,
                  "business_dispatch": False, "B01_B04_available": False, "overall_complete": False},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    path = STAGE / "entry-contract-ledger-001.json"
    text = json.dumps(build(), ensure_ascii=False, indent=2) + "\n"
    if args.verify_existing:
        assert path.read_text(encoding="utf-8") == text
    else:
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
    print(json.dumps({"output": pin(path), "verified_existing": args.verify_existing}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
