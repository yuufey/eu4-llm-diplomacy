"""Reuse accepted caller evidence and bind a bounded IBOW v5 contract.

Only --run writes a new report. No REA, process access or game calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, make_disassembler
from work.local_config import game_exe
from work.probe_information_battle_context_contract import selected
from work.research_information_branch_inputs import _decode_range

STAGE = ROOT / "work/runtime/information-battle-war-identity-20261027-001"
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def pin(path):
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": digest}


def run(output):
    if output.exists():
        raise FileExistsError(output)
    exe = game_exe()
    with exe.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == EXE_SHA
    evidence = {}
    for key, relative in (
        ("caller", "work/runtime/information-battles-20261025-001/rea-battle-result-router-001/evidence.json"),
        ("relation_lookup", "work/runtime/information-battle-entry-20261025-001/rea-country-relation-war-001/evidence.json"),
        ("result_retention", "work/runtime/information-battle-war-records-20261025-001/rea-war-result-retain-001/evidence.json"),
    ):
        doc = selected(ROOT / relative, ("procedure", "pseudocode", "assembly"))
        evidence[key] = doc
    assembly = evidence["caller"]["assembly"]
    required = [
        "0x14023a276: CALL 0x140a688b0", "0x14023a27b: MOV RBX, RAX",
        "0x14023a3e4: MOV RDX, RBX", "0x14023a3e7: MOV RCX, R14",
        "0x14023a3ea: CALL 0x1401dd3c0", "0x14023a3f3: MOV RDX, R14",
        "0x14023a3f6: MOV RCX, RBX", "0x14023a3f9: CALL 0x140d89a80",
        "0x14023a3fe: MOV R8, R14", "0x14023a405: MOV RCX, RDI",
        "0x14023a408: CALL 0x140238620",
    ]
    assert all(line in assembly for line in required)
    pe = PE(exe)
    md, _ = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    if md is None:
        raise RuntimeError("pinned Capstone unavailable")
    windows = []
    for start, end in ((0x23A228, 0x23A27E), (0x23A3D6, 0x23A40D), (0xA688B0, 0xA688E5)):
        raw = pe.bytes_at(start, end-start)
        windows.append({"rva": hex(start), "static_va": hex(pe.base+start),
                        "end_rva_exclusive": hex(end), "hex": raw.hex(),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "instructions": _decode_range(pe, md, start, end)})
    sources = [pin(ROOT / rel) for rel in (
        "work/runtime/information-battle-business-20261025-001/context-source-contract-001.json",
        "work/runtime/information-battle-entry-20261025-001/entry-contract-ledger-001.json",
        "work/runtime/information-battle-war-identity-20261027-001/source-002.json",
        "work/native/information-battle-observer.inc", "work/native/information-battle-entry-stub.S",
        "work/native/peace-context-query.inc", "work/native/information-battle-owned-context.h",
    )]
    result = {
        "schema": "information_battle_war_binding_contract.v1", "status": "source_closed_implementation_pending",
        "binary": {"version": "1.37.4", "sha256": EXE_SHA, "image_base": hex(pe.base)},
        "accepted_REA": {key: {"evidence_id": doc["evidence_id"], "source": doc["source"],
                                  "subject_sha256": EXE_SHA, "procedure": doc["procedure"],
                                  "raw_normalized_selected_values_match": True} for key, doc in evidence.items()},
        "caller_REA_assembly": required, "ordinary_PE_windows": windows, "sources": sources,
        "binding": {
            "known_return_rva": "0x23a40d", "candidate": "incoming RBX at 238620 entry",
            "result": "incoming R8, same R14 as the optional result-retention call",
            "retention_branch_optional": True,
            "proof_scope": "known caller-local candidate/result association; no fresh runtime observation",
            "mandatory_guards": ["known_router", "complete_native_war_context", "opposite_result_participants",
                                  "current_country_fullrefs", "symmetric_pair_contains_exact_candidate", "double_pass_unchanged"],
            "multiple_wars": "Select the exact native candidate in equal pair sets; never take an arbitrary first registry row.",
            "registry": "same DLL peace_query_register_war; only after all guards",
            "public_scope": "observer_session; original native reference stays inside the DLL",
            "lifetime_limit": "Registry deduplicates native addresses; native allocation generation and cross-save identity are unproven.",
        },
        "wire": {
            "version": 5, "prefix": "IBOW + u16(5) + u32(inner_v4_length) + complete_v4_bytes",
            "extension": ["WARI", "u8 status", "u8 reason", "u32 binding_flags", "u64 process_creation_filetime",
                          "i32 raw_date", "u64 result_side_0_fullref", "u64 result_side_1_fullref", "u8 id_length", "ASCII id bytes"],
            "statuses": {"0": "absent", "1": "bound", "2": "invalid"},
            "reasons": {"0": "none", "1": "unknown_caller", "2": "context_unavailable", "3": "result_pair_unverified",
                        "4": "association_unavailable", "5": "association_changed", "6": "registry_full"},
            "bound_flags": 63, "bound_id_bytes": 29, "id_shape": "war_[0-9a-f]{16}_[0-9a-f]{8}",
            "unknown_id_bytes": 0, "unknown_flags": 0, "unknown_pair_refs": [0, 0],
            "max_wire_bytes": 524288, "old_versions_unchanged": [1, 2, 3, 4],
            "decoder_key": "war_identity", "pair_full_refs": "two integers in result-side order; no attacker/defender claim",
        },
        "public_field": {"field": "B01.war_id", "value": "opaque shared registry ID when bound; unknown otherwise",
                         "coverage": "partial", "complete": False, "identity_scope": "observer_session",
                         "native_integer_id_proven": False, "cross_session_or_save_identity_proven": False},
        "authority": {"new_REA": False, "process_access": False, "native_game_calls": False, "dispatch_authorized": False},
        "unresolved": ["runtime v5 capture and pair/registry correspondence", "native allocation generation",
                       "stable battle ID", "full B01-B04 and complete plan"],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2); stream.write("\n")
    print(json.dumps(pin(output), ensure_ascii=False))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, default=STAGE / "war-binding-contract-001.json")
    args = parser.parse_args()
    if not args.run:
        parser.print_help(); return 0
    return run(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
