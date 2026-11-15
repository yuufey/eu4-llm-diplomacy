"""Build a bounded source index for the B01 battle/war identity gap.

The script is deliberately inert unless ``--run`` is supplied.  ``--run``
only hashes and reads already archived source/fixture files; it never opens a
process, calls REA/RPM, invokes a native function, starts a game, or imports a
production battle reader.  The output keeps ordinary PE/source, accepted REA
readback, and recorded runtime observations in separate evidence layers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / "work" / "runtime" / "information-battle-war-identity-20261027-001"
DEFAULT_OUTPUT = STAGE / "source-001.json"
MAX_SOURCE_BYTES = 16 * 1024 * 1024
HASH_CHUNK = 1024 * 1024

TARGET_BUILD = {
    "game_version": "1.37.4",
    "executable_sha256": "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77",
    "image_base": "0x140000000",
    "address_convention": "RVA and static VA are separate; VA=image_base+RVA for this EXE",
}


SOURCE_SPECS: tuple[dict[str, Any], ...] = (
    {
        "layer": "ordinary_static",
        "path": "bridge/information/battles.py",
        "role": "B01 adapter and history projection",
        "line_ranges": ["1-6", "219-291", "355-454", "535-591"],
    },
    {
        "layer": "ordinary_static",
        "path": "work/information_battle_observation_wire.py",
        "role": "pointer-free observation wire",
        "line_ranges": ["1-7", "101-166"],
    },
    {
        "layer": "ordinary_static",
        "path": "work/information_battle_context_wire.py",
        "role": "pointer-free context/war-members wire",
        "line_ranges": ["149-195", "263-300"],
    },
    {
        "layer": "ordinary_static",
        "path": "work/native/information-battle-owned-context.h",
        "role": "bounded optional war-candidate copy contract",
        "line_ranges": ["1-48", "267-365", "470-608", "652-725"],
    },
    {
        "layer": "ordinary_static",
        "path": "work/native/information-battle-context-wire.h",
        "role": "value-only serialization boundary",
        "line_ranges": ["1-10", "295-377", "410-486"],
    },
    {
        "layer": "ordinary_static",
        "path": "work/runtime/diplomacy-observer-20261020-r74-economic-war-a/peace-context-query.inc",
        "role": "current-1.37.4 pair-scoped opaque war registry consumer",
        "line_ranges": ["1-4", "18-41", "44-90", "93-131"],
    },
    {
        "layer": "ordinary_static",
        "path": "work/runtime/diplomacy-observer-20261020-r74-economic-war-a/peace-war-context-query.inc",
        "role": "constructed peace-offer to war-context consumer",
        "line_ranges": ["148-225", "228-296", "298-366"],
    },
    {
        "layer": "ordinary_static",
        "path": "work/inspect_declare_war_save_pair.py",
        "role": "recorded save active_war scanner; heuristic identity only",
        "line_ranges": ["1-6", "195-209", "451-464", "533-610"],
    },
    {
        "layer": "ordinary_static",
        "path": "docs/逐场战报持续摄取与兵力字段.md",
        "role": "current B01 scope and unresolved-war-id boundary",
        "line_ranges": ["28-46"],
    },
    {
        "layer": "REA_static_contract",
        "path": "work/runtime/information-battle-business-20261025-001/context-source-contract-001.json",
        "role": "accepted 23A020 caller binding for private war context and result dispatch",
        "line_ranges": ["1-48", "108-151", "209-231"],
        "evidence_id": "ev_c499fbd451a6770ca30c322fada384276fa7aba73aae2447fc14a1479753eae3",
        "rva": "0x23a020",
        "va": "0x14023a020",
        "body_rva_range_inclusive": ["0x23a020", "0x23a6b7"],
    },
    {
        "layer": "REA_static_contract",
        "path": "work/runtime/information-battle-entry-20261025-001/entry-contract-ledger-001.json",
        "role": "accepted bounded caller/first-match contract used to identify the private context candidate",
        "line_ranges": ["1-22", "118-145", "209-231"],
        "evidence_id": "ev_15a90cdd6f1fac2564cae44bf01ac0529c31e82f5b5c42460d43556094f47833",
        "rva": "0xa688b0",
        "va": "0x140a688b0",
        "body_rva_range_inclusive": ["0xa688b0", "0xa688e4"],
    },
    {
        "layer": "REA_static",
        "path": "work/runtime/information-battle-war-records-20261025-001/rea-war-result-retain-001/selected-evidence-001.json",
        "role": "accepted static D89A80 result-retention readback",
        "rva": "0xd89a80",
        "va": "0x140d89a80",
        "body_rva_range_inclusive": ["0xd89a80", "0xd89b34"],
        "evidence_id": "ev_09d14e848427a1ccc47ef38639261998f557fe988622a6cb44417f70ddc370be",
    },
    {
        "layer": "REA_static",
        "path": "work/runtime/information-battle-war-records-20261025-001/rea-result-war-binding-001/selected-evidence-001.json",
        "role": "accepted static D D3C0 result-side binding candidate; not war-id binding",
        "rva": "0x1dd3c0",
        "va": "0x1401dd3c0",
        "body_rva_range_inclusive": ["0x1dd3c0", "0x1dd624"],
        "evidence_id": "ev_e0a32ef721d9d9338289ffa18d0c634ad990e51926fd895320ba0e2fbb3351d3",
    },
    {
        "layer": "REA_static",
        "path": "work/runtime/information-battle-war-records-20261025-001/rea-war-history-append-001/selected-evidence-001.json",
        "role": "accepted static D8FF10 history-group append consumer",
        "rva": "0xd8ff10",
        "va": "0x140d8ff10",
        "body_rva_range_inclusive": ["0xd8ff10", "0xd9002a"],
        "evidence_id": "ev_56f6735890a8a3ee8919a5e7b25dc031f87ee1afb5242c0a9d7b39359b1fa6e0",
    },
    {
        "layer": "REA_static",
        "path": "work/runtime/information-battle-war-records-20261025-001/rea-history-date-set-001/selected-evidence-001.json",
        "role": "accepted static 7E7FB0 date propagation consumer",
        "rva": "0x7e7fb0",
        "va": "0x1407e7fb0",
        "body_rva_range_inclusive": ["0x7e7fb0", "0x7e8018"],
        "evidence_id": "ev_76e2c137910b7b747b329b716db096cd32ce69b78eb895add4d2fb8540f941e2",
    },
    {
        "layer": "REA_static",
        "path": "work/runtime/information-battle-continuous-20261026-001/native-value-contract-001.json",
        "role": "accepted static battle result callback/router ledger",
        "rva": "0x238620",
        "va": "0x140238620",
        "line_ranges": ["177-200"],
    },
    {
        "layer": "recorded_runtime",
        "path": "bridge/tests/fixtures/information_battle_live_stream_1374.jsonl",
        "role": "14 archived v2 battle frames used for offline shape inventory",
    },
    {
        "layer": "recorded_runtime",
        "path": "work/runtime/information-battle-continuous-20261026-001/live-result-001.json",
        "role": "recorded B01/B02 projection and event identity",
    },
    {
        "layer": "recorded_runtime",
        "path": "work/runtime/information-battle-continuous-20261026-001/live-history-001.json",
        "role": "recorded H01/W03 page with explicit WAR_ID_UNRESOLVED",
    },
    {
        "layer": "recorded_static_audit",
        "path": "work/runtime/information-battle-war-records-20261025-001/existing-war-readers-survey-001.json",
        "role": "current-1.37.4 war-reader survey and session-scoped identity limit",
    },
    {
        "layer": "recorded_static_audit",
        "path": "work/runtime/information-battle-war-records-20261025-001/history-root-contract-001.json",
        "role": "archived war-history root pointer/vtable distinction",
    },
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(HASH_CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _pin(spec: dict[str, Any]) -> dict[str, Any]:
    relpath = str(spec["path"])
    path = ROOT / relpath
    if not path.is_file():
        raise FileNotFoundError(relpath)
    size = path.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"source_over_bound:{relpath}:{size}")
    result = {
        "path": relpath,
        "bytes": size,
        "sha256": _sha256(path),
        "layer": spec["layer"],
        "role": spec["role"],
        "bounded_read": True,
    }
    for key in ("line_ranges", "rva", "va", "body_rva_range_inclusive", "evidence_id"):
        if key in spec:
            result[key] = spec[key]
    return result


def _load_json(relpath: str) -> Any:
    path = ROOT / relpath
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError(f"json_over_bound:{relpath}")
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_inventory() -> dict[str, Any]:
    """Decode only the small archived JSONL fixture, never a live source."""

    sys.path.insert(0, str(ROOT))
    from work.information_battle_template_wire import decode  # local, offline

    path = ROOT / "bridge/tests/fixtures/information_battle_live_stream_1374.jsonl"
    frame_count = 0
    sequences: list[int] = []
    status_counts: dict[str, int] = {}
    public_identity_absent = 0
    war_member_counts: list[list[int]] = []
    payload_offsets: list[int] = []
    for line in path.open("r", encoding="utf-8"):
        if not line.lstrip().startswith("{"):
            continue
        record = json.loads(line)
        raw = bytes.fromhex(str(record["payload_hex"]))
        offset = raw.find(b"IBOW")
        if offset < 0 or len(raw) - offset > 256 * 1024:
            raise ValueError("fixture_payload_not_bounded")
        decoded = decode(raw[offset:])
        frame_count += 1
        payload_offsets.append(offset)
        observation = decoded["observation"]
        sequences.append(int(observation["sequence"]))
        context = decoded.get("context") or {}
        status = str(context.get("war_context_status"))
        status_counts[status] = status_counts.get(status, 0) + 1
        if decoded.get("public_identity") == {
                "status": "absent", "war_id": None, "battle_id": None}:
            public_identity_absent += 1
        members = context.get("war_members")
        if isinstance(members, dict):
            war_member_counts.append([
                int(members.get("side_a_count", 0)),
                int(members.get("side_b_count", 0)),
            ])
    return {
        "source": "archived_fixture_only",
        "frame_count": frame_count,
        "sequences": {"min": min(sequences), "max": max(sequences),
                       "unique": len(set(sequences))},
        "war_context_status_counts": status_counts,
        "observed_member_vector_frames": len(war_member_counts),
        "member_vector_count_examples": war_member_counts[:4],
        "public_identity_absent_frames": public_identity_absent,
        "payload_ibow_offsets": sorted(set(payload_offsets)),
        "pointer_or_id_interpretation": "none; decoder output retains value full-refs only",
    }


def _recorded_projection() -> dict[str, Any]:
    result = _load_json(
        "work/runtime/information-battle-continuous-20261026-001/live-result-001.json"
    )
    history = _load_json(
        "work/runtime/information-battle-continuous-20261026-001/live-history-001.json"
    )
    event = result.get("event") if isinstance(result, dict) else None
    history_refs: list[dict[str, Any]] = []
    for item in history.get("items", []) if isinstance(history, dict) else []:
        value = item.get("fields", {}).get("battle_sequence", {}).get("value", {})
        history_refs.extend(value.get("event_refs", []))
        value = item.get("fields", {}).get("battle_losses", {}).get("value", {})
        history_refs.extend(value.get("event_refs", []))
    return {
        "source_mode": "recorded_artifact_not_new_runtime_capture",
        "result_context": result.get("context", {}),
        "event": {
            "event_id": event.get("event_id") if isinstance(event, dict) else None,
            "source": event.get("source") if isinstance(event, dict) else None,
            "record_order": (
                event.get("payload", {}).get("battle_fields", {})
                .get("record_order") if isinstance(event, dict) else None
            ),
        },
        "history_war_id_values": [ref.get("war_id") for ref in history_refs],
        "history_gap_reasons": sorted({
            gap.get("reason")
            for item in history.get("items", [])
            for gap in item.get("coverage", {}).get("gaps", [])
            if isinstance(gap, dict) and isinstance(gap.get("reason"), str)
        }),
    }


def _build_report() -> dict[str, Any]:
    source_pins = [_pin(spec) for spec in SOURCE_SPECS]
    fixture = _fixture_inventory()
    recorded = _recorded_projection()
    script_path = Path(__file__).resolve()
    return {
        "schema": "information_battle_war_identity_source_index_v2",
        "revision": "source-002",
        "supersedes": "work/runtime/information-battle-war-identity-20261027-001/source-001.json",
        "status": "static_source_index_complete_war_id_unresolved",
        "target_build": TARGET_BUILD,
        "scope": {
            "purpose": "补充 B01 battle/war identity 信息导出来源索引",
            "new_rea_query": False,
            "game_access": False,
            "rpm_or_native_call": False,
            "production_modified": False,
            "mcp_or_pytest": False,
            "recorded_runtime_is_not_new_observation": True,
        },
        "script": {
            "path": script_path.relative_to(ROOT).as_posix(),
            "sha256": _sha256(script_path),
            "default_is_inert": True,
            "run_mode": "offline_source_and_archived_fixture_inventory_only",
        },
        "b01_identity_contract": {
            "status": "partial",
            "event_id": {
                "status": "known",
                "shape": "battle-observation:<installation>:<generation>:<message_id>",
                "meaning": "durable captured-record key; not a game battle identity",
            },
            "battle_id": {
                "status": "unknown",
                "reason": "BATTLE_ID_NOT_SERIALIZED",
            },
            "war_id": {
                "status": "unknown",
                "reason": "WAR_ID_UNRESOLVED",
                "reason_detail": "B01 payload has no native war pointer/reference-to-public-ID binding; war membership values are only copied member full-ref vectors.",
            },
            "sequence": {
                "status": "known",
                "meaning": "observation/capture order only; not battle or war identity",
            },
            "page_cursor": {
                "status": "known",
                "meaning": "durable storage progress; not a battle or war number",
            },
            "r37b_boundary": "Any diplomacy R37B/session war_id remains a separate peace-context identifier and is not a B01 prerequisite or join key.",
        },
        "raw_record_fields": {
            "observation_wire": {
                "sequence": "u64",
                "thread": "u32",
                "raw_date": "signed i32",
                "province_id": "signed i32",
                "sides": "two country full-ref u64 values plus nine signed i32 raw fields per side",
                "commanders": "bounded raw byte strings",
                "summary": "11 signed i32 values plus control byte",
                "identity_absent_marker": "public_identity={status:absent,war_id:null,battle_id:null}",
            },
            "context_wire": {
                "physical_player_full_ref": "country full-ref u64",
                "side_participant_full_refs": "bounded country full-ref vectors",
                "war_context_status": "absent/observed/invalid",
                "war_members": "side_a/side_b full-ref vectors, completeness and physical-player membership booleans",
                "pointer_status": "native pointers are consumed by the bounded copy seam and are not serialized",
            },
            "optional_war_candidate_input_only": {
                "root_field": "war_candidate+0x108",
                "root_vtable_rva": "0x1d20be0",
                "side_a_vector_bounds": ["war+0x48", "war+0x50", "war+0x58"],
                "side_b_vector_bounds": ["war+0x78", "war+0x80", "war+0x88"],
                "member_stride": "8 bytes",
                "status": "input-to-capture-only; current B01 wire does not retain this pointer or a stable war ID",
            },
        },
        "archived_fixture_inventory": fixture,
        "recorded_projection_inventory": recorded,
        "accepted_source_findings": {
            "battle_result_router": {
                "kind": "REA_static",
                "rva": "0x238620",
                "va": "0x140238620",
                "finding": "non-null result path calls D89A80 retention and then result projection; static callback path does not expose a war identity",
                "next_narrow_consumer": "the 23A020 caller binding is now pinned below; stable semantic war identity and public projection remain unclosed",
            },
            "private_war_context_same_result_chain": {
                "kind": "REA_static_caller_binding",
                "evidence_id": "ev_c499fbd451a6770ca30c322fada384276fa7aba73aae2447fc14a1479753eae3",
                "rva": "0x23a020",
                "va": "0x14023a020",
                "caller_return_rva": "0x23a40d",
                "finding": "After A688B0 returns the original RBX private context candidate, this caller passes that same candidate in RCX to 1DD3C0 and then D89A80; the same result in R14 is then passed to 238620. This closes the same-candidate/same-result retention-router call chain for this caller.",
                "call_chain": [
                    "0x14023a3e4: MOV RDX,RBX; 0x14023a3e7: MOV RCX,R14; CALL 0x1401dd3c0",
                    "0x14023a3ef: MOVZX R8D,SIL; 0x14023a3f3: MOV RDX,R14; 0x14023a3f6: MOV RCX,RBX; CALL 0x140d89a80",
                    "0x14023a3fe: MOV R8,R14; 0x14023a405: MOV RCX,RDI; CALL 0x140238620",
                ],
                "identity_limit": "This proves caller-local pointer/dataflow only. It does not prove that RBX is a stable native war object, that the B01 wire frame came from this exact caller, or that a public/cross-session war_id exists.",
            },
            "war_result_retention": {
                "kind": "REA_static",
                "rva": "0xd89a80",
                "va": "0x140d89a80",
                "finding": "when enabled, appends result pointer to context F0/F8/100 and creates a 0x48-byte history event; event+0x38 stores context and event+0x40 stores result before D8FF10",
                "identity_limit": "retained result/context linkage is not a proven battle-to-war ID",
            },
            "war_history_append": {
                "kind": "REA_static",
                "rva": "0xd8ff10",
                "va": "0x140d8ff10",
                "finding": "allocates a 0x40-byte history group, stores raw date at event+0x10 and context+0x118, then appends through embedded root+0x108",
                "identity_limit": "history node/object storage is not a stable public war or battle identity",
            },
            "war_result_binding": {
                "kind": "REA_static",
                "rva": "0x1dd3c0",
                "va": "0x1401dd3c0",
                "finding": "computes result+0x84/+0xfc side/goal-derived values through context virtuals and /1000 arithmetic",
                "identity_limit": "directory/query label does not make this a war-ID binder or B01 getter",
            },
            "pair_war_registry": {
                "kind": "ordinary_static",
                "entry": "peace_query_register_war / peace_context_query_run",
                "rva": None,
                "finding": "pair relation rows provide private uintptr_t references; registry emits observer-session war_<16hex>_<8hex> IDs, capped at 256, and strips native addresses from public rows",
                "identity_limit": "pair-scoped diplomacy consumer; no B01 event binding",
            },
            "recorded_save_identity": {
                "kind": "ordinary_static_and_recorded",
                "finding": "active_war serialized fields and war_identity tuple are bounded save heuristics; save cross-check explicitly has no native war ID",
                "identity_limit": "cannot join B01 capture events across session/save",
            },
        },
        "narrow_reader_profile_audit": {
            "status": "no_stable_native_constructor_serializer_or_integer_id_found",
            "current_1374_pair_reader": {
                "source": "work/runtime/information-battle-war-records-20261025-001/existing-war-readers-survey-001.json",
                "finding": "The fixed-1.37.4 reader is pair-scoped: opaque uintptr references are registered into an observer-session war_<16hex>_<8hex> registry capped at 256; no global war-array reader or stable UID is proven.",
                "native_consumer": "FUN_14097bba0 / RVA 0x97bba0 constructs a CPeaceOffer-to-war-context path; this is a peace/pair consumer, not a B01 battle identity constructor.",
                "identity_limit": "session-scoped and not proven across save/session; no native integer ID is exposed",
            },
            "history_root": {
                "source": "work/runtime/information-battle-war-records-20261025-001/history-root-contract-001.json",
                "root_vtable_rva": "0x1d20be0",
                "storage": "runtime-observed embedded war+0x108 root; runtime VA/heap pointer only",
                "finding": "The history root/vtable and child list describe storage/dispatch, not a constructor or unique native war integer.",
            },
            "retention_and_save": {
                "finding": "D89A80/D8FF10 retain context/result pointers and raw date; the recorded active_war/war_identity tuple is explicitly a save heuristic. Neither supplies a stable public/native integer ID.",
                "status": "unknown",
            },
            "unresolved": [
                "No bounded current-1.37.4 evidence identifies a war serializer emitting a stable native integer ID.",
                "No constructor/profile contract proves the B01 combat result's RBX candidate is a globally addressable war object.",
                "No cross-session or save join between B01 event IDs and pair-scoped war IDs is proven.",
            ],
        },
        "unresolved_conditions": [
            "The accepted 23A020 caller proves a same-candidate/same-result retention-router call chain, but does not prove that this candidate is the semantic war object that produced every B01 frame.",
            "No current B01 wire field carries a native war pointer, public war_id, or stable battle_id.",
            "Participant and war member full-ref vectors do not establish attacker/defender roles, war leaders, join dates, duration, or cross-session identity.",
            "The next useful bounded investigation would correlate this caller's private context with a B01 frame and verify any public projection; broad binary scanning or a new REA/RPM run is outside this batch.",
        ],
        "source_pins": source_pins,
        "conclusion": "B01 can currently export captured battle observations and, when the optional candidate copy succeeds, war-member full-ref snapshots. It cannot publish a battle war_id. Keep WAR_ID_UNRESOLVED and keep R37B diplomacy war_id separate.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="build the offline source index")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help="exclusive output path used with --run")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({
            "status": "ready",
            "run_required": True,
            "default_is_inert": True,
            "output": str(args.output),
        }, ensure_ascii=False))
        return 0
    output = args.output.expanduser()
    if not output.is_absolute():
        output = (ROOT / output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = _build_report()
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    print(json.dumps({
        "status": report["status"],
        "output": output.relative_to(ROOT).as_posix(),
        "bytes": output.stat().st_size,
        "source_count": len(report["source_pins"]),
        "fixture_frames": report["archived_fixture_inventory"]["frame_count"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
