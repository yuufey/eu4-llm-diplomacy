"""Bind the static type dispatch to a future pointer-free context copy.

Only bounded saved REA values and the already tested reader contracts are
used. This does not read a live combat or call a game function.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.extract_information_battle_evidence import _SpanScanner, _find_member, _decode_span

STAGE = ROOT / "work/runtime/information-battle-business-20261025-001"
OUTPUT = STAGE / "context-source-contract-001.json"
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"


def pin(path: Path) -> dict:
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size, "sha256": digest}


def selected(path: Path, names: tuple[str, ...]) -> dict:
    """Decode individual values under 2 MiB, comparing raw and normalized."""
    result = {}
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as view:
        scanner = _SpanScanner(view)
        top, error = _find_member(scanner, 0, len(view), {"evidence_id", "subject", "raw_result", "normalized_result"})
        assert error is None
        for key in ("evidence_id", "subject"):
            item = _decode_span(view, *top[key], path=key)
            assert item["status"] == "observed"
            result[key] = item["value"]
        raw, error = _find_member(scanner, *top["raw_result"], {"value"})
        assert error is None
        source, error = _find_member(scanner, *raw["value"], set(names))
        assert error is None
        normalized, error = _find_member(scanner, *top["normalized_result"], set(names))
        assert error is None
        for key in names:
            left = _decode_span(view, *source[key], path="raw_result.value." + key)
            right = _decode_span(view, *normalized[key], path="normalized_result." + key)
            assert left["status"] == right["status"] == "observed"
            assert left["value"] == right["value"]
            result[key] = left["value"]
    assert result["subject"]["digest"]["sha256"] == EXE_SHA
    result["source"] = pin(path)
    result["whole_json_revalidated"] = False
    result["raw_normalized_selected_values_match"] = True
    return result


def near(text: str, needle: str, before: int = 3, after: int = 7) -> list[str]:
    lines = [line for line in text.splitlines() if line.strip()]
    matches = [index for index, line in enumerate(lines) if needle in line]
    assert matches, needle
    return ["\n".join(lines[max(0, index - before):index + after + 1]) for index in matches]


def assemble() -> dict:
    old = ROOT / "work/runtime/information-battles-20261025-001"
    layout = ROOT / "work/runtime/information-battle-layout-20261025-001"
    router = selected(old / "rea-battle-result-router-001/evidence.json", ("procedure", "pseudocode", "assembly"))
    builder = selected(old / "rea-battle-result-builder-001/evidence.json", ("procedure", "pseudocode"))
    # Both large original formatters are parsed by individual mmap values.
    naval = selected(old / "rea-message-dispatch-001/evidence.json", ("procedure", "pseudocode"))
    land = selected(layout / "rea-land-result-message-001/evidence.json", ("procedure", "pseudocode"))
    assert "NAVALBATTLEOVER" in naval["pseudocode"]
    assert "LANDBATTLEOVER" in land["pseudocode"]
    assert "FUN_14022e6b0(param_1,local_88,puVar6)" in router["pseudocode"]
    assert "FUN_140232a80(param_1,local_88,puVar6)" in router["pseudocode"]
    selectors = near(router["pseudocode"], "iVar3 == 2", 3, 11)
    assert any("iVar3 == 1" in item and "FUN_140232a80" in item for item in selectors)
    machine = router["assembly"]
    # Retain only the bounded original call neighborhood, never all disassembly.
    call_index = next(i for i, line in enumerate(machine) if "0x14023a408:" in line)
    assert "CALL 0x140238620" in machine[call_index]
    known_context = machine[max(0, call_index - 12):call_index + 23]
    helper = ROOT / "work/information_battle_war_memory.py"
    owned_summary = ROOT / "work/native/information-battle-owned-summary.h"
    previous_context = ROOT / "work/runtime/information-battle-entry-20261025-001/entry-contract-ledger-001.json"
    previous_root = ROOT / "work/runtime/information-battle-war-records-20261025-001/history-root-contract-001.json"
    return {
        "schema": "BATTLE-CONTEXT-SOURCE/1", "status": "static_dispatch_bound_runtime_context_unverified",
        "target": {"version": "1.37.4", "exe_sha256": EXE_SHA, "static_image_base": "0x140000000"},
        "scope": {"new_rea": False, "live_game_access": False, "native_function_calls": False,
                  "production_source_modified": False, "business_export_available": False},
        "kind_binding": {"evidence_kind": "derived_from_saved_REA_dispatch_and_message_keys",
            "router_evidence": router["evidence_id"], "router_body_inclusive": router["procedure"]["body"],
            "selector": "combat vtable slot +0x60 return value; no combat object byte offset guessed",
            "mapping": {"1": "land", "2": "naval"}, "dispatch_proof": selectors,
            "land": {"evidence_id": land["evidence_id"], "body_inclusive": land["procedure"]["body"],
                     "message_key_proof": near(land["pseudocode"], "LANDBATTLEOVER", 1, 3)},
            "naval": {"evidence_id": naval["evidence_id"], "body_inclusive": naval["procedure"]["body"],
                      "message_key_proof": near(naval["pseudocode"], "NAVALBATTLEOVER", 1, 3)},
            "future_noncalling_reader_rule": "accept only in-image vtable slot and in-image six bytes B8 imm32 C3, imm=1 or2, stable before/after; unsupported bodies remain unknown",
            "natural_type_leaf_observed": False, "all_combat_subclasses_supported": False},
        "raw_original_sides": {"evidence_kind": "saved_REA_layout",
            "combat_offsets": ["0x20", "0x28"], "participant_begin_end_offsets": ["0x100", "0x108"],
            "participant_stride": 32, "country_ref_row_offset": "0x10",
            "proof": near(builder["pseudocode"], "SetupNonSiegeResults", 1, 15),
            "router_loop": near(router["pseudocode"], "lVar4 = lVar4 + 0x20", 3, 3),
            "role_rule": "original side0/side1 only; do not relabel them as result attacker/defender or observer our/enemy"},
        "private_war_context": {"evidence_kind": "saved_REA_caller_register_plus_prior_bounded_reader_contract",
            "known_caller_return_rva": "0x23a40d", "private_candidate": "original RBX only for this exact caller",
            "call_neighborhood": known_context, "previous_contract": pin(previous_context),
            "membership_vectors": [["0x48", "0x50", "0x58"], ["0x78", "0x80", "0x88"]],
            "history_root_offset": "0x108", "history_root_vtable_rva": "0x1d20be0",
            "history_root_contract": pin(previous_root), "reader_contract": pin(helper),
            "limits": {"members_each": 256, "participants_each": 256},
            "member_status_is_visibility": False, "native_reference_is_public_id": False,
            "unknown_policy": "not the known caller, null context, invalid vtable/vector/ref, or unstable reads => war unknown; never report unknown as not-a-member"},
        "raw_scalar_slots": {"side_offsets": ["0x118", "0x11c", "0x120", "0x134", "0x138", "0x13c"],
            "evidence_kind": "prior formatter/unit-display ledger, not runtime context acceptance",
            "contract": pin(layout / "unit-display-ledger-001.json"),
            "public_units_or_remaining_counts_assigned": False,
            "summary_source_preserved": pin(owned_summary)},
        "sources": [item["source"] for item in (router, builder, naval, land)] + [pin(Path(__file__))],
        "unresolved": ["actual type leaf encoding and vtable at natural entry",
            "same-address same-date reload and context lifetime/reentry",
            "observer visibility, final UI counts/roles/winner and complete formatted result text",
            "stable war/battle identity and InformationService/LLM event delivery"],
        "goal_complete": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-existing", action="store_true")
    args = parser.parse_args()
    report = assemble()
    if args.verify_existing:
        assert json.loads(OUTPUT.read_text(encoding="utf-8")) == report
    else:
        with OUTPUT.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(json.dumps({"status": report["status"], "kind": report["kind_binding"]["mapping"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
