"""Record bounded static facts needed before capturing natural battle results.

This consumes existing, hash-bound REA records. It never calls the game, REA,
or a disassembler. Side representatives, selected country references, original
combat sides and reordered result sides deliberately remain separate objects.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-battle-capture-contract-20261025-001"
TARGET_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
SPECS = {
    "result_constructor": (
        ROOT / "work/runtime/information-battles-20261025-001/rea-battle-result-object-001/evidence.json",
        "ev_5a34a1545032fa29696f022c0f7ce62107b4677dc9af13d095461271c051cce9", 0x237FC0),
    "country_selector": (STAGE / "rea-side-country-selector-001/evidence.json",
        "ev_eb423943852560c33b8bf764a143cd8c925e88887656fb8f828bfd24719d719d", 0x21C7D0),
    "capture_effects": (STAGE / "rea-naval-captured-results-001/evidence.json",
        "ev_ba2f394615966814a83a2a7efe7d010b1b032d6a5b0e006eb5ec43986470de41", 0x237150),
    "commander_selector": (STAGE / "rea-side-commander-selector-001/evidence.json",
        "ev_66949db89bae83ffb97d97534caf7313ed6692fd7db61ea141f6b78b1c40a973", 0x21FEB0),
}


def load(name: str) -> tuple[dict, dict]:
    path, evidence_id, rva = SPECS[name]
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError(f"evidence exceeds bounded read: {path}")
    raw = path.read_bytes()
    evidence = json.loads(raw)
    assert evidence["subject"]["digest"]["sha256"] == TARGET_SHA
    assert evidence["evidence_id"] == evidence_id
    value = evidence["normalized_result"]
    assert value["procedure"]["address"] == hex(IMAGE_BASE + rva)
    original = evidence["raw_result"]["value"]
    for key in ("procedure", "pseudocode", "assembly"):
        assert original[key] == value[key], (name, key)
    record = {"path": path.relative_to(ROOT).as_posix(), "bytes": len(raw),
              "sha256": hashlib.sha256(raw).hexdigest(), "evidence_id": evidence_id,
              "rva": hex(rva), "static_va": hex(IMAGE_BASE + rva),
              "body_inclusive": value["procedure"]["body"]}
    return value, record


def excerpt(value: dict, needle: str, *, assembly: bool = False, after: int = 2) -> dict:
    lines = value["assembly"] if assembly else value["pseudocode"].splitlines()
    for index, line in enumerate(lines):
        if needle in line:
            return {"kind": "rea_assembly" if assembly else "rea_pseudocode",
                    "line_1based": index + 1, "needle": needle,
                    "lines": lines[max(0, index - 1):index + after + 1]}
    raise ValueError(f"required static expression is absent: {needle}")


def main() -> None:
    output = STAGE / "side-identity-ledger-001.json"
    if output.exists():
        raise FileExistsError(output)
    values, records = {}, {}
    for name in SPECS:
        values[name], records[name] = load(name)
    constructor = values["result_constructor"]
    country = values["country_selector"]
    capture = values["capture_effects"]
    commander = values["commander_selector"]
    facts = [
        {"id": "initial_result_sides", "evidence": "result_constructor",
         "observation": "Before optional war-side reordering, result+0x20 and +0x98 receive qword references at original combat side +0x100 begin +0x10; original sides are combat+0x20/+0x28. These are result side+0x10 country fields, not the complete participant lists.",
         "proof": [excerpt(constructor, "MOV RCX, qword ptr [RAX + 0x100]", assembly=True, after=3),
                   excerpt(constructor, "MOV qword ptr [RBX + 0x98], RAX", assembly=True)],
         "unresolved": "No runtime handle resolution, participant completeness, attacker/defender business role or visibility validation."},
        {"id": "country_selection_is_not_first_entry", "evidence": "country_selector",
         "observation": "Selector examines the side's +0x100/+0x108 range, +0xf8 count and +0xe8 linked nodes. Its return can be a first participant reference, a node object's +0xd0 reference, a value obtained by virtual +0x68 then 1a8ba0, or the empty placeholder bytes. Do not replace it with an unconditional first-entry read.",
         "proof": [excerpt(country, "if ((*(longlong *)(param_1 + 0x108)", after=10),
                   excerpt(country, "FUN_1401a8ba0", after=4),
                   excerpt(country, "MOV word ptr [RSP + 0x30], 0x2d2d", assembly=True, after=4)],
         "unresolved": "Virtual target semantics and exact constituent roles remain unresolved; this is not a proven pure getter contract."},
        {"id": "war_membership_comparison", "evidence": "result_constructor",
         "observation": "Only when third parameter war-context is nonzero, constructor runs 21c7d0 on original side0, compares reference bits 32..47 with each 8-byte entry of war+0x48..+0x50, and skips swapping on a match. No match, including an empty range, enters the swap. It does not compare the full 64-bit references.",
         "proof": [excerpt(constructor, "0x140238513:", assembly=True, after=17)],
         "unresolved": "war side A has not been independently named war attacker; no-match alone does not prove membership of side B or a valid complete context."},
        {"id": "swap_is_field_specific", "evidence": "result_constructor",
         "observation": "Swap inverts result+0x108, exchanges +0x64/+0xdc losses, +0x84/+0xfc fields, commander strings +0x28/+0xa0, country references +0x20/+0x98, +0x100/+0x104 auxiliaries, then calls 1a0ce68 with [result+0x48,result+0x64) and result+0xc0. The last range is seven 4-byte count slots, not a copy of the entire side object.",
         "proof": [excerpt(constructor, "0x14023854f:", assembly=True, after=38)],
         "unresolved": "Callee string/range-swap behavior is inferred from arguments here, not newly analyzed in this batch. Preserve original-side identity separately from saved attacker/defender names."},
        {"id": "loss_slots_change_after_capture", "evidence": "result_constructor",
         "observation": "Constructor copies pre-capture result losses into summary+0x44/+0x48, then calls 1dd930 and, for kind2, 237150. After possible war-side swap it adds summary's pointer-vector element count to result+0x64 when result+0x108 is false, otherwise to +0xdc. Result loss slots and the earlier summary loss values therefore are not interchangeable snapshots.",
         "proof": [excerpt(constructor, "0x1402384da:", assembly=True, after=16),
                   excerpt(constructor, "0x1402385db:", assembly=True, after=11)],
         "unresolved": "Precise displayed loss/capture totals and side meaning need natural naval runtime validation; no uniform field mapping is promoted."},
        {"id": "capture_vector_contains_live_ship_references", "evidence": "capture_effects",
         "observation": "237150 appends references from one side's +0x170/+0x178 vector and later selected fleet entries into summary begin/end/capacity at +0/+8/+0x10. It also transfers ships via d3f620/d3f3e0 and changes owner-related state. Static diagnostic string names CCombat::StealShips Append %u.",
         "proof": [excerpt(capture, "*(longlong *)(lVar12 + 0x178)", after=19),
                   excerpt(capture, '"CCombat::StealShips Append %u"', after=8),
                   excerpt(capture, "FUN_140d3f620", after=8)],
         "unresolved": "Ship type/name/owner schema, lifetimes, duplicate entries and actual displayed capture detail not yet validated. Deferred pointers must not escape to an external poller."},
        {"id": "capture_path_is_stateful_and_random", "evidence": "capture_effects",
         "observation": "The natural capture path calls the random routine 14c70b0, increments a global counter, compares random modulo100 against a threshold, transfers ships, updates statistics and invokes additional virtual callbacks. It cannot be called to obtain a read-only query or recompute a historical capture outcome.",
         "proof": [excerpt(capture, "FUN_1414c70b0", after=15),
                   excerpt(capture, "if (iVar3 % 100 <", after=13)],
         "unresolved": "This is static code evidence, not observation of a capture or RNG execution in the current game."},
        {"id": "commander_selection_is_stateful", "evidence": "commander_selector",
         "observation": "21feb0 lazily allocates a 0xa8 default object in global233fea0, walks side+0xe8 nodes, uses object+d8 commander candidates and a computed score via8629d0 to select a higher score. Even a selector-like function is not automatically allocation-free or pure.",
         "proof": [excerpt(commander, "if (DAT_14233fea0 == 0)", after=7),
                   excerpt(commander, "FUN_1408629d0", after=8)],
         "unresolved": "Commander role/scoring business semantics and default-object display are not independently validated. Capture already-created result commander text during its valid lifetime."},
    ]
    report = {
        "schema": "information_battle_side_identity_ledger_v1",
        "status": "static_findings_with_explicit_unresolved_conditions",
        "target_exe_sha256": TARGET_SHA, "static_image_base": hex(IMAGE_BASE),
        "address_convention": "RVA in conclusions; static VA and inclusive body in evidence records",
        "evidence_kind": "existing REA assembly/pseudocode; derived static interpretation",
        "runtime_observed": False, "game_accessed": False,
        "new_native_calls": 0, "new_hooks_installed": 0,
        "source_files": records, "facts": facts,
        "capture_requirements": [
            "Copy original combat side references, complete participant sets and result-side mapping independently; do not replace them with one country label.",
            "Choose a point after natural naval transfer/capture completion if final capture vector is required, before stack-summary cleanup and result release.",
            "Retain raw capture vector count and converted summary loss slots separately from post-adjustment result loss slots.",
            "Copy owned strings and ship details during verified valid lifetime; do not call selectors/constructors/effect paths as queries.",
            "Prove hook ABI, thread/reentrancy and callback lifetime, world/session identity, visibility and full native formatted-text path before production enablement.",
        ],
        "catalog_promotion": False,
        "limits": "No natural land/naval battle sample, full B01-B04 payload, hook/producer or end-to-end event delivery is established by this ledger.",
    }
    STAGE.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path": output.relative_to(ROOT).as_posix(), "facts": len(facts),
                      "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()
