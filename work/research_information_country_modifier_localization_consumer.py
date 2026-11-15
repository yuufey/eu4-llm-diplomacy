"""Bounded ordinary-PE review of country-modifier localization consumers.

The static YAML report establishes the disk text and name-key convention.
This companion report follows the already identified modifier serializer
family, the generic localization lookup call, and bounded UI candidates.  It
does not attach to a process, call native code, or run REA/RPM; a consumer is
only accepted after its operands are decoded in the fixed window.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-country-records-localization-20261027-001"
REPORT = STAGE / "modifier-localization-consumer-001.json"
EXPECTED_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000

sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, make_disassembler, rip_references  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _range_record(pe: PE, md: Any, begin: int, end: int, label: str,
                  selected_rvas: tuple[int, ...] = ()) -> dict[str, Any]:
    if end <= begin or end - begin > 8 * 1024:
        raise ValueError("consumer decode range exceeds 8 KiB bound")
    if not pe.executable(begin) or not pe.executable(end - 1):
        raise ValueError(f"non-executable consumer range: {begin:#x}..{end:#x}")
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise ValueError("consumer range is not fully file-backed")
    decoded = _decode_range(pe, md, begin, end)
    by_rva = {int(row["rva"], 16): row for row in decoded}
    selected = []
    for rva in selected_rvas:
        row = by_rva.get(rva)
        if row is None:
            raise ValueError(f"decoder did not return selected RVA {rva:#x}")
        selected.append(row)
    pdata = pe.function(begin)
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": hex(IMAGE_BASE + begin),
        "end_va_exclusive": hex(IMAGE_BASE + end),
        "byte_length": len(raw),
        "bytes_sha256": _sha256_bytes(raw),
        "pdata_function_at_start": (
            [hex(pdata[0]), hex(pdata[1])] if pdata else None
        ),
        "decoded_instruction_count": len(decoded),
        "selected_instructions": selected,
    }


def _vtable_refs(pe: PE) -> list[dict[str, Any]]:
    refs = rip_references(pe, {0x1CE7F08}).get(0x1CE7F08, [])
    result = []
    for item in refs:
        result.append({
            "instruction_rva": item["instruction_rva"],
            "function_range": item["function_range"],
            "evidence": item["evidence"],
            "interpretation": "vtable address reference only; no modifier text consumer proved",
        })
    return result


def _desc_prefix_literals(pe: PE) -> tuple[list[dict[str, Any]], dict[int, list[dict[str, Any]]]]:
    """Find printable ``desc_`` literals and only their RIP-load candidates."""

    nul = bytes([0])
    literals: list[dict[str, Any]] = []
    targets: set[int] = set()
    for section in pe.sections:
        begin = section["raw"]
        end = begin + section["size"]
        cursor = begin
        while cursor < end:
            offset = pe.data.find(b"desc_", cursor, end)
            if offset < 0:
                break
            terminator = pe.data.find(nul, offset, min(end, offset + 161))
            if terminator < 0:
                terminator = min(end, offset + 161)
            raw = pe.data[offset:terminator]
            if raw and all(0x20 <= byte < 0x7F for byte in raw):
                rva = pe.to_rva(offset)
                if rva is not None:
                    literals.append({
                        "rva": hex(rva),
                        "va": hex(IMAGE_BASE + rva),
                        "section": section["name"],
                        "text": raw.decode("ascii"),
                        "raw_hex": (raw + nul).hex(),
                    })
                    targets.add(rva)
            cursor = offset + 1
    refs = rip_references(pe, targets)
    return literals, refs


def build_report() -> dict[str, Any]:
    pe = PE(game_exe())
    digest = hashlib.sha256(pe.data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unsupported executable SHA-256: {digest}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")
    md, _capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")

    # B359E0 is the vtable +0x10 entry.  The method is split into contiguous
    # .pdata entries; the fixed window covers the complete contiguous method
    # family without decoding anything outside 0xB359E0..0xB35C1A.
    serializer_window = _range_record(
        pe, md, 0xB359E0, 0xB35C1A, "modifier_definition_serializer_family",
        (0xB35A3C, 0xB35A44, 0xB35A49, 0xB35A50, 0xB35A57, 0xB35A60, 0xB35A63),
    )
    serializer_window["pdata_family"] = [
        ["0xb359e0", "0xb359f2"],
        ["0xb359f2", "0xb35a77"],
        ["0xb35a77", "0xb35ada"],
        ["0xb35ada", "0xb35be6"],
        ["0xb35be6", "0xb35c1a"],
    ]
    serializer_window["findings"] = [
        "definition pointer is loaded from instance +0x30",
        "token 0x2968 is passed to helper 0x17091b0",
        "definition +0x158 is read with the SSO length/capacity branch",
        "the resulting key bytes are passed to 0x1707cc0",
        "no desc_ prefix construction or localization lookup call occurs in this window",
    ]

    ui_candidate = _range_record(
        pe, md, 0x4727D0, 0x472B76, "generic_ui_localization_candidate",
        (0x472980, 0x472983, 0x47298E, 0x472991, 0x472AD5, 0x472AE0, 0x472B2F),
    )
    ui_candidate["findings"] = [
        "the +0x158 call at 0x472991 is a virtual predicate on a list object",
        "the direct localization call at 0x472AE0 targets RVA 0x14B33A0",
        "the preceding RIP-relative literal is CHARTERCOMPANY_EXPENSEDESC",
        "this consumer does not read a country modifier definition key or build desc_<key>",
    ]
    ui_candidate["fixed_literal"] = {
        "rva": "0x1c659d0",
        "va": hex(IMAGE_BASE + 0x1C659D0),
        "text": "CHARTERCOMPANY_EXPENSEDESC",
        "raw_hex": (b"CHARTERCOMPANY_EXPENSEDESC\0").hex(),
        "evidence": "RIP-relative lea at RVA 0x472AD5",
    }

    desc_literals, desc_refs = _desc_prefix_literals(pe)
    desc_ref_summary = []
    for literal in desc_literals:
        rva = int(literal["rva"], 16)
        candidates = desc_refs.get(rva, [])
        if candidates:
            desc_ref_summary.append({
                "literal": literal,
                "references": [
                    {
                        "instruction_rva": item["instruction_rva"],
                        "function_range": item["function_range"],
                        "evidence": item["evidence"],
                    }
                    for item in candidates
                ],
            })

    # This is the only desc_-prefix caller decoded in this task.  It reads the
    # already validated definition +0x158 key, appends it to the static prefix,
    # and sends the resulting key to the generic lookup.  The helper is decoded
    # separately only to establish its destination/source/length ABI.
    modifier_description_ui = _range_record(
        pe, md, 0x127A420, 0x127AC21, "modifier_description_ui_consumer",
        (0x127A600, 0x127A606, 0x127A622, 0x127A629, 0x127A63C,
         0x127A641, 0x127A651, 0x127A65B),
    )
    modifier_description_ui["binding"] = {
        "prefix_literal_rva": "0x1c6627c",
        "prefix_literal": "desc_",
        "key_source_instruction": {
            "rva": "0x127a622",
            "operands": "rdx,[r14+0x158]",
            "meaning": "same definition +0x158 stable-key layout closed by country-modifier source contract",
        },
        "sso_length_instruction": {
            "rva": "0x127a629",
            "operands": "r8,[rdx+0x10]",
        },
        "sso_capacity_instruction": {
            "rva": "0x127a62d",
            "operands": "[rdx+0x18],0x10",
        },
        "append_call": {
            "callsite_rva": "0x127a63c",
            "target_rva": "0x932f0",
            "abi": "rcx=local desc_ string, rdx=key bytes, r8=key length",
        },
        "lookup_call": {
            "callsite_rva": "0x127a65b",
            "target_rva": "0x14b33a0",
            "key_operand": "rdx=local string after append",
        },
        "result": "native description key is constructed as desc_ + definition key before lookup",
    }
    append_helper = _range_record(
        pe, md, 0x932F0, 0x9335E, "native_string_append_helper",
        (0x93300, 0x93304, 0x93307, 0x93311, 0x9331C, 0x93320,
         0x93337, 0x9333C),
    )
    append_helper["abi_finding"] = [
        "reads destination end/capacity from [rcx+0x10]/[rcx+0x18]",
        "uses rdx as source pointer and r8 as source length",
        "advances destination end and copies source bytes",
        "writes a NUL terminator at the new end",
    ]

    literal_reference = STAGE / "literal-reference-001" / "native-cache.json"
    literal_meta: dict[str, Any] = {
        "path": "work/runtime/information-country-records-localization-20261027-001/literal-reference-001/native-cache.json",
        "role": "runtime literal cache shape only; not evidence of a native modifier UI consumer",
        "used_for_static_consumer_conclusion": False,
    }
    if literal_reference.is_file():
        literal_meta.update({
            "sha256": _sha256_bytes(literal_reference.read_bytes()),
            "bytes": literal_reference.stat().st_size,
            "observed_keys": [
                "papal_sanction_for_church_taxes",
                "desc_papal_sanction_for_church_taxes",
                "shady_people",
                "desc_shady_people",
            ],
        })

    report = {
        "schema": "information_country_modifier_localization_consumer.v1",
        "stage": "information-country-records-localization-20261027-001",
        "evidence_kind": "ordinary_bounded_pe_static_review",
        "read_only": True,
        "analysis": {
            "native_game_call": False,
            "rpm": False,
            "rea": False,
            "mcp": False,
            "game_process_started": False,
            "decode_budget": {
                "ranges": 4,
                "per_range_max_bytes": 8192,
                "total_decoded_window_bytes": (
                    (0xB35C1A - 0xB359E0)
                    + (0x472B76 - 0x4727D0)
                    + (0x127AC21 - 0x127A420)
                    + (0x9335E - 0x932F0)
                ),
            },
        },
        "target": {
            "game_version": "1.37.4",
            "executable": {"path": str(game_exe()), "sha256": digest, "bytes": len(pe.data)},
            "expected_exe_sha256": EXPECTED_SHA256,
            "image_base_va": hex(IMAGE_BASE),
            "rva_va_rule": "VA = image_base_va + RVA; ranges are half-open",
        },
        "inputs": {
            "research_script": {
                "path": "work/research_information_country_modifier_localization_consumer.py",
                "sha256": _sha256_bytes(Path(__file__).read_bytes()),
            },
            "static_resource_report": "work/runtime/information-country-records-localization-20261027-001/modifier-localization-source-001.json",
            "static_resource_report_role": "disk key convention only; no native consumer claim",
            "modifier_source_contract": "work/runtime/information-country-records-20261027-001/country-modifiers-source-contract-002.json",
            "modifier_vtable_rva": "0x1ce7f08",
            "modifier_vtable_slot": "+0x10 -> 0xb359e0",
        },
        "bounded_ranges": {
            "serializer": serializer_window,
            "ui_candidate": ui_candidate,
            "modifier_description_ui": modifier_description_ui,
            "append_helper": append_helper,
        },
        "desc_prefix_scan": {
            "scope": "all PE sections, printable ASCII strings beginning at desc_",
            "literal_count": len(desc_literals),
            "literals": desc_literals,
            "literals_with_rip_references": desc_ref_summary,
            "exact_modifier_name_literals": [],
            "exact_modifier_description_literals": [],
            "reference_scanner": "bounded RIP-relative LEA/MOV byte pattern; candidates require decoded instruction context",
        },
        "vtable_address_references": _vtable_refs(pe),
        "generic_localization_lookup": {
            "body": {
                "rva": "0x14b33a0",
                "end_rva_exclusive": "0x14b35ba",
                "va": "0x1414b33a0",
                "bytes": 538,
                "role": "generic FNV-1/hash-table localization lookup; reused existing bounded contract",
            },
            "hash_helper": {
                "rva": "0x16faf60",
                "end_rva_exclusive": "0x16fafe3",
                "va": "0x1416faf60",
                "bytes": 131,
                "role": "generic hash-table lower-bound helper; reused existing bounded contract",
            },
            "existing_contract": "work/runtime/information-localization-20261024-001/native-localization-contract.json",
            "modifier_key_binding_found": False,
        },
        "runtime_literal_reference": literal_meta,
        "conclusion": {
            "static_yaml_convention_only": False,
            "static_yaml_convention_scope": "disk text and name-key mapping only; desc_ prefix binding is separately supported by decoded native UI bytes",
            "name_key_binding_closed": False,
            "description_prefix_binding_closed": True,
            "native_modifier_name_consumer_closed": False,
            "native_modifier_description_consumer_closed": True,
            "implementation_status": "native desc_ + definition +0x158 key construction is closed; name-key consumer remains unresolved",
        },
        "known_and_unknown": {
            "known": [
                "the validated native modifier definition carries an ASCII stable key at definition +0x158",
                "the disk resource contains matching key and desc_<key> entries for papal_sanction_for_church_taxes and shady_people",
                "the shared NativeLocalizationReader normalizes literal cache entries and preserves language/provenance",
                "RVA 0x127A622 reads the known definition +0x158 key layout",
                "RVA 0x127A63C appends that key to the native desc_ prefix through RVA 0x932F0",
                "RVA 0x127A65B looks up the resulting desc_<key> string",
            ],
            "unknown": [
                "B359E0 serializes a key but does not establish display-text lookup semantics",
                "the 0x4727D0 UI candidate is unrelated to modifiers based on its fixed literal",
                "current native cache presence for these two modifier keys was not observed in this task",
                "the corresponding native name-key consumer is not closed; the same UI function's other branch uses a virtual getter result +0x10",
                "the exact widget/type name of the 0x127A420 object list is not separately RTTI-closed",
            ],
        },
        "next_bounded_entry": {
            "suggested_rva": "0x127a4f4",
            "reason": "resolve the name branch's virtual getter result +0x10 without reopening the generic lookup",
            "constraint": "preserve the closed desc_ path and do not treat the name branch as proven until its stable key source is identified",
        },
        "source_hashes": {
            "static_source_report_sha256": "2e1047a61c40439818c3f2f2fa7ef423d7fdfd0d1be8d94dfba7c0efe92f72e5",
            "static_contract_sha256": "69e4e4983da8c18bed44392ce0c737fec41348f43273ff62aaced7eb1291c64e",
        },
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=REPORT)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing evidence: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    report = build_report()
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(output),
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "serializer_bytes": report["bounded_ranges"]["serializer"]["byte_length"],
        "ui_candidate_bytes": report["bounded_ranges"]["ui_candidate"]["byte_length"],
        "name_key_binding_closed": report["conclusion"]["name_key_binding_closed"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
