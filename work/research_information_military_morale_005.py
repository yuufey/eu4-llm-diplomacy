"""Normalize the completed REA evidence for the land-morale builder.

This report consumes one already-completed, read-only REA function query.  It
does not invoke REA, decode the executable again, attach to a game, or use
runtime/RPM data.  The purpose is to make the builder's exact labels and
fixed-point delta branch explicit, while keeping its unresolved helper and
neutral fallback separate from the numeric record writer reported earlier.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-military-effective-20261027-001"
EVIDENCE = STAGE / "rea-land-morale-builder-33ffa0-001/evidence.json"
EVIDENCE_SHA256 = "bb5eff9e29833b7adec60e7896e53e039698f8da777e5b562a5111c308fd915e"
WIDGET_REPORT = STAGE / "morale-widget-source-001.json"
WIDGET_REPORT_SHA256 = "b5ded8a222b6ea1cca8e60425398e9e0240f43ccb2341450ea9b6d4bfd0055e5"
PRIOR_EFFECTIVE = STAGE / "morale-effective-source-001.json"
PRIOR_EFFECTIVE_SHA256 = "f9a68ad086c2b6686a8f0e14c0c6fdb1d6cf411dcd7b950f9fdf44a7a520f9b9"
OUTPUT = STAGE / "morale-effective-source-002.json"

EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
BUILDER_RVA = 0x33FFA0
BUILDER_VA = IMAGE_BASE + BUILDER_RVA


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def pin(path: Path, expected: str, kind: str) -> dict:
    actual = digest(path)
    if actual != expected:
        raise RuntimeError(f"input_pin_mismatch:{path}:{actual}")
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": actual,
        "bytes": path.stat().st_size,
        "evidence_kind": kind,
    }


def load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"expected_object:{path}")
    return value


def address_of(assembly_line: str) -> int | None:
    if not assembly_line.startswith("0x") or ":" not in assembly_line:
        return None
    try:
        return int(assembly_line.split(":", 1)[0], 16)
    except ValueError:
        return None


def callees_by_address(value: dict, addresses: set[int]) -> list[dict]:
    selected = []
    for item in value.get("callees", []):
        try:
            address = int(item["address"], 16)
        except (KeyError, TypeError, ValueError):
            continue
        if address in addresses:
            selected.append(item)
    return selected


def make_report() -> dict:
    evidence_pin = pin(EVIDENCE, EVIDENCE_SHA256, "completed_read_only_REA_evidence")
    widget_pin = pin(WIDGET_REPORT, WIDGET_REPORT_SHA256, "pinned_prior_ordinary_static_report")
    prior_pin = pin(PRIOR_EFFECTIVE, PRIOR_EFFECTIVE_SHA256, "pinned_prior_ordinary_static_report")
    evidence = load(EVIDENCE)
    raw_value = evidence["raw_result"]["value"]
    normalized = evidence.get("normalized_result", {})
    pseudocode = raw_value["pseudocode"].replace("\r", "")
    pseudocode_lines = pseudocode.splitlines()

    # Keep only the lines that establish labels, the branch and its final
    # output ABI.  The full source remains pinned by the evidence digest.
    excerpt_numbers = [56, 194, 195, 199, 200, 203, 212, 213, 218, 219, 222, 254, 255, 256, 257, 258, 259, 260, 310, 314, 315, 318, 319, 325, 326, 328, 330]
    pseudocode_excerpts = [
        {"line": number, "text": pseudocode_lines[number - 1]}
        for number in excerpt_numbers
        if 0 < number <= len(pseudocode_lines)
    ]

    important_addresses = {
        0x14033FFD3,
        0x14033FFDA,
        0x14033FFDF,
        0x14034053B,
        0x14034055F,
        0x140340570,
        0x140340577,
        0x14034057E,
        0x14034058C,
        0x140340591,
        0x140340593,
        0x140340596,
        0x14034059B,
        0x14034059E,
        0x1403405A4,
        0x1403405A8,
        0x1403405AC,
        0x1403405BA,
        0x1403405C1,
        0x1403405C6,
        0x1403407A0,
        0x1403407A5,
        0x1403407AB,
        0x1403407AF,
        0x1403407B2,
        0x1403407B7,
        0x1403407BA,
        0x1403407BF,
        0x1403407CF,
        0x1403407EC,
    }
    assembly_excerpts = [
        line for line in raw_value["assembly"] if address_of(line) in important_addresses
    ]

    procedure = raw_value["procedure"]
    body = procedure["body"]
    direct_callees = callees_by_address(
        raw_value,
        {
            0x14033FCA0,
            0x1414BC950,
            0x1414B33A0,
            0x1417042F0,
            0x1408E8AE0,
            0x1408685D0,
        },
    )

    report = {
        "report_id": "information-military-effective-morale-source-002",
        "schema": "information_military_effective_morale_rea_builder.v1",
        "evidence_kind": "REA_read_only_evidence_normalization_with_static_inference",
        "target": {
            "exe_sha256": EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "builder_rva": hex(BUILDER_RVA),
            "builder_va": hex(BUILDER_VA),
            "runtime_or_RPM": False,
            "game_or_native_calls": False,
            "REA_query_in_this_script": False,
            "whole_image_disassembly": False,
        },
        "source_pins": {
            "rea_evidence": evidence_pin,
            "prior_effective_static": prior_pin,
            "numeric_record_writer_static": widget_pin,
        },
        "rea_provenance": {
            "evidence_id": evidence["evidence_id"],
            "provider": evidence["provider"],
            "operation": evidence["operation"],
            "procedure": evidence["parameters"]["procedure"],
            "confidence": evidence.get("confidence"),
            "authority": evidence.get("authority"),
            "analysis_profile_digest": evidence["analysis_profile"].get("digest"),
            "database_mutation": evidence["analysis_profile"]["parameters"].get("database_mutation"),
            "body": body,
            "normalized_result_present": isinstance(normalized, dict),
            "evidence_limits": evidence.get("limitations", []),
        },
        "builder_shape": {
            "signature_reported_by_REA": raw_value["procedure"].get("signature"),
            "param_1": "country-like object; inferred from [param_1+0x2440], [param_1+0x28c0], [param_1+0xe0c], [param_1+0x9874]",
            "param_2": "output object/string-container destination; pseudocode ends FUN_1417042f0(local_e0,param_2) then returns param_2",
            "param_3": "optional contribution/context object; checked for null and vtable+0x50, then param_3[0xd] is appended",
            "static_status": "param_1/param_2 semantic names are inference from accesses and final call; REA signature itself remains undefined",
        },
        "labels_and_sources": {
            "entry_label": {
                "literal": "COUNTRY_MORALE_TECH",
                "literal_va": "0x141c5b970",
                "source_va": "0x14033ffd3",
                "assembly": "LEA RDX,[0x141c5b970]; CALL 0x1414b33a0",
                "meaning_status": "literal is exact; business interpretation is a morale-tech contribution/explanation label, not by itself a scalar getter name",
            },
            "delta_label": {
                "literal": "land_maintenance",
                "literal_va": "0x141c5b988",
                "source_va": "0x1403405ba",
                "assembly": "LEA RDX,[0x141c5b988]; CALL 0x1414b33a0",
                "meaning_status": "exact localized key used for the non-neutral delta line; do not rename it to a complete morale field",
            },
            "keyed_contributions": {
                "country_container": "param_1+0x28c0 through FUN_14093d5c0",
                "entry_key": "0x252",
                "entry_value_default": 1000,
                "optional_param3_key": "0x252",
                "final_base_key": "0x2a",
                "final_base_value": 1000,
                "semantic_status": "the key/value bytes are observed; their complete domain names are unresolved",
            },
        },
        "numeric_calculation": {
            "gate": {
                "rva": "0x34055f",
                "instruction": "CMP dword ptr [R15 + 0xe0c], 0x3e8",
                "non_neutral_branch": "country+0xe0c != 1000",
                "neutral_branch": "country+0xe0c == 1000 jumps to 0x34071b and skips the +0x9874/helper delta block",
            },
            "non_neutral": {
                "raw_source": "signed DWORD [country+0x9874] loaded at 0x340570",
                "helper_call": {
                    "rva": "0x34058c",
                    "target_rva": "0x33fca0",
                    "rcx": "country pointer (R15)",
                    "rdx": "output slot [RBP+0x78]",
                    "r8": "input slot [RBP+0x60] containing 1000",
                    "r9d": 0,
                },
                "arithmetic": "delta_raw = wrap_i32(i32(country+0x9874) - i32(helper_result_dword))",
                "formatter": {
                    "rva": "0x14bc950",
                    "call_rva": "0x3405ac",
                    "raw_pointer": "[RBP+0x60] containing delta_raw",
                    "kind": 2,
                    "flag": 1,
                    "scale_from_pinned_formatter": 1000,
                },
                "localized_line": "delta_raw / 1000 is appended under land_maintenance",
            },
            "output": {
                "finalizer_rva": "0x17042f0",
                "call_rva": "0x3407bf",
                "return_rva": "0x3407cf",
                "observed": "finalizer receives the assembled local_e0 and param_2; RAX is then set to the saved param_2 and returned",
                "classification": "formatted explanation/string-container output, not a numeric scalar return",
            },
        },
        "semantic_contract": {
            "closed": [
                "The builder is label-aware: it creates COUNTRY_MORALE_TECH content and, only on the non-neutral branch, a land_maintenance contribution line.",
                "The displayed contribution is a signed 32-bit difference between country+0x9874 and the helper result with input 1000.",
                "The difference is passed to the fixed-point formatter with kind=2/flag=1; the pinned formatter evidence gives signed_i32/1000 display scale.",
                "The function returns an assembled formatted object through param_2; it is not a standalone army-morale numeric getter.",
            ],
            "not_closed": [
                "The helper 0x33fca0 has an indirect manager callback/global contribution; a raw +0x9874 reader cannot reproduce it.",
                "The neutral +0xe0c==1000 path bypasses the raw/helper delta and uses the existing fallback branch at 0x34071b.",
                "The complete semantic names of keys 0x252 and 0x2a and the final visible control that consumes the formatted object remain unresolved.",
                "This land builder evidence does not by itself close the analogous naval builder 0x340c50.",
            ],
            "unit": {
                "raw_unit": "fixed-point morale multiplier/delta candidate",
                "scale": 1000,
                "display_example": "raw 1000 formats as 1.000 under the pinned formatter contract",
                "scope": "displayed contribution line only; not a claim that the complete N03 maximum morale equals delta_raw/1000",
            },
        },
        "adapter_boundary": {
            "safe_contract": "If an adapter exposes this builder-derived contribution, it must validate the +0xe0c gate, reproduce the helper 0x33fca0 with input=1000/r9=0 and signed i32 subtraction, and represent the result as a partial display-contribution field. It must withdraw the value on the neutral fallback or unresolved callback path.",
            "unsafe_shortcut": "Reading country+0x9874 and publishing it as complete army_morale, maximum morale, or total multiplier would omit the helper subtraction and neutral fallback.",
            "relation_to_numeric_record": "The separate 0x119fb40 numeric record writer copies +0x9874 verbatim into record+0x40; that raw record is not equivalent to this builder's land_maintenance delta.",
        },
        "minimal_remaining_targets": [
            {
                "rva": "0x33fca0",
                "va": "0x14033fca0",
                "reason": "close the helper's indirect manager contribution and confirm whether its output is the complete adjustment used by the builder",
                "already_static_range": "prior ordinary bounded report 0x33fca0..0x33ff99",
                "next_action": "one narrow REA callee query if root chooses; no new game/RPM",
            },
            {
                "rva": "0x34071b",
                "va": "0x14034071b",
                "reason": "close the neutral fallback object/value branch, which is intentionally skipped when +0xe0c != 1000",
                "already_static_range": "prior ordinary bounded report land_morale_display_getter 0x34055f..0x340819",
                "next_action": "reuse existing bounded bytes or one narrow query only if needed",
            },
            {
                "rva": "0x340c50",
                "va": "0x140340c50",
                "reason": "analogous naval builder is not closed by the land-only REA evidence",
                "already_static_range": "prior ordinary bounded report naval_morale_display_getter 0x340c50..0x341463",
                "next_action": "only query separately if naval completion is required",
            },
        ],
        "direct_callee_metadata": direct_callees,
        "pseudocode_excerpts": pseudocode_excerpts,
        "assembly_excerpts": assembly_excerpts,
        "limits_and_unknowns": [
            "The REA p-code is decompiler output, not source code or runtime behavior; indirect callback semantics remain unresolved.",
            "The REA function query used a completed read-only database and did not mutate or reanalyze it.",
            "No new runtime/RPM sample, game action, save, or native call was performed.",
            "The report does not overwrite morale-effective-source-001 or morale-widget-source-001.",
        ],
    }
    return report


def main() -> None:
    report = make_report()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    if OUTPUT.exists():
        raise RuntimeError(f"refusing_to_overwrite:{OUTPUT}")
    with OUTPUT.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(OUTPUT)
    print(json.dumps({"evidence_id": report["rea_provenance"]["evidence_id"], "source_sha256": report["source_pins"]["rea_evidence"]["sha256"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
