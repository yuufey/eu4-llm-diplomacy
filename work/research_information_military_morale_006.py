"""Synthesize the smallest positive contract for the current morale cache.

This report deliberately consumes only already-pinned, bounded reports.  It
does not invoke REA, decode the executable, attach to a game, use RPM, or
change the earlier source reports.  The two parallel numeric-record writers,
their exact labels/registration records, and the signed fixed-point consumers
are sufficient to name the copied country cache.  The report keeps the
complete effective/max formula and refresh timing as separate unknowns.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-military-effective-20261027-001"
QUALITY_STAGE = ROOT / "work/runtime/information-military-quality-20261027-001"

WIDGET = STAGE / "morale-widget-source-001.json"
WIDGET_SHA256 = "b5ded8a222b6ea1cca8e60425398e9e0240f43ccb2341450ea9b6d4bfd0055e5"
DISCIPLINE_001 = QUALITY_STAGE / "morale-discipline-source-001.json"
DISCIPLINE_001_SHA256 = "93fd027a25b109214443370ba999bf07e24e3010fe687dec66820d1e32ed0276"
DISCIPLINE_002 = QUALITY_STAGE / "morale-discipline-source-002.json"
DISCIPLINE_002_SHA256 = "db4bd888912fca012c32bed29fda79e6c45f0d1dfc03b989158d97a6b89baf67"
EFFECTIVE_002 = STAGE / "morale-effective-source-002.json"
EFFECTIVE_002_SHA256 = "5c988e0ab3bbed5fb21b02749e0f55bb03a5807fd0999b8ea3f8ace5cbe5c5b0"
OUTPUT = STAGE / "morale-effective-source-003.json"

EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def pin(path: Path, expected: str, evidence_kind: str) -> dict:
    actual = digest(path)
    if actual != expected:
        raise RuntimeError(f"input_pin_mismatch:{path}:{actual}")
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": actual,
        "bytes": path.stat().st_size,
        "evidence_kind": evidence_kind,
    }


def load(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"expected_object:{path}")
    return value


def location(rva: int) -> dict:
    return {"rva": hex(rva), "va": hex(IMAGE_BASE + rva)}


def writer_case(source: dict, side: str) -> dict:
    writer = source["numeric_record_writers"][side]
    return {
        "function": {
            "entry_rva": writer["function"]["entry_rva"],
            "end_rva_exclusive": writer["function"]["end_rva_exclusive"],
            "unwind_rva": writer["function"]["unwind_rva"],
        },
        "bounded_window": {
            "start": writer["bounded_window"]["start"],
            "end_exclusive": writer["bounded_window"]["end_exclusive"],
            "byte_length": writer["bounded_window"]["byte_length"],
            "bytes_sha256": writer["bounded_window"]["bytes_sha256"],
        },
        "case_instructions": writer["case_instructions"],
        "abi_alias": writer["abi_alias"],
        "text_side_effect": writer["text_side_effect"],
    }


def assert_writer_contract(writer: dict, offset: str) -> None:
    effects = {item["rva"]: item["effect"] for item in writer["case_instructions"]}
    if not any(offset in effect for effect in effects.values()):
        raise RuntimeError(f"writer_offset_not_pinned:{offset}")
    if effects.get("0x119fc51", effects.get("0x11a00f0")) is None:
        raise RuntimeError("writer_tag_not_pinned")


def make_report() -> dict:
    widget_pin = pin(WIDGET, WIDGET_SHA256, "pinned_prior_bounded_ordinary_static_report")
    discipline_001_pin = pin(
        DISCIPLINE_001,
        DISCIPLINE_001_SHA256,
        "pinned_prior_bounded_ordinary_static_report",
    )
    discipline_002_pin = pin(
        DISCIPLINE_002,
        DISCIPLINE_002_SHA256,
        "pinned_prior_bounded_ordinary_static_report",
    )
    effective_002_pin = pin(
        EFFECTIVE_002,
        EFFECTIVE_002_SHA256,
        "pinned_prior_REA_evidence_normalization_and_static_inference",
    )

    widget = load(WIDGET)
    discipline_001 = load(DISCIPLINE_001)
    discipline_002 = load(DISCIPLINE_002)
    effective_002 = load(EFFECTIVE_002)

    land_writer = writer_case(widget, "land")
    naval_writer = writer_case(widget, "naval")
    assert_writer_contract(land_writer, "0x9874")
    assert_writer_contract(naval_writer, "0x987c")

    land = discipline_001["findings"]["land_morale"]
    naval = discipline_001["findings"]["naval_morale"]
    raw_fields = discipline_002["findings"]["raw_morale_fields"]
    labels = widget["literal_bindings"]
    registration = widget["registration_paths"]
    corrected_gate = effective_002["numeric_calculation"]["gate"]

    report = {
        "report_id": "information-military-effective-morale-source-003",
        "schema": "information_military_effective_morale_current_cache_contract.v1",
        "evidence_kind": "bounded_static_synthesis_positive_cache_binding",
        "target": {
            "exe_sha256": EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "address_rule": "VA=image_base+RVA; all ranges retain their original bounded half-open semantics",
            "runtime_or_RPM": False,
            "game_or_native_calls": False,
            "REA_query_in_this_script": False,
            "whole_image_disassembly": False,
        },
        "source_pins": {
            "numeric_record_writers": widget_pin,
            "label_and_signed_consumers": discipline_001_pin,
            "country_indexed_raw_field_reanalysis": discipline_002_pin,
            "neutral_gate_correction": effective_002_pin,
        },
        "decision": {
            "positive_static_binding": True,
            "publishable_minimal_cache": True,
            "publish_names": ["army_morale", "navy_morale"],
            "contract": "value={army:raw,navy:raw}; unit=morale; scale=1000; period=current; origin=copied_native_country_morale_cache",
            "complete_effective_or_max_formula": False,
            "refresh_timing": "unknown",
            "runtime_freshness": "unobserved",
            "reason": [
                "Each field has an exact LAND_MORALE/NAVAL_MORALE label and a parallel registration token.",
                "The two index-2 writer cases copy the corresponding country-pointer DWORD verbatim into the same typed record layout (tag=9, payload+0x40, kind=2).",
                "Independent labelled consumers sign-extend the same country fields and use the common 1000 fixed-point scale.",
            ],
        },
        "field_contract": {
            "army_morale": {
                "status": "known_static_cache_binding",
                "source": "country+0x9874",
                "offset": "0x9874",
                "width_bits": 32,
                "signed": True,
                "value_origin": "copied_native_country_morale_cache",
                "unit": "morale",
                "scale": 1000,
                "period": "current",
                "record_writer": {
                    "function_rva": "0x119fb40",
                    "function_va": hex(IMAGE_BASE + 0x119FB40),
                    "case_index": 2,
                    "case_target_rva": "0x119fc4a",
                    "case_target_va": hex(IMAGE_BASE + 0x119FC4A),
                    "case_instructions": [
                        {"rva": "0x119fc4a", "va": hex(IMAGE_BASE + 0x119FC4A), "bytes": "418b8174980000", "effect": "mov eax,DWORD PTR [r9+0x9874]"},
                        {"rva": "0x119fc51", "va": hex(IMAGE_BASE + 0x119FC51), "bytes": "c70309000000", "effect": "mov DWORD PTR [rbx],0x9"},
                        {"rva": "0x119fc57", "va": hex(IMAGE_BASE + 0x119FC57), "bytes": "894340", "effect": "mov DWORD PTR [rbx+0x40],eax"},
                        {"rva": "0x119fc5a", "va": hex(IMAGE_BASE + 0x119FC5A), "bytes": "c7430402000000", "effect": "mov DWORD PTR [rbx+0x4],0x2"},
                    ],
                    "record_layout": {"tag_offset": "0x0", "tag": 9, "raw_offset": "0x40", "kind_offset": "0x4", "kind": 2},
                    "country_pointer_alias": "entry original RDX is moved to R9 at 0x119fb5c; the case reads R9+0x9874 and passes R9 as RCX to 0x33ffa0",
                    "bounded_function_range": writer_case(widget, "land")["function"],
                },
                "label_binding": {
                    "literal": labels["land"]["term"],
                    "rva": labels["land"]["rva"],
                    "va": labels["land"]["va"],
                    "bytes_hex": labels["land"]["bytes_hex"],
                    "registration_token": labels["registration_tokens"]["land"]["token"],
                    "descriptor_key": labels["registration_tokens"]["land"]["descriptor_key"],
                    "registration_callsite": registration["land"]["callsite"]["start"]["rva"] + ".." + registration["land"]["callsite"]["end_exclusive"]["rva"],
                },
                "signed_scale_evidence": {
                    "signed_consumer": land["country_storage"]["signed_consumer_rva"],
                    "unit_from_pinned_consumer": land["country_storage"]["unit"],
                    "scale": land["country_storage"]["scale"],
                    "country_selection_context": raw_fields["land"]["evidence"],
                },
            },
            "navy_morale": {
                "status": "known_static_cache_binding",
                "source": "country+0x987c",
                "offset": "0x987c",
                "width_bits": 32,
                "signed": True,
                "value_origin": "copied_native_country_morale_cache",
                "unit": "morale",
                "scale": 1000,
                "period": "current",
                "record_writer": {
                    "function_rva": "0x119ffd0",
                    "function_va": hex(IMAGE_BASE + 0x119FFD0),
                    "case_index": 2,
                    "case_target_rva": "0x11a00e9",
                    "case_target_va": hex(IMAGE_BASE + 0x11A00E9),
                    "case_instructions": [
                        {"rva": "0x11a00e9", "va": hex(IMAGE_BASE + 0x11A00E9), "bytes": "418b817c980000", "effect": "mov eax,DWORD PTR [r9+0x987c]"},
                        {"rva": "0x11a00f0", "va": hex(IMAGE_BASE + 0x11A00F0), "bytes": "c70309000000", "effect": "mov DWORD PTR [rbx],0x9"},
                        {"rva": "0x11a00f6", "va": hex(IMAGE_BASE + 0x11A00F6), "bytes": "894340", "effect": "mov DWORD PTR [rbx+0x40],eax"},
                        {"rva": "0x11a00f9", "va": hex(IMAGE_BASE + 0x11A00F9), "bytes": "c7430402000000", "effect": "mov DWORD PTR [rbx+0x4],0x2"},
                    ],
                    "record_layout": {"tag_offset": "0x0", "tag": 9, "raw_offset": "0x40", "kind_offset": "0x4", "kind": 2},
                    "country_pointer_alias": "entry original RDX is moved to R9 at 0x119ffef; the case reads R9+0x987c and passes R9 as RCX to 0x340c50",
                    "bounded_function_range": writer_case(widget, "naval")["function"],
                },
                "label_binding": {
                    "literal": labels["naval"]["term"],
                    "rva": labels["naval"]["rva"],
                    "va": labels["naval"]["va"],
                    "bytes_hex": labels["naval"]["bytes_hex"],
                    "registration_token": labels["registration_tokens"]["naval"]["token"],
                    "descriptor_key": labels["registration_tokens"]["naval"]["descriptor_key"],
                    "registration_callsite": registration["naval"]["callsite"]["start"]["rva"] + ".." + registration["naval"]["callsite"]["end_exclusive"]["rva"],
                },
                "signed_scale_evidence": {
                    "signed_consumer": naval["country_storage"]["signed_consumer_rva"],
                    "unit_from_pinned_consumer": naval["country_storage"]["unit"],
                    "scale": naval["country_storage"]["scale"],
                    "country_selection_context": raw_fields["naval"]["evidence"],
                },
            },
        },
        "parallel_writer_dispatch": {
            "land": {
                "function_range": "[0x119fb40,0x119ffd0)",
                "jump_table_rva": "0x119ffb0",
                "case_index": 2,
                "case_target_rva": "0x119fc4a",
            },
            "naval": {
                "function_range": "[0x119ffd0,0x11a0468)",
                "jump_table_rva": "0x11a0448",
                "case_index": 2,
                "case_target_rva": "0x11a00e9",
            },
            "interpretation": "parallel native branches, not an offset-only naming guess",
        },
        "semantic_correction": {
            "prior_misreading": "Do not infer that +0x9874 is merely the neutral multiplier from a 1000 sample.",
            "corrected_gate": corrected_gate,
            "meaning": "REA builder evidence compares country+0xe0c with 1000; the neutral branch skips the +0x9874/helper delta. Therefore +0x9874 is not the neutral comparator used by that builder.",
            "boundary": "This correction separates the copied current cache from the builder's maintenance/contribution explanation; it does not make the cache a complete effective/max formula.",
        },
        "publishable_adapter_contract": {
            "topic": "N03.morale",
            "value_shape": {"army": "signed raw int32", "navy": "signed raw int32"},
            "unit": "morale",
            "scale": 1000,
            "period": "current",
            "basis": "native_country_morale_cache",
            "origin": "copied_native_country_morale_cache",
            "status": "static_bound; runtime freshness and refresh timing remain unobserved",
            "complete": False,
            "retraction_conditions": ["invalid country identity/context", "unvalidated source/profile guard", "parent context change", "short or tampered raw record"],
        },
        "remaining_unknowns": [
            "No runtime/RPM observation was made, so this report does not claim a live value or freshness.",
            "The complete effective/max morale computation, modifiers, and update timing are not reconstructed.",
            "The generic visible consumer of record tag=9/payload+0x40/kind=2 was not followed; the exact writer already establishes the copied source and the exact labels establish the field names.",
            "The REA builder at 0x33ffa0/0x340c50 formats a separate explanation path; its helper/country+0xe0c gate must not be folded into this raw-cache contract.",
        ],
        "minimal_follow_up_target": {
            "selected_rva": "0x119fb40",
            "selected_va": hex(IMAGE_BASE + 0x119FB40),
            "why": "smallest direct positive native writer: parallel case index 2 copies the labelled army field into the typed numeric record; the paired naval writer is already bounded at 0x119ffd0.",
            "not_selected": {"rva": "0x33fca0", "reason": "tooltip/helper contribution path with unresolved manager callback, not the direct current-cache producer"},
        },
        "evidence_layers": {
            "ordinary_static": ["numeric record writer", "labels/registration", "signed country consumers"],
            "REA_normalized_static": ["+0xe0c neutral gate correction in the land explanation builder"],
            "runtime": "none",
        },
    }
    return report


def main() -> None:
    report = make_report()
    OUTPUT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": OUTPUT.relative_to(ROOT).as_posix(), "sha256": digest(OUTPUT), "bytes": OUTPUT.stat().st_size}, ensure_ascii=False))


if __name__ == "__main__":
    main()
