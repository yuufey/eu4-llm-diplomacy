"""Synthesize the bounded, already archived evidence for N03 military modifiers.

This is an offline evidence join.  It does not open the game, call REA, read
RPM data, disassemble a PE, or import a production reader.  Source files are
size checked and SHA-256 pinned before the report is written.  The report is
created exclusively so an accidental rerun cannot silently replace evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "work" / "runtime" / "information-military-professionalism-20261027-001" / "next-military-modifiers-source-001.json"
MAX_SOURCE_BYTES = 2_000_000
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = "0x140000000"


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def _sha256(path: Path) -> tuple[str, int]:
    size = path.stat().st_size
    if size <= 0 or size > MAX_SOURCE_BYTES:
        raise RuntimeError(f"source_size_out_of_bound:{_relative(path)}:{size}")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            digest.update(block)
    if total != size:
        raise RuntimeError(f"source_size_changed:{_relative(path)}")
    return digest.hexdigest(), total


def _load_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise RuntimeError(f"json_size_out_of_bound:{_relative(path)}")
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"json_root_not_object:{_relative(path)}")
    return value


def _pin(path_text: str, role: str) -> dict[str, Any]:
    path = ROOT / path_text
    digest, size = _sha256(path)
    return {"path": path_text, "sha256": digest, "bytes": size, "role": role}


def _range_pin(item: dict[str, Any]) -> dict[str, Any]:
    start = item.get("start") or item.get("start_rva")
    end = item.get("end_exclusive") or item.get("end_rva_exclusive")
    result = {
        "purpose": item.get("purpose"),
        "start": start,
        "end_exclusive": end,
        "byte_length": item.get("byte_length"),
        "bytes_sha256": item.get("bytes_sha256"),
    }
    if "start_va" in item:
        result["start_va"] = item.get("start_va")
    if "end_va_exclusive" in item:
        result["end_va_exclusive"] = item.get("end_va_exclusive")
    if "pdata" in item:
        pdata = item["pdata"]
        if isinstance(pdata, dict):
            result["pdata"] = {
                "start_rva": pdata.get("start_rva"),
                "end_rva_exclusive": pdata.get("end_rva_exclusive"),
            }
    return result


def build_report() -> dict[str, Any]:
    links_path = ROOT / "work" / "runtime" / "information-military-effective-20261027-001" / "discipline-links-003.json"
    source_path = ROOT / "work" / "runtime" / "information-military-quality-20261027-001" / "morale-discipline-source-002.json"
    profile_path = ROOT / "bridge" / "information" / "profiles" / "military-effective-memory-1374-v2.json"
    religion_profile_path = ROOT / "bridge" / "information" / "profiles" / "religious-unity-memory-1374.json"
    links = _load_json(links_path)
    source = _load_json(source_path)
    profile = _load_json(profile_path)
    religion_profile = _load_json(religion_profile_path)

    if links.get("exe", {}).get("sha256") != EXE_SHA256:
        raise RuntimeError("discipline_links_exe_sha_mismatch")
    if source.get("exe", {}).get("sha256") != EXE_SHA256:
        raise RuntimeError("morale_discipline_exe_sha_mismatch")
    if profile.get("executable", {}).get("sha256") != EXE_SHA256:
        raise RuntimeError("military_effective_profile_exe_sha_mismatch")
    if religion_profile.get("executable", {}).get("sha256") != EXE_SHA256:
        raise RuntimeError("religious_unity_profile_exe_sha_mismatch")

    layout = profile["layout"]
    religion_layout = religion_profile["layout"]
    discipline_ranges = [
        _range_pin(item)
        for item in source.get("ranges", [])
        if item.get("purpose") == "discipline_effective_value_and_manager_callback"
    ]
    if len(discipline_ranges) != 1:
        raise RuntimeError("discipline_range_not_unique")
    callback_windows = [_range_pin(item) for item in links.get("decoded_windows", [])]

    artifacts = [
        _pin("docs/LLM导出信息目录.md", "original information catalog N03/N07/N08/N09 requirements"),
        _pin("docs/信息字段覆盖.json", "current coverage matrix; military_modifiers and N07-N09 remain planned"),
        _pin("bridge/information/catalog.py", "source catalog field names and object/trigger contract"),
        _pin("docs/宗教统一计算路径.md", "bounded dense/sparse country modifier layout reference"),
        _pin("bridge/information/profiles/religious-unity-memory-1374.json", "numeric modifier database offsets and boolean metadata offsets"),
        _pin("bridge/information/religious_unity_memory.py", "bounded reader showing record access is limited to processor/resolved type/flags"),
        _pin("bridge/information/profiles/military-effective-memory-1374-v2.json", "corrected discipline modifier-cache profile"),
        _pin("bridge/information/military_effective_memory.py", "bounded discipline cache reader implementation and validation"),
        _pin("work/runtime/information-military-effective-20261027-001/source-contract-002.json", "corrected embedded modifier-object address semantics"),
        _pin("work/runtime/information-military-effective-20261027-001/discipline-links-003.json", "bounded global manager/processor slot and constructor evidence"),
        _pin("work/runtime/information-military-quality-20261027-001/morale-discipline-source-002.json", "bounded discipline keyed-cache consumer"),
        _pin("work/runtime/information-military-effective-20261027-001/discipline-container-code-001.json", "bounded country modifier-cache selector window"),
    ]

    return {
        "report_id": "next-military-modifiers-source-001",
        "schema": "information_military_modifiers_source_synthesis.v1",
        "evidence_kind": "bounded_existing_repository_evidence_synthesis",
        "created_by": "work/research_information_military_modifiers_001.py",
        "research_boundary": {
            "runtime_or_RPM": False,
            "game_or_native_calls": 0,
            "new_REA": False,
            "whole_image_disassembly": False,
            "source_read_limit_bytes": MAX_SOURCE_BYTES,
            "note": "Only existing small reports, profiles, source and catalog files were read; no old large REA evidence was loaded.",
        },
        "target": {
            "game_version": "1.37.4",
            "executable_sha256": EXE_SHA256,
            "image_base": IMAGE_BASE,
            "address_rule": "RVA is relative to the image base; runtime VA requires the current module base.",
            "observer_scope": "country/FRA is the existing production boundary; this report contains no runtime country value.",
        },
        "original_requirements": {
            "N03": {
                "catalog_field": "military_modifiers",
                "catalog_status": "planned",
                "catalog_description": "N03 names key military modifiers but provides no fixed hand-picked ID set.",
                "decision_scope": "Keep modifier values and final combat attributes separate; do not substitute morale/discipline outputs for the modifier collection.",
                "selection_rule": "unresolved; a reader must not silently select a few familiar IDs or expose every raw slot as the field.",
            },
            "N07": {
                "required_current_projection": ["modifier_id", "name", "description", "source", "target", "effects"],
                "scope": "country plus explicitly associated local targets; country and province/local modifiers must remain distinct.",
            },
            "N08": {
                "required_lifecycle": ["modifier_start_date", "modifier_end_date", "remaining_days", "duration_type", "removal_conditions"],
                "scope": "fixed-term, permanent, conditional, unknown and refresh/replace/remove transitions must remain distinguishable.",
            },
            "N09": {
                "required_effect_projection": ["modifier_effects", "effective_status", "source_breakdown", "final_value"],
                "scope": "Definition records are not active effects; final attributes must not be double-counted as a modifier list.",
            },
        },
        "reusable_sources": {
            "country_modifier_cache": {
                "status": "reusable_as_keyed_numeric_cache_input_only",
                "profile": _relative(profile_path),
                "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
                "layout": {
                    "country_cache_state_offset": layout["country_cache_state_offset"],
                    "country_modifier_object_offset": layout["country_modifier_object_offset"],
                    "dense_flag_offset": layout["modifier_dense_flag_offset"],
                    "values_pointer_offset": layout["modifier_values_pointer_offset"],
                    "sparse_count_offset": layout["modifier_sparse_count_offset"],
                    "sparse_entry_stride": layout["sparse_entry_stride"],
                    "dense_value_offset_for_discipline": layout["dense_modifier_value_offset"],
                    "max_sparse_count": layout["max_sparse_count"],
                },
                "what_it_proves": "country+0x28d0 is an embedded modifier object; object+0x10/+0x58/+0x64 select dense or sparse keyed values. Sparse entries are {id,value} pairs, first matching id, stride 8.",
                "not_full_military_modifiers": ["no active-item owner/list head", "no source/target provenance", "no start/end/removal dates", "no name/description/category/effect expansion"],
            },
            "global_modifier_database": {
                "status": "reusable_numeric_record_layout_only",
                "global_rva": "0x2358060",
                "global_va_at_static_image_base": "0x142358060",
                "record_stride": "0x60",
                "known_record_offsets": {
                    "processor": "0x40",
                    "resolved_type": "0x54",
                    "flags": "0x5c",
                },
                "what_it_proves": "At runtime, module_base+0x2358060 must first be dereferenced to a manager pointer; an indexed processor slot can then be addressed as manager+(index*0x60)+0x40.",
                "not_metadata_proof": "The selected archived evidence does not provide a verified record name/key/category table or an ID-to-definition mapping. The queried 0x77 is a discipline key, not a proof of such metadata.",
                "religion_layout_source": _relative(religion_profile_path),
                "religion_layout_source_sha256": hashlib.sha256(religion_profile_path.read_bytes()).hexdigest(),
            },
            "discipline_processor": {
                "status": "reusable_only_for_existing_discipline_child",
                "index": "0x77",
                "processor_slot_formula": "manager+(0x77*0x60)+0x40",
                "vtable_rva": "0x1cc9400",
                "method_rva": "0x8f71d0",
                "constructor_rva": "0x8f1df0",
                "what_it_proves": "The discipline child can recognize its own processor and keyed inputs; this is not an active modifier enumerator.",
            },
        },
        "evidence_ranges": {
            "discipline_keyed_cache_consumer": discipline_ranges,
            "manager_callback_readers_and_constructor": callback_windows,
            "cache_selector": {
                "path": "work/runtime/information-military-effective-20261027-001/discipline-container-code-001.json",
                "range": {
                    "start_rva": "0x93d5c0",
                    "end_rva_exclusive": "0x93d660",
                    "start_va": "0x14093d5c0",
                    "end_va_exclusive": "0x14093d660",
                    "bytes_sha256": "ed542085239be6cb137b158e89cfb7ad09830f212bce2b47cb70ac1cbaa0e063",
                },
                "semantic_boundary": "selector/normal-cache path only; it does not enumerate active modifiers.",
            },
        },
        "record_metadata_audit": {
            "status": "offsets_only_no_decoded_name_key_category_rows",
            "checked_artifacts": [
                "bridge/information/profiles/religious-unity-memory-1374.json",
                "bridge/information/profiles/military-effective-memory-1374-v2.json",
                "work/runtime/information-military-effective-20261027-001/discipline-links-003.json",
                "work/runtime/information-military-quality-20261027-001/morale-discipline-source-002.json",
                "docs/宗教统一计算路径.md",
            ],
            "positive": ["numeric global RVA 0x2358060", "record stride 0x60", "processor +0x40", "religion profile resolved-type +0x54", "religion profile flags +0x5c"],
            "not_found": ["verified name/key/category table", "ID-to-name/key/category mapping", "active record source/target/date/effects rows"],
            "interpretation": "A flags offset in a profile is a layout hint, not evidence that the current country has a record or that the record is active.",
        },
        "layers": {
            "static_definition_records": {
                "status": "partial_layout_only",
                "reusable": ["manager global dereference", "0x60 record stride", "processor/resolved-type/flags offsets"],
                "missing": ["definition metadata mapping", "category predicate for N03 key military modifiers", "effect/unit expansion"],
            },
            "country_modifier_cache": {
                "status": "bounded_keyed_values_only",
                "reusable": ["country+0x28c8 state", "embedded object at country+0x28d0", "dense/sparse value storage"],
                "missing": ["complete active collection", "provenance and lifecycle"],
            },
            "active_modifier_container": {
                "status": "unresolved",
                "required": ["country-level active-list/vector owner and bounded iterator", "record ID to definition mapping", "source/target and dates/removal state", "effect list and effective-status path"],
                "available_evidence": "No selected archived source identifies its head, iterator or owner; the 0x93d5c0 selector and 0x341850 discipline helper are readers of a keyed cache, not this container.",
            },
        },
        "minimal_next_step": {
            "goal": "Find one bounded native reader/writer that enumerates the country active-modifier container, then join its IDs to a separately verified definition record mapping.",
            "must_pin": ["exact RVA/VA and half-open range", "country vs province/local target", "record ID and name/key/category source", "source/start/end/removal fields", "effect values and units"],
            "do_not_reuse_as_substitute": ["discipline key 0x77", "religious-unity key 0xa8", "all sparse cache entries", "final morale/discipline values", "the 697-definition count without active-state proof"],
            "bounded_follow_up": "A future ordinary-PE or existing evidence review should start from an already identified active-container caller/serializer; no concrete RVA is claimed here because none is closed in the selected sources.",
        },
        "decision": {
            "publishable_N03_military_modifiers": False,
            "reusable_partial": "Numeric country modifier cache and static modifier-database offsets can be reused as lower-level inputs after independent guard validation.",
            "reason": [
                "N03 has no proved fixed selection list, so a hand-picked subset would change its meaning.",
                "The country cache exposes keyed numeric values, not current active modifier items.",
                "The global table evidence exposes layout offsets and a processor slot, not name/key/category definitions or active state.",
                "N07/N08/N09 require source/target, dates/conditions, effects and effective status that are not present in the selected sources.",
            ],
        },
        "source_artifacts": artifacts,
    }


def main() -> None:
    report = build_report()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    with REPORT.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(payload)
    print(json.dumps({"report": _relative(REPORT), "bytes": REPORT.stat().st_size, "sha256": hashlib.sha256(REPORT.read_bytes()).hexdigest()}, ensure_ascii=False))


if __name__ == "__main__":
    main()
