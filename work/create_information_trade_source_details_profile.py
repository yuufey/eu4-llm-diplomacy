"""Create the pinned Batch-46 trade-details v2 source index and profile.

Only the fixed 1.37.4 PE and the already written Batch-45/46 static reports
are consumed.  This generator does not attach to the game, invoke a native
function, or generate a runtime sample.  The profile keeps the old share and
three source rows intact and adds bounded raw contracts for the capital scalar
and the entry+0x90 dynamic list.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE  # noqa: E402
from work.local_config import game_exe  # noqa: E402


EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
PROFILE_ID = "trade-details-memory-1374-v2"
SOURCE_INDEX_ID = "trade-details-source-index-002"
STAGE = ROOT / "work/runtime/information-trade-source-details-20261027-001"
PROFILE_PATH = ROOT / "bridge/information/profiles/trade-details-memory-1374-v2.json"
OLD_PROFILE_PATH = ROOT / "bridge/information/profiles/trade-details-memory-1374.json"
OLD_SOURCE_INDEX_PATH = ROOT / "work/runtime/information-trade-share-20261027-001/trade-details-source-index-001.json"
SHARE_SOURCE_PATH = ROOT / "work/runtime/information-trade-share-20261027-001/share-source-002.json"
POWER_SOURCE_PATH = ROOT / "work/runtime/information-trade-share-20261027-001/power-sources-source-002.json"
CAPITAL_SOURCE_PATH = STAGE / "capital-source-001.json"
DYNAMIC_SOURCE_PATH = STAGE / "dynamic-source-001.json"
SOURCE_INDEX_PATH = STAGE / "trade-details-source-index-002.json"

EXPECTED_SHA = {
    OLD_PROFILE_PATH: "2d04808a1e24ecaf7cb7cf162743f7ada7412fa95522ce324f9e5959bca522aa",
    OLD_SOURCE_INDEX_PATH: "1fa9c3ffa37ab485965b9be1da9bdbb40b2708de8494983ec2d1ce368c6d01f2",
    SHARE_SOURCE_PATH: "1878bcbd2f395b0b01beb1d6b12c73ba527e87d50fff7b85ba0ebeb4c11c8d4d",
    POWER_SOURCE_PATH: "952d2bfc5e9d9dfb2e0012d834b0d548a281f0ac29d5e6b5fbfa062f99d010e9",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def pin(path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": digest(path),
        "bytes": path.stat().st_size,
    }


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"report_not_object:{path}")
    return value


def write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise RuntimeError(f"refusing_to_overwrite:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def guard_from_range(pe: PE, source: dict[str, Any], entry: dict[str, Any], *, name: str, kind: str) -> dict[str, Any]:
    rva_key = "rva_exclusive" if "rva_exclusive" in entry else "rva_range"
    if rva_key == "rva_exclusive":
        begin, end = (int(item, 0) for item in entry[rva_key])
        expected_sha = entry["raw_range_sha256"]
    else:
        begin, end = (int(item, 0) for item in entry[rva_key])
        expected_sha = entry["bytes_sha256"]
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise RuntimeError(f"bounded_guard_short_read:{name}")
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha != expected_sha:
        raise RuntimeError(f"bounded_guard_sha_mismatch:{name}:{actual_sha}")
    return {
        "name": name,
        "kind": kind,
        "rva": hex(begin),
        "rva_end_exclusive": hex(end),
        "va": hex(IMAGE_BASE + begin),
        "va_end_exclusive": hex(IMAGE_BASE + end),
        "hex": raw.hex(),
        "sha256": actual_sha,
        "source_report": source["report_id"],
        "source_report_sha256": digest(CAPITAL_SOURCE_PATH if source["report_id"] == "information-trade-capital-source-001" else DYNAMIC_SOURCE_PATH),
        "address_semantics": "RVA/VA retained separately; half-open range; bounded bytes contain no ASLR absolute pointer claim",
    }


def add_capital_localization(old_guards: list[dict[str, Any]], capital: dict[str, Any]) -> list[dict[str, Any]]:
    result = [dict(item) for item in old_guards]
    line = capital["localization"]["lines"]["37"]
    result.append({
        "native_key": "TRADE_POWER_CAPITAL",
        "line": line["line"],
        "text": line["text"].strip(),
        "bytes_hex": line["bytes_hex"],
        "sha256": line["sha256"],
        "path": capital["localization"]["path"],
        "file_sha256": capital["input_evidence"][2]["sha256"],
        "evidence_kind": "pinned_disk_localization_label; not a runtime value sample",
    })
    return result


def main() -> None:
    for path, expected in EXPECTED_SHA.items():
        if not path.is_file() or digest(path) != expected:
            raise RuntimeError(f"pinned_input_mismatch:{path}")
    capital = load(CAPITAL_SOURCE_PATH)
    dynamic = load(DYNAMIC_SOURCE_PATH)
    old_profile = load(OLD_PROFILE_PATH)
    old_source = load(OLD_SOURCE_INDEX_PATH)
    share = load(SHARE_SOURCE_PATH)
    power = load(POWER_SOURCE_PATH)
    if capital.get("report_id") != "information-trade-capital-source-001":
        raise RuntimeError("capital_report_id_mismatch")
    if dynamic.get("report_id") != "information-trade-dynamic-source-001":
        raise RuntimeError("dynamic_report_id_mismatch")
    if old_profile.get("profile_id") != "trade-details-memory-1374":
        raise RuntimeError("old_profile_id_mismatch")
    if old_source.get("source_index_id") != "information-trade-details-source-index-001":
        raise RuntimeError("old_source_index_id_mismatch")
    if share.get("report_id") != "information-trade-share-source-002":
        raise RuntimeError("share_report_id_mismatch")
    if power.get("report_id") != "information-trade-power-sources-source-002":
        raise RuntimeError("power_report_id_mismatch")

    pe = PE(game_exe())
    if digest(pe.path) != EXE_SHA or pe.base != IMAGE_BASE:
        raise RuntimeError("fixed_executable_identity_mismatch")

    # The old nine guards are copied byte-for-byte from the pinned v1 profile.
    old_guards = [dict(item) for item in old_profile["code_guards"]]
    capital_range = capital["decoded_code_ranges"][0]
    capital_guard = guard_from_range(
        pe, capital, capital_range,
        name="capital_row_caller_context",
        kind="complete_capital_selector_identity_and_formatter_caller",
    )
    dynamic_guards = []
    for item in dynamic["decoded_code_ranges"]:
        dynamic_guards.append(guard_from_range(
            pe, dynamic, item,
            name=f"dynamic_{item['label']}",
            kind="complete_bounded_dynamic_source_path",
        ))
    code_guards = old_guards + [capital_guard] + dynamic_guards
    if len(code_guards) != 14:
        raise RuntimeError(f"expected_14_guards:{len(code_guards)}")

    layout = {
        "entry_size_bytes": 192,
        "share_offset": "0x2c",
        "share_width": 4,
        "share_signed": True,
        "source_offsets": {
            "TP_PROVINCE_POWER": "0x28",
            "TP_SHIP_POWER": "0x1c",
            "MERCHANT_DOWNSTREAM_BONUS": "0x40",
        },
        "source_width": 4,
        "source_signed": True,
        "source_conditions": {
            "TP_PROVINCE_POWER": "signed_i32(entry+0x28) != 0",
            "TP_SHIP_POWER": "signed_i32(entry+0x1c) != 0",
            "MERCHANT_DOWNSTREAM_BONUS": "signed_i32(entry+0x40) > 0",
        },
        "capital": {
            "database_global_rva": "0x233d8b0",
            "table_offset": "0x118",
            "country_anchor_offset": "0x14c8",
            "node_identity_offset": "0xe8",
            "scalar_rva": "0x233f2f0",
            "scalar_width": 4,
            "scalar_signed": True,
            "scalar_scale": 1000,
            "condition": "u64(country_selected+0x14c8)+0xe8 == supplied_node_pointer",
        },
        "dynamic": {
            "link_head_offset": "0x90",
            "link_item_offset": "0x0",
            "link_next_offset": "0x10",
            "item_value_offset": "0x34",
            "name_object_offset": "0x10",
            "name_capacity_offset_from_object": "0x18",
            "name_heap_pointer_offset_from_object": "0x0",
            "name_inline_pointer": "object_base",
            "name_inline_threshold": 16,
            "name_terminator": "NUL",
            "name_max_bytes": 1024,
            "max_items_per_node": 64,
            "max_items_global": 256,
            "max_extension_read_bytes_per_pass": 131072,
            "raw_value_width": 4,
            "raw_value_signed_view": True,
            "raw_value_scale": 1000,
            "raw_value_unit": "unknown",
            "name_semantics": "dynamic lookup key candidate; not proven display text or template",
        },
        "entry_table_offset": "0x18",
        "entry_stride": "0xc0",
        "node_definition_offset": "0xa8",
        "definition_key_offset": "0x10",
        "predicate_true_rva": "0x8f440",
        "predicate_false_rva": "0x8f450",
        "reused_graph_profile_sha256": digest(OLD_PROFILE_PATH),
        "signed": True,
    }

    source_rows = {}
    for key, row in power["rows"].items():
        source_rows[key] = {
            "entry_offset": row["entry_offset"],
            "condition": row["condition"],
            "raw_semantics": row["raw_semantics"],
            "unit": row["unit"],
            "scale": row["scale"],
            "native_key": row["native_key"],
            "localization_line": row["localization_line"],
            "localization_text": row["localization_text"],
            "raw_load_rva": row["raw_load_rva"],
            "call_rva": row["call_rva"],
            "builder_rva": row["builder_rva"],
            "helper_rva": row["direct_call_arguments"]["helper_rva"],
            "display_formula": row["display_formula"],
            "reader_disposition": row["reader_disposition"],
        }

    capital_row = capital["implemented_reader_contract"]["row"]
    dynamic_schema = dynamic["bounded_read_schema"]
    source = {
        "schema": "information_trade_details_source.v2",
        "source_index_id": SOURCE_INDEX_ID,
        "profile_id": PROFILE_ID,
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": EXE_SHA,
            "image_base_va": hex(IMAGE_BASE),
            "address_rule": "RVA; VA=image_base+RVA; all ranges end exclusive",
        },
        "fields": ["shares", "sources"],
        "source_subfields": [
            "shares",
            "TP_PROVINCE_POWER",
            "TP_SHIP_POWER",
            "MERCHANT_DOWNSTREAM_BONUS",
            "TRADE_POWER_CAPITAL",
            "dynamic_sources",
        ],
        "behavior": "Copy the selected FRA trade-node entry raw share/source fields and add capital/dynamic raw source evidence with independent conditions; do not publish dynamic normalized values or translated names.",
        "basis": "native_trade_node_share_source_capital_and_dynamic_caches",
        "unit": "mixed",
        "scale": 1000,
        "period": "current",
        "value_origin": "copied_native_cache",
        "freshness": "partial_cache_observation",
        "complete": False,
        "field_units": {
            "shares": {"unit": "ratio", "scale": 1000, "raw": "signed32 entry+0x2c"},
            "sources": {"unit": "trade_power", "scale": 1000, "raw": "signed32 entry source offsets"},
            "TRADE_POWER_CAPITAL": {"unit": "trade_power", "scale": 1000, "raw": "signed32 [module+0x233f2f0] when anchor identity matches"},
            "dynamic_sources": {"unit": "unknown", "scale": 1000, "raw": "signed32 view of item+0x34; preserve raw bits"},
        },
        "layout": layout,
        "share_contract": {
            "source_report": pin(SHARE_SOURCE_PATH),
            "interpretation": "Reuse the existing entry+0x2c ratio contract; it remains separate from the B58D00 income-like return.",
        },
        "source_rows": source_rows,
        "capital_contract": {
            "source_report": pin(CAPITAL_SOURCE_PATH),
            "native_key": capital_row["key"],
            "raw": capital_row["raw"],
            "unit": capital_row["unit"],
            "scale": capital_row["scale"],
            "condition": capital_row["condition"],
            "localization": capital_row["localization"],
            "selector": capital["implemented_reader_contract"]["selector"],
            "reads": capital["implemented_reader_contract"]["reads"],
            "guards": capital["implemented_reader_contract"]["guards"],
            "freshness": "runtime scalar observation remains partial",
        },
        "dynamic_contract": {
            "source_report": pin(DYNAMIC_SOURCE_PATH),
            "chain": dynamic["static_contract"]["chain"],
            "value": dynamic["static_contract"]["value"],
            "name": dynamic["static_contract"]["name"],
            "bounded_read_schema": dynamic_schema,
            "publication": "raw items only; no normalized unit, power sum, locale translation, or public display row",
        },
        "reused_graph_contract": {
            "profile": pin(OLD_PROFILE_PATH),
            "source_index": pin(OLD_SOURCE_INDEX_PATH),
            "role": "Reuse the validated definitions, predicates, node keys, runtime table and FRA fullref binding; v2 does not duplicate or replace that graph contract.",
        },
        "code_guards": code_guards,
        "localization_guards": add_capital_localization(old_profile["localization_guards"], capital),
        "provenance": {
            "share_source": pin(SHARE_SOURCE_PATH),
            "power_source": pin(POWER_SOURCE_PATH),
            "capital_source": pin(CAPITAL_SOURCE_PATH),
            "dynamic_source": pin(DYNAMIC_SOURCE_PATH),
            "reused_graph_profile": pin(OLD_PROFILE_PATH),
            "reused_graph_source_index": pin(OLD_SOURCE_INDEX_PATH),
        },
        "unresolved_conditions": [
            "Cache freshness, update timing, and live GUI selector equality remain unproven; metadata stays partial/complete false.",
            "Dynamic list ownership, allocator type, runtime count, and non-empty values remain unobserved; current empty heads do not close those semantics.",
            "Dynamic item+0x34 public unit and modifier-versus-power-point meaning remain unknown; values must not be summed.",
            "Dynamic item+0x10 is a lookup-key candidate; locale resolution and translated display/template status remain unknown.",
            "The capital scalar is raw and condition-bound to selected-country anchor identity; it is not a province-capital name or B58D00 income return.",
        ],
        "evidence_layers": {
            "ordinary_PE": "The added code guards are bounded bytes from the fixed PE and preserve RVA/VA and half-open boundaries; no whole-image disassembly or REA was used.",
            "static_reports": "Batch-45 share/source reports and Batch-46 capital/dynamic reports remain distinct inputs.",
            "runtime": "The independent raw probe and expected reference are generated separately and are not imported into this static profile.",
        },
    }
    write_new(SOURCE_INDEX_PATH, source)

    profile = {
        "profile_id": PROFILE_ID,
        "game_version": "1.37.4",
        "executable": {"sha256": EXE_SHA, "image_base_va": hex(IMAGE_BASE)},
        "source_index": {
            "source_index_id": SOURCE_INDEX_ID,
            "path": SOURCE_INDEX_PATH.relative_to(ROOT).as_posix(),
            "sha256": digest(SOURCE_INDEX_PATH),
        },
        "layout": layout,
        "semantics": {
            "basis": source["basis"],
            "unit": source["unit"],
            "scale": source["scale"],
            "period": source["period"],
            "value_origin": source["value_origin"],
            "freshness": source["freshness"],
            "complete": source["complete"],
            "field_units": source["field_units"],
        },
        "code_guards": code_guards,
        "localization_guards": source["localization_guards"],
        "provenance": source["provenance"],
        "limits": {
            "profile_max_bytes": 64 * 1024,
            "max_extension_read_bytes_per_pass": 131072,
            "dynamic_name_max_bytes": 1024,
            "dynamic_max_items_per_node": 64,
            "dynamic_max_items_global": 256,
            "max_single_rpm_bytes": 65536,
            "max_total_rpm_bytes": 512 * 1024,
        },
        "production_boundary": "This v2 profile describes the extended raw contract; no production reader is changed or authorized by this generator.",
    }
    write_new(PROFILE_PATH, profile)
    print(json.dumps({"source_index": pin(SOURCE_INDEX_PATH), "profile": pin(PROFILE_PATH), "guard_count": len(code_guards)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
