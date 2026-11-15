"""Create the frozen Batch-46 v3 trade-details profile and source index.

The v2 profile and source index remain immutable inputs.  This generator adds
the two native transfer-detail chains at entry+0x60/+0x78 and their bounded
country-fullref binding.  It consumes only the already saved bounded PE/static
reports; it does not attach to the game or run a native function.
"""
from __future__ import annotations

import copy
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
PROFILE_ID = "trade-details-memory-1374-v3"
SOURCE_INDEX_ID = "trade-details-source-index-003"
STAGE = ROOT / "work/runtime/information-trade-source-details-20261027-001"
V2_PROFILE_PATH = ROOT / "bridge/information/profiles/trade-details-memory-1374-v2.json"
V2_SOURCE_INDEX_PATH = STAGE / "trade-details-source-index-002.json"
PROFILE_PATH = ROOT / "bridge/information/profiles/trade-details-memory-1374-v3.json"
SOURCE_INDEX_PATH = STAGE / "trade-details-source-index-003.json"
MODIFIER_PATHS = {
    "source_modifiers_001": STAGE / "source-modifiers-001.json",
    "source_modifiers_002": STAGE / "source-modifiers-002.json",
    "source_modifiers_003": STAGE / "source-modifiers-003.json",
    "source_modifiers_004": STAGE / "source-modifiers-004.json",
}

EXPECTED_SHA = {
    V2_PROFILE_PATH: "6f4f248041561b700ca50529e146a9d19272f0b7fab7bbdbe33b0788518e169f",
    V2_SOURCE_INDEX_PATH: "50ad236e23c0479c60a04aa7741db99e1f2c33c87e615596e24f826f419ccb6a",
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


def find_range(report: dict[str, Any], name: str) -> dict[str, Any]:
    for item in report.get("decoded_code_ranges", []):
        if item.get("name") == name:
            return item
    raise RuntimeError(f"decoded_range_missing:{report.get('report_id')}:{name}")


def make_guard(pe: PE, report: dict[str, Any], entry: dict[str, Any], *, name: str, kind: str, report_path: Path) -> dict[str, Any]:
    begin, end = (int(item, 0) for item in entry["rva_exclusive"])
    expected_sha = entry["raw_range_sha256"]
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
        "source_report": report["report_id"],
        "source_report_sha256": digest(report_path),
        "address_semantics": "RVA/VA retained separately; half-open range; bounded bytes preserve the fixed PE identity",
    }


def main() -> None:
    for path, expected in EXPECTED_SHA.items():
        if not path.is_file() or digest(path) != expected:
            raise RuntimeError(f"pinned_v2_input_mismatch:{path}")
    if PROFILE_PATH.exists() or SOURCE_INDEX_PATH.exists():
        raise RuntimeError("refusing_to_overwrite_v3_output")

    v2_profile = load(V2_PROFILE_PATH)
    v2_source = load(V2_SOURCE_INDEX_PATH)
    if v2_profile.get("profile_id") != "trade-details-memory-1374-v2":
        raise RuntimeError("v2_profile_id_mismatch")
    if v2_source.get("source_index_id") != "trade-details-source-index-002":
        raise RuntimeError("v2_source_index_id_mismatch")

    modifiers = {key: load(path) for key, path in MODIFIER_PATHS.items()}
    expected_ids = {
        "source_modifiers_001": "information-trade-source-modifiers-001",
        "source_modifiers_002": "information-trade-source-modifiers-002",
        "source_modifiers_003": "information-trade-source-modifiers-003",
        "source_modifiers_004": "information-trade-source-modifiers-004",
    }
    for key, report in modifiers.items():
        if report.get("report_id") != expected_ids[key]:
            raise RuntimeError(f"modifier_report_id_mismatch:{key}")

    pe = PE(game_exe())
    if digest(pe.path) != EXE_SHA or pe.base != IMAGE_BASE:
        raise RuntimeError("fixed_executable_identity_mismatch")

    # B5DCD0/B5DEF0 are the complete element and two-direction builders;
    # 2892D0 and 1F4700 are the bounded fullref/label callees they require.
    tail_guard_specs = (
        ("source_modifiers_002", "b5dcd0_detail_element_builder", "tail_b5dcd0_detail_element_builder", "complete_native_tail_element_builder"),
        ("source_modifiers_001", "b5def0_detail_string_builder", "tail_b5def0_direction_builder", "complete_native_tail_direction_builder"),
        ("source_modifiers_002", "2892d0_key_country_resolver", "tail_2892d0_fullref_country_resolver", "native_tail_fullref_country_binding_callee"),
        ("source_modifiers_002", "1f4700_to_from_formatter", "tail_1f4700_direction_label_formatter", "native_tail_direction_label_callee"),
    )
    code_guards = [copy.deepcopy(item) for item in v2_profile["code_guards"]]
    for report_key, range_name, guard_name, guard_kind in tail_guard_specs:
        report_path = MODIFIER_PATHS[report_key]
        report = modifiers[report_key]
        code_guards.append(make_guard(
            pe, report, find_range(report, range_name),
            name=guard_name, kind=guard_kind, report_path=report_path,
        ))
    if len(code_guards) != 18:
        raise RuntimeError(f"expected_18_guards:{len(code_guards)}")

    localization_guards = [copy.deepcopy(item) for item in v2_profile["localization_guards"]]
    localization = modifiers["source_modifiers_003"]["localization"]
    for line in localization["lines"]:
        localization_guards.append({
            "native_key": line["key"],
            "line": line["line"],
            "text": line["text"].strip(),
            "bytes_hex": line["bytes_hex"],
            "sha256": line["sha256"],
            "path": localization["path"],
            "file_sha256": localization["sha256"],
            "evidence_kind": "pinned_disk_localization_label; direction and trade_power unit only",
        })

    layout = copy.deepcopy(v2_profile["layout"])
    layout["native_tail"] = {
        "chains": {
            "TRANSFER_TRADE_POWER_TO": {
                "container_offset": "0x60",
                "native_key": "TRANSFER_TRADE_POWER_TO",
                "direction": "to",
            },
            "TRANSFER_TRADE_POWER_FROM": {
                "container_offset": "0x78",
                "native_key": "TRANSFER_TRADE_POWER_FROM",
                "direction": "from",
            },
        },
        "container_head_offset": "0x0",
        "element_offsets": {
            "fullref": "0x0",
            "value": "0x8",
            "next": "0x18",
        },
        "element_min_read_bytes": 32,
        "fullref_slot": "signed_i16(fullref[4:6])",
        "max_country_slot_for_read": 4095,
        "max_country_slot_is_read_bound_not_total_country_count": True,
        "country_object_fullref_offset": "0x20",
        "country_fullref_match": "element fullref == country_table[slot]+0x20 fullref before country_tag is saved",
        "value_width": 4,
        "value_signed": True,
        "value_scale": 1000,
        "value_unit": "trade_power",
        "raw_sign_is_direction": False,
        "direction_from_container": True,
        "max_elements_per_node": 64,
        "max_elements_global": 256,
        "chains_share_element_cap": True,
        "max_extension_read_bytes_per_pass": 131072,
        "empty_head": "[entry+offset]==0 or [container]==0 yields an empty raw chain",
        "name_or_key_resolution": "not captured; B5DCD0 resolver/formatter evidence remains separate from raw element contract",
    }

    source = copy.deepcopy(v2_source)
    source.update({
        "schema": "information_trade_details_source.v3",
        "source_index_id": SOURCE_INDEX_ID,
        "profile_id": PROFILE_ID,
        "fields": ["shares", "sources"],
        "source_subfields": [
            "shares", "TP_PROVINCE_POWER", "TP_SHIP_POWER", "MERCHANT_DOWNSTREAM_BONUS",
            "TRADE_POWER_CAPITAL", "dynamic_sources", "TRANSFER_TRADE_POWER_TO", "TRANSFER_TRADE_POWER_FROM",
        ],
        "behavior": "Retain the v2 raw share/source/capital/dynamic contract and add separately bound transfer-detail chains; preserve raw sign and do not sum transfer rows into direct source rows or country_power.",
        "basis": "native_trade_node_share_source_capital_dynamic_and_transfer_tail",
        "unit": "mixed",
        "scale": 1000,
        "period": "current",
        "value_origin": "copied_native_cache",
        "freshness": "partial_cache_observation",
        "complete": False,
        "layout": layout,
        "code_guards": code_guards,
        "localization_guards": localization_guards,
        "source_index_parent": pin(V2_SOURCE_INDEX_PATH),
        "profile_parent": pin(V2_PROFILE_PATH),
        "tail_static_sources": [pin(path) for path in MODIFIER_PATHS.values()],
        "tail_contract": {
            "source_reports": [pin(MODIFIER_PATHS["source_modifiers_002"]), pin(MODIFIER_PATHS["source_modifiers_003"]), pin(MODIFIER_PATHS["source_modifiers_004"])],
            "code_range_roles": {
                "B5DCD0": "element root/value/next raw chain and signed fixed-point formatting",
                "B5DEF0": "entry+0x60/+0x78 TO/FROM container selection",
                "0x2892D0": "packed element fullref country resolver",
                "0x1F4700": "TO/FROM label formatter call path",
            },
            "raw_value": "signed_i32(element+0x08), preserve raw/raw_hex, format hint raw/1000",
            "unit": "trade_power",
            "scale": 1000,
            "direction_rule": "container field and native label determine TO/FROM; never infer direction from raw sign",
            "country_binding": "read country_table[sign_extend_i16(fullref[4:6])]+0x20 and require exact fullref equality before saving country_tag",
        },
        "limits": {
            "profile_max_bytes": 64 * 1024,
            "max_extension_read_bytes_per_pass": 131072,
            "max_single_rpm_bytes": 65536,
            "max_total_rpm_bytes": 512 * 1024,
            "max_country_slot_for_read": 4095,
            "max_elements_per_node_across_three_chains": 64,
            "max_elements_global_across_three_chains": 256,
        },
        "unresolved_conditions": list(v2_source.get("unresolved_conditions", [])) + [
            "Transfer-chain runtime freshness, update timing, and GUI selector equality remain unproven; metadata stays partial/complete false.",
            "Country tag is saved only after exact element-fullref versus country_table[slot]+0x20 equality; slot 4095 is a bounded read maximum, not a country-count claim.",
            "The transfer chains remain separate detail rows; they are not summed with the three direct source rows or treated as complete country_power.",
        ],
        "evidence_layers": {
            "ordinary_PE": "The v2 bounded PE guards are retained and four additional tail/callee ranges are pinned to the same fixed executable; no whole-image disassembly or REA was used.",
            "static_reports": "source-modifiers-001/002/003/004 are retained as separate bounded/static/localization evidence.",
            "runtime": "The v3 raw probe samples only missing tail elements and current country-table fullref bindings; it does not call native functions.",
        },
    })
    write_new(SOURCE_INDEX_PATH, source)

    profile = copy.deepcopy(v2_profile)
    profile.update({
        "profile_id": PROFILE_ID,
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
            "field_units": dict(v2_profile["semantics"].get("field_units", {}), **{
                "TRANSFER_TRADE_POWER_TO": {"unit": "trade_power", "scale": 1000, "raw": "signed32 element+0x08 under entry+0x60"},
                "TRANSFER_TRADE_POWER_FROM": {"unit": "trade_power", "scale": 1000, "raw": "signed32 element+0x08 under entry+0x78"},
            }),
        },
        "code_guards": code_guards,
        "localization_guards": localization_guards,
        "provenance": dict(v2_profile.get("provenance", {}), **{
            "v2_profile": pin(V2_PROFILE_PATH),
            "v2_source_index": pin(V2_SOURCE_INDEX_PATH),
            "tail_source_modifiers_001": pin(MODIFIER_PATHS["source_modifiers_001"]),
            "tail_source_modifiers_002": pin(MODIFIER_PATHS["source_modifiers_002"]),
            "tail_source_modifiers_003": pin(MODIFIER_PATHS["source_modifiers_003"]),
            "tail_source_modifiers_004": pin(MODIFIER_PATHS["source_modifiers_004"]),
        }),
        "limits": source["limits"],
        "production_boundary": "This v3 profile adds a bounded raw transfer-tail contract; it does not authorize production-reader changes or public normalization of unresolved detail rows.",
    })
    write_new(PROFILE_PATH, profile)
    print(json.dumps({
        "source_index": pin(SOURCE_INDEX_PATH),
        "profile": pin(PROFILE_PATH),
        "guard_count": len(code_guards),
        "tail_ranges": [item[2] for item in tail_guard_specs],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
