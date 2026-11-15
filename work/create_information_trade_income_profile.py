"""Pin bounded trade-node cache evidence; no process access or native calls."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE
from work.local_config import game_exe

STAGE = ROOT / "work/runtime/information-budget-collectors-20261027-001"
SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PROFILE_ID = "trade-income-memory-1374"
SOURCE_ID = "information-trade-income-source-index-001"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path), "bytes": path.stat().st_size}


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    pe = PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest() == SHA and pe.base == 0x140000000
    windows = [
        ("manager_pointer_accessor", 0xB65AD0, 0xB65AD8),
        ("vector_begin_out_pointer", 0xC9720, 0xC972A),
        ("vector_end_out_pointer", 0xC3050, 0xC305B),
        ("vector_increment_eight", 0xC9A30, 0xC9A38),
        ("definition_predicate_true", 0x8F440, 0x8F443),
        ("definition_predicate_false", 0x8F450, 0x8F453),
        ("definition_center_to_province", 0xB69860, 0xB6987D),
        ("province_runtime_trade_node", 0x98890, 0x98898),
        ("node_definition_display_name", 0xB510F0, 0xB510FC),
        ("country_node_eligibility", 0xB58C70, 0xB58CD0),
        ("country_node_income_copy", 0xB58CD0, 0xB58CFA),
        ("budget_trade_enumeration_and_aggregate", 0xEB95E1, 0xEB9855),
        ("budget_trade_amount_formatter_binding", 0xEB9855, 0xEB99B6),
        ("budget_trade_widget_binding", 0xEB7DAC, 0xEB7E42),
        ("budget_trade_widget_literal", 0x1CE3F30, 0x1CE3F3C),
        ("money_formatter", 0x14BD100, 0x14BD6D5),
    ]
    guards = [{"name": name, "rva": hex(begin), "rva_end_exclusive": hex(end),
               "hex": pe.bytes_at(begin, end-begin).hex(),
               "sha256": hashlib.sha256(pe.bytes_at(begin, end-begin)).hexdigest()}
              for name, begin, end in windows]
    assert pe.bytes_at(0x1CE3F30, 12) == b"INCOMETRADE\0"
    assert pe.bytes_at(0x8F440, 3) == bytes.fromhex("b001c3")
    assert pe.bytes_at(0x8F450, 3) == bytes.fromhex("32c0c3")
    layout = {
        "manager_global_rva": "0x242be28", "vector_begin_offset": "0x0", "vector_end_offset": "0x8",
        "vector_stride": 8, "max_definitions": 1024, "definition_predicate_slot": "0x40",
        "predicate_true_rva": "0x8f440", "predicate_false_rva": "0x8f450", "definition_key_offset": "0x10",
        "string_size": 32, "string_length_offset": 16, "string_capacity_offset": 24,
        "string_inline_capacity": 16, "max_key_length": 128,
        "definition_center_offset": "0xdc", "max_center": 32767, "game_global_rva": "0x233fe58",
        "province_base_offset": "0x1ca8", "province_stride": "0x2e10", "province_trade_node_offset": "0xe8",
        "node_definition_offset": "0xa8", "country_fullref_offset": "0x20", "country_slot_offset": 4,
        "entry_table_offset": "0x18", "entry_stride": "0xc0", "entry_income_offset": "0x34",
        "entry_flags_offset": "0xac", "special_slot_global_rva": "0x233d8b8", "signed": True, "wrap_bits": 32,
    }
    names = ["trade-income-source-001.json", "trade-income-enumeration-002.json", "trade-node-key-source-001.json",
             "trade-global-accessor-002.json", "trade-enumeration-helpers-002.json", "trade-enumeration-helpers-003.json",
             "trade-definition-predicates-extent-001.json", "income-category-bindings-001.json", "budget-widget-literals-001.json"]
    source = {"schema": "information_trade_income_source.v1", "source_index_id": SOURCE_ID, "profile_id": PROFILE_ID,
              "target": {"game_version": "1.37.4", "exe_sha256": SHA, "image_base_va": hex(pe.base),
                         "addresses": "RVA; VA=image_base+RVA; all ranges end exclusive"},
              "behavior": "Copy node-country income caches and reproduce the native budget trade eligibility filter. Sum selected contributions with signed int32 wrap.",
              "basis": "native_trade_node_country_income_cache", "unit": "ducats", "scale": 1000, "period": "month",
              "country_value_origin": "derived_from_copied_native_caches", "node_value_origin": "copied_native_cache",
              "node_semantics": "Eligible nodes contribute the copied cache; ineligible nodes contribute zero and retain their original cache and eligibility provenance.",
              "derivation": {"slot": "signed int16 from country fullref bytes4:6; never a fixed FRA slot",
                             "eligibility": "slot==special OR (AE!=0 AND AC==0) OR (AD!=0 AND NOT(AE!=0 AND AC!=0)); only after pointer validation",
                             "aggregate": "sum of eligible node signed32 cache values, modulo2^32 after every add",
                             "ordering": "The native temporary list sorts entries; addition modulo2^32 is order independent.",
                             "key": "definition+0x10 internal key, distinct from localized display name at +0x30",
                             "null_definition": "virtual predicate false at RVA8F450 is excluded before following center/runtime pointers"},
              "layout": layout, "ordinary_bounded_PE": [pin(STAGE/name) for name in names],
              "runtime_guards": guards,
              "evidence_layers": {"ordinary_PE": "Bounded static code and literal evidence; no new REA function analysis.",
                                  "independent_RPM": "native-trade-income-inputs-005.json and expected-trade-income-001.json are separate raw/correlated artifacts, not production-reader values.",
                                  "public_MCP": "Acceptance is archived separately after implementation; no public success is asserted by this source index."},
              "corrections": ["Old enumeration001 misread returned out pointers as extra holder layers and B65AD0 as an address-returning accessor; enumeration002 supersedes these statements.",
                              "B510F0 exposes the localized display string at definition+30. It does not expose the ASCII node_id at +10.",
                              "333310 and333620 are coefficient paths, not production/trade income totals."],
              "unresolved_conditions": ["Only the fixed executable and verified live FRA observer context are supported.",
                                        "This is the native cached trade component; it does not implement the remaining monthly GUI budget components or the other T05 fields.",
                                        "No new cache refresh is invoked. Multi-read snapshots are double-pass checked, not atomic; same-date reload generations are not independently established.",
                                        "1024 definitions,32767 center and128 key bytes are reader resource bounds, not claimed native limits."]}
    source_path = STAGE / "trade-income-source-index-001.json"
    write(source_path, source)
    profile = {"profile_id": PROFILE_ID, "game_version": "1.37.4", "executable": {"sha256": SHA},
               "source_index": {"source_index_id": SOURCE_ID, "path": source_path.relative_to(ROOT).as_posix(), "sha256": digest(source_path)},
               "layout": layout, "semantics": {key: source[key] for key in ("basis", "unit", "scale", "period", "country_value_origin", "node_value_origin", "node_semantics")},
               "code_guards": guards}
    profile_path = ROOT / "bridge/information/profiles/trade-income-memory-1374.json"
    write(profile_path, profile)
    print(json.dumps({"source": pin(source_path), "profile": pin(profile_path), "guard_count": len(guards),
                      "guard_bytes": sum(len(bytes.fromhex(x["hex"])) for x in guards)}))


if __name__ == "__main__":
    main()
