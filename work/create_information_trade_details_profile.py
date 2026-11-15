"""Pin the bounded native trade-share/source entry contract for build 1.37.4.

This generator reads the fixed executable and already-saved bounded reports only.
It does not attach to the game, invoke a game function, or import a production
reader.  The generated profile keeps the native share cache separate from the
B58D00 income-like return and reuses the previously pinned 192-byte node graph.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE
from work.local_config import game_exe


STAGE = ROOT / "work/runtime/information-trade-share-20261027-001"
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
PROFILE_ID = "trade-details-memory-1374"
SOURCE_ID = "information-trade-details-source-index-001"
TRADE_PROFILE_SHA = "1375800668ed0ddec29d2e5f8efe8e1369d1e4da8b0aa6916b5b970078b137cd"
SHARE_SOURCE_SHA = "1878bcbd2f395b0b01beb1d6b12c73ba527e87d50fff7b85ba0ebeb4c11c8d4d"
POWER_SOURCE_SHA = "952d2bfc5e9d9dfb2e0012d834b0d548a281f0ac29d5e6b5fbfa062f99d010e9"
OLD_SOURCE_SHA = "8350859150dae894212d2ed15e8f5c528e590b91e9f52401010bbdb761f60955"

SHARE_SOURCE_PATH = STAGE / "share-source-002.json"
POWER_SOURCE_PATH = STAGE / "power-sources-source-002.json"
OLD_SOURCE_PATH = ROOT / "work/runtime/information-budget-collectors-20261027-001/trade-income-source-index-001.json"
OLD_PROFILE_PATH = ROOT / "bridge/information/profiles/trade-income-memory-1374.json"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def pin(path: Path) -> dict:
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": digest(path), "bytes": path.stat().st_size}


def write(path: Path, value: dict) -> None:
    if path.exists():
        raise RuntimeError(f"refusing_to_overwrite:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def make_guard(pe: PE, name: str, begin: int, end: int, kind: str) -> dict:
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise RuntimeError(f"bounded_pe_window_missing:{name}")
    return {
        "name": name,
        "kind": kind,
        "rva": hex(begin),
        "rva_end_exclusive": hex(end),
        "va": hex(IMAGE_BASE + begin),
        "va_end_exclusive": hex(IMAGE_BASE + end),
        "hex": raw.hex(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "address_semantics": "RVA/VA retained separately; end is exclusive; bytes contain no ASLR absolute pointer",
    }


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"report_not_object:{path}")
    return value


def build_guards(pe: PE) -> list[dict]:
    # Each code window is a complete instruction range from the bounded reports.
    # The 14BC950 window is its complete pdata function, not a guessed prefix.
    windows = [
        ("share_percentage_raw_chain", 0xB58E45, 0xB58EC9, "complete_fixed_point_share_percentage_path"),
        ("share_percentage_label_row", 0xB58EFC, 0xB58F13, "complete_share_label_and_formatter_row"),
        ("income_return_separation_ui_path", 0x101DA77, 0x101DB29, "complete_income_key_before_nonshare_return"),
        ("tp_province_power_caller_condition", 0xB57763, 0xB577B6, "complete_source_caller_condition_and_formatter"),
        ("tp_ship_power_caller_condition", 0xB57890, 0xB578E1, "complete_source_caller_condition_and_formatter"),
        ("merchant_downstream_bonus_caller_condition", 0xB57E49, 0xB57E94, "complete_source_caller_condition_and_formatter"),
        ("fixed_point_formatter_14bc950", 0x14BC950, 0x14BD0F1, "complete_pdata_formatter_function"),
        ("predicate_true", 0x8F440, 0x8F443, "predicate_leaf"),
        ("predicate_false", 0x8F450, 0x8F453, "predicate_leaf"),
    ]
    return [make_guard(pe, *item) for item in windows]


def localization_guards(power_source: dict) -> list[dict]:
    localization = power_source["localization"]
    result = []
    for line_key in ("23", "24", "149"):
        item = localization["lines"][line_key]
        result.append({
            "native_key": item["text"].split(":", 1)[0].strip(),
            "line": item["line"],
            "text": item["text"].strip(),
            "bytes_hex": item["bytes_hex"],
            "sha256": item["sha256"],
            "path": localization["path"],
            "file_sha256": localization["sha256"],
            "evidence_kind": "pinned_disk_localization_label; not a runtime value sample",
        })
    return result


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    for path, expected in (
        (SHARE_SOURCE_PATH, SHARE_SOURCE_SHA),
        (POWER_SOURCE_PATH, POWER_SOURCE_SHA),
        (OLD_SOURCE_PATH, OLD_SOURCE_SHA),
        (OLD_PROFILE_PATH, TRADE_PROFILE_SHA),
    ):
        if not path.exists() or digest(path) != expected:
            raise RuntimeError(f"pinned_input_mismatch:{path}")

    share_source = load_json(SHARE_SOURCE_PATH)
    power_source = load_json(POWER_SOURCE_PATH)
    if share_source.get("report_id") != "information-trade-share-source-002":
        raise RuntimeError("share_source_report_id_mismatch")
    if power_source.get("report_id") != "information-trade-power-sources-source-002":
        raise RuntimeError("power_source_report_id_mismatch")
    if power_source.get("target", {}).get("exe_sha256") != EXE_SHA:
        raise RuntimeError("power_source_executable_mismatch")

    pe = PE(game_exe())
    if hashlib.sha256(pe.data).hexdigest() != EXE_SHA or pe.base != IMAGE_BASE:
        raise RuntimeError("fixed_executable_identity_mismatch")
    guards = build_guards(pe)
    guard_by_name = {item["name"]: item for item in guards}
    expected_raw_sha = {
        "share_percentage_raw_chain": "5a7f17bcc8b7deb1af1e39aaa1532fa30e9b62f165e2ca489fc70949b40e358b",
        "income_return_separation_ui_path": "bed5b8624bb5560cd22a599de2b6942f225efac0a94ac54a927c88829982052c",
        "fixed_point_formatter_14bc950": "60dd94dd7c17c89de30515eda804d83edeb384257aa0204069d6471ff2362300",
        "tp_province_power_caller_condition": "ddab87bcd3b872c30111df79dc137790d895af6a6b2d0cad9248ca888ca9b89b",
        "tp_ship_power_caller_condition": "109a759ca60fd266b17996a03268f2123a0214c31b4046c6012b84fcc2f2ebe2",
        "merchant_downstream_bonus_caller_condition": "6647e25a184459c2d70fb6a909909ece9dccf5aee6fd07156dc163b95d56a933",
    }
    for name, expected in expected_raw_sha.items():
        if guard_by_name[name]["sha256"] != expected:
            raise RuntimeError(f"guard_bytes_mismatch:{name}")
    if bytes.fromhex(guard_by_name["predicate_true"]["hex"]) != b"\xb0\x01\xc3":
        raise RuntimeError("predicate_true_mismatch")
    if bytes.fromhex(guard_by_name["predicate_false"]["hex"]) != b"\x32\xc0\xc3":
        raise RuntimeError("predicate_false_mismatch")

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
        "entry_table_offset": "0x18",
        "entry_stride": "0xc0",
        "node_definition_offset": "0xa8",
        "definition_key_offset": "0x10",
        "predicate_true_rva": "0x8f440",
        "predicate_false_rva": "0x8f450",
        "source_trade_profile_sha256": TRADE_PROFILE_SHA,
        "reused_graph_profile_sha256": TRADE_PROFILE_SHA,
        "signed": True,
    }

    source_rows = {}
    for key, row in power_source["rows"].items():
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
            "direct_call_arguments": row["direct_call_arguments"],
            "display_formula": row["display_formula"],
            "reader_disposition": row["reader_disposition"],
        }

    share_contract = share_source["entry_0x2c_share_contract"]
    source = {
        "schema": "information_trade_details_source.v1",
        "source_index_id": SOURCE_ID,
        "profile_id": PROFILE_ID,
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": EXE_SHA,
            "image_base_va": hex(IMAGE_BASE),
            "address_rule": "RVA; VA=image_base+RVA; all ranges end exclusive",
        },
        "fields": ["shares", "sources"],
        "behavior": "Copy the selected FRA trade-node entry share cache and the three statically closed source-row caches, retaining raw signed32 values and per-row inclusion conditions.",
        "basis": "native_trade_node_share_and_source_caches",
        "unit": "mixed",
        "scale": 1000,
        "field_units": {
            "shares": {"unit": "ratio", "scale": 1000, "raw": "signed32 entry+0x2c"},
            "sources": {"unit": "trade_power", "scale": 1000, "raw": "signed32 entry source offsets"},
        },
        "period": "current",
        "value_origin": "copied_native_cache",
        "freshness": "partial_cache_observation",
        "complete": False,
        "layout": layout,
        "share_contract": {
            "raw_source": "selected runtime entry+0x2c signed32",
            "fixed_point_scale": share_contract["fixed_point_scale"],
            "percentage_path": share_contract["percentage_format_path"],
            "native_detail_label": share_contract["native_detail_label"],
            "interpretation": "The native percentage/detail row formats raw entry+0x2c*100 through the fixed-point path; this is the share cache. It is separate from B58D00's composite return.",
        },
        "b58d00_nonshare_boundary": {
            "rva": share_source["ui_binding"]["first_path"]["scalar_call"]["rva"],
            "income_key": share_source["ui_binding"]["first_path"]["income_key_setup"]["key"],
            "base_inputs": share_source["b58d00_return_binding"]["base_inputs"],
            "not_share": share_source["b58d00_return_binding"]["not_share_contract"],
            "factor_label": share_source["b58d00_return_binding"]["factor_detail_label"],
        },
        "source_rows": source_rows,
        "localization_guards": localization_guards(power_source),
        "reused_graph_contract": {
            "profile": pin(OLD_PROFILE_PATH),
            "source_index": pin(OLD_SOURCE_PATH),
            "role": "The existing validated graph supplies definitions, true/false predicates, node keys, runtime table and dynamic FRA fullref slot; this source index does not duplicate that graph.",
        },
        "ordinary_bounded_evidence": [pin(SHARE_SOURCE_PATH), pin(POWER_SOURCE_PATH), pin(OLD_SOURCE_PATH), pin(OLD_PROFILE_PATH)],
        "code_guards": guards,
        "evidence_layers": {
            "ordinary_PE": "The listed ranges are bounded bytes from the fixed PE with complete instruction/function boundaries; no whole-image disassembly or REA was used.",
            "static_reports": "share-source-002 separates the +0x2c percentage path from B58D00; power-sources-source-002 closes the three source callers, conditions, labels and 14BC950 formatter.",
            "runtime": "No runtime sample is created by this generator. The independent raw entry reference is generated separately and remains distinct from this static profile.",
        },
        "unresolved_conditions": [
            "The runtime cache refresh timing and same-date generation are not established; metadata remains partial.",
            "Capital, dynamic entry+0x90 list, multiplier and other native tail rows remain unresolved and are not exposed by this profile.",
            "The B58D00 income-like composite return and its +0xb0/factor semantics are not a share value and are not substituted for entry+0x2c.",
            "Widget selector/fullref pointer equality and complete live GUI equivalence are not established by static bytes or an independent raw reference.",
        ],
    }
    source_path = STAGE / "trade-details-source-index-001.json"
    write(source_path, source)

    profile = {
        "profile_id": PROFILE_ID,
        "game_version": "1.37.4",
        "executable": {"sha256": EXE_SHA, "image_base_va": hex(IMAGE_BASE)},
        "source_index": {"source_index_id": SOURCE_ID, "path": source_path.relative_to(ROOT).as_posix(), "sha256": digest(source_path)},
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
        "code_guards": guards,
        "localization_guards": source["localization_guards"],
        "provenance": {
            "share_source": pin(SHARE_SOURCE_PATH),
            "power_source": pin(POWER_SOURCE_PATH),
            "reused_graph_profile": pin(OLD_PROFILE_PATH),
            "reused_graph_source_index": pin(OLD_SOURCE_PATH),
        },
    }
    profile_path = ROOT / "bridge/information/profiles/trade-details-memory-1374.json"
    write(profile_path, profile)
    print(json.dumps({
        "source_index": pin(source_path),
        "profile": pin(profile_path),
        "guards": len(guards),
        "guard_bytes": sum(len(bytes.fromhex(item["hex"])) for item in guards),
        "localization_guards": len(source["localization_guards"]),
        "fields": source["fields"],
    }))


if __name__ == "__main__":
    main()
