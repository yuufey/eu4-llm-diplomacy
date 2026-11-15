"""Pin the bounded native trade-power cache contract for build 1.37.4.

This script only reads the fixed executable and existing batch-43 reports.  It
does not attach to a process, invoke a game function, or perform a new runtime
sample.  The generated source index keeps the UI selector/fullref distinction
explicit and records the exact signed-width arithmetic order, including the
32-bit TEST/CMOVG branch after the 64-bit quotient is narrowed.
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


STAGE = ROOT / "work/runtime/information-trade-power-20261027-001"
OLD_STAGE = ROOT / "work/runtime/information-trade-state-20261027-001"
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
PROFILE_ID = "trade-power-memory-1374"
SOURCE_ID = "information-trade-power-source-index-002"
OLD_SOURCE_ID = "information-trade-power-source-index-001"
OLD_ADDENDUM_SHA = "699e3d8b3e83591aa48c05cf00e9fb772f17089010667aff7382275a47bf63e4"
OLD_PROFILE_SHA = "9663f10ac0191c485e4ddc6e25ae4644616139e033619df290e194c74b2b0dfb"
TRADE_PROFILE_SHA = "1375800668ed0ddec29d2e5f8efe8e1369d1e4da8b0aa6916b5b970078b137cd"
RAW_PATH = OLD_STAGE / "native-trade-power-inputs-002.json"
SOURCE_001_PATH = OLD_STAGE / "trade-power-source-001.json"
SOURCE_002_PATH = OLD_STAGE / "trade-power-source-002.json"


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
        "address_semantics": "RVA/VA retained separately; end is exclusive",
    }


def build_guards(pe: PE) -> list[dict]:
    # The selector and formula ranges come from source-002's two independent
    # UI paths.  Every range ends on an instruction boundary (or a complete
    # literal/code instruction for the small copy/key guards).
    windows = [
        ("country_power_selector_path_1", 0x101DD01, 0x101DD21, "selector_and_entry_selection"),
        ("country_power_selector_path_2", 0x101ED2B, 0x101ED4B, "selector_and_entry_selection"),
        ("country_power_formula_zero_init_path_1", 0x101D64B, 0x101D64E, "formula_zero_init"),
        ("country_power_formula_zero_init_path_2", 0x101E3FA, 0x101E3FD, "formula_zero_init"),
        ("country_power_formula_path_1", 0x101DD21, 0x101DD69, "complete_signed_formula"),
        ("country_power_formula_path_2", 0x101ED4B, 0x101ED93, "complete_signed_formula"),
        ("total_power_copy_path_1", 0x101DCBB, 0x101DCC1, "single_complete_copy_instruction"),
        ("total_power_copy_path_2", 0x101EF61, 0x101EF67, "single_complete_copy_instruction"),
        ("fixed_point_formatter", 0x101D170, 0x101D2BE, "complete_formatter_function"),
        ("node_definition_string_accessor", 0xB510F0, 0xB510FC, "existing_key_display_string_accessor"),
        ("definition_predicate_true", 0x8F440, 0x8F443, "predicate_leaf"),
        ("definition_predicate_false", 0x8F450, 0x8F453, "predicate_leaf"),
        ("current_power_label", 0x1D4FB98, 0x1D4FB98 + len(b"current_power\0"), "compiled_literal"),
        ("total_power_label", 0x1D4FBD0, 0x1D4FBD0 + len(b"total_power\0"), "compiled_literal"),
    ]
    return [make_guard(pe, *item) for item in windows]


def load_old_report(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"report_not_object:{path}")
    return value


def main() -> None:
    STAGE.mkdir(parents=True, exist_ok=True)
    pe = PE(game_exe())
    if hashlib.sha256(pe.data).hexdigest() != EXE_SHA or pe.base != IMAGE_BASE:
        raise RuntimeError("fixed_executable_identity_mismatch")
    raw = load_old_report(RAW_PATH)
    source_001 = load_old_report(SOURCE_001_PATH)
    source_002 = load_old_report(SOURCE_002_PATH)
    if raw.get("completed") is not True or raw.get("status") != "observed":
        raise RuntimeError("independent_raw_reference_not_complete")
    if raw.get("identity", {}).get("binding_verified") is not True:
        raise RuntimeError("independent_raw_identity_not_bound")
    if raw.get("doublepass", {}).get("consistent") is not True:
        raise RuntimeError("independent_raw_doublepass_not_consistent")
    if raw.get("cleanup", {}).get("handle_close", {}).get("closed") is not True:
        raise RuntimeError("independent_raw_handle_not_closed")

    guards = build_guards(pe)
    guard_map = {item["name"]: item for item in guards}
    assert bytes.fromhex(guard_map["definition_predicate_true"]["hex"]) == bytes.fromhex("b001c3")
    assert bytes.fromhex(guard_map["definition_predicate_false"]["hex"]) == bytes.fromhex("32c0c3")
    assert bytes.fromhex(guard_map["current_power_label"]["hex"]) == b"current_power\0"
    assert bytes.fromhex(guard_map["total_power_label"]["hex"]) == b"total_power\0"

    layout = {
        "runtime_total_power_offset": "0xc8",
        "runtime_total_power_width": 4,
        "runtime_total_power_signed": True,
        "entry_power_offsets": ["0x44", "0x48", "0x4c", "0x50", "0x54"],
        "entry_power_width": 4,
        "entry_power_signed": True,
        "source_trade_profile_sha256": TRADE_PROFILE_SHA,
        "country_fullref_offset": "0x20",
        "country_fullref_slot_offset": "0x4",
        "country_fullref_slot_width": 2,
        "country_fullref_slot_signed": True,
        "entry_table_offset": "0x18",
        "entry_stride": "0xc0",
        "node_definition_offset": "0xa8",
        "definition_key_offset": "0x10",
        "predicate_true_rva": "0x8f440",
        "predicate_false_rva": "0x8f450",
        "signed": True,
        "wrap_bits": 32,
    }
    formula = {
        "input_widths": {"0x44": "signed32", "0x48": "signed32", "0x4c": "signed32", "0x50": "signed32", "0x54": "signed32"},
        "q64": "trunc0(i64(i32(entry+0x44)) * i64(i32(entry+0x4c)) / 1000)",
        "q32": "i32(q64)",
        "positive32": "q32 if q32 > 0 else 0",
        "cap": "signed_min(i32(entry+0x48), positive32)",
        "delta": "i32(entry+0x54 - entry+0x50)",
        "final": "i32(cap + delta)",
        "order": ["signed64 product/trunc0", "narrow q64 to signed32", "TEST/CMOVG signed max-zero on q32", "signed cap", "32-bit delta", "32-bit final wrap"],
        "native_width_boundary": "The TEST/CMOVG sequence reads EDX/R8D, so the branch predicate is signed q32, not the un-narrowed q64.",
        "forbidden_rewrites": ["q64>0 then narrow", "max(0, product/1000 + delta)", "cap after delta", "unsigned cap", "sum as denominator"],
    }

    addendum = {
        "report_id": "information-trade-power-source-addendum-002",
        "batch": 44,
        "generated_on": "2026-10-27",
        "status": "bounded_formula_width_correction",
        "supersedes": {
            "report_path": "work/runtime/information-trade-power-20261027-001/trade-power-source-addendum-001.json",
            "report_sha256": OLD_ADDENDUM_SHA,
            "preserved": True,
            "reason": "The prior positive32 wording tested q64 before the native 32-bit TEST/CMOVG narrowing; this addendum corrects that semantic text without changing the preserved 001 bytes.",
        },
        "target": {"game_version": "1.37.4", "exe_sha256": EXE_SHA, "image_base_va": hex(IMAGE_BASE),
                   "address_rule": "VA=image_base+RVA; RVA and VA retained separately; ranges end exclusive"},
        "inputs": [pin(SOURCE_001_PATH), pin(SOURCE_002_PATH), pin(RAW_PATH),
                   pin(STAGE / "trade-power-source-addendum-001.json"),
                   pin(ROOT / "bridge/information/profiles/trade-income-memory-1374.json")],
        "fullref_runtime_observation": {
            "source": "independent raw trade-power input, country pointer + 0x20",
            "country": "FRA",
            "fullref_raw_hex": "465241007a000001",
            "fullref_bytes_4_6_hex": "7a00",
            "slot_signed16_little_endian": 122,
            "session_id": raw["identity"]["installation_session_id"],
            "game_date": raw["trade_power_inputs"][0]["date"]["value"],
            "meaning": "The observer country's native fullref carries FRA in bytes 0:3 and slot 122 in bytes 4:6; the remaining upper bytes are retained generation/fullref bytes and are not discarded as a tag-only identity.",
        },
        "ui_selector_static_mapping": {
            "path_1_rva_exclusive": ["0x101dd01", "0x101dd21"],
            "path_2_rva_exclusive": ["0x101ed2b", "0x101ed4b"],
            "path_1_steps": [
                "widget+0x58 is loaded, then wrapper+0x20 is loaded as a fullref qword",
                "shr qword,0x20",
                "movsx signed16 from dx",
                "index = signed16 * 3 * 0x40; add to node+0x18 table",
            ],
            "path_2_steps": [
                "widget+0x58 is loaded, then wrapper+0x20 is loaded as a fullref qword",
                "shr qword,0x20",
                "movsx signed16 from ax",
                "index = signed16 * 3 * 0x40; add to node+0x18 table",
            ],
            "byte_correspondence": "For a little-endian 8-byte fullref, (fullref_qword >> 32) low signed16 is exactly fullref bytes[4:6].",
            "identity_boundary": "This proves the UI selector's extraction shape only. It does not prove widget+0x58 points to the observer country pointer or that its selected slot equals the live FRA fullref slot.",
        },
        "country_power_source_decision": {
            "source": "FRA country pointer + 0x20 bytes[4:6], then runtime node table entry at slot*0xc0",
            "slot_binding": "dynamic signed16 from the observed country fullref; never hard-code 122 in production",
            "gui_status": "static entry formula is closed for the FRA raw reference; live widget selector equality remains unobserved",
            "publication_boundary": "Use this as an independent FRA entry formula/cache reference, not as a live GUI equivalence claim.",
        },
        "formula_contract": formula,
        "native_width_correction": {
            "post_quotient_instructions": [
                {"rva": "0x101dd48", "va": hex(IMAGE_BASE + 0x101DD48), "bytes": "458bc6", "instruction": "mov r8d,r14d"},
                {"rva": "0x101dd4b", "va": hex(IMAGE_BASE + 0x101DD4B), "bytes": "85d2", "instruction": "test edx,edx"},
                {"rva": "0x101dd4d", "va": hex(IMAGE_BASE + 0x101DD4D), "bytes": "440f4fc2", "instruction": "cmovg r8d,edx"},
                {"rva": "0x101ed72", "va": hex(IMAGE_BASE + 0x101ED72), "bytes": "458bc6", "instruction": "mov r8d,r14d"},
                {"rva": "0x101ed75", "va": hex(IMAGE_BASE + 0x101ED75), "bytes": "85d2", "instruction": "test edx,edx"},
                {"rva": "0x101ed77", "va": hex(IMAGE_BASE + 0x101ED77), "bytes": "440f4fc2", "instruction": "cmovg r8d,edx"},
            ],
            "interpretation": "After reciprocal-division correction leaves q64 in RDX, TEST EDX,EDX and CMOVG R8D,EDX inspect the signed low 32 bits. The zero-initialized R14D is copied into R8D first; therefore positive32=max(0,i32(q64)).",
            "zero_init_guards": [
                {"rva": "0x101d64b", "rva_end_exclusive": "0x101d64e", "bytes": "4533f6", "instruction": "xor r14d,r14d"},
                {"rva": "0x101e3fa", "rva_end_exclusive": "0x101e3fd", "bytes": "4533f6", "instruction": "xor r14d,r14d"},
            ],
        },
        "formula_counterexample": {
            "inputs": {"0x44": 2000000000, "0x4c": 2000000000, "0x48": 2147483647, "0x50": 0, "0x54": 0},
            "q64": 4000000000000000,
            "q32": -1827012608,
            "corrected_positive32": 0,
            "corrected_final": 0,
            "old_q64_test_wording_would_have_used": -1827012608,
            "meaning": "q64 is positive but its signed low 32 bits are negative; the native TEST/CMOVG path takes the zero branch.",
        },
        "total_power_contract": {
            "source": "runtime node pointer + 0xc8",
            "operation": "signed32 copy, then fixed-point formatter scale 1000",
            "gui_status": "static getter/copy and formatter scale are closed; cache freshness remains partial",
        },
        "static_guard_ranges": guards,
        "evidence_layers": {
            "ordinary_PE": "The listed bounded windows are local bytes from the fixed PE; no new REA function analysis or whole-image disassembly.",
            "independent_RPM": "native-trade-power-inputs-002 is raw two-pass observation and is not a production-reader result.",
            "production": "No production reader or formula was imported by this source/profile generation.",
        },
        "unresolved_conditions": [
            "Widget+0x58 fullref pointer equality with the captured observer country pointer was not observed.",
            "Cache refresh timing and same-date reload generation are not established.",
            "Shares and sources remain separate unresolved T04 fields and are not prerequisites for total_power or country_power cache reference.",
            "The static formula does not by itself establish complete live GUI equivalence.",
        ],
    }
    addendum_path = STAGE / "trade-power-source-addendum-002.json"
    write(addendum_path, addendum)

    source = {
        "schema": "information_trade_power_source.v1",
        "source_index_id": SOURCE_ID,
        "profile_id": PROFILE_ID,
        "target": {"game_version": "1.37.4", "exe_sha256": EXE_SHA, "image_base_va": hex(IMAGE_BASE),
                   "address_rule": "RVA; VA=image_base+RVA; all ranges end exclusive"},
        "fields": ["country_power", "total_power", "shares", "sources"],
        "behavior": "Copy current trade-node power caches and reproduce the bounded native current_power arithmetic for the selected FRA entry.",
        "basis": "native_trade_node_power_caches",
        "unit": "trade_power",
        "scale": 1000,
        "period": "current",
        "country_value_origin": "derived_from_copied_native_caches",
        "node_value_origin": "derived_from_copied_native_entry_caches",
        "total_value_origin": "copied_native_cache",
        "freshness": "partial_cache_observation",
        "complete": False,
        "layout": layout,
        "formula": formula,
        "fullref_contract": {
            "country_source": "country_pointer+0x20",
            "slot_bytes": "fullref bytes[4:6], little-endian signed int16",
            "entry_address": "runtime_node+0x18 + signed_slot*0xc0",
            "widget_selector": "separate static UI path widget+0x58 -> wrapper+0x20 -> (qword>>32) signed16",
            "no_substitution": "The widget selector is not substituted for the country fullref slot without a live equality guard.",
        },
        "runtime_reference": {
            "raw_path": RAW_PATH.relative_to(ROOT).as_posix(),
            "raw_sha256": digest(RAW_PATH),
            "session_id": raw["identity"]["installation_session_id"],
            "pid": raw["identity"]["installation_pid"],
            "game_date": raw["trade_power_inputs"][0]["date"]["value"],
            "country": "FRA",
            "fullref_raw_hex": raw["trade_power_inputs"][0]["country_fullref_raw_hex"],
            "country_slot_observed": raw["trade_power_inputs"][0]["country_slot"],
            "true_node_count": raw["trade_power_inputs"][0]["true_node_count"],
            "doublepass_consistent": raw["doublepass"]["consistent"],
            "handle_closed": raw["cleanup"]["handle_close"]["closed"],
        },
        "ordinary_bounded_evidence": [pin(SOURCE_001_PATH), pin(SOURCE_002_PATH), pin(addendum_path),
                                       pin(STAGE / "trade-power-source-addendum-001.json"),
                                       pin(ROOT / "bridge/information/profiles/trade-income-memory-1374.json")],
        "independent_raw_evidence": [pin(RAW_PATH)],
        "reused_trade_profile_sha256": TRADE_PROFILE_SHA,
        "code_guards": guards,
        "evidence_layers": {
            "ordinary_PE": "Bounded static bytes and existing source-002 instruction rows; no new REA analysis.",
            "independent_RPM": "The two-pass raw input contains 80 real nodes and one skipped false predicate; it does not invoke production readers.",
            "public_or_GUI": "No GUI screenshot or widget pointer equality was observed; the country source remains an FRA entry/cache reference.",
        },
        "unresolved_conditions": addendum["unresolved_conditions"],
    }
    source_path = STAGE / "trade-power-source-index-002.json"
    write(source_path, source)

    profile = {
        "profile_id": PROFILE_ID,
        "game_version": "1.37.4",
        "executable": {"sha256": EXE_SHA, "image_base_va": hex(IMAGE_BASE)},
        "source_index": {"source_index_id": SOURCE_ID, "path": source_path.relative_to(ROOT).as_posix(), "sha256": digest(source_path)},
        "layout": layout,
        "semantics": {
            "basis": source["basis"], "unit": source["unit"], "scale": source["scale"], "period": source["period"],
            "country_value_origin": source["country_value_origin"], "node_value_origin": source["node_value_origin"],
            "total_value_origin": source["total_value_origin"], "freshness": source["freshness"], "complete": source["complete"],
        },
        "formula": formula,
        "code_guards": guards,
        "provenance": {
            "source_report_addendum": pin(addendum_path),
            "reused_trade_profile": pin(ROOT / "bridge/information/profiles/trade-income-memory-1374.json"),
            "independent_raw": pin(RAW_PATH),
        },
    }
    profile_path = ROOT / "bridge/information/profiles/trade-power-memory-1374.json"
    snapshot_path = STAGE / "trade-power-memory-1374-profile-001.json"
    if not snapshot_path.exists():
        if not profile_path.exists() or digest(profile_path) != OLD_PROFILE_SHA:
            raise RuntimeError("old_profile_snapshot_source_mismatch")
        snapshot_path.write_bytes(profile_path.read_bytes())
    if digest(snapshot_path) != OLD_PROFILE_SHA:
        raise RuntimeError("old_profile_snapshot_digest_mismatch")
    if profile_path.exists():
        if digest(profile_path) != OLD_PROFILE_SHA:
            raise RuntimeError("refusing_to_replace_unpinned_profile")
        with profile_path.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(profile, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    else:
        write(profile_path, profile)
    print(json.dumps({
        "source_index": pin(source_path),
        "profile": pin(profile_path),
        "addendum": pin(addendum_path),
        "guards": len(guards),
        "guard_bytes": sum(len(bytes.fromhex(item["hex"])) for item in guards),
    }))


if __name__ == "__main__":
    main()
