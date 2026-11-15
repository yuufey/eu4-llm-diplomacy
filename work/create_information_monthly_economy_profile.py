"""Pin already researched, bounded monthly-ledger source windows (no game IO)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE
from work.local_config import game_exe

STAGE = ROOT / "work/runtime/information-economy-20261027-001"
SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PROFILE_ID = "monthly-economy-memory-1374"
SOURCE_ID = "information-monthly-ledger-source-001"


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def write(path, document):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    pe = PE(game_exe())
    assert hashlib.sha256(pe.data).hexdigest() == SHA and pe.base == 0x140000000
    windows = [
        ("monthly_income_property_constructor", 0x6D8883, 0x6D88AE),
        ("monthly_income_property_literal", 0x1CA8DA8, 0x1CA8DB7),
        ("monthly_income_callback", 0x6DF9A0, 0x6DF9F8),
        ("recurring_net_helper_and_relative_tables", 0x33D270, 0x33D3BA),
        ("country_ledger_writer_binding", 0x2DF5CC, 0x2DF5E0),
        ("ledger_constructor_binding", 0x2CD306, 0x2CD314),
        ("ledger_named_monthly_table_dispatch", 0xAF2EFB, 0xAF2F4D),
        ("income_19_signed_fixed_point_writer_loop", 0xAF301F, 0xAF307A),
        ("expense_38_signed_fixed_point_writer_loop", 0xAF30AF, 0xAF310A),
        ("signed_fixed_point_thousand_writer", 0x246BF9, 0x246C66),
        ("signed_fixed_point_format_literals", 0x1DBF978, 0x1DBF98B),
        ("lastmonthincometable_token", 0x207BA90, 0x207BAA9),
        ("lastmonthexpensetable_token", 0x207BC98, 0x207BCB2),
    ]
    # Token sizes are taken from their explicitly recorded serialized byte strings.
    unit = json.loads((STAGE / "ledger-unit-source-001.json").read_text(encoding="utf-8"))
    tokens = {item["name"]: item for item in unit["token_literals"]}
    guards = []
    for name, begin, end in windows:
        token_name = name.removesuffix("_token")
        if token_name in tokens:
            end = begin + len(bytes.fromhex(tokens[token_name]["bytes"]))
        raw = pe.bytes_at(begin, end - begin)
        assert len(raw) == end - begin
        guards.append({"name": name, "rva": hex(begin), "rva_end_exclusive": hex(end),
                       "hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()})
    assert pe.bytes_at(0x1CA8DA8, 15) == b"monthly_income\0"
    # Pin the static absolute-pointer table as evidence only, never as an ASLR runtime guard.
    table = pe.bytes_at(0x1C9FD30, 32)
    assert int.from_bytes(table[16:24], "little") == pe.base + 0x6DF9A0
    sources = [
        "budget-mask-audit-002.json", "ledger-unit-source-001.json",
        "ordinary-function-6d8870-001.json", "ordinary-monthly-income-callback-001.json",
        "ordinary-function-eb40f0-001.json", "ordinary-function-eb7b20-001.json",
        "expense-ui-source-001.json",
    ]
    pins = [{"path": str((STAGE / name).relative_to(ROOT)).replace("\\", "/"),
             "sha256": digest(STAGE / name), "bytes": (STAGE / name).stat().st_size}
            for name in sources]
    old_rea = ROOT / "work/runtime/r71-favor-budget-contract-20261020-001/query-33d270/evidence.json"
    assert digest(old_rea) == "6cf027c9b783916c07f4cbdaf640f00c74b2b10eeb71656e4bf92deba77e3039"
    source = {
        "schema": "information_monthly_ledger_source.v1", "source_index_id": SOURCE_ID,
        "profile_id": PROFILE_ID, "target": {"game_version": "1.37.4", "exe_sha256": SHA,
        "image_base_va": hex(pe.base), "addresses": "RVA; VA=image_base+RVA; ranges end exclusive unless explicitly inclusive"},
        "behavior": "Copy the previous-month native income/expense tables; derive the audited recurring subset and its signed int32 difference.",
        "basis": "native_recurring_monthly_ledger", "period": "month", "reference_period": "previous_month",
        "value_semantics": "previous_month_recurring_ledger", "unit": "ducats", "scale": 1000,
        "value_origin": "derived_from_copied_native_ledger", "complete": False,
        "evidence_layers": {
            "prior_REA": {"evidence_id": "ev_05980d052b181cdb7939c24ae4ff96bbd59895140ade149f3c51169d3b394a6b",
                "path": str(old_rea.relative_to(ROOT)).replace("\\", "/"), "sha256": digest(old_rea),
                "analyzed_body_rva_start": "0x33d270", "analyzed_body_rva_end_inclusive": "0x33d372",
                "bytes": 259, "pdata_unwind_coverage_end_exclusive": "0x33d3ba",
                "separation": "The 330-byte pdata coverage also includes relative jump-table data; it is not the 259-byte analyzed body."},
            "ordinary_bounded_PE": pins,
            "runtime": "Independent raw RPM and public MCP acceptance are separate artifacts; this source index makes no runtime claim."},
        "property_binding": {"name": "monthly_income", "constructor_rva": "0x6d8870",
            "vtable_rva": "0x1c9fd30", "getter_slot": "0x10", "getter_rva": "0x6df9a0",
            "static_vtable_window_sha256": hashlib.sha256(table).hexdigest(),
            "runtime_guard_rule": "Absolute vtable pointers are static evidence only and are excluded from runtime byte guards."},
        "derivation": {"income_source": "country+0x770, 19 signed int32 slots, serialized lastmonthincometable",
            "expenses_source": "country+0x7bc, 38 signed int32 slots, serialized lastmonthexpensetable",
            "income_indices": [0,1,2,3,4,5,6,7,8,15,16],
            "expense_indices": [0,1,2,3,4,5,6,7,8,9,10,15,21,22,23,24,25,26,27,30,31,33,34],
            "arithmetic": "Each addition and final income-minus-expenses subtraction wraps modulo 2^32; expose signed int32.",
            "correction": "Old R71 prose included income index 12 incorrectly. Both the native named property and net helper exclude it; retain old reports unchanged.",
            "raw_hex": "Little-endian encoding of the derived aggregate, not a directly copied aggregate cache."},
        "unit_proof": {"serializer_rva": "0xaf2dc0", "income_loop_rva": "0xaf301f",
            "expense_loop_rva": "0xaf30af", "fixed_point_writer_rva": "0x246bf0",
            "divisor": 1000, "format": ["%d.%03d", "-%d.%03d"],
            "proof": "Named last-month table serializers pass each signed int32 to the common /1000 quotient/remainder writer."},
        "unresolved_conditions": ["The current GUI budget recomputes forecast components; equality with this previous-month recurring ledger is not established.",
            "One-time ledger rows are excluded by the native recurring masks; this is not the sum of every last-month transaction.",
            "Same-date world reload generations and atomic multi-read world snapshots are not independently established.",
            "Only the fixed executable identity and the verified FRA runtime context are supported."],
        "runtime_guards": guards,
    }
    source_path = STAGE / "monthly-ledger-source-001.json"
    write(source_path, source)
    profile = {"profile_id": PROFILE_ID, "game_version": "1.37.4", "executable": {"sha256": SHA},
        "source_index": {"source_index_id": SOURCE_ID, "path": str(source_path.relative_to(ROOT)).replace("\\", "/"),
                         "sha256": digest(source_path)},
        "layout": {"income_offset": "0x770", "income_count": 19, "expense_offset": "0x7bc",
            "expense_count": 38, "payload_size": 228, "component_width": 4, "signed": True,
            "wrap_bits": 32, "income_indices": source["derivation"]["income_indices"],
            "expense_indices": source["derivation"]["expense_indices"]},
        "semantics": {key: source[key] for key in ("basis", "period", "reference_period", "value_semantics", "unit", "scale", "value_origin", "complete")},
        "code_guards": guards}
    profile_path = ROOT / "bridge/information/profiles/monthly-economy-memory-1374.json"
    write(profile_path, profile)
    print(json.dumps({"source_sha256": digest(source_path), "profile_sha256": digest(profile_path),
                      "guards": len(guards), "guard_bytes": sum(len(bytes.fromhex(g["hex"])) for g in guards)}))


if __name__ == "__main__":
    main()
