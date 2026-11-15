"""Bounded source/runtime design audit for T04 target-country scope.

This is a research-only script.  It reads the checked-in information readers,
their small profiles, and the already archived T04 JSON.  It does not open a
game process, invoke REA, decode a binary, or modify production code.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-trade-share-20261027-001"
OUT = STAGE / "country-scope-design-001.json"
MAX_INPUT_BYTES = 2 * 1024 * 1024


def _raw(path: Path) -> bytes:
    size = path.stat().st_size
    if size <= 0 or size > MAX_INPUT_BYTES:
        raise RuntimeError(f"input_size_out_of_bound:{path}:{size}")
    value = path.read_bytes()
    if len(value) != size:
        raise RuntimeError(f"input_size_changed:{path}")
    return value


def _sha(path: Path) -> tuple[int, str]:
    value = _raw(path)
    return len(value), hashlib.sha256(value).hexdigest()


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(_raw(path).decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"json_root_not_object:{path}")
    return value


def _line(path: Path, pattern: str) -> int | None:
    text = _raw(path).decode("utf-8").splitlines()
    regex = re.compile(pattern)
    for index, item in enumerate(text, 1):
        if regex.search(item):
            return index
    return None


def _number(value: Any) -> int:
    if isinstance(value, bool):
        raise RuntimeError("boolean_not_integer")
    return int(value, 0) if isinstance(value, str) else int(value)


def _ref(path: str, role: str, *patterns: str) -> dict[str, Any]:
    file = ROOT / path
    size, digest = _sha(file)
    return {
        "path": path,
        "bytes": size,
        "sha256": digest,
        "role": role,
        "source_lines": {
            pattern: _line(file, pattern) for pattern in patterns
        },
    }


def _main() -> dict[str, Any]:
    loc_profile = _json(ROOT / "bridge/information/profiles/localization-memory-1374.json")
    country_profile = _json(ROOT / "bridge/information/profiles/country-resources-memory-1374.json")
    income_profile = _json(ROOT / "bridge/information/profiles/trade-income-memory-1374.json")
    power_profile = _json(ROOT / "bridge/information/profiles/trade-power-memory-1374.json")
    power_source = _json(ROOT / "work/runtime/information-trade-state-20261027-001/trade-power-source-002.json")
    raw_power = _json(ROOT / "work/runtime/information-trade-state-20261027-001/native-trade-power-inputs-002.json")

    passes = raw_power.get("trade_power_inputs")
    pass_shape = []
    if isinstance(passes, list):
        for item in passes:
            if not isinstance(item, dict):
                continue
            nodes = item.get("trade_power_nodes")
            country_scan = item.get("country")
            matches = country_scan.get("matches") if isinstance(country_scan, dict) else None
            match = matches[0] if isinstance(matches, list) and matches else None
            skipped = item.get("skipped_false_nodes")
            pass_shape.append({
                "country_status": country_scan.get("status") if isinstance(country_scan, dict) else None,
                "requested_country": country_scan.get("requested_country") if isinstance(country_scan, dict) else None,
                "country_scan_entries": (
                    country_scan.get("scanned_entries", country_scan.get("entries"))
                    if isinstance(country_scan, dict) else None
                ),
                "country_match_count": len(matches) if isinstance(matches, list) else None,
                "country_match_index": match.get("index") if isinstance(match, dict) else None,
                "country_fullref_raw_hex": item.get("country_fullref_raw_hex"),
                "country_slot": item.get("country_slot"),
                "trade_power_node_count": len(nodes) if isinstance(nodes, list) else None,
                "skipped_false_node_count": len(skipped) if isinstance(skipped, list) else None,
            })

    loc_country = loc_profile["country"]
    loc_globals = loc_profile["globals"]
    country_layout = country_profile["country"]
    income_layout = income_profile["layout"]
    power_layout = power_profile["layout"]
    target = power_source.get("target", {})

    report: dict[str, Any] = {
        "schema": "information_trade_country_scope_design.v1",
        "batch": 45,
        "status": "design_only_no_production_change",
        "objective": (
            "Define the smallest correct T04 target-country contract while preserving "
            "the FRA mother identity; do not claim foreign runtime coverage."
        ),
        "target_build": {
            "game_version": target.get("game_version", "1.37.4"),
            "exe_sha256": target.get("exe_sha256"),
            "image_base_va": target.get("image_base_va", "0x140000000"),
            "address_rule": "VA=image_base+RVA; retain RVA and VA separately",
        },
        "evidence_inputs": [
            _ref(
                "bridge/information/localization_memory.py",
                "mature shared country-table identity helper",
                r"def _tag_and_slot\(", r"def _country_identity\(",
            ),
            _ref(
                "bridge/information/profiles/localization-memory-1374.json",
                "country-table and fullref layout pin",
            ),
            _ref(
                "bridge/information/country_resources_memory.py",
                "country-resource parent capture and FRA gate",
                r"def _snapshot\(", r"def capture\(", r"if country != EXPECTED_COUNTRY",
            ),
            _ref(
                "bridge/information/profiles/country-resources-memory-1374.json",
                "country-resource table layout pin",
            ),
            _ref(
                "bridge/information/domestic_pressure_memory.py",
                "independent duplicate country-table implementation",
                r"def _country_identity\(", r"def capture\(", r"if country != EXPECTED_COUNTRY",
            ),
            _ref(
                "bridge/information/trade_income_memory.py",
                "FRA-bound trade graph/entry reader and validator",
                r"def read_fields\(", r"def validate_record\(", r"COUNTRY_FULLREF_PREFIX",
            ),
            _ref(
                "bridge/information/profiles/trade-income-memory-1374.json",
                "trade graph and entry layout pin",
            ),
            _ref(
                "bridge/information/trade_power_memory.py",
                "FRA-bound power child reader and validator",
                r"def read_fields\(", r"def validate_record\(", r"EXPECTED_COUNTRY",
            ),
            _ref(
                "bridge/information/profiles/trade-power-memory-1374.json",
                "power offsets/layout pin",
            ),
            _ref(
                "bridge/information/trade_power.py",
                "current T04 adapter and fixed FRA capture call",
                r"class NativeTradePowerSource", r"include_trade_income=True",
            ),
            _ref(
                "work/runtime/information-trade-state-20261027-001/trade-power-source-002.json",
                "bounded T04 static contract; no foreign runtime observation",
            ),
            _ref(
                "work/runtime/information-trade-state-20261027-001/native-trade-power-inputs-002.json",
                "two-pass FRA-only raw input",
            ),
        ],
        "mature_country_lookup": {
            "primary_function": "bridge.information.localization_memory._country_identity(reader, database, requested_country)",
            "reused_by": [
                "bridge.information.country_resources_memory._country_identity",
                "bridge.information.domestic_pressure_memory._country_identity (same bounded semantics, local implementation)",
            ],
            "layout": {
                "database_global_rva": loc_globals["database_rva"],
                "database_country_table_offset": loc_country["table_offset"],
                "table_pointer_width_bytes": 8,
                "table_pointer_stride_bytes": 8,
                "table_scan_entries": _number(loc_country["country_scan_entries"]),
                "table_scan_bytes": _number(loc_country["country_scan_entries"]) * 8,
                "country_handle_offset": loc_country["handle_offset"],
                "country_handle_width_bytes": 8,
                "tag_encoding": "low 24 handle bits, three ASCII bytes [A-Z0-9]",
                "slot_encoding": "low 16 bits of handle>>32; compare to table index",
            },
            "acceptance": {
                "requested_country": "exact uppercase three-character tag",
                "match": "tag == requested_country and embedded handle slot == table index",
                "known_only_if": "exactly one match",
                "zero_or_duplicate": "unknown; no pointer fallback",
                "tail": "not claimed beyond the fixed 256-entry window",
            },
            "fullref_followup": {
                "address": "resolved_country_pointer + 0x20",
                "width_bytes": 8,
                "prefix": "target_tag + NUL in bytes 0:4",
                "slot": "signed int16 little-endian bytes 4:6; require 0..32767",
                "bytes_6_8": "retain generation/upper fullref bytes; do not discard",
                "cross_checks": [
                    "table index == handle embedded slot == fullref slot",
                    "fullref tag == requested target tag",
                ],
            },
        },
        "current_scope_boundaries": {
            "country_resources": {
                "snapshot_parameters": "(reader, module_base, country, profile, include_monthly_economy=False, include_trade_income=False, include_home_trade_node=False, include_trade_power=False)",
                "capture_parameters": "capture(installation, country, *, include_trade_income=False, include_home_trade_node=False, include_trade_power=False, ...)",
                "gate": "capture rejects country != EXPECTED_COUNTRY (FRA); profile supported_country is FRA",
                "mother": "report.country and parent identity remain FRA",
            },
            "trade_income": {
                "reader": "read_fields(reader, module_base, country_pointer)",
                "hardcoded_contract": [
                    "COUNTRY_FULLREF_PREFIX == b'FRA\\0'",
                    "record country/output and validator EXPECTED_COUNTRY == FRA",
                ],
                "entry": "reads the supplied pointer's fullref slot and table+slot*0xc0, but current validator is not target-country parameterized",
            },
            "trade_power": {
                "reader": "read_fields(reader, module_base, trade_income_record)",
                "hardcoded_contract": "child validator requires the FRA-bound trade-income record and EXPECTED_COUNTRY",
                "adapter": "NativeTradePowerSource.read fixes capture country FRA and requests both children once",
            },
        },
        "trade_node_layout_required_for_target": {
            "definition_graph": {
                "manager_global_rva": income_layout["manager_global_rva"],
                "begin_offset": income_layout["vector_begin_offset"],
                "end_offset": income_layout["vector_end_offset"],
                "vector_stride_bytes": income_layout["vector_stride"],
                "max_definitions": income_layout["max_definitions"],
                "predicate_slot": income_layout["definition_predicate_slot"],
                "predicate_true_rva": income_layout["predicate_true_rva"],
                "predicate_false_rva": income_layout["predicate_false_rva"],
                "key_offset": income_layout["definition_key_offset"],
                "key_max_bytes": income_layout["max_key_length"],
                "center_offset": income_layout["definition_center_offset"],
            },
            "runtime_chain": {
                "game_global_rva": income_layout["game_global_rva"],
                "province_base_offset": income_layout["province_base_offset"],
                "province_stride": income_layout["province_stride"],
                "province_trade_node_offset": income_layout["province_trade_node_offset"],
                "runtime_definition_offset": income_layout["node_definition_offset"],
                "runtime_entry_table_offset": income_layout["entry_table_offset"],
            },
            "target_entry": {
                "address": "same validated node table pointer + target_country_slot * 0xc0",
                "stride_bytes": income_layout["entry_stride"],
                "max_target_entry_bytes_at_1024_definitions": _number(income_layout["max_definitions"]) * _number(income_layout["entry_stride"]),
                "income_offset": income_layout["entry_income_offset"],
                "flags_offsets": {
                    "AC": "0xac",
                    "AD": "0xad",
                    "AE": "0xae",
                },
                "power_offsets": {
                    "0x44": power_layout["entry_power_offsets"][0],
                    "0x48": power_layout["entry_power_offsets"][1],
                    "0x4c": power_layout["entry_power_offsets"][2],
                    "0x50": power_layout["entry_power_offsets"][3],
                    "0x54": power_layout["entry_power_offsets"][4],
                },
                "do_not_reuse": "FRA node entry_raw_hex is not a foreign target entry; target slot requires a new 0xc0 read per real node",
            },
            "total_power": {
                "address": "validated runtime node pointer + 0xc8",
                "width_bytes": 4,
                "semantics": "shared node cache; target-country query must label it global/node-scoped, not target-owned",
            },
            "budget": {
                "current_trade_reader_max_single_read_bytes": 65536,
                "current_trade_reader_max_total_read_bytes": 524288,
                "country_table_scan_bytes": 2048,
                "target_entry_read_upper_bound_bytes": 196608,
                "rule": "account for mother graph plus target entries and fail closed if the shared bounded RPM budget is exceeded",
            },
        },
        "minimal_correct_integration": {
            "query": {
                "object": {"type": "trade_node", "node_id": "<ASCII node id>"},
                "parameters": {
                    "country": {
                        "type": "string",
                        "pattern": "^[A-Z0-9]{3}$",
                        "required": False,
                        "default": "FRA",
                        "meaning": "target country entry; observer/mother remains FRA",
                    }
                },
                "compatibility": "omitting country preserves the current FRA result; shares/sources remain unsupported",
            },
            "single_capture_shape": {
                "request": "mother country='FRA', include_trade_income=True, include_trade_power=True, include_trade_country=<target>",
                "same_pass": "resolve target pointer/fullref and target entries inside the existing AddressBoundedRPM pass",
                "before_after": "target child is present in top/before/after and canonical-equal; parent identity/date/doublepass/cleanup remain FRA-bound",
                "no_second_capture": "do not call capture(country=target) as a second read; that would replace the mother identity and lose atomicity",
            },
            "target_record": {
                "identity": "requested tag, pointer, fullref_raw_hex, slot, table index, handle raw",
                "topology": "reuse only validated mother graph topology (node id/definition/predicate/center/runtime/table) with explicit provenance",
                "payload": "read and validate target table+slot*0xc0 independently for every retained real node",
                "values": "country_power derives from target entry +0x44/+0x4c/+0x48/+0x50/+0x54; total_power copies validated node +0xc8 cache",
                "visibility": "publish target only after identity and target-entry guards pass; otherwise unknown/unavailable, never FRA fallback",
            },
            "metadata": {
                "observer": "FRA",
                "mother_country": "FRA",
                "requested_country": "target tag",
                "context_scope": "country_scope_with_query_target",
                "visibility": "loaded_country_table_entry; active/player-visible scope not proven",
                "target_binding": "country_table index + handle slot + target fullref slot/tag",
                "topology_source": "mother_FRA_trade_graph",
                "target_entry_source": "target_country_pointer + 0x20 slot -> node table + slot*0xc0",
                "gaps": [
                    "ACTIVE_COUNTRY_OR_VISIBLE_COUNTRY_PREDICATE_NOT_IDENTIFIED",
                    "TARGET_ENTRY_RUNTIME_TWO_PASS_NOT_OBSERVED",
                    "GUI_SELECTOR_TO_TARGET_FULLREF_EQUALITY_NOT_OBSERVED",
                    "TARGET_COUNTRY_POWER_FRESHNESS_NOT_PROVEN",
                ],
            },
        },
        "runtime_evidence_boundary": {
            "archived_input_country": raw_power.get("country"),
            "passes": pass_shape,
            "foreign_target_observed": False,
            "reason": "native-trade-power-inputs-002 contains two FRA passes and 80 node entries per pass; no foreign country pointer/fullref/entry payload is present",
            "source_report_boundary": power_source.get("country_context_contract", {}),
        },
        "unresolved": [
            "Current profiles/country table prove loaded tag+slot identity, not an active or UI-visible country predicate.",
            "Current trade-income and trade-power records/validators hard-code FRA and cannot safely validate a foreign target.",
            "The UI packed selector is statically mapped to a node entry slot, but equality to an arbitrary query target fullref is not observed.",
            "No foreign target two-pass raw record exists in the archived runtime evidence.",
        ],
        "decision": "Do not expand T04 coverage in this research turn; implement the target-country child only after the separate fullref/entry reader and visibility guard are pinned.",
        "verification": {
            "script": "work/research_information_trade_country_scope.py",
            "inputs_bounded": True,
            "game_access": False,
            "rea_access": False,
            "production_files_changed": False,
            "old_stage_files_changed": False,
        },
    }
    return report


def main() -> None:
    report = _main()
    STAGE.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    OUT.write_text(encoded, encoding="utf-8", newline="\n")
    size, digest = _sha(OUT)
    print(json.dumps({"path": str(OUT), "bytes": size, "sha256": digest}, ensure_ascii=False))


if __name__ == "__main__":
    main()
