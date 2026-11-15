"""Build a bounded, read-only survey of the 238620 battle-entry payload.

The report is deliberately mechanical.  It consumes the already frozen
selected reports and ledgers for 238620 and the later battle-message/layout
work.  It does not query REA, attach to a game, call native code, or infer
visibility, stable battle identities, or business field semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "runtime" / "information-battle-entry-20261025-001"
OUTPUT = STAGE / "payload-source-survey-001.json"

FIXED_BUILD = "1.37.4"
FIXED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
STATIC_IMAGE_BASE = "0x140000000"
MAX_SELECTED_JSON_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json_bounded(path: Path, expected_sha256: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read only a small selected/ledger report and fail closed on changes."""

    before = path.stat()
    require(before.st_size <= MAX_SELECTED_JSON_BYTES, f"selected/ledger JSON exceeds bound: {rel(path)}")
    content = path.read_bytes()
    after = path.stat()
    require(
        (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
        f"source changed during read: {rel(path)}",
    )
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if expected_sha256 is not None:
        require(actual_sha256 == expected_sha256, f"SHA-256 changed: {rel(path)}")
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid UTF-8 JSON: {rel(path)}") from exc
    require(isinstance(value, dict), f"top-level object required: {rel(path)}")
    return value, {
        "path": rel(path),
        "bytes": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "sha256": actual_sha256,
        "read_limit_bytes": MAX_SELECTED_JSON_BYTES,
        "stable_during_read": True,
    }


def pin(path_text: str, expected_sha256: str | None = None, role: str = "input") -> dict[str, Any]:
    path = ROOT / path_text
    value, meta = load_json_bounded(path, expected_sha256)
    return {"role": role, **meta, "top_level_keys": list(value)[:32]}


def unwrap_selected(node: Any, label: str) -> Any:
    require(isinstance(node, dict), f"missing selected wrapper: {label}")
    require(node.get("status") == "observed", f"selected value is not observed: {label}")
    require("value" in node, f"selected value missing: {label}")
    return node["value"]


def callback_lines(callback: dict[str, Any], numbers: list[int]) -> list[dict[str, Any]]:
    pseudo = unwrap_selected(callback["raw_result_value"]["pseudocode"], "callback.pseudocode")
    require(isinstance(pseudo, str), "callback pseudocode must be text")
    lines = pseudo.splitlines()
    result: list[dict[str, Any]] = []
    for number in numbers:
        require(1 <= number <= len(lines), f"callback line out of range: {number}")
        result.append({"line": number, "text": lines[number - 1]})
    return result


def callback_body(callback: dict[str, Any]) -> dict[str, Any]:
    procedure = unwrap_selected(callback["raw_result_value"]["procedure"], "callback.procedure")
    require(isinstance(procedure, dict), "callback procedure must be object")
    body = procedure.get("body")
    require(isinstance(body, dict), "callback procedure body missing")
    return {
        "address": procedure.get("address"),
        "name": procedure.get("name"),
        "signature": procedure.get("signature"),
        "body": {
            "ranges": body.get("ranges"),
            "total_bytes": body.get("total_bytes"),
            "span_bytes": body.get("span_bytes"),
            "non_contiguous": body.get("non_contiguous"),
            "contains_entry": body.get("contains_entry"),
        },
    }


def source_record(path: str, expected_sha256: str, role: str) -> tuple[dict[str, Any], dict[str, Any]]:
    value, meta = load_json_bounded(ROOT / path, expected_sha256)
    return value, {"role": role, **meta}


def report_source_pin(path_text: str, expected_sha256: str, role: str) -> dict[str, Any]:
    path = ROOT / path_text
    stat = path.stat()
    actual = sha256_file(path)
    require(actual == expected_sha256, f"source SHA changed: {rel(path)}")
    return {"role": role, "path": rel(path), "bytes": stat.st_size, "sha256": actual}


def fixed_build_checks(reports: dict[str, dict[str, Any]]) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    retention = reports["retention"]
    checks["retention_target"] = {
        "build": retention["target"]["build"],
        "executable_sha256": retention["target"]["executable_sha256"],
        "static_image_base": retention["target"]["static_image_base"],
    }
    message = reports["message"]
    checks["message_target_exe_sha256"] = message["target_exe_sha256"]
    land = reports["land"]
    checks["land_scope"] = {
        "fixed_build": land["scope"]["fixed_build"],
        "target_exe_sha256": land["scope"]["target_exe_sha256"],
    }
    result = reports["result_keys"]
    checks["result_scope"] = {
        "game_version": result["scope"]["game_version"],
        "target_executable_sha256": result["scope"]["target_executable_sha256"],
    }
    side = reports["side_keys"]
    checks["side_scope"] = {
        "game_version": side["scope"]["game_version"],
        "target_executable_sha256": side["scope"]["target_executable_sha256"],
    }
    unit = reports["unit"]
    checks["unit_target"] = {
        "version": unit["target_build"]["version"],
        "executable_sha256": unit["target_build"]["executable_sha256"],
    }
    scalar = reports["scalar"]
    checks["scalar_target"] = {
        "version": scalar["target_build"]["version"],
        "executable_sha256": scalar["target_build"]["executable_sha256"],
    }
    require(checks["retention_target"] == {
        "build": FIXED_BUILD,
        "executable_sha256": FIXED_EXE_SHA256,
        "static_image_base": STATIC_IMAGE_BASE,
    }, "retention fixed-build pin mismatch")
    require(checks["message_target_exe_sha256"] == FIXED_EXE_SHA256, "message fixed-build pin mismatch")
    require(checks["land_scope"] == {"fixed_build": FIXED_BUILD, "target_exe_sha256": FIXED_EXE_SHA256}, "land fixed-build pin mismatch")
    require(checks["result_scope"]["game_version"] == FIXED_BUILD, "result key build mismatch")
    require(checks["result_scope"]["target_executable_sha256"] == FIXED_EXE_SHA256, "result key EXE mismatch")
    require(checks["side_scope"]["game_version"] == FIXED_BUILD, "side key build mismatch")
    require(checks["side_scope"]["target_executable_sha256"] == FIXED_EXE_SHA256, "side key EXE mismatch")
    require(checks["unit_target"] == {"version": FIXED_BUILD, "executable_sha256": FIXED_EXE_SHA256}, "unit build pin mismatch")
    require(checks["scalar_target"] == {"version": FIXED_BUILD, "executable_sha256": FIXED_EXE_SHA256}, "scalar build pin mismatch")
    return checks


def evidence_ref(source_id: str, path: str, sha256: str, evidence_id: str, rva: str, body: Any, lines: list[int] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "source_id": source_id,
        "path": path,
        "sha256": sha256,
        "evidence_id": evidence_id,
        "rva": rva,
        "body_inclusive": body,
    }
    if lines is not None:
        result["pseudocode_lines"] = lines
    return result


def retention_source_ref(source_id: str, item: dict[str, Any], line_range: list[int] | None = None) -> dict[str, Any]:
    selected = item.get("selected")
    require(isinstance(selected, dict), f"retention selected source missing: {source_id}")
    result: dict[str, Any] = {
        "source_id": source_id,
        "selected_path": selected.get("path"),
        "selected_bytes": selected.get("bytes"),
        "selected_sha256": selected.get("sha256"),
        "evidence_id": item.get("evidence_id"),
        "rva": item.get("rva"),
        "body_inclusive": item.get("Ghidra_body_inclusive"),
    }
    if line_range is not None:
        result["line_range"] = line_range
    return result


def record_by_name(report: dict[str, Any], name: str) -> dict[str, Any] | None:
    for record in report["compiled_record_inventory"]["records"]:
        if record.get("compiled_name") == name:
            return record
    return None


def key_ref(source_id: str, report: dict[str, Any], name: str) -> dict[str, Any]:
    record = record_by_name(report, name)
    require(record is not None, f"compiled record missing: {name}")
    return {
        "source_id": source_id,
        "compiled_name": record["compiled_name"],
        "key_id": record["key_id"],
        "key_id_hex": record["key_id_hex"],
        "record_rva": record["record_rva"],
        "record_va": record["record_va"],
        "raw_bytes_hex": record["raw_bytes_hex"],
        "raw_bytes_sha256": record["raw_bytes_sha256"],
        "semantic_status": record.get("semantic_status"),
        "runtime_key_vector_override": record.get("runtime_key_vector_override"),
    }


def unit_template_refs(unit: dict[str, Any], side: str) -> list[dict[str, Any]]:
    selected = unit["selected_sources"][side]
    return [
        {
            "template": item["template"],
            "side_label": item.get("side_label"),
            "unit_label": item.get("unit_label"),
            "phase": item.get("phase"),
            "template_line": item.get("template_line"),
            "native_combat_side_offsets": item.get("native_combat_side_offsets"),
            "source_binding": item.get("source_binding"),
            "formula_as_decompiled": item.get("formula_as_decompiled"),
            "player_or_country_view": item.get("player_or_country_view"),
        }
        for item in selected.get("templates", [])
    ]


def make_report() -> dict[str, Any]:
    paths = {
        "callback": ("work/runtime/information-battle-war-records-20261025-001/callback-entry-selected-001.json", "1d7114d3accb76b417b6a4a56135cc32e8ff8cb3640d1242ff4fe0c5b280a8f6", "238620 selected callback evidence"),
        "retention": ("work/runtime/information-battle-war-records-20261025-001/war-result-retention-ledger-001.json", "a04abb14cf1100b27f99cd0ed7c00d879303381fa341dff92ffd7289f821379c", "war/result retention ledger"),
        "message": ("work/runtime/information-battle-message-20261025-001/message-lifetime-ledger-001.json", "1affeab5db5f76f0a3350a71596053ec3e0f1b72c1d3394e1e270c63b8fc777f", "message lifetime ledger"),
        "land": ("work/runtime/information-battle-layout-20261025-001/land-message-field-ledger-001.json", "4ecf78cd675e82558ef4935659d0d49544c7d004c80f07971804be42ed16b9cc", "land message field ledger"),
        "result_keys": ("work/runtime/information-battle-layout-20261025-001/result-save-keys-001.json", "02bf98a96cdc04d411d82fbca6c39b0d63b9a691d319bc485864a7c847985ba4", "result save-key inventory"),
        "side_keys": ("work/runtime/information-battle-layout-20261025-001/side-save-keys-001.json", "75594b4629a05c647c767eea23fe95b0c04c852ee0113c573486c87f053a75d3", "side save-key inventory"),
        "unit": ("work/runtime/information-battle-layout-20261025-001/unit-display-ledger-001.json", "20ba4eb0a313bf369c0afba2d79b7541620d932ef70724b105b6282ab0e85d41", "unit display ledger"),
        "scalar": ("work/runtime/information-battle-scalar-writers-20261025-001/scalar-field-writer-001.json", "3bd495ce9575b7f4a3134512f7fb27fd9ad6594632b1afd4026e9a419b574400", "scalar writer ledger"),
    }
    reports: dict[str, dict[str, Any]] = {}
    input_pins: list[dict[str, Any]] = []
    for key, (path, expected_sha, role) in paths.items():
        reports[key], meta = source_record(path, expected_sha, role)
        input_pins.append(meta)

    callback = reports["callback"]
    require(callback.get("status") == "observed", "callback selected report is not observed")
    subject = callback["top_level"]["subject"]["value"]
    require(subject["digest"]["sha256"] == FIXED_EXE_SHA256, "callback selected EXE mismatch")
    callback_source = callback["source"]
    callback_raw_path = ROOT / Path(callback_source["path"])
    require(callback_source["sha256"] == "0da43feb0120230fe0d9e99acb444a996dd5ad89462f3fd2e9dba2a798de6cde", "callback raw SHA pin mismatch")
    require(callback_raw_path.exists() and callback_raw_path.stat().st_size == callback_source["size_bytes"], "callback raw source stat mismatch")
    require(sha256_file(callback_raw_path) == callback_source["sha256"], "callback raw source changed")

    callback_selected_pin = input_pins[0]
    body = callback_body(callback)
    cb_lines = lambda nums: callback_lines(callback, nums)

    retention = reports["retention"]
    callback_src = retention["sources"]["callback"]
    callback_ref = evidence_ref(
        "entry_callback",
        callback_selected_pin["path"],
        callback_selected_pin["sha256"],
        callback_src["evidence_id"],
        callback_src["rva"],
        callback_src["Ghidra_body_inclusive"],
    )
    land_evidence = reports["land"]["evidence"]
    land_ref = evidence_ref(
        "land_field_ledger",
        land_evidence["selected_evidence_path"],
        land_evidence["selected_evidence_sha256"],
        land_evidence["evidence_id"],
        "0x232a80",
        land_evidence["procedure_body"],
    )
    message_sources = reports["message"]["rea_sources"]
    message_refs = {
        name: evidence_ref(
            f"message_{name}",
            item["path"],
            item["sha256"],
            item["evidence_id"],
            item["rva"],
            item["body_inclusive"],
        )
        for name, item in message_sources.items()
    }

    summary_fields = reports["land"]["objects"]["param_2_summary_input"]["fields"]
    summary_by_offset = {item["offset"]: item for item in summary_fields}
    result_input = reports["land"]["objects"]["param_3_result_input"]
    side_selection = reports["land"]["combat_context_not_param2_or_param3"]["side_selection"]
    result_keys = reports["result_keys"]
    side_keys = reports["side_keys"]
    unit = reports["unit"]

    fields: list[dict[str, Any]] = []

    fields.append({
        "field": "combat",
        "entry_presence": "pointer_and_kind_inputs_observed",
        "entry_refs": [
            {**callback_ref, "pseudocode_lines": [123, 124, 126, 128, 129, 131, 133], "expressions": cb_lines([123, 124, 126, 128, 129, 131, 133])},
            {**callback_ref, "pseudocode_lines": [243, 244, 774, 775, 841, 842], "expressions": cb_lines([243, 244, 774, 775, 841, 842])},
        ],
        "later_change": {
            "status": "later_consumed_and_formatted_no_mutation_proven",
            "refs": [land_ref],
            "assessment": "The later land reader separates param_1-side pointers and unit fields; it does not close a stable combat object schema.",
        },
        "direct_owned_copy": {
            "status": "candidate_raw_pointer_snapshot_only",
            "allowed_values": ["param_1 + 0x20", "param_1 + 0x28", "kind branch result"],
            "blockers": ["pointer ownership/deep copy", "thread/reentrancy/lifetime", "ABI/unwind and visibility"],
        },
    })

    fields.append({
        "field": "summary",
        "entry_presence": "summary_pointer_and_control_byte_observed",
        "entry_refs": [{**callback_ref, "pseudocode_lines": [123, 125, 126, 130, 132], "expressions": cb_lines([123, 125, 126, 130, 132])}],
        "later_change": {
            "status": "later_direct_reads_and_branch_dependent_formatter_use",
            "refs": [
                {**land_ref, "pseudocode_lines": sorted({line for item in summary_fields for occ in item.get("occurrences", []) for line in [occ["pseudocode_line"]]})},
            ],
            "field_table": summary_fields,
            "assessment": "The table preserves native offsets and nearby template keys; labels and units remain unresolved.",
        },
        "direct_owned_copy": {
            "status": "conditional_entry_snapshot_candidate",
            "values": ["param_2 + 0x4c at 238620", "param_2 + 0x20..0x48 in later renderers"],
            "blockers": ["238620 itself does not directly read all +0x20..+0x48 fields", "side/meaning/unit are unresolved"],
        },
    })

    fields.append({
        "field": "result",
        "entry_presence": "direct_integer_reads_and_dynamic_downstream_input_observed",
        "entry_refs": [
            {**callback_ref, "pseudocode_lines": [135, 136, 139, 140], "expressions": cb_lines([135, 136, 139, 140])},
            {**callback_ref, "pseudocode_lines": [780, 781, 791, 796, 875, 880, 890, 895], "expressions": cb_lines([780, 781, 791, 796, 875, 880, 890, 895])},
        ],
        "later_change": {
            "status": "later_conditional_field_reads_and_retention",
            "refs": [land_ref, retention_source_ref("retention_d89a80", retention["sources"]["retain"])],
            "result_input_table": result_input,
            "assessment": "The callback reads result-side integers and emits unit-key writes; the later ledger retains only a gated subset and does not prove all results are retained.",
        },
        "direct_owned_copy": {
            "status": "raw_integer_snapshot_candidate_semantics_blocked",
            "values": ["param_3 + 0x64", "param_3 + 0xdc"],
            "blockers": ["kind/side branch", "raw scale and business meaning", "pointer lifetime and safe entry capture"],
        },
    })

    fields.append({
        "field": "kind",
        "entry_presence": "vtable_branch_selector_observed",
        "entry_refs": [{**callback_ref, "pseudocode_lines": [243, 244, 774, 775, 841, 842], "expressions": cb_lines([243, 244, 774, 775, 841, 842])}],
        "later_change": {
            "status": "later_reused_for_land_naval_and_popup_routes",
            "refs": [
                {"source_id": "retention_router", "path": retention["sources"]["router"]["raw"]["path"], "sha256": retention["sources"]["router"]["raw"]["sha256"], "rva": retention["sources"]["router"]["rva"], "evidence_id": retention["sources"]["router"]["evidence_id"], "line_range": [177, 189]},
                {**message_refs["presenter"], "fact_id": "popup_selection_is_explicit"},
            ],
            "assessment": "Branches 1 and 2 are observed; their business enum/name is not proven and no mutation is observed.",
        },
        "direct_owned_copy": {"status": "candidate_branch_result_only", "blockers": ["vtable call contract", "enum semantics", "ABI/thread/reentrancy"]},
    })

    fields.append({
        "field": "province",
        "entry_presence": "not_observed_in_238620_selected_payload",
        "entry_refs": [],
        "later_change": {
            "status": "static_save_key_name_only_no_semantic_mapping",
            "refs": [key_ref("result_save_keys", result_keys, "location")],
            "assessment": "The compiled name location is an inventory label only; the key's runtime vector, type, province identity and relation to this entry are unresolved.",
        },
        "direct_owned_copy": {"status": "none_proved", "blockers": ["no entry field read or runtime value", "no province identity proof"]},
    })

    fields.append({
        "field": "date",
        "entry_presence": "not_observed_as_entry_field",
        "entry_refs": [],
        "later_change": {
            "status": "later_message_date_and_conditional_history_date_static_only",
            "refs": [
                {**message_refs["instance"], "fact_id": "message_records_game_date", "line_range": [54, 58]},
                retention_source_ref("retention_history_date", retention["sources"]["date"], [1, 42]),
            ],
            "assessment": "Message +0x88 and the retained history group's raw date are native construction fields; correspondence to an entry battle date/world generation is unresolved.",
        },
        "direct_owned_copy": {"status": "none_at_entry", "blockers": ["no entry date read", "runtime calendar correlation not observed"]},
    })

    fields.append({
        "field": "sides",
        "entry_presence": "side_pointer_selection_observed",
        "entry_refs": [
            {**callback_ref, "pseudocode_lines": [123, 124, 126, 128, 129, 131, 133], "expressions": cb_lines([123, 124, 126, 128, 129, 131, 133])},
            {"source_id": "land_field_ledger", "path": land_evidence["selected_evidence_path"], "sha256": land_evidence["selected_evidence_sha256"], "rva": "0x232a80", "pseudocode_lines": [84, 85, 86, 87, 89, 91, 93], "expressions": [x["raw_expression"] for x in side_selection["param_1_pointer_candidates"]] + [side_selection["condition_from_param2"]["raw_expression"]]},
        ],
        "later_change": {
            "status": "later_side_context_used_with_label_ambiguity",
            "refs": [land_ref, {**message_refs["consumer"], "fact_id": "consumer_has_drop_and_route_gates"}],
            "assessment": "OUR/ENEMY and selected pointer roles are explicitly unresolved; no player/attacker/defender or visibility mapping is made.",
        },
        "direct_owned_copy": {"status": "raw_pointer_or_snapshot_candidate_blocked", "blockers": ["pointer ownership", "side order", "observer visibility", "reentrancy/lifetime"]},
    })

    fields.append({
        "field": "fullcountry",
        "entry_presence": "not_observed",
        "entry_refs": [],
        "later_change": {
            "status": "static_side_save_key_only",
            "refs": [key_ref("side_save_keys", side_keys, "country")],
            "assessment": "The compiled key name country has unresolved width, scope, runtime override and business semantics.",
        },
        "direct_owned_copy": {"status": "none_proved", "blockers": ["no entry read", "no full-country/observer binding proof"]},
    })

    fields.append({
        "field": "commanderSSO",
        "entry_presence": "not_observed",
        "entry_refs": [],
        "later_change": {
            "status": "static_commander_key_only_no_sso_proof",
            "refs": [key_ref("side_save_keys", side_keys, "commander")],
            "assessment": "The compiled commander key is not evidence of a commander object, string, SSO identity, side or runtime value.",
        },
        "direct_owned_copy": {"status": "none_proved", "blockers": ["no entry read", "SSO and commander lifetime not evidenced"]},
    })

    unit_templates = {"land": unit_template_refs(unit, "land"), "naval": unit_template_refs(unit, "naval")}
    fields.append({
        "field": "units",
        "entry_presence": "unit_key_writes_from_entry_path_observed",
        "entry_refs": [{**callback_ref, "pseudocode_lines": [774, 780, 781, 795, 796, 811, 812, 848, 849, 864, 865, 879, 880, 894, 895], "expressions": cb_lines([774, 780, 781, 795, 796, 811, 812, 848, 849, 864, 865, 879, 880, 894, 895])}],
        "later_change": {
            "status": "later_formatter_reads_and_transforms_static_unit_fields",
            "refs": [
                {"source_id": "unit_display_ledger", "path": "work/runtime/information-battle-layout-20261025-001/unit-display-ledger-001.json", "sha256": "20ba4eb0a313bf369c0afba2d79b7541620d932ef70724b105b6282ab0e85d41", "land_template_count": len(unit_templates["land"]), "naval_template_count": len(unit_templates["naval"]), "land_templates": unit_templates["land"], "naval_templates": unit_templates["naval"]},
                {**land_ref, "pseudocode_lines": [402, 403, 422, 423, 442, 443, 462, 463, 497, 498, 532, 533, 550, 551]},
            ],
            "assessment": "Unit labels, /1000 and opaque formatter calls are preserved mechanically; side/player meaning, unit total semantics and rounding remain unresolved.",
        },
        "direct_owned_copy": {"status": "raw_key_and_integer_candidate_only", "blockers": ["unit object pointers", "kind/side branch", "raw scale/rounding", "ownership/lifetime"]},
    })

    fields.append({
        "field": "losses",
        "entry_presence": "raw_loss_like_integer_inputs_and_loss_keys_observed",
        "entry_refs": [{**callback_ref, "pseudocode_lines": [780, 781, 795, 796, 811, 812, 848, 849, 864, 865, 879, 880, 894, 895], "expressions": cb_lines([780, 781, 795, 796, 811, 812, 848, 849, 864, 865, 879, 880, 894, 895])}],
        "later_change": {
            "status": "later_summary_and_static_save_key_use_without_semantic_closure",
            "refs": [
                {**land_ref, "pseudocode_lines": [1130, 1138, 1146, 1154, 1187, 1195, 1203, 1211, 1226, 1234, 1242, 1250, 1336, 1344, 1352, 1360]},
                key_ref("side_save_keys", side_keys, "losses"),
            ],
            "assessment": "The same summary offsets appear under branch-dependent US/THEIR keys; no loss sign, side, unit or scale is assigned.",
        },
        "direct_owned_copy": {"status": "raw_integer_snapshot_candidate_semantics_blocked", "values": ["param_3 + 0x64", "param_3 + 0xdc", "param_2 + 0x3c..0x48 in later reader"], "blockers": ["branch-dependent mapping", "scale/sign", "pointer lifetime"]},
    })

    fields.append({
        "field": "aux",
        "entry_presence": "not_observed_in_scoped_selected_payloads",
        "entry_refs": [],
        "later_change": {"status": "not_found_in_scoped_ledgers", "refs": [], "assessment": "This is a bounded survey result, not a global absence claim."},
        "direct_owned_copy": {"status": "none_proved", "blockers": ["no selected source field or runtime value"]},
    })

    fields.append({
        "field": "war_goal",
        "entry_presence": "not_directly_observed_at_238620; conditional_result_offsets_are_exposed_by_later_reader",
        "entry_refs": [{**land_ref, "pseudocode_lines": [1113, 1114, 1115, 1116, 1117], "expressions": ["Result offset selection is 0xfc by default and 0x84 when param_3[0x108] is nonzero; 238620 itself has no direct +0x84/+0xfc expression in the selected pseudocode."]}],
        "later_change": {
            "status": "conditional_pre_entry_computation_and_static_key_name",
            "refs": [
                {"source_id": "retention_score_1dd3c0", "path": retention["sources"]["score"]["selected"]["path"], "sha256": retention["sources"]["score"]["selected"]["sha256"], "evidence_id": retention["sources"]["score"]["evidence_id"], "rva": retention["sources"]["score"]["rva"], "line_range": [21, 34, 89, 93]},
                key_ref("side_save_keys", side_keys, "war_goal"),
            ],
            "assessment": "1DD3C0 computes result+0x84/+0xfc under a retained-path condition using context virtual rules/country modifier and /1000 arithmetic; the ledger explicitly says this is not a war-ID binding/getter.",
        },
        "direct_owned_copy": {"status": "raw_offset_candidate_not_semantic_war_goal", "values": ["result + 0x84 (conditional in later reader)", "result + 0xfc (default in later reader)"], "blockers": ["not a direct 238620 read", "conditional pre-entry path", "war-goal semantics and runtime key override unresolved"]},
    })

    # Make the chronology answer explicit for reviewers.  These flags refer to
    # the 238620 entry object's fields, not to unrelated message/history
    # objects that are constructed later.
    entry_mutation_notes = {
        "combat": "not_observed",
        "summary": "not_observed",
        "result": "not_observed_as_entry_field_mutation",
        "kind": "not_observed",
        "province": "not_applicable_no_entry_field",
        "date": "not_observed_for_entry; separate message/history date assignments exist",
        "sides": "not_observed",
        "fullcountry": "not_applicable_no_entry_field",
        "commanderSSO": "not_applicable_no_entry_field",
        "units": "later_reads_and_formatter_transforms_observed; entry_object_mutation_not_proven",
        "losses": "not_observed_as_entry_field_mutation",
        "aux": "not_observed_in_scoped_sources",
        "war_goal": "conditional_pre_entry_result_writes_observed_at_1dd3c0; not a later getter",
    }
    for item in fields:
        item["later_change"]["entry_object_change"] = entry_mutation_notes[item["field"]]

    return {
        "schema": "information_battle_entry_payload_survey_v1",
        "status": "passed_static_mechanical_survey",
        "target": {"build": FIXED_BUILD, "executable_sha256": FIXED_EXE_SHA256, "static_image_base": STATIC_IMAGE_BASE, "address_convention": "RVA in findings; static VA and Ghidra inclusive ranges are retained separately"},
        "scope": {
            "read_only": True,
            "game_access": False,
            "rea_query": False,
            "native_function_invoked": False,
            "production_modified": False,
            "runtime_observed": False,
            "visibility_inferred": False,
            "stable_battle_or_war_id_inferred": False,
            "whole_large_raw_loaded": False,
            "survey_basis": "existing bounded selected reports and frozen ledgers only",
        },
        "inputs": input_pins,
        "fixed_build_checks": fixed_build_checks(reports),
        "entry": {
            "rva": "0x238620",
            "static_va": "0x140238620",
            "evidence_id": callback_src["evidence_id"],
            "selected_report": callback_selected_pin,
            "raw_source": {
                "path": callback_source["path"],
                "bytes": callback_source["size_bytes"],
                "sha256": callback_source["sha256"],
                "raw_json_loaded": False,
                "bounded_selected_values_used": ["procedure", "pseudocode", "assembly", "callees"],
                "integrity": callback["parser"]["integrity"],
            },
            "procedure": body,
            "argument_roles": {
                "param_1": "combat-like pointer input; router/land ledgers use side-pointer and kind branches, not a closed native type",
                "param_2": "summary-like pointer input; only +0x4c is read directly by 238620, while the land reader records additional summary offsets",
                "param_3": "result-like pointer input; 238620 directly reads +0x64/+0xdc in kind branches; later readers select additional offsets",
                "role_provenance": "existing retention router and land-message ledgers; labels are not ABI or business-semantic proof",
            },
            "entry_observations": [
                {"label": "side_selection_and_result_values", "lines": cb_lines([123, 124, 126, 128, 129, 131, 133, 135, 136, 139, 140])},
                {"label": "kind_branch_and_unit_key_writes", "lines": cb_lines([243, 244, 774, 775, 780, 781, 795, 796, 811, 812, 841, 842, 848, 849, 864, 865, 879, 880, 894, 895])},
            ],
        },
        "field_inventory": fields,
        "later_source_provenance": {
            "retention": {"path": paths["retention"][0], "sha256": paths["retention"][1], "status": retention.get("status", retention.get("schema")), "scope": retention["scope"]},
            "message": {"path": paths["message"][0], "sha256": paths["message"][1], "status": reports["message"]["status"], "runtime_observed": reports["message"]["runtime_observed"], "native_game_functions_called": reports["message"]["native_game_functions_called"]},
            "layout_land": {"path": paths["land"][0], "sha256": paths["land"][1], "status": reports["land"]["status"], "scope": reports["land"]["scope"]},
            "layout_result_keys": {"path": paths["result_keys"][0], "sha256": paths["result_keys"][1], "status": reports["result_keys"]["status"], "scope": reports["result_keys"]["scope"]},
            "layout_side_keys": {"path": paths["side_keys"][0], "sha256": paths["side_keys"][1], "status": reports["side_keys"]["status"], "scope": reports["side_keys"]["scope"]},
            "layout_unit": {"path": paths["unit"][0], "sha256": paths["unit"][1], "status": reports["unit"]["status"], "runtime_observed": reports["unit"]["runtime_observed"]},
            "scalar": {"path": paths["scalar"][0], "sha256": paths["scalar"][1], "status": reports["scalar"]["status"], "runtime_observed": reports["scalar"]["runtime_observed"]},
        },
        "ownership_candidates": [
            {"name": "entry_param3_raw_0x64_0xdc", "status": "candidate_raw_snapshot", "source": "entry_callback", "reason": "238620 directly reads two 4-byte result-side values before writing unit-key values", "not_semantic": True},
            {"name": "entry_param2_control_0x4c", "status": "candidate_raw_snapshot", "source": "entry_callback", "reason": "238620 directly reads the summary control byte", "not_semantic": True},
            {"name": "entry_param1_side_pointers", "status": "candidate_pointer_snapshot_only", "source": "entry_callback", "reason": "pointer selection is observed; deep ownership and side identity are not", "not_semantic": True},
            {"name": "downstream_param2_summary_0x20_to_0x48", "status": "downstream_snapshot_candidate", "source": "land_field_ledger", "reason": "232a80 has exact raw reads, but these are not direct 238620 reads and semantic mapping is unresolved", "not_semantic": True},
            {"name": "result_0x84_0xfc", "status": "blocked_semantic_candidate", "source": "retention_score_1dd3c0", "reason": "conditional pre-entry computed offsets; cannot be promoted as war_goal getter", "not_semantic": True},
        ],
        "unresolved_conditions": [
            "238620 entry ABI, unwind metadata, thread affinity, reentrancy and safe hook/copy implementation are not validated.",
            "Pointer/object lifetime and deep ownership for combat, summary, result and message containers are unresolved.",
            "Retention is a gated native subset; below-threshold/non-retained results are outside that history path.",
            "Kind branches 1/2, OUR/ENEMY/US/THEIR labels, attacker/defender ordering and observer visibility are not mapped.",
            "Province/location, full-country, commander/SSO, auxiliary fields and stable battle/war IDs have no proved entry mapping.",
            "Raw integer scales, signedness, rounding, unit totals and loss semantics remain unresolved.",
            "The static result-save and side-save key inventories are defaults only; runtime key-vector overrides were not read.",
            "No natural event, game call, production hook, or source-to-subscription payload has been installed or accepted.",
        ],
        "conclusion": {
            "mechanical_result": "238620 receives combat-like, summary-like and result-like inputs and exposes bounded raw reads/key writes; later ledgers add static readers/formatters and retention paths.",
            "owned_copy_boundary": "Only a future validated entry snapshot may copy the listed raw bytes/pointers. No field is promoted to a public battle payload by this survey.",
            "root_action": "Use these exact refs to choose the capture contract and separately close lifetime, visibility, identity, scale and complete-event coverage.",
            "production_authorized": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    report = make_report()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    require(len(content) <= MAX_OUTPUT_BYTES, f"output exceeds bound: {len(content)}")
    output.write_bytes(content)
    print(json.dumps({"path": rel(output), "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(), "status": report["status"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
