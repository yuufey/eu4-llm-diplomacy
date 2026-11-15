"""Join archived bounded evidence for the N03 active military-modifier gap.

This is a read-only evidence join.  It does not open the game, invoke native
code, run RPM/REA, disassemble the PE, or import a production reader.  The
existing country modifier reports are deliberately retained as numeric-cache
evidence only; the report is exclusive so a later source revision gets a new
stage/name instead of silently replacing this conclusion.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = (
    ROOT
    / "work"
    / "runtime"
    / "information-military-modifiers-20261027-001"
    / "active-military-modifiers-source-001.json"
)
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = "0x140000000"
MAX_JSON_BYTES = 2_000_000
MAX_PIN_BYTES = 10_000_000


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def _sha256(path: Path, *, limit: int = MAX_PIN_BYTES) -> tuple[str, int]:
    size = path.stat().st_size
    if size <= 0 or size > limit:
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
    return digest.hexdigest(), size


def _load_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise RuntimeError(f"json_size_out_of_bound:{_relative(path)}")
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise RuntimeError(f"json_root_not_object:{_relative(path)}")
    return value


def _pin(path_text: str, role: str, *, expected_sha256: str | None = None) -> dict[str, Any]:
    path = ROOT / path_text
    digest, size = _sha256(path)
    if expected_sha256 is not None and digest != expected_sha256:
        raise RuntimeError(f"sha_mismatch:{path_text}:{digest}:{expected_sha256}")
    return {"path": path_text, "sha256": digest, "bytes": size, "role": role}


def _record_summary(record: dict[str, Any], semantic: str) -> dict[str, Any]:
    body = record.get("rea_body_range") or {}
    ranges = []
    for item in body.get("ranges") or []:
        ranges.append(
            {
                "rva_start": item.get("rva_start"),
                "rva_end_inclusive": item.get("rva_end_inclusive"),
                "rva_end_exclusive": item.get("rva_end_exclusive"),
                "va_start": item.get("va_start"),
                "va_end_exclusive": item.get("va_end_exclusive"),
            }
        )
    return {
        "name": record.get("name"),
        "evidence_id": record.get("evidence_id"),
        "evidence_path": record.get("evidence_path"),
        "evidence_sha256": record.get("evidence_sha256"),
        "evidence_bytes": record.get("evidence_bytes"),
        "procedure": record.get("procedure"),
        "body_range": {
            "rva_start": body.get("rva_start"),
            "rva_end_inclusive": body.get("rva_end_inclusive"),
            "rva_end_exclusive": body.get("rva_end_exclusive"),
            "va_start": body.get("va_start"),
            "va_end_exclusive": body.get("va_end_exclusive"),
            "span_bytes": body.get("span_bytes"),
            "total_body_bytes": body.get("total_body_bytes"),
            "end_semantics": body.get("end_semantics"),
            "ranges": ranges,
        },
        "semantic_boundary": semantic,
    }


def _caller_summary(caller_report: dict[str, Any]) -> list[dict[str, Any]]:
    wanted = {"0x3b47b0", "0x6dffa0", "0xc0da30", "0xfebfb0"}
    result: list[dict[str, Any]] = []
    for item in caller_report.get("direct_callers", []):
        if item.get("rva") not in wanted:
            continue
        sites = []
        for site in item.get("call_sites", []):
            call_site = site.get("call_site") or {}
            target = site.get("target") or {}
            sites.append(
                {
                    "call_site_rva": call_site.get("rva"),
                    "target_rva": target.get("rva"),
                    "reference_kind": (site.get("reference_kind") or {}).get("type"),
                }
            )
        result.append(
            {
                "owner_rva": item.get("rva"),
                "body_ranges": item.get("body", {}).get("ranges", []),
                "call_sites": sites,
            }
        )
    return result


def _writer_summary(widget: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    writers = widget.get("numeric_record_writers") or {}
    for side in ("land", "naval"):
        data = writers.get(side) or {}
        window = data.get("bounded_window") or {}
        result[side] = {
            "entry_rva": (data.get("function") or {}).get("entry_rva"),
            "end_rva_exclusive": (data.get("function") or {}).get("end_rva_exclusive"),
            "bounded_window": {
                "start": window.get("start"),
                "end_exclusive": window.get("end_exclusive"),
                "byte_length": window.get("byte_length"),
                "bytes_sha256": window.get("bytes_sha256"),
            },
            "case_instructions": data.get("case_instructions", []),
            "semantic_boundary": "typed current-morale numeric-record writer; not an active modifier-item enumerator",
        }
    return result


def build_report() -> dict[str, Any]:
    prior_path = ROOT / "work/runtime/information-military-professionalism-20261027-001/next-military-modifiers-source-001.json"
    unity_path = ROOT / "work/runtime/information-religious-unity-20261025-001/effective-unity-paths-001.json"
    callers_path = ROOT / "work/runtime/information-religious-unity-20261025-001/caller-candidates-001.json"
    widget_path = ROOT / "work/runtime/information-military-effective-20261027-001/morale-widget-source-001.json"
    cache_window_path = ROOT / "work/runtime/information-military-effective-20261027-001/discipline-container-code-001.json"
    prior = _load_json(prior_path)
    unity = _load_json(unity_path)
    callers = _load_json(callers_path)
    widget = _load_json(widget_path)
    cache_window = _load_json(cache_window_path)

    if prior.get("target", {}).get("executable_sha256") != EXE_SHA256:
        raise RuntimeError("prior_exe_sha_mismatch")
    if unity.get("exe_sha256") != EXE_SHA256:
        raise RuntimeError("unity_index_exe_sha_mismatch")
    if (callers.get("source_evidence") or {}).get("exe_sha256") != EXE_SHA256:
        raise RuntimeError("caller_index_exe_sha_mismatch")
    if widget.get("target", {}).get("exe_sha256") != EXE_SHA256:
        raise RuntimeError("morale_widget_exe_sha_mismatch")
    if cache_window.get("binary_sha256") != EXE_SHA256:
        raise RuntimeError("cache_window_exe_sha_mismatch")

    by_name = {item.get("name"): item for item in unity.get("source_records", [])}
    required_names = {
        "country_unity_wrapper": "country pointer +0x28c0 is forwarded into the cache getter; no active-item traversal",
        "country_modifier_cache": "embedded dense/sparse keyed numeric cache selector; sparse count is pair count, not active-item count",
        "modifier_value": "single keyed value read from dense/sparse cache, with optional processor callback",
        "modifier_boolean": "single keyed flag read with optional processor/type remap",
        "effective_unity_getter": "downstream scalar getter used by the prior UI example; not an item-list source",
    }
    known_paths: dict[str, Any] = {}
    for name, semantic in required_names.items():
        if name not in by_name:
            raise RuntimeError(f"missing_archived_source_record:{name}")
        known_paths[name] = _record_summary(by_name[name], semantic)

    cache_w = (cache_window.get("windows") or [None])[0]
    if not isinstance(cache_w, dict):
        raise RuntimeError("cache_window_missing")
    cache_loop = {
        "start_rva": cache_w.get("start_rva"),
        "end_rva_exclusive": cache_w.get("end_rva_exclusive"),
        "start_va": cache_w.get("start_va"),
        "end_va_exclusive": cache_w.get("end_va_exclusive"),
        "bytes_sha256": cache_w.get("bytes_sha256"),
        "byte_length": len(bytes.fromhex(cache_w.get("bytes_hex", ""))),
        "instruction_anchors": [
            {"rva": item.get("rva"), "bytes": item.get("bytes"), "mnemonic": item.get("mnemonic"), "operands": item.get("operands")}
            for item in cache_w.get("instructions", [])
            if item.get("rva") in {"0x3be5fe", "0x3be601", "0x3be609", "0x3be615", "0x3be620", "0x3be629", "0x3be62c", "0x3be630", "0x3be633", "0x3be63c"}
        ],
        "semantic_boundary": "bounded keyed-cache loop; it proves numeric keyed storage only, not current active modifier instances",
    }

    artifacts = [
        _pin(_relative(prior_path), "prior N03 military-modifier source synthesis"),
        _pin(_relative(unity_path), "archived same-SHA country-cache and getter paths"),
        _pin(_relative(callers_path), "archived callers of the cache getter; negative control for active-list search"),
        _pin(_relative(widget_path), "archived military numeric writers; negative control for active-list search"),
        _pin(_relative(cache_window_path), "bounded keyed-cache window"),
        _pin("bridge/information/profiles/military-effective-memory-1374-v2.json", "numeric cache profile only"),
    ]
    for name in required_names:
        rec = by_name[name]
        artifacts.append(
            _pin(
                rec["evidence_path"],
                f"archived REA evidence for {name}; hashed by bounded streaming read",
                expected_sha256=rec.get("evidence_sha256"),
            )
        )

    prior_reusable = prior.get("reusable_sources", {})
    prior_decision = prior.get("decision", {})
    return {
        "report_id": "active-military-modifiers-source-001",
        "schema": "information_active_military_modifiers_static_gap.v1",
        "status": "bounded_existing_evidence_gap_closed_only",
        "created_by": "work/research_information_active_military_modifiers_001.py",
        "research_boundary": {
            "runtime_or_RPM": False,
            "game_or_native_calls": 0,
            "new_REA": False,
            "whole_image_disassembly": False,
            "large_REA_payload_loaded": False,
            "json_load_limit_bytes": MAX_JSON_BYTES,
            "hash_stream_limit_bytes": MAX_PIN_BYTES,
            "note": "Only archived reports and bounded windows were joined. The 7.2 MB country-cache REA evidence was hashed in streaming mode and not parsed into memory.",
        },
        "target": {
            "game_version": "1.37.4",
            "executable_sha256": EXE_SHA256,
            "image_base": IMAGE_BASE,
            "address_rule": "RVA is relative to the static image base; runtime VA requires the current module base.",
            "observer_scope": "Existing production scope is country/FRA; this report contains no runtime values.",
        },
        "catalog_requirements": {
            "N03_military_modifiers": {
                "required_projection": ["modifier_id", "name", "description", "source", "target", "effects"],
                "required_state": ["active", "start_date", "end_date", "remaining_days", "removal_conditions"],
                "selection_rule": "No fixed hand-picked IDs and no dense-cache dump may stand in for the active collection.",
            },
            "related_N07_N09": "Source/target, lifecycle and effect status remain separate from definition metadata and final morale/discipline scalars.",
        },
        "closed_static_entries": {
            "country_wrapper_and_cache": known_paths["country_unity_wrapper"],
            "country_modifier_cache_selector": known_paths["country_modifier_cache"],
            "numeric_value_reader": known_paths["modifier_value"],
            "boolean_value_reader": known_paths["modifier_boolean"],
            "downstream_scalar_getter": known_paths["effective_unity_getter"],
            "keyed_cache_loop_window": cache_loop,
            "global_modifier_database_layout": {
                "global_rva": "0x2358060",
                "static_va": "0x142358060",
                "record_stride": "0x60",
                "known_offsets": {"processor": "0x40", "resolved_type": "0x54", "flags": "0x5c"},
                "semantic_boundary": "Indexed global processor/flag layout only; no verified ID-to-name definition table or active-country row was established.",
            },
        },
        "known_country_cache_shape": {
            "country_cache_argument": "country+0x28c0",
            "embedded_modifier_object": "country+0x28d0 (cache helper result +0x8 in normal path)",
            "dense_flag": "object+0x10",
            "values_pointer": "object+0x58",
            "sparse_count": "object+0x64",
            "sparse_entry": "{modifier_key,value} with 8-byte stride; first matching key",
            "boundary": "This is a keyed numeric cache. sparse_count is not a count of active modifier instances, and values have no source/date/name fields.",
        },
        "military_numeric_negative_control": {
            "writers": _writer_summary(widget),
            "interpretation": "The archived 0x119fb40/0x119ffd0 and 0x119ffd0/0x11a0141 branches write current morale record tag=9, kind=2 and copy +0x9874/+0x987c. They establish a scalar record path, not a modifier-instance iterator.",
        },
        "cache_getter_callers_negative_control": {
            "target_rva": "0x3b4530",
            "callers": _caller_summary(callers),
            "interpretation": "These archived callers feed the cached scalar getter (including a religious-unity UI path). They are retained as exact entry/call-site pins but do not prove a military active-modifier list.",
        },
        "active_instance_contract_audit": {
            "status": "not_closed",
            "country_owner": {"status": "not_proven", "known": "Only the country cache argument/object is proven; no active-list owner/container pointer is present."},
            "container_head_tail_count": {"status": "not_proven", "known": "No begin/end/head/tail/count fields for active instances were found in the selected bounded evidence."},
            "iterator": {"status": "not_proven", "known": "The only loop is over keyed sparse numeric pairs; it cannot be treated as an active-instance iterator."},
            "definition": {"status": "not_proven", "known": "Global +0x40/+0x54/+0x5c offsets expose processor/resolved-type/flags only; name/key/category mapping is absent."},
            "provenance": {"status": "not_proven", "fields": ["source", "target", "source_type", "target_scope"]},
            "lifecycle": {"status": "not_proven", "fields": ["start_date", "end_date", "remaining_days", "duration_type", "removal_conditions"]},
            "effects": {"status": "not_proven", "fields": ["effect_rows", "effective_status", "source_breakdown"]},
        },
        "minimal_next_step": {
            "status": "bounded_entry_required",
            "do_not_reuse_as_list": ["country+0x28d0 dense/sparse cache", "sparse_count +0x64", "global processor slot 0x77", "religious-unity key 0xa8", "morale/discipline numeric records", "dense 697-definition count"],
            "required_entry": "A verified current-country modifier-panel/serializer caller that carries the country pointer into a list/object traversal; decode only the adjacent head/begin/end/count and one node load, then separately pin the definition lookup.",
            "exact_known_cache_call_sites": ["0x3b47f0", "0x6dffd2", "0xc0da83", "0xfec7ff"],
            "call_site_semantics": "These are known cache-getter call sites from the archived index and are not asserted to be the missing active-list entry; a future search must identify a military modifier UI/serializer caller before using any of them.",
            "must_pin": ["country/province/local owner", "head/tail/count or begin/end", "node stride and fields", "definition ID/name/key/category", "source/target", "start/end/removal", "effect units"],
        },
        "decision": {
            "publishable_N03_military_modifiers": False,
            "minimal_useful_active_list": None,
            "reusable_lower_level": "Keyed numeric country cache and global processor/flag layout may be reused only as separately guarded inputs.",
            "reason": [
                "The selected same-SHA evidence proves a country-owned numeric cache, not an active modifier-instance collection.",
                "No owner/list head/iterator/node layout for active instances is closed.",
                "No verified definition name/key/category mapping or source/target/lifecycle/effect rows is present.",
                "Promoting sparse entries, selected discipline/unity keys, or morale/discipline records would silently change N03 semantics.",
            ],
            "prior_report_decision_preserved": prior_decision,
        },
        "source_artifacts": artifacts,
    }


def write_report() -> Path:
    if REPORT.exists():
        raise FileExistsError(f"exclusive_output_exists:{_relative(REPORT)}")
    report = build_report()
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    with REPORT.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return REPORT


if __name__ == "__main__":
    print(write_report())
