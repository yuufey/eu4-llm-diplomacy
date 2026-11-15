"""Offline, bounded join of private gate diagnostics to committed wire6 battles.

This operator audit never opens a game process, starts a service, writes a
request, repairs a file, or upgrades B04 visibility/completeness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from work.information_battle_native_text_wire import decode

MAX_TRACE_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 8192
MAX_RECORDS = 1024
MAX_PAYLOAD_BYTES = 1024 * 1024
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def integer(value, low=0, high=(1 << 64)-1):
    require(type(value) is int and low <= value <= high, "integer_out_of_bounds")
    return value


def decimal(value, low=0):
    require(isinstance(value, str) and DECIMAL.fullmatch(value), "noncanonical_decimal")
    return integer(int(value), low)


def hex_ref(value):
    require(isinstance(value, str) and HEX16.fullmatch(value), "invalid_fullref_hex")
    return int(value, 16)


def _pairs(items):
    output = {}
    for key, value in items:
        require(key not in output, "duplicate_json_key")
        output[key] = value
    return output


def read_json(path):
    require(path.is_file() and 0 < path.stat().st_size <= MAX_PAYLOAD_BYTES, "json_size_out_of_bounds")
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs)
    require(isinstance(value, dict), "json_object_required")
    return value


def pin(path):
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns), "file_changed_while_hashing")
    return {"path": str(path.resolve()), "bytes": before.st_size, "sha256": digest.hexdigest()}


def read_trace(path):
    require(path.is_file() and 0 < path.stat().st_size <= MAX_TRACE_BYTES, "trace_size_out_of_bounds")
    rows = []
    with path.open("rb") as stream:
        while True:
            line = stream.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            require(len(line) <= MAX_LINE_BYTES and line.endswith(b"\n") and not line.endswith(b"\r\n"), "trace_line_not_complete_LF")
            value = json.loads(line.decode("ascii"), object_pairs_hook=_pairs)
            require(isinstance(value, dict), "trace_object_required")
            rows.append(value)
            require(len(rows) <= MAX_RECORDS, "too_many_trace_records")
    return rows


def _sample(value):
    require(isinstance(value, dict), "sample_object_required")
    for key, maximum in (("status", 2), ("failure", 8), ("kind", 2),
                         ("current_country_state", 1), ("default_ref_state", 1),
                         ("alternate_ref_state", 1), ("selected_ref_state", 1),
                         ("land_enable_state", 1), ("registry_state", 2),
                         ("slot_state", 2), ("combat_state", 2),
                         ("mode", 255), ("alternate_flag", 255), ("land_enable_raw", 255),
                         ("read_calls", 16), ("read_bytes", 128)):
        integer(value.get(key), 0, maximum)
    for key in ("equals_current_combat_known", "equals_current_combat", "ui_override_known", "ui_override_value"):
        require(type(value.get(key)) is bool, "noncanonical_sample_boolean")
    refs = {key: hex_ref(value.get(key)) for key in ("default_ref", "alternate_ref", "selected_ref")}
    raw_hex = value.get("current_country_raw")
    require(isinstance(raw_hex, str) and re.fullmatch(r"[0-9a-f]{32}", raw_hex), "invalid_current_country_span")
    raw = bytes.fromhex(raw_hex)
    if value["current_country_state"] == 1:
        require(value["mode"] == raw[6] and value["alternate_flag"] == raw[15], "selector_raw_fields_mismatch")
        require(value["default_ref_state"] == value["alternate_ref_state"] == value["selected_ref_state"] == 1,
                "observed_selector_missing_ref_state")
        require(refs["default_ref"] == int.from_bytes(raw[:8], "little")
                and refs["alternate_ref"] == int.from_bytes(raw[8:], "little"), "selector_raw_refs_mismatch")
        selected = refs["alternate_ref"] if raw[6] == 7 and raw[15] else refs["default_ref"]
        require(refs["selected_ref"] == selected, "selector_rule_mismatch")
    else:
        require(not any(raw) and all(value[f"{key}_state"] == 0 and refs[key] == 0 for key in refs),
                "unknown_selector_contains_values")
    if value["ui_override_value"]:
        require(value["ui_override_known"] and value["slot_state"] == value["combat_state"] == 2
                and value["equals_current_combat_known"] and value["equals_current_combat"], "override_true_without_inputs")
        require(value["kind"] != 1 or (value["land_enable_state"] == 1 and value["land_enable_raw"] != 0),
                "land_override_without_enable")
    return value


def audit_record(trace, decoded, expected):
    require(trace.get("schema") == "EU4-BATTLE-GATE-TRACE/1", "trace_schema_mismatch")
    for key in ("pid", "creation_filetime", "dll_sha256", "installation", "generation"):
        require(trace.get(key) == expected[key], f"trace_identity_mismatch:{key}")
    sequence = decimal(trace.get("sequence"), 1)
    observation = decoded.get("observation", {})
    require(observation.get("sequence") == sequence, "trace_payload_sequence_mismatch")
    require(trace.get("native_date") == observation.get("result", {}).get("raw_date"), "trace_payload_date_mismatch")
    require(decoded.get("wire6", {}).get("version") == 6, "wire6_required")
    for key in ("scope_completed", "scope_ambiguous", "counter_overflow", "observation_complete",
                "scope_guards_before", "scope_guards_after"):
        require(type(trace.get(key)) is bool, "noncanonical_trace_boolean")
    drops = decimal(trace.get("observation_drops"))
    complete = trace["scope_completed"] and not trace["scope_ambiguous"] and not trace["counter_overflow"] and drops == 0
    require(trace["observation_complete"] == complete, "observation_complete_overclaim")
    for key in ("passed_marker_candidates", "passed_marker_accepted", "message_entries", "message_copy_attempts",
                "cleanup_entries", "line1_entries", "marker_reject_mask", "message_reject_mask",
                "line1_reject_mask", "cleanup_reject_mask", "last_marker_return_rva", "last_message_return_rva"):
        integer(trace.get(key), 0, (1 << 32)-1)
    if "router_return_rva" in trace:
        integer(trace["router_return_rva"], 0, (1 << 32)-1)
    require(trace["passed_marker_accepted"] <= trace["passed_marker_candidates"], "accepted_more_than_candidate_markers")
    if complete:
        require(trace["message_copy_attempts"] <= trace["message_entries"], "copy_without_message_entry")
    mask = integer(trace.get("sample_mask"), 0, 15)
    samples = trace.get("samples")
    require(isinstance(samples, list) and len(samples) == 4, "four_stage_samples_required")
    for index, sample in enumerate(samples):
        require(bool(mask & (1 << index)) == (sample is not None), "sample_mask_mismatch")
        if sample is not None:
            _sample(sample)
    context = decoded.get("context") if decoded.get("context_present") else None
    require(trace.get("kind") == ("land" if context and context["kind"] == 1 else "naval" if context else "unknown"),
            "trace_payload_kind_mismatch")
    if context:
        require(context["physical_player_full_ref"] == expected["physical_ref"], "physical_player_changed")
        for sample in samples:
            if sample is not None and sample["default_ref_state"] == 1:
                require(hex_ref(sample["default_ref"]) == expected["physical_ref"], "physical_player_changed_inside_scope")
    refs = [side["participants"]["full_refs"] for side in context["sides"]] if context else []
    observer_participated = any(expected["observer_ref"] in side for side in refs)
    result = "unresolved_incomplete_scope_observation"
    if complete and context and not (trace["scope_guards_before"] and trace["scope_guards_after"]):
        result = "unresolved_scope_guard_continuity"
    elif complete and context:
        if trace["passed_marker_candidates"] and (trace["marker_reject_mask"] or not trace["passed_marker_accepted"]):
            result = "post_gate_call_seen_scope_binding_rejected"
        elif trace["passed_marker_accepted"]:
            result = "native_client_message_gate_passed"
        elif trace["cleanup_entries"] and not trace["cleanup_reject_mask"] and samples[2] is not None:
            result = "post_gate_call_not_reached_before_formatter_cleanup"
        else:
            result = "unresolved_formatter_completion_binding"
        if trace["message_entries"]:
            result = ("message_entry_seen_copy_attempted" if trace["message_copy_attempts"]
                      else "message_entry_seen_copy_filter_rejected" if trace["message_reject_mask"]
                      else "message_entry_seen_copy_not_attempted_reason_unresolved")
    fields = decoded.get("native_text", {}).get("text_fields", {})
    line1 = fields.get("line1_text", {})
    return {"sequence": sequence, "native_date": trace["native_date"], "kind": trace["kind"],
            "observer_participated": observer_participated, "physical_player_full_ref": f"{expected['physical_ref']:016x}",
            "diagnosis": result, "observation_complete": complete, "trace": trace,
            "native_line1_state": line1.get("state", "unknown"),
            "full_b04_complete": False, "visibility_verified": False}


def run(installation_path, stream_path, trace_path, output, manifest_sha, dll_sha):
    require(not output.exists(), "output_must_be_new")
    require(SHA.fullmatch(manifest_sha) and SHA.fullmatch(dll_sha), "external_sha256_required")
    installation = read_json(installation_path)
    directory = installation_path.resolve().parent
    manifest_path = directory / "build-manifest.json"
    manifest = read_json(manifest_path)
    require(pin(manifest_path)["sha256"] == manifest_sha and manifest.get("version") == 32, "manifest_pin_or_version_mismatch")
    require(manifest.get("information_battle_gate_trace") is True, "gate_trace_capability_missing")
    dll_path = directory / "eu4_bridge_diplomacy_observer_v32.dll"
    require(pin(dll_path)["sha256"] == dll_sha == installation.get("dll_sha256"), "dll_pin_mismatch")
    binding = read_json(directory / "information-battle-binding.json")
    stream = read_json(stream_path)
    stream_binding = stream.get("binding", {})
    expected = {"pid": integer(installation.get("pid"), 1, (1 << 32)-1),
                "creation_filetime": str(integer(installation.get("creation_filetime"), 1)),
                "dll_sha256": dll_sha, "installation": f"{int(binding['installation']):016x}",
                "generation": f"{int(binding['generation']):016x}",
                "physical_ref": hex_ref(binding["player_ref"]), "observer_ref": hex_ref(stream_binding.get("observer_ref"))}
    require(expected["physical_ref"].to_bytes(8, "little")[:3] == b"POR"
            and expected["observer_ref"].to_bytes(8, "little")[:3] == b"FRA"
            and expected["physical_ref"] != expected["observer_ref"], "POR_player_and_nonplayer_FRA_required")
    require(binding.get("pid") == expected["pid"] and str(binding.get("creation_filetime")) == expected["creation_filetime"]
            and binding.get("session_id") == installation.get("session_id")
            and binding.get("dll_sha256") == dll_sha, "native_binding_mismatch")
    require(all(stream_binding.get(key) == expected[key] for key in ("installation", "generation"))
            and stream_binding.get("session_id") == installation.get("session_id"), "stream_binding_mismatch")
    database = Path(stream["database"]).resolve()
    before = pin(trace_path)
    rows = read_trace(trace_path)
    seen = set()
    results = []
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        for row in rows:
            sequence = decimal(row.get("sequence"), 1)
            require(sequence not in seen, "duplicate_trace_sequence")
            seen.add(sequence)
            found = connection.execute(
                "SELECT length(c.payload),c.payload_sha256,c.group_id FROM complete_messages c JOIN fragment_groups g "
                "ON g.group_id=c.group_id WHERE g.installation=? AND g.world_generation=? AND g.message_id=? AND g.status='complete'",
                (expected["installation"], expected["generation"], str(sequence))).fetchone()
            require(found is not None and integer(found[0], 1, MAX_PAYLOAD_BYTES), "missing_or_oversize_complete_payload")
            payload_row = connection.execute("SELECT payload FROM complete_messages WHERE group_id=?", (found[2],)).fetchone()
            require(payload_row is not None, "complete_payload_disappeared")
            payload = bytes(payload_row[0])
            require(len(payload) == found[0] and hashlib.sha256(payload).hexdigest() == found[1], "complete_payload_hash_mismatch")
            result = audit_record(row, decode(payload), expected)
            result["payload_sha256"] = found[1]
            results.append(result)
    require(before == pin(trace_path), "trace_changed_during_audit")
    report = {"schema": "information.battle_gate_trace.offline_join.v1", "status": "joined_with_diagnostic_limits",
              "identity": expected, "records": results, "FRA_records": sum(r["observer_participated"] for r in results),
              "sources": [pin(p) for p in (installation_path, manifest_path, dll_path, stream_path, trace_path, database)],
              "activity": {"game_access": False, "RPM_or_MCP": False, "native_calls": 0, "request_writes": 0,
                           "SQLite": "mode=ro/query_only/one_read_transaction"},
              "limits": ["Private diagnostic evidence, not a public B04 field.",
                         "Sampled UI fields are not an atomic world snapshot.",
                         "A missing post-gate marker concerns the pinned synchronous client path only.",
                         "No conclusion about all AI-country messages, complete body text or visibility."]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as file:
        json.dump(report, file, ensure_ascii=False, indent=2)
        file.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("installation", "battle-stream", "trace", "output"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--expected-dll-sha256", required=True)
    args = parser.parse_args()
    try:
        report = run(args.installation, args.battle_stream, args.trace, args.output,
                     args.expected_manifest_sha256, args.expected_dll_sha256)
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error) as error:
        print(json.dumps({"status": "failed", "error": f"{type(error).__name__}:{error}"}), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "records": len(report["records"]), "FRA_records": report["FRA_records"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
