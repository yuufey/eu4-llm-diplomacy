"""Mechanically audit the immutable post-window observation report.

The input is an ingest report, not the live JSONL source.  This script reads
only that bounded report, rechecks each complete wire payload with the strict
pointer-free decoder, and preserves raw country/name/commander bytes.  It
does not decode country tags, names, commanders, battle kind, result,
visibility, units, war identity, or battle identity.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Iterable
import zlib


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.information_battle_observation_wire import (  # noqa: E402
    MAX_WIRE_BYTES,
    ObservationWireError,
    decode as decode_observation,
)


MAX_INPUT_BYTES = 16 * 1024 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
EXPECTED_MESSAGES = 18

DEFAULT_INPUT = ROOT / "work/runtime/information-battle-live-20261025-001/raw-after-window-002.json"
DEFAULT_OUTPUT = ROOT / "work/runtime/information-battle-live-20261025-001/payload-analysis-001.json"


class PayloadAuditError(RuntimeError):
    """Raised when the bounded report cannot be mechanically audited."""


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(resolved)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _sha256(path: Path) -> tuple[int, str]:
    size = path.stat().st_size
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return size, digest.hexdigest()


def _load_input(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if not path.is_file():
        raise PayloadAuditError(f"input_missing:{path}")
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise PayloadAuditError(f"input_over_bound:{size}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PayloadAuditError(f"input_json_invalid:{exc}") from exc
    if not isinstance(document, dict):
        raise PayloadAuditError("input_object_required")
    input_pin = {
        "path": _display_path(path),
        "bytes": size,
        "sha256": _sha256(path)[1],
        "mtime_ns": path.stat().st_mtime_ns,
    }
    return document, input_pin


def _hex_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise PayloadAuditError(f"invalid_hex:{label}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise PayloadAuditError(f"invalid_hex:{label}") from exc


def _validate_raw_string(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PayloadAuditError(f"string_object_required:{label}")
    length = value.get("length")
    raw_hex = value.get("raw_hex")
    raw = _hex_bytes(raw_hex, f"{label}.raw_hex")
    if not _is_int(length) or length != len(raw):
        raise PayloadAuditError(f"string_length_mismatch:{label}")
    return {"length": length, "raw_hex": raw_hex}


def _validate_observation(observation: dict[str, Any], label: str) -> dict[str, Any]:
    sequence = observation.get("sequence")
    thread = observation.get("thread")
    known_router = observation.get("known_router")
    if not _is_int(sequence) or sequence <= 0:
        raise PayloadAuditError(f"invalid_sequence:{label}")
    if not _is_int(thread) or thread <= 0:
        raise PayloadAuditError(f"invalid_thread:{label}")
    if not isinstance(known_router, bool):
        raise PayloadAuditError(f"invalid_known_router:{label}")
    result = observation.get("result")
    summary = observation.get("summary")
    if not isinstance(result, dict) or not isinstance(summary, dict):
        raise PayloadAuditError(f"observation_result_summary_required:{label}")

    raw_date = result.get("raw_date")
    province_id = result.get("province_id")
    flag108 = result.get("flag108")
    aux100 = result.get("aux100")
    aux104 = result.get("aux104")
    if not all(_is_int(value) for value in (raw_date, province_id, flag108, aux100, aux104)):
        raise PayloadAuditError(f"invalid_result_scalar:{label}")
    name = _validate_raw_string(result.get("name"), f"{label}.name")
    sides = result.get("sides")
    if not isinstance(sides, list) or len(sides) != 2:
        raise PayloadAuditError(f"two_sides_required:{label}")
    side_records: list[dict[str, Any]] = []
    for side_index, side in enumerate(sides):
        side_label = f"{label}.side{side_index}"
        if not isinstance(side, dict):
            raise PayloadAuditError(f"side_object_required:{side_label}")
        country = side.get("country")
        country_raw_hex = side.get("country_raw_hex")
        country_raw = _hex_bytes(country_raw_hex, f"{side_label}.country_raw_hex")
        if not _is_int(country) or len(country_raw) != 8 or len(country_raw_hex) != 16:
            raise PayloadAuditError(f"country_ref_incomplete:{side_label}")
        commander = _validate_raw_string(side.get("commander"), f"{side_label}.commander")
        raw_fields = side.get("raw_fields")
        if not isinstance(raw_fields, list) or len(raw_fields) != 9 or not all(_is_int(value) for value in raw_fields):
            raise PayloadAuditError(f"raw_fields_invalid:{side_label}")
        side_records.append({
            "country": country,
            "country_raw_hex": country_raw_hex,
            "commander": commander,
            "raw_fields": list(raw_fields),
        })

    control_byte = summary.get("control_byte")
    summary_raw = summary.get("raw_i32")
    if not _is_int(control_byte) or not isinstance(summary_raw, list) or len(summary_raw) != 11 or not all(_is_int(value) for value in summary_raw):
        raise PayloadAuditError(f"summary_invalid:{label}")
    return {
        "sequence": sequence,
        "thread": thread,
        "known_router": known_router,
        "result": {
            "raw_date": raw_date,
            "flag108": flag108,
            "aux100": aux100,
            "aux104": aux104,
            "province_id": province_id,
            "name": name,
            "sides": side_records,
        },
        "summary": {"control_byte": control_byte, "raw_i32": list(summary_raw)},
    }


def _check_complete_flags(value: dict[str, Any], label: str) -> dict[str, Any]:
    required_false = ("complete", "visibility_verified")
    flags = {key: value.get(key) for key in required_false}
    flags["public_identity"] = value.get("public_identity")
    checks = {
        "complete_false": value.get("complete") is False,
        "visibility_verified_false": value.get("visibility_verified") is False,
        "public_identity_absent": value.get("public_identity") == {"battle_id": None, "status": "absent", "war_id": None},
    }
    if not all(checks.values()):
        raise PayloadAuditError(f"unexpected_complete_flags:{label}")
    return {"values": flags, "checks": checks}


def _analyze(document: dict[str, Any], input_pin: dict[str, Any]) -> dict[str, Any]:
    messages = document.get("messages")
    if not isinstance(messages, list):
        raise PayloadAuditError("messages_list_required")
    if len(messages) != EXPECTED_MESSAGES:
        raise PayloadAuditError(f"expected_{EXPECTED_MESSAGES}_messages:{len(messages)}")
    binding = document.get("binding")
    source = document.get("source")
    transport = document.get("transport")
    message_page = document.get("message_page")
    reassembly = document.get("reassembly")
    if not all(isinstance(value, dict) for value in (binding, source, transport, message_page, reassembly)):
        raise PayloadAuditError("binding_source_transport_page_reassembly_required")
    reassembly_groups = reassembly.get("groups", {}).get("groups")
    if not isinstance(reassembly_groups, list) or len(reassembly_groups) != len(messages):
        raise PayloadAuditError("reassembly_group_count_mismatch")
    group_by_id = {group.get("group_id"): group for group in reassembly_groups if isinstance(group, dict)}
    if len(group_by_id) != len(messages):
        raise PayloadAuditError("reassembly_group_ids_not_unique")

    message_records: list[dict[str, Any]] = []
    sequence_values: list[int] = []
    date_values: list[int] = []
    thread_values: list[int] = []
    router_values: list[bool] = []
    payload_hashes: list[str] = []
    group_ids: list[int] = []
    message_ids: list[str] = []
    strict_decode_matches = 0
    raw_payload_complete = 0
    transport_complete = 0
    complete_flags: Counter[str] = Counter()
    country_ref_count = 0
    country_ref_complete = 0
    commander_count = 0
    name_values: list[dict[str, Any]] = []
    province_values: list[int] = []
    crc_mismatches: list[int] = []
    source_identity_mismatches: list[int] = []

    for index, message in enumerate(messages):
        label = f"message[{index}]"
        if not isinstance(message, dict):
            raise PayloadAuditError(f"message_object_required:{label}")
        raw = _hex_bytes(message.get("raw_payload_hex"), f"{label}.raw_payload_hex")
        if len(raw) > MAX_WIRE_BYTES:
            raise PayloadAuditError(f"wire_over_bound:{label}")
        payload_hash = hashlib.sha256(raw).hexdigest()
        if message.get("payload_bytes") != len(raw) or message.get("payload_sha256") != payload_hash:
            raise PayloadAuditError(f"payload_hash_or_size_mismatch:{label}")
        if message.get("raw_payload_complete") is True:
            raw_payload_complete += 1
        if message.get("transport_complete") is True:
            transport_complete += 1
        group_id = message.get("group_id")
        message_id = message.get("message_id")
        if not _is_int(group_id) or not isinstance(message_id, str):
            raise PayloadAuditError(f"message_identity_invalid:{label}")
        group = message.get("group")
        if not isinstance(group, dict) or group.get("status") != "complete" or group.get("fragment_count") != 1 or group.get("received_count") != 1:
            raise PayloadAuditError(f"message_fragment_incomplete:{label}")
        reassembly_group = group_by_id.get(group_id)
        if not isinstance(reassembly_group, dict):
            raise PayloadAuditError(f"reassembly_group_missing:{label}")
        if (
            reassembly_group.get("status") != "complete"
            or reassembly_group.get("message_id") != message_id
            or reassembly_group.get("fragment_count") != 1
            or reassembly_group.get("received_count") != 1
            or reassembly_group.get("missing_indices") != []
            or reassembly_group.get("total_bytes") != len(raw)
            or reassembly_group.get("transport_complete") is not True
        ):
            raise PayloadAuditError(f"reassembly_group_incomplete:{label}")
        if reassembly_group.get("whole_crc32") != zlib.crc32(raw) & 0xFFFFFFFF:
            crc_mismatches.append(index)
        if reassembly_group.get("installation") != transport.get("installation") or reassembly_group.get("world_generation") != transport.get("world_generation"):
            source_identity_mismatches.append(index)

        try:
            strict_value = decode_observation(raw)
        except ObservationWireError as exc:
            raise PayloadAuditError(f"strict_decode_failed:{label}:{exc}") from exc
        if strict_value != message.get("decode", {}).get("value"):
            raise PayloadAuditError(f"strict_decode_report_mismatch:{label}")
        strict_decode_matches += 1
        value = strict_value
        flag_info = _check_complete_flags(value, label)
        complete_flags.update({
            "wire_complete_false": int(flag_info["checks"]["complete_false"]),
            "visibility_verified_false": int(flag_info["checks"]["visibility_verified_false"]),
            "public_identity_absent": int(flag_info["checks"]["public_identity_absent"]),
        })
        observation = _validate_observation(value.get("observation"), label)
        sequence_values.append(observation["sequence"])
        date_values.append(observation["result"]["raw_date"])
        thread_values.append(observation["thread"])
        router_values.append(observation["known_router"])
        payload_hashes.append(payload_hash)
        group_ids.append(group_id)
        message_ids.append(message_id)
        name_values.append(observation["result"]["name"])
        province_values.append(observation["result"]["province_id"])
        country_ref_count += 2
        country_ref_complete += sum(
            len(side["country_raw_hex"]) == 16 and len(_hex_bytes(side["country_raw_hex"], f"{label}.country")) == 8
            for side in observation["result"]["sides"]
        )
        commander_count += 2
        message_records.append({
            "index": index,
            "group_id": group_id,
            "message_id": message_id,
            "sequence": observation["sequence"],
            "fragment": {"count": group["fragment_count"], "received": group["received_count"], "status": group["status"]},
            "wire": {"bytes": len(raw), "sha256": payload_hash, "magic": value["wire"]["magic"], "version": value["wire"]["version"], "trailing_bytes": value["wire"]["trailing_bytes"]},
            "thread": observation["thread"],
            "known_router": observation["known_router"],
            "raw_date": observation["result"]["raw_date"],
            "flag108": observation["result"]["flag108"],
            "aux100": observation["result"]["aux100"],
            "aux104": observation["result"]["aux104"],
            "province_id": observation["result"]["province_id"],
            "name": observation["result"]["name"],
            "sides": observation["result"]["sides"],
            "summary": observation["summary"],
            "complete_flags": flag_info,
            "reassembly": {
                "installation": reassembly_group.get("installation"),
                "world_generation": reassembly_group.get("world_generation"),
                "crc32": reassembly_group.get("whole_crc32"),
            },
        })

    sequence_expected = list(range(1, EXPECTED_MESSAGES + 1))
    sequence_checks = {
        "contiguous_1_to_18": sequence_values == sequence_expected,
        "unique": len(set(sequence_values)) == len(sequence_values),
        "group_ids_unique": len(set(group_ids)) == len(group_ids),
        "message_ids_unique": len(set(message_ids)) == len(message_ids),
    }
    page_checks = {
        "returned_matches_messages": message_page.get("returned") == len(messages),
        "complete_groups_matches_messages": message_page.get("complete_groups") == len(messages),
        "truncated_false": message_page.get("truncated") is False,
    }
    transport_checks = {
        "received_count_matches": transport.get("received_count") == len(messages),
        "first_sequence_1": transport.get("first_sequence") == "1",
        "max_sequence_18": transport.get("max_sequence") == "18",
        "observed_gap_false": transport.get("observed_gap") is False,
        "open_gap_ranges_empty": transport.get("open_gap_ranges") == [],
        "transport_stream_complete_false": transport.get("complete") is False,
    }
    binding_checks = {
        "header_matches_binding": source.get("header_matches_binding") is True,
        "binding_checks_all_true": isinstance(binding.get("checks"), dict) and all(value is True for value in binding["checks"].values()),
        "installation_matches_transport": binding.get("installation", {}).get("wire_hex") == transport.get("installation"),
        "generation_matches_transport": binding.get("generation", {}).get("wire_hex") == transport.get("world_generation"),
        "source_identity_per_group": not source_identity_mismatches,
    }
    top_complete = document.get("completeness")
    if not isinstance(top_complete, dict):
        raise PayloadAuditError("top_completeness_required")
    completeness_checks = {
        "raw_payload_complete_count_18": top_complete.get("raw_payload_complete_count") == len(messages),
        "transport_stream_complete_false": top_complete.get("transport_stream_complete") is False,
        "battle_complete_false": top_complete.get("battle_complete") is False,
        "business_complete_false": top_complete.get("business_complete") is False,
        "overall_complete_false": top_complete.get("overall_complete") is False,
        "visibility_verified_false": top_complete.get("visibility_verified") is False,
        "public_identity_absent": top_complete.get("public_identity") == {"battle_id": None, "status": "absent", "war_id": None},
    }
    checks = {
        "message_count": len(messages) == EXPECTED_MESSAGES,
        "strict_decode_matches": strict_decode_matches == len(messages),
        "all_raw_payloads_complete": raw_payload_complete == len(messages),
        "all_transport_groups_complete": transport_complete == len(messages),
        "crc32_all_match": not crc_mismatches,
        "sequence": all(sequence_checks.values()),
        "message_page": all(page_checks.values()),
        "transport": all(transport_checks.values()),
        "binding_and_source_identity": all(binding_checks.values()),
        "country_refs_complete": country_ref_complete == country_ref_count == len(messages) * 2,
        "complete_flags": all(complete_flags.get(key, 0) == len(messages) for key in ("wire_complete_false", "visibility_verified_false", "public_identity_absent")),
        "top_completeness_flags": all(completeness_checks.values()),
    }
    return {
        "schema": "information_battle_natural_payload_analysis_v1",
        "status": "passed" if all(checks.values()) else "failed",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input": input_pin,
        "scope": {
            "input_kind": "immutable_ingest_report",
            "game_access": False,
            "process_access": False,
            "live_raw_log_read": False,
            "database_read": False,
            "control_command_sent": False,
            "strict_codec_redecoded": True,
        },
        "source_identity": {
            "binding": {
                "pid": binding.get("pid"),
                "creation_filetime": binding.get("creation_filetime"),
                "session_id": binding.get("session_id"),
                "installation_wire_hex": binding.get("installation", {}).get("wire_hex"),
                "generation_wire_hex": binding.get("generation", {}).get("wire_hex"),
                "dll_sha256": binding.get("dll_sha256"),
                "physical_player_ref_raw_hex": binding.get("physical_player_ref", {}).get("raw_hex"),
            },
            "checks": binding_checks,
            "source_header_matches_binding": source.get("header_matches_binding"),
            "reassembly_installations": sorted({group.get("installation") for group in reassembly_groups}),
            "reassembly_world_generations": sorted({group.get("world_generation") for group in reassembly_groups}),
        },
        "message_page": {
            "reported": message_page,
            "checks": page_checks,
            "message_count": len(messages),
        },
        "transport": {
            "reported": {
                "received_count": transport.get("received_count"),
                "first_sequence": transport.get("first_sequence"),
                "max_sequence": transport.get("max_sequence"),
                "observed_gap": transport.get("observed_gap"),
                "observed_gaps_total": transport.get("observed_gaps_total"),
                "open_gap_ranges_total": transport.get("open_gap_ranges_total"),
                "complete": transport.get("complete"),
                "consistent": transport.get("consistent"),
            },
            "checks": transport_checks,
            "sequence": {"values": sequence_values, "checks": sequence_checks},
            "source_gap_summary": {"observed_gap": transport.get("observed_gap"), "observed_gaps": transport.get("observed_gaps"), "open_gap_ranges": transport.get("open_gap_ranges")},
        },
        "dates": {
            "raw_value_counts": {str(value): count for value, count in sorted(Counter(date_values).items())},
            "raw_min": min(date_values),
            "raw_max": max(date_values),
            "unique_raw_value_count": len(set(date_values)),
            "sequence_order_non_decreasing": date_values == sorted(date_values),
            "interpretation": "raw wire date integers only; no calendar conversion or date semantics inferred",
        },
        "thread_and_router": {
            "thread_counts": {str(value): count for value, count in sorted(Counter(thread_values).items())},
            "known_router_counts": {str(value).lower(): count for value, count in Counter(router_values).items()},
            "unique_thread_count": len(set(thread_values)),
        },
        "payloads": {
            "count": len(message_records),
            "strict_decoded_count": strict_decode_matches,
            "duplicate_payload_sha256": {digest: count for digest, count in Counter(payload_hashes).items() if count > 1},
            "unique_payload_count": len(set(payload_hashes)),
            "crc32_mismatch_indices": crc_mismatches,
        },
        "country_refs": {
            "expected_side_count": len(messages) * 2,
            "complete_raw_ref_count": country_ref_complete,
            "missing_or_short_ref_count": country_ref_count - country_ref_complete,
            "raw_bytes_preserved": True,
        },
        "complete_flags": {
            "per_message": dict(complete_flags),
            "top_level": top_complete,
            "checks": completeness_checks,
            "business_interpretation": "not_complete: this is a bounded raw observation payload, not a public battle result",
        },
        "messages": message_records,
        "checks": checks,
        "unresolved_semantics": [
            "kind",
            "winner_or_loser",
            "final_quantity_or_scale",
            "unit_identity",
            "visibility",
            "war_id",
            "battle_id",
            "public_message_text_semantics",
        ],
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(list(argv) if argv is not None else None)
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"refusing_to_overwrite:{output}")
    document, input_pin = _load_input(args.input.resolve())
    report = _analyze(document, input_pin)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": report["status"], "output": _display_path(output), "message_count": len(report["messages"]), "checks_failed": [key for key, value in report["checks"].items() if not value]}, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
