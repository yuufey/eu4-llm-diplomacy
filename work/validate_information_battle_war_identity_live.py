"""Prepare the bounded B01 war-identity live acceptance.

The helper is inert unless ``--run`` is supplied.  A run first reads an
already-ingested battle database and its ingest report, then independently
parses the WARI suffix of one v5 payload.  It does not use the production
``war_id`` projection to select or validate the record.  Only after a single
bound record with a direct FRA participant and an exact match from the
existing empty-parameter FRA peace-context registry discovery has been found
does it start the existing read-only information server with a generated
``--battle-stream`` configuration.  Ended or missing pairs remain explicitly
unavailable and are never compared as contradictory history.

No battle, peace, save, date, restart, DLL, RPM, REA, or UI action is issued
by this script.  A missing bound FRA record produces an ``unavailable``
receipt and never starts MCP.  ``--resume-query`` reuses a previously saved
query response and ``--resume-report-query`` reuses a previously saved report
query response; neither repeats the corresponding successful read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys
import time
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.information_battle_template_wire import decode as decode_template
from bridge.diplomacy import DiplomacyTools, ObserverSession
from bridge.diplomacy_journal import DurableJournal
from work.run_alliance_inbound_response import control_snapshot
from work.local_config import game_exe
from work.validate_information_trade_power_live import CheckedClient


STAGE = ROOT / "work/runtime/information-battle-war-identity-20261027-001"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024
MAX_BASE_V4_BYTES = 256 * 1024
MAX_DB_ROWS = 512
BOUND_FLAGS = 63
WARI = b"WARI"
WAR_ID_RE = re.compile(rb"war_[0-9a-f]{16}_[0-9a-f]{8}\Z")
WAR_ID_TEXT_RE = re.compile(r"war_[0-9a-f]{16}_[0-9a-f]{8}\Z")
HEX16_RE = re.compile(r"[0-9a-f]{16}\Z")
DECIMAL_RE = re.compile(r"[0-9]+\Z")
FULL_REF_TAG_RE = re.compile(r"[A-Z0-9]{3}\Z")
V5_STATUS = {0: "absent", 1: "bound", 2: "invalid"}
FIELDS_BY_TOPIC = {
    "B01": ("event_id", "battle_type", "name", "location", "end_date",
            "sides", "commanders", "war_id", "winner"),
    "B02": ("initial_forces", "losses", "remaining_forces", "unit_breakdown"),
    "B03": ("ships_captured", "war_score", "prestige", "army_tradition"),
    "B04": ("details", "record_order", "deduplication", "completeness", "gaps"),
}


class AcceptanceUnavailable(RuntimeError):
    """Inputs do not contain one safe real bound FRA record."""


def _request_namespace(output: Path) -> str:
    """Make a stable, path-scoped identifier namespace for one run."""
    digest = hashlib.sha256(str(output.resolve()).encode("utf-8")).hexdigest()[:16]
    return f"war-identity-{digest}"


def _request_id(namespace: str, operation: str) -> str:
    return f"{namespace}-{operation}"


def _read_json(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> Any:
    path = path.resolve(strict=True)
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise AcceptanceUnavailable(f"json_size_out_of_bound:{path}:{size}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_exclusive(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _positive_decimal(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise AcceptanceUnavailable(f"{label}_must_be_integer")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and DECIMAL_RE.fullmatch(value):
        number = int(value, 10)
    else:
        raise AcceptanceUnavailable(f"{label}_must_be_decimal")
    if not 0 < number < (1 << 64):
        raise AcceptanceUnavailable(f"{label}_out_of_uint64_range")
    return number


def _wire_identity(value: Any, label: str) -> str:
    return f"{_positive_decimal(value, label):016x}"


def _tag(full_ref: int) -> str | None:
    if not isinstance(full_ref, int) or full_ref <= 0 or full_ref >= (1 << 64):
        return None
    try:
        tag = full_ref.to_bytes(8, "little")[:3].decode("ascii")
    except (OverflowError, UnicodeDecodeError):
        return None
    return tag if FULL_REF_TAG_RE.fullmatch(tag) else None


def _splitmix64(value: int) -> int:
    mask = (1 << 64) - 1
    value = (value + 0x9E3779B97F4A7C15) & mask
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & mask
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & mask
    return (value ^ (value >> 31)) & mask


def _load_installation(installation: Path) -> dict[str, Any]:
    value = _read_json(installation, max_bytes=4 * 1024 * 1024)
    if not isinstance(value, dict):
        raise AcceptanceUnavailable("installation_not_object")
    pid = value.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise AcceptanceUnavailable("installation_pid_invalid")
    creation = _positive_decimal(value.get("creation_filetime"), "installation_creation_filetime")
    session = value.get("session_id")
    game_sha = value.get("game_sha256")
    if not isinstance(session, str) or not session:
        raise AcceptanceUnavailable("installation_session_missing")
    if not isinstance(game_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", game_sha):
        raise AcceptanceUnavailable("installation_game_sha_invalid")

    binding_path = installation.parent / "information-battle-binding.json"
    binding = _read_json(binding_path, max_bytes=256 * 1024)
    if not isinstance(binding, dict):
        raise AcceptanceUnavailable("battle_binding_not_object")
    if binding.get("session_id") != session or _positive_decimal(
            binding.get("creation_filetime"), "binding_creation_filetime") != creation:
        raise AcceptanceUnavailable("battle_binding_process_identity_mismatch")
    if binding.get("dll_sha256") != value.get("dll_sha256"):
        raise AcceptanceUnavailable("battle_binding_dll_mismatch")
    installation_id = _wire_identity(binding.get("installation"), "binding_installation")
    generation = _wire_identity(binding.get("generation"), "binding_generation")
    player_ref = binding.get("player_ref")
    if not isinstance(player_ref, str) or HEX16_RE.fullmatch(player_ref) is None:
        raise AcceptanceUnavailable("battle_binding_player_ref_invalid")
    return {
        "path": installation,
        "raw": value,
        "binding_path": binding_path,
        "binding": binding,
        "pid": pid,
        "creation_filetime": creation,
        "session_id": session,
        "game_sha256": game_sha,
        "dll_sha256": value.get("dll_sha256"),
        "installation_wire": installation_id,
        "generation_wire": generation,
        "player_ref": player_ref,
    }


def _parse_v5_payload(payload: bytes) -> dict[str, Any]:
    """Read the base v4 and WARI suffix without importing the v5 decoder."""
    if len(payload) > MAX_PAYLOAD_BYTES or len(payload) < 14:
        raise ValueError("payload_size_or_prefix_invalid")
    if payload[:4] != b"IBOW" or struct.unpack_from("<H", payload, 4)[0] != 5:
        raise ValueError("not_v5_payload")
    base_bytes = struct.unpack_from("<I", payload, 6)[0]
    if not 1 <= base_bytes <= MAX_BASE_V4_BYTES:
        raise ValueError("base_v4_size_invalid")
    base_start, base_end = 10, 10 + base_bytes
    if base_end + 4 > len(payload) or payload[base_end:base_end + 4] != WARI:
        raise ValueError("wari_extension_missing")
    base_raw = payload[base_start:base_end]
    base = decode_template(base_raw)
    if base.get("wire", {}).get("version") != 4:
        raise ValueError("base_is_not_v4")
    cursor = base_end + 4
    fixed_bytes = 1 + 1 + 4 + 8 + 4 + 8 + 8 + 1
    if cursor + fixed_bytes > len(payload):
        raise ValueError("wari_header_truncated")
    status, reason, flags = struct.unpack_from("<BBI", payload, cursor)
    cursor += 6
    creation = struct.unpack_from("<Q", payload, cursor)[0]
    cursor += 8
    raw_date = struct.unpack_from("<i", payload, cursor)[0]
    cursor += 4
    pair = list(struct.unpack_from("<QQ", payload, cursor))
    cursor += 16
    id_length = payload[cursor]
    cursor += 1
    if id_length > 29 or cursor + id_length != len(payload):
        raise ValueError("wari_id_length_invalid")
    id_bytes = payload[cursor:cursor + id_length]
    status_name = V5_STATUS.get(status)
    if status_name is None:
        raise ValueError("wari_status_invalid")
    war_id = None
    epoch = None
    suffix = None
    if status == 1:
        if reason != 0 or flags != BOUND_FLAGS or creation == 0 or len(id_bytes) != 29:
            raise ValueError("wari_bound_guard_invalid")
        if not WAR_ID_RE.fullmatch(id_bytes):
            raise ValueError("wari_bound_id_invalid")
        war_id = id_bytes.decode("ascii")
        epoch = int(war_id[4:20], 16)
        suffix = int(war_id[21:], 16)
    elif id_bytes:
        raise ValueError("wari_nonbound_id_not_empty")
    return {
        "base": base,
        "status": status_name,
        "status_code": status,
        "reason": reason,
        "binding_flags": flags,
        "process_creation_filetime": creation,
        "raw_date": raw_date,
        "pair_full_refs": pair,
        "war_id": war_id,
        "epoch_u64": epoch,
        "suffix": suffix,
        "payload_bytes": len(payload),
        "base_v4_bytes": base_bytes,
        "wari_bytes": len(payload) - base_end,
    }


def _direct_fra_witness(base: Mapping[str, Any]) -> dict[str, Any]:
    if base.get("context_present") is not True:
        raise ValueError("context_not_present")
    observation = base.get("observation")
    context = base.get("context")
    if not isinstance(observation, Mapping) or not isinstance(context, Mapping):
        raise ValueError("base_context_missing")
    if observation.get("known_router") is not True or context.get("known_router") is not True:
        raise ValueError("known_router_not_verified")
    result = observation.get("result")
    result_sides = result.get("sides") if isinstance(result, Mapping) else None
    context_sides = context.get("sides")
    if not isinstance(result_sides, list) or not isinstance(context_sides, list):
        raise ValueError("battle_side_vectors_missing")
    complete_context_sides: list[tuple[int, list[int]]] = []
    fra_matches: list[tuple[int, int]] = []
    for index, side in enumerate(context_sides):
        if not isinstance(side, Mapping) or side.get("present") is not True:
            continue
        participants = side.get("participants")
        if not isinstance(participants, Mapping) or participants.get("complete") is not True:
            continue
        refs = participants.get("full_refs")
        if (not isinstance(refs, list)
                or any(type(ref) is not int or ref <= 0 for ref in refs)
                or len(set(refs)) != len(refs)):
            continue
        normalized_refs = list(refs)
        complete_context_sides.append((index, normalized_refs))
        for ref in normalized_refs:
            if _tag(ref) == "FRA":
                fra_matches.append((index, ref))
    if len(fra_matches) != 1:
        raise ValueError("FRA_context_participation_not_unique")
    fra_side_index, fra_ref = fra_matches[0]

    if len(result_sides) != 2:
        raise ValueError("result_side_count_invalid")
    result_pair: list[int] = []
    result_to_context: list[int] = []
    for side in result_sides:
        if not isinstance(side, Mapping) or type(side.get("country")) is not int or side["country"] <= 0:
            raise ValueError("result_representative_invalid")
        representative = side["country"]
        matches = [index for index, refs in complete_context_sides if representative in refs]
        if len(matches) != 1:
            raise ValueError("result_representative_context_mapping_not_unique")
        result_pair.append(representative)
        result_to_context.append(matches[0])
    if len(set(result_to_context)) != 2 or fra_side_index not in result_to_context:
        raise ValueError("FRA_result_context_side_mapping_invalid")
    opponent_result_indices = [index for index, context_index in enumerate(result_to_context)
                               if context_index != fra_side_index]
    if len(opponent_result_indices) != 1:
        raise ValueError("opposing_result_side_not_unique")
    opponent_result_index = opponent_result_indices[0]
    opponent_ref = result_pair[opponent_result_index]
    opponent_tag = _tag(opponent_ref)
    if opponent_tag is None or opponent_tag == "FRA":
        raise ValueError("opposing_representative_tag_unavailable")
    if not isinstance(result, Mapping) or not isinstance(result.get("raw_date"), int):
        raise ValueError("result_raw_date_missing")
    return {
        "observer_ref": fra_ref,
        "observer_ref_hex": f"{fra_ref:016x}",
        "observer_tag": "FRA",
        "participant_side_index": fra_side_index,
        "sequence": observation.get("sequence"),
        "raw_date": result["raw_date"],
        "result_pair_full_refs": result_pair,
        "result_to_context_side": result_to_context,
        "opponent_result_side_index": opponent_result_index,
        "opponent_representative_ref": opponent_ref,
        "opponent_representative_ref_hex": f"{opponent_ref:016x}",
        "opponent_representative_tag": opponent_tag,
        "context_side_count": len(context_sides),
    }


def _db_v5_rows(database: Path):
    if not database.is_file():
        raise AcceptanceUnavailable(f"battle_database_missing:{database}")
    uri = database.resolve().as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise AcceptanceUnavailable(f"battle_database_open_failed:{type(exc).__name__}") from exc
    try:
        connection.execute("PRAGMA query_only=ON")
        cursor = connection.execute(
            "SELECT g.message_id,g.group_id,c.payload,c.payload_sha256,c.total_bytes "
            "FROM complete_messages c JOIN fragment_groups g ON g.group_id=c.group_id "
            "WHERE g.status='complete' ORDER BY g.group_id LIMIT ?", (MAX_DB_ROWS,))
        for row in cursor:
            payload = bytes(row[2])
            yield {
                "message_id": str(row[0]),
                "group_id": int(row[1]),
                "payload": payload,
                "payload_sha256": str(row[3]),
                "total_bytes": int(row[4]),
            }
    except sqlite3.Error as exc:
        raise AcceptanceUnavailable(f"battle_database_read_failed:{type(exc).__name__}") from exc
    finally:
        connection.close()


def _candidate_sort_key(candidate: Mapping[str, Any]) -> tuple[int, int, int]:
    witness = candidate.get("witness")
    sequence = witness.get("sequence") if isinstance(witness, Mapping) else None
    sequence_key = sequence if isinstance(sequence, int) and not isinstance(sequence, bool) else (1 << 63)
    message_id = candidate.get("message_id")
    message_key = int(message_id) if isinstance(message_id, str) and message_id.isdigit() else (1 << 63)
    group_id = candidate.get("group_id")
    group_key = group_id if isinstance(group_id, int) and not isinstance(group_id, bool) else (1 << 63)
    return sequence_key, message_key, group_key


def _candidate_summary(candidate: Mapping[str, Any]) -> dict[str, Any]:
    witness = candidate.get("witness")
    parsed = candidate.get("parsed")
    return {
        "message_id": candidate.get("message_id"),
        "group_id": candidate.get("group_id"),
        "payload_sha256": candidate.get("payload_sha256"),
        "sequence": witness.get("sequence") if isinstance(witness, Mapping) else None,
        "raw_date": parsed.get("raw_date") if isinstance(parsed, Mapping) else None,
        "war_id": parsed.get("war_id") if isinstance(parsed, Mapping) else None,
    }


def _select_record(installation: dict[str, Any], database: Path, ingest_report: Path) -> dict[str, Any]:
    report = _read_json(ingest_report)
    if not isinstance(report, Mapping) or report.get("schema") != "information_battle_raw_ingest_v1":
        raise AcceptanceUnavailable("ingest_report_schema_invalid")
    binding = report.get("binding")
    if not isinstance(binding, Mapping) or binding.get("session_id") != installation["session_id"]:
        raise AcceptanceUnavailable("ingest_report_identity_mismatch")
    if _positive_decimal(binding.get("creation_filetime"), "ingest_report_creation_filetime") != installation["creation_filetime"]:
        raise AcceptanceUnavailable("ingest_report_creation_mismatch")
    messages = report.get("messages")
    if not isinstance(messages, list) or len(messages) > MAX_DB_ROWS:
        raise AcceptanceUnavailable("ingest_report_messages_invalid")
    report_items = {str(item.get("message_id")): item for item in messages if isinstance(item, Mapping)}
    bound_seen = 0
    v5_seen = 0
    rejected: list[str] = []
    candidates: list[dict[str, Any]] = []
    for row in _db_v5_rows(database):
        payload = row["payload"]
        if len(payload) < 6 or payload[:4] != b"IBOW" or struct.unpack_from("<H", payload, 4)[0] != 5:
            continue
        v5_seen += 1
        item = report_items.get(row["message_id"])
        if item is None:
            rejected.append(f"message_not_in_ingest_report:{row['message_id']}")
            continue
        expected_sha = item.get("payload_sha256")
        actual_sha = hashlib.sha256(payload).hexdigest()
        if expected_sha != actual_sha or row["payload_sha256"] != actual_sha:
            raise AcceptanceUnavailable(f"ingest_db_payload_sha_mismatch:{row['message_id']}")
        try:
            parsed = _parse_v5_payload(payload)
            witness = _direct_fra_witness(parsed["base"])
        except (ValueError, UnicodeDecodeError, KeyError) as exc:
            rejected.append(f"message_{row['message_id']}:{type(exc).__name__}:{exc}")
            continue
        if parsed["status"] != "bound":
            rejected.append(f"message_{row['message_id']}:status_{parsed['status']}")
            continue
        bound_seen += 1
        if parsed["process_creation_filetime"] != installation["creation_filetime"]:
            rejected.append(f"message_{row['message_id']}:creation_mismatch")
            continue
        if parsed["raw_date"] != witness["raw_date"]:
            rejected.append(f"message_{row['message_id']}:date_mismatch")
            continue
        if parsed["pair_full_refs"] != witness["result_pair_full_refs"]:
            rejected.append(f"message_{row['message_id']}:pair_mismatch")
            continue
        if parsed["epoch_u64"] != _splitmix64(installation["creation_filetime"]):
            rejected.append(f"message_{row['message_id']}:epoch_mismatch")
            continue
        if not isinstance(parsed["suffix"], int) or not 1 <= parsed["suffix"] <= 256:
            rejected.append(f"message_{row['message_id']}:suffix_out_of_range")
            continue
        if not re.fullmatch(r"[1-9][0-9]{0,19}", row["message_id"]):
            rejected.append(f"message_{row['message_id']}:message_id_invalid")
            continue
        candidates.append({
            "message_id": row["message_id"],
            "group_id": row["group_id"],
            "payload_sha256": actual_sha,
            "payload_bytes": len(payload),
            "parsed": parsed,
            "witness": witness,
            "ingest_item": item,
        })
    if not candidates:
        raise AcceptanceUnavailable(
            f"WAR_ID_BOUND_FRA_RECORD_UNAVAILABLE:v5={v5_seen}:bound={bound_seen}:candidates=0"
        )
    candidates.sort(key=_candidate_sort_key)
    selected = candidates[0]
    selected["installation"] = installation
    selected["rejected_records"] = rejected[:64]
    selected["valid_candidate_count"] = len(candidates)
    selected["valid_candidate_summaries"] = [_candidate_summary(item) for item in candidates]
    return selected


def _peace_context_summary(value: Any, *, target: str, expected_war_id: str) -> dict[str, Any]:
    """Validate the existing empty-parameter peace-context public shape.

    A missing current pair is deliberately represented as unavailable.  A
    different current registry id is not treated as a contradiction: the
    independent WARI id may describe an ended or no-longer-visible event.
    """
    summary: dict[str, Any] = {
        "actor": "FRA", "recipient": target, "expected_war_id": expected_war_id,
        "status": "unavailable", "reason": "PEACE_CONTEXT_WAR_NOT_CURRENT",
        "war_context_count": None, "current_war_ids": [],
    }
    if not isinstance(value, Mapping):
        summary["reason"] = "PEACE_CONTEXT_RESULT_NOT_OBJECT"
        return summary
    if any(value.get(key) != wanted for key, wanted in (
        ("action_id", "white_peace"), ("actor", "FRA"), ("recipient", target),
        ("phase", "initiate"), ("family", "peace"),
        ("context_discovery", True), ("query_complete", True),
        ("war_context_enumeration_complete", True), ("native_offer_inspected", False),
    )):
        summary["reason"] = "PEACE_CONTEXT_CONTRACT_UNVERIFIED"
        return summary
    wars = value.get("war_contexts")
    if not isinstance(wars, list) or len(wars) > 32:
        summary["reason"] = "PEACE_CONTEXT_WAR_CONTEXTS_INVALID"
        return summary
    summary["war_context_count"] = len(wars)
    current_ids: list[str] = []
    for row in wars:
        if (not isinstance(row, Mapping) or not isinstance(row.get("war_id"), str)
                or WAR_ID_TEXT_RE.fullmatch(row["war_id"]) is None
                or row.get("identity_scope") != "observer_session"
                or row.get("actor") != "FRA" or row.get("recipient") != target
                or row.get("pair_at_war") is not True):
            summary["reason"] = "PEACE_CONTEXT_WAR_CONTEXT_ROW_INVALID"
            return summary
        current_ids.append(row["war_id"])
    summary["current_war_ids"] = current_ids
    if expected_war_id in current_ids:
        summary["status"] = "matched"
        summary["reason"] = "SHARED_PEACE_REGISTRY_WAR_ID_MATCH"
        summary["war_id"] = expected_war_id
    else:
        summary["reason"] = (
            "WARI_WAR_ID_NOT_CURRENT_IN_SHARED_REGISTRY" if current_ids
            else "PEACE_CONTEXT_WAR_NOT_CURRENT")
    return summary


def _peace_registry_crosscheck(installation_path: Path, parsed: Mapping[str, Any],
                               witness: Mapping[str, Any], resume_query: Path | None = None) -> dict[str, Any]:
    """Cross-check the WARI id against the existing read-only peace registry.

    A resume can reuse a prior successful crosscheck beside its query receipt;
    it must not silently repeat the native discovery.  The live path uses the
    established empty-parameter FRA-view inspection and an in-memory journal.
    """
    expected_war_id = parsed.get("war_id")
    if not isinstance(expected_war_id, str):
        raise AcceptanceUnavailable("peace_registry_crosscheck_wari_shape_invalid")
    opponent_ref = witness.get("opponent_representative_ref")
    target = witness.get("opponent_representative_tag")
    if type(opponent_ref) is not int or opponent_ref <= 0 or not isinstance(target, str):
        raise AcceptanceUnavailable("peace_registry_crosscheck_opponent_not_unique")
    if target is None or target == "FRA":
        raise AcceptanceUnavailable("peace_registry_crosscheck_opponent_tag_unavailable")

    if resume_query is not None:
        saved_path = resume_query.resolve(strict=True).with_name("peace-context-crosscheck.json")
        if not saved_path.is_file():
            raise AcceptanceUnavailable("resume_peace_registry_crosscheck_missing")
        saved = _read_json(saved_path, max_bytes=256 * 1024)
        if not isinstance(saved, Mapping):
            raise AcceptanceUnavailable("resume_peace_registry_crosscheck_invalid")
        if saved.get("status") != "matched" or saved.get("war_id") != expected_war_id:
            raise AcceptanceUnavailable("resume_peace_registry_crosscheck_not_matching")
        if saved.get("recipient") != target:
            raise AcceptanceUnavailable("resume_peace_registry_crosscheck_pair_mismatch")
        return dict(saved)

    try:
        session = ObserverSession(installation_path, game_exe())
        health = session.health()
        if not isinstance(health, Mapping) or health.get("status") != "ready":
            raise AcceptanceUnavailable("peace_registry_session_not_ready")
        with DurableJournal(":memory:", session.experiment_id, session.session_id) as journal:
            value = DiplomacyTools(journal, session).inspect_diplomatic_action(
                "white_peace", "FRA", target, "initiate", {})
    except AcceptanceUnavailable:
        raise
    except Exception as exc:
        raise AcceptanceUnavailable(
            f"peace_registry_crosscheck_failed:{type(exc).__name__}") from exc
    summary = _peace_context_summary(value, target=target, expected_war_id=expected_war_id)
    summary["source"] = "DiplomacyTools.inspect_diplomatic_action:white_peace:empty_parameters"
    summary["identity_scope"] = "observer_session"
    # Keep an explicit unavailable state instead of declaring a historical
    # WARI id contradictory to the current shared registry.  The caller
    # decides whether this prevents the live MCP phase and preserves this
    # summary in the unavailable receipt.
    return summary


def _event_id(installation: dict[str, Any], message_id: str) -> str:
    return f"battle-observation:{installation['installation_wire']}:{installation['generation_wire']}:{message_id}"


def _queries(event_id: str, topics: Mapping[str, Mapping[str, Any]] | None = None) -> list[dict[str, Any]]:
    result = []
    for topic_id, defaults in FIELDS_BY_TOPIC.items():
        fields = list(defaults)
        if topics is not None:
            fields_meta = topics[topic_id].get("fields")
            if isinstance(fields_meta, Mapping):
                fields = list(fields_meta)
        result.append({"topic": topic_id, "object": {"type": "battle"},
                       "fields": fields, "parameters": {"event_id": event_id}})
    return result


def _topic_items(result: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    items = result.get("items")
    if not isinstance(items, list):
        raise AssertionError("battle_result_items_missing")
    output: dict[str, Mapping[str, Any]] = {}
    for item in items:
        if not isinstance(item, Mapping):
            raise AssertionError("battle_result_item_invalid")
        topic = item.get("topic")
        if not isinstance(topic, str):
            query = item.get("query")
            topic = query.get("topic") if isinstance(query, Mapping) else None
        if not isinstance(topic, str) or topic in output:
            raise AssertionError("battle_result_topic_missing_or_duplicate")
        output[topic] = item
    return output


def _assert_no_native_pointer(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            lowered = str(key).lower()
            assert not any(token in lowered for token in ("native_pointer", "native_ptr", "pointer_address")), key
            _assert_no_native_pointer(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_native_pointer(child)


def _assert_battle_id_unknown(value: Any) -> None:
    if isinstance(value, Mapping):
        if "battle_id" in value:
            battle_id = value["battle_id"]
            assert battle_id is None or (isinstance(battle_id, Mapping)
                                         and battle_id.get("status") == "unknown"), battle_id
        for child in value.values():
            _assert_battle_id_unknown(child)
    elif isinstance(value, list):
        for child in value:
            _assert_battle_id_unknown(child)


def _assert_result(result: Mapping[str, Any], *, expected_id: str, expected_event_id: str,
                   expected_session: str, minimum_date: int) -> None:
    assert result.get("delivery", {}).get("status") == "delivered", result
    context = result.get("context")
    assert isinstance(context, Mapping), result
    assert context.get("session_id") == expected_session, context
    current_date = context.get("game_date", context.get("game_date_raw"))
    assert isinstance(current_date, int) and current_date >= minimum_date, context
    assert result.get("complete") is False, result
    items = _topic_items(result)
    assert set(items) == set(FIELDS_BY_TOPIC), items
    for topic_id, item in items.items():
        assert item.get("complete") is False, item
        fields = item.get("fields")
        assert isinstance(fields, Mapping), item
        for field, value in fields.items():
            assert isinstance(value, Mapping), (topic_id, field)
            status = value.get("status")
            assert status in {"known", "unknown", "unavailable", "unsupported"}, (topic_id, field, value)
            if status == "unsupported":
                # Discovery may expose planned or conditionally unavailable
                # extension fields.  They remain part of the full query for
                # resume identity, but must never be treated as a value.
                assert isinstance(value.get("reason"), str) and value["reason"], (topic_id, field, value)
                assert "value" not in value and "raw" not in value, (topic_id, field, value)
        _assert_no_native_pointer(item)
        _assert_battle_id_unknown(item)
    b01 = items["B01"]
    assert b01.get("fields", {}).get("event_id", {}).get("value") == expected_event_id, b01
    war_id = b01.get("fields", {}).get("war_id")
    assert isinstance(war_id, Mapping) and war_id.get("status") == "known", war_id
    assert war_id.get("value") == expected_id, war_id


def _resume_response(path: Path, default_queries: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    value = _read_json(path, max_bytes=MAX_JSON_BYTES)
    if not isinstance(value, Mapping):
        raise AcceptanceUnavailable("resume_query_not_object")
    response = value.get("response") if isinstance(value.get("response"), Mapping) else value
    request = value.get("request")
    request_id = request.get("request_id") if isinstance(request, Mapping) else None
    if isinstance(request, Mapping) and isinstance(request.get("queries"), list):
        queries = request["queries"]
    else:
        companion = path.with_name("query-request.json")
        if companion.is_file():
            request_value = _read_json(companion, max_bytes=MAX_JSON_BYTES)
            queries = request_value.get("queries") if isinstance(request_value, Mapping) else None
            request_id = request_value.get("request_id") if isinstance(request_value, Mapping) else None
        else:
            queries = None
    if not isinstance(response, dict) or not isinstance(response.get("items"), list):
        raise AcceptanceUnavailable("resume_query_response_invalid")
    if not isinstance(queries, list):
        queries = default_queries
    if not isinstance(request_id, str) or not request_id:
        raise AcceptanceUnavailable("resume_query_request_id_missing")
    return response, queries, request_id


def _resume_report_response(path: Path, default_queries: list[dict[str, Any]]) -> tuple[
        dict[str, Any], list[dict[str, Any]], str, str]:
    """Load a saved report query without treating it as a new live read.

    A report query response carries its original report id and request id.  The
    companion report-config file supplies the exact query list because the
    report query itself is not an information_query request envelope.
    """
    value = _read_json(path, max_bytes=MAX_JSON_BYTES)
    if not isinstance(value, Mapping):
        raise AcceptanceUnavailable("resume_report_query_not_object")
    response_value = value.get("response") if isinstance(value.get("response"), Mapping) else value
    if not isinstance(response_value, dict) or not isinstance(response_value.get("items"), list):
        raise AcceptanceUnavailable("resume_report_query_response_invalid")
    response = dict(response_value)
    report_id = response.get("report_id")
    if not isinstance(report_id, str) or not report_id:
        raise AcceptanceUnavailable("resume_report_query_report_id_missing")
    request_id = response.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        raise AcceptanceUnavailable("resume_report_query_request_id_missing")

    queries: Any = None
    request = value.get("request")
    if isinstance(request, Mapping) and isinstance(request.get("queries"), list):
        queries = request["queries"]
    companion = path.with_name("report-config.json")
    if queries is None and companion.is_file():
        report_config = _read_json(companion, max_bytes=MAX_JSON_BYTES)
        report = report_config.get("report") if isinstance(report_config, Mapping) else None
        if isinstance(report, Mapping):
            queries = report.get("queries")
            configured_id = report.get("id")
            if configured_id is not None and configured_id != report_id:
                raise AcceptanceUnavailable("resume_report_query_report_id_mismatch")
    if queries is None:
        queries = default_queries
    if not isinstance(queries, list):
        raise AcceptanceUnavailable("resume_report_query_queries_invalid")
    return response, queries, request_id, report_id


def _binding_config(installation: dict[str, Any], observer_ref: int, database: Path) -> dict[str, Any]:
    return {
        "schema": "EU4-BATTLE-STREAM/1",
        "database": str(database.resolve()),
        "binding": {
            "session_id": installation["session_id"],
            "installation": installation["installation_wire"],
            "generation": installation["generation_wire"],
            "game_sha256": installation["game_sha256"],
            "observer_ref": f"{observer_ref:016x}",
            "mode": "live",
            "process_creation_filetime": installation["creation_filetime"],
        },
    }


def _unavailable(output: Path, error: Exception, *, inputs: Mapping[str, Any],
                 details: Mapping[str, Any] | None = None) -> int:
    if output.exists():
        raise AssertionError(f"refusing_to_overwrite_output:{output}")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": "information_battle_war_identity_live_acceptance.v1",
        "status": "unavailable",
        "mcp_started": False,
        "error": {"type": type(error).__name__, "message": str(error)},
        "inputs": dict(inputs),
        "limitations": ["No live service was started because the WARI/peace-registry preflight was unavailable.",
                        "This receipt is not a passed MCP acceptance."],
    }
    if details:
        report.update(dict(details))
    _write_exclusive(output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 1


def run(installation_path: Path, battle_db: Path, ingest_report: Path, output: Path,
        resume_query: Path | None = None, resume_report_query: Path | None = None) -> int:
    installation_path = installation_path.resolve(strict=True)
    battle_db = battle_db.resolve(strict=True)
    ingest_report = ingest_report.resolve(strict=True)
    output = output.resolve()
    if output.exists():
        raise AssertionError(f"refusing_to_overwrite_output:{output}")
    request_namespace = _request_namespace(output)
    selected: dict[str, Any] | None = None
    crosscheck: dict[str, Any] | None = None
    try:
        installation = _load_installation(installation_path)
        selected = _select_record(installation, battle_db, ingest_report)
        crosscheck = _peace_registry_crosscheck(
            installation_path, selected["parsed"], selected["witness"], resume_query)
        if crosscheck.get("status") != "matched":
            raise AcceptanceUnavailable(
                f"peace_registry_unavailable:{crosscheck.get('reason', 'unknown')}")
    except (AcceptanceUnavailable, OSError, sqlite3.Error, ValueError, TypeError) as exc:
        return _unavailable(output, exc, inputs={
            "installation": str(installation_path),
            "battle_db": str(battle_db),
            "ingest_report": str(ingest_report),
        }, details={
            "request_namespace": request_namespace,
            "peace_registry_crosscheck": crosscheck,
            "record_selection": ({
                "selected_message_id": selected.get("message_id"),
                "valid_candidate_count": selected.get("valid_candidate_count"),
                "valid_candidates": selected.get("valid_candidate_summaries"),
            } if selected is not None else None),
        })

    output.mkdir(parents=True, exist_ok=False)
    parsed = selected["parsed"]
    witness = selected["witness"]
    event_id = _event_id(installation, selected["message_id"])
    config_path = output / "battle-stream.json"
    config = _binding_config(installation, witness["observer_ref"], battle_db)
    _write_exclusive(config_path, config)
    report: dict[str, Any] = {
        "schema": "information_battle_war_identity_live_acceptance.v1",
        "status": "running",
        "mcp_started": False,
        "stage": STAGE.relative_to(ROOT).as_posix(),
        "inputs": {
            "installation": {"path": installation_path.relative_to(ROOT).as_posix(), "sha256": _sha(installation_path)},
            "battle_db": {"path": battle_db.relative_to(ROOT).as_posix(), "sha256": _sha(battle_db)},
            "ingest_report": {"path": ingest_report.relative_to(ROOT).as_posix(), "sha256": _sha(ingest_report)},
        },
        "request_namespace": request_namespace,
        "request_ids": {},
        "peace_registry_crosscheck": crosscheck,
        "binding": {
            "session_id": installation["session_id"],
            "process_creation_filetime": installation["creation_filetime"],
            "installation_wire": installation["installation_wire"],
            "generation_wire": installation["generation_wire"],
            "observer": "FRA",
            "observer_ref": witness["observer_ref_hex"],
            "game_sha256": installation["game_sha256"],
            "config": {"path": config_path.relative_to(ROOT).as_posix(), "sha256": _sha(config_path)},
        },
        "independent_wire_reference": {
            "message_id": selected["message_id"],
            "group_id": selected["group_id"],
            "payload_bytes": selected["payload_bytes"],
            "payload_sha256": selected["payload_sha256"],
            "base_v4_bytes": parsed["base_v4_bytes"],
            "wari_bytes": parsed["wari_bytes"],
            "status": parsed["status"],
            "reason": parsed["reason"],
            "binding_flags": parsed["binding_flags"],
            "process_creation_filetime": parsed["process_creation_filetime"],
            "raw_date": parsed["raw_date"],
            "pair_full_refs": parsed["pair_full_refs"],
            "war_id": parsed["war_id"],
            "epoch_u64": parsed["epoch_u64"],
            "suffix": parsed["suffix"],
            "valid_candidate_count": selected["valid_candidate_count"],
            "valid_candidates": selected["valid_candidate_summaries"],
            "identity_scope": "observer_session",
            "source": "manual_struct_WARI_plus_old_v4_decoder",
        },
        "event": {"event_id": event_id, "sequence": witness["sequence"],
                  "observer_tag": witness["observer_tag"],
                  "participant_side_index": witness["participant_side_index"],
                  "result_pair_full_refs": witness["result_pair_full_refs"],
                  "result_to_context_side": witness["result_to_context_side"],
                  "opponent_representative_tag": witness["opponent_representative_tag"],
                  "opponent_result_side_index": witness["opponent_result_side_index"]},
        "checks": {"shared_peace_registry_war_id_match": True},
        "event_results": 0,
        "subscriptions_created": 0,
        "subscription_kind": "event",
        "delivery_kind": "event",
        "business_actions_submitted": 0,
        "save_restart_or_date_advance": False,
        "battle_id": {"status": "unknown", "reason": "BATTLE_ID_UNRESOLVED"},
        "original_query_reused_offline": resume_query is not None,
        "original_report_query_reused_offline": resume_report_query is not None,
    }
    _write_exclusive(output / "peace-context-crosscheck.json", crosscheck)
    client: CheckedClient | None = None
    subscription: dict[str, Any] | None = None
    before: dict[str, Any] | None = None
    try:
        before = control_snapshot(installation["pid"], output / "before-control.json")
        assert before["date_raw"] >= parsed["raw_date"], before
        client = CheckedClient(installation_path, output,
                               extra_args=["--battle-stream", str(config_path)])
        report["mcp_started"] = True
        discovery = client.call("information_discover")
        _write_exclusive(output / "discovery.json", discovery)
        topics = {item["topic_id"]: item for item in discovery.get("topics", [])
                  if isinstance(item, Mapping) and isinstance(item.get("topic_id"), str)}
        assert set(FIELDS_BY_TOPIC) <= set(topics), topics.keys()
        for topic_id in FIELDS_BY_TOPIC:
            topic = topics[topic_id]
            assert topic.get("status") == "available", topic
            fields_meta = topic.get("fields")
            assert isinstance(fields_meta, Mapping), topic
            for field in FIELDS_BY_TOPIC[topic_id]:
                assert field in fields_meta and fields_meta[field].get("coverage") == "partial", (topic_id, field)
        report["checks"]["B01_B04_discovery_partial"] = True
        queries = _queries(event_id, topics)
        query_request_id = _request_id(request_namespace, "query")
        if resume_query is not None:
            result, saved_queries, query_request_id = _resume_response(
                resume_query.resolve(strict=True), queries)
            assert saved_queries == queries, "resume_query_request_mismatch"
        else:
            result = client.call("information_query", request_id=query_request_id, queries=queries)
        report["request_ids"]["query"] = query_request_id
        report["request_ids"]["query_source"] = "resumed_original" if resume_query is not None else "new_namespace"
        _write_exclusive(output / "query-request.json", {"request_id": query_request_id, "queries": queries})
        _write_exclusive(output / "query.json", result)
        _assert_result(result, expected_id=parsed["war_id"], expected_event_id=event_id,
                       expected_session=installation["session_id"], minimum_date=parsed["raw_date"])
        report["checks"]["independent_WARI_matches_B01_war_id_and_B01_B04_partial"] = True

        # Always create a fresh report for the current server so the event
        # subscription is bound to this run.  A resumed report query remains
        # an independent, preserved result below; its original report id is
        # recorded rather than silently substituted with the new id.
        report_config = client.call(
            "information_manage_report", request_id=_request_id(request_namespace, "report-create"), operation="create",
            config={"name": "FRA战报战争编号", "queries": queries, "detail": "raw"},
        )
        report["request_ids"]["report_create"] = _request_id(request_namespace, "report-create")
        _write_exclusive(output / "report-config.json", report_config)
        report_id = report_config["report"]["id"]
        if resume_report_query is not None:
            saved, saved_queries, report_query_id, original_report_id = _resume_report_response(
                resume_report_query.resolve(strict=True), queries)
            assert saved_queries == queries, "resume_report_query_mismatch"
            report["request_ids"]["report_query_source"] = "resumed_original"
            report["original_report_id"] = original_report_id
            report["resumed_report_id"] = original_report_id
            report["resumed_report_query_path"] = resume_report_query.resolve().relative_to(ROOT).as_posix()
        else:
            report_query_id = _request_id(request_namespace, "report-query")
            saved = client.call("information_query", request_id=report_query_id, report_id=report_id)
            report["request_ids"]["report_query_source"] = "new_namespace"
        report["request_ids"]["report_query"] = report_query_id
        _write_exclusive(output / "report-query.json", saved)
        _assert_result(saved, expected_id=parsed["war_id"], expected_event_id=event_id,
                       expected_session=installation["session_id"], minimum_date=parsed["raw_date"])
        report["checks"]["saved_report_replays_same_WARI_projection"] = True

        event_binding = {
            "session_id": installation["session_id"],
            "observer": "FRA",
            "game_version": "1.37.4",
            "game_sha256": installation["game_sha256"],
        }
        report["event_binding"] = event_binding
        created = client.call(
            "information_manage_subscription", request_id=_request_id(request_namespace, "subscribe"), operation="create",
            config={"name": "war-identity-one-event", "kind": "event", "report_id": report_id,
                    "enabled": True,
                    "binding": event_binding,
                    "event": {"types": ["battle_observation"]}},
        )
        report["request_ids"]["subscribe"] = _request_id(request_namespace, "subscribe")
        subscription = created["subscription"]
        report["subscriptions_created"] = 1
        _write_exclusive(output / "subscription-config.json", created)
        event_results: list[dict[str, Any]] = []
        deadline = time.monotonic() + 35
        while not event_results and time.monotonic() < deadline:
            ticked = client.call("information_tick")
            event_results = [item for item in ticked.get("results", [])
                             if item.get("subscription_id") == subscription["id"]]
            if not event_results:
                listed = client.call("information_list_results", limit=100)
                event_results = [item for item in listed.get("results", [])
                                 if item.get("subscription_id") == subscription["id"]]
            if len(event_results) > 1:
                raise AssertionError("more_than_one_event_result_before_cancel")
            if not event_results:
                time.sleep(0.2)
        assert len(event_results) == 1, "one_event_result_not_delivered"
        _write_exclusive(output / "event-results.json", event_results)
        _assert_result(event_results[0], expected_id=parsed["war_id"], expected_event_id=event_id,
                       expected_session=installation["session_id"], minimum_date=parsed["raw_date"])
        assert event_results[0].get("trigger") == "event", event_results[0]
        assert event_results[0].get("subscription_id") == subscription["id"], event_results[0]
        report["event_results"] = 1
        report["checks"]["event_delivery_kind"] = True
        cancelled = client.call(
            "information_manage_subscription", request_id=_request_id(request_namespace, "cancel"), operation="cancel",
            subscription_id=subscription["id"], expected_version=subscription["version"],
        )
        report["request_ids"]["cancel"] = _request_id(request_namespace, "cancel")
        subscription = cancelled["subscription"]
        _write_exclusive(output / "cancelled-subscription.json", cancelled)
        assert subscription.get("state") == "cancelled", subscription
        list_request_id = _request_id(request_namespace, "list")
        report["request_ids"]["list"] = list_request_id
        listed = client.call("information_manage_subscription", request_id=list_request_id, operation="list")
        _write_exclusive(output / "subscriptions-after.json", listed)
        assert all(item.get("state") == "cancelled" for item in listed.get("subscriptions", [])), listed
        report["checks"]["one_event_result_cancelled_no_active_subscription"] = True
        report["status"] = "passed"
        report["outbox"] = "delivered"
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") != "cancelled":
                    cleanup_request_id = _request_id(request_namespace, "cleanup")
                    report["request_ids"]["cleanup"] = cleanup_request_id
                    client.call("information_manage_subscription", request_id=cleanup_request_id,
                                operation="cancel", subscription_id=subscription["id"],
                                expected_version=subscription["version"])
            except Exception as exc:
                report["status"] = "failed"
                report["cleanup_error"] = {"type": type(exc).__name__, "message": str(exc)}
            finally:
                try:
                    client.close()
                except Exception as exc:
                    report["status"] = "failed"
                    report["close_error"] = {"type": type(exc).__name__, "message": str(exc)}
            report["server_exit_code"] = client.process.returncode
            report["checks"]["server_exit_code_zero"] = report["server_exit_code"] == 0
            if not report["checks"]["server_exit_code_zero"]:
                report["status"] = "failed"
        if before is not None:
            try:
                after = control_snapshot(installation["pid"], output / "after-control.json")
                report["checks"]["date_pause_player_preserved"] = all(
                    before[key] == after[key] for key in ("date_raw", "paused_flag", "speed", "player_slot"))
                if not report["checks"]["date_pause_player_preserved"]:
                    report["status"] = "failed"
            except Exception as exc:
                report["status"] = "failed"
                report["after_control_error"] = {"type": type(exc).__name__, "message": str(exc)}
        _write_exclusive(output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly start the read-only MCP acceptance")
    parser.add_argument("--installation", type=Path, help="verified observer installation.json")
    parser.add_argument("--battle-db", type=Path, help="existing read-only reassembly SQLite database")
    parser.add_argument("--ingest-report", type=Path, help="existing offline raw-ingest report")
    parser.add_argument("--output", type=Path, help="new exclusive acceptance directory")
    parser.add_argument("--resume-query", type=Path,
                        help="previous query.json plus its query-request.json; skip the successful query call")
    parser.add_argument("--resume-report-query", type=Path,
                        help="previous report-query.json plus report-config.json; reuse its result while creating a new event report")
    args = parser.parse_args(argv)
    if not args.run:
        parser.print_help()
        return 0
    missing = [name for name, value in (("--installation", args.installation),
                                        ("--battle-db", args.battle_db),
                                        ("--ingest-report", args.ingest_report),
                                        ("--output", args.output)) if value is None]
    if missing:
        parser.error("--run requires " + ", ".join(missing))
    return run(args.installation, args.battle_db, args.ingest_report, args.output,
               args.resume_query, args.resume_report_query)


if __name__ == "__main__":
    raise SystemExit(main())
