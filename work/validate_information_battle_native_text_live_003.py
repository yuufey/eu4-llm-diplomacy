"""Prepare a bounded live B04 native-text acceptance.

The helper is inert unless ``--run`` is supplied.  A run reads one already
selected battle event from the read-only battle database, checks its identity
and independent payload pin, then starts the normal operator-bound information
server with a live battle stream.  It queries only ``B04.details`` and
``B04.raw_text``.  A v6 native-text projection is checked when present; the
unimplemented full ``raw_text`` field and missing title/Line1 values remain
explicitly unresolved.

The first query and report-query responses are written before their
assertions.  ``--resume-query`` and ``--resume-report-query`` validate and
reuse those saved responses without sending the successful read again.  The
The event subscription is read-only and uses one tick followed by a second
deduplication tick; it is never a periodic subscription.  Its report has no
event selector, so every currently visible FRA record is checked.  Selected
message 7 remains the query/report witness and is checked against that full
event set.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import time
from collections.abc import Mapping
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from work.run_alliance_inbound_response import control_snapshot
from work.validate_information_trade_power_live import CheckedClient


STAGE = ROOT / "work/runtime/information-battle-native-observer-20261027-001"
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
GAME_VERSION = "1.37.4"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
EVENT_ID = re.compile(r"^battle-observation:([0-9a-f]{16}):([0-9a-f]{16}):([1-9][0-9]{0,19})\Z")
ALLOWED_STATUS = {"known", "unknown", "unavailable", "unsupported"}
NATIVE_STATUS = {"known", "unknown", "absent"}

# The natural-window-002 raw ingest independently established these three
# direct-FRA records.  Keep the map explicit: a new or missing payload must
# fail the acceptance instead of silently becoming an empty event set.
EXPECTED_EVENT_PAYLOADS = {
    "7": ("6b0056e70e5b4a41dd0836e14d569515073f07fc6ac4908e73ba422f5841e711", 2069),
    "8": ("8676c92d5bd3bb629e77bfc570acb4d164a8d3469f62c87d8b26b6765f17ac6f", 2253),
    "15": ("9ce52aaaa9d3d47f9abfb8edf90938dbf5e2486ee627574af4f384e39171bee3", 2076),
}


class AcceptanceUnavailable(RuntimeError):
    """The requested live acceptance has no safe bound input."""


def _read_json(path: Path, *, limit: int = MAX_JSON_BYTES) -> Any:
    path = path.resolve(strict=True)
    size = path.stat().st_size
    if size <= 0 or size > limit:
        raise AcceptanceUnavailable(f"json_size_out_of_bound:{path}:{size}")
    with path.open("r", encoding="utf-8-sig") as stream:
        return json.load(stream)


def _sha_file(path: Path) -> str:
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


def _request_namespace(output: Path) -> str:
    digest = hashlib.sha256(str(output.resolve()).encode("utf-8")).hexdigest()[:16]
    return f"battle-native-text-{digest}"


def _request_id(namespace: str, suffix: str) -> str:
    return f"{namespace}-{suffix}"


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AcceptanceUnavailable(f"{label}_must_be_integer")
    if positive and value <= 0:
        raise AcceptanceUnavailable(f"{label}_must_be_positive")
    if value < 0 or value >= (1 << 64):
        raise AcceptanceUnavailable(f"{label}_out_of_range")
    return value


def _load_installation(path: Path) -> dict[str, Any]:
    value = _read_json(path, limit=512 * 1024)
    if not isinstance(value, dict):
        raise AcceptanceUnavailable("installation_not_object")
    pid = _integer(value.get("pid"), "installation_pid", positive=True)
    creation = _integer(value.get("creation_filetime"), "creation_filetime", positive=True)
    session = value.get("session_id")
    game_sha = value.get("game_sha256")
    if not isinstance(session, str) or not session:
        raise AcceptanceUnavailable("installation_session_missing")
    if game_sha != GAME_SHA256:
        raise AcceptanceUnavailable("installation_game_sha_mismatch")
    return {
        "path": path,
        "pid": pid,
        "creation_filetime": creation,
        "session_id": session,
        "game_sha256": game_sha,
        "dll_sha256": value.get("dll_sha256"),
        "raw": value,
    }


def _tag_from_fullref(value: str) -> str | None:
    if not isinstance(value, str) or HEX16.fullmatch(value) is None:
        return None
    try:
        raw = int(value, 16).to_bytes(8, "little")[:3].decode("ascii")
    except (ValueError, OverflowError, UnicodeDecodeError):
        return None
    return raw if re.fullmatch(r"[A-Z0-9]{3}", raw) else None


def _load_stream(path: Path, database: Path, installation: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    value = _read_json(path, limit=256 * 1024)
    if not isinstance(value, dict) or value.get("schema") != "EU4-BATTLE-STREAM/1":
        raise AcceptanceUnavailable("battle_stream_schema_mismatch")
    binding = value.get("binding")
    if not isinstance(binding, dict):
        raise AcceptanceUnavailable("battle_stream_binding_missing")
    if binding.get("mode") != "live":
        raise AcceptanceUnavailable("battle_stream_must_be_live")
    if binding.get("session_id") != installation["session_id"]:
        raise AcceptanceUnavailable("battle_stream_session_mismatch")
    if binding.get("game_sha256") != GAME_SHA256:
        raise AcceptanceUnavailable("battle_stream_game_sha_mismatch")
    creation = binding.get("process_creation_filetime", binding.get("creation_filetime"))
    if creation != installation["creation_filetime"]:
        raise AcceptanceUnavailable("battle_stream_creation_mismatch")
    for key in ("installation", "generation", "observer_ref"):
        if not isinstance(binding.get(key), str) or HEX16.fullmatch(binding[key]) is None:
            raise AcceptanceUnavailable(f"battle_stream_{key}_invalid")
    if _tag_from_fullref(binding["observer_ref"]) != "FRA":
        raise AcceptanceUnavailable("battle_stream_observer_must_be_FRA")
    generated = deepcopy(value)
    generated["database"] = str(database.resolve())
    generated["binding"] = deepcopy(binding)
    generated["binding"]["process_creation_filetime"] = installation["creation_filetime"]
    return generated, binding


def _event_parts(event_id: str, binding: Mapping[str, Any]) -> str:
    match = EVENT_ID.fullmatch(event_id)
    if match is None:
        raise AcceptanceUnavailable("selected_event_id_invalid")
    if match.group(1) != binding["installation"] or match.group(2) != binding["generation"]:
        raise AcceptanceUnavailable("selected_event_id_binding_mismatch")
    return match.group(3)


def _database_payload_pin(database: Path, binding: Mapping[str, Any], message_id: str) -> dict[str, Any]:
    if not database.is_file():
        raise AcceptanceUnavailable("battle_database_missing")
    uri = database.resolve().as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            rows = connection.execute(
                "SELECT g.group_id,g.message_id,c.payload_sha256,c.total_bytes,"
                "length(c.payload) AS payload_bytes "
                "FROM fragment_groups g JOIN complete_messages c USING(group_id) "
                "WHERE g.installation=? AND g.world_generation=? "
                "AND g.message_id=? AND g.status='complete' "
                "ORDER BY g.group_id LIMIT 2",
                (binding["installation"], binding["generation"], message_id),
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise AcceptanceUnavailable(f"battle_database_read_failed:{type(error).__name__}") from error
    if len(rows) != 1:
        raise AcceptanceUnavailable("selected_event_payload_not_unique")
    row = dict(rows[0])
    if (not isinstance(row.get("payload_sha256"), str)
            or isinstance(row.get("payload_bytes"), bool)
            or not isinstance(row.get("payload_bytes"), int)
            or not 0 < row["payload_bytes"] <= MAX_PAYLOAD_BYTES
            or row.get("total_bytes") != row["payload_bytes"]):
        raise AcceptanceUnavailable("selected_event_payload_pin_invalid")
    return row


def _extract_payload_pin(value: Any) -> tuple[str | None, int | None]:
    if not isinstance(value, Mapping):
        return None, None
    holders = [value]
    for key in ("payload", "pin", "source", "independent_payload"):
        child = value.get(key)
        if isinstance(child, Mapping):
            holders.append(child)
    digest = next((item.get("payload_sha256") for item in holders
                   if isinstance(item.get("payload_sha256"), str)), None)
    size = next((item.get("payload_bytes") for item in holders
                 if type(item.get("payload_bytes")) is int), None)
    return digest, size


def _independent_pin(expected: Path | None, payload: Path | None,
                     row: Mapping[str, Any], event_id: str) -> dict[str, Any]:
    if expected is None and payload is None:
        raise AcceptanceUnavailable("expected_json_or_payload_pin_required")
    expected_value: Any = None
    expected_sha = expected_bytes = None
    if expected is not None:
        expected_value = _read_json(expected, limit=2 * 1024 * 1024)
        if not isinstance(expected_value, Mapping):
            raise AcceptanceUnavailable("expected_json_not_object")
        if expected_value.get("event_id") not in (None, event_id):
            raise AcceptanceUnavailable("expected_event_id_mismatch")
        expected_sha, expected_bytes = _extract_payload_pin(expected_value)
    payload_info: dict[str, Any] | None = None
    if payload is not None:
        payload = payload.resolve(strict=True)
        if payload.stat().st_size > MAX_PAYLOAD_BYTES:
            raise AcceptanceUnavailable("payload_pin_too_large")
        if payload.suffix.lower() == ".json":
            payload_value = _read_json(payload, limit=2 * 1024 * 1024)
            payload_sha, payload_bytes = _extract_payload_pin(payload_value)
            if payload_sha is None:
                raise AcceptanceUnavailable("payload_json_pin_missing")
            payload_info = {"path": str(payload), "sha256": payload_sha,
                            "bytes": payload_bytes, "kind": "json_pin"}
        else:
            payload_sha = _sha_file(payload)
            payload_info = {"path": str(payload), "sha256": payload_sha,
                            "bytes": payload.stat().st_size, "kind": "binary"}
        if expected_sha is not None and expected_sha != payload_info["sha256"]:
            raise AcceptanceUnavailable("expected_and_payload_pin_mismatch")
        expected_sha = payload_info["sha256"]
        expected_bytes = payload_info["bytes"]
    # An expected JSON is itself an independent witness and may intentionally
    # contain only projected metadata.  A separate payload pin, when supplied,
    # must bind to the durable database row byte-for-byte.
    if expected_sha is not None and expected_sha != row["payload_sha256"]:
        raise AcceptanceUnavailable("independent_payload_sha_mismatch")
    if expected_bytes is not None and expected_bytes != row["payload_bytes"]:
        raise AcceptanceUnavailable("independent_payload_bytes_mismatch")
    return {
        "event_id": event_id,
        "payload_sha256": row["payload_sha256"],
        "payload_bytes": row["payload_bytes"],
        "database_row": row,
        "expected_path": str(expected) if expected else None,
        "payload_path": str(payload) if payload else None,
        "expected": expected_value,
        "payload": payload_info,
    }


def _native_from_details(details: Any) -> dict[str, Any] | None:
    if not isinstance(details, Mapping) or details.get("status") != "known":
        return None
    value = details.get("value")
    if not isinstance(value, Mapping):
        return None
    native = value.get("native_text")
    if not isinstance(native, Mapping):
        return None
    if native.get("complete") is not False:
        raise AssertionError("native_text_must_remain_partial")
    fields = native.get("text_fields")
    if not isinstance(fields, Mapping):
        # Public projection names this member directly by field, while the
        # decoder names it text_fields.  Accept either shape but validate the
        # known public contract below.
        fields = {key: native.get(key) for key in (
            "definition_key", "auxiliary_text", "title_helper_candidate", "line1_text")
                  if key in native}
    for name in ("definition_key", "auxiliary_text", "title_helper_candidate", "line1_text"):
        item = fields.get(name)
        if not isinstance(item, Mapping) or item.get("status") not in NATIVE_STATUS:
            raise AssertionError(f"native_text_{name}_status_invalid")
        if item.get("status") == "known" and not isinstance(item.get("raw_hex"), str):
            raise AssertionError(f"native_text_{name}_raw_missing")
    return dict(native)


def _context_assert(result: Mapping[str, Any], installation: Mapping[str, Any],
                    before: Mapping[str, Any]) -> None:
    context = result.get("context")
    if not isinstance(context, Mapping):
        raise AssertionError("live_context_missing")
    for key, wanted in (("status", "ready"), ("mode", "live"),
                        ("session_id", installation["session_id"]),
                        ("observer", "FRA"), ("game_version", GAME_VERSION),
                        ("game_sha256", GAME_SHA256)):
        if context.get(key) != wanted:
            raise AssertionError(f"live_context_{key}_mismatch:{context.get(key)!r}")
    date = context.get("game_date", context.get("game_date_raw"))
    if type(date) is not int or date != before.get("date_raw"):
        raise AssertionError("live_context_date_mismatch")


def _field_map(result: Mapping[str, Any], *, delivered: bool) -> dict[str, Any]:
    if delivered and result.get("delivery", {}).get("status") != "delivered":
        raise AssertionError("event_not_delivered")
    if result.get("complete") is not False:
        raise AssertionError("battle_result_must_be_partial")
    items = result.get("items")
    if not isinstance(items, list) or len(items) != 1:
        raise AssertionError("expected_one_B04_item")
    item = items[0]
    if not isinstance(item, Mapping):
        raise AssertionError("battle_item_not_object")
    fields = item.get("fields")
    if not isinstance(fields, Mapping):
        raise AssertionError("battle_fields_missing")
    for name in ("details", "raw_text"):
        value = fields.get(name)
        if not isinstance(value, Mapping) or value.get("status") not in ALLOWED_STATUS:
            raise AssertionError(f"B04_{name}_status_invalid")
        if value.get("status") in {"unknown", "unavailable", "unsupported"}:
            if "value" in value:
                raise AssertionError(f"B04_{name}_unresolved_has_value")
    raw_text = fields["raw_text"]
    if raw_text.get("status") in {"unknown", "unavailable", "unsupported"}:
        if "complete" in raw_text and raw_text.get("complete") is not False:
            raise AssertionError("raw_text_unresolved_complete")
    event_id = result.get("event_id")
    if event_id is not None and not isinstance(event_id, str):
        raise AssertionError("result_event_id_invalid")
    return dict(fields)


def _find_payload_sha(value: Any) -> str | None:
    if isinstance(value, Mapping):
        found = value.get("payload_sha256")
        if isinstance(found, str) and re.fullmatch(r"[0-9a-f]{64}", found):
            return found
        for child in value.values():
            result = _find_payload_sha(child)
            if result is not None:
                return result
    elif isinstance(value, list):
        for child in value:
            result = _find_payload_sha(child)
            if result is not None:
                return result
    return None


def _result_event_id(result: Mapping[str, Any]) -> str | None:
    """Return the durable event id without depending on result ordering."""
    event = result.get("event")
    if isinstance(event, Mapping) and isinstance(event.get("event_id"), str):
        return event["event_id"]
    items = result.get("items")
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, Mapping):
                continue
            fields = item.get("fields")
            if not isinstance(fields, Mapping):
                continue
            field = fields.get("event_id")
            if isinstance(field, Mapping) and field.get("status") == "known":
                value = field.get("value")
                if isinstance(value, str):
                    return value
    value = result.get("event_id")
    return value if isinstance(value, str) else None


def _subscription_results(listed: Mapping[str, Any], subscription_id: str) -> list[dict[str, Any]]:
    results = listed.get("results")
    if not isinstance(results, list):
        raise AssertionError("information_results_missing")
    selected = [item for item in results
                if isinstance(item, Mapping)
                and item.get("subscription_id") == subscription_id]
    if any(not isinstance(item, dict) for item in selected):
        raise AssertionError("subscription_result_not_object")
    return selected


def _verify_expected_payloads(database: Path, binding: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Bind the known raw-window event set to complete SQLite payload rows."""
    result: dict[str, dict[str, Any]] = {}
    for suffix, (wanted_sha, wanted_bytes) in EXPECTED_EVENT_PAYLOADS.items():
        event_id = f"battle-observation:{binding['installation']}:{binding['generation']}:{suffix}"
        row = _database_payload_pin(database, binding, suffix)
        if row["payload_sha256"] != wanted_sha or row["payload_bytes"] != wanted_bytes:
            raise AcceptanceUnavailable(f"event_payload_manifest_mismatch:{suffix}")
        result[event_id] = {
            "message_id": suffix,
            "payload_sha256": wanted_sha,
            "payload_bytes": wanted_bytes,
        }
    return result


def _assert_visible_event_set(results: list[dict[str, Any]], *,
                              installation: Mapping[str, Any],
                              before: Mapping[str, Any],
                              expected: Any, selected_event_id: str,
                              payload_manifest: Mapping[str, Mapping[str, Any]]) -> tuple[
                                  dict[str, dict[str, Any]], list[str]]:
    result_ids: list[str] = []
    event_info: dict[str, dict[str, Any]] = {}
    for result in results:
        result_id = result.get("result_id")
        if not isinstance(result_id, str) or not result_id:
            raise AssertionError("event_result_id_missing")
        if result_id in result_ids:
            raise AssertionError("event_result_id_duplicate")
        result_ids.append(result_id)
        event_id = _result_event_id(result)
        if event_id not in payload_manifest:
            raise AssertionError(f"unexpected_or_missing_event:{event_id!r}")
        if event_id in event_info:
            raise AssertionError(f"event_id_duplicate:{event_id}")
        exposed_sha = _find_payload_sha(result)
        wanted_sha = payload_manifest[event_id]["payload_sha256"]
        if exposed_sha != wanted_sha:
            raise AssertionError(f"event_payload_sha_mismatch:{event_id}")
        expected_for_event = expected if event_id == selected_event_id else None
        info = _assert_b04(result, installation, before, expected_for_event,
                           wanted_sha, delivered=True,
                           label=f"event_{event_id.rsplit(':', 1)[-1]}")
        details = info["fields"].get("details")
        if not isinstance(details, Mapping) or details.get("status") != "known":
            raise AssertionError(f"visible_event_details_not_known:{event_id}")
        event_info[event_id] = info
    expected_ids = set(payload_manifest)
    if set(event_info) != expected_ids:
        raise AssertionError(
            f"visible_event_set_mismatch:{sorted(event_info)}:{sorted(expected_ids)}")
    if selected_event_id not in event_info:
        raise AssertionError("selected_event_must_occur_exactly_once")
    return event_info, result_ids


def _expected_native(expected: Any) -> Mapping[str, Any] | None:
    if not isinstance(expected, Mapping):
        return None
    direct = expected.get("native_text")
    if isinstance(direct, Mapping):
        return direct
    details = expected.get("details")
    if isinstance(details, Mapping):
        direct = details.get("native_text")
        if direct is None and isinstance(details.get("value"), Mapping):
            direct = details["value"].get("native_text")
        if isinstance(direct, Mapping):
            return direct
    if any(name in expected for name in (
            "text_fields", "definition_key", "auxiliary_text",
            "title_helper_candidate", "line1_text", "metadata")):
        return expected
    return None


def _compare_expected_native(actual: Mapping[str, Any] | None,
                             expected: Any) -> None:
    wanted = _expected_native(expected)
    if wanted is None:
        return
    if actual is None:
        raise AssertionError("expected_native_text_missing")
    wanted_fields = wanted.get("text_fields")
    if not isinstance(wanted_fields, Mapping):
        wanted_fields = {name: wanted[name] for name in (
            "definition_key", "auxiliary_text", "title_helper_candidate", "line1_text")
                         if name in wanted}
    actual_fields = actual.get("text_fields")
    if not isinstance(actual_fields, Mapping):
        actual_fields = {name: actual[name] for name in (
            "definition_key", "auxiliary_text", "title_helper_candidate", "line1_text")
                       if name in actual}
    if isinstance(wanted_fields, Mapping) and isinstance(actual_fields, Mapping):
        for name, expected_field in wanted_fields.items():
            if not isinstance(expected_field, Mapping):
                continue
            actual_field = actual_fields.get(name)
            if not isinstance(actual_field, Mapping):
                raise AssertionError(f"expected_native_field_missing:{name}")
            for key in ("status", "raw_hex", "source"):
                if key in expected_field and actual_field.get(key) != expected_field[key]:
                    raise AssertionError(f"expected_native_field_mismatch:{name}:{key}")
    for key in ("metadata", "codec", "complete"):
        if key in wanted and key != "metadata" and actual.get(key) != wanted[key]:
            raise AssertionError(f"expected_native_{key}_mismatch")
    if isinstance(wanted.get("metadata"), Mapping):
        actual_meta = actual.get("metadata")
        if not isinstance(actual_meta, Mapping):
            raise AssertionError("expected_native_metadata_missing")
        for section, expected_section in wanted["metadata"].items():
            if not isinstance(expected_section, Mapping):
                continue
            actual_section = actual_meta.get(section)
            if not isinstance(actual_section, Mapping):
                raise AssertionError(f"expected_native_metadata_section_missing:{section}")
            for key, value in expected_section.items():
                if key in {"value", "raw_flag_8c", "raw_flag_8d", "status", "state"}:
                    if actual_section.get(key) != value:
                        raise AssertionError(f"expected_native_metadata_mismatch:{section}:{key}")


def _assert_b04(result: Mapping[str, Any], installation: Mapping[str, Any],
                before: Mapping[str, Any], expected: Any, payload_sha: str,
                *, delivered: bool, label: str) -> dict[str, Any]:
    _context_assert(result, installation, before)
    fields = _field_map(result, delivered=delivered)
    details = fields["details"]
    native = _native_from_details(details)
    _compare_expected_native(native, expected)
    exposed_sha = _find_payload_sha(result)
    if exposed_sha is not None and exposed_sha != payload_sha:
        raise AssertionError(f"{label}_payload_sha_mismatch")
    if fields["raw_text"].get("status") == "unsupported":
        reason = fields["raw_text"].get("reason")
        if not isinstance(reason, str) or not reason:
            raise AssertionError(f"{label}_raw_text_unsupported_reason_missing")
    return {"fields": fields, "native_text": native,
            "payload_sha256_exposed": exposed_sha,
            "raw_text_status": fields["raw_text"].get("status"),
            "native_text_present": native is not None}


def _resume_response(path: Path, query: dict[str, Any]) -> tuple[dict[str, Any], str]:
    value = _read_json(path)
    if not isinstance(value, Mapping):
        raise AcceptanceUnavailable("resume_query_not_object")
    response = value.get("response") if isinstance(value.get("response"), Mapping) else value
    request = value.get("request")
    if not isinstance(request, Mapping):
        companion = path.with_name("query-request.json")
        request = _read_json(companion) if companion.is_file() else None
    request_id = request.get("request_id") if isinstance(request, Mapping) else None
    queries = request.get("queries") if isinstance(request, Mapping) else None
    if queries != [query]:
        raise AcceptanceUnavailable("resume_query_shape_mismatch")
    if not isinstance(response, dict) or not isinstance(request_id, str) or not request_id:
        raise AcceptanceUnavailable("resume_query_response_or_id_missing")
    return response, request_id


def _resume_report_response(path: Path, query: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    value = _read_json(path)
    if not isinstance(value, Mapping):
        raise AcceptanceUnavailable("resume_report_query_not_object")
    response = value.get("response") if isinstance(value.get("response"), Mapping) else value
    request = value.get("request")
    if not isinstance(request, Mapping):
        for name in ("report-query-request.json", "report-config.json"):
            candidate = path.with_name(name)
            if candidate.is_file():
                request = _read_json(candidate)
                break
    report_id = response.get("report_id") if isinstance(response, Mapping) else None
    request_id = response.get("request_id") if isinstance(response, Mapping) else None
    if isinstance(request, Mapping):
        request_id = request.get("request_id", request_id)
        if isinstance(request.get("queries"), list) and request["queries"] != [query]:
            raise AcceptanceUnavailable("resume_report_query_shape_mismatch")
        report_id = request.get("report_id", report_id)
    if not isinstance(response, dict) or not isinstance(report_id, str) or not report_id:
        raise AcceptanceUnavailable("resume_report_id_missing")
    if not isinstance(request_id, str) or not request_id:
        raise AcceptanceUnavailable("resume_report_query_id_missing")
    return response, request_id, report_id


def _unavailable(output: Path, error: Exception, inputs: Mapping[str, Any]) -> int:
    if output.exists():
        raise AssertionError(f"refusing_to_overwrite_output:{output}")
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "schema": "information_battle_native_text_live_acceptance.v3",
        "status": "unavailable", "mode": "live", "mcp_started": False,
        "inputs": dict(inputs),
        "error": {"type": type(error).__name__, "message": str(error)},
        "limitations": ["No MCP server was started; this is not a passed acceptance."],
    }
    _write_exclusive(output / "report.json", report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 1


def run(installation_path: Path, database: Path, battle_stream: Path, event_id: str,
        output: Path, *, expected: Path | None = None, payload: Path | None = None,
        resume_query: Path | None = None,
        resume_report_query: Path | None = None) -> int:
    output = output.resolve()
    inputs = {"installation": str(installation_path), "database": str(database),
              "battle_stream": str(battle_stream), "event_id": event_id,
              "expected": str(expected) if expected else None,
              "payload": str(payload) if payload else None}
    if output.exists():
        raise AssertionError(f"refusing_to_overwrite_output:{output}")
    try:
        installation = _load_installation(installation_path.resolve(strict=True))
        database = database.resolve(strict=True)
        generated_stream, binding = _load_stream(
            battle_stream.resolve(strict=True), database, installation)
        message_id = _event_parts(event_id, binding)
        row = _database_payload_pin(database, binding, message_id)
        pin = _independent_pin(expected.resolve(strict=True) if expected else None,
                               payload.resolve(strict=True) if payload else None,
                               row, event_id)
        payload_manifest = _verify_expected_payloads(database, binding)
        if event_id not in payload_manifest:
            raise AcceptanceUnavailable("selected_event_not_in_visible_payload_manifest")
    except (OSError, ValueError, TypeError, sqlite3.Error, AcceptanceUnavailable) as error:
        return _unavailable(output, error, inputs)

    output.mkdir(parents=True, exist_ok=False)
    namespace = _request_namespace(output)
    config_path = output / "battle-stream.json"
    _write_exclusive(config_path, generated_stream)
    report: dict[str, Any] = {
        "schema": "information_battle_native_text_live_acceptance.v3",
        "status": "running", "mode": "live", "mcp_started": False,
        "text_origin": "native_observer_payload",
        "native_game_capture": True, "business_actions_submitted": 0,
        "save_restart_or_date_advance": False, "line1_or_title_required": False,
        "request_namespace": namespace, "request_ids": {}, "checks": {},
        "inputs": inputs,
        "identity": {key: installation[key] for key in (
            "pid", "creation_filetime", "session_id", "game_sha256", "dll_sha256")},
        "binding": {key: binding.get(key) for key in (
            "installation", "generation", "observer_ref", "session_id",
            "process_creation_filetime", "mode")},
        "payload_pin": {key: pin[key] for key in (
            "event_id", "payload_sha256", "payload_bytes", "database_row",
            "expected_path", "payload_path")},
        "visible_payload_manifest": payload_manifest,
        "config": {"path": str(config_path), "sha256": _sha_file(config_path)},
        "query_reused_offline": resume_query is not None,
        "report_query_reused_offline": resume_report_query is not None,
        "event_results": 0,
        "periodic_results": 0,
    }
    client: CheckedClient | None = None
    subscription: dict[str, Any] | None = None
    before: dict[str, Any] | None = None
    try:
        before = control_snapshot(installation["pid"], output / "before-control.json")
        client = CheckedClient(installation["path"], output,
                               extra_args=["--battle-stream", str(config_path)])
        report["mcp_started"] = True
        discovery = client.call("information_discover")
        _write_exclusive(output / "discovery.json", discovery)
        topic = next((item for item in discovery.get("topics", [])
                      if isinstance(item, Mapping) and item.get("topic_id") == "B04"), None)
        if not isinstance(topic, Mapping):
            raise AssertionError("B04_not_discoverable")
        fields_meta = topic.get("fields")
        if not isinstance(fields_meta, Mapping) or "details" not in fields_meta or "raw_text" not in fields_meta:
            raise AssertionError("B04_details_or_raw_text_not_discoverable")
        if "query" not in topic.get("triggers", []) or "event" not in topic.get("triggers", []):
            raise AssertionError("B04_query_event_triggers_missing")
        report["checks"]["B04_details_raw_text_query_and_event_discovered"] = True

        query = {"topic": "B04", "object": {"type": "battle"},
                 "fields": ["details", "raw_text"],
                 "parameters": {"event_id": event_id}}
        query_id = _request_id(namespace, "query")
        if resume_query is not None:
            query_result, query_id = _resume_response(resume_query.resolve(strict=True), query)
            query_source = "resumed_original"
        else:
            query_result = client.call("information_query", request_id=query_id, queries=[query])
            query_source = "new_live_query"
        _write_exclusive(output / "query-request.json", {
            "tool": "information_query", "request_id": query_id,
            "queries": [query], "source": query_source,
            "resume_path": str(resume_query) if resume_query else None,
        })
        _write_exclusive(output / "query.json", query_result)
        query_info = _assert_b04(query_result, installation, before,
                                 pin.get("expected"), pin["payload_sha256"],
                                 delivered=False, label="query")
        report["request_ids"]["query"] = query_id
        report["query"] = query_info
        report["checks"]["query_saved_then_native_projection_checked"] = True

        subscription_query = {"topic": "B04", "object": {"type": "battle"},
                              "fields": ["details", "raw_text"],
                              "parameters": {}}
        _write_exclusive(output / "report-config-request.json", {
            "tool": "information_manage_report", "request_id": _request_id(namespace, "report-create"),
            "operation": "create", "config": {
                "name": "live native battle text all visible events", "detail": "raw",
                "queries": [subscription_query]},
        })
        config_result = client.call(
            "information_manage_report", request_id=_request_id(namespace, "report-create"),
            operation="create", config={
                "name": "live native battle text all visible events", "detail": "raw",
                "queries": [subscription_query]},
        )
        _write_exclusive(output / "report-config.json", config_result)
        saved_report = config_result.get("report")
        if not isinstance(saved_report, Mapping) or not isinstance(saved_report.get("id"), str):
            raise AssertionError("report_id_missing")
        report_id = saved_report["id"]
        report_query_id = _request_id(namespace, "report-query")
        if resume_report_query is not None:
            report_result, old_report_query_id, old_report_id = _resume_report_response(
                resume_report_query.resolve(strict=True), query)
            report_query_id = old_report_query_id
            report_query_source = "resumed_original"
        else:
            report_result = client.call("information_query", request_id=report_query_id,
                                        report_id=report_id)
            old_report_id = report_id
            report_query_source = "new_live_report_query"
        _write_exclusive(output / "report-query-request.json", {
            "tool": "information_query", "request_id": report_query_id,
            "report_id": old_report_id, "new_report_id": report_id,
            "source": report_query_source,
            "resume_path": str(resume_report_query) if resume_report_query else None,
        })
        _write_exclusive(output / "report-query.json", report_result)
        report_info = _assert_b04(report_result, installation, before,
                                  pin.get("expected"), pin["payload_sha256"],
                                  delivered=False, label="report_query")
        report["request_ids"]["report_query"] = report_query_id
        report["report"] = report_info
        report["report_id"] = report_id
        report["subscription_query"] = subscription_query
        report["checks"]["report_query_saved_then_native_projection_checked"] = True
        report["checks"]["subscription_report_has_no_event_selector"] = True

        created = client.call(
            "information_manage_subscription", request_id=_request_id(namespace, "event-create"),
            operation="create", config={
                "name": "live native battle event", "kind": "event",
                "report_id": report_id, "enabled": True,
                "binding": {"session_id": installation["session_id"],
                             "observer": "FRA", "game_version": GAME_VERSION,
                             "game_sha256": GAME_SHA256},
                "event": {"types": ["battle_observation"]},
            })
        _write_exclusive(output / "subscription-create.json", created)
        subscription = created.get("subscription")
        if not isinstance(subscription, Mapping) or subscription.get("state") != "active":
            raise AssertionError("event_subscription_not_active")
        report["request_ids"]["event_create"] = _request_id(namespace, "event-create")
        listed_before = client.call("information_list_results", limit=100)
        _write_exclusive(output / "event-results-before-tick.json", listed_before)
        first_tick = client.call("information_tick")
        _write_exclusive(output / "event-tick.json", first_tick)
        listed = client.call("information_list_results", limit=100)
        _write_exclusive(output / "event-results.json", listed)
        event_results = _subscription_results(listed, subscription["id"])
        event_info, event_result_ids = _assert_visible_event_set(
            event_results, installation=installation, before=before,
            expected=pin.get("expected"), selected_event_id=event_id,
            payload_manifest=payload_manifest)
        selected_info = event_info[event_id]
        query_sha = query_info.get("payload_sha256_exposed")
        if query_sha != pin["payload_sha256"]:
            raise AssertionError("selected_query_payload_sha_missing_or_mismatch")
        if selected_info.get("payload_sha256_exposed") != query_sha:
            raise AssertionError("selected_event_query_payload_mismatch")
        if query_info["native_text"] is not None and selected_info["native_text"] is not None:
            if query_info["native_text"] != selected_info["native_text"]:
                raise AssertionError("query_event_native_text_mismatch")
        report["event_results"] = len(event_results)
        report["event_result_ids"] = event_result_ids
        report["event_ids"] = sorted(event_info)
        report["event"] = selected_info
        report["checks"]["all_visible_events_delivered_and_payloads_bound"] = True
        report["checks"]["selected_event7_occurs_once_and_matches_query"] = True
        second_tick = client.call("information_tick")
        _write_exclusive(output / "event-tick-repeat.json", second_tick)
        listed_repeat = client.call("information_list_results", limit=100)
        _write_exclusive(output / "event-results-after-repeat.json", listed_repeat)
        event_results_repeat = _subscription_results(listed_repeat, subscription["id"])
        repeat_info, repeat_result_ids = _assert_visible_event_set(
            event_results_repeat, installation=installation, before=before,
            expected=pin.get("expected"), selected_event_id=event_id,
            payload_manifest=payload_manifest)
        if set(repeat_result_ids) != set(event_result_ids):
            raise AssertionError("event_tick_result_id_set_changed")
        if set(repeat_info) != set(event_info):
            raise AssertionError("event_tick_event_id_set_changed")
        report["checks"]["next_tick_preserves_complete_result_id_set"] = True

        cancelled = client.call(
            "information_manage_subscription", request_id=_request_id(namespace, "event-cancel"),
            operation="cancel", subscription_id=subscription["id"],
            expected_version=subscription["version"])
        _write_exclusive(output / "subscription-cancel.json", cancelled)
        subscription = cancelled.get("subscription", subscription)
        listed_after = client.call(
            "information_manage_subscription", request_id=_request_id(namespace, "subscription-list"),
            operation="list")
        _write_exclusive(output / "subscriptions-after.json", listed_after)
        if any(item.get("state") == "active" for item in listed_after.get("subscriptions", [])):
            raise AssertionError("active_subscription_after_cancel")
        report["checks"]["event_cancelled_and_no_active_subscription"] = True
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if client is not None:
            try:
                if subscription is not None and subscription.get("state") == "active":
                    try:
                        client.call(
                            "information_manage_subscription", request_id=_request_id(namespace, "cleanup-cancel"),
                            operation="cancel", subscription_id=subscription["id"],
                            expected_version=subscription["version"])
                    except Exception as error:
                        report["cleanup_cancel_error"] = str(error)
            finally:
                try:
                    client.close()
                except Exception as error:
                    report["status"] = "failed"
                    report["cleanup_close_error"] = str(error)
                report["server_exit_code"] = client.process.returncode
        if before is not None:
            try:
                after = control_snapshot(installation["pid"], output / "after-control.json")
                report["control_after"] = after
                report["checks"]["date_pause_speed_player_preserved"] = all(
                    before.get(key) == after.get(key)
                    for key in ("date_raw", "paused_flag", "speed", "player_slot"))
                if not report["checks"]["date_pause_speed_player_preserved"]:
                    report["status"] = "failed"
            except Exception as error:
                report["status"] = "failed"
                report["after_control_error"] = str(error)
        _write_exclusive(output / "report.json", report)
    print(json.dumps({"status": report["status"], "output": str(output),
                      "checks": report["checks"],
                      "event_results": report["event_results"]},
                     ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="start the live read-only acceptance")
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--battle-stream", type=Path)
    parser.add_argument("--event-id")
    parser.add_argument("--expected", type=Path,
                        help="independent expected JSON containing event/payload pin")
    parser.add_argument("--payload", type=Path,
                        help="independent payload binary or JSON pin")
    parser.add_argument("--resume-query", type=Path)
    parser.add_argument("--resume-report-query", type=Path)
    parser.add_argument("--output", type=Path,
                        default=STAGE / "live-acceptance-003")
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"status": "inert", "run": False}, sort_keys=True))
        return 0
    missing = [name for name, value in (
        ("installation", args.installation), ("database", args.database),
        ("battle-stream", args.battle_stream), ("event-id", args.event_id))
               if value is None]
    if missing:
        parser.error("--run requires " + ", ".join("--" + item for item in missing))
    if args.expected is None and args.payload is None:
        parser.error("--run requires --expected or --payload")
    try:
        return run(args.installation, args.database, args.battle_stream, args.event_id,
                   args.output, expected=args.expected, payload=args.payload,
                   resume_query=args.resume_query,
                   resume_report_query=args.resume_report_query)
    except (OSError, ValueError, RuntimeError, AcceptanceUnavailable) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
