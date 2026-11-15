"""Independent v23 retained-result cross-check reader.

This module is deliberately narrower than the historical v22 reader.  It
opens one already-authorized process with QUERY_INFORMATION|VM_READ, performs
two paused, pair-scoped passes, and exposes only the copied retained-result
fields needed for comparison with the immutable raw observation.  It never
invokes a game function, writes process memory, sends a control command, or
publishes an InformationService value.

The retained reader and the raw observation describe different layers.  In
particular, ``retained_raw_date`` and the raw wire observation's ``raw_date``
are retained as diagnostic values; ``date`` is populated only from the
history/event date produced by the audited retained reader.  A missing match
is reported as unmatched evidence rather than a failure or a claim that all
natural battle results were retained.
"""
from __future__ import annotations

import copy
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from work import information_battle_war_memory as _war
from work import probe_information_battle_v23 as _v23


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INSTALLATION = _v23.DEFAULT_INSTALLATION
DEFAULT_RAW_REFERENCE = ROOT / "work" / "runtime" / "information-battle-live-20261025-001" / "raw-after-window-002.json"
DEFAULT_OUTPUT = ROOT / "work" / "runtime" / "information-battle-live-20261025-001" / "retained-live-001" / "report.json"

RAW_REFERENCE_SHA256 = "06c674404eea9407900e438a86a71aae1e03b34986a0d562447f7e3383405318"
EXPECTED_VERSION = _v23.EXPECTED_VERSION
EXPECTED_EXE_SHA256 = _v23.EXPECTED_EXE_SHA256
EXPECTED_DLL_SHA256 = _v23.EXPECTED_DLL_SHA256
EXPECTED_MANIFEST_SHA256 = _v23.EXPECTED_MANIFEST_SHA256
EXPECTED_SOURCE_COUNT = _v23.EXPECTED_SOURCE_COUNT
EXPECTED_PLAYER_TAG = "POR"
MAX_PAIRS = 2
MAX_RESULTS = _war.MAX_RESULTS
MAX_TOTAL_RPM = _war.MAX_TOTAL_RPM
MAX_SINGLE_RPM = _war.MAX_SINGLE_RPM
MAX_RAW_BYTES = 8 * 1024 * 1024
ALLOWED_PAIRS: tuple[tuple[str, str], ...] = (("FRA", "BRE"), ("TYR", "CNN"))

# These are aliases to audited helpers.  The v22 module's constants are never
# changed or patched; only its bounded reader and retained snapshot routine
# are reused.  v23 identity/code helpers are independent of those constants.
AddressBoundedRPM = _war.AddressBoundedRPM
_snapshot = _war._snapshot
_retained_snapshot = _snapshot
_context_snapshot = _v23._snapshot
_load_document = _v23._load_document
_configure_kernel = _v23._loc._configure_kernel
_capture_identity = _v23._capture_identity
_query_loaded_dll = _v23._query_module_records
_runtime_code_guard = _v23._runtime_code_guard
_file_code_guard = _v23._file_code_guard
_manifest_static_guard = _v23._manifest_static_guard
_coff_symbol = _v23._coff_symbol
_close_process_handle = _v23._loc._close_process_handle
_sha256_file = _v23._sha256_file
_configured_game_exe = _v23._configured_game_exe


class ProbeError(RuntimeError):
    """A bounded cross-check cannot be completed safely."""


def _copy(value: Any) -> Any:
    return copy.deepcopy(value)


def _new_report(installation: Path, pairs: Sequence[tuple[str, str]], limit: int, expect_patch: str) -> dict[str, Any]:
    return {
        "schema": "information_battle_live_retained_crosscheck_v1",
        "probe": "information-battle-live-retained-crosscheck",
        "probe_version": 1,
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "read_only": True,
        "native_function_invoked": False,
        "control_command_sent": False,
        "game_access": False,
        "source_semantics": "v23_paused_query_only_retained_subset",
        "retained_subset_only": True,
        "all_natural_results_captured": False,
        "visibility_verified": False,
        "request": {
            "installation": str(installation),
            "pairs": [{"actor": a, "recipient": b} for a, b in pairs],
            "limit": limit,
            "max_pairs": MAX_PAIRS,
            "expect_patch": expect_patch,
            "raw_reference": str(DEFAULT_RAW_REFERENCE),
        },
        "target_build": {
            "version": EXPECTED_VERSION,
            "expected_exe_sha256": EXPECTED_EXE_SHA256,
            "expected_v23_dll_sha256": EXPECTED_DLL_SHA256,
            "expected_manifest_sha256": EXPECTED_MANIFEST_SHA256,
            "expected_source_count": EXPECTED_SOURCE_COUNT,
            "image_base": hex(_v23.EXPECTED_IMAGE_BASE),
        },
        "provenance": {
            "installation": None,
            "static_manifest": None,
            "executable": None,
            "loaded_dll": {"before": None, "after": None},
            "fixed_file_code_guard": None,
            "raw_reference": None,
        },
        "identity": {"before": None, "after": None, "binding_verified": False},
        "module_base": None,
        "stub": None,
        "runtime_code_guard": {"before": None, "after": None},
        "context": {"before": None, "after": None},
        "pairs": [],
        "doublepass": {
            "performed": False,
            "consistent": None,
            "mismatches": [],
            "all_read_bytes_compared": True,
            "read_log_before_count": 0,
            "read_log_after_count": 0,
        },
        "raw_crosscheck": None,
        "access": {
            "open_process_mask_hex": hex(_v23.PROCESS_ACCESS),
            "rpm_total_limit": MAX_TOTAL_RPM,
            "rpm_single_read_limit": MAX_SINGLE_RPM,
            "rpm_bytes_requested": 0,
            "rpm_calls": 0,
            "read_log": [],
        },
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False, "calls": 0}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _request_error(report: dict[str, Any], error: str) -> dict[str, Any]:
    report["status"] = "invalid_request"
    report["errors"].append({"stage": "request", "status": "unknown", "error": error})
    report["completed"] = True
    return report


def _validate_pairs(pairs: Any) -> tuple[tuple[str, str], ...]:
    if pairs is None:
        return ALLOWED_PAIRS
    if isinstance(pairs, (str, bytes, bytearray)) or not isinstance(pairs, Sequence):
        raise ProbeError("pairs_must_be_sequence")
    if len(pairs) < 1 or len(pairs) > MAX_PAIRS:
        raise ProbeError("pairs_count_out_of_bound")
    output: list[tuple[str, str]] = []
    for item in pairs:
        if isinstance(item, Mapping):
            actor, recipient = item.get("actor"), item.get("recipient")
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)) and len(item) == 2:
            actor, recipient = item
        else:
            raise ProbeError("pair_shape_invalid")
        if not isinstance(actor, str) or not isinstance(recipient, str):
            raise ProbeError("pair_tag_type_invalid")
        if (actor, recipient) not in ALLOWED_PAIRS:
            raise ProbeError("pair_not_in_fixed_scope")
        if (actor, recipient) in output:
            raise ProbeError("pair_duplicate")
        output.append((actor, recipient))
    return tuple(output)


def _strip_phase(value: Any) -> Any:
    """Remove only pass/phase labels before comparing two observations."""
    value = _copy(value)
    if isinstance(value, dict):
        value.pop("phase", None)
        value.pop("pass", None)
        value.pop("read_log", None)
        for key in list(value):
            value[key] = _strip_phase(value[key])
    elif isinstance(value, list):
        value = [_strip_phase(item) for item in value]
    return value


def _diff(left: Any, right: Any, path: str = "$") -> list[str]:
    if type(left) is not type(right):
        return [path]
    if isinstance(left, dict):
        out: list[str] = []
        for key in sorted(set(left) | set(right)):
            if key not in left or key not in right:
                out.append(f"{path}.{key}")
            else:
                out.extend(_diff(left[key], right[key], f"{path}.{key}"))
        return out
    if isinstance(left, list):
        out: list[str] = []
        if len(left) != len(right):
            out.append(f"{path}.length")
        for index, (a, b) in enumerate(zip(left, right)):
            out.extend(_diff(a, b, f"{path}[{index}]"))
        return out
    return [] if left == right else [path]


def _normalized_read_log(entries: Sequence[Any]) -> list[Any]:
    """Compare every RPM byte/address while ignoring only the pass label."""
    out: list[Any] = []
    for entry in entries:
        item = _copy(entry)
        if isinstance(item, dict) and isinstance(item.get("label"), str):
            for prefix in ("before.", "after."):
                if item["label"].startswith(prefix):
                    item["label"] = item["label"][len(prefix):]
                    break
        out.append(item)
    return out


def _tag_from_raw(raw_hex: Any) -> str | None:
    if not isinstance(raw_hex, str):
        return None
    try:
        if len(raw_hex) != 16:
            return None
        value = int(raw_hex, 16)
    except (TypeError, ValueError):
        return None
    try:
        return _war._tag(value)
    except Exception:
        return None


def _sso_copy(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    length = value.get("length")
    raw_hex = value.get("raw_hex")
    if raw_hex is None:
        raw_hex = value.get("bytes_hex")
    if raw_hex is None and isinstance(value.get("payload_raw_hex"), str) and isinstance(length, int):
        raw_hex = value["payload_raw_hex"][: max(0, length) * 2]
    if not isinstance(length, int) or isinstance(length, bool) or length < 0 or not isinstance(raw_hex, str):
        return None
    try:
        if len(raw_hex) != length * 2 or bytes.fromhex(raw_hex).hex() != raw_hex.lower():
            return None
    except ValueError:
        return None
    # Text is intentionally not decoded.  Both retained String32 and wire
    # strings are normalized to their copied payload bytes only.
    return {"length": length, "raw_hex": raw_hex.lower()}


def _numeric_ref(value: Any, raw_identity_hex: Any = None) -> str | None:
    """Return a canonical 16-digit numeric handle, independent of byte order."""
    try:
        if isinstance(value, str):
            try:
                number = int(value, 0)
            except ValueError:
                # Some recorded readers omit the ``0x`` prefix.  A fixed
                # 16-hex value is still a numeric reference, not LE bytes.
                if len(value) != 16:
                    return None
                number = int(value, 16)
        elif isinstance(value, int) and not isinstance(value, bool):
            number = value
        elif isinstance(raw_identity_hex, str):
            raw = bytes.fromhex(raw_identity_hex)
            if len(raw) != 8:
                return None
            number = int.from_bytes(raw, "little")
        else:
            return None
        if number < 0 or number >= 1 << 64:
            return None
        return f"{number:016x}"
    except (TypeError, ValueError):
        return None


def _country_copy(side: Any) -> dict[str, Any] | None:
    if not isinstance(side, Mapping):
        return None
    country = side.get("country")
    if not isinstance(country, Mapping):
        return None
    reference = None
    for key in ("identity", "handle"):
        candidate = country.get(key)
        if candidate is None:
            continue
        reference = _numeric_ref(candidate)
        if reference is not None:
            break
    if reference is None:
        reference = _numeric_ref(None, country.get("identity_raw_hex"))
    if reference is None:
        return None
    return {"ref": reference, "tag": country.get("tag")}


def _side_raw_fields(side: Any) -> list[int | None]:
    fields = side.get("fields") if isinstance(side, Mapping) else None
    result: list[int | None] = []
    for field, _offset in _war.SIDE_SCALAR_OFFSETS:
        value = fields.get(field) if isinstance(fields, Mapping) else None
        if isinstance(value, Mapping):
            value = value.get("raw")
        result.append(value if isinstance(value, int) and not isinstance(value, bool) else None)
    return result


def _wire_raw_fields(value: Any) -> list[int] | None:
    """Validate the wire's fixed nine-slot scalar vector without naming it."""
    if not isinstance(value, list) or len(value) != len(_war.SIDE_SCALAR_OFFSETS):
        return None
    if any(not isinstance(item, int) or isinstance(item, bool) for item in value):
        return None
    return list(value)


def _retained_field_copy(result: Any, pair: tuple[str, str], *, index: int) -> dict[str, Any]:
    result = result if isinstance(result, Mapping) else {}
    side_a = _country_copy(result.get("side_a"))
    side_b = _country_copy(result.get("side_b"))
    countryrefs = [item for item in (side_a, side_b) if item is not None]
    sides = (result.get("side_a"), result.get("side_b"))
    commander = [_sso_copy(side.get("commander")) if isinstance(side, Mapping) else None for side in sides]
    raw_fields = [_side_raw_fields(side) for side in sides]
    province = result.get("province_id")
    if isinstance(province, Mapping):
        province_copy: Any = province.get("raw") if isinstance(province.get("raw"), int) else None
    else:
        province_copy = province if isinstance(province, int) and not isinstance(province, bool) else None
    timeline = result.get("timeline_date")
    date_copy = _copy(timeline) if isinstance(timeline, Mapping) else None
    raw_date = _copy(result.get("raw_date")) if "raw_date" in result else None
    return {
        "pair": {"actor": pair[0], "recipient": pair[1]},
        "result_index": index,
        "countryrefs": countryrefs,
        "name": _sso_copy(result.get("name")),
        "commander": commander,
        "province": province_copy,
        "raw_fields": raw_fields,
        "raw_count": len(_war.SIDE_SCALAR_OFFSETS),
        "aux_raw": [
            result.get("aux", {}).get("first", {}).get("raw") if isinstance(result.get("aux"), Mapping) else None,
            result.get("aux", {}).get("second", {}).get("raw") if isinstance(result.get("aux"), Mapping) else None,
        ],
        "flag_raw": result.get("flag", {}).get("raw") if isinstance(result.get("flag"), Mapping) else None,
        "date": date_copy,
        # Never alias this to date.  It is retained only as diagnostic data if
        # a future reader exposes a native result raw-date field.
        "retained_raw_date": raw_date,
        "source": "retained_result",
    }


def _retained_records(snapshot: Any, pair: tuple[str, str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not isinstance(snapshot, Mapping):
        return records
    wars = snapshot.get("wars")
    if not isinstance(wars, list):
        return records
    for war_index, war in enumerate(wars):
        if not isinstance(war, Mapping):
            continue
        collection = war.get("results")
        values = collection.get("results") if isinstance(collection, Mapping) else None
        if not isinstance(values, list):
            continue
        for result_index, result in enumerate(values):
            item = _retained_field_copy(result, pair, index=result_index)
            item["war_index"] = war_index
            records.append(item)
    return records


def _snapshot_for_report(snapshot: Any) -> dict[str, Any]:
    """Keep status/count/date evidence without a second copy of native bytes."""
    if not isinstance(snapshot, Mapping):
        return {"status": "unknown", "complete": False}
    output: dict[str, Any] = {
        "status": snapshot.get("status"),
        "complete": snapshot.get("complete"),
        "partial": snapshot.get("partial"),
        "unknown_conditions": _copy(snapshot.get("unknown_conditions", [])),
        "pair_references": _copy(snapshot.get("pair_references")),
        "wars": [],
    }
    for war in snapshot.get("wars", []) if isinstance(snapshot.get("wars"), list) else []:
        if not isinstance(war, Mapping):
            continue
        collection = war.get("results") if isinstance(war.get("results"), Mapping) else {}
        history = war.get("history") if isinstance(war.get("history"), Mapping) else {}
        output["wars"].append({
            "status": war.get("status"),
            "complete": war.get("complete"),
            "actor_side": war.get("actor_side"),
            "recipient_side": war.get("recipient_side"),
            "native_reference": war.get("native_reference"),
            "results": {
                "status": collection.get("status"),
                "complete": collection.get("complete"),
                "truncated": collection.get("truncated"),
                "count": len(collection.get("results", [])) if isinstance(collection.get("results"), list) else None,
            },
            "history": {
                "status": history.get("status"),
                "supported": history.get("supported"),
                "root_date": _copy(history.get("root_date")),
                "bound_result_dates": _copy(history.get("bound_result_dates")),
                "ambiguous_result_dates": _copy(history.get("ambiguous_result_dates")),
                "nodes_read": history.get("nodes_read"),
                "unknown_conditions": _copy(history.get("unknown_conditions", [])),
            },
        })
    return output


def _read_log_digest(entries: Sequence[Any]) -> str:
    raw = json.dumps(_normalized_read_log(entries), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _raw_record(message: Any) -> dict[str, Any] | None:
    if not isinstance(message, Mapping):
        return None
    decoded = message.get("decode")
    value = decoded.get("value") if isinstance(decoded, Mapping) else None
    observation = value.get("observation") if isinstance(value, Mapping) else None
    native = observation.get("result") if isinstance(observation, Mapping) else None
    if not isinstance(native, Mapping):
        return None
    sides = native.get("sides")
    side_list = sides if isinstance(sides, list) else []
    countryrefs: list[dict[str, Any]] = []
    commander: list[Any] = []
    for side in side_list:
        if not isinstance(side, Mapping):
            continue
        raw_country = side.get("country_raw_hex")
        if not isinstance(raw_country, str) or len(raw_country) != 16:
            return None
        try:
            country_number = int(raw_country, 16)
        except (TypeError, ValueError):
            return None
        if country_number < 0 or country_number >= 1 << 64:
            return None
        countryrefs.append({"ref": f"{country_number:016x}", "tag": _tag_from_raw(raw_country)})
        commander_value = side.get("commander")
        commander.append(_sso_copy(commander_value))
    raw_fields: list[list[int]] = []
    for side in side_list:
        if not isinstance(side, Mapping):
            return None
        slots = _wire_raw_fields(side.get("raw_fields"))
        if slots is None:
            return None
        raw_fields.append(slots)
    name = native.get("name")
    return {
        "message_id": _copy(message.get("message_id")),
        "pair": {"actor": None, "recipient": None},
        "countryrefs": countryrefs,
        "name": _sso_copy(name),
        "commander": commander,
        "province": _copy(native.get("province_id")) if isinstance(native.get("province_id"), int) and not isinstance(native.get("province_id"), bool) else None,
        "raw_fields": raw_fields,
        "raw_count": len(_war.SIDE_SCALAR_OFFSETS),
        "aux_raw": [_copy(native.get("aux100")), _copy(native.get("aux104"))],
        "flag_raw": _copy(native.get("flag108")),
        "date": None,
        # This is an observation wire field, not an event/history date.
        "raw_date": _copy(native.get("raw_date")),
        "source": "immutable_raw_observation",
    }


def _raw_crosscheck(records: Sequence[Mapping[str, Any]], raw_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "source": "immutable_raw_after_window_002",
        "path": str(raw_path),
        "expected_sha256": RAW_REFERENCE_SHA256,
        "sha256": None,
        "raw_message_count": 0,
        "raw_records": [],
        "matched": [],
        "ambiguous": [],
        "unmatched_retained": [],
        "unmatched_raw": [],
        "mismatches": [],
        "raw_date_not_used_as_date": True,
        "date_source": "retained history/event timeline_date only",
        "all_natural_results_captured": False,
    }
    try:
        size = raw_path.stat().st_size
        if size > MAX_RAW_BYTES:
            raise ProbeError("raw_reference_size_limit")
        actual = _sha256_file(raw_path).lower()
        result["sha256"] = actual
        if actual != RAW_REFERENCE_SHA256:
            raise ProbeError("raw_reference_sha256_mismatch")
        document = json.loads(raw_path.read_bytes().decode("utf-8"))
        messages = document.get("messages") if isinstance(document, Mapping) else None
        if not isinstance(messages, list):
            raise ProbeError("raw_reference_messages_missing")
        raw_records = [item for item in (_raw_record(message) for message in messages) if item is not None]
        result["raw_message_count"] = len(messages)
        result["raw_records"] = raw_records
        remaining = list(enumerate(raw_records))

        def stable_key(item: Mapping[str, Any]) -> tuple[Any, ...] | None:
            refs = tuple(sorted(str(ref.get("ref")) for ref in item.get("countryrefs", []) if isinstance(ref, Mapping) and isinstance(ref.get("ref"), str)))
            name = item.get("name") if isinstance(item.get("name"), Mapping) else {}
            province = item.get("province")
            if len(refs) != 2 or not isinstance(name.get("length"), int) or isinstance(name.get("length"), bool) or not isinstance(name.get("raw_hex"), str) or not isinstance(province, int) or isinstance(province, bool):
                return None
            return refs, name.get("length"), name.get("raw_hex"), province

        for retained_index, retained in enumerate(records):
            retained_key = stable_key(retained)
            if retained_key is None:
                result["unmatched_retained"].append({"retained_index": retained_index, "record": _copy(retained), "stable_key": None})
                continue
            candidates = [(index, candidate) for index, candidate in remaining if stable_key(candidate) == retained_key]
            if len(candidates) > 1:
                result["ambiguous"].append({"retained_index": retained_index, "candidate_raw_indices": [index for index, _ in candidates], "stable_key": _copy(retained_key)})
                continue
            if not candidates:
                result["unmatched_retained"].append({"retained_index": retained_index, "record": _copy(retained), "stable_key": _copy(retained_key)})
                continue
            raw_index, candidate = candidates[0]
            remaining = [(index, item) for index, item in remaining if index != raw_index]
            checks: dict[str, Any] = {}
            for field in ("countryrefs", "name", "commander", "province", "raw_fields", "raw_count", "aux_raw", "flag_raw"):
                checks[field] = {"equal": retained.get(field) == candidate.get(field), "retained": _copy(retained.get(field)), "raw": _copy(candidate.get(field))}
                if checks[field]["equal"] is False:
                    result["mismatches"].append({"retained_index": retained_index, "raw_index": raw_index, "field": field, "retained": _copy(retained.get(field)), "raw": _copy(candidate.get(field))})
            retained_date = retained.get("date")
            retained_date_raw = retained_date.get("raw") if isinstance(retained_date, Mapping) else None
            raw_date = candidate.get("raw_date")
            date_equal = retained_date_raw == raw_date
            checks["date"] = {
                "status": "same_value_different_source" if date_equal else "post_field_difference",
                "equal": date_equal,
                "retained_history_raw": _copy(retained_date_raw),
                "raw_wire_snapshot_raw_date": _copy(raw_date),
                "source_note": "history/event timeline_date compared to wire snapshot raw_date; neither is result object +8",
            }
            if not date_equal:
                result.setdefault("post_field_differences", []).append({"retained_index": retained_index, "raw_index": raw_index, "field": "date", "retained_history_raw": _copy(retained_date_raw), "raw_wire_snapshot_raw_date": _copy(raw_date)})
            result["matched"].append({"retained_index": retained_index, "raw_index": raw_index, "fields": checks})
        result["unmatched_raw"] = [{"raw_index": index, "record": _copy(item), "stable_key": _copy(stable_key(item))} for index, item in remaining]
        result["status"] = "observed" if result["matched"] else "unmatched_only"
        return result
    except Exception as exc:
        result["status"] = "unknown"
        result["errors"] = [{"stage": "raw_reference", "error": f"{type(exc).__name__}:{exc}"}]
        return result


def _retract(report: dict[str, Any]) -> None:
    report["pairs"] = []
    report["raw_crosscheck"] = None
    report["context"]["before"] = None
    report["context"]["after"] = None
    report["identity"]["binding_verified"] = False
    report["doublepass"]["consistent"] = False
    report["completed"] = True


def _expected_exe(document: Mapping[str, Any]) -> Path:
    declared = document.get("process_path") or document.get("game_path")
    if isinstance(declared, str) and declared:
        return Path(declared).resolve()
    return Path(_configured_game_exe()).resolve()


def _validate_installation(document: Mapping[str, Any], expected_exe: Path, build_dir: Path, report: dict[str, Any]) -> None:
    if not isinstance(document, Mapping):
        raise ProbeError("installation_document_invalid")
    if document.get("experiment_id") not in {_v23.BUILD_ID, _v23.LIVE_BUILD_ID}:
        raise ProbeError("installation_experiment_id_mismatch")
    if str(document.get("game_sha256", "")).lower() != EXPECTED_EXE_SHA256:
        raise ProbeError("installation_exe_sha256_mismatch")
    if str(document.get("dll_sha256", "")).lower() != EXPECTED_DLL_SHA256:
        raise ProbeError("installation_v23_dll_sha256_mismatch")
    pid = _v23._int(document.get("pid"), "installation_pid")
    creation = _v23._int(document.get("creation_filetime"), "installation_creation_filetime")
    session = document.get("session_id")
    if not isinstance(session, str) or session != f"{pid}-{creation:x}":
        raise ProbeError("installation_session_id_mismatch")
    if not expected_exe.is_file():
        raise ProbeError("configured_process_path_missing")
    exe_sha = _sha256_file(expected_exe).lower()
    report["provenance"]["executable"] = {"path": str(expected_exe), "sha256": exe_sha, "expected_sha256": EXPECTED_EXE_SHA256, "matches": exe_sha == EXPECTED_EXE_SHA256}
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ProbeError("executable_sha256_mismatch")
    dll_path = build_dir / _v23.DLL_PATH.name
    dll_pin = _v23._stable_file_pin(dll_path, max_bytes=16 * 1024 * 1024)
    report["provenance"]["installation"] = {
        "experiment_id": document.get("experiment_id"),
        "pid": pid,
        "creation_filetime": creation,
        "session_id": session,
        "game_sha256": str(document.get("game_sha256", "")).lower(),
        "dll_sha256": str(document.get("dll_sha256", "")).lower(),
        "modules_after_install": _copy(document.get("modules_after_install")),
    }
    report["provenance"]["installation"]["dll_file"] = dll_pin
    if dll_pin.get("sha256") != EXPECTED_DLL_SHA256:
        raise ProbeError("v23_dll_file_sha256_mismatch")
    modules = document.get("modules_after_install") or []
    expected_modules = [item for item in modules if isinstance(item, Mapping) and str(item.get("sha256", "")).lower() == EXPECTED_DLL_SHA256]
    if len(expected_modules) != 1:
        raise ProbeError("installation_loaded_dll_record_not_unique")


def capture(
    installation: Path = DEFAULT_INSTALLATION,
    pairs: Sequence[tuple[str, str]] | None = None,
    *,
    raw_reference: Path = DEFAULT_RAW_REFERENCE,
    limit: int = MAX_RESULTS,
    expect_patch: str = "installed",
    output: Path | None = None,
) -> dict[str, Any]:
    """Capture at most two fixed pairs using one v23 process handle.

    ``output`` is optional for tests; when present it is created exclusively
    and never overwritten.  The caller must supply an already-authorized v23
    installation document; this function does not launch or control a game.
    """
    installation = Path(installation)
    raw_reference = Path(raw_reference)
    try:
        pair_list = _validate_pairs(pairs)
    except Exception as exc:
        report = _new_report(installation, (), limit if isinstance(limit, int) else 0, expect_patch)
        result = _request_error(report, f"{type(exc).__name__}:{exc}")
        if output is not None:
            _write_new(Path(output), result)
        return result
    report = _new_report(installation, pair_list, limit, expect_patch)
    report["request"]["raw_reference"] = str(raw_reference)
    try:
        report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    except Exception as exc:
        report["errors"].append({"stage": "probe_identity", "error": f"{type(exc).__name__}:{exc}"})
    if expect_patch not in {"original", "installed"}:
        return _request_error(report, "expect_patch_must_be_original_or_installed")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_RESULTS:
        return _request_error(report, f"limit_must_be_integer_1..{MAX_RESULTS}")
    kernel: Any = None
    handle: Any = None
    reader: Any = None
    try:
        document, install_pin = _load_document(installation)
        build_dir = installation.resolve().parent
        expected_exe = _expected_exe(document)
        _validate_installation(document, expected_exe, build_dir, report)
        report["provenance"]["installation_file"] = _copy(install_pin)
        static_manifest = _manifest_static_guard(build_dir)
        report["provenance"]["static_manifest"] = _copy(static_manifest)
        if static_manifest.get("status") != "observed":
            raise ProbeError("v23_static_manifest_guard_failed")
        file_guard = _file_code_guard(expected_exe)
        report["provenance"]["fixed_file_code_guard"] = _copy(file_guard)
        if file_guard.get("status") != "observed":
            raise ProbeError("v23_fixed_file_code_guard_failed")
        dll_path = build_dir / _v23.DLL_PATH.name
        coff = _coff_symbol(dll_path)
        if coff.get("status") != "observed" or not isinstance(coff.get("rva"), str):
            raise ProbeError("v23_stub_symbol_unavailable")
        report["stub"] = _copy(coff)
        kernel = _configure_kernel()
        pid = _v23._int(document.get("pid"), "installation_pid")
        handle = kernel.OpenProcess(_v23.PROCESS_ACCESS, False, pid)
        if not handle:
            raise ProbeError("OpenProcess_failed")
        identity_before = _capture_identity(kernel, handle, document, expected_exe, "before")
        report["identity"]["before"] = _copy(identity_before)
        if identity_before.get("status") != "observed":
            raise ProbeError("v23_identity_before_failed")
        module_base = int(str(identity_before.get("module_base")), 0)
        report["module_base"] = {"value": hex(module_base), "rvas_resolved_against_runtime_base": True}
        loaded_before = _query_loaded_dll(kernel, handle, dll_path, EXPECTED_DLL_SHA256)
        report["provenance"]["loaded_dll"]["before"] = _copy(loaded_before)
        if loaded_before.get("status") != "observed" or len(loaded_before.get("matching_modules", [])) != 1:
            raise ProbeError("v23_loaded_dll_before_failed")
        dll_base = int(str(loaded_before["matching_modules"][0]["base"]), 0)
        stub_rva = int(str(coff["rva"]), 0)
        stub_va = dll_base + stub_rva
        if not _v23._safe_address(stub_va):
            raise ProbeError("v23_stub_va_invalid")
        report["stub"]["runtime_va"] = hex(stub_va)
        reader = AddressBoundedRPM(kernel, handle, module_base)
        pass_before_start = len(reader.read_log)
        runtime_before = _runtime_code_guard(reader, module_base, "before", expect_patch, stub_va)
        report["runtime_code_guard"]["before"] = _copy(runtime_before)
        if runtime_before.get("status") != "observed":
            raise ProbeError("v23_runtime_code_guard_before_failed")
        context_before = _context_snapshot(reader, module_base, "before")
        report["context"]["before"] = _copy(context_before)
        if context_before.get("status") != "observed":
            raise ProbeError("v23_context_before_failed")
        player_before = context_before.get("physical_player", {})
        control_before = context_before.get("control", {})
        if player_before.get("tag") != EXPECTED_PLAYER_TAG or player_before.get("complete") is not True:
            raise ProbeError("physical_player_not_verified_por")
        if control_before.get("status") != "observed" or control_before.get("paused", {}).get("value") is not True or control_before.get("speed", {}).get("value") != 0:
            raise ProbeError("paused_speed_zero_guard_failed")
        pass_before_reads: list[dict[str, Any]] = []
        pair_before: list[dict[str, Any]] = []
        for pair in pair_list:
            snapshot = _retained_snapshot(reader, module_base, pair[0], pair[1], limit, 1)
            pair_before.append({"pair": {"actor": pair[0], "recipient": pair[1]}, "snapshot": _copy(snapshot), "records": _retained_records(snapshot, pair)})
            if snapshot.get("status") != "observed":
                raise ProbeError(f"retained_snapshot_before_failed:{pair[0]}:{pair[1]}")
        pass_before_reads = _copy(reader.read_log[pass_before_start:])
        pass_after_start = len(reader.read_log)
        runtime_after = _runtime_code_guard(reader, module_base, "after", expect_patch, stub_va)
        report["runtime_code_guard"]["after"] = _copy(runtime_after)
        if runtime_after.get("status") != "observed":
            raise ProbeError("v23_runtime_code_guard_after_failed")
        context_after = _context_snapshot(reader, module_base, "after")
        report["context"]["after"] = _copy(context_after)
        if context_after.get("status") != "observed":
            raise ProbeError("v23_context_after_failed")
        player_after = context_after.get("physical_player", {})
        control_after = context_after.get("control", {})
        if player_after.get("tag") != EXPECTED_PLAYER_TAG or player_after.get("complete") is not True:
            raise ProbeError("physical_player_after_not_verified_por")
        if control_after.get("status") != "observed" or control_after.get("paused", {}).get("value") is not True or control_after.get("speed", {}).get("value") != 0:
            raise ProbeError("paused_speed_zero_after_guard_failed")
        if _strip_phase(context_before.get("game_date")) != _strip_phase(context_after.get("game_date")):
            raise ProbeError("game_date_changed_between_passes")
        pair_after: list[dict[str, Any]] = []
        for pair in pair_list:
            snapshot = _retained_snapshot(reader, module_base, pair[0], pair[1], limit, 2)
            pair_after.append({"pair": {"actor": pair[0], "recipient": pair[1]}, "snapshot": _copy(snapshot), "records": _retained_records(snapshot, pair)})
            if snapshot.get("status") != "observed":
                raise ProbeError(f"retained_snapshot_after_failed:{pair[0]}:{pair[1]}")
        pass_after_reads = _copy(reader.read_log[pass_after_start:])
        # Recheck identity and the loaded v23 DLL only after the second full
        # retained pass has finished, so a same-handle replacement during the
        # read cannot be mistaken for a stable observation.
        identity_after = _capture_identity(kernel, handle, document, expected_exe, "after")
        report["identity"]["after"] = _copy(identity_after)
        if identity_after.get("status") != "observed":
            raise ProbeError("v23_identity_after_failed")
        loaded_after = _query_loaded_dll(kernel, handle, dll_path, EXPECTED_DLL_SHA256)
        report["provenance"]["loaded_dll"]["after"] = _copy(loaded_after)
        if loaded_after.get("status") != "observed" or len(loaded_after.get("matching_modules", [])) != 1:
            raise ProbeError("v23_loaded_dll_after_failed")
        report["doublepass"]["performed"] = True
        report["doublepass"]["read_log_before_count"] = len(pass_before_reads)
        report["doublepass"]["read_log_after_count"] = len(pass_after_reads)
        report["context"]["before"] = _copy(context_before)
        report["context"]["after"] = _copy(context_after)
        report["pairs"] = [{"pair": item["pair"], "before": _snapshot_for_report(item["snapshot"]), "after": _snapshot_for_report(pair_after[index]["snapshot"]), "records_before": item["records"], "records_after": pair_after[index]["records"]} for index, item in enumerate(pair_before)]
        identity_before_cmp = _strip_phase(report["identity"]["before"])
        identity_after_cmp = _strip_phase(report["identity"]["after"])
        comparisons: list[str] = []
        comparisons.extend(f"$.identity{path[1:]}" for path in _diff(identity_before_cmp, identity_after_cmp))
        if _strip_phase(loaded_before) != _strip_phase(loaded_after):
            comparisons.append("$.provenance.loaded_dll")
        if _strip_phase(runtime_before) != _strip_phase(runtime_after):
            comparisons.append("$.runtime_code_guard")
        if _strip_phase(context_before) != _strip_phase(context_after):
            comparisons.append("$.context")
        if _normalized_read_log(pass_before_reads) != _normalized_read_log(pass_after_reads):
            comparisons.append("$.access.read_log")
        for index, item in enumerate(pair_before):
            if _strip_phase(item["snapshot"]) != _strip_phase(pair_after[index]["snapshot"]):
                comparisons.append(f"$.pairs[{index}].snapshot")
            if item["records"] != pair_after[index]["records"]:
                comparisons.append(f"$.pairs[{index}].records")
        identity_ok = report["identity"]["before"].get("status") == "observed" and report["identity"]["after"].get("status") == "observed" and report["identity"]["before"].get("session_id") == report["identity"]["after"].get("session_id") == document.get("session_id")
        report["identity"]["binding_verified"] = identity_ok
        report["doublepass"]["mismatches"] = comparisons[:256]
        report["doublepass"]["read_log_before_sha256"] = _read_log_digest(pass_before_reads)
        report["doublepass"]["read_log_after_sha256"] = _read_log_digest(pass_after_reads)
        report["doublepass"]["consistent"] = not comparisons and identity_ok and loaded_after.get("status") == "observed" and runtime_after.get("status") == "observed"
        if not report["doublepass"]["consistent"]:
            raise ProbeError("v23_retained_doublepass_mismatch")
        retained_records = [record for item in report["pairs"] for record in item.get("records_after", [])]
        report["raw_crosscheck"] = _raw_crosscheck(retained_records, raw_reference)
        report["status"] = "observed" if report["raw_crosscheck"].get("status") in {"observed", "unmatched_only"} else "observed_raw_reference_unknown"
    except Exception as exc:
        report["errors"].append({"stage": "capture", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
        report["status"] = "failed_read_only_crosscheck"
        _retract(report)
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
            report["access"]["read_log"] = _copy(reader.read_log)
        close = _close_process_handle(kernel, handle)
        # Count the attempted CloseHandle call even when the OS reports an
        # error; a failed cleanup must be visible and must never be retried by
        # this reader.
        close["calls"] = 1 if handle is not None else 0
        report["cleanup"]["handle_close"] = close
        if close.get("status") != "closed" and report.get("status") in {"observed", "observed_raw_reference_unknown"}:
            _retract(report)
            report["status"] = "cleanup_error"
            report["errors"].append({"stage": "cleanup", "status": "unknown", "error": "process_handle_not_closed"})
        report["completed"] = True
    if output is not None:
        _write_new(Path(output), report)
    return report


def _write_new(path: Path, value: Mapping[str, Any]) -> str:
    if path.exists():
        raise ProbeError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > 16 * 1024 * 1024:
        raise ProbeError("report_size_limit")
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_bytes(raw)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return hashlib.sha256(raw).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Cross-check a bounded v23 retained battle subset")
    parser.add_argument("--installation", type=Path, required=True, help="already-authorized v23 installation.json")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--raw-reference", type=Path, default=DEFAULT_RAW_REFERENCE)
    parser.add_argument("--expect-patch", choices=("original", "installed"), default="installed")
    args = parser.parse_args(argv)
    report = capture(args.installation, raw_reference=args.raw_reference, expect_patch=args.expect_patch, output=args.output)
    return 0 if report.get("status") in {"observed", "observed_raw_reference_unknown"} and report.get("completed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
