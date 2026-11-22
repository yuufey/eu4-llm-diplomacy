"""Bounded current bilateral opinion-modifier memory reader.

This module is a leaf for the R04 modifier capture wrapper.  It follows only
the already accepted country/relation container and the current B23 modifier
class.  It never calls a game function and it does not interpret date,
multiplier, or flag bytes as expiry/decay semantics.
"""
from __future__ import annotations

from copy import deepcopy
from functools import partial
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from . import country_reference_memory as ref
from . import foreign_country_memory as backend
from . import opinion_capture as opinion


PROFILE_FILE = Path(__file__).resolve().parent / "profiles" / "opinion-modifiers-memory-1374-v1-sampling-r1.json"
PROFILE_MAX_BYTES = 64 * 1024
SOURCE_EVIDENCE_MAX_BYTES = 256 * 1024
PROFILE_SHA256 = "005b3e92697fb5dfd099cdc10ba665b3c5557163fd2794905ce872f2b168336a"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
PROFILE_ID = "opinion-modifiers-memory-1374-v1"
SCHEMA = "information.opinion_modifiers_capture.v1"
OBSERVER = "FRA"

FIELDS = (
    "R04.opinion_modifiers.outgoing",
    "R04.opinion_modifiers.incoming",
)
FIELD_OUTGOING, FIELD_INCOMING = FIELDS
UNIT = "opinion_points"
SCALE = 1000
PERIOD = "current"
COMPLETE = False
BASIS = "native_current_bilateral_opinion_modifier_records"
VALUE_ORIGIN = "copied_native_opinion_modifier_records"

IMAGE_BASE = 0x140000000
MODIFIER_VTABLE_RVA = 0x1CCF388
MODIFIER_SERIALIZER_SLOT = 2
MODIFIER_SERIALIZER_RVA = 0x9494A0
MAX_RECORDS = 256
MAX_DIRECTION_BYTES = 196608
MAX_TOTAL_BYTES = 512 * 1024
MAX_KEY_BYTES = 128
MAX_STRING_CAPACITY = 8192
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000

_LAYOUT = {
    "holder_relation_array_offset": 0x1510,
    "relation_stride": 0x48,
    "relation_fullref_offset": 0x10,
    "manager_outer_offset": 0x308,
    "outer_pointer_offset": 0,
    "outer_count_offset": 0xC,
    "candidate_stride": 0x18,
    "candidate_entries_offset": 8,
    "candidate_count_offset": 0x14,
    "fallback_offset": 0x318,
    "selected_entries_offset": 8,
    "selected_count_offset": 0x14,
    "object_header_width": 0x18,
    "object_vtable_offset": 0,
    "object_definition_offset": 0x10,
    "object_fields_date_offset": 0x18,
    "object_fields_multiplier_offset": 0x1C,
    "object_fields_current_offset": 0x20,
    "object_fields_flag24_offset": 0x24,
    "object_fields_flag26_offset": 0x26,
    "modifier_vtable_rva": MODIFIER_VTABLE_RVA,
    "modifier_serializer_slot": MODIFIER_SERIALIZER_SLOT,
    "modifier_serializer_rva": MODIFIER_SERIALIZER_RVA,
    "max_records_per_direction": MAX_RECORDS,
    "max_direction_bytes": MAX_DIRECTION_BYTES,
    "max_total_bytes": MAX_TOTAL_BYTES,
    "max_key_bytes": MAX_KEY_BYTES,
    "max_string_capacity": MAX_STRING_CAPACITY,
    "pointer_min": MIN_USER_ADDRESS,
    "pointer_max": MAX_USER_ADDRESS_EXCLUSIVE - 1,
}


class ProfileError(RuntimeError):
    """The independent modifier profile or its pinned evidence is invalid."""


class _DirectionUnknown(ValueError):
    pass


def _same(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, Mapping):
        return set(left) == set(right) and all(_same(left[key], right[key]) for key in left)
    if isinstance(left, (list, tuple)):
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def _bounded_bytes(path: Path, limit: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if size <= 0 or size > limit:
            raise ProfileError(f"{label}_size_out_of_bound")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except (OSError, UnicodeError) as exc:
        raise ProfileError(f"{label}_read_failed") from exc
    if len(raw) != size or len(raw) > limit:
        raise ProfileError(f"{label}_read_size_changed")
    return raw


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _source_path(raw_path: Any) -> Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ProfileError("source_evidence_path_invalid")
    root = _workspace_root().resolve()
    path = (root / raw_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ProfileError("source_evidence_outside_workspace") from exc
    return path


def _validate_source_evidence(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    items = profile.get("source_evidence")
    if not isinstance(items, list) or len(items) != 1:
        raise ProfileError("source_evidence_shape_invalid")
    output: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise ProfileError("source_evidence_item_invalid")
        path = _source_path(item.get("path"))
        digest = item.get("sha256")
        expected_bytes = item.get("bytes")
        if (not isinstance(digest, str) or len(digest) != 64
                or type(expected_bytes) is not int or expected_bytes <= 0):
            raise ProfileError("source_evidence_item_invalid")
        raw = _bounded_bytes(path, SOURCE_EVIDENCE_MAX_BYTES, "source_evidence")
        if len(raw) != expected_bytes or hashlib.sha256(raw).hexdigest() != digest.lower():
            raise ProfileError("source_evidence_digest_mismatch")
        output.append({"path": path.relative_to(_workspace_root()).as_posix(),
                       "bytes": len(raw), "sha256": digest.lower(),
                       "role": item.get("role")})
    return output


def _profile_guard(profile: Mapping[str, Any]) -> dict[str, Any]:
    guards = profile.get("code_guards")
    if not isinstance(guards, list) or len(guards) != 1:
        raise ProfileError("profile_code_guards_shape_invalid")
    guard = guards[0]
    if not isinstance(guard, Mapping) or guard.get("name") != "opinion_modifier_serializer":
        raise ProfileError("profile_code_guard_invalid")
    try:
        begin = int(guard["rva"], 0)
        end = int(guard["end_rva_exclusive"], 0)
        code = bytes.fromhex(str(guard["bytes"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ProfileError("profile_code_guard_invalid") from exc
    if (begin != MODIFIER_SERIALIZER_RVA or end - begin != len(code)
            or len(code) != 263 or len(code) > 4096
            or hashlib.sha256(code).hexdigest() != guard.get("sha256")
            or guard.get("aslr_invariant") is not True):
        raise ProfileError("profile_code_guard_mismatch")
    return {"name": guard["name"], "rva": hex(begin),
            "end_rva_exclusive": hex(end), "bytes": code.hex(),
            "sha256": guard["sha256"]}


def _load_profile() -> dict[str, Any]:
    raw = _bounded_bytes(PROFILE_FILE, PROFILE_MAX_BYTES, "profile")
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ProfileError("OPINION_MODIFIERS_PROFILE_PIN")
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProfileError("OPINION_MODIFIERS_PROFILE_JSON") from exc
    if not isinstance(profile, Mapping):
        raise ProfileError("OPINION_MODIFIERS_PROFILE_SHAPE")
    if (profile.get("profile_id") != PROFILE_ID
            or profile.get("game_version") != EXPECTED_VERSION
            or profile.get("base_profile_id") != "opinion-memory-1374"
            or profile.get("base_profile_sha256") != opinion.PROFILE_SHA256
            or profile.get("observer") != OBSERVER
            or profile.get("executable", {}).get("sha256") != EXPECTED_EXE_SHA256):
        raise ProfileError("OPINION_MODIFIERS_PROFILE_BUILD")
    layout = profile.get("layout")
    if not isinstance(layout, Mapping):
        raise ProfileError("OPINION_MODIFIERS_PROFILE_LAYOUT")
    for key, expected in _LAYOUT.items():
        value = layout.get(key)
        if isinstance(expected, int):
            if isinstance(value, str):
                try:
                    value = int(value, 0)
                except ValueError as exc:
                    raise ProfileError("OPINION_MODIFIERS_PROFILE_LAYOUT") from exc
            if type(value) is not int or value != expected:
                raise ProfileError("OPINION_MODIFIERS_PROFILE_LAYOUT")
        elif value != expected:
            raise ProfileError("OPINION_MODIFIERS_PROFILE_LAYOUT")
    semantics = profile.get("semantics")
    if (not isinstance(semantics, Mapping)
            or semantics.get("fields") != list(FIELDS)
            or semantics.get("unit") != UNIT or semantics.get("scale") != SCALE
            or semantics.get("period") != PERIOD or semantics.get("complete") is not COMPLETE
            or semantics.get("basis") != BASIS
            or semantics.get("value_origin") != VALUE_ORIGIN):
        raise ProfileError("OPINION_MODIFIERS_PROFILE_SEMANTICS")
    _validate_source_evidence(profile)
    guard = _profile_guard(profile)
    base = opinion._load_profile()
    if (base.get("profile_id") != "opinion-memory-1374"
            or base.get("profile_version") != 1):
        raise ProfileError("OPINION_MODIFIERS_BASE_PROFILE")
    merged = deepcopy(base)
    merged.update({"profile_id": PROFILE_ID, "profile_version": 1,
                   "base_profile_sha256": opinion.PROFILE_SHA256,
                   "modifier_layout": deepcopy(dict(layout)),
                   "modifier_semantics": deepcopy(dict(semantics))})
    merged["code_guards"] = [*merged.get("code_guards", []), guard]
    return merged


def _address(base: int, offset: int, size: int = 1) -> int:
    value = ref._checked_add(base, offset, label="opinion_modifiers")
    ref._checked_range(value, size, label="opinion_modifiers")
    return value


def _read(reader: Any, address: int, size: int, label: str) -> bytes:
    if type(size) is not int or size <= 0 or size > 65536:
        raise ValueError("OPINION_MODIFIERS_READ_SIZE")
    raw = reader.read(address, size, label)
    if not isinstance(raw, bytes) or len(raw) != size:
        raise ValueError("OPINION_MODIFIERS_SHORT_READ")
    return raw


def _qword(reader: Any, address: int, label: str) -> int:
    return int.from_bytes(_read(reader, address, 8, label), "little")


def _i32(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=True)


class _DirectionReader:
    """Per-direction budget wrapper layered over foreign_country_memory's limiter."""

    def __init__(self, source: Any):
        self.source = source
        self.bytes_requested = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if type(size) is not int or size <= 0 or size > 65536:
            raise ValueError("OPINION_MODIFIERS_READ_SIZE")
        if self.bytes_requested + size > MAX_DIRECTION_BYTES:
            self.bytes_requested += size
            raise ValueError("OPINION_MODIFIER_DIRECTION_BUDGET")
        self.bytes_requested += size
        return self.source.read(address, size, label)


def _parse_address(value: Any) -> int:
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise ValueError("OPINION_MODIFIERS_POINTER_INVALID") from exc
    if type(value) is not int:
        raise ValueError("OPINION_MODIFIERS_POINTER_INVALID")
    ref._checked_range(value, 1, label="opinion_modifiers")
    return value


def _binding(binding: Mapping[str, Any]) -> tuple[int, int, int]:
    if not isinstance(binding, Mapping):
        raise ValueError("OPINION_MODIFIERS_BINDING_INVALID")
    pointer = _parse_address(binding.get("country_pointer"))
    fullref = binding.get("fullref")
    if isinstance(fullref, str):
        try:
            fullref = int(fullref, 0)
        except ValueError as exc:
            raise ValueError("OPINION_MODIFIERS_FULLREF_INVALID") from exc
    slot = binding.get("slot")
    if type(fullref) is not int or not 0 <= fullref <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("OPINION_MODIFIERS_FULLREF_INVALID")
    if type(slot) is not int or not 0 <= slot < 4096:
        raise ValueError("OPINION_MODIFIERS_SLOT_INVALID")
    return pointer, fullref, slot


def _common_stable(reader: Any, holder_pointer: int, relations: int,
                   relation: int, relation_before: bytes, manager: int,
                   outer_before: bytes, indexed_ref: int) -> None:
    if _qword(reader, _address(holder_pointer, 0x1510, 8), "relation_array.after") != relations:
        raise _DirectionUnknown("OPINION_MODIFIER_HEAD_CHANGED")
    relation_after = _read(reader, relation, 24, "relation.after")
    if relation_after != relation_before or int.from_bytes(relation_after[16:24], "little") != indexed_ref:
        raise _DirectionUnknown("OPINION_MODIFIER_RELATION_CHANGED")
    if _read(reader, _address(manager, 0x308, 16), 16, "outer.after") != outer_before:
        raise _DirectionUnknown("OPINION_MODIFIER_OUTER_CHANGED")


def _read_string32(reader: Any, definition: int, label: str) -> dict[str, Any]:
    header = _read(reader, _address(definition, 0x10, 0x20), 0x20, label + ".header")
    length = int.from_bytes(header[16:24], "little")
    capacity = int.from_bytes(header[24:32], "little")
    if (not 1 <= length <= MAX_KEY_BYTES or capacity > MAX_STRING_CAPACITY
            or capacity < length):
        raise _DirectionUnknown("OPINION_MODIFIER_KEY_BOUNDS")
    if capacity < 16:
        if length > 15:
            raise _DirectionUnknown("OPINION_MODIFIER_KEY_SSO_BOUNDS")
        payload = header[:16]
        raw = payload[:length]
        terminator = payload[length:length + 1]
        storage_pointer = None
    else:
        storage_pointer = int.from_bytes(header[:8], "little")
        raw_with_nul = _read(reader, _address(storage_pointer, 0, length + 1),
                             length + 1, label + ".bytes")
        raw, terminator = raw_with_nul[:-1], raw_with_nul[-1:]
    if (terminator != b"\x00" or b"\x00" in raw
            or any(byte >= 0x80 for byte in raw)):
        raise _DirectionUnknown("OPINION_MODIFIER_KEY_INVALID")
    try:
        key = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _DirectionUnknown("OPINION_MODIFIER_KEY_INVALID") from exc
    return {
        "header_raw": header,
        "storage_raw": raw,
        "storage_pointer": storage_pointer,
        "key": key,
    }


def _record_snapshot(reader: Any, base: int, pointer: int, label: str) -> dict[str, Any]:
    header = _read(reader, _address(pointer, 0, 24), 24, label + ".header")
    vtable = int.from_bytes(header[:8], "little")
    if vtable != base + MODIFIER_VTABLE_RVA:
        return {"status": "unsupported", "header": header,
                "reason": "OPINION_MODIFIER_CLASS_UNSUPPORTED"}
    slot2 = _qword(reader, _address(vtable, MODIFIER_SERIALIZER_SLOT * 8, 8),
                   label + ".serializer_slot2")
    if slot2 != base + MODIFIER_SERIALIZER_RVA:
        return {"status": "unsupported", "header": header, "slot2": slot2,
                "reason": "OPINION_MODIFIER_CLASS_UNSUPPORTED"}
    definition = int.from_bytes(header[16:24], "little")
    definition = _parse_address(definition)
    date_raw = _read(reader, _address(pointer, 0x18, 4), 4, label + ".date")
    multiplier_raw = _read(reader, _address(pointer, 0x1C, 4), 4, label + ".multiplier")
    current_raw = _read(reader, _address(pointer, 0x20, 4), 4, label + ".current")
    flag24_raw = _read(reader, _address(pointer, 0x24, 1), 1, label + ".flag24")
    flag26_raw = _read(reader, _address(pointer, 0x26, 1), 1, label + ".flag26")
    key = _read_string32(reader, definition, label + ".definition_key")
    return {
        "status": "known", "header": header, "slot2": slot2,
        "date_raw": date_raw, "multiplier_raw": multiplier_raw,
        "current_raw": current_raw, "flag24_raw": flag24_raw,
        "flag26_raw": flag26_raw, "key": key,
    }


def _record(reader: Any, base: int, pointer: int, index: int) -> dict[str, Any]:
    before = _record_snapshot(reader, base, pointer, f"modifier.record[{index}].before")
    after = _record_snapshot(reader, base, pointer, f"modifier.record[{index}].after")
    if not _same(before, after):
        raise _DirectionUnknown("OPINION_MODIFIER_RECORD_CHANGED")
    if before["status"] != "known":
        return {"status": "unknown", "reason": "OPINION_MODIFIER_CLASS_UNSUPPORTED"}
    current_raw = before["current_raw"]
    return {
        "status": "known",
        "modifier_id": before["key"]["key"],
        "current_opinion_raw": _i32(current_raw),
        "raw_hex": current_raw.hex(),
        "record_date_raw": _i32(before["date_raw"]),
        "multiplier_raw": _i32(before["multiplier_raw"]),
        "flags_raw": {
            "24": before["flag24_raw"][0],
            "26": before["flag26_raw"][0],
        },
    }


def _structural_stable(reader: Any, holder_pointer: int, relations: int,
                       relation: int, relation_before: bytes, manager: int,
                       outer_before: bytes, candidate: int, candidate_before: bytes,
                       selected: int, selected_before: bytes, entries: int,
                       pointers_before: bytes, count: int, indexed_ref: int) -> None:
    _common_stable(reader, holder_pointer, relations, relation, relation_before,
                   manager, outer_before, indexed_ref)
    if _read(reader, candidate, 24, "candidate.after") != candidate_before:
        raise _DirectionUnknown("OPINION_MODIFIER_CANDIDATE_CHANGED")
    if _read(reader, selected, 24, "selected.after") != selected_before:
        raise _DirectionUnknown("OPINION_MODIFIER_SELECTED_CHANGED")
    if count:
        after = _read(reader, _address(entries, 0, count * 8), count * 8,
                      "entry_pointers.after")
        if after != pointers_before:
            raise _DirectionUnknown("OPINION_MODIFIER_POINTERS_CHANGED")


def _direction_impl(reader: Any, base: int, holder: Mapping[str, Any],
                    indexed: Mapping[str, Any], *, record_reader: Any = None) -> dict[str, Any]:
    holder_pointer, _holder_ref, _holder_slot = _binding(holder)
    _indexed_pointer, indexed_ref, slot = _binding(indexed)
    relations = _qword(reader, _address(holder_pointer, 0x1510, 8),
                       "relation_array.before")
    relation = _address(relations, slot * 0x48, 24)
    relation_before = _read(reader, relation, 24, "relation.before")
    if int.from_bytes(relation_before[16:24], "little") != indexed_ref:
        raise _DirectionUnknown("OPINION_MODIFIER_RELATION_DIRECTION_MISMATCH")
    manager = _parse_address(int.from_bytes(relation_before[:8], "little"))
    outer_address = _address(manager, 0x308, 16)
    outer_before = _read(reader, outer_address, 16, "outer.before")
    outer_pointer = int.from_bytes(outer_before[:8], "little")
    outer_count = int.from_bytes(outer_before[12:16], "little", signed=True)
    if not 0 <= outer_count <= 4096:
        raise _DirectionUnknown("OPINION_MODIFIER_OUTER_COUNT_INVALID")
    if slot >= outer_count:
        _common_stable(reader, holder_pointer, relations, relation, relation_before,
                       manager, outer_before, indexed_ref)
        return {"status": "unknown", "reason": "OPINION_MODIFIER_CONTAINER_UNMATERIALIZED"}
    outer_pointer = _parse_address(outer_pointer)
    candidate = _address(outer_pointer, slot * 0x18, 24)
    candidate_before = _read(reader, candidate, 24, "candidate.before")
    candidate_count = int.from_bytes(candidate_before[20:24], "little", signed=True)
    if not 0 <= candidate_count <= MAX_RECORDS:
        _common_stable(reader, holder_pointer, relations, relation, relation_before,
                       manager, outer_before, indexed_ref)
        if _read(reader, candidate, 24, "candidate.after") != candidate_before:
            raise _DirectionUnknown("OPINION_MODIFIER_CANDIDATE_CHANGED")
        return {"status": "unknown", "reason": "OPINION_MODIFIER_RECORD_LIMIT"}
    selected = candidate if candidate_count else _address(manager, 0x318, 24)
    selected_before = _read(reader, selected, 24, "selected.before")
    count = int.from_bytes(selected_before[20:24], "little", signed=True)
    if not 0 <= count <= MAX_RECORDS:
        _structural_stable(reader, holder_pointer, relations, relation, relation_before,
                           manager, outer_before, candidate, candidate_before,
                           selected, selected_before, 0, b"", 0, indexed_ref)
        return {"status": "unknown", "reason": "OPINION_MODIFIER_RECORD_LIMIT"}
    if not candidate_count and count:
        _structural_stable(reader, holder_pointer, relations, relation, relation_before,
                           manager, outer_before, candidate, candidate_before,
                           selected, selected_before, 0, b"", 0, indexed_ref)
        return {"status": "unknown", "reason": "OPINION_MODIFIER_NATIVE_FALLBACK_NONEMPTY"}
    entries = int.from_bytes(selected_before[8:16], "little")
    pointers_before = (_read(reader, _address(entries, 0, count * 8), count * 8,
                             "entry_pointers.before") if count else b"")
    pointers = [int.from_bytes(pointers_before[index * 8:index * 8 + 8], "little")
                for index in range(count)]
    if len(set(pointers)) != len(pointers):
        _structural_stable(reader, holder_pointer, relations, relation, relation_before,
                           manager, outer_before, candidate, candidate_before,
                           selected, selected_before, entries, pointers_before,
                           count, indexed_ref)
        return {"status": "unknown", "reason": "OPINION_MODIFIER_DUPLICATE_OBJECT"}
    read_record = _record if record_reader is None else record_reader
    if not callable(read_record):
        raise ValueError("OPINION_MODIFIER_RECORD_READER_INVALID")
    records = [read_record(reader, base, pointer, index)
               for index, pointer in enumerate(pointers)]
    _structural_stable(reader, holder_pointer, relations, relation, relation_before,
                       manager, outer_before, candidate, candidate_before,
                       selected, selected_before, entries, pointers_before,
                       count, indexed_ref)
    return {
        "status": "knownempty" if not records else "known",
        "records": records,
        "selected_kind": "materialized" if candidate_count else "native_fallback",
    }


def _direction(reader: Any, base: int, holder: Mapping[str, Any],
               indexed: Mapping[str, Any], *, record_reader: Any = None) -> dict[str, Any]:
    local = _DirectionReader(reader)
    try:
        if record_reader is None:
            return _direction_impl(local, base, holder, indexed)
        return _direction_impl(local, base, holder, indexed,
                               record_reader=record_reader)
    except _DirectionUnknown as exc:
        return {"status": "unknown", "reason": str(exc)}
    except ValueError as exc:
        if str(exc) == "OPINION_MODIFIER_DIRECTION_BUDGET":
            return {"status": "unknown", "reason": "OPINION_MODIFIER_DIRECTION_BUDGET"}
        return {"status": "unknown", "reason": "OPINION_MODIFIER_READ_FAILED"}
    except Exception:
        return {"status": "unknown", "reason": "OPINION_MODIFIER_READ_FAILED"}


def _field(holder_tag: str, target_tag: str, result: Mapping[str, Any]) -> dict[str, Any]:
    if result.get("status") == "unknown":
        return {"status": "unknown", "reason": result.get("reason", "OPINION_MODIFIER_DIRECTION_UNKNOWN")}
    records = result.get("records")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        return {"status": "unknown", "reason": "OPINION_MODIFIER_RECORDS_INVALID"}
    return {
        "status": "known",
        "value": {"holder": holder_tag, "target": target_tag, "records": deepcopy(records)},
        "unit": UNIT,
        "scale": SCALE,
        "complete": COMPLETE,
    }


def _backend_read(reader: Any, base: int, country: str, *, observer=OBSERVER) -> dict[str, Any]:
    pair: dict[str, Any] = {}

    def admit(read_bytes: Any, module_base: int, scan: Mapping[str, Any],
              observer: str, target: str):
        pair.clear()
        pair.update(deepcopy(scan["requested"]))
        gate = opinion._admission(read_bytes, module_base, scan, observer, target)
        if isinstance(gate, Mapping):
            gate = deepcopy(dict(gate))
            gate["field_scope"] = {
                "field": "R04.opinion_modifiers",
                "basis": "native_country_selection_and_bilateral_opinion_controls_projected_to_observer",
                "actual_UI_observed": False,
                "physical_player_equals_observer_required": False,
                "cache_freshness_proven": False,
            }
        return gate

    def fields(read_bytes: Any, module_base: int, binding: Mapping[str, Any], selected: tuple[str, ...]):
        if selected != FIELDS or not _same(binding, pair.get(country)):
            raise ValueError("OPINION_MODIFIERS_PASS_BINDING_CHANGED")
        observer_binding = pair[observer]
        target = pair[country]
        outgoing = _direction(read_bytes, module_base, observer_binding, target)
        incoming = _direction(read_bytes, module_base, target, observer_binding)
        return {
            FIELD_OUTGOING: _field(observer, country, outgoing),
            FIELD_INCOMING: _field(country, observer, incoming),
        }

    return backend.read_two_pass(reader, base, observer, [country], FIELDS,
                                 read_fields=fields, admission_reader=admit)


def _observe(reader: Any, base: int, country: str, profile: Mapping[str, Any],
             *, observer=OBSERVER) -> dict[str, Any]:
    return opinion._owner._observe(reader, base, country, profile,
                                   backend_reader=partial(_backend_read, observer=observer))


__all__ = [
    "PROFILE_FILE", "PROFILE_SHA256", "PROFILE_ID", "SCHEMA", "FIELDS",
    "FIELD_OUTGOING", "FIELD_INCOMING", "UNIT", "SCALE", "PERIOD",
    "COMPLETE", "BASIS", "VALUE_ORIGIN", "MAX_RECORDS", "MAX_DIRECTION_BYTES",
    "MAX_TOTAL_BYTES", "_load_profile", "_observe", "_backend_read", "_direction",
]
