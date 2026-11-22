"""Read the native army-ratio numerator and land force-limit denominator.

This adapter reuses the bounded country-force and military-resource readers.
It only reads the caller's existing process reader and never invokes game code.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import country_forces_memory as forces
from . import military_resources_memory as military_resources


SOURCE = "native_group_gate_with_country_forces_and_military_resources"
_MIN_USER_ADDRESS = 0x10000
_MAX_USER_ADDRESS = 0x0000800000000000
_VTABLE_RANGE = 0x2800000
_CODE_RANGE = 0x1C00000
_MAX_GROUPS = 128
_MAX_VECTOR_LENGTH = 1024


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _wrap_s32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _valid_pointer(value: Any) -> bool:
    return (type(value) is int and _MIN_USER_ADDRESS <= value < _MAX_USER_ADDRESS
            and value % 8 == 0)


def _valid_address(value: Any) -> bool:
    return type(value) is int and _MIN_USER_ADDRESS <= value < _MAX_USER_ADDRESS


def _pointer(value: Any, label: str) -> int:
    if type(value) is int:
        parsed = value
    elif type(value) is str:
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise ValueError(f"{label}_invalid") from exc
    else:
        raise ValueError(f"{label}_invalid")
    if not _valid_pointer(parsed):
        raise ValueError(f"{label}_invalid")
    return parsed


def _add(base: int, offset: int, size: int, label: str) -> int:
    address = base + offset
    if (type(offset) is not int or offset < 0 or address < base
            or address < _MIN_USER_ADDRESS or address + size > _MAX_USER_ADDRESS
            or address + size < address):
        raise ValueError(f"{label}_range_invalid")
    return address


def _read_qword(reader: Any, address: int, label: str) -> int:
    if address % 8:
        raise ValueError(f"{label}_alignment_invalid")
    method = getattr(reader, "read", None)
    if not callable(method):
        raise ValueError("reader_read_method_missing")
    raw = method(address, 8, label)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != 8:
        raise ValueError(f"{label}_short_or_invalid_read")
    return int.from_bytes(raw, "little", signed=False)


def _read_bytes(reader: Any, address: int, size: int, label: str, *, code: bool = False) -> bytes:
    method = (getattr(reader, "read_code", None) if code else None) or getattr(reader, "read", None)
    if not callable(method):
        raise ValueError("reader_read_method_missing")
    raw = method(address, size, label)
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
        raise ValueError(f"{label}_short_or_invalid_read")
    return bytes(raw)


def _constant_bool(method_bytes: bytes) -> bool:
    if (method_bytes.startswith(b"\xb0\x01\xc3")
            or method_bytes == b"\xb8\x01\x00\x00\x00\xc3"):
        return True
    if method_bytes.startswith((b"\x32\xc0\xc3", b"\x33\xc0\xc3")):
        return False
    raise ValueError("ARMY_RATIO_GROUP_METHOD_NOT_CONSTANT")


def _group_gate(reader: Any, module_base: int, group_object: int, index: int) -> bool:
    label = f"mission_trigger.army_ratio.group[{index}]"

    # C8F430 first applies the group object's optional country-state gate.
    auxiliary_slot = _add(group_object, 0x48, 8, f"{label}.auxiliary_slot")
    auxiliary = _read_qword(reader, auxiliary_slot, f"{label}.auxiliary_pointer")
    if auxiliary:
        if not _valid_pointer(auxiliary):
            raise ValueError(f"{label}_auxiliary_pointer_invalid")
        nested_slot = _add(auxiliary, 0x28, 8, f"{label}.nested_slot")
        nested = _read_qword(reader, nested_slot, f"{label}.nested_pointer")
        if not _valid_pointer(nested):
            raise ValueError(f"{label}_nested_pointer_invalid")
        flag_address = _add(nested, 0x291, 1, f"{label}.flag")
        flag = _read_bytes(reader, flag_address, 1, f"{label}.flag", code=True)[0]
        if flag == 0:
            return False

    # The supported static methods are the exact constant-bool forms already
    # established for mission group evaluators. No virtual function is called.
    vtable = _read_qword(reader, group_object, f"{label}.vtable")
    if not _valid_pointer(vtable) or not module_base <= vtable < module_base + _VTABLE_RANGE:
        raise ValueError(f"{label}_vtable_outside_module")
    method_slot = _add(vtable, 0x80, 8, f"{label}.method_slot")
    if method_slot + 8 > module_base + _VTABLE_RANGE:
        raise ValueError(f"{label}_method_slot_outside_module")
    method = _read_qword(reader, method_slot, f"{label}.method")
    if (not _valid_address(method) or not module_base <= method
            or method + 6 > module_base + _CODE_RANGE):
        raise ValueError(f"{label}_method_outside_code")
    method_bytes = _read_bytes(reader, method, 6, f"{label}.method_bytes", code=True)
    return _constant_bool(method_bytes)


def _land_force_limit_raw(observed: Any, country_pointer: int, country: str) -> int:
    if not isinstance(observed, Mapping) or observed.get("status") != "observed":
        reason = observed.get("reason", observed.get("error", "not_observed")) if isinstance(observed, Mapping) else "invalid_result"
        raise ValueError(f"MILITARY_RESOURCES_UNAVAILABLE:{reason}")
    if observed.get("country") != country:
        raise ValueError("MILITARY_RESOURCES_COUNTRY_MISMATCH")
    returned_pointer = observed.get("country_pointer")
    if returned_pointer is None and isinstance(observed.get("private"), Mapping):
        returned_pointer = observed["private"].get("country_pointer")
    if returned_pointer is not None and returned_pointer != hex(country_pointer):
        raise ValueError("MILITARY_RESOURCES_COUNTRY_POINTER_MISMATCH")
    fields = observed.get("fields")
    force_limits = fields.get("force_limits") if isinstance(fields, Mapping) else None
    values = force_limits.get("value") if isinstance(force_limits, Mapping) else None
    land = values.get("land") if isinstance(values, Mapping) else None
    if not isinstance(land, Mapping) or land.get("status") != "known":
        reason = land.get("reason", "land_force_limit_unknown") if isinstance(land, Mapping) else "land_force_limit_missing"
        raise ValueError(f"LAND_FORCE_LIMIT_UNKNOWN:{reason}")
    raw = land.get("raw")
    if (type(raw) is not int or not 0 < raw <= 0x7FFFFFFF or raw % 1000
            or land.get("value") != raw // 1000 or land.get("scale") != 1000
            or land.get("unit") != "regiments" or land.get("complete") is not True
            or land.get("partial") is not False):
        raise ValueError("LAND_FORCE_LIMIT_CONTRACT_INVALID")
    return raw


def count_army_ratio_inputs(reader: Any, module_base: int, country_pointer: int,
                           *, country: str = "FRA") -> dict[str, Any]:
    """Return fixed-milli army count and land force-limit raw inputs.

    The numerator counts group vector entries only for groups whose native
    optional pointer gate passes and whose known virtual-method bytes return
    constant true. Record kind and strength are intentionally unused.
    """
    try:
        if (not _valid_pointer(module_base) or module_base % 0x1000 != 0
                or module_base + _VTABLE_RANGE > _MAX_USER_ADDRESS
                or module_base + _CODE_RANGE > _MAX_USER_ADDRESS
                or not _valid_pointer(country_pointer)):
            raise ValueError("REQUEST_POINTER_INVALID")

        force_result = forces.read_fields(reader, module_base, country_pointer, country=country)
        if not isinstance(force_result, Mapping) or force_result.get("status") != "observed":
            reason = force_result.get("reason", "not_observed") if isinstance(force_result, Mapping) else "invalid_result"
            raise ValueError(f"COUNTRY_FORCES_UNAVAILABLE:{reason}")
        if force_result.get("country") != country:
            raise ValueError("COUNTRY_FORCES_COUNTRY_MISMATCH")
        returned_pointer = force_result.get("country_pointer")
        if returned_pointer is None and isinstance(force_result.get("private"), Mapping):
            returned_pointer = force_result["private"].get("country_pointer")
        if returned_pointer is not None and returned_pointer != hex(country_pointer):
            raise ValueError("COUNTRY_FORCES_POINTER_MISMATCH")

        groups = force_result.get("groups")
        if not isinstance(groups, list) or len(groups) > _MAX_GROUPS:
            raise ValueError("COUNTRY_FORCES_GROUPS_INVALID")
        declared_count = force_result.get("group_count")
        if declared_count is not None and (type(declared_count) is not int or declared_count != len(groups)):
            raise ValueError("COUNTRY_FORCES_GROUP_COUNT_MISMATCH")

        army_count = 0
        for index, group in enumerate(groups):
            if not isinstance(group, Mapping):
                raise ValueError(f"COUNTRY_FORCES_GROUP_INVALID:{index}")
            vector_length = group.get("vector_length")
            if (type(vector_length) is not int or vector_length < 0
                    or vector_length > _MAX_VECTOR_LENGTH):
                raise ValueError(f"COUNTRY_FORCES_VECTOR_LENGTH_INVALID:{index}")
            group_object = _pointer(group.get("group_object"), f"group[{index}].object")
            if _group_gate(reader, module_base, group_object, index):
                army_count = _wrap_s32(army_count + vector_length)

        army_raw_fixed_milli = _wrap_s32(army_count * 1000)
        military_result = military_resources.read_fields(reader, module_base, country_pointer, country=country)
        land_force_limit_raw = _land_force_limit_raw(military_result, country_pointer, country)
        return {
            "status": "known",
            "army_raw_fixed_milli": army_raw_fixed_milli,
            "land_force_limit_raw": land_force_limit_raw,
            "source": SOURCE,
        }
    except Exception as exc:
        return _unknown(f"{type(exc).__name__}:{exc}")
