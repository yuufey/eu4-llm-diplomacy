"""Read bounded owned-province and subject-country inputs for count triggers."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import mission_task_memory
from . import mission_trigger_country_scope


SOURCE = "mission_trigger_count_domain.read_count_domain"
OWNED_DATA_POINTER_OFFSET = 0x1338
OWNED_COUNT_OFFSET = 0x1344
COUNTRY_FULLREF_OFFSET = 0x20
SUBJECT_BEGIN_OFFSET = 0x1A18
SUBJECT_END_OFFSET = 0x1A20
SUBJECT_PARENT_REFERENCE_OFFSET = 0x18F0
SUBJECT_TYPE_INCLUDE_FLAG_OFFSET = 0x11B
MAX_OWNED_PROVINCES = 256
MAX_SUBJECTS_PER_COUNTRY = 64
MAX_SUBJECT_VISITS = 64
MAX_SUBJECT_DEPTH = 8
MAX_TOTAL_PROVINCES = 256
MAX_PROVINCE_ID_EXCLUSIVE = 65536
_MAX_USER_ADDRESS_EXCLUSIVE = mission_task_memory.MAX_USER_ADDRESS


class _DomainFailure(ValueError):
    pass


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _valid_pointer(value: Any, alignment: int = 8) -> bool:
    return (
        type(value) is int
        and 0x10000 <= value < _MAX_USER_ADDRESS_EXCLUSIVE
        and (alignment <= 1 or value % alignment == 0)
    )


def _checked_add(base: int, offset: int, size: int, label: str) -> int:
    if (not _valid_pointer(base) or type(offset) is not int or offset < 0
            or type(size) is not int or size <= 0
            or base > _MAX_USER_ADDRESS_EXCLUSIVE - offset):
        raise _DomainFailure(f"address_invalid:{label}")
    address = base + offset
    if address < 0x10000 or address > _MAX_USER_ADDRESS_EXCLUSIVE - size:
        raise _DomainFailure(f"range_invalid:{label}")
    return address


def _checked_span(address: int, size: int, alignment: int, label: str) -> None:
    if (not _valid_pointer(address, alignment)
            or type(size) is not int or size <= 0
            or address > _MAX_USER_ADDRESS_EXCLUSIVE - size):
        raise _DomainFailure(f"range_invalid:{label}")


class _TrackedReaderAdapter:
    """Preserve the caller's tracked unaligned path, budget, and read trace."""

    def __init__(self, reader: Any, module_base: int):
        self._reader = reader
        self.module_base = module_base

    def read(self, address: int, size: int, label: str) -> bytes:
        return mission_task_memory._read_unaligned(
            self._reader, address, size, label
        )

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return mission_task_memory._read_unaligned(
            self._reader, address, size, label
        )

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = _read_exact(self, address, 8, label, alignment=8)
        return int.from_bytes(raw, "little", signed=False), raw


def _read_exact(reader: Any, address: int, size: int, label: str,
                alignment: int = 1) -> bytes:
    _checked_span(address, size, alignment, label)
    try:
        raw = reader.read(address, size, label)
    except Exception as exc:
        raise _DomainFailure(f"read_failed:{label}:{type(exc).__name__}") from exc
    if type(raw) is not bytes or len(raw) != size:
        raise _DomainFailure(f"short_or_invalid_read:{label}")
    return raw


def _read_u64(reader: Any, address: int, label: str) -> int:
    return int.from_bytes(_read_exact(reader, address, 8, label, alignment=8),
                          "little", signed=False)


def _country_tag(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 3
        and value.isascii()
        and all("A" <= char <= "Z" or "0" <= char <= "9" for char in value)
    )


def _bind_country(reader: Any, module_base: int, fullref: int) -> tuple[int, str]:
    if type(fullref) is not int or not 0 <= fullref <= 0xFFFFFFFFFFFFFFFF:
        raise _DomainFailure("country_fullref_invalid")
    try:
        result = mission_trigger_country_scope.bind_country_scope(
            reader, module_base, fullref
        )
    except Exception as exc:
        raise _DomainFailure(f"country_binding_failed:{type(exc).__name__}") from exc
    if not isinstance(result, Mapping):
        raise _DomainFailure("country_binding_result_invalid")
    if result.get("status") != "known":
        reason = result.get("reason")
        raise _DomainFailure(
            reason if type(reason) is str and reason else "country_binding_unknown"
        )
    pointer = result.get("pointer")
    tag = result.get("tag")
    if (not _valid_pointer(pointer) or not _country_tag(tag)
            or type(result.get("fullref")) is not int
            or result.get("fullref") != fullref):
        raise _DomainFailure("country_binding_echo_invalid")
    return pointer, tag


def _read_country_fullref(reader: Any, country_pointer: int) -> int:
    address = _checked_add(
        country_pointer, COUNTRY_FULLREF_OFFSET, 8, "country_fullref"
    )
    return _read_u64(reader, address, "count_domain.country_fullref")


def _read_owned_ids(reader: Any, country_pointer: int,
                    province_ids: list[int]) -> None:
    data_address = _checked_add(
        country_pointer, OWNED_DATA_POINTER_OFFSET, 8, "owned_data_pointer"
    )
    count_address = _checked_add(
        country_pointer, OWNED_COUNT_OFFSET, 4, "owned_count"
    )
    data_pointer = _read_u64(reader, data_address,
                             "count_domain.owned_data_pointer")
    count_raw = _read_exact(reader, count_address, 4,
                            "count_domain.owned_count_i32", alignment=4)
    count = int.from_bytes(count_raw, "little", signed=True)
    if not 0 <= count <= MAX_OWNED_PROVINCES:
        raise _DomainFailure("owned_count_out_of_bound")
    if len(province_ids) + count > MAX_TOTAL_PROVINCES:
        raise _DomainFailure("total_province_id_count_out_of_bound")
    if count == 0:
        if data_pointer != 0 and not _valid_pointer(data_pointer, alignment=4):
            raise _DomainFailure("owned_data_pointer_invalid_for_empty_list")
        return
    if not _valid_pointer(data_pointer, alignment=4):
        raise _DomainFailure("owned_data_pointer_invalid")
    size = count * 4
    _checked_span(data_pointer, size, 4, "owned_ids")
    raw = _read_exact(reader, data_pointer, size,
                      "count_domain.owned_province_ids", alignment=4)
    for offset in range(0, size, 4):
        province_id = int.from_bytes(raw[offset:offset + 4], "little", signed=True)
        if not 1 <= province_id < MAX_PROVINCE_ID_EXCLUSIVE:
            raise _DomainFailure("owned_province_id_out_of_range")
        province_ids.append(province_id)


def _read_subject_refs(reader: Any, country_pointer: int) -> list[int]:
    address = _checked_add(
        country_pointer, SUBJECT_BEGIN_OFFSET, 16, "subject_vector_header"
    )
    raw = _read_exact(reader, address, 16,
                      "count_domain.subject_vector_header", alignment=8)
    begin = int.from_bytes(raw[:8], "little", signed=False)
    end = int.from_bytes(raw[8:], "little", signed=False)
    if begin == 0 and end == 0:
        return []
    if (begin == 0 or end == 0 or begin < 0x10000
            or begin >= _MAX_USER_ADDRESS_EXCLUSIVE
            or end < 0x10000 or end > _MAX_USER_ADDRESS_EXCLUSIVE
            or begin & 7 or end & 7 or end < begin):
        raise _DomainFailure("subject_vector_bounds_invalid")
    byte_count = end - begin
    if byte_count % 8:
        raise _DomainFailure("subject_vector_size_unaligned")
    count = byte_count // 8
    if count > MAX_SUBJECTS_PER_COUNTRY:
        raise _DomainFailure("subject_count_out_of_bound")
    if count == 0:
        return []
    _checked_span(begin, byte_count, 8, "subject_fullrefs")
    refs_raw = _read_exact(reader, begin, byte_count,
                           "count_domain.subject_fullrefs", alignment=8)
    return [int.from_bytes(refs_raw[index:index + 8], "little", signed=False)
            for index in range(0, byte_count, 8)]


def _resolve_subject_type(reader: Any, owner_pointer: int,
                          parent_reference: int, label: str) -> int:
    # Lazy import avoids a module cycle when mission_trigger_memory configures
    # this adapter as one of its method-family readers.
    from . import mission_trigger_memory

    helper = getattr(mission_trigger_memory, "_subject_type_pointer", None)
    if not callable(helper):
        raise _DomainFailure("subject_type_helper_unavailable")
    try:
        result = helper(reader, owner_pointer, parent_reference, label)
    except Exception as exc:
        raise _DomainFailure(f"subject_type_read_failed:{type(exc).__name__}") from exc
    if not isinstance(result, tuple) or len(result) != 2:
        raise _DomainFailure("subject_type_result_invalid")
    pointer, reason = result
    if pointer is None:
        raise _DomainFailure(
            reason if type(reason) is str and reason else "subject_type_unknown"
        )
    if type(pointer) is not int:
        raise _DomainFailure("subject_type_pointer_invalid")
    if pointer == 0:
        return 0
    if not _valid_pointer(pointer):
        raise _DomainFailure("subject_type_pointer_invalid")
    return pointer


def _collect_country(reader: Any, module_base: int, country_pointer: int,
                     mode: int, depth: int,
                     province_ids: list[int], state: dict[str, Any]) -> None:
    if depth > MAX_SUBJECT_DEPTH:
        raise _DomainFailure("subject_depth_out_of_bound")
    if country_pointer in state["active_pointers"]:
        raise _DomainFailure("subject_cycle_detected")
    if state["visits"] >= MAX_SUBJECT_VISITS:
        raise _DomainFailure("subject_visit_count_out_of_bound")

    state["visits"] += 1
    state["active_pointers"].add(country_pointer)
    try:
        _read_owned_ids(reader, country_pointer, province_ids)
        if mode == 0:
            return

        fullrefs = _read_subject_refs(reader, country_pointer)
        for index, fullref in enumerate(fullrefs):
            child_pointer, _child_tag = _bind_country(reader, module_base, fullref)
            parent_address = _checked_add(
                child_pointer, SUBJECT_PARENT_REFERENCE_OFFSET, 8,
                f"subject_parent_reference[{index}]",
            )
            parent_reference = _read_u64(
                reader, parent_address,
                f"count_domain.subject[{index}].parent_reference",
            )
            # Native skips a child whose parent fullref has a zero high byte.
            if (parent_reference >> 56) & 0xFF == 0:
                continue

            subject_type = _resolve_subject_type(
                reader, child_pointer, parent_reference,
                f"count_domain.subject[{index}]",
            )
            if subject_type == 0:
                continue
            if mode == 1:
                flag_address = _checked_add(
                    subject_type, SUBJECT_TYPE_INCLUDE_FLAG_OFFSET, 1,
                    f"subject_type_include_flag[{index}]",
                )
                flag = _read_exact(
                    reader, flag_address, 1,
                    f"count_domain.subject[{index}].type_flag_11b",
                )[0]
                if flag != 0:
                    continue

            if child_pointer in state["active_pointers"]:
                raise _DomainFailure("subject_cycle_detected")
            _collect_country(reader, module_base, child_pointer, mode,
                             depth + 1, province_ids, state)
    finally:
        state["active_pointers"].remove(country_pointer)


def read_count_domain(reader: Any, module_base: int,
                      country_pointer: int, mode: Any) -> dict[str, Any]:
    """Read ordered owned province IDs, optionally including subject countries.

    ``mode`` is exactly 0 (owned), 1 (recursively include subject types whose
    native byte at +0x11B is zero), or 2 (recursively include every resolved
    subject type). Unknown inputs or any incomplete child/vector read fail the
    entire result; province IDs are kept in native order, including duplicates.
    """
    if type(mode) is not int or mode not in (0, 1, 2):
        return _unknown("count_domain_mode_invalid")
    if (type(module_base) is not int or not _valid_pointer(module_base)
            or module_base & 7):
        return _unknown("module_base_invalid")
    if not _valid_pointer(country_pointer):
        return _unknown("country_pointer_invalid")
    if not (callable(getattr(reader, "read_code", None))
            or callable(getattr(reader, "_read", None))
            or callable(getattr(reader, "read", None))):
        return _unknown("reader_invalid")

    tracked = _TrackedReaderAdapter(reader, module_base)
    try:
        root_reference = _read_country_fullref(tracked, country_pointer)
        root_pointer, root_tag = _bind_country(
            tracked, module_base, root_reference
        )
        if root_pointer != country_pointer:
            raise _DomainFailure("root_country_pointer_mismatch")

        province_ids: list[int] = []
        state = {"visits": 0, "active_pointers": set()}
        _collect_country(tracked, module_base, root_pointer, mode, 0,
                         province_ids, state)
        return {
            "status": "known",
            "province_ids": province_ids,
            "country_pointer": root_pointer,
            "root_reference": root_reference,
            "country": root_tag,
            "source": SOURCE,
        }
    except _DomainFailure as exc:
        return _unknown(str(exc))
    except Exception as exc:
        return _unknown(f"count_domain_read_failed:{type(exc).__name__}")


__all__ = ["SOURCE", "read_count_domain"]
