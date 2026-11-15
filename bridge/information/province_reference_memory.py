"""Bind province IDs to records in the bounded B23 province array.

This is a one-pass memory-reader leaf. It does not open a process or file,
resolve owners/controllers, infer visibility, or certify a public field. A
parent must establish the executable/profile/session context and compare
separate observations if it needs stability; this scan is not atomic.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Callable


PROVINCE_GLOBAL_RVA = 0x233FE58
ARRAY_BEGIN_OFFSET = 0x1C90
ARRAY_END_OFFSET = 0x1C98
RECORDS_POINTER_OFFSET = 0x1CA8
RECORD_STRIDE = 0x2E10
RECORD_ID_OFFSET = 0x20
MAX_PROVINCE_COUNT = 65536
MAX_REQUESTED_PROVINCES = 32
MAX_TOTAL_READ_BYTES = 4096
MAX_READ_CALLS = 128
MAX_SINGLE_READ_BYTES = 64
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS_EXCLUSIVE = 0x800000000000
MAX_U64 = 0xFFFFFFFFFFFFFFFF


class _Unknown(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _is_user_address(value: Any) -> bool:
    return (type(value) is int and MIN_USER_ADDRESS <= value < MAX_USER_ADDRESS_EXCLUSIVE
            and value <= MAX_U64)


def _checked_add(address: int, offset: int, label: str) -> int:
    if (not _is_user_address(address) or type(offset) is not int or offset < 0
            or address > MAX_U64 - offset):
        raise _Unknown(f"address_arithmetic_invalid:{label}")
    result = address + offset
    if not _is_user_address(result):
        raise _Unknown(f"address_arithmetic_invalid:{label}")
    return result


def _checked_range(address: int, size: int, label: str) -> tuple[int, int]:
    if (not _is_user_address(address) or type(size) is not int or size <= 0
            or address > MAX_U64 - (size - 1)):
        raise _Unknown(f"address_range_invalid:{label}")
    last = address + size - 1
    if not _is_user_address(last):
        raise _Unknown(f"address_range_invalid:{label}")
    return address, last + 1


def _read_exact(read: Callable[[int, int, str], bytes], address: int, size: int,
                label: str, budget: dict[str, Any]) -> bytes:
    if type(size) is not int or not 0 < size <= MAX_SINGLE_READ_BYTES:
        raise _Unknown(f"read_size_out_of_range:{label}")
    _checked_range(address, size, label)
    if budget["calls"] >= MAX_READ_CALLS:
        raise _Unknown("read_call_budget_exceeded")
    if budget["bytes_requested"] + size > MAX_TOTAL_READ_BYTES:
        raise _Unknown("read_byte_budget_exceeded")

    budget["calls"] += 1
    budget["bytes_requested"] += size
    try:
        raw = read(address, size, label)
    except Exception as exc:
        budget["reads"].append({
            "address": hex(address), "size": size, "label": label,
            "status": "failed", "error_type": type(exc).__name__,
        })
        raise _Unknown(f"read_failed:{label}:{type(exc).__name__}") from exc
    if not isinstance(raw, (bytes, bytearray, memoryview)) or len(raw) != size:
        budget["reads"].append({
            "address": hex(address), "size": size, "label": label,
            "status": "failed", "error_type": "short_or_invalid_read",
        })
        raise _Unknown(f"short_or_invalid_read:{label}")
    raw = bytes(raw)
    budget["reads"].append({
        "address": hex(address), "size": size, "label": label,
        "status": "ok", "raw_hex": raw.hex(),
    })
    return raw


def _read_u64(read: Callable[[int, int, str], bytes], address: int, label: str,
              budget: dict[str, Any]) -> tuple[int, bytes]:
    raw = _read_exact(read, address, 8, label, budget)
    return int.from_bytes(raw, "little", signed=False), raw


def _unknown_result(budget: dict[str, Any], reason: str,
                    world: dict[str, Any] | None,
                    header: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "status": "unknown",
        "basis": "province_id_indexed_record_identity_only",
        "requested": {},
        "world": world,
        "header": header,
        "visibility": "unknown",
        "complete": False,
        "public_export_ready": False,
        "reason": reason,
        "budget": {
            "calls": budget["calls"],
            "bytes_requested": budget["bytes_requested"],
            "limits": {
                "calls": MAX_READ_CALLS,
                "total_bytes": MAX_TOTAL_READ_BYTES,
                "single_read_bytes": MAX_SINGLE_READ_BYTES,
            },
            "reads": budget["reads"],
        },
    }


def resolve_provinces(read: Callable[[int, int, str], bytes], base: int,
                      province_ids: Iterable[int]) -> dict[str, Any]:
    """Resolve requested positive province IDs through the B23 record array.

    The array count comes from ``world+0x1c90`` and ``world+0x1c98`` while
    record storage is independently read from ``world+0x1ca8``. Each requested
    record is ``records + id*0x2e10`` and must echo the same signed ID at
    ``record+0x20``. All errors return an unknown result with bounded raw-read
    evidence; no partial request mapping is exposed.
    """
    budget: dict[str, Any] = {"calls": 0, "bytes_requested": 0, "reads": []}
    world_info: dict[str, Any] | None = None
    header: dict[str, Any] | None = None
    try:
        if not callable(read):
            raise _Unknown("reader_not_callable")
        if not _is_user_address(base) or base & 7:
            raise _Unknown("module_base_invalid")

        if isinstance(province_ids, (str, bytes, bytearray, Mapping)):
            raise _Unknown("province_ids_shape_invalid")
        try:
            iterator = iter(province_ids)
        except TypeError as exc:
            raise _Unknown("province_ids_not_iterable") from exc

        requested: list[int] = []
        seen: set[int] = set()
        try:
            for province_id in iterator:
                if len(requested) >= MAX_REQUESTED_PROVINCES:
                    raise _Unknown("province_id_count_out_of_range")
                if type(province_id) is not int or province_id < 1:
                    raise _Unknown("province_id_invalid")
                if province_id in seen:
                    raise _Unknown(f"duplicate_province_id:{province_id}")
                seen.add(province_id)
                requested.append(province_id)
        except _Unknown:
            raise
        except Exception as exc:
            raise _Unknown(f"province_ids_iteration_failed:{type(exc).__name__}") from exc
        if not requested:
            raise _Unknown("province_ids_empty")

        global_address = _checked_add(base, PROVINCE_GLOBAL_RVA, "province_global")
        global_raw = _read_exact(read, global_address, 8,
                                 "province_reference.world_global", budget)
        world = int.from_bytes(global_raw, "little", signed=False)
        world_info = {
            "global_address": hex(global_address),
            "global_raw_hex": global_raw.hex(),
            "pointer": hex(world),
        }
        if not _is_user_address(world) or world & 7:
            raise _Unknown("world_pointer_invalid")
        if world in (base, global_address):
            raise _Unknown("world_pointer_alias")

        begin_address = _checked_add(world, ARRAY_BEGIN_OFFSET, "array_begin")
        end_address = _checked_add(world, ARRAY_END_OFFSET, "array_end")
        records_address = _checked_add(world, RECORDS_POINTER_OFFSET, "records_pointer")
        begin, begin_raw = _read_u64(read, begin_address,
                                    "province_reference.array_begin", budget)
        end, end_raw = _read_u64(read, end_address,
                                "province_reference.array_end", budget)
        records, records_raw = _read_u64(read, records_address,
                                         "province_reference.records_pointer", budget)
        header = {
            "begin_address": hex(begin_address),
            "begin": hex(begin),
            "begin_raw_hex": begin_raw.hex(),
            "end_address": hex(end_address),
            "end": hex(end),
            "end_raw_hex": end_raw.hex(),
            "records_pointer_address": hex(records_address),
            "records_pointer": hex(records),
            "records_pointer_raw_hex": records_raw.hex(),
            "count": None,
            "records_range": None,
        }
        if (not _is_user_address(begin) or not _is_user_address(end)
                or begin & 7 or end & 7 or end < begin):
            raise _Unknown("province_array_bounds_invalid")
        vector_bytes = end - begin
        if vector_bytes % 8:
            raise _Unknown("province_array_bounds_misaligned")
        count = vector_bytes // 8
        if not 1 < count <= MAX_PROVINCE_COUNT:
            raise _Unknown("province_count_out_of_range")
        header["count"] = count
        if not _is_user_address(records) or records & 7:
            raise _Unknown("province_records_pointer_invalid")
        records_range = _checked_range(records, count * RECORD_STRIDE,
                                       "province_records")
        header["records_range"] = [hex(records_range[0]), hex(records_range[1])]

        bindings: dict[str, dict[str, Any]] = {}
        for province_id in requested:
            if province_id >= count:
                raise _Unknown(f"province_id_out_of_range:{province_id}")
            record = _checked_add(records, province_id * RECORD_STRIDE,
                                  f"province_record:{province_id}")
            _checked_range(record, RECORD_STRIDE, f"province_record:{province_id}")
            id_address = _checked_add(record, RECORD_ID_OFFSET,
                                      f"province_record_id:{province_id}")
            raw = _read_exact(read, id_address, 4,
                              f"province_reference.id[{province_id}]", budget)
            stored_id = int.from_bytes(raw, "little", signed=True)
            if stored_id != province_id:
                raise _Unknown(f"province_id_record_mismatch:{province_id}")
            bindings[str(province_id)] = {
                "province_id": province_id,
                "record_pointer": hex(record),
                "id_address": hex(id_address),
                "id_raw_hex": raw.hex(),
                "record_id": stored_id,
            }

        return {
            "status": "observed",
            "basis": "province_id_indexed_record_identity_only",
            "requested": bindings,
            "world": world_info,
            "header": header,
            "visibility": "unknown",
            "complete": False,
            "public_export_ready": False,
            "budget": {
                "calls": budget["calls"],
                "bytes_requested": budget["bytes_requested"],
                "limits": {
                    "calls": MAX_READ_CALLS,
                    "total_bytes": MAX_TOTAL_READ_BYTES,
                    "single_read_bytes": MAX_SINGLE_READ_BYTES,
                },
                "reads": budget["reads"],
            },
        }
    except _Unknown as exc:
        return _unknown_result(budget, exc.reason, world_info, header)
