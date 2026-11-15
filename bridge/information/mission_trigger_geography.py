"""Bounded memory reader for loaded geographic area definitions.

This module reuses the mission-condition name-map walker and follows only the
loaded area's native province-vector begin/end pair. It never parses source
files, opens a process, or invokes native game code.
"""
from __future__ import annotations

import re
from typing import Any

from . import mission_condition_memory as _mission_condition_memory


AREA_MANAGER_SINGLETON_RVA = 0x233FEB8
AREA_MANAGER_NAME_MAP_OFFSET = 0x5D0
AREA_PROVINCE_VECTOR_OFFSET = 0x88
MAX_AREA_NAME_MAP_SIZE = 16384
MAX_AREA_PROVINCES = 64
SOURCE = "reused_area_manager_name_map_and_loaded_area_province_vector"
_NAME = re.compile(r"[A-Za-z0-9_]{1,256}\Z", re.ASCII)


class _UnalignedReader:
    """Adapt a caller-tracked reader without bypassing its read accounting."""

    def __init__(self, reader: Any, module_base: int):
        read = getattr(reader, "read", None)
        if not callable(read):
            raise ValueError("geographic_reader_missing_read")
        self._reader = reader
        self.module_base = module_base

    def read(self, address: int, size: int, label: str) -> bytes:
        raw = self._reader.read(address, size, label)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise ValueError(f"{label}_short_read")
        return raw

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        # The shared map walker may use qword reads at packed offsets. Route
        # them through read() so the caller's tracked reader accounts for them.
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little"), raw


def _unknown(reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "found": None,
        "province_ids": [],
        "source": SOURCE,
        "reason": reason,
    }


def _known(found: bool, province_ids: list[int] | None = None) -> dict[str, Any]:
    return {
        "status": "known",
        "found": found,
        "province_ids": province_ids or [],
        "source": SOURCE,
    }


def _valid_vector_endpoint(address: int, *, allow_end: bool, label: str) -> None:
    maximum = _mission_condition_memory.MAX_USER_ADDRESS
    if (isinstance(address, bool) or not isinstance(address, int)
            or address < 0x10000 or address & 3
            or address > maximum or (not allow_end and address == maximum)):
        raise ValueError(f"{label}_invalid")


def read_geographic_state(reader: Any, module_base: int, name: str) -> dict[str, Any]:
    """Resolve one loaded area name and read its bounded province-ID vector."""
    try:
        _mission_condition_memory._valid_pointer(module_base, "module_base")
    except Exception as exc:
        return _unknown(f"module_base_invalid:{type(exc).__name__}:{exc}")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        return _unknown("geographic_name_invalid")

    try:
        tracked = _UnalignedReader(reader, module_base)
        manager_address = module_base + AREA_MANAGER_SINGLETON_RVA
        manager = tracked.qword(manager_address, "geography.area_manager_singleton")[0]
        _mission_condition_memory._valid_pointer(manager, "area_manager")

        map_header = _mission_condition_memory._read_map_header(
            tracked,
            manager + AREA_MANAGER_NAME_MAP_OFFSET,
            "area_name_map",
            MAX_AREA_NAME_MAP_SIZE,
        )
        names = _mission_condition_memory._MapWalk(tracked, map_header, "area_name_map")
        try:
            area = names.find_name(name)
        except ValueError as exc:
            if str(exc) == f"canonical_definition_missing:{name}":
                return _known(False)
            raise

        _mission_condition_memory._valid_pointer(area, "area_definition")
        raw = tracked.read(
            area + AREA_PROVINCE_VECTOR_OFFSET,
            16,
            f"geography.area[{name}].province_vector",
        )
        begin = int.from_bytes(raw[:8], "little")
        end = int.from_bytes(raw[8:], "little")
        if begin == 0 and end == 0:
            return _known(True)
        if begin == 0 or end == 0:
            raise ValueError("area_province_vector_null_endpoint")

        _valid_vector_endpoint(begin, allow_end=False, label="area_province_vector_begin")
        _valid_vector_endpoint(end, allow_end=True, label="area_province_vector_end")
        if end < begin:
            raise ValueError("area_province_vector_reversed")
        byte_count = end - begin
        if byte_count % 4:
            raise ValueError("area_province_vector_size_unaligned")
        count = byte_count // 4
        if count > MAX_AREA_PROVINCES:
            raise ValueError("area_province_vector_count_over_bound")
        if count == 0:
            return _known(True)

        values = tracked.read(begin, byte_count, f"geography.area[{name}].province_ids")
        province_ids: list[int] = []
        seen: set[int] = set()
        for offset in range(0, byte_count, 4):
            province_id = int.from_bytes(values[offset:offset + 4], "little", signed=True)
            if not 1 <= province_id < 65536:
                raise ValueError("area_province_id_out_of_range")
            if province_id in seen:
                raise ValueError("area_province_id_duplicate")
            seen.add(province_id)
            province_ids.append(province_id)
        return _known(True, province_ids)
    except Exception as exc:
        return _unknown(f"geographic_read_failed:{type(exc).__name__}:{exc}")


__all__ = ["read_geographic_state"]
