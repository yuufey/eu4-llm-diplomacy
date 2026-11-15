"""Narrow selectors over existing world/country identities and province binding."""
from __future__ import annotations

from typing import Any

from . import empire_memory
from . import mission_task_memory


COUNTRY_CAPITAL_ID_OFFSET = 0x14B8
EMPEROR_FULLREF_OFFSET = 0x10
SOURCE = "retained_scope_selector_with_existing_empire_and_province_bindings"


def _read(reader: Any, address: int, size: int, label: str) -> bytes:
    return mission_task_memory._read_unaligned(reader, address, size, label)


def read_scope_selector(reader: Any, module_base: int, kind: str,
                        current_country_pointer: int) -> dict[str, Any]:
    """Read selector input only; the caller canonically binds/admit its target."""
    try:
        if type(module_base) is not int or not mission_task_memory._valid_pointer(module_base):
            raise ValueError("dynamic_scope_module_base_invalid")
        if kind == "capital":
            if (type(current_country_pointer) is not int
                    or not mission_task_memory._valid_pointer(current_country_pointer)):
                raise ValueError("capital_country_pointer_invalid")
            raw = _read(reader, current_country_pointer + COUNTRY_CAPITAL_ID_OFFSET,
                        4, "mission_scope.capital.province_id")
            province_id = int.from_bytes(raw, "little", signed=True)
            if not 1 <= province_id < 65536:
                raise ValueError("capital_province_id_missing_or_invalid")
            return {"status": "known", "province_id": province_id, "source": SOURCE}
        if kind != "emperor":
            raise ValueError("dynamic_scope_kind_unsupported")
        world = int.from_bytes(_read(reader, module_base + empire_memory.WORLD_GLOBAL_RVA,
                                     8, "mission_scope.emperor.world"), "little")
        empire_memory._pointer(world, "world")
        world_vtable = int.from_bytes(_read(reader, world, 8,
                                            "mission_scope.emperor.world_vtable"), "little")
        if world_vtable != module_base + empire_memory.WORLD_VTABLE_RVA:
            raise ValueError("emperor_world_vtable_mismatch")
        hre = world + empire_memory.HRE_OFFSET
        hre_vtable = int.from_bytes(_read(reader, hre, 8,
                                          "mission_scope.emperor.hre_vtable"), "little")
        if hre_vtable != module_base + empire_memory.HRE_VTABLE_RVA:
            raise ValueError("emperor_hre_vtable_mismatch")
        raw = _read(reader, hre + EMPEROR_FULLREF_OFFSET, 8,
                    "mission_scope.emperor.fullref")
        fullref, _tag = empire_memory._fullref(raw, "emperor")
        return {"status": "known", "fullref": fullref, "source": SOURCE}
    except Exception as exc:
        return {"status": "unknown", "reason": f"dynamic_scope_read_failed:{type(exc).__name__}:{exc}"}
