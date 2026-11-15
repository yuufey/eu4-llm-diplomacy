"""Narrow DLC predicate adapter for the loaded mission trigger reader."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import mission_branch_memory
from . import mission_task_memory
from .dlc_short_circuit_bindings import DLC_BINDINGS, DLC_OVERRIDE_RVA, SUPPORTED_DLC_NAMES


SOURCE = "mission_branch_memory._read_domination"
DOMINATION_MASK = 0x80000
_MIN_USER_ADDRESS = 0x10000
_MAX_USER_ADDRESS_EXCLUSIVE = 0x0000800000000000


def _bound_profile_mask() -> int:
    """Read the DLC mask from the already pinned branch profile."""
    try:
        value = mission_branch_memory.PROFILE["domination"]["domination_name_mapping"]["object_mask"]
        if type(value) is not str:
            raise ValueError("profile_mask_not_string")
        parsed = int(value, 0)
    except Exception as exc:
        raise RuntimeError("bound_domination_mask_unavailable") from exc
    if parsed != DOMINATION_MASK:
        raise RuntimeError("bound_domination_mask_mismatch")
    return parsed


_PROFILE_DOMINATION_MASK = _bound_profile_mask()
if (DLC_BINDINGS[_PROFILE_DOMINATION_MASK] != (
        "Domination", mission_branch_memory.DOMINATION_GLOBAL_BOOL_RVA)
        or DLC_OVERRIDE_RVA != mission_branch_memory.DOMINATION_OVERRIDE_BYTE_RVA):
    raise RuntimeError("retained_dlc_binding_anchor_mismatch")


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


class _TrackedReaderAdapter:
    """Keep the branch helper on the caller's tracked, unaligned read path."""

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


def read_dlc_state(reader: Any, module_base: int, mask: Any) -> dict[str, Any]:
    """Resolve retained single-bit DLC positive short circuits.

    All other masks and all unresolved TLS/override paths remain unknown. The
    supplied reader owns process/session checks, call accounting, and tracing.
    """
    if type(mask) is not int:
        return _unknown("dlc_mask_invalid")
    if mask not in DLC_BINDINGS:
        return _unknown("dlc_mask_unsupported")
    if (type(module_base) is not int
            or not _MIN_USER_ADDRESS <= module_base < _MAX_USER_ADDRESS_EXCLUSIVE
            or module_base & 7):
        return _unknown("module_base_invalid")
    if not (callable(getattr(reader, "read_code", None))
            or callable(getattr(reader, "_read", None))
            or callable(getattr(reader, "read", None))):
        return _unknown("reader_invalid")

    try:
        if mask != _PROFILE_DOMINATION_MASK:
            name, global_rva = DLC_BINDINGS[mask]
            tracked = _TrackedReaderAdapter(reader, module_base)
            global_raw = mission_branch_memory._read_unaligned(
                tracked, module_base + global_rva, 1, "dlc.global_bool")
            override_raw = mission_branch_memory._read_unaligned(
                tracked, module_base + DLC_OVERRIDE_RVA, 1, "dlc.override_byte")
            if len(global_raw) != 1 or len(override_raw) != 1:
                raise ValueError("dlc_byte_read_size_invalid")
            if global_raw[0] != 0 and override_raw[0] == 0:
                return {"status": "known", "satisfied": True, "dlc": name,
                        "source": "retained_dlc_short_circuit"}
            return _unknown(mission_branch_memory.DOMINATION_UNKNOWN_REASON)
        record = mission_branch_memory._read_domination(
            _TrackedReaderAdapter(reader, module_base), module_base
        )
    except Exception as exc:
        return _unknown(f"domination_reader_failed:{type(exc).__name__}")
    if not isinstance(record, Mapping):
        return _unknown("domination_result_invalid")
    if (record.get("status") == "observed"
            and record.get("known") is True
            and record.get("value") is True):
        return {
            "status": "known",
            "satisfied": True,
            "dlc": "Domination",
            "source": SOURCE,
        }
    reason = record.get("unknown_reason")
    if type(reason) is str and reason:
        return _unknown(reason)
    return _unknown("DOMINATION_DLC_UNRESOLVED")


__all__ = ["DOMINATION_MASK", "SOURCE", "SUPPORTED_DLC_NAMES", "read_dlc_state"]
