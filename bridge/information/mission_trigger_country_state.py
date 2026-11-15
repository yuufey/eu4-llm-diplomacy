"""Narrow adapters for country scalar state used by mission triggers.

The caller owns process/session identity, FRA binding, outer two-pass capture,
and knowledge/eligibility gates. These helpers only reuse existing read-only
country readers through the caller's already tracked reader.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from . import country_modifiers_memory
from . import mission_task_memory
from . import religious_unity_memory


SOURCE_UNITY = "religious_unity_memory.capture"
SOURCE_MODIFIERS = "country_modifiers_memory.read_fields"
_MIN_USER_ADDRESS = 0x10000
_MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF
_INT32_MIN = -(2**31)
_INT32_MAX = 2**31 - 1
_MODIFIER_KEY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _reason(record: Any, fallback: str) -> str:
    if isinstance(record, Mapping) and type(record.get("reason")) is str:
        return record["reason"]
    return fallback


class _TrackedReaderAdapter:
    """Route child reader calls through the mission reader's unaligned path."""

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


def _canonical_pointer(value: Any) -> int | None:
    if type(value) is not str or not value.startswith("0x"):
        return None
    digits = value[2:]
    if not digits or any(char not in "0123456789abcdefABCDEF" for char in digits):
        return None
    try:
        pointer = int(digits, 16)
    except ValueError:
        return None
    if not _MIN_USER_ADDRESS <= pointer <= _MAX_USER_ADDRESS:
        return None
    if hex(pointer) != value:
        return None
    return pointer


def _canonical_key(value: Any) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 255
        and value.isascii()
        and all(char in _MODIFIER_KEY_CHARS for char in value)
    )


def _read_religious_unity(
    reader: Any, module_base: int, country_pointer: int
) -> dict[str, Any]:
    tracked = _TrackedReaderAdapter(reader, module_base)
    try:
        record = religious_unity_memory.capture(
            tracked, module_base, country_pointer
        )
    except Exception as exc:
        return _unknown(
            f"RELIGIOUS_UNITY_CAPTURE_FAILED:{type(exc).__name__}"
        )
    if not isinstance(record, Mapping):
        return _unknown("RELIGIOUS_UNITY_RECORD_INVALID")
    if record.get("status") != "known":
        return _unknown(_reason(record, "RELIGIOUS_UNITY_NOT_KNOWN"))

    raw = record.get("raw")
    if type(raw) is not int or not _INT32_MIN <= raw <= _INT32_MAX:
        return _unknown("RELIGIOUS_UNITY_RAW_INVALID")
    if type(record.get("scale")) is not int or record.get("scale") != 1000:
        return _unknown("RELIGIOUS_UNITY_SCALE_INVALID")
    if record.get("unit") != "fraction":
        return _unknown("RELIGIOUS_UNITY_UNIT_INVALID")
    try:
        validated = religious_unity_memory.validate_record(record)
    except Exception as exc:
        return _unknown(
            f"RELIGIOUS_UNITY_VALIDATOR_FAILED:{type(exc).__name__}"
        )
    if validated is not True:
        return _unknown("RELIGIOUS_UNITY_RECORD_VALIDATION_FAILED")
    return {
        "status": "known",
        "raw_fixed_milli": raw,
        "source": SOURCE_UNITY,
    }


def _read_modifiers(
    reader: Any, module_base: int, country_pointer: int
) -> dict[str, Any]:
    tracked = _TrackedReaderAdapter(reader, module_base)
    try:
        record = country_modifiers_memory.read_fields(
            tracked, module_base, country_pointer
        )
    except Exception as exc:
        return _unknown(
            f"COUNTRY_MODIFIERS_CAPTURE_FAILED:{type(exc).__name__}"
        )
    if not isinstance(record, Mapping):
        return _unknown("COUNTRY_MODIFIERS_RECORD_INVALID")
    if record.get("status") != "observed":
        return _unknown(_reason(record, "COUNTRY_MODIFIERS_NOT_OBSERVED"))

    expected_module = hex(module_base)
    expected_country = hex(country_pointer)
    if (
        record.get("module_base") != expected_module
        or record.get("country_pointer") != expected_country
    ):
        return _unknown("COUNTRY_MODIFIERS_IDENTITY_MISMATCH")

    fields = record.get("fields")
    field = fields.get("modifiers") if isinstance(fields, Mapping) else None
    if not isinstance(field, Mapping):
        return _unknown("COUNTRY_MODIFIERS_FIELD_MISSING")
    if field.get("status") != "known":
        return _unknown(_reason(field, "COUNTRY_MODIFIERS_FIELD_NOT_KNOWN"))
    if field.get("complete") is not True:
        return _unknown("COUNTRY_MODIFIERS_FIELD_INCOMPLETE")

    compact = field.get("value")
    values = record.get("values")
    value_copy = values.get("modifiers") if isinstance(values, Mapping) else None
    if not isinstance(compact, list) or compact != value_copy:
        return _unknown("COUNTRY_MODIFIERS_COMPACT_VALUE_MISMATCH")

    observation = record.get("observation")
    if not isinstance(observation, Mapping):
        return _unknown("COUNTRY_MODIFIERS_OBSERVATION_MISSING")
    if (
        observation.get("module_base") != expected_module
        or observation.get("country_pointer") != expected_country
    ):
        return _unknown("COUNTRY_MODIFIERS_OBSERVATION_IDENTITY_MISMATCH")
    nodes = observation.get("nodes")
    if not isinstance(nodes, list) or len(nodes) > 128:
        return _unknown("COUNTRY_MODIFIERS_NODES_INVALID")
    if observation.get("terminated") is not True:
        return _unknown("COUNTRY_MODIFIERS_LIST_NOT_TERMINATED")
    count = observation.get("count_observed")
    if type(count) is not int or count != len(nodes) or len(nodes) != len(compact):
        return _unknown("COUNTRY_MODIFIERS_NODE_COUNT_MISMATCH")

    definitions: list[dict[str, Any]] = []
    pointer_keys: dict[int, str] = {}
    seen_definitions: set[int] = set()
    for node, compact_item in zip(nodes, compact):
        if not isinstance(node, Mapping) or not isinstance(compact_item, Mapping):
            return _unknown("COUNTRY_MODIFIERS_NODE_PAIR_INVALID")
        pointer = _canonical_pointer(node.get("definition_address"))
        definition = node.get("definition")
        key = definition.get("key") if isinstance(definition, Mapping) else None
        compact_key = compact_item.get("key")
        if pointer is None or not _canonical_key(key):
            return _unknown("COUNTRY_MODIFIERS_DEFINITION_INVALID")
        if not _canonical_key(compact_key) or compact_key != key:
            return _unknown("COUNTRY_MODIFIERS_NODE_PAIR_MISMATCH")
        previous_key = pointer_keys.get(pointer)
        if previous_key is not None and previous_key != key:
            return _unknown("COUNTRY_MODIFIERS_POINTER_KEY_CONFLICT")
        pointer_keys[pointer] = key
        if pointer not in seen_definitions:
            definitions.append({"pointer": pointer, "key": key})
            seen_definitions.add(pointer)

    return {
        "status": "known",
        "definitions": definitions,
        "source": SOURCE_MODIFIERS,
    }


def read_country_state(
    reader: Any, module_base: int, country_pointer: int, kind: str
) -> dict[str, Any]:
    """Read one supported country state through the existing tracked reader."""
    if type(kind) is not str or kind not in {"religious_unity", "modifiers"}:
        return _unknown("COUNTRY_STATE_KIND_UNSUPPORTED")
    if type(module_base) is not int or type(country_pointer) is not int:
        return _unknown("COUNTRY_STATE_IDENTITY_INVALID")
    if kind == "religious_unity":
        return _read_religious_unity(reader, module_base, country_pointer)
    return _read_modifiers(reader, module_base, country_pointer)


__all__ = ["SOURCE_UNITY", "SOURCE_MODIFIERS", "read_country_state"]
