"""Bounded leaf for reading one province resource's cached localization bytes.

The province identity/key source and country-view admission remain parent
responsibilities. This leaf only reuses the fixed-build localization snapshot
helper through an already supplied RPM reader; it never opens a process or
decodes/substitutes the returned text.
"""
from __future__ import annotations

import re
from typing import Any

from . import localization_memory as _localization


_RESOURCE_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z", re.ASCII)
_LANGUAGE = re.compile(r"l_[A-Za-z0-9_]{1,63}\Z", re.ASCII)
_MAX_READ_CALLS = 2048
_MAX_TOTAL_READ_BYTES = 65_536
_MAX_SINGLE_READ_BYTES = 16_384
_MAX_USER_ADDRESS = 0x0000800000000000


class _LocalReadError(RuntimeError):
    """A local bound or supplied-reader failure stopped this leaf."""


class _SnapshotReader:
    """Narrow budget wrapper exposing only the API used by `_snapshot`."""

    def __init__(self, reader: Any, module_base: int):
        self._reader = reader
        self.module_base = module_base
        self.calls = 0
        self.bytes_requested = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if (type(address) is not int or address < 0x10000
                or address >= _MAX_USER_ADDRESS
                or type(size) is not int or size <= 0
                or size > _MAX_SINGLE_READ_BYTES
                or address + size > _MAX_USER_ADDRESS):
            raise _LocalReadError("LOCALIZATION_READ_RANGE_INVALID")
        if self.calls >= _MAX_READ_CALLS:
            raise _LocalReadError("LOCALIZATION_CALL_BUDGET_EXCEEDED")
        if self.bytes_requested + size > _MAX_TOTAL_READ_BYTES:
            raise _LocalReadError("LOCALIZATION_BYTE_BUDGET_EXCEEDED")
        method = getattr(self._reader, "read", None)
        if not callable(method):
            raise _LocalReadError("LOCALIZATION_READER_UNAVAILABLE")
        # Count requested work even if the backing reader fails or short-reads.
        self.calls += 1
        self.bytes_requested += size
        raw = method(address, size, label)
        if not isinstance(raw, (bytes, bytearray, memoryview)):
            raise _LocalReadError("LOCALIZATION_READ_NOT_BYTES")
        data = bytes(raw)
        if len(data) != size:
            raise _LocalReadError("LOCALIZATION_SHORT_READ")
        return data

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little"), raw


def _unknown(reason: str, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    # Keep the public reason vocabulary fixed and safe. Diagnostic details stay
    # inside the caller-owned private raw_inputs object.
    if not isinstance(reason, str) or re.fullmatch(r"[A-Z0-9_]{1,64}", reason) is None:
        reason = "LOCALIZATION_LOOKUP_UNKNOWN"
    return {"status": "unknown", "reason": reason, "raw_inputs": raw_inputs}


def _entry_shape_valid(entry: Any, key: str) -> bool:
    expected_keys = {
        "key", "status", "hash", "offset", "value_address", "value_read_bytes",
        "raw_hex", "value_hex", "byte_length", "native_cached_template",
        "dynamic_tokens_not_substituted",
    }
    if not isinstance(entry, dict) or set(entry) != expected_keys:
        return False
    if (entry.get("key") != key or entry.get("status") != "observed"
            or entry.get("hash") != hex(_localization._fnv1_ascii(key))
            or type(entry.get("offset")) is not int or entry["offset"] < 0
            or type(entry.get("value_read_bytes")) is not int
            or not 1 <= entry["value_read_bytes"] <= _localization.MAX_VALUE_BYTES + 1
            or type(entry.get("byte_length")) is not int
            or not 0 <= entry["byte_length"] <= _localization.MAX_VALUE_BYTES
            or entry.get("native_cached_template") is not True
            or entry.get("dynamic_tokens_not_substituted") is not True):
        return False
    raw_hex = entry.get("raw_hex")
    value_hex = entry.get("value_hex")
    if (not isinstance(raw_hex, str) or not isinstance(value_hex, str)
            or raw_hex != value_hex or len(value_hex) % 2
            or re.fullmatch(r"(?:[0-9a-f]{2})*", value_hex) is None
            or len(value_hex) // 2 != entry["byte_length"]):
        return False
    return entry["value_read_bytes"] >= entry["byte_length"] + 1


def _language_valid(language: Any) -> bool:
    if (not isinstance(language, dict) or language.get("status") != "observed"
            or language.get("complete") is not True
            or not isinstance(language.get("text"), str)
            or _LANGUAGE.fullmatch(language["text"]) is None
            or type(language.get("length")) is not int
            or language["length"] != len(language["text"])
            or type(language.get("capacity")) is not int
            or language["capacity"] < language["length"]
            or language["capacity"] > _localization.MAX_STRING_CAPACITY
            or language.get("nul_terminator_observed") is not True):
        return False
    storage = "inline" if language["capacity"] < 16 else "heap"
    if language.get("storage") != storage:
        return False
    header_hex = language.get("header_hex")
    payload_hex = language.get("payload_hex")
    if (not isinstance(header_hex, str) or len(header_hex) != 64
            or re.fullmatch(r"[0-9a-f]{64}", header_hex) is None
            or not isinstance(payload_hex, str) or len(payload_hex) % 2
            or re.fullmatch(r"(?:[0-9a-f]{2})*", payload_hex) is None):
        return False
    payload = bytes.fromhex(payload_hex)
    if len(payload) != language["length"] + 1 or payload[-1] != 0:
        return False
    if any(byte >= 0x80 or byte == 0 for byte in payload[:-1]):
        return False
    return payload[:-1].decode("ascii") == language["text"]


def read_cached_name(reader: Any, base: Any, key: Any) -> dict[str, Any]:
    """Read one key from the current native localization cache.

    `reader` must be an existing bounded RPM adapter. The result preserves the
    cached value as bytes; it does not claim key-to-text identity beyond the
    native hash lookup, and it does not evaluate EU4 dynamic tokens.
    """
    request_raw: dict[str, Any] = {
        "module_base": hex(base) if type(base) is int else None,
        "key": key if isinstance(key, str) else {"type": type(key).__name__},
    }
    if (not isinstance(key, str) or _RESOURCE_KEY.fullmatch(key) is None):
        return _unknown("RESOURCE_LOCALIZATION_KEY_INVALID", {"request": request_raw})
    if (type(base) is not int or not 0x10000 <= base < _MAX_USER_ADDRESS
            or base % 8):
        return _unknown("LOCALIZATION_MODULE_BASE_INVALID", {"request": request_raw})
    try:
        reader_base = getattr(reader, "module_base", base)
    except Exception:
        return _unknown("LOCALIZATION_READER_UNAVAILABLE", {"request": request_raw})
    if type(reader_base) is not int or reader_base != base:
        return _unknown("LOCALIZATION_MODULE_BASE_MISMATCH", {"request": request_raw})
    if not callable(getattr(reader, "read", None)):
        return _unknown("LOCALIZATION_READER_UNAVAILABLE", {"request": request_raw})

    bounded = _SnapshotReader(reader, base)
    try:
        snapshot = _localization._snapshot(bounded, base, "FRA", [key])
    except Exception as exc:
        return _unknown("LOCALIZATION_SNAPSHOT_FAILED", {
            "request": request_raw,
            "snapshot_error": f"{type(exc).__name__}:{str(exc)[:160]}",
        })
    raw_inputs = {"snapshot": snapshot}
    if not isinstance(snapshot, dict) or snapshot.get("status") != "observed":
        return _unknown("LOCALIZATION_SNAPSHOT_INCOMPLETE", raw_inputs)

    country = snapshot.get("country_scan")
    matches = country.get("matches") if isinstance(country, dict) else None
    if (not isinstance(country, dict) or country.get("status") != "observed"
            or country.get("requested_country") != "FRA"
            or not isinstance(matches, list) or len(matches) != 1):
        return _unknown("LOCALIZATION_COUNTRY_SCAN_INVALID", raw_inputs)

    localization = snapshot.get("localization")
    language = localization.get("language") if isinstance(localization, dict) else None
    if (not isinstance(localization, dict) or localization.get("status") != "observed"
            or not _language_valid(language)):
        return _unknown("LOCALIZATION_LANGUAGE_INVALID", raw_inputs)

    entries = snapshot.get("entries")
    localization_entries = localization.get("entries")
    if (not isinstance(entries, dict) or set(entries) != {key}
            or not isinstance(localization_entries, dict)
            or set(localization_entries) != {key}
            or entries[key] != localization_entries[key]):
        return _unknown("LOCALIZATION_ENTRY_SHAPE_INVALID", raw_inputs)
    entry = entries[key]
    if isinstance(entry, dict) and entry.get("status") == "unknown":
        if (entry.get("key") == key
                and entry.get("hash") == hex(_localization._fnv1_ascii(key))
                and entry.get("unknown_reason") == "localization_key_not_found"
                and entry.get("value") is None and entry.get("raw_hex") is None
                and entry.get("value_hex") is None):
            return _unknown("LOCALIZATION_KEY_NOT_FOUND", raw_inputs)
        return _unknown("LOCALIZATION_ENTRY_UNKNOWN", raw_inputs)
    if not _entry_shape_valid(entry, key):
        return _unknown("LOCALIZATION_ENTRY_SHAPE_INVALID", raw_inputs)

    return {
        "status": "known",
        "raw_hex": entry["value_hex"],
        "language": language["text"],
        "raw_inputs": raw_inputs,
    }


__all__ = ["read_cached_name"]
