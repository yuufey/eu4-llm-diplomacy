"""Evaluate the fixed 1.37.4 unclamped unity getter from copied inputs.

No game function is called. CALCULATING caches and non-null modifier
processors remain explicit gaps. The supported path includes the E7 rule,
dense/sparse lookup, signed 32-bit addition and the native lower clamp.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


PROFILE_FILE = Path(__file__).with_name("profiles") / "religious-unity-memory-1374.json"
EXPECTED_PROFILE_SHA256 = "281c45c5dfee98a366858e212eefc52c26c907d8695b3802538fcd2bde4caef7"
_ROOT = Path(__file__).resolve().parents[2]
_BASIS = "native_getter_equivalent_from_copied_inputs"


def _load_profile():
    with PROFILE_FILE.open("rb") as stream:
        raw = stream.read(65537)
    if not 0 < len(raw) <= 65536 or hashlib.sha256(raw).hexdigest() != EXPECTED_PROFILE_SHA256:
        raise ValueError("RELIGIOUS_UNITY_PROFILE_MISMATCH")
    profile = json.loads(raw)
    source = profile["source_index"]
    path = (_ROOT / source["path"]).resolve()
    if _ROOT not in path.parents or path.stat().st_size > 65536:
        raise ValueError("RELIGIOUS_UNITY_SOURCE_INDEX_INVALID")
    with path.open("rb") as stream:
        source_raw = stream.read(65537)
    if len(source_raw) > 65536 or hashlib.sha256(source_raw).hexdigest() != source["sha256"]:
        raise ValueError("RELIGIOUS_UNITY_SOURCE_INDEX_MISMATCH")
    return profile


def _integer(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def _derive(inputs):
    def integer(value, minimum=-(2**31), maximum=2**31-1):
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError("RELIGIOUS_UNITY_INPUT_INVALID")
        return value

    if integer(inputs["cache_state"]) == 1:
        raise ValueError("RELIGIOUS_UNITY_CACHE_CALCULATING")
    special = inputs["special_rule"]
    if integer(special["processor"], 0, 2**64-1):
        raise ValueError("RELIGIOUS_UNITY_SPECIAL_PROCESSOR_UNSUPPORTED")
    flags = integer(special["type_flags"], 0, 255)
    if flags & 0x40 and integer(special["base_raw"]) != 0:
        return 1000
    unity = inputs["unity_modifier"]
    if integer(unity["processor"], 0, 2**64-1):
        raise ValueError("RELIGIOUS_UNITY_VALUE_PROCESSOR_UNSUPPORTED")
    total = integer(inputs["province_component_raw"]) + integer(unity["base_raw"])
    # The recorded 3B46D0 ADD EBX,EAX precedes the signed lower-bound test.
    signed = (total + 2**31) % 2**32 - 2**31
    return max(0, signed)


def validate_record(record):
    """Check the derived value and its field-specific guard independently."""
    try:
        calculation = record["calculation"]
        if (calculation["basis"] != _BASIS
                or calculation["profile_sha256"] != EXPECTED_PROFILE_SHA256
                or calculation["upper_clamp"] is not False):
            return False
        profile = _load_profile()
        expected = {item["name"]: item["sha256"] for item in profile["code_guards"]}
        guard = calculation["code_guard"]
        if (guard["status"] != "observed" or guard["checks"] != dict.fromkeys(expected, True)
                or guard["actual_sha256"] != expected):
            return False
        return _derive(calculation["inputs"]) == record["raw"]
    except (KeyError, TypeError, ValueError, OSError, OverflowError):
        return False


def capture(reader, module_base: int, country: int) -> dict:
    """Use the caller's already bound, budgeted reader and process lifetime."""
    calculation = {"basis": _BASIS, "upper_clamp": False,
                   "profile_sha256": EXPECTED_PROFILE_SHA256, "inputs": {}}
    try:
        profile = _load_profile()
        layout = {key: _integer(value) for key, value in profile["layout"].items()}
        limits = {key: _integer(value) for key, value in profile["limits"].items()}
        guard = {"status": "unknown", "checks": {}, "actual_sha256": {}}
        calculation["code_guard"] = guard
        for item in profile["code_guards"]:
            expected = bytes.fromhex(item["hex"])
            actual = reader.read(module_base + _integer(item["rva"]), len(expected),
                                 "religious_unity.code." + item["name"])
            guard["checks"][item["name"]] = actual == expected
            guard["actual_sha256"][item["name"]] = hashlib.sha256(actual).hexdigest()
        if not guard["checks"] or not all(guard["checks"].values()):
            raise ValueError("RELIGIOUS_UNITY_CODE_CHANGED")
        guard["status"] = "observed"

        def read(address, size, label):
            return reader.read(address, size, "religious_unity." + label)

        def int32(address, label):
            return int.from_bytes(read(address, 4, label), "little", signed=True)

        inputs = calculation["inputs"]
        inputs["cache_state"] = int32(country + layout["country_cache_state_offset"], "cache_state")
        if inputs["cache_state"] == layout["calculating_state"]:
            raise ValueError("RELIGIOUS_UNITY_CACHE_CALCULATING")
        modifier = country + layout["country_modifier_object_offset"]
        header_size = max(layout["modifier_sparse_count_offset"] + 4,
                          layout["modifier_values_pointer_offset"] + 8,
                          layout["modifier_dense_flag_offset"] + 1)
        header = read(modifier, header_size, "modifier_header")
        dense = header[layout["modifier_dense_flag_offset"]] != 0
        offset = layout["modifier_values_pointer_offset"]
        pointer = int.from_bytes(header[offset:offset+8], "little")
        offset = layout["modifier_sparse_count_offset"]
        count = int.from_bytes(header[offset:offset+4], "little", signed=True)
        inputs.update(dense=dense, sparse_count=count)
        database = int.from_bytes(read(module_base + layout["modifier_database_rva"], 8,
                                       "modifier_database"), "little")

        def record(identifier, label):
            row = read(database + identifier * layout["record_stride"],
                       layout["record_stride"], label + ".record")
            offset = layout["record_processor_offset"]
            processor = int.from_bytes(row[offset:offset+8], "little")
            offset = layout["record_resolved_type_offset"]
            resolved = int.from_bytes(row[offset:offset+4], "little")
            return {"processor": processor, "resolved_type": resolved}

        def base_value(identifier, label):
            if dense:
                return int32(pointer + identifier * layout["dense_entry_stride"]
                             + layout["dense_value_offset"], label + ".dense_value")
            if count > limits["max_sparse_entries"]:
                raise ValueError("RELIGIOUS_UNITY_SPARSE_TABLE_OVER_BOUND")
            for index in range(max(0, count)):
                pair = read(pointer + index * 8, 8, label + f".sparse[{index}]")
                if int.from_bytes(pair[:4], "little") == identifier:
                    return int.from_bytes(pair[4:], "little", signed=True)
            return 0

        special_id = layout["special_rule_id"]
        special = record(special_id, "special")
        inputs["special_rule"] = special
        if special["processor"]:
            raise ValueError("RELIGIOUS_UNITY_SPECIAL_PROCESSOR_UNSUPPORTED")
        if special["resolved_type"] > limits["max_type_id"]:
            raise ValueError("RELIGIOUS_UNITY_RESOLVED_TYPE_OVER_BOUND")
        special["type_flags"] = read(database + special["resolved_type"] * layout["record_stride"]
                                     + layout["record_flags_offset"], 1, "special.type_flags")[0]
        special["base_raw"] = (base_value(special_id, "special")
                               if special["type_flags"] & layout["boolean_flag_mask"] else 0)
        forced = special["type_flags"] & layout["boolean_flag_mask"] and special["base_raw"] != 0
        if not forced:
            inputs["province_component_raw"] = int32(country + layout["country_province_component_offset"],
                                                       "province_component")
            unity_id = layout["unity_modifier_id"]
            unity = record(unity_id, "unity")
            inputs["unity_modifier"] = unity
            if unity["processor"]:
                raise ValueError("RELIGIOUS_UNITY_VALUE_PROCESSOR_UNSUPPORTED")
            unity["base_raw"] = base_value(unity_id, "unity")
        raw = _derive(inputs)
        return {"status": "known", "raw": raw, "raw_hex": raw.to_bytes(4, "little", signed=True).hex(),
                "unit": "fraction", "scale": 1000, "calculation": calculation}
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ValueError) else "RELIGIOUS_UNITY_INPUT_READ_FAILED:" + type(exc).__name__
        return {"status": "unknown", "reason": reason, "calculation": calculation}
