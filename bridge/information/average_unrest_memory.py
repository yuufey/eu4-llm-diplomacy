"""Copy the country cache registered as average_unrest on fixed 1.37.4.

The parent owns identity, process lifetime, read budget and double pass.
The independent profile binds the exact property, producer and unit evidence.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


PROFILE_FILE = Path(__file__).with_name("profiles") / "average-unrest-memory-1374.json"
EXPECTED_PROFILE_SHA256 = "d5ec922b125ac8bf34ddf3063bd3c2212a3cfd5590f3f781d09296c55efc9cb1"
_ROOT = Path(__file__).resolve().parents[2]
_BASIS = "native_country_average_unrest_cache"


def _load_profile():
    with PROFILE_FILE.open("rb") as stream:
        raw = stream.read(65537)
    if not 0 < len(raw) <= 65536 or hashlib.sha256(raw).hexdigest() != EXPECTED_PROFILE_SHA256:
        raise ValueError("AVERAGE_UNREST_PROFILE_MISMATCH")
    profile = json.loads(raw)
    source = profile["source_index"]
    path = (_ROOT / source["path"]).resolve()
    if _ROOT not in path.parents or path.stat().st_size > 131072:
        raise ValueError("AVERAGE_UNREST_SOURCE_INDEX_INVALID")
    with path.open("rb") as stream:
        source_raw = stream.read(131073)
    if len(source_raw) > 131072 or hashlib.sha256(source_raw).hexdigest() != source["sha256"]:
        raise ValueError("AVERAGE_UNREST_SOURCE_INDEX_MISMATCH")
    return profile


def validate_record(record):
    """Require the field-specific code guards and the copied scalar bytes."""
    try:
        observation = record["observation"]
        if (observation["basis"] != _BASIS
                or observation["profile_sha256"] != EXPECTED_PROFILE_SHA256):
            return False
        profile = _load_profile()
        expected = {item["name"]: item["sha256"] for item in profile["code_guards"]}
        guard = observation["code_guard"]
        raw = bytes.fromhex(observation["cache_raw_hex"])
        return (guard["status"] == "observed"
                and guard["checks"] == dict.fromkeys(expected, True)
                and guard["actual_sha256"] == expected
                and observation["offset"] == profile["layout"]["country_average_unrest_offset"]
                and len(raw) == 4 and raw.hex() == record["raw_hex"]
                and type(record["raw"]) is int
                and int.from_bytes(raw, "little", signed=True) == record["raw"])
    except (KeyError, TypeError, ValueError, OSError):
        return False


def capture(reader, module_base: int, country: int) -> dict:
    observation = {"basis": _BASIS, "profile_sha256": EXPECTED_PROFILE_SHA256}
    try:
        profile = _load_profile()
        guard = {"status": "unknown", "checks": {}, "actual_sha256": {}}
        observation["code_guard"] = guard
        for item in profile["code_guards"]:
            expected = bytes.fromhex(item["hex"])
            actual = reader.read(module_base + int(item["rva"], 0), len(expected),
                                 "unrest.code." + item["name"])
            guard["checks"][item["name"]] = actual == expected
            guard["actual_sha256"][item["name"]] = hashlib.sha256(actual).hexdigest()
        if not guard["checks"] or not all(guard["checks"].values()):
            raise ValueError("AVERAGE_UNREST_CODE_CHANGED")
        guard["status"] = "observed"
        observation["offset"] = profile["layout"]["country_average_unrest_offset"]
        raw = reader.read(country + int(observation["offset"], 0), 4, "unrest.current_cache")
        if len(raw) != 4:
            raise ValueError("AVERAGE_UNREST_READ_INCOMPLETE")
        observation["cache_raw_hex"] = raw.hex()
        return {"status": "known", "raw": int.from_bytes(raw, "little", signed=True),
                "raw_hex": raw.hex(), "unit": "unrest", "scale": 1000,
                "observation": observation}
    except Exception as exc:
        return {"status": "unknown", "reason": str(exc) or type(exc).__name__,
                "observation": observation}
