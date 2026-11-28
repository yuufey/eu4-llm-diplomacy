"""Add the native retention-tooltip amount to the immutable T03 v1 leaf.

The value describes money retained in the node before individual countries'
trade efficiency. It does not sum country income or convert a power percent.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from . import trade_value_memory as legacy
from . import province_state_capture as _reviewed

ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = Path(__file__).with_name("profiles") / "trade-collected-memory-1374-v2.json"
PROFILE_SHA256 = "68a7f0a4f7822124f6ee3dd13d1b8982e3fc38de977bd58e7a1379c9adb78c93"
LEGACY_PROFILE_SHA256 = "4e376be3cd5a9bbaa412e6c0183bc0fbabc0fab019da88cc4d44309312bb35b4"
FIELDS = legacy.FIELDS
_MAX_PROFILE_BYTES = 256 * 1024


def _sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_profile():
    if not 0 < PROFILE_FILE.stat().st_size <= _MAX_PROFILE_BYTES:
        raise ValueError("TRADE_COLLECTED_PROFILE_SIZE")
    raw = PROFILE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("TRADE_COLLECTED_PROFILE_PIN")
    profile = json.loads(raw)
    if (profile.get("profile_id") != "trade-collected-memory-1374"
            or profile.get("profile_version") != 2 or profile.get("game_version") != "1.37.4"
            or profile.get("executable", {}).get("sha256") != legacy.EXPECTED_EXE_SHA256):
        raise ValueError("TRADE_COLLECTED_PROFILE_BUILD")
    for section in ("source_evidence", "layout_dependencies"):
        for item in profile[section]:
            path = (ROOT / item["path"]).resolve()
            path.relative_to(ROOT)
            if (item["path"] == "bridge/information/trade_value_capture.py"
                    and _reviewed._matches_reviewed_layout(item)):
                continue
            if path.stat().st_size != item["bytes"] or _sha(path) != item["sha256"]:
                raise ValueError("TRADE_COLLECTED_PROFILE_DEPENDENCY")
    guards = profile.get("code_guards")
    if not isinstance(guards, list) or not 1 <= len(guards) <= 64:
        raise ValueError("TRADE_COLLECTED_GUARDS_MISSING")
    total = 0
    for guard in guards:
        raw = bytes.fromhex(guard["bytes"])
        rva = int(guard["rva"], 0)
        if (not 0 < len(raw) <= 1024 or int(guard["end_rva_exclusive"], 0) != rva + len(raw)
                or hashlib.sha256(raw).hexdigest() != guard["sha256"]):
            raise ValueError("TRADE_COLLECTED_GUARD_INVALID")
        total += len(raw)
    if total > 32 * 1024:
        raise ValueError("TRADE_COLLECTED_GUARD_BUDGET")
    return profile


def code_guards():
    return load_profile()["code_guards"]


def _guards(reader, base, guards):
    evidence = []
    for guard in guards:
        expected = bytes.fromhex(guard["bytes"])
        address = base + int(guard["rva"], 0)
        actual = reader.read(address, len(expected), "trade_collected.code." + guard["name"])
        evidence.append({"address": hex(address), "name": guard["name"],
                         "expected_hex": expected.hex(), "actual_hex": actual.hex(),
                         "matches": actual == expected})
    return evidence


def read_fields(reader, base, province_binding, fields, *, node_id):
    if (not isinstance(fields, (tuple, list)) or not fields or len(fields) > 5
            or any(type(name) is not str or name not in FIELDS for name in fields)
            or len(set(fields)) != len(fields)):
        raise ValueError("TRADE_COLLECTED_FIELD_SCOPE")
    names = tuple(fields)
    collected = "T03.collected_value"
    needed = [name for name in names if name != collected]
    if collected in names and "T03.total_value" not in needed:
        needed.append("T03.total_value")
    values = legacy.read_fields(reader, base, province_binding, needed, node_id=node_id)
    result = {name: deepcopy(values[name]) for name in names if name != collected}
    if collected not in names:
        return result
    total = values.get("T03.total_value", {})
    if total.get("status") != "known":
        result[collected] = {"status": "unknown", "reason": "NODE_RETENTION_VALUE_INPUTS_UNKNOWN"}
        return result
    raw_inputs = {"profile_sha256": PROFILE_SHA256, "value_inputs": deepcopy(total["raw_inputs"])}
    try:
        guards = code_guards()
        before = _guards(reader, base, guards)
        raw_inputs["runtime_code_before"] = before
        if not all(row["matches"] for row in before):
            raise ValueError("NODE_RETENTION_CODE_MISMATCH")
        runtime = int(total["raw_inputs"]["identity"]["runtime_pointer"], 0)
        if not legacy._valid_address(runtime, alignment=8):
            raise ValueError("NODE_RETENTION_RUNTIME_POINTER_INVALID")
        address = legacy._address_add(runtime, 0xDC, "retention_power_gate")
        raw = reader.read(address, 8, "trade_collected.power_gate_i32_pair")
        if not isinstance(raw, bytes) or len(raw) != 8:
            raise ValueError("NODE_RETENTION_POWER_GATE_SHORT_READ")
        pull = int.from_bytes(raw[:4], "little", signed=True)
        retention = int.from_bytes(raw[4:], "little", signed=True)
        summed = legacy._wrap_i32(pull + retention)
        quotient = (abs(summed) // 1000) * (-1 if summed < 0 else 1)
        raw_inputs["power_gate"] = {"address": hex(address), "raw_hex": raw.hex(),
                                   "pull_power_raw": pull, "retention_power_raw": retention,
                                   "sum_i32": summed, "quotient_trunc0": quotient}
        after = _guards(reader, base, guards)
        raw_inputs["runtime_code_after"] = after
        if before != after or not all(row["matches"] for row in after):
            raise ValueError("NODE_RETENTION_CODE_CHANGED")
        if quotient == 0:
            result[collected] = {"status": "unknown", "reason": "NODE_RETENTION_NO_TRADE_IN_NODE",
                                 "raw_inputs": raw_inputs}
        else:
            result[collected] = {"status": "known", "value": total["value"], "raw_inputs": raw_inputs,
                                 "basis": "native_trade_node_retention_tooltip_amount", "unit": "ducats",
                                 "scale": 1000, "period": "current", "complete": False,
                                 "scope": "node_retained_value_before_country_efficiency"}
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ValueError) else "NODE_RETENTION_READ_FAILED"
        result[collected] = {"status": "unknown", "reason": reason, "raw_inputs": raw_inputs}
    return {name: result[name] for name in names}


__all__ = ["PROFILE_SHA256", "load_profile", "code_guards", "read_fields"]
