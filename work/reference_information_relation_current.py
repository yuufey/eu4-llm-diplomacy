"""Offline replay of a relation-current raw capture.

This helper intentionally does not import the production reader.  It checks
the copied row/vector bytes and reproduces only the direct leaf comparison;
it cannot make an unknown expiry/date field known.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys


PROFILE_ID = "relation-memory-1374"
PROFILE_SHA256 = "156cdfc92c96694189544ed99a1e15028236cee0d40460e326a0106597a77ba6"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
SOURCE_SHA256 = "31b786d242753f8849e0f2efee483d429a4a801eae0b6ef25d17245d5a5d3d41"
FAMILIES = ("alliance", "royal_marriage")


def _as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _unknown(family: str, reason: str) -> dict:
    return {"status": "unknown", "family": family, "value": None, "reason": reason, "partial": True, "complete": False, "unit": "relation_state", "scale": 1, "period": "current"}


def _replay_field(report: dict, family: str) -> dict:
    field = report.get("fields", {}).get(family)
    if not isinstance(field, dict) or field.get("status") != "known":
        return deepcopy(field) if isinstance(field, dict) else _unknown(family, "field_missing")
    raw = field.get("raw")
    context = report.get("context_after") or report.get("context_before")
    if not isinstance(raw, dict) or not isinstance(context, dict):
        return _unknown(family, "raw_context_missing")
    recipient = context.get("recipient")
    fullref = _as_int((recipient or {}).get("fullref", {}).get("value"))
    if fullref is None:
        return _unknown(family, "recipient_fullref_missing")
    slot = (fullref >> 32) & 0xffff
    slot_signed = slot - 0x10000 if slot & 0x8000 else slot
    if raw.get("recipient_slot_signed_i16") != slot_signed:
        return _unknown(family, "recipient_slot_binding_mismatch")
    elements = raw.get("elements")
    count = _as_int((raw.get("vector_count") or {}).get("value"))
    begin = _as_int((raw.get("vector_begin") or {}).get("value"))
    if count is None or count < 0 or count > 4096 or not isinstance(elements, list) or len(elements) != count:
        return _unknown(family, "vector_shape_invalid")
    matches = []
    for index, element in enumerate(elements):
        if not isinstance(element, dict) or element.get("index") != index:
            return _unknown(family, "element_index_invalid")
        raw_hex = element.get("raw_hex")
        if not isinstance(raw_hex, str) or len(raw_hex) != 32:
            return _unknown(family, "element_raw_invalid")
        try:
            chunk = bytes.fromhex(raw_hex)
        except ValueError:
            return _unknown(family, "element_hex_invalid")
        address = _as_int((element.get("address") or {}).get("va"))
        if begin is None or address != begin + index * 16:
            return _unknown(family, "element_address_binding_mismatch")
        if element.get("first_dword") != int.from_bytes(chunk[:4], "little") or element.get("unread_tail_raw_hex") != chunk[4:].hex():
            return _unknown(family, "element_decoded_value_mismatch")
        if int.from_bytes(chunk[:4], "little") == (slot_signed & 0xffffffff):
            matches.append(index)
    out = deepcopy(field)
    out["status"] = "known"
    out["value"] = bool(matches)
    out.setdefault("proof", {})["matching_element_indices"] = matches
    return out


def reference(report: dict) -> dict:
    requested = report.get("request", {}).get("families", list(FAMILIES)) if isinstance(report, dict) else list(FAMILIES)
    selected = [item for item in requested if item in FAMILIES]
    fields = {family: _replay_field(report, family) for family in selected}
    return {
        "schema": "information_relation_current_reference.v1",
        "source_kind": "independent_offline_raw_replay",
        "source_profile": {"profile_id": PROFILE_ID, "profile_sha256": PROFILE_SHA256},
        "source_evidence": {"relation-current-source-002.json": SOURCE_SHA256},
        "target_build": {"version": "1.37.4", "expected_exe_sha256": EXE_SHA256},
        "request": deepcopy(report.get("request", {})) if isinstance(report, dict) else {},
        "fields": fields,
        "rows": [{"relation_type": family, "status": "active" if field.get("value") is True else "inactive" if field.get("status") == "known" else "unknown", "actor": (report.get("request", {}) if isinstance(report, dict) else {}).get("actor"), "recipient": (report.get("request", {}) if isinstance(report, dict) else {}).get("recipient"), "grantor": {"status": "not_applicable", "reason": "SYMMETRIC_RELATION_NO_GRANTOR_ROLE"}, "expires_at": {"status": "unknown", "reason": "RELATION_EXPIRY_UNREAD"}} for family, field in fields.items()],
        "status": "observed" if isinstance(report, dict) and report.get("status") == "observed" else "unknown",
        "complete": False,
        "read_only": True,
        "native_game_calls": False,
        "new_runtime_sample": False,
        "unknown_conditions": ["relation start and expiry dates are not replayed because no direct leaf bytes read them"],
    }


def _write_once(path: Path, payload: dict) -> None:
    if path.exists():
        raise FileExistsError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay relation-current raw report without a game or native call")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.input.stat().st_size > 8 * 1024 * 1024:
            raise OSError("input_too_large")
        with args.input.open("r", encoding="utf-8") as stream:
            report = json.load(stream)
        _write_once(args.output, reference(report))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"relation_reference_error:{exc}", file=sys.stderr)
        return 2
    print(json.dumps({"status": "observed", "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
