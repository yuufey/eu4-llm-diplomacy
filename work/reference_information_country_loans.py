"""Recompute the closed loan fields from an archived independent raw sample.

The reference path is standard-library only and intentionally does not import
the production loan reader.  It checks the two-pass raw record shape, decodes
signed fields from their preserved bytes, and keeps unresolved lender/date
semantics explicit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_PROFILE_SHA256 = "8c3ab5ed8c72e859d2af6d1a8f689901de94243ca903c6af0a103ed32af9e481"
EXPECTED_COUNTRY = "FRA"
EXPECTED_OFFSET = "0xde8"
MAX_NODES = 64


class ReferenceError(RuntimeError):
    """The archived raw sample does not satisfy the independent contract."""


def _load(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size <= 0 or size > 8 * 1024 * 1024:
        raise ReferenceError(f"input_size_out_of_bound:{size}")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ReferenceError("input_size_changed")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ReferenceError("input_root_not_object")
    return value


def _pin(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": path.resolve().relative_to(ROOT.resolve()).as_posix(), "bytes": path.stat().st_size, "sha256": digest.hexdigest()}


def _i32(raw_hex: str, label: str) -> int:
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ReferenceError(f"{label}_hex_invalid") from exc
    if len(raw) != 4:
        raise ReferenceError(f"{label}_width:{len(raw)}")
    return struct.unpack("<i", raw)[0]


def _u64(raw_hex: str, label: str) -> int:
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ReferenceError(f"{label}_hex_invalid") from exc
    if len(raw) != 8:
        raise ReferenceError(f"{label}_width:{len(raw)}")
    return int.from_bytes(raw, "little", signed=False)


def _normalize_node(node: dict[str, Any]) -> dict[str, Any]:
    fields_hex = node.get("record_fields_raw_hex")
    try:
        fields = bytes.fromhex(str(fields_hex))
    except ValueError as exc:
        raise ReferenceError("record_fields_hex_invalid") from exc
    if len(fields) != 0x14:
        raise ReferenceError(f"record_fields_width:{len(fields)}")
    lender_raw = fields[:8]
    interest_raw = _i32(fields[8:12].hex(), "interest")
    principal_raw = _i32(fields[12:16].hex(), "principal")
    due_raw = _i32(fields[16:20].hex(), "due")
    if node.get("lender_fullref_raw_hex") != lender_raw.hex() or node.get("interest_raw_hex") != fields[8:12].hex() or node.get("principal_raw_hex") != fields[12:16].hex() or node.get("due_raw_hex") != fields[16:20].hex():
        raise ReferenceError("node_raw_projection_mismatch")
    try:
        node_address = int(str(node.get("node_address")), 0)
        record_address = int(str(node.get("record_address")), 0)
        payload_address = _u64(str(node.get("node_payload_raw_hex")), "node_payload")
        vtable_address = _u64(str(node.get("record_vtable_pointer_raw_hex")), "vtable")
        entry_address = _u64(str(node.get("vtable_entry_raw_hex")), "entry")
        next_address_raw = _u64(str(node.get("next_raw_hex")), "next")
        next_address = node.get("next_address")
        next_value = int(str(next_address), 0) if next_address is not None else 0
    except (TypeError, ValueError) as exc:
        raise ReferenceError("node_pointer_shape_invalid") from exc
    if record_address != payload_address:
        raise ReferenceError("record_address_payload_mismatch")
    if next_value != next_address_raw:
        raise ReferenceError("next_address_raw_mismatch")
    if next_address_raw == 0 and next_address is not None:
        raise ReferenceError("null_next_address_not_none")
    if next_address_raw != 0 and next_address is None:
        raise ReferenceError("non_null_next_address_missing")
    return {
        "node_address": hex(node_address),
        "record_address": hex(record_address),
        "record_vtable_pointer": hex(vtable_address),
        "vtable_entry": hex(entry_address),
        "next_address": hex(next_address_raw) if next_address_raw else None,
        "principal": {"raw": principal_raw, "raw_hex": fields[12:16].hex(), "value": principal_raw, "unit": "ducats", "scale": 1},
        "interest": {"raw": interest_raw, "raw_hex": fields[8:12].hex(), "value": interest_raw / 1000.0, "unit": "percent", "scale": 1000},
        "due": {"raw": due_raw, "raw_hex": fields[16:20].hex(), "value": due_raw, "unit": "engine_date_raw", "scale": 1, "semantics": "raw_only_epoch_unresolved"},
        "lender": {"status": "unknown", "raw_fullref": int.from_bytes(lender_raw, "little"), "raw_fullref_hex": lender_raw.hex(), "mapping": None},
        "raw": {"record_fields_raw_hex": fields.hex(), "next_raw_hex": node.get("next_raw_hex"), "node_payload_raw_hex": node.get("node_payload_raw_hex")},
    }


def reference(input_path: Path) -> dict[str, Any]:
    report = _load(input_path)
    if report.get("target_build", {}).get("expected_exe_sha256") != EXPECTED_EXE_SHA256:
        raise ReferenceError("executable_sha256_mismatch")
    if report.get("country") != EXPECTED_COUNTRY or report.get("profile", {}).get("sha256") != EXPECTED_PROFILE_SHA256:
        raise ReferenceError("identity_or_profile_mismatch")
    inputs = report.get("loan_inputs")
    if not isinstance(inputs, list) or len(inputs) != 2 or any(item.get("status") != "observed" for item in inputs if isinstance(item, dict)):
        raise ReferenceError("two_pass_input_shape_invalid")
    normalized: list[dict[str, Any]] = []
    for item in inputs:
        nodes = item.get("nodes")
        if not isinstance(nodes, list) or len(nodes) > MAX_NODES:
            raise ReferenceError("node_list_bound_invalid")
        normalized.append(
            {
                "game_date": item.get("game_date"),
                "country_pointer": item.get("country", {}).get("country_pointer") if isinstance(item.get("country"), dict) else None,
                "container_address": item.get("container_address"),
                "container_head_raw_hex": item.get("container_head_raw_hex"),
                "nodes": [_normalize_node(node) for node in nodes],
            }
        )
    if normalized[0] != normalized[1]:
        raise ReferenceError("two_pass_raw_mismatch")
    current = normalized[0]
    return {
        "schema": "information_country_loans_independent_reference.v1",
        "status": "observed",
        "completed": True,
        "country": EXPECTED_COUNTRY,
        "target_build": {"version": "1.37.4", "exe_sha256": EXPECTED_EXE_SHA256},
        "profile_sha256": EXPECTED_PROFILE_SHA256,
        "fields": {
            "loans": {
                "status": "known",
                "complete": False,
                "partial": True,
                "value": current["nodes"],
                "unit": "loan_records",
                "scale": 1,
                "period": "current",
                "basis": "native_country_loan_records",
                "value_origin": "copied_native_country_loan_records",
            }
        },
        "two_pass_raw_equal": True,
        "native_function_invoked": False,
        "target_memory_writes": False,
        "unknown_conditions": [
            "lender bank/foreign mapping is not inferred from fullref",
            "due date epoch is not inferred from raw scalar",
            "nested serializer and amount-with-interest helper are not replayed",
        ],
        "source": _pin(input_path),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    document = reference(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": document["status"], "fields": list(document["fields"]), "source": document["source"]}, ensure_ascii=False))
