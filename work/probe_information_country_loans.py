"""Capture one bounded read-only current-country loan-list observation.

This script is intentionally independent of the production loan reader.  It
reuses only the established identity/date/country/handle seams and performs
its own bounded RPM reads.  It never calls a game function, writes memory, or
starts a game.  The script is normally run only when a new independent raw
sample is explicitly authorized.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bridge.information import domestic_pressure_memory as base


PROFILE_PATH = ROOT / "bridge/information/profiles/country-loans-memory-1374.json"
PROFILE_SHA256 = "8c3ab5ed8c72e859d2af6d1a8f689901de94243ca903c6af0a103ed32af9e481"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
COUNTRY = "FRA"
COUNTRY_OFFSET = 0xDE8
NODE_PAYLOAD_OFFSET = 0x0
NODE_NEXT_OFFSET = 0x10
LENDER_OFFSET = 0x20
RECORD_FIELDS_SIZE = 0x14
MAX_NODES = 64
CHILD_BUDGET_BYTES = 16 * 1024
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_profile() -> dict[str, Any]:
    size = PROFILE_PATH.stat().st_size
    if size <= 0 or size > 64 * 1024:
        raise ValueError("loan_profile_size_out_of_bound")
    raw = PROFILE_PATH.read_bytes()
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError("loan_profile_sha256_mismatch")
    profile = json.loads(raw.decode("utf-8"))
    if not isinstance(profile, dict) or profile.get("profile_id") != "country-loans-memory-1374":
        raise ValueError("loan_profile_shape_invalid")
    return profile


def _profile_guards(profile: Mapping[str, Any]) -> list[tuple[str, int, bytes]]:
    guards = profile.get("code_guards")
    if not isinstance(guards, list) or not guards:
        raise ValueError("loan_profile_code_guards_missing")
    result = []
    for item in guards:
        if not isinstance(item, Mapping):
            raise ValueError("loan_profile_code_guard_invalid")
        name = item.get("name")
        rva = int(str(item.get("rva")), 0)
        raw = bytes.fromhex(str(item.get("hex")))
        if not isinstance(name, str) or not raw or item.get("sha256") != hashlib.sha256(raw).hexdigest():
            raise ValueError("loan_profile_code_guard_invalid")
        result.append((name, rva, raw))
    return result


def _guard(reader: Any, module_base: int, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "module_base": hex(module_base), "checks": {}, "records": [], "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_guards(profile):
            address = module_base + rva
            actual = reader.read_code(address, len(expected), f"country_loans.code.{name}")
            result["records"].append({"name": name, "rva": hex(rva), "address": hex(address), "expected_hex": expected.hex(), "actual_hex": actual.hex()})
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        result["status"] = "observed" if not failed else "mismatch"
        if failed:
            result["unknown_conditions"].append("runtime_code_guard_mismatch:" + ",".join(failed))
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _valid_pointer(value: Any) -> bool:
    return type(value) is int and 0x10000 <= value <= MAX_USER_ADDRESS


class _ChildBudgetReader:
    """Pre-reserving view for the independent loan-list reads.

    The underlying AddressBoundedRPM also enforces the process-wide budget.
    This local view keeps the loan child budget separate and reserves each
    read before invoking the underlying reader; a failed underlying call
    therefore still consumes the reservation.
    """

    def __init__(self, reader: Any, limit: int = CHILD_BUDGET_BYTES):
        self.reader = reader
        self.limit = limit
        self.bytes_reserved = 0
        self.calls = 0
        self.read_log: list[dict[str, Any]] = []

    def _reserve(self, address: int, size: int, label: str) -> None:
        if type(size) is not int or size <= 0 or self.bytes_reserved + size > self.limit:
            raise base.ProbeError(f"loan_child_budget_exceeded:{label}")
        self.bytes_reserved += size
        self.calls += 1

    def read(self, address: int, size: int, label: str) -> bytes:
        self._reserve(address, size, label)
        try:
            raw = self.reader.read(address, size, label)
        except Exception as exc:
            self.read_log.append({"label": label, "address": hex(address), "size": size, "status": "failed", "error": type(exc).__name__})
            raise
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
            self.read_log.append({"label": label, "address": hex(address), "size": size, "status": "failed", "error": "short_read"})
            raise base.ProbeError(f"loan_child_short_read:{label}")
        raw = bytes(raw)
        self.read_log.append({"label": label, "address": hex(address), "size": size, "status": "observed", "raw_hex": raw.hex()})
        return raw

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label)
        return int.from_bytes(raw, "little", signed=False), raw

    def summary(self) -> dict[str, Any]:
        return {
            "bytes_requested": self.bytes_reserved,
            "calls": self.calls,
            "limit": self.limit,
            "pre_reserved": True,
            "read_log": list(self.read_log),
        }


def _file_guard(path: Path, profile: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "path": str(path), "checks": {}, "records": [], "unknown_conditions": []}
    try:
        for name, rva, expected in _profile_guards(profile):
            actual = base._read_pe_rva_bytes(path, rva, len(expected))
            result["records"].append({"name": name, "rva": hex(rva), "expected_hex": expected.hex(), "actual_hex": actual.hex()})
            result["checks"][name] = actual == expected
        failed = [name for name, ok in result["checks"].items() if ok is not True]
        result["status"] = "observed" if not failed else "mismatch"
        if failed:
            result["unknown_conditions"].append("file_code_guard_mismatch:" + ",".join(failed))
    except Exception as exc:
        result["unknown_conditions"].append(f"file_code_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _pass(reader: Any, module_base: int, domestic_profile: Mapping[str, Any], loan_profile: Mapping[str, Any]) -> dict[str, Any]:
    start = len(reader.read_log)
    child_reader = _ChildBudgetReader(reader)
    guard = _guard(child_reader, module_base, loan_profile)
    if guard.get("status") != "observed":
        return {"status": "unknown", "runtime_code_guard": guard, "child_budget": child_reader.summary(), "read_log": reader.read_log[start:], "unknown_reason": "runtime_code_guard_failed"}
    try:
        snapshot = base._snapshot(reader, module_base, COUNTRY, domestic_profile, [])
        if snapshot.get("status") != "observed" or not isinstance(snapshot.get("country_scan"), Mapping):
            raise base.ProbeError("country_snapshot_failed")
        country_pointer = base._va(snapshot["country_scan"].get("country_pointer"))
        if country_pointer is None or not _valid_pointer(country_pointer):
            raise base.ProbeError("country_pointer_invalid")
        container_address = country_pointer + COUNTRY_OFFSET
        head, head_raw = child_reader.qword(container_address, "country_loans.container_head")
        if head and not _valid_pointer(head):
            raise base.ProbeError("loan_container_head_invalid")
        nodes: list[dict[str, Any]] = []
        seen: set[int] = set()
        current = head
        while current:
            if len(nodes) >= MAX_NODES:
                raise base.ProbeError("loan_node_limit_exceeded")
            if current in seen or not _valid_pointer(current):
                raise base.ProbeError("loan_node_cycle_or_pointer_invalid")
            seen.add(current)
            record, record_raw = child_reader.qword(current + NODE_PAYLOAD_OFFSET, "country_loans.node_payload")
            if not _valid_pointer(record) or record in seen:
                raise base.ProbeError("loan_record_pointer_invalid_or_cycle")
            vtable, vtable_raw = child_reader.qword(record, "country_loans.record_vtable")
            if not _valid_pointer(vtable):
                raise base.ProbeError("loan_record_vtable_invalid")
            entry, entry_raw = child_reader.qword(vtable, "country_loans.vtable_entry")
            if not _valid_pointer(entry):
                raise base.ProbeError("loan_vtable_entry_invalid")
            fields_raw = child_reader.read(record + LENDER_OFFSET, RECORD_FIELDS_SIZE, "country_loans.record_fields")
            next_node, next_raw = child_reader.qword(current + NODE_NEXT_OFFSET, "country_loans.node_next")
            if next_node and not _valid_pointer(next_node):
                raise base.ProbeError("loan_node_next_invalid")
            nodes.append(
                {
                    "node_address": hex(current),
                    "record_address": hex(record),
                    "node_payload_raw_hex": record_raw.hex(),
                    "record_vtable_pointer_raw_hex": vtable_raw.hex(),
                    "vtable_entry_raw_hex": entry_raw.hex(),
                    "record_fields_raw_hex": fields_raw.hex(),
                    "lender_fullref_raw_hex": fields_raw[:8].hex(),
                    "interest_raw": int.from_bytes(fields_raw[8:12], "little", signed=True),
                    "interest_raw_hex": fields_raw[8:12].hex(),
                    "principal_raw": int.from_bytes(fields_raw[12:16], "little", signed=True),
                    "principal_raw_hex": fields_raw[12:16].hex(),
                    "due_raw": int.from_bytes(fields_raw[16:20], "little", signed=True),
                    "due_raw_hex": fields_raw[16:20].hex(),
                    "next_address": hex(next_node) if next_node else None,
                    "next_raw_hex": next_raw.hex(),
                }
            )
            current = next_node
        return {
            "status": "observed",
            "game_date": snapshot.get("game_date"),
            "country": snapshot.get("country_scan"),
            "container_address": hex(container_address),
            "container_head": hex(head) if head else None,
            "container_head_raw_hex": head_raw.hex(),
            "nodes": nodes,
            "node_count": len(nodes),
            "runtime_code_guard": guard,
            "child_budget": child_reader.summary(),
            "read_log": reader.read_log[start:],
        }
    except Exception as exc:
        return {"status": "unknown", "runtime_code_guard": guard, "child_budget": child_reader.summary(), "read_log": reader.read_log[start:], "unknown_reason": f"loan_snapshot_failed:{type(exc).__name__}:{exc}"}


def probe(installation: Path) -> dict[str, Any]:
    """Capture two independent raw passes with QUERY_INFORMATION|VM_READ only."""
    installation = Path(installation)
    domestic_profile = base._load_profile()
    loan_profile = _load_profile()
    report = base._base_report(installation, COUNTRY, [])
    report.update(
        {
            "probe": "information-country-loans-runtime",
            "probe_version": 1,
            "profile": {"path": str(PROFILE_PATH), "sha256": PROFILE_SHA256, "profile_id": loan_profile.get("profile_id")},
            "request": {"installation": str(installation), "country": COUNTRY, "field": "loans"},
            "target_build": {"version": "1.37.4", "expected_exe_sha256": EXE_SHA256},
            "loan_inputs": [],
            "native_function_invoked": False,
            "target_memory_writes": False,
            "status": "starting",
        }
    )
    kernel = handle = reader = None
    try:
        report["probe_script_sha256"] = _sha256(Path(__file__).resolve())
        document = base._load_installation(installation)
        kernel = base._configure_kernel()
        handle = kernel.OpenProcess(base.PROCESS_ACCESS, False, int(document["pid"]))
        if not handle:
            raise base.ProbeError("open_process_failed")
        module_base = base._capture_identity(report, document, kernel, handle)
        if report["identity"].get("binding_verified") is not True:
            raise base.ProbeError("identity_not_bound")
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = _file_guard(process_path, loan_profile)
        if report["file_code_guard"].get("status") != "observed":
            raise base.ProbeError("file_code_guard_failed")
        reader = base.AddressBoundedRPM(kernel, handle, module_base)
        for _index in range(2):
            report["loan_inputs"].append(_pass(reader, module_base, domestic_profile, loan_profile))
        report["doublepass"] = {
            "performed": True,
            "consistent": report["loan_inputs"][0] == report["loan_inputs"][1],
            "atomic": False,
            "mismatches": [] if report["loan_inputs"][0] == report["loan_inputs"][1] else ["loan_inputs"],
        }
        report["status"] = "observed" if report["doublepass"]["consistent"] else "doublepass_mismatch"
    except Exception as exc:
        report["status"] = "error"
        report.setdefault("errors", []).append({"stage": "loan_inputs", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"].update(rpm_bytes_requested=reader.bytes_requested, rpm_calls=reader.calls)
        base._apply_cleanup(report, kernel, handle)
    report["completed"] = report.get("status") == "observed" and report.get("cleanup", {}).get("handle_close", {}).get("closed") is True
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    result = probe(args.installation)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"status": result.get("status"), "completed": result.get("completed"), "errors": result.get("errors", [])}, ensure_ascii=False))
    raise SystemExit(0 if result.get("completed") else 1)
