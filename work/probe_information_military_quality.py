"""Capture independent raw military-quality inputs through bounded RPM.

The mature domestic-pressure probe supplies the QUERY|VM_READ process binding,
country identity, runtime guards, two-pass comparison, and handle cleanup.  This
module only adds its own bounded readers for the statically closed ``mil_tech``
definition chain, the selected country technology level, and the raw signed
country ``+0xe40`` army-tradition DWORD.  It does not import a military-quality
production reader or adapter and never invokes a game function.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.probe_information_current_overextension import probe as _mature_probe


EXPECTED_INSTALLATION = (
    ROOT
    / "work/runtime/diplomacy-observer-20261026-information-battle-v27-002/installation.json"
).resolve()
EXPECTED_COUNTRY = "FRA"
EXPECTED_PID = 31460
EXPECTED_CREATION_FILETIME = 134374886912306555
EXPECTED_SESSION_ID = "31460-1dd653f69242d7b"
EXPECTED_DATE = 56557728
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"

PARENT_RPM_TOTAL = 512 * 1024
CHILD_RESERVED_BYTES = 64 * 1024
MAX_SINGLE_READ = 65_536
MAX_USER_ADDRESS = 0x7FFFFFFFFFFF
MAX_TECH_DEFINITIONS = 65_536
MAX_CHAIN_LENGTH = 64
MAX_TECH_LEVELS = 256
TECHNOLOGY_KEY = "mil_tech"

TECHNOLOGY_LAYOUT = {
    "manager_global_rva": "0x242be30",
    "manager_bucket_count_offset": "0x34",
    "manager_bucket_array_offset": "0x38",
    "link_item_offset": "0x0",
    "link_next_offset": "0x8",
    "definition_name_offset": "0x10",
    "definition_name_length_offset": "0x20",
    "definition_name_capacity_offset": "0x28",
    "definition_index_offset": "0x50",
    "country_technology_pointer_offset": "0x2440",
    "technology_vector_begin_offset": "0x128",
    "technology_vector_end_offset": "0x130",
}

STATIC_SOURCE_PINS = (
    {
        "name": "military_technology_source_002",
        "path": "work/runtime/information-military-quality-20261027-001/military-technology-source-002.json",
        "sha256": "fb642e67080996395f5b8e9568fb2de0465e203a28626c22d895147a26e4f5a4",
    },
    {
        "name": "military_technology_code_003",
        "path": "work/runtime/information-military-quality-20261027-001/military-technology-code-003.json",
        "sha256": "286b74fdb83da462ace8694bb27449c3e11366e7d401f7cf0e3356f15f625cc5",
    },
    {
        "name": "military_technology_code_004",
        "path": "work/runtime/information-military-quality-20261027-001/military-technology-code-004.json",
        "sha256": "a1b3cf3b22b73cc6b0e9fe4b379ff4481c919a9a6e8b564205d11640cbf8c49f",
    },
    {
        "name": "military_technology_code_005",
        "path": "work/runtime/information-military-quality-20261027-001/military-technology-code-005.json",
        "sha256": "742a0b6db8c7654ef69c836f94772d1cace88714bba7e6fdda66f55d09e2f9b9",
    },
    {
        "name": "army_tradition_source_004",
        "path": "work/runtime/information-military-quality-20261027-001/tradition-source-004.json",
        "sha256": "df63aa6650d1d39e94f165ebd3b9f938cad1784eb0971a4360e30ab97446e1d1",
    },
    {
        "name": "army_tradition_source_003",
        "path": "work/runtime/information-military-quality-20261027-001/tradition-source-003.json",
        "sha256": "64721bc7c80c8adfd9a4db99cc5a1aeeeec6c8a34e09ccee1dbdf67ade69b611",
    },
)


class CaptureContractError(RuntimeError):
    """The independent probe contract or a bounded read was not satisfied."""


def _sha256_file(path: Path, *, max_bytes: int = 16 * 1024 * 1024) -> str:
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise CaptureContractError(f"file_size_out_of_bound:{path}:{size}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if path.stat().st_size != size:
        raise CaptureContractError(f"file_changed_during_hash:{path}")
    return digest.hexdigest()


def _verify_static_source_pins() -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    for item in STATIC_SOURCE_PINS:
        path = (ROOT / item["path"]).resolve()
        actual = _sha256_file(path)
        if actual.lower() != item["sha256"]:
            raise CaptureContractError(f"static_source_sha256_mismatch:{item['name']}")
        verified.append({**item, "path": str(path), "verified_sha256": actual, "status": "observed"})
    return verified


def _installation_preflight(installation: Path) -> dict[str, Any]:
    resolved = installation.resolve()
    if resolved != EXPECTED_INSTALLATION:
        raise CaptureContractError("refusing_non_v27_002_installation")
    size = resolved.stat().st_size
    if size <= 0 or size > 1024 * 1024:
        raise CaptureContractError(f"installation_size_out_of_bound:{size}")
    with resolved.open("rb") as stream:
        raw = stream.read(size + 1)
    if len(raw) != size:
        raise CaptureContractError("installation_size_changed")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CaptureContractError(f"installation_json_invalid:{exc}") from exc
    expected = {
        "pid": EXPECTED_PID,
        "creation_filetime": EXPECTED_CREATION_FILETIME,
        "session_id": EXPECTED_SESSION_ID,
        "game_sha256": EXPECTED_EXE_SHA256,
    }
    observed = {key: document.get(key) for key in expected}
    checks = {key: observed[key] == value for key, value in expected.items()}
    if not all(checks.values()):
        raise CaptureContractError("installation_preflight_identity_mismatch")
    return {
        "status": "observed",
        "path": str(resolved),
        "checks": checks,
        "expected": expected,
        "observed": observed,
        "read_only": True,
    }


def _valid_pointer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0x10000 <= value < MAX_USER_ADDRESS


def _checked_address(base: int, offset: int, label: str) -> int:
    if not _valid_pointer(base) or not isinstance(offset, int) or offset < 0:
        raise CaptureContractError(f"invalid_address_arithmetic:{label}")
    value = base + offset
    if value < 0x10000 or value >= MAX_USER_ADDRESS:
        raise CaptureContractError(f"address_range_overflow:{label}")
    return value


def _address(value: int, module_base: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"va": hex(value)}
    if isinstance(module_base, int) and module_base <= value < module_base + 0x4000000:
        result["rva"] = hex(value - module_base)
    return result


class _ChildBudget:
    """Precharge the child extension before its first RPM request."""

    def __init__(self, reader: Any):
        parent_before = int(getattr(reader, "bytes_requested", 0))
        if parent_before + CHILD_RESERVED_BYTES > PARENT_RPM_TOTAL:
            raise CaptureContractError("military_quality_child_budget_unavailable")
        self.reader = reader
        self.parent_bytes_before = parent_before
        self.reserved_bytes = CHILD_RESERVED_BYTES
        self.attempted_bytes = 0
        self.calls = 0

    def read(self, address: int, size: int, label: str) -> bytes:
        if not _valid_pointer(address):
            raise CaptureContractError(f"invalid_child_address:{label}")
        if not isinstance(size, int) or size <= 0 or size > MAX_SINGLE_READ:
            raise CaptureContractError(f"invalid_child_read_size:{label}")
        if self.attempted_bytes + size > self.reserved_bytes:
            raise CaptureContractError("military_quality_child_budget_exceeded")
        # Count before delegating so a failed read consumes the attempted
        # extension budget instead of allowing a retry to bypass the bound.
        self.attempted_bytes += size
        self.calls += 1
        return self.reader.read(address, size, "reference.military_quality." + label)

    def report(self) -> dict[str, Any]:
        return {
            "status": "precharged",
            "reserved_bytes": self.reserved_bytes,
            # The cumulative parent counter is checked by the budget guard,
            # but must not enter the per-pass native-state comparison.
            "parent_total_limit": PARENT_RPM_TOTAL,
            "attempted_bytes": self.attempted_bytes,
            "calls": self.calls,
            "remaining_reserved_bytes": self.reserved_bytes - self.attempted_bytes,
        }


def _read_pointer(budget: _ChildBudget, address: int, label: str, module_base: int) -> tuple[int, dict[str, Any]]:
    raw = budget.read(address, 8, label)
    value = int.from_bytes(raw, "little", signed=False)
    record = {"address": _address(address, module_base), "raw_hex": raw.hex(), "value": _address(value, module_base) if value else None}
    if not _valid_pointer(value):
        raise CaptureContractError(f"pointer_invalid:{label}")
    return value, record


def _read_u32(budget: _ChildBudget, address: int, label: str, module_base: int) -> tuple[int, dict[str, Any]]:
    raw = budget.read(address, 4, label)
    value = int.from_bytes(raw, "little", signed=False)
    return value, {"address": _address(address, module_base), "raw_hex": raw.hex(), "value": value}


def _hash_key(key: str) -> tuple[int, list[int]]:
    value = 0
    steps: list[int] = []
    for byte in key.encode("ascii"):
        signed_byte = byte if byte < 0x80 else byte - 0x100
        value = ((value + signed_byte) * 61) & 0xFFFFFFFF
        steps.append(value)
    return value, steps


def _read_definition_candidate(
    budget: _ChildBudget,
    item_pointer: int,
    link_pointer: int,
    chain_index: int,
    module_base: int,
) -> dict[str, Any]:
    # The selected definition's String32 begins at definition+0x10 and the
    # signed index is at definition+0x50.  Reading through +0x53 captures both
    # in one bounded raw block without touching the unproved +0x138 field.
    definition_raw = budget.read(item_pointer + 0x10, 0x44, f"technology.definition_{chain_index}")
    header = definition_raw[:32]
    length = int.from_bytes(header[16:24], "little", signed=False)
    capacity = int.from_bytes(header[24:32], "little", signed=False)
    index_raw = definition_raw[0x40:0x44]
    candidate: dict[str, Any] = {
        "chain_index": chain_index,
        "link_address": _address(link_pointer, module_base),
        "item_pointer": _address(item_pointer, module_base),
        "definition_address": _address(item_pointer + 0x10, module_base),
        "definition_raw_hex": definition_raw.hex(),
        "name_header_hex": header.hex(),
        "name_length": length,
        "name_capacity": capacity,
        "index_address": _address(item_pointer + 0x50, module_base),
        "index_raw_hex": index_raw.hex(),
        "index": int.from_bytes(index_raw, "little", signed=True),
        "name": None,
        "name_payload_address": None,
        "name_payload_raw_hex": None,
        "exact_key": False,
    }
    if length != len(TECHNOLOGY_KEY):
        candidate["name_status"] = "length_mismatch"
        return candidate
    if capacity < 16:
        payload_address = item_pointer + 0x10
        payload = header[: length + 1]
    else:
        pointer = int.from_bytes(header[:8], "little", signed=False)
        if not _valid_pointer(pointer):
            raise CaptureContractError(f"technology_name_pointer_invalid:{chain_index}")
        payload_address = pointer
        payload = budget.read(pointer, length + 1, f"technology.name_{chain_index}")
    candidate["name_payload_address"] = _address(payload_address, module_base)
    candidate["name_payload_raw_hex"] = payload.hex()
    if len(payload) != length + 1 or payload[-1:] != b"\0":
        raise CaptureContractError(f"technology_name_not_nul_terminated:{chain_index}")
    try:
        name = payload[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise CaptureContractError(f"technology_name_not_ascii:{chain_index}") from exc
    candidate["name"] = name
    candidate["name_status"] = "observed"
    candidate["exact_key"] = name == TECHNOLOGY_KEY
    return candidate


def _capture_technology(budget: _ChildBudget, module_base: int, country_pointer: int) -> dict[str, Any]:
    manager_address = _checked_address(module_base, 0x242BE30, "technology.manager_global")
    manager, manager_record = _read_pointer(budget, manager_address, "technology.manager_global", module_base)
    count, count_record = _read_u32(budget, manager + 0x34, "technology.bucket_count", module_base)
    if not 1 <= count <= MAX_TECH_DEFINITIONS:
        raise CaptureContractError(f"technology_bucket_count_out_of_bound:{count}")
    bucket_array, bucket_record = _read_pointer(budget, manager + 0x38, "technology.bucket_array", module_base)
    hash_value, hash_steps = _hash_key(TECHNOLOGY_KEY)
    bucket_index = hash_value % count
    bucket_address = _checked_address(bucket_array, bucket_index * 8, "technology.selected_bucket")
    link, link_record = _read_pointer(budget, bucket_address, "technology.selected_bucket", module_base)
    candidates: list[dict[str, Any]] = []
    seen_links: set[int] = set()
    selected: dict[str, Any] | None = None
    while link:
        if len(candidates) >= MAX_CHAIN_LENGTH:
            raise CaptureContractError("technology_bucket_chain_over_bound")
        if link in seen_links:
            raise CaptureContractError("technology_bucket_chain_cycle")
        seen_links.add(link)
        link_raw = budget.read(link, 16, f"technology.link_{len(candidates)}")
        item = int.from_bytes(link_raw[:8], "little", signed=False)
        next_link = int.from_bytes(link_raw[8:16], "little", signed=False)
        if not _valid_pointer(item):
            raise CaptureContractError(f"technology_link_item_invalid:{len(candidates)}")
        candidate = _read_definition_candidate(budget, item, link, len(candidates), module_base)
        candidate["link_raw_hex"] = link_raw.hex()
        candidate["next_pointer"] = _address(next_link, module_base) if next_link else None
        candidates.append(candidate)
        if candidate["exact_key"]:
            selected = candidate
            break
        if next_link and not _valid_pointer(next_link):
            raise CaptureContractError(f"technology_link_next_invalid:{len(candidates) - 1}")
        link = next_link
    if selected is None:
        raise CaptureContractError("technology_mil_tech_definition_not_found")
    selected_index = int(selected["index"])
    technology_pointer_address = _checked_address(country_pointer, 0x2440, "country.technology_pointer")
    technology_pointer, technology_pointer_record = _read_pointer(budget, technology_pointer_address, "country.technology_pointer", module_base)
    vector_address = _checked_address(technology_pointer, 0x128, "technology.level_vector")
    vector_raw = budget.read(vector_address, 16, "technology.level_vector")
    begin = int.from_bytes(vector_raw[:8], "little", signed=False)
    end = int.from_bytes(vector_raw[8:16], "little", signed=False)
    if not _valid_pointer(begin) or not _valid_pointer(end) or end < begin or (end - begin) % 4:
        raise CaptureContractError("technology_level_vector_invalid")
    level_count = (end - begin) // 4
    if not 0 < level_count <= MAX_TECH_LEVELS:
        raise CaptureContractError(f"technology_level_count_out_of_bound:{level_count}")
    if not 0 <= selected_index < level_count:
        raise CaptureContractError(f"technology_index_out_of_bounds:{selected_index}:{level_count}")
    level_address = _checked_address(begin, selected_index * 4, "technology.selected_level")
    level_raw = budget.read(level_address, 4, "technology.selected_level")
    level = int.from_bytes(level_raw, "little", signed=True)
    return {
        "status": "observed",
        "key": TECHNOLOGY_KEY,
        "hash": {"algorithm": "h=((h+signedASCIIbyte)*61) mod 2^32", "unsigned_hash": hash_value, "steps": hash_steps, "bucket_count": count, "bucket_index": bucket_index},
        "manager": {"address": _address(manager, module_base), "global": manager_record, "bucket_count": count_record, "bucket_array": bucket_record},
        "selected_bucket": {"address": _address(bucket_address, module_base), "raw_pointer": link_record},
        "chain": {"length_observed": len(candidates), "max_length": MAX_CHAIN_LENGTH, "candidates": candidates},
        "selected_definition": selected,
        "country_technology_pointer": technology_pointer_record,
        "level_vector": {"address": _address(vector_address, module_base), "raw_hex": vector_raw.hex(), "begin": _address(begin, module_base), "end": _address(end, module_base), "count": level_count, "max_count": MAX_TECH_LEVELS},
        "selected_level": {"address": _address(level_address, module_base), "raw_hex": level_raw.hex(), "raw": level, "signed": True, "width": 4, "unit": "technology_level", "scale": 1, "value_origin": "copied_native_country_technology_cache"},
        "unproved_fields_not_read": ["technology+0x138"],
    }


def _capture_army_tradition(budget: _ChildBudget, country_pointer: int, module_base: int) -> dict[str, Any]:
    address = _checked_address(country_pointer, 0xE40, "country.army_tradition")
    raw = budget.read(address, 4, "country.army_tradition_raw")
    value = int.from_bytes(raw, "little", signed=True)
    return {
        "status": "observed",
        "address": _address(address, module_base),
        "raw": value,
        "raw_hex": raw.hex(),
        "width": 4,
        "signed": True,
        "unit": "unknown",
        "scale": None,
        "value_origin": "copied_country_cache_raw",
        "semantics": "raw country+0xe40 DWORD only; source-004 unit/multiplier publication remains pending",
    }


def read_inputs(reader: Any, module_base: int, country_pointer: int) -> dict[str, Any]:
    """Read only the independent military-quality raw inputs for one pass."""
    if not isinstance(module_base, int) or not _valid_pointer(module_base):
        raise CaptureContractError("military_quality_module_base_invalid")
    if not isinstance(country_pointer, int) or not _valid_pointer(country_pointer):
        raise CaptureContractError("military_quality_country_pointer_invalid")
    budget = _ChildBudget(reader)
    child_log_start = len(getattr(reader, "read_log", []))
    technology = _capture_technology(budget, module_base, country_pointer)
    tradition = _capture_army_tradition(budget, country_pointer, module_base)
    child_log = copy.deepcopy(getattr(reader, "read_log", [])[child_log_start:])
    return {
        "status": "observed",
        "expected_game_date": EXPECTED_DATE,
        "module_base": _address(module_base),
        "country_pointer": _address(country_pointer),
        "technology": technology,
        "military_technology": technology["selected_level"],
        "army_tradition": tradition,
        "army_tradition_raw": tradition["raw"],
        "army_tradition_raw_hex": tradition["raw_hex"],
        "profile_and_source_pins": {
            "source_reports": [dict(item) for item in STATIC_SOURCE_PINS],
            "technology_layout": dict(TECHNOLOGY_LAYOUT),
        },
        "child_budget": budget.report(),
        "child_read_log": child_log,
        "raw_only": True,
        "native_function_invoked": False,
        "game_function_or_write": False,
    }


def probe(installation: Path) -> dict[str, Any]:
    installation = installation.resolve()
    preflight = _installation_preflight(installation)
    verified_sources = _verify_static_source_pins()
    report = _mature_probe(installation, field="military_quality", input_reader=read_inputs)
    inputs = report.get("military_quality_inputs", [])
    if (len(inputs) != 2 or any(
            not isinstance(item.get("date"), dict)
            or item["date"].get("value") != EXPECTED_DATE
            or int.from_bytes(bytes.fromhex(item["date"].get("raw_hex", "")), "little", signed=True) != EXPECTED_DATE
            for item in inputs)):
        report.update(status="error", completed=False)
        report["errors"].append({"stage": "military_quality_date", "error": "observed_date_does_not_match_expected"})
    script_path = Path(__file__).resolve()
    report.update(
        {
            "schema": "information_independent_military_quality_inputs.v1",
            "field": "military_quality",
            "probe": "information-independent-military-quality-runtime",
            "probe_script": str(script_path),
            "probe_script_sha256": _sha256_file(script_path),
            "installation_preflight": preflight,
            "verified_source_report_pins": verified_sources,
            "expected_identity": {
                "pid": EXPECTED_PID,
                "creation_filetime": EXPECTED_CREATION_FILETIME,
                "session_id": EXPECTED_SESSION_ID,
                "game_date": EXPECTED_DATE,
                "exe_sha256": EXPECTED_EXE_SHA256,
            },
            "capture_contract": {
                "read_only": True,
                "open_process_mask": "QUERY_INFORMATION|VM_READ",
                "native_function_invoked": False,
                "game_function_or_write": False,
                "save_restart_date_ui": False,
                "raw_input_only": True,
                "child_reserved_bytes_per_pass": CHILD_RESERVED_BYTES,
                "technology_definition_chain_limit": MAX_CHAIN_LENGTH,
                "technology_bucket_count_limit": MAX_TECH_DEFINITIONS,
                "technology_level_count_limit": MAX_TECH_LEVELS,
                "unproved_technology_offset_not_read": "0x138",
                "army_tradition_unit": "unknown",
            },
            "profile_pins": {
                "runtime_parent_profile": report.get("profile"),
                "static_source_reports": verified_sources,
            },
            "read_log_semantics": "Each child_read_log entry retains the bounded RPM label, address, size, status, and raw_hex returned by ReadProcessMemory.",
        }
    )
    return report


def main() -> int:
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
    summary = {
        "status": result.get("status"),
        "completed": result.get("completed"),
        "doublepass": result.get("doublepass"),
        "closed": result.get("cleanup", {}).get("handle_close", {}).get("status") == "closed",
        "errors": result.get("errors"),
        "output": str(args.output),
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if result.get("completed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
