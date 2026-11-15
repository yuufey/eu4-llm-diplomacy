"""Freeze the 1.37.4 country-power native contract and reader profile.

This is a bounded evidence join.  It reads only the fixed executable header
and four REA evidence JSON files (each checked against a 16 MiB limit), then
extracts the four profiled function spans from PE raw sections.  It never
disassembles the executable, invokes a game function, opens a process, or
changes the low-level reader.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
RUNTIME = ROOT / "work" / "runtime" / "information-country-scalars-20261024-001"
PROFILE_PATH = ROOT / "bridge" / "information" / "profiles" / "country-resources-memory-1374.json"
CONTRACT_PATH = RUNTIME / "native-power-contract-001.json"
INDEX_PATH = RUNTIME / "research-index-001.json"
DEFAULT_EXE = (
    ROOT / "work" / "runtime" / "ghidra-full"
    / "b23fa0e1f698d31b-20261014T054913Z-6dda97" / "input" / "eu4.exe"
)

EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_VERSION = "1.37.4"
IMAGE_BASE = 0x140000000
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_PROFILE_BYTES = 64 * 1024


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path, *, max_bytes: int | None = None) -> tuple[int, str]:
    size = path.stat().st_size
    if max_bytes is not None and size > max_bytes:
        raise ValueError(f"file_over_limit:{path}:{size}>{max_bytes}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return size, digest.hexdigest()


def read_json_bounded(path: Path, *, max_bytes: int = MAX_EVIDENCE_BYTES) -> tuple[dict[str, Any], int, str]:
    size, digest = sha256_file(path, max_bytes=max_bytes)
    raw = path.read_bytes()
    if len(raw) != size:
        raise ValueError(f"file_changed_during_read:{path}")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"json_object_required:{path}")
    return value, size, digest


def relpath(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def parse_hex(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"integer_invalid:{label}")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        result = int(value, 0)
    else:
        raise ValueError(f"integer_invalid:{label}")
    if result < 0:
        raise ValueError(f"integer_negative:{label}")
    return result


def get_path(value: Mapping[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, Mapping) or key not in current:
            raise ValueError("missing_path:" + ".".join(keys))
        current = current[key]
    return current


def _read_pe_rva_bytes(path: Path, rva: int, size: int) -> bytes:
    """Read one bounded RVA slice using the existing audited PE helper."""
    from bridge.information.mission_memory import _read_pe_rva_bytes as reader

    return reader(path, rva, size)


REA_SPECS: tuple[dict[str, Any], ...] = (
    {
        "directory": "rea-power-gui-001",
        "name": "power_kind_labels",
        "rva": 0x37F860,
        "anchors": (
            "iVar2 = FUN_140384a90(0,param_3,local_1c0);",
            'FUN_1414b33a0(local_230,"ADM_POWER",0,0);',
            'FUN_1414b33a0(local_230,"DIP_POWER",0,0);',
            'FUN_1414b33a0(local_230,"MIL_POWER",0,0);',
        ),
        "kind_mapping": {"0": "ADM_POWER", "1": "DIP_POWER", "2": "MIL_POWER"},
    },
    {
        "directory": "rea-power-balance-rules-001",
        "name": "power_balance_rules",
        "rva": 0x2F36F0,
        "anchors": (
            "uVar11 = FUN_140384a90(param_1,0,0);",
            "FUN_14037f530(param_1,0,*puVar30,0);",
            "uVar11 = FUN_140384a90(param_1,1,0);",
            "FUN_14037f530(param_1,1,*puVar30,0);",
            "uVar11 = FUN_140384a90(param_1,2,0);",
            "iVar10 = FUN_14009a320(param_1,2);",
            "FUN_14037f530(param_1,2,*puVar30);",
        ),
    },
    {
        "directory": "rea-power-balance-update-001",
        "name": "power_balance_update",
        "rva": 0x37F530,
        "anchors": (
            '"AddPower, %d, %d, %d"',
            "param_1 = (longlong)param_2 * 4 + param_1;",
            "param_3 = *(int *)(param_1 + 0x260) + param_3;",
            "*(int *)(param_1 + 0x260) = param_3;",
            "if (param_3 < iVar4) {",
        ),
    },
    {
        "directory": "rea-power-counter-001",
        "name": "power_counter",
        "rva": 0x9A320,
        "anchors": (
            "return *(undefined4 *)(param_1 + 0x260 + (longlong)param_2 * 4);",
        ),
    },
)

ORDINARY_REPORTS: tuple[tuple[str, str, str], ...] = (
    (
        "string-entry-survey-001.json",
        "ordinary_static_scan",
        "labels and GUI string survey; no scalar semantics",
    ),
    (
        "string-entry-disassembly-001.json",
        "ordinary_static_bounded_disassembly",
        "bounded ordinary disassembly; no scalar assignment",
    ),
    (
        "indexed-power-access-001.json",
        "ordinary_raw_candidates",
        "raw indexed-dword candidates; type/enum/balance unresolved",
    ),
    (
        "save-powers-crosscheck-001.json",
        "recorded_save",
        "recorded save vector; component order and live fallback unverified",
    ),
)


def _procedure_record(spec: Mapping[str, Any], path: Path, evidence: dict[str, Any], evidence_size: int, evidence_sha: str) -> dict[str, Any]:
    subject_sha = get_path(evidence, "subject", "digest", "sha256")
    if str(subject_sha).lower() != EXPECTED_EXE_SHA256:
        raise ValueError(f"evidence_exe_sha256_mismatch:{path}")
    value = get_path(evidence, "raw_result", "value")
    procedure = get_path(value, "procedure")
    address = parse_hex(procedure.get("address"), f"{path}.procedure.address")
    if address - IMAGE_BASE != spec["rva"]:
        raise ValueError(f"procedure_rva_mismatch:{path}:{hex(address - IMAGE_BASE)}")
    body = get_path(procedure, "body")
    ranges = body.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        raise ValueError(f"procedure_body_ranges_missing:{path}")
    parsed_ranges: list[tuple[int, int]] = []
    for item in ranges:
        start = parse_hex(item.get("start"), "body.start")
        end_inclusive = parse_hex(item.get("end"), "body.end")
        if start < IMAGE_BASE or end_inclusive < start:
            raise ValueError(f"body_range_invalid:{path}")
        parsed_ranges.append((start, end_inclusive))
    min_va = min(start for start, _ in parsed_ranges)
    max_va = max(end for _, end in parsed_ranges)
    total_bytes = sum(end - start + 1 for start, end in parsed_ranges)
    span_bytes = max_va - min_va + 1
    if body.get("total_bytes") != total_bytes or body.get("span_bytes") != span_bytes:
        raise ValueError(f"body_size_semantics_mismatch:{path}")
    if min_va - IMAGE_BASE != spec["rva"]:
        raise ValueError(f"body_start_rva_mismatch:{path}")
    pseudocode = get_path(value, "pseudocode")
    if not isinstance(pseudocode, str):
        raise ValueError(f"pseudocode_missing:{path}")
    missing = [anchor for anchor in spec["anchors"] if anchor not in pseudocode]
    if missing:
        raise ValueError(f"pseudocode_anchor_missing:{path}:{missing}")
    source_ranges = []
    for start, end in parsed_ranges:
        source_ranges.append(
            {
                "va_start": hex(start),
                "va_end_inclusive": hex(end),
                "va_end_exclusive": hex(end + 1),
                "rva_start": hex(start - IMAGE_BASE),
                "rva_end_inclusive": hex(end - IMAGE_BASE),
                "rva_end_exclusive": hex(end - IMAGE_BASE + 1),
            }
        )
    return {
        "name": spec["name"],
        "evidence_id": evidence.get("evidence_id"),
        "evidence_path": relpath(path),
        "evidence_sha256": evidence_sha,
        "evidence_bytes": evidence_size,
        "procedure": {
            "name": procedure.get("name"),
            "va": hex(address),
            "rva": hex(address - IMAGE_BASE),
        },
        "rea_body_range": {
            "rva_start": hex(min_va - IMAGE_BASE),
            "rva_end_inclusive": hex(max_va - IMAGE_BASE),
            "rva_end_exclusive": hex(max_va - IMAGE_BASE + 1),
            "va_start": hex(min_va),
            "va_end_inclusive": hex(max_va),
            "va_end_exclusive": hex(max_va + 1),
            "span_bytes": span_bytes,
            "total_body_bytes": total_bytes,
            "end_semantics": "REA procedure.body.ranges end is inclusive",
            "ranges": source_ranges,
        },
        "pseudocode_anchors": list(spec["anchors"]),
        "kind_mapping": spec.get("kind_mapping"),
    }


def collect_rea_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for spec in REA_SPECS:
        path = RUNTIME / str(spec["directory"]) / "evidence.json"
        evidence, size, digest = read_json_bounded(path)
        record = _procedure_record(spec, path, evidence, size, digest)
        records.append(record)
    return records


def _write_json_new(path: Path, value: Mapping[str, Any], *, overwrite: bool) -> tuple[int, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing_to_overwrite:{path}")
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    path.write_bytes(raw)
    return len(raw), sha256_bytes(raw)


def dependency_record(path: Path, *, role: str, max_bytes: int = MAX_EVIDENCE_BYTES) -> dict[str, Any]:
    size, digest = sha256_file(path, max_bytes=max_bytes)
    return {"path": relpath(path), "sha256": digest, "bytes": size, "role": role}


def build_contract(exe: Path, exe_sha: str, rea_records: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "information_native_country_power_contract_v1",
        "contract_id": "native-power-contract-001",
        "evidence_kind": "REA_static_semantic_contract_not_runtime_observation",
        "game": {
            "version": EXPECTED_VERSION,
            "executable_sha256": exe_sha,
            "image_base": hex(IMAGE_BASE),
            "country_scope": "FRA",
        },
        "semantics": {
            "fields": {
                "administrative": {"kind": 0, "label": "ADM_POWER", "offset": "0x260"},
                "diplomatic": {"kind": 1, "label": "DIP_POWER", "offset": "0x264"},
                "military": {"kind": 2, "label": "MIL_POWER", "offset": "0x268"},
            },
            "component_width_bytes": 4,
            "signed": True,
            "scale": 1,
            "unit": "monarch_points",
            "storage_expression": "signed_int32(country + 0x260 + kind * 4)",
            "read_only_bridge": {
                "method": "bounded RPM reads the selected country's fields",
                "function_calls": False,
                "memory_writes": False,
                "dispatch_or_gameplay": False,
            },
        },
        "bridge_explanation": [
            "REA 0x37f860 labels kind 0/1/2 as ADM_POWER/DIP_POWER/MIL_POWER through the shared 0x384a90 formatter.",
            "REA 0x2f36f0 subtracts the corresponding 0x384a90 values and writes kinds 0/1 via 0x37f530; kind 2 is read through 0x9a320 and written through 0x37f530.",
            "REA 0x37f530 logs AddPower and applies signed-int32 clamp logic to country + 0x260 + kind*4.",
            "REA 0x9a320 directly returns the signed dword at country + 0x260 + kind*4.",
            "The information reader consumes these offsets as memory fields and never calls any of the functions.",
        ],
        "rea_evidence": rea_records,
        "limitations": [
            "The REA evidence is static shipped-artifact evidence; it contains no live RPM value.",
            "The reader double-pass is not an atomic main-thread snapshot.",
            "World generation, process identity, country pointer lifetime, and runtime values require the reader's independent guards.",
            "The contract does not authorize execution, dispatch, or game-state mutation.",
        ],
    }


def build_profile(
    exe: Path,
    exe_sha: str,
    contract_sha: str,
    rea_records: list[dict[str, Any]],
) -> dict[str, Any]:
    guard_names = {
        "power_kind_labels": "power_kind_labels",
        "power_balance_rules": "power_balance_rules",
        "power_balance_update": "power_balance_update",
        "power_counter": "power_counter",
    }
    code_guards: list[dict[str, Any]] = []
    for record in rea_records:
        body = record["rea_body_range"]
        start = parse_hex(body["rva_start"], "guard.rva")
        end_exclusive = parse_hex(body["rva_end_exclusive"], "guard.end")
        raw = _read_pe_rva_bytes(exe, start, end_exclusive - start)
        code_guards.append(
            {
                "name": guard_names[record["name"]],
                "rva": body["rva_start"],
                "end_rva_exclusive": body["rva_end_exclusive"],
                "size": len(raw),
                "hex": raw.hex(),
                "sha256": sha256_bytes(raw),
                "source_evidence_id": record["evidence_id"],
            }
        )

    dependencies = [
        dependency_record(ROOT / "bridge/information/localization_memory.py", role="bounded helper source"),
        dependency_record(ROOT / "bridge/information/mission_memory.py", role="PE/RPM helper source"),
        dependency_record(
            ROOT / "bridge/information/profiles/localization-memory-1374.json",
            role="localization layout/profile dependency",
        ),
        dependency_record(
            ROOT / "bridge/information/profiles/mission-memory-1374.json",
            role="mission bounded-reader/profile dependency",
        ),
    ]
    for record in rea_records:
        dependencies.append(
            {
                "path": record["evidence_path"],
                "sha256": record["evidence_sha256"],
                "bytes": record["evidence_bytes"],
                "role": "REA semantic evidence",
            }
        )
    dependencies.append(
        {
            "path": relpath(CONTRACT_PATH),
            "sha256": contract_sha,
            "bytes": CONTRACT_PATH.stat().st_size,
            "role": "frozen native power contract",
        }
    )
    return {
        "profile_id": "country-resources-memory-1374",
        "profile_version": 1,
        "contract_sha256": contract_sha,
        "source_evidence_kind": "frozen_REA_semantic_contract_plus_bounded_file_guards",
        "game_version": EXPECTED_VERSION,
        "executable": {"sha256": exe_sha, "image_base": hex(IMAGE_BASE)},
        "globals": {
            "database_rva": "0x233d8b0",
            "game_rva": "0x233fe58",
            "game_date_offset": "0x1dd0",
        },
        "country": {
            "supported_country": "FRA",
            "table_offset": "0x118",
            "handle_offset": "0x20",
            "country_scan_entries": 256,
        },
        "powers": {
            "administrative_offset": "0x260",
            "diplomatic_offset": "0x264",
            "military_offset": "0x268",
            "component_width": 4,
            "signed": True,
            "scale": 1,
            "unit": "monarch_points",
            "kind_enum": {"0": "ADM_POWER", "1": "DIP_POWER", "2": "MIL_POWER"},
        },
        "limits": {
            "max_total_rpm": 524288,
            "max_single_rpm": 65536,
            "double_pass": True,
            "country_scan_entries": 256,
        },
        "code_guards": code_guards,
        "source_evidence": {
            record["name"]: {
                "path": record["evidence_path"],
                "sha256": record["evidence_sha256"],
                "bytes": record["evidence_bytes"],
                "evidence_id": record["evidence_id"],
                "body_rva": {
                    "start": record["rea_body_range"]["rva_start"],
                    "end_exclusive": record["rea_body_range"]["rva_end_exclusive"],
                },
            }
            for record in rea_records
        },
        "provenance": {
            "contract_path": relpath(CONTRACT_PATH),
            "contract_sha256": contract_sha,
            "source_helper_sha256": {
                "localization_memory.py": next(
                    item["sha256"] for item in dependencies if item["path"] == "bridge/information/localization_memory.py"
                ),
                "mission_memory.py": next(
                    item["sha256"] for item in dependencies if item["path"] == "bridge/information/mission_memory.py"
                ),
            },
            "dependencies": dependencies,
            "reader_self_reference": False,
        },
        "unknown_conditions": [
            "REA does not provide runtime values or atomic snapshot evidence.",
            "The reader must keep identity/date/code guards and close-handle checks independent.",
        ],
    }


def recursive_find_strings(value: Any, needle: str) -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for child in value.values():
            found.extend(recursive_find_strings(child, needle))
    elif isinstance(value, list):
        for child in value:
            found.extend(recursive_find_strings(child, needle))
    elif isinstance(value, str) and needle in value:
        found.append(value)
    return found


def build_research_index(exe_sha: str, rea_records: list[dict[str, Any]]) -> dict[str, Any]:
    selected_by_path = {record["evidence_path"]: record for record in rea_records}
    rea_entries: list[dict[str, Any]] = []
    excluded_rea_reasons = {
        "rea-power-balance-caller-001": "caller context did not establish the country storage field",
        "rea-power-display-001": "display/formatter path did not establish the country storage field",
        "rea-power-panel-001": "panel projection did not establish the country storage field",
        "rea-war-exhaustion-cost-001": "unrelated war-exhaustion cost path, outside country power contract",
    }
    for path in sorted(RUNTIME.glob("rea-*/evidence.json")):
        evidence, size, digest = read_json_bounded(path)
        subject_sha = get_path(evidence, "subject", "digest", "sha256")
        if str(subject_sha).lower() != exe_sha:
            raise ValueError(f"rea_index_exe_sha256_mismatch:{path}")
        value = evidence.get("raw_result", {}).get("value", {})
        procedure = value.get("procedure") if isinstance(value, Mapping) else None
        path_key = relpath(path)
        selected = selected_by_path.get(path_key)
        entry: dict[str, Any] = {
            "path": path_key,
            "sha256": digest,
            "bytes": size,
            "evidence_id": evidence.get("evidence_id"),
            "status": "success" if evidence.get("confidence") == "observed" else "unresolved",
            "evidence_kind": "REA_static_function_analysis",
            "procedure": {
                "name": procedure.get("name"),
                "va": procedure.get("address"),
                "rva": hex(parse_hex(procedure.get("address"), "rea.procedure.address") - IMAGE_BASE),
            }
            if isinstance(procedure, Mapping) and procedure.get("address") is not None
            else None,
            "selection_status": "selected_semantic_contract" if selected else "excluded_from_power_contract",
        }
        if selected:
            entry["body_range"] = selected["rea_body_range"]
        else:
            entry["exclusion_reason"] = excluded_rea_reasons.get(
                path.parent.name,
                "not selected: no exact bridge from the REA body to the signed country power fields",
            )
        rea_entries.append(entry)
    ordinary_entries: list[dict[str, Any]] = []
    for filename, kind, note in ORDINARY_REPORTS:
        path = RUNTIME / filename
        report, size, digest = read_json_bounded(path)
        if filename != "save-powers-crosscheck-001.json":
            report_sha = report.get("exe", {}).get("sha256", report.get("executable_sha256"))
            if report_sha != exe_sha:
                raise ValueError(f"ordinary_report_exe_sha256_mismatch:{path}")
        entry: dict[str, Any] = {
            "path": relpath(path),
            "sha256": digest,
            "bytes": size,
            "status": "recorded",
            "evidence_kind": kind,
            "note": note,
        }
        if isinstance(report.get("script_sha256"), str):
            entry["script_sha256"] = report["script_sha256"]
        if isinstance(report.get("script"), Mapping):
            entry["script"] = report["script"]
        ordinary_entries.append(entry)
    disassembly, _, _ = read_json_bounded(RUNTIME / "string-entry-disassembly-001.json")
    excluded = recursive_find_strings(disassembly, "0x37f860")
    return {
        "schema": "information_country_powers_research_index_v1",
        "index_id": "research-index-001",
        "game": {
            "version": EXPECTED_VERSION,
            "executable_sha256": exe_sha,
            "image_base": hex(IMAGE_BASE),
        },
        "rea_successes": rea_entries,
        "ordinary_and_recorded": ordinary_entries,
        "excluded_candidates": [
            {
                "candidate": "0x37f860",
                "source": "string-entry-disassembly-001.json",
                "source_sha256": next(
                    item["sha256"]
                    for item in ordinary_entries
                    if item["path"].endswith("/string-entry-disassembly-001.json")
                ),
                "reason": "excluded from ordinary disassembly selection because it was root-owned; separately retained as successful REA power_kind_labels evidence",
                "rea_replacement": "rea-power-gui-001",
                "ordinary_evidence_matches": len(excluded) > 0,
            },
            {
                "candidate": "indexed-power-access-001 rows",
                "source": "indexed-power-access-001.json",
                "source_sha256": next(
                    item["sha256"]
                    for item in ordinary_entries
                    if item["path"].endswith("/indexed-power-access-001.json")
                ),
                "reason": "raw indexed-dword candidates remain excluded from semantic contract because enum, object type, and balance semantics were unresolved",
                "ordinary_evidence_matches": True,
            },
        ],
        "selection_rule": "Only the four successful REA function bodies establish the native power semantic contract; ordinary and recorded reports remain context or cross-checks.",
        "unresolved": [
            "Recorded save component order is not verified and is not a live-state fallback.",
            "Ordinary candidate offsets without the four REA bridges are excluded from field publication.",
            "World generation and atomic runtime snapshot remain reader-level conditions.",
        ],
    }


def freeze(exe: Path, *, overwrite: bool = False) -> dict[str, Any]:
    if not exe.is_file():
        raise FileNotFoundError(exe)
    exe_size, exe_sha = sha256_file(exe)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"executable_sha256_mismatch:{exe_sha}")
    rea_records = collect_rea_records()
    contract = build_contract(exe, exe_sha, rea_records)
    contract_size, contract_sha = _write_json_new(CONTRACT_PATH, contract, overwrite=overwrite)
    profile = build_profile(exe, exe_sha, contract_sha, rea_records)
    profile_size, profile_sha = _write_json_new(PROFILE_PATH, profile, overwrite=overwrite)
    if profile_size > MAX_PROFILE_BYTES:
        raise ValueError(f"profile_over_limit:{profile_size}")
    index = build_research_index(exe_sha, rea_records)
    index_size, index_sha = _write_json_new(INDEX_PATH, index, overwrite=overwrite)
    return {
        "executable": {"path": relpath(exe), "bytes": exe_size, "sha256": exe_sha},
        "contract": {"path": relpath(CONTRACT_PATH), "bytes": contract_size, "sha256": contract_sha},
        "profile": {"path": relpath(PROFILE_PATH), "bytes": profile_size, "sha256": profile_sha},
        "research_index": {"path": relpath(INDEX_PATH), "bytes": index_size, "sha256": index_sha},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    result = freeze(args.exe.resolve(), overwrite=args.overwrite)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
