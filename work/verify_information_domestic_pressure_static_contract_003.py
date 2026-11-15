from __future__ import annotations

import hashlib
import json
import re
import struct
from datetime import date
from pathlib import Path
from typing import Any


WORKSPACE = Path(__file__).resolve().parents[1]
BATCH = WORKSPACE / "work" / "runtime" / "information-domestic-pressure-20261025-001"
PROFILE_PATH = WORKSPACE / "bridge" / "information" / "profiles" / "domestic-pressure-memory-1374.json"
READER_PATH = WORKSPACE / "bridge" / "information" / "domestic_pressure_memory.py"
ADAPTER_PATH = WORKSPACE / "bridge" / "information" / "domestic_pressure.py"
CONTRACT_PATH = BATCH / "native-domestic-pressure-contract-003.json"
UNITY_EVIDENCE_PATH = BATCH / "rea-religious-unity-ratio-001" / "evidence.json"
PE_PATH = WORKSPACE / "work" / "runtime" / "ghidra-full" / "b23fa0e1f698d31b-20261014T054913Z-6dda97" / "input" / "eu4.exe"
OUT_PATH = BATCH / "static-contract-independent-audit-003.json"
EXE_SHA = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
PROFILE_SHA = "b727bcd112ace025fcbc0fce78e6194cbb5055642ff12fd85280356e8347d9fd"
CONTRACT_SHA = "902bef470421f8abe3ac4636ce13cb2d2c57f60e2985fcc7c40a28ca89bcaeaf"
IMAGE_BASE = 0x140000000
FIELDS = ("stability", "war_exhaustion", "corruption")
UNITY_EVIDENCE_ID = "ev_748cf5af2ec959f26081f35f01612fcb519f65aa8999014dd772bc8f5cffd436"
UNITY_EVIDENCE_SHA = "a8e020f8b2e300cb7c79ae76e929bf44e9d8e2e0800998d549e8df22fccb2534"


def digest(path: Path) -> tuple[str | None, int]:
    h = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
                total += len(chunk)
    except OSError:
        return None, total
    return h.hexdigest(), total


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def integer(value: Any) -> int:
    return value if isinstance(value, int) else int(str(value), 0)


class PEReader:
    """Bounded RVA reads from the fixed PE; never reads the full image."""

    def __init__(self, path: Path):
        self.path = path
        self.file = path.open("rb")
        self.sections: list[dict[str, int | str]] = []
        self.image_base: int | None = None
        self.machine: int | None = None
        self.section_count: int | None = None
        self._headers()

    def _headers(self) -> None:
        f = self.file
        f.seek(0)
        if f.read(2) != b"MZ":
            raise ValueError("missing_MZ")
        f.seek(0x3C)
        raw = f.read(4)
        if len(raw) != 4:
            raise ValueError("missing_e_lfanew")
        pe_offset = struct.unpack("<I", raw)[0]
        f.seek(pe_offset)
        if f.read(4) != b"PE" + bytes((0, 0)):
            raise ValueError("missing_PE")
        coff = f.read(20)
        if len(coff) != 20:
            raise ValueError("short_COFF")
        machine, sections, _stamp, _sym, _nsym, optional_size, _chars = struct.unpack("<HHIIIHH", coff)
        optional = f.read(optional_size)
        if len(optional) != optional_size or struct.unpack_from("<H", optional, 0)[0] != 0x20B:
            raise ValueError("invalid_PE32plus")
        self.machine = machine
        self.section_count = sections
        self.image_base = struct.unpack_from("<Q", optional, 24)[0]
        for _ in range(sections):
            header = f.read(40)
            if len(header) != 40:
                raise ValueError("short_section_header")
            name = header[:8].rstrip(bytes((0,))).decode("ascii", "replace")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", header, 8)
            self.sections.append({
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
            })

    def _offset(self, rva: int, size: int) -> int:
        if rva < 0 or size < 0:
            raise ValueError("negative_range")
        for section in self.sections:
            va = int(section["virtual_address"])
            raw_size = int(section["raw_size"])
            virtual_size = int(section["virtual_size"])
            if va <= rva and rva + size <= va + max(raw_size, virtual_size) and rva - va + size <= raw_size:
                return int(section["raw_pointer"]) + rva - va
        raise ValueError(f"rva_not_file_backed:{rva:#x}:{size}")

    def read(self, rva: int, size: int) -> bytes:
        self.file.seek(self._offset(rva, size))
        raw = self.file.read(size)
        if len(raw) != size:
            raise ValueError(f"short_rva_read:{rva:#x}:{size}")
        return raw

    def close(self) -> None:
        self.file.close()


def main() -> None:
    profile = load_json(PROFILE_PATH) or {}
    contract = load_json(CONTRACT_PATH) or {}
    profile_sha, profile_bytes = digest(PROFILE_PATH)
    contract_sha, contract_bytes = digest(CONTRACT_PATH)
    exe_sha, exe_bytes = digest(PE_PATH)
    report: dict[str, Any] = {
        "schema": "information_domestic_pressure_static_contract_independent_audit_v3",
        "status": "unresolved",
        "created_on": str(date.today()),
        "evidence_kind": "bounded_PE_byte_checks_plus_existing_REA_evidence_metadata",
        "fixed_target": {
            "game_version": profile.get("game_version"),
            "exe_path": str(PE_PATH),
            "exe_sha256_expected": EXE_SHA,
            "image_base_expected": hex(IMAGE_BASE),
            "scope": list(FIELDS),
            "excluded_fields": {"religious_unity": "EE0_is_province_component_not_effective_unity"},
        },
        "method": {
            "rea_invoked": False,
            "rpm_invoked": False,
            "game_started": False,
            "full_image_disassembly": False,
            "read_policy": "PE headers and selected RVA windows only; evidence JSON processed sequentially",
        },
        "artifacts": {
            "pe": {"path": str(PE_PATH), "bytes": exe_bytes, "sha256": exe_sha, "sha256_expected": EXE_SHA},
            "profile": {"path": str(PROFILE_PATH), "bytes": profile_bytes, "sha256": profile_sha, "sha256_expected": PROFILE_SHA},
            "contract": {"path": str(CONTRACT_PATH), "bytes": contract_bytes, "sha256": contract_sha, "sha256_expected": CONTRACT_SHA},
        },
        "checks": {},
        "fields": {},
        "unresolved": [],
        "conclusion": {},
    }

    try:
        pe = PEReader(PE_PATH)
    except Exception as exc:
        pe = None
        report["checks"]["pe_headers"] = {"status": "unresolved", "error": f"{type(exc).__name__}:{exc}"}
    else:
        report["checks"]["pe_headers"] = {
            "status": "observed",
            "machine": hex(pe.machine or 0),
            "section_count": pe.section_count,
            "image_base": hex(pe.image_base or 0),
            "checks": {
                "sha256": exe_sha == EXE_SHA,
                "image_base": pe.image_base == IMAGE_BASE,
                "peplus_x64": pe.machine == 0x8664,
            },
        }

    report["checks"]["artifact_identity"] = {
        "status": "observed" if profile_sha == PROFILE_SHA and contract_sha == CONTRACT_SHA and exe_sha == EXE_SHA else "unresolved",
        "checks": {
            "profile_sha256": profile_sha == PROFILE_SHA,
            "contract_sha256": contract_sha == CONTRACT_SHA,
            "exe_sha256": exe_sha == EXE_SHA,
            "profile_size_bounded": isinstance(profile_bytes, int) and profile_bytes <= 64 * 1024,
        },
    }

    profile_scalars = profile.get("scalars", {}) if isinstance(profile.get("scalars"), dict) else {}
    profile_tokens = profile.get("save_tokens", {}).get("tokens", {}) if isinstance(profile.get("save_tokens"), dict) else {}
    excluded_profile = profile.get("excluded_fields", {})
    excluded_contract = contract.get("excluded_fields", {})
    report["checks"]["corrected_three_field_scope"] = {
        "status": "observed" if (
            profile.get("profile_version") == 3
            and set(profile_scalars) == set(FIELDS)
            and set(profile_tokens) == set(FIELDS)
            and isinstance(excluded_profile, dict)
            and "religious_unity" in excluded_profile
            and isinstance(contract.get("fields"), dict)
            and set(contract["fields"]) == set(FIELDS)
            and isinstance(excluded_contract, dict)
            and excluded_contract.get("religious_unity", {}).get("status") == "not_implemented"
        ) else "unresolved",
        "profile_version": profile.get("profile_version"),
        "profile_fields": list(profile_scalars),
        "profile_token_fields": list(profile_tokens),
        "contract_fields": list(contract.get("fields", {})) if isinstance(contract.get("fields"), dict) else None,
        "excluded_profile": excluded_profile,
        "excluded_contract": excluded_contract,
        "religious_unity_status": "withdrawn_planned_not_implemented",
    }

    records = contract.get("rea_records", []) if isinstance(contract.get("rea_records"), list) else []
    rea_checks: list[dict[str, Any]] = []
    for record in records:
        rel = record.get("evidence_path")
        path = WORKSPACE / rel if isinstance(rel, str) else WORKSPACE / "__missing__"
        actual_sha, actual_bytes = digest(path)
        evidence = load_json(path) if actual_bytes <= 16 * 1024 * 1024 else None
        normalized = evidence.get("normalized_result", {}) if isinstance(evidence, dict) else {}
        procedure = normalized.get("procedure", {}) if isinstance(normalized, dict) else {}
        body = procedure.get("body", {}) if isinstance(procedure, dict) else {}
        ranges = body.get("ranges", []) if isinstance(body, dict) else []
        first = ranges[0] if ranges and isinstance(ranges[0], dict) else {}
        expected_proc = record.get("procedure", {}) if isinstance(record.get("procedure"), dict) else {}
        expected_body = record.get("rea_body_range", {}) if isinstance(record.get("rea_body_range"), dict) else {}
        checks = {
            "path_exists": path.is_file(),
            "size_matches_contract": actual_bytes == record.get("evidence_bytes"),
            "sha256_matches_contract": actual_sha == record.get("evidence_sha256"),
            "evidence_id_matches_contract": isinstance(evidence, dict) and evidence.get("evidence_id") == record.get("evidence_id"),
            "subject_exe_matches": isinstance(evidence, dict) and evidence.get("subject", {}).get("digest", {}).get("sha256") == EXE_SHA,
            "procedure_address": procedure.get("address") == expected_proc.get("va"),
            "procedure_name": procedure.get("name") == expected_proc.get("name"),
            "body_start": first.get("start") == expected_body.get("va_start"),
            "body_end_inclusive": first.get("end") == expected_body.get("va_end_inclusive"),
            "body_total_bytes": body.get("total_bytes") == expected_body.get("total_body_bytes"),
            "body_span_bytes": body.get("span_bytes") == expected_body.get("span_bytes"),
            "body_single_contiguous": body.get("non_contiguous") is False,
        }
        rea_checks.append({
            "name": record.get("name"),
            "evidence_id": record.get("evidence_id"),
            "path": rel,
            "bytes": actual_bytes,
            "sha256": actual_sha,
            "procedure_rva": expected_proc.get("rva"),
            "checks": checks,
            "status": "observed" if all(checks.values()) else "unresolved",
        })
    report["checks"]["rea_evidence_identity_and_ranges"] = {
        "status": "observed" if len(rea_checks) == 7 and all(item["status"] == "observed" for item in rea_checks) else "unresolved",
        "count": len(rea_checks),
        "expected_count": 7,
        "records": rea_checks,
    }

    unity_sha, unity_bytes = digest(UNITY_EVIDENCE_PATH)
    unity_evidence = load_json(UNITY_EVIDENCE_PATH) if unity_bytes <= 16 * 1024 * 1024 else None
    unity_normalized = unity_evidence.get("normalized_result", {}) if isinstance(unity_evidence, dict) else {}
    unity_procedure = unity_normalized.get("procedure", {}) if isinstance(unity_normalized, dict) else {}
    unity_body = unity_procedure.get("body", {}) if isinstance(unity_procedure, dict) else {}
    unity_ranges = unity_body.get("ranges", []) if isinstance(unity_body, dict) else []
    unity_first = unity_ranges[0] if unity_ranges and isinstance(unity_ranges[0], dict) else {}
    unity_text = str(unity_normalized.get("pseudocode", "")).replace(chr(13), "") if isinstance(unity_normalized, dict) else ""
    unity_anchors = {
        "reads_country_ee0_component": "param_1 + 0xee0" in unity_text,
        "labels_province_component": '"RELIG_UNITY_FROM_PROVINCES"' in unity_text,
        "scans_modifier_a8": "*piVar5 == 0xa8" in unity_text,
        "adds_modifier_result": "iVar7 = iVar7 + local_114" in unity_text,
        "invokes_callback_path": "(**(code **)(*plVar2 + 8))(plVar2,&local_114,param_3,&local_118)" in unity_text,
        "checks_special_rule": "FUN_1408e79a0(param_3,0xe7)" in unity_text and "*(char *)(param_3 + 0x10)" in unity_text,
        "clamps_or_defaults_to_1000": "*param_2 = 1000" in unity_text,
    }
    unity_checks = {
        "path_exists": UNITY_EVIDENCE_PATH.is_file(),
        "size_matches_expected": unity_bytes == 503072,
        "sha256_matches_expected": unity_sha == UNITY_EVIDENCE_SHA,
        "evidence_id_matches_expected": isinstance(unity_evidence, dict) and unity_evidence.get("evidence_id") == UNITY_EVIDENCE_ID,
        "subject_exe_matches": isinstance(unity_evidence, dict) and unity_evidence.get("subject", {}).get("digest", {}).get("sha256") == EXE_SHA,
        "procedure_address": unity_procedure.get("address") == "0x1403b4530",
        "body_range": unity_first.get("start") == "0x1403b4530" and unity_first.get("end") == "0x1403b47a2",
        "body_size": unity_body.get("total_bytes") == 627 and unity_body.get("span_bytes") == 627 and unity_body.get("non_contiguous") is False,
        "anchors": all(unity_anchors.values()),
    }
    report["checks"]["religious_unity_exclusion_evidence"] = {
        "status": "observed" if all(unity_checks.values()) else "unresolved",
        "path": str(UNITY_EVIDENCE_PATH.relative_to(WORKSPACE)),
        "evidence_id": UNITY_EVIDENCE_ID,
        "sha256": unity_sha,
        "bytes": unity_bytes,
        "procedure": {"address": unity_procedure.get("address"), "name": unity_procedure.get("name")},
        "checks": unity_checks,
        "anchors": unity_anchors,
        "semantic_conclusion": "EE0 is RELIG_UNITY_FROM_PROVINCES; final value also applies modifier 0xa8, callback/special-rule logic, and a possible 1000 clamp.",
        "reader_consequence": "Do not read EE0 as final religious_unity; field remains planned/not implemented.",
        "cap_1000_is_final_source": False,
    }

    def evidence_pseudocode(name: str) -> str:
        item = next((entry for entry in rea_checks if entry.get("name") == name), None)
        if not item or not isinstance(item.get("path"), str):
            return ""
        evidence = load_json(WORKSPACE / item["path"])
        return str((evidence or {}).get("normalized_result", {}).get("pseudocode", "")).replace(chr(13), "")

    copy_text = evidence_pseudocode("fixed_point_copy")
    formatter_text = evidence_pseudocode("signed_fixed_point_formatter")
    resolver_text = evidence_pseudocode("save_key_resolver")
    initializer_text = evidence_pseudocode("compiled_save_token_initializer")
    vector_text = evidence_pseudocode("save_key_vector")

    formatter_checks = {
        "copy_signed_4byte_assignment": "*param_1 = *param_2" in copy_text,
        "copy_returns_destination": "return param_1" in copy_text,
        "formatter_signed_int_parameter": "int *param_2" in formatter_text,
        "formatter_divides_by_1000": "*param_2 / 1000" in formatter_text,
        "formatter_modulo_1000": "*param_2 % 1000" in formatter_text,
        "formatter_negative_handling": "if (iVar3 < 0)" in formatter_text,
        "formatter_three_decimal_format": '"%d.%03d"' in formatter_text,
    }
    report["checks"]["copy_and_formatter_semantics"] = {
        "status": "observed" if all(formatter_checks.values()) else "unresolved",
        "rvas": {"copy": "0x956f0", "formatter": "0x246bf0"},
        "anchors": formatter_checks,
        "semantic_limit": "The formatter proves signed int32 serialization/display scale 1000, not a field-specific domain unit or live balance visibility.",
    }

    def parse_address(line: str) -> int | None:
        match = re.search(r"0x([0-9a-fA-F]+):", line)
        return int(match.group(1), 16) if match else None

    def read_abs(address: int, size: int) -> bytes:
        if pe is None:
            raise ValueError("pe_unavailable")
        return pe.read(address - IMAGE_BASE, size)

    def call_target(address: int) -> int:
        raw = read_abs(address, 5)
        if raw[:1] != bytes((0xE8,)):
            raise ValueError("not_relative_call")
        return address + 5 + struct.unpack("<i", raw[1:5])[0]

    compiled = contract.get("compiled_token_records", {}) if isinstance(contract.get("compiled_token_records"), dict) else {}
    writer_results: dict[str, Any] = {}
    for field in FIELDS:
        item = compiled.get(field, {}) if isinstance(compiled.get(field), dict) else {}
        assembly = item.get("writer_assembly", []) if isinstance(item.get("writer_assembly"), list) else []
        parsed = [(parse_address(str(line)), str(line)) for line in assembly]
        parsed = [(addr, line) for addr, line in parsed if addr is not None]
        ranges = item.get("writer_rva_range", [])
        start, end = (integer(ranges[0]), integer(ranges[1])) if len(ranges) == 2 else (None, None)
        scalar = profile.get("scalars", {}).get(field, {}) if isinstance(profile.get("scalars", {}).get(field), dict) else {}
        token = profile.get("save_tokens", {}).get("tokens", {}).get(field, {}) if isinstance(profile.get("save_tokens", {}).get("tokens", {}).get(field), dict) else {}
        lea = next((addr for addr, line in parsed if "LEA RDX, [R15 +" in line), None)
        copy = next((addr for addr, line in parsed if "CALL 0x1400956f0" in line), None)
        r8 = next((addr for addr, line in parsed if "MOV R8, RAX" in line), None)
        imm = next((addr for addr, line in parsed if "MOV EDX," in line), None)
        rcx = next((addr for addr, line in parsed if "MOV RCX, RSI" in line), None)
        writer = next((addr for addr, line in parsed if "CALL 0x141707a10" in line), None)
        lea_offset = None
        imm_value = None
        if lea is not None:
            try:
                raw = read_abs(lea, 7)
                if raw[:3] == bytes.fromhex("498d97"):
                    lea_offset = int.from_bytes(raw[3:7], "little")
            except Exception:
                pass
        if imm is not None:
            try:
                raw = read_abs(imm, 5)
                if raw[:1] == bytes((0xBA,)):
                    imm_value = int.from_bytes(raw[1:5], "little")
            except Exception:
                pass
        try:
            copy_target = call_target(copy) if copy is not None else None
        except Exception:
            copy_target = None
        try:
            writer_target = call_target(writer) if writer is not None else None
        except Exception:
            writer_target = None
        try:
            window_raw = pe.read(start, end - start + 1) if pe is not None and start is not None and end is not None else None
        except Exception:
            window_raw = None
        checks = {
            "window_file_backed": window_raw is not None,
            "window_starts_at_first_instruction": bool(parsed) and start is not None and parsed[0][0] - IMAGE_BASE == start,
            "window_contains_last_call": bool(parsed) and end is not None and writer is not None and writer + 5 - IMAGE_BASE <= end + 1,
            "lea_country_offset": lea_offset == integer(scalar.get("offset")),
            "copy_call_target_0x956f0": copy_target == IMAGE_BASE + 0x956F0,
            "copy_result_to_r8": r8 is not None and read_abs(r8, 3) == bytes.fromhex("4c8bc0"),
            "key_immediate_opcode": imm is not None and read_abs(imm, 1) == bytes((0xBA,)),
            "key_id_matches_profile": imm_value == token.get("key_id"),
            "context_to_rcx": rcx is not None and read_abs(rcx, 3) == bytes.fromhex("488bce"),
            "writer_call_target_0x1707a10": writer_target == IMAGE_BASE + 0x1707A10,
        }
        writer_results[field] = {
            "rva_range_inclusive": [hex(start), hex(end)] if start is not None and end is not None else None,
            "actual_window_hex": window_raw.hex() if window_raw is not None else None,
            "decoded": {"lea_offset": hex(lea_offset) if lea_offset is not None else None, "copy_target": hex(copy_target) if copy_target is not None else None, "key_id": imm_value, "writer_target": hex(writer_target) if writer_target is not None else None},
            "checks": checks,
            "status": "observed" if all(checks.values()) else "unresolved",
        }
    report["checks"]["three_writer_instruction_windows"] = {
        "status": "observed" if len(writer_results) == 3 and all(item["status"] == "observed" for item in writer_results.values()) else "unresolved",
        "target_chain": "country+field_offset -> FUN_1400956f0 copy -> FUN_141707a10(key_id) -> FUN_140246bf0 signed/1000 formatter",
        "fields": writer_results,
    }

    # The three retained records are checked at their exact PE record boundaries.
    first_record = compiled.get("stability", {}) if isinstance(compiled.get("stability"), dict) else {}
    array_ranges = [integer(x) for x in first_record.get("record_array_rva", [])] if isinstance(first_record.get("record_array_rva"), list) else []
    array_start, array_end = (array_ranges[0], array_ranges[1]) if len(array_ranges) == 2 else (None, None)
    stride = first_record.get("stride")
    count = ((array_end - array_start) // stride) if isinstance(array_start, int) and isinstance(array_end, int) and isinstance(stride, int) and stride else None
    token_results: dict[str, Any] = {}
    for field in FIELDS:
        item = compiled.get(field, {}) if isinstance(compiled.get(field), dict) else {}
        rva = integer(item.get("rva")) if item.get("rva") is not None else None
        index = item.get("index")
        key_id = item.get("key_id")
        name = item.get("name")
        expected_hex = item.get("hex")
        raw = None
        try:
            raw = pe.read(rva, len(bytes.fromhex(expected_hex))) if pe is not None and rva is not None else None
        except Exception:
            pass
        profile_token = profile.get("save_tokens", {}).get("tokens", {}).get(field, {}) if isinstance(profile.get("save_tokens", {}).get("tokens", {}).get(field), dict) else {}
        checks = {
            "array_stride_0x208": stride == 0x208,
            "array_span_divisible": isinstance(array_start, int) and isinstance(array_end, int) and isinstance(stride, int) and (array_end - array_start) % stride == 0,
            "index_in_bounds": isinstance(index, int) and isinstance(count, int) and 0 <= index < count,
            "record_boundary": isinstance(rva, int) and isinstance(array_start, int) and isinstance(stride, int) and (rva - array_start) % stride == 0,
            "record_formula": isinstance(rva, int) and isinstance(index, int) and isinstance(array_start, int) and isinstance(stride, int) and rva == array_start + index * stride,
            "record_inside_array": isinstance(rva, int) and isinstance(array_end, int) and isinstance(expected_hex, str) and rva >= array_start and rva + len(bytes.fromhex(expected_hex)) <= array_end,
            "pe_bytes_match_contract": raw is not None and raw.hex() == expected_hex,
            "id_matches_profile": raw is not None and int.from_bytes(raw[:4], "little") == key_id == profile_token.get("key_id"),
            "name_matches_profile": raw is not None and raw[4:] == str(name).encode("ascii") + bytes((0,)) and name == field == profile_token.get("name"),
        }
        token_results[field] = {
            "rva": hex(rva) if isinstance(rva, int) else None,
            "index": index,
            "key_id": key_id,
            "name": name,
            "record_hex": raw.hex() if raw is not None else None,
            "checks": checks,
            "status": "observed" if all(checks.values()) else "unresolved",
        }
    report["checks"]["compiled_token_array"] = {
        "status": "observed" if len(token_results) == 3 and all(item["status"] == "observed" for item in token_results.values()) else "unresolved",
        "record_array_rva": [hex(array_start), hex(array_end)] if array_start is not None and array_end is not None else None,
        "stride_bytes": stride,
        "record_count": count,
        "fields": token_results,
    }

    vector_anchors = {
        "vector_global": "DAT_14242b868" in vector_text,
        "default_id_stride_0x20": "*puVar2 * 0x20 + DAT_14242b868" in vector_text,
        "runtime_registration_range": "DAT_14242b888 - DAT_14242b880" in vector_text,
        "runtime_entry_pointer": "*(uint **)(uVar6 * 8 + DAT_14242b880)" in vector_text,
        "runtime_registration_same_vector": vector_text.count("*puVar2 * 0x20 + DAT_14242b868") >= 2,
        "initializer_calls_vector_builder": "FUN_14170d980();" in initializer_text,
        "resolver_reads_vector": "puVar2 = DAT_14242b868" in resolver_text and "FUN_141708e10" in resolver_text,
    }
    report["checks"]["vector_builder_and_dynamic_registration"] = {
        "status": "observed" if all(vector_anchors.values()) else "unresolved",
        "rva": "0x170d980",
        "anchors": vector_anchors,
        "dynamic_override_precedence": "unresolved",
        "semantic_limit": "The evidence shows runtime-registration entries use the same key-vector writer; exact duplicate-key precedence is not independently closed.",
    }

    guard_records: list[dict[str, Any]] = []
    guards = profile.get("code_guards", []) if isinstance(profile.get("code_guards"), list) else []
    for guard in guards:
        rva = integer(guard.get("rva"))
        expected = bytes.fromhex(str(guard.get("hex", "")))
        try:
            actual = pe.read(rva, len(expected)) if pe is not None else None
        except Exception:
            actual = None
        checks = {
            "size": actual is not None and len(actual) == guard.get("size") == len(expected),
            "hex": actual is not None and actual.hex() == guard.get("hex"),
            "sha256": actual is not None and hashlib.sha256(actual).hexdigest() == guard.get("sha256"),
            "end_rva_exclusive": guard.get("end_rva_exclusive") == hex(rva + len(expected)),
        }
        guard_records.append({
            "name": guard.get("name"),
            "rva": hex(rva),
            "size": len(expected),
            "actual_sha256": hashlib.sha256(actual).hexdigest() if actual is not None else None,
            "checks": checks,
            "status": "observed" if all(checks.values()) else "unresolved",
        })
    report["checks"]["profile_code_guards"] = {
        "status": "observed" if len(guard_records) == 11 and sum(item["size"] for item in guard_records) == 21043 and all(item["status"] == "observed" for item in guard_records) else "unresolved",
        "count": len(guard_records),
        "expected_count": 11,
        "total_bytes": sum(item["size"] for item in guard_records),
        "expected_total_bytes": 21043,
        "guards": guard_records,
        "scope_note": "The retained compiled_token_religious_unity byte guard is an immutable file guard only; it does not publish or authorize the withdrawn field.",
    }

    dependencies = profile.get("provenance", {}).get("dependencies", []) if isinstance(profile.get("provenance"), dict) else []
    dependency_records: list[dict[str, Any]] = []
    for dependency in dependencies if isinstance(dependencies, list) else []:
        rel = dependency.get("path") if isinstance(dependency, dict) else None
        path = WORKSPACE / rel if isinstance(rel, str) else WORKSPACE / "__missing__"
        actual, size = digest(path)
        checks = {
            "path_exists": path.is_file(),
            "size_matches": size == dependency.get("bytes"),
            "sha256_matches": actual == dependency.get("sha256"),
            "regular_and_bounded": path.is_file() and size <= 16 * 1024 * 1024,
        }
        dependency_records.append({
            "path": rel,
            "role": dependency.get("role"),
            "bytes_expected": dependency.get("bytes"),
            "bytes_actual": size,
            "sha256_expected": dependency.get("sha256"),
            "sha256_actual": actual,
            "checks": checks,
            "status": "observed" if all(checks.values()) else "unresolved",
        })
    report["checks"]["profile_provenance_dependencies"] = {
        "status": "observed" if len(dependency_records) == 19 and all(item["status"] == "observed" for item in dependency_records) else "unresolved",
        "count": len(dependency_records),
        "expected_count": 19,
        "reader_self_reference": (profile.get("provenance", {}) or {}).get("reader_self_reference"),
        "dependencies": dependency_records,
    }

    reader_text = ""
    try:
        reader_text = READER_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        pass
    reader_sha, reader_bytes = digest(READER_PATH)
    reader_anchors = {
        "three_field_tuple": 'FIELDS = ("stability", "war_exhaustion", "corruption")' in reader_text,
        "religious_mapping_absent": "religious_unity" not in reader_text,
        "save_token_guard_function": "def _save_token_guard(" in reader_text,
        "vector_read_label": '"save_tokens.vector"' in reader_text,
        "key_stride_read": "key_id * 32" in reader_text,
        "string32_label": '"save_token.{field}.String32"' in reader_text,
        "expected_name_comparison": "expected_name" in reader_text and "save_token_name_mismatch" in reader_text,
        "guard_in_snapshot": "save_token_guard = _save_token_guard" in reader_text,
        "guard_in_compare_snapshot": '"save_token_guard": snapshot.get("save_token_guard")' in reader_text,
        "guard_in_report": 'report["save_token_guard"]' in reader_text,
    }
    report["checks"]["reader_current_name_guard"] = {
        "status": "observed" if all(reader_anchors.values()) else "unresolved",
        "path": str(READER_PATH.relative_to(WORKSPACE)),
        "bytes": reader_bytes,
        "sha256": reader_sha,
        "anchors": reader_anchors,
        "evidence_boundary": "Source guard wiring is present; it is not a live process capture.",
    }

    adapter_text = ""
    try:
        adapter_text = ADAPTER_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        pass
    adapter_sha, adapter_bytes = digest(ADAPTER_PATH)
    adapter_anchors = {
        "three_field_tuple": '_FIELDS = ("stability", "war_exhaustion", "corruption")' in adapter_text,
        "religious_mapping_absent": "religious_unity" not in adapter_text,
        "unknown_field_rejection": "unknown = set(fields) - set(_FIELDS)" in adapter_text,
        "catalog_from_fields": "for field in _FIELDS" in adapter_text,
    }
    report["checks"]["adapter_current_three_field_scope"] = {
        "status": "observed" if all(adapter_anchors.values()) else "unresolved",
        "path": str(ADAPTER_PATH.relative_to(WORKSPACE)),
        "bytes": adapter_bytes,
        "sha256": adapter_sha,
        "anchors": adapter_anchors,
        "religious_unity_route": "absent; composite seed remains planned and unsupported for this field",
    }

    for field in FIELDS:
        scalar = profile.get("scalars", {}).get(field, {}) if isinstance(profile.get("scalars"), dict) else {}
        token = profile.get("save_tokens", {}).get("tokens", {}).get(field, {}) if isinstance(profile.get("save_tokens", {}).get("tokens", {}).get(field), dict) else {}
        entry: dict[str, Any] = {
            "country_offset": scalar.get("offset"),
            "width": scalar.get("width"),
            "signed": scalar.get("signed"),
            "scale": scalar.get("scale"),
            "profile_unit": scalar.get("unit"),
            "save_token": {"key_id": token.get("key_id"), "name": token.get("name")},
            "mechanical_status": "observed" if writer_results.get(field, {}).get("status") == "observed" and token_results.get(field, {}).get("status") == "observed" and scalar.get("width") == 4 and scalar.get("signed") is True and scalar.get("scale") == 1000 else "unresolved",
            "unit_semantics": "observed_for_serialized_label_only",
            "unresolved": ["live balance/value visibility", "save-to-live equivalence"],
        }
        report["fields"][field] = entry

    report["excluded_fields"] = {
        "religious_unity": {
            "status": "withdrawn_not_implemented",
            "country_offset": "0xee0",
            "reason": "EE0 is only RELIG_UNITY_FROM_PROVINCES; final value requires modifier/callback/special-rule path.",
            "evidence_id": UNITY_EVIDENCE_ID,
            "reader_supported": False,
            "adapter_published": False,
            "composite_seed": "planned",
            "query_result": "unsupported",
        }
    }

    semantic_join = contract.get("semantic_join", []) if isinstance(contract.get("semantic_join"), list) else []
    semantic_join_text = " ".join(str(item) for item in semantic_join)
    report["checks"]["contract_narrative_scope"] = {
        "status": "observed" if not any(token in semantic_join_text.lower() for token in ("four selected", "all four actual")) else "unresolved",
        "fields_are_three": isinstance(contract.get("fields"), dict) and set(contract["fields"]) == set(FIELDS),
        "excluded_religious_unity": "religious_unity" in (contract.get("excluded_fields") or {}),
        "stale_scope_phrasing": [item for item in semantic_join if "four selected" in str(item).lower() or "all four actual" in str(item).lower()],
        "note": "Field map and compiled records are three-field; obsolete scope wording is reported as an audit caveat and does not authorize an extra route.",
    }

    report["unresolved"] = [
        "No current EU4 process/session was available; no live RPM capture or runtime value verification was performed.",
        "The vector-builder evidence shows a runtime-registration path using the same vector writer; coverage/order and exact duplicate-key override precedence remain unresolved, while the reader's requested-name guard closes key identity for each retained request.",
        "Static writer/formatter paths prove signed int32 serialization with scale 1000, not atomicity, current UI visibility, or save-to-live equivalence.",
    ]
    static_keys = (
        "rea_evidence_identity_and_ranges",
        "religious_unity_exclusion_evidence",
        "three_writer_instruction_windows",
        "copy_and_formatter_semantics",
        "compiled_token_array",
        "profile_code_guards",
        "profile_provenance_dependencies",
        "corrected_three_field_scope",
        "reader_current_name_guard",
        "adapter_current_three_field_scope",
    )
    retained_layout_verified = all(report["checks"].get(key, {}).get("status") == "observed" for key in static_keys)
    report["claims"] = {
        "retained_scalar_layout_verified": retained_layout_verified,
        "live_validation_pending": True,
        "complete_N04_verified": False,
        "religious_unity_final_value_verified": False,
        "religious_unity_status": "planned_not_implemented",
    }
    report["conclusion"] = {
        "mechanical_static_checks": {
            key: report["checks"][key]["status"]
            for key in static_keys + ("vector_builder_and_dynamic_registration", "contract_narrative_scope")
        },
        "overall": "corrected_pending_runtime" if retained_layout_verified else "unresolved",
        "reason": "The retained three-field PE/evidence/profile chain is mechanically checked and the religious_unity mapping is explicitly withdrawn; no live process was available, so this is not complete N04 acceptance.",
        "runtime_claim": "none",
    }
    report["status"] = report["conclusion"]["overall"]
    if pe is not None:
        pe.close()
    OUT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(OUT_PATH),
        "rea": report["checks"]["rea_evidence_identity_and_ranges"]["status"],
        "writers": report["checks"]["three_writer_instruction_windows"]["status"],
        "formatter": report["checks"]["copy_and_formatter_semantics"]["status"],
        "tokens": report["checks"]["compiled_token_array"]["status"],
        "guards": report["checks"]["profile_code_guards"]["status"],
        "dependencies": report["checks"]["profile_provenance_dependencies"]["status"],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
