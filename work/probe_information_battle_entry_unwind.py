"""Extract bounded PE unwind metadata for the fixed battle-entry candidate.

The candidate is the already researched RVA 0x238620.  This script reuses the
read-only PE/mmap helpers from ``probe_information_message_vtable.py`` and
does not run REA, open a process, call RPM, or install a hook.  It records
mechanical x64 UNWIND_INFO fields and leaves unsupported opcode meanings
explicitly unresolved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import struct
import sys
from pathlib import Path
from typing import Any


WORK = Path(__file__).resolve().parent
ROOT = WORK.parent
if str(WORK) not in sys.path:
    sys.path.insert(0, str(WORK))

import probe_information_message_vtable as pe_helper  # noqa: E402


EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_EXE_SIZE = 38_463_016
IMAGE_BASE = 0x140000000
TARGET_RVA = 0x238620
PROLOGUE_BYTES = 36
UNWIND_WINDOW_BYTES = 512
CALLBACK_REPORT = ROOT / (
    "work/runtime/information-battle-war-records-20261025-001/"
    "callback-entry-selected-001.json"
)
CALLBACK_REPORT_SHA256 = "1d7114d3accb76b417b6a4a56135cc32e8ff8cb3640d1242ff4fe0c5b280a8f6"
CALLBACK_REPORT_BYTES = 271_092
HELPER_RELATIVE = "work/probe_information_message_vtable.py"
HELPER_SHA256 = "fccc7ef747b79df79765b6d5e69aecc2631ce57237409f4e51f688e19836ade6"
HELPER_BYTES = 14_307
DEFAULT_EXE = pe_helper.DEFAULT_EXE
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-battle-entry-20261025-001/"
    "entry-unwind-pe-001.json"
)

UNW_FLAG_NAMES = {
    0x1: "UNW_FLAG_EHANDLER",
    0x2: "UNW_FLAG_UHANDLER",
    0x4: "UNW_FLAG_CHAININFO",
}
NONVOL_REGISTERS = (
    "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
)
XMM_REGISTERS = tuple(f"XMM{index}" for index in range(16))


def _frame_register_name(number: int) -> str | None:
    # In UNWIND_INFO, FrameRegister==0 denotes that no frame register is
    # selected.  The nonzero values use the x64 register numbering table.
    return None if number == 0 else (NONVOL_REGISTERS[number] if number < len(NONVOL_REGISTERS) else None)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _hex(value: int | None) -> str | None:
    return None if value is None else hex(value)


def _resolve_workspace(relative: str | Path, *, max_bytes: int = 16 * 1024 * 1024) -> Path:
    path = (ROOT / Path(relative)).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError(f"path outside workspace: {relative}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"bounded input exceeds {max_bytes} bytes: {path}")
    return path


def _pin(relative: str | Path, expected_sha256: str, expected_bytes: int) -> dict[str, Any]:
    path = _resolve_workspace(relative)
    actual_bytes = path.stat().st_size
    actual_sha = _sha256_file(path)
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "expected": {"bytes": expected_bytes, "sha256": expected_sha256},
        "actual": {"bytes": actual_bytes, "sha256": actual_sha},
        "status": "match" if actual_bytes == expected_bytes and actual_sha == expected_sha256 else "mismatch",
    }


def _rva_record(pe: dict[str, Any], rva: int, size: int = 1) -> dict[str, Any]:
    section = pe_helper._section_for_rva(pe, rva, size)
    offset = pe_helper._rva_to_file_offset(pe, rva, size)
    return {
        "rva": _hex(rva),
        "va": _hex(IMAGE_BASE + rva),
        "file_offset": _hex(offset),
        "file_backed": offset is not None,
        "section": pe_helper._section_record(section),
    }


def _flag_record(flags: int) -> dict[str, Any]:
    known = [name for bit, name in UNW_FLAG_NAMES.items() if flags & bit]
    reserved = flags & ~0x7
    return {
        "raw": flags,
        "raw_hex": _hex(flags),
        "names": known,
        "reserved_bits_raw": reserved,
        "reserved_bits_status": "none" if reserved == 0 else "present_uninterpreted",
    }


def _decode_unwind_codes(codes_raw: bytes, count: int, frame_register: int, frame_offset_nibble: int) -> tuple[list[dict[str, Any]], list[int]]:
    """Decode only specified x64 UNWIND_OP layouts; never infer unknown operands."""

    records: list[dict[str, Any]] = []
    unsupported: list[int] = []
    slot = 0
    while slot < count:
        start = slot
        if slot * 2 + 2 > len(codes_raw):
            records.append({
                "slot_index": start,
                "slot_exclusive": count,
                "status": "truncated_code_header",
                "raw_hex": codes_raw[slot * 2:].hex(),
            })
            break
        code_offset = codes_raw[slot * 2]
        op_info_byte = codes_raw[slot * 2 + 1]
        operation = op_info_byte & 0x0F
        op_info = op_info_byte >> 4
        consumed = 1
        name = {
            0: "UWOP_PUSH_NONVOL",
            1: "UWOP_ALLOC_LARGE",
            2: "UWOP_ALLOC_SMALL",
            3: "UWOP_SET_FPREG",
            4: "UWOP_SAVE_NONVOL",
            5: "UWOP_SAVE_NONVOL_FAR",
            6: "UWOP_SPARE_CODE",
            7: "UWOP_UNKNOWN_7",
            8: "UWOP_SAVE_XMM128",
            9: "UWOP_SAVE_XMM128_FAR",
            10: "UWOP_PUSH_MACHFRAME",
        }.get(operation, f"UWOP_UNKNOWN_{operation}")
        record: dict[str, Any] = {
            "slot_index": start,
            "code_offset": code_offset,
            "code_offset_hex": _hex(code_offset),
            "unwind_op": operation,
            "unwind_op_hex": _hex(operation),
            "op_info": op_info,
            "op_info_hex": _hex(op_info),
            "name": name,
            "raw_header_hex": codes_raw[slot * 2 : slot * 2 + 2].hex(),
        }

        def need_slots(number: int) -> bool:
            return start + number <= count and (start + number) * 2 <= len(codes_raw)

        if operation == 0:
            record.update({
                "status": "decoded",
                "register": NONVOL_REGISTERS[op_info] if op_info < len(NONVOL_REGISTERS) else None,
                "operand_status": "known" if op_info < len(NONVOL_REGISTERS) else "unsupported_register_number",
            })
        elif operation == 1:
            if op_info == 0:
                consumed = 2
                if need_slots(consumed):
                    scaled = struct.unpack_from("<H", codes_raw, (start + 1) * 2)[0]
                    record.update({
                        "status": "decoded",
                        "allocation_bytes": scaled * 8,
                        "allocation_encoding": "u16_scaled_by_8",
                        "continuation_raw_hex": codes_raw[(start + 1) * 2 : (start + consumed) * 2].hex(),
                    })
                else:
                    record.update({"status": "truncated_continuation", "allocation_encoding": "u16_scaled_by_8"})
            elif op_info == 1:
                consumed = 3
                if need_slots(consumed):
                    value = struct.unpack_from("<I", codes_raw, (start + 1) * 2)[0]
                    record.update({
                        "status": "decoded",
                        "allocation_bytes": value,
                        "allocation_encoding": "u32_unscaled",
                        "continuation_raw_hex": codes_raw[(start + 1) * 2 : (start + consumed) * 2].hex(),
                    })
                else:
                    record.update({"status": "truncated_continuation", "allocation_encoding": "u32_unscaled"})
            else:
                record.update({"status": "unsupported_op_info", "operand_status": "no_allocation_operand_decoded"})
                unsupported.append(operation)
        elif operation == 2:
            record.update({"status": "decoded", "allocation_bytes": op_info * 8 + 8})
        elif operation == 3:
            record.update({
                "status": "decoded",
                "frame_register": _frame_register_name(frame_register),
                "frame_offset_bytes": frame_offset_nibble * 16,
            })
        elif operation == 4:
            consumed = 2
            if need_slots(consumed):
                scaled = struct.unpack_from("<H", codes_raw, (start + 1) * 2)[0]
                record.update({"status": "decoded", "register": NONVOL_REGISTERS[op_info] if op_info < len(NONVOL_REGISTERS) else None, "save_offset_bytes": scaled * 8, "continuation_raw_hex": codes_raw[(start + 1) * 2 : (start + consumed) * 2].hex()})
            else:
                record["status"] = "truncated_continuation"
        elif operation == 5:
            consumed = 3
            if need_slots(consumed):
                value = struct.unpack_from("<I", codes_raw, (start + 1) * 2)[0]
                record.update({"status": "decoded", "register": NONVOL_REGISTERS[op_info] if op_info < len(NONVOL_REGISTERS) else None, "save_offset_bytes": value, "continuation_raw_hex": codes_raw[(start + 1) * 2 : (start + consumed) * 2].hex()})
            else:
                record["status"] = "truncated_continuation"
        elif operation in (6, 7):
            record.update({"status": "unsupported", "operand_status": "not_decoded"})
            unsupported.append(operation)
        elif operation == 8:
            consumed = 2
            if op_info >= len(XMM_REGISTERS):
                record.update({"status": "unsupported_xmm_register", "operand_status": "not_decoded"})
                unsupported.append(operation)
            elif need_slots(consumed):
                scaled = struct.unpack_from("<H", codes_raw, (start + 1) * 2)[0]
                record.update({"status": "decoded", "register": XMM_REGISTERS[op_info], "save_offset_bytes": scaled * 16, "continuation_raw_hex": codes_raw[(start + 1) * 2 : (start + consumed) * 2].hex()})
            else:
                record["status"] = "truncated_continuation"
        elif operation == 9:
            consumed = 3
            if op_info >= len(XMM_REGISTERS):
                record.update({"status": "unsupported_xmm_register", "operand_status": "not_decoded"})
                unsupported.append(operation)
            elif need_slots(consumed):
                value = struct.unpack_from("<I", codes_raw, (start + 1) * 2)[0]
                record.update({"status": "decoded", "register": XMM_REGISTERS[op_info], "save_offset_bytes": value, "continuation_raw_hex": codes_raw[(start + 1) * 2 : (start + consumed) * 2].hex()})
            else:
                record["status"] = "truncated_continuation"
        elif operation == 10:
            if op_info in (0, 1):
                record.update({"status": "decoded", "error_code_pushed": bool(op_info)})
            else:
                record.update({"status": "unsupported_op_info", "operand_status": "not_decoded"})
                unsupported.append(operation)
        else:
            record.update({"status": "unsupported", "operand_status": "not_decoded"})
            unsupported.append(operation)

        exclusive = min(count, start + consumed)
        record["slot_exclusive"] = exclusive
        record["slot_span"] = {"start": start, "end_exclusive": exclusive, "within_declared_count": exclusive <= count}
        record["raw_hex"] = codes_raw[start * 2 : exclusive * 2].hex()
        records.append(record)
        slot = exclusive if exclusive > start else start + 1
    return records, unsupported


def _read_unwind_info(mm: mmap.mmap, pe: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    unwind_rva = row["unwind_rva"]
    section = pe_helper._section_for_rva(pe, unwind_rva, 1)
    offset = pe_helper._rva_to_file_offset(pe, unwind_rva, 1)
    if section is None or offset is None:
        raise ValueError("UNWIND_INFO is not file-backed")
    section_end = section["raw_pointer"] + section["raw_size"]
    available = min(UNWIND_WINDOW_BYTES, section_end - offset, mm.size() - offset)
    if available < 4:
        raise ValueError("UNWIND_INFO header is shorter than four bytes")
    raw_window = bytes(mm[offset : offset + available])
    version = raw_window[0] & 0x07
    flags = raw_window[0] >> 3
    prolog_size = raw_window[1]
    count_of_codes = raw_window[2]
    frame_register = raw_window[3] & 0x0F
    frame_offset_nibble = raw_window[3] >> 4
    code_end = 4 + count_of_codes * 2
    if code_end > len(raw_window):
        raise ValueError("UNWIND_INFO code array exceeds bounded window")
    codes_raw = raw_window[4:code_end]
    code_records, unsupported = _decode_unwind_codes(codes_raw, count_of_codes, frame_register, frame_offset_nibble)
    aligned_end = (code_end + 3) & ~3
    if aligned_end > len(raw_window):
        raise ValueError("UNWIND_INFO alignment exceeds bounded window")
    alignment_raw = raw_window[code_end:aligned_end]
    metadata: dict[str, Any] = {
        "rva": _hex(unwind_rva),
        "va": _hex(IMAGE_BASE + unwind_rva),
        "file_offset": _hex(offset),
        "section": pe_helper._section_record(section),
        "window_limit_bytes": UNWIND_WINDOW_BYTES,
        "window_bytes_read": available,
        "raw_window_sha256": hashlib.sha256(raw_window).hexdigest(),
        "raw_window_hex": raw_window.hex(),
        "header": {
            "raw_hex": raw_window[:4].hex(),
            "version": version,
            "version_status": "known" if version == 1 else "unsupported_version",
            "flags": _flag_record(flags),
            "prolog_size": prolog_size,
            "count_of_codes": count_of_codes,
            "frame_register_number": frame_register,
            "frame_register": _frame_register_name(frame_register),
            "frame_offset_nibble": frame_offset_nibble,
            "frame_offset_bytes": frame_offset_nibble * 16,
        },
        "codes": {
            "declared_slot_count": count_of_codes,
            "raw_hex": codes_raw.hex(),
            "records": code_records,
            "unsupported_operations": unsupported,
            "all_declared_slots_accounted": bool(code_records) and code_records[-1].get("slot_exclusive") == count_of_codes,
            "interpretation": "mechanical UNWIND_CODE opcode/operand decode only; unsupported operations retain raw bytes without guessed operands",
        },
        "alignment": {
            "code_end_offset": code_end,
            "aligned_metadata_offset": aligned_end,
            "padding_raw_hex": alignment_raw.hex(),
            "padding_status": "zero_or_recorded" if alignment_raw in (b"", b"\x00\x00", b"\x00\x00\x00") else "nonzero_recorded",
        },
    }
    cursor = aligned_end
    handler_present = bool(flags & 0x3)
    chain_present = bool(flags & 0x4)
    metadata["handler_or_chain"] = {
        "handler_flag_present": handler_present,
        "chain_flag_present": chain_present,
        "mutually_exclusive_flags": not (handler_present and chain_present),
    }
    if handler_present:
        if cursor + 4 > len(raw_window):
            metadata["handler_or_chain"]["handler"] = {"status": "truncated"}
        else:
            handler_rva = struct.unpack_from("<I", raw_window, cursor)[0]
            handler_record = _rva_record(pe, handler_rva, 1)
            handler_record.update({
                "status": "present",
                "raw_hex": raw_window[cursor : cursor + 4].hex(),
                "data_status": "present_unparsed",
                "data_reason": "exception/unwind handler data is not interpreted by this bounded metadata probe",
            })
            metadata["handler_or_chain"]["handler"] = handler_record
        cursor += 4
    if chain_present:
        if cursor + 12 > len(raw_window):
            metadata["handler_or_chain"]["chained"] = {"status": "truncated"}
        else:
            start_rva, end_rva, chain_unwind_rva = struct.unpack_from("<III", raw_window, cursor)
            chain = {
                "status": "present",
                "raw_hex": raw_window[cursor : cursor + 12].hex(),
                "start_rva": _hex(start_rva),
                "end_rva_exclusive": _hex(end_rva),
                "unwind_rva": _hex(chain_unwind_rva),
                "range_kind": "half_open",
                "row_match_status": "not_rechecked_by_function_semantics",
            }
            metadata["handler_or_chain"]["chained"] = chain
        cursor += 12
    metadata["metadata_prefix_bytes_consumed"] = cursor
    metadata["metadata_prefix_within_window"] = cursor <= available
    return metadata


def _callback_comparison() -> dict[str, Any]:
    path = _resolve_workspace(CALLBACK_REPORT.relative_to(ROOT))
    actual_sha = _sha256_file(path)
    pin = {
        "path": path.relative_to(ROOT).as_posix(),
        "expected": {"bytes": CALLBACK_REPORT_BYTES, "sha256": CALLBACK_REPORT_SHA256},
        "actual": {"bytes": path.stat().st_size, "sha256": actual_sha},
        "status": "match" if path.stat().st_size == CALLBACK_REPORT_BYTES and actual_sha == CALLBACK_REPORT_SHA256 else "mismatch",
    }
    with path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)
    assembly = ((report.get("raw_result_value") or {}).get("assembly") or {}).get("value") or []
    first = [item for item in assembly if isinstance(item, str)][:16]
    addresses: list[int] = []
    for item in first:
        try:
            addresses.append(int(item.split(":", 1)[0], 16))
        except (ValueError, IndexError):
            continue
    target_va = IMAGE_BASE + TARGET_RVA
    prologue_end_va = target_va + PROLOGUE_BYTES
    in_window = [item for item, address in zip(first, addresses) if target_va <= address < prologue_end_va]
    next_address = next((address for address in addresses if address >= prologue_end_va), None)
    procedure = ((report.get("raw_result_value") or {}).get("procedure") or {}).get("value") or {}
    return {
        "report_pin": pin,
        "report_status": report.get("status"),
        "procedure": {
            "address": procedure.get("address"),
            "name": procedure.get("name"),
            "body_ranges": (procedure.get("body") or {}).get("ranges", [])[:2],
        },
        "assembly_source": {
            "path": "raw_result.value.assembly",
            "status": ((report.get("raw_result_value") or {}).get("assembly") or {}).get("status"),
            "first_entries": in_window,
            "first_entry_address": _hex(addresses[0]) if addresses else None,
            "next_entry_at_or_after_prologue_end": _hex(next_address),
            "prologue_address_span_matches": bool(addresses) and addresses[0] == target_va and next_address == prologue_end_va,
            "interpretation": "reused recorded Ghidra instruction addresses only; no new REA or instruction-byte claim",
        },
        "reuse_limitations": [
            "The recorded assembly identifies the first 36-byte address span but does not replace this PE byte read.",
            "The callback report does not establish hook ABI, thread/reentry safety, visibility, ownership lifetime, or runtime installation.",
        ],
    }


def probe(executable: Path = DEFAULT_EXE) -> dict[str, Any]:
    executable = executable.resolve()
    before_size = executable.stat().st_size
    if before_size != EXPECTED_EXE_SIZE:
        raise ValueError(f"unexpected executable size: {before_size} != {EXPECTED_EXE_SIZE}")
    sha_before = _sha256_file(executable)
    if sha_before != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected executable SHA-256: {sha_before}")
    with executable.open("rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        pe = pe_helper._parse_pe(mm)
        if pe["image_base"] != IMAGE_BASE:
            raise ValueError(f"unexpected image base: {pe['image_base']:#x}")
        pdata_section, rows = pe_helper._pdata_rows(mm, pe)
        matching_rows = [row for row in rows if row["start_rva"] <= TARGET_RVA < row["end_rva_exclusive"]]
        if len(matching_rows) != 1:
            raise ValueError(f"expected one .pdata row for target, found {len(matching_rows)}")
        row = matching_rows[0]
        prologue_offset = pe_helper._rva_to_file_offset(pe, TARGET_RVA, PROLOGUE_BYTES)
        prologue_section = pe_helper._section_for_rva(pe, TARGET_RVA, PROLOGUE_BYTES)
        if prologue_offset is None or prologue_section is None:
            raise ValueError("target prologue is not fully file-backed")
        prologue = bytes(mm[prologue_offset : prologue_offset + PROLOGUE_BYTES])
        if len(prologue) != PROLOGUE_BYTES:
            raise ValueError("short target prologue")
        unwind = _read_unwind_info(mm, pe, row)
        target_end = TARGET_RVA + PROLOGUE_BYTES
        row_bounds = {
            "start_rva": _hex(row["start_rva"]),
            "end_rva_exclusive": _hex(row["end_rva_exclusive"]),
            "start_va": _hex(IMAGE_BASE + row["start_rva"]),
            "end_va_exclusive": _hex(IMAGE_BASE + row["end_rva_exclusive"]),
            "range_kind": "half_open",
            "contains_target": row["start_rva"] <= TARGET_RVA < row["end_rva_exclusive"],
            "contains_complete_36b_prologue": row["start_rva"] <= TARGET_RVA and target_end <= row["end_rva_exclusive"],
            "unwind_rva": _hex(row["unwind_rva"]),
            "entry_file_offset": _hex(row["file_offset"]),
            "entry_raw_hex": row["raw_hex"],
        }
        after_size = executable.stat().st_size
    if after_size != before_size:
        raise ValueError("executable size changed while being read")
    sha_after = _sha256_file(executable)
    if sha_after != sha_before or sha_after != EXPECTED_EXE_SHA256:
        raise ValueError("executable SHA changed while being read")
    callback = _callback_comparison()
    helper_pin = _pin(HELPER_RELATIVE, HELPER_SHA256, HELPER_BYTES)
    script_path = Path(__file__).resolve()
    script_pin = {
        "path": script_path.relative_to(ROOT).as_posix(),
        "bytes": script_path.stat().st_size,
        "sha256": _sha256_file(script_path),
    }
    return {
        "schema": "information_battle_entry_unwind_pe_metadata_v1",
        "status": "observed_static_pe_unwind_metadata",
        "evidence_kind": "ordinary_PE_pdata_unwind_and_bounded_prologue_bytes",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "rea_invoked": False,
        "game_or_process_accessed": False,
        "target": {
            "path": str(executable),
            "size_bytes": after_size,
            "sha256": sha_after,
            "image_base": _hex(pe["image_base"]),
            "fixed_sha_guard": True,
            "fixed_size_guard": True,
            "size_before_read": before_size,
            "size_after_read": after_size,
            "sha_before_read": sha_before,
            "sha_after_read": sha_after,
            "section_count": pe["section_count"],
        },
        "source_pins": {
            "entry_unwind_probe": script_pin,
            "pe_mmap_helper": helper_pin,
            "prior_callback_entry_selected": callback["report_pin"],
        },
        "target_function": {
            "rva": _hex(TARGET_RVA),
            "va": _hex(IMAGE_BASE + TARGET_RVA),
            "prologue": {
                "rva_start": _hex(TARGET_RVA),
                "rva_end_exclusive": _hex(TARGET_RVA + PROLOGUE_BYTES),
                "va_start": _hex(IMAGE_BASE + TARGET_RVA),
                "va_end_exclusive": _hex(IMAGE_BASE + TARGET_RVA + PROLOGUE_BYTES),
                "file_offset": _hex(prologue_offset),
                "bytes": PROLOGUE_BYTES,
                "raw_hex": prologue.hex(),
                "sha256": hashlib.sha256(prologue).hexdigest(),
                "section": pe_helper._section_record(prologue_section),
                "complete_requested_span": len(prologue) == PROLOGUE_BYTES,
            },
            "pdata_row": row_bounds,
        },
        "unwind_info": unwind,
        "prior_callback_comparison": callback,
        "reusable_metadata_checks": {
            "fixed_exe_guard_passed": sha_after == EXPECTED_EXE_SHA256 and after_size == EXPECTED_EXE_SIZE,
            "exact_pdata_row_found": len(matching_rows) == 1,
            "complete_36b_prologue_read": len(prologue) == PROLOGUE_BYTES,
            "unwind_version_1": unwind["header"]["version"] == 1,
            "unwind_code_slots_bounded": unwind["header"]["count_of_codes"] * 2 <= UNWIND_WINDOW_BYTES - 4,
            "unwind_codes_mechanically_accounted": unwind["codes"]["all_declared_slots_accounted"],
            "callback_assembly_reused_without_new_rea": callback["assembly_source"]["prologue_address_span_matches"] and callback["report_pin"]["status"] == "match",
            "runtime_hook_not_verified": True,
        },
        "limitations": [
            "The 36-byte prefix and UNWIND_INFO are fixed-build ordinary PE metadata; they do not prove that a copied prefix is a valid hook or trampoline.",
            "UNWIND_INFO handler/chained metadata is reported only as bounded presence and raw fields; handler data and chained semantics are not interpreted.",
            "x64 opcode decoding is mechanical and bounded to documented operand layouts; unsupported opcodes or op_info values retain raw bytes and are not guessed.",
            "The prior callback report supplies recorded instruction addresses only. It does not establish hook ABI, thread/reentry safety, visibility, owned lifetime, or runtime installation.",
            "The PE .pdata row is a half-open function-unwind range and does not establish complete non-contiguous body semantics or battle/public identity.",
        ],
        "scope": {
            "full_disassembly": False,
            "new_rea_query": False,
            "runtime_installation": False,
            "hook_or_dispatch": False,
            "game_access": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output = output.resolve()
    output.relative_to(ROOT)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = probe(args.exe)
    serialized = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    with output.open("x", encoding="utf-8", newline="") as handle:
        handle.write(serialized)
    print(json.dumps({"output": output.relative_to(ROOT).as_posix(), "status": report["status"], "bytes": output.stat().st_size}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
