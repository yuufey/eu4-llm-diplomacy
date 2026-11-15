"""Collect bounded static evidence for the battle scalar writer paths.

This probe combines two already-frozen REA function reports with a narrow
ordinary PE read.  It does not start a game, read a process, call a native
function, or disassemble the image.  The REA assembly is kept separate from
the ordinary bytes so that the report does not turn a static call path into a
runtime or business-semantic claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import re
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
EXPECTED_IMAGE_BASE = IMAGE_BASE
MAX_EXE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
FORMAT_RVA = 0x1D648D8
WRITER_RVA = 0x1707B30
LOSSES_CALL_RVA = 0x15C260
WRITER_PROCEDURE_VA = IMAGE_BASE + WRITER_RVA
LOSSES_CALL_VA = IMAGE_BASE + LOSSES_CALL_RVA
DEFAULT_EXE = Path(r"D:\Downloads\Europa Universalis IV（1.37.4）\Europa Universalis IV\eu4.exe")
DEFAULT_WRITER_EVIDENCE = (
    ROOT
    / "work/runtime/information-battle-scalar-writers-20261025-001/"
    "rea-scalar-writer-001/evidence.json"
)
DEFAULT_SIDE_EVIDENCE = (
    ROOT
    / "work/runtime/information-battle-layout-20261025-001/"
    "rea-side-writer-001/evidence.json"
)
DEFAULT_OUTPUT = (
    ROOT
    / "work/runtime/information-battle-scalar-writers-20261025-001/"
    "scalar-field-writer-001.json"
)

_INSTRUCTION_RE = re.compile(r"^\s*(0x[0-9a-fA-F]+):\s*(.+?)\s*$")
_CALL_RE = re.compile(r"\bCALL\s+(0x[0-9a-fA-F]+)\b", re.IGNORECASE)
_FIELD_RE = re.compile(
    r"\bMOV\s+R8D,\s*(?:DWORD\s+PTR\s+)?\[\s*"
    r"([A-Z0-9]+)\s*\+\s*(0x[0-9a-fA-F]+)\s*\]",
    re.IGNORECASE,
)
_ID_RE = re.compile(
    r"\bMOV\s+EDX,\s*(0x[0-9a-fA-F]+)\b", re.IGNORECASE
)
_LOSSES_FIELD_RE = re.compile(
    r"\bMOV\s+EBX,\s*(?:DWORD\s+PTR\s+)?\[\s*"
    r"([A-Z0-9]+)\s*\+\s*(0x54)\s*\]",
    re.IGNORECASE,
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _load_evidence(path: Path, expected_id: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    path = path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"REA evidence is missing: {path}")
    size = path.stat().st_size
    if size > MAX_EVIDENCE_BYTES:
        raise ValueError(f"REA evidence exceeds 16 MiB bound: {path} ({size})")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"REA evidence root is not an object: {path}")
    evidence_id = document.get("evidence_id")
    if expected_id is not None and evidence_id != expected_id:
        raise ValueError(
            f"unexpected evidence id for {path}: {evidence_id!r} != {expected_id!r}"
        )
    subject_sha = (
        document.get("subject", {}).get("digest", {}).get("sha256")
        if isinstance(document.get("subject"), dict)
        else None
    )
    if subject_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"REA evidence target SHA mismatch for {path}: {subject_sha!r}")
    descriptor = {
        "path": _relative(path),
        "sha256": digest,
        "bytes": size,
        "evidence_id": evidence_id,
        "subject_exe_sha256": subject_sha,
        "procedure": document.get("parameters", {}).get("procedure"),
    }
    return descriptor, document


def _parse_pe(mm: mmap.mmap) -> dict[str, Any]:
    if mm.size() > MAX_EXE_BYTES:
        raise ValueError(f"executable exceeds 64 MiB bound: {mm.size()}")
    if mm.size() < 0x40 or bytes(mm[:2]) != b"MZ":
        raise ValueError("executable is not a PE image")
    pe_offset = struct.unpack_from("<I", mm, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > mm.size():
        raise ValueError("invalid PE header offset")
    if bytes(mm[pe_offset : pe_offset + 4]) != b"PE\0\0":
        raise ValueError("invalid PE signature")
    machine, section_count, _timestamp, _symptr, _symbols, optional_size, _chars = (
        struct.unpack_from("<HHIIIHH", mm, pe_offset + 4)
    )
    if not 1 <= section_count <= 96 or optional_size < 32:
        raise ValueError("invalid PE section or optional-header count")
    optional = pe_offset + 24
    if optional + optional_size > mm.size():
        raise ValueError("PE optional header exceeds file")
    magic = struct.unpack_from("<H", mm, optional)[0]
    if magic != 0x20B or optional_size < 32:
        raise ValueError("target is not a PE32+ image")
    image_base = struct.unpack_from("<Q", mm, optional + 24)[0]
    sections_offset = optional + optional_size
    if sections_offset + section_count * 40 > mm.size():
        raise ValueError("PE section table exceeds file")
    sections: list[dict[str, Any]] = []
    for index in range(section_count):
        offset = sections_offset + index * 40
        name = bytes(mm[offset : offset + 8]).split(b"\0", 1)[0].decode(
            "ascii", errors="replace"
        )
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", mm, offset + 8
        )
        if raw_pointer + raw_size > mm.size():
            raise ValueError(f"PE section exceeds file: {name}")
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_pointer": raw_pointer,
            }
        )
    return {
        "machine": machine,
        "section_count": section_count,
        "image_base": image_base,
        "sections": sections,
    }


def _rva_location(pe: dict[str, Any], rva: int, read_length: int) -> dict[str, Any]:
    if rva < 0 or read_length < 0:
        raise ValueError("negative RVA or read length")
    for section in pe["sections"]:
        va = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if va <= rva < va + span:
            delta = rva - va
            if delta + read_length > section["raw_size"]:
                raise ValueError("requested RVA crosses section raw-data boundary")
            return {
                "file_offset": section["raw_pointer"] + delta,
                "section": section["name"],
                "section_rva": va,
            }
    raise ValueError(f"RVA is not file-backed: {rva:#x}")


def _escaped_bytes(raw: bytes) -> str:
    return "".join(
        chr(value) if 32 <= value < 127 else f"\\x{value:02x}" for value in raw
    )


def _read_format_string(executable: Path) -> dict[str, Any]:
    actual_sha = _sha256_file(executable)
    if actual_sha != EXPECTED_EXE_SHA256:
        raise ValueError(f"fixed executable SHA mismatch: {actual_sha}")
    with executable.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            pe = _parse_pe(mm)
            if pe["image_base"] != EXPECTED_IMAGE_BASE:
                raise ValueError(
                    f"unexpected PE image base: {pe['image_base']:#x}"
                )
            location = _rva_location(pe, FORMAT_RVA, 16)
            file_offset = location["file_offset"]
            raw = bytes(mm[file_offset : file_offset + 16])
            prefix = raw.split(b"\0", 1)[0]
            return {
                "kind": "ordinary_pe_file_bytes",
                "executable_path": str(executable.resolve()),
                "executable_sha256": actual_sha,
                "file_size": mm.size(),
                "pe": {
                    "machine": hex(pe["machine"]),
                    "image_base": hex(pe["image_base"]),
                    "section_count": pe["section_count"],
                },
                "rva": hex(FORMAT_RVA),
                "static_va": hex(pe["image_base"] + FORMAT_RVA),
                "file_offset": hex(file_offset),
                "section": location["section"],
                "read_length": len(raw),
                "raw_hex": raw.hex(),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "escaped_ascii": _escaped_bytes(raw),
                "string_prefix_hex": prefix.hex(),
                "nul_terminated_within_read": b"\0" in raw,
                "format_string_verified": prefix == b"%d" and b"\0" in raw,
                "method": "PE section-table RVA-to-raw mapping plus 16-byte mmap read",
            }


def _parse_instruction(line: str, index: int) -> dict[str, Any] | None:
    match = _INSTRUCTION_RE.match(line)
    if not match:
        return None
    address = int(match.group(1), 16)
    text = match.group(2)
    pieces = text.split(None, 1)
    return {
        "assembly_index": index,
        "va": hex(address),
        "rva": hex(address - IMAGE_BASE) if address >= IMAGE_BASE else None,
        "text": line,
        "mnemonic": pieces[0].upper(),
        "operands": pieces[1] if len(pieces) == 2 else "",
    }


def _parse_assembly(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("REA raw_result.value.assembly is not a list")
    parsed: list[dict[str, Any]] = []
    for index, line in enumerate(value):
        if not isinstance(line, str):
            continue
        instruction = _parse_instruction(line, index)
        if instruction is not None:
            parsed.append(instruction)
    if not parsed:
        raise ValueError("REA assembly contained no parseable instructions")
    return parsed


def _assembly_window(
    assembly: list[dict[str, Any]], index: int, before: int = 4, after: int = 3
) -> list[dict[str, Any]]:
    return assembly[max(0, index - before) : min(len(assembly), index + after + 1)]


def _writer_calls(side_document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    value = side_document.get("raw_result", {}).get("value", {})
    assembly = _parse_assembly(value.get("assembly"))
    calls: list[dict[str, Any]] = []
    for index, instruction in enumerate(assembly):
        match = _CALL_RE.search(instruction["text"])
        if not match or int(match.group(1), 16) != WRITER_PROCEDURE_VA:
            continue
        field_read: dict[str, Any] | None = None
        field_index: int | None = None
        for candidate_index in range(index - 1, max(-1, index - 10), -1):
            candidate = assembly[candidate_index]
            field_match = _FIELD_RE.search(candidate["text"])
            if field_match:
                field_index = candidate_index
                field_read = {
                    "instruction": candidate["text"],
                    "va": candidate["va"],
                    "rva": candidate["rva"],
                    "base_register": field_match.group(1).upper(),
                    "field_offset": hex(int(field_match.group(2), 16)),
                    "field_offset_int": int(field_match.group(2), 16),
                }
                break
        id_set: dict[str, Any] | None = None
        id_index: int | None = None
        if field_index is not None:
            for candidate_index in range(field_index + 1, index):
                candidate = assembly[candidate_index]
                id_match = _ID_RE.search(candidate["text"])
                if id_match:
                    id_index = candidate_index
                    id_set = {
                        "instruction": candidate["text"],
                        "va": candidate["va"],
                        "rva": candidate["rva"],
                        "immediate_hex": id_match.group(1).lower(),
                        "immediate_int": int(id_match.group(1), 16),
                    }
        guards = [
            candidate["text"]
            for candidate in assembly[max(0, (field_index or index) - 1) : index]
            if re.search(r"\b(?:TEST|J[A-Z]+)\b", candidate["mnemonic"])
        ]
        calls.append(
            {
                "call_site_va": instruction["va"],
                "call_site_rva": instruction["rva"],
                "target_va": hex(WRITER_PROCEDURE_VA),
                "target_rva": hex(WRITER_RVA),
                "field_read": field_read,
                "id_immediate": id_set,
                "guard_instructions": guards,
                "assembly_window": _assembly_window(assembly, index),
                "assembly_source": "REA raw_result.value.assembly",
                "mapping_evidence": {
                    "field_offset": "direct MOV R8D memory operand when present",
                    "id_immediate": "direct MOV EDX immediate when present",
                    "business_name": "unresolved",
                },
            }
        )

    if not calls:
        raise ValueError("old REA assembly contained no 1707B30 calls")
    return calls, assembly


def _losses54_windows(assembly: list[dict[str, Any]]) -> list[dict[str, Any]]:
    field_rows = []
    for index, instruction in enumerate(assembly):
        match = _LOSSES_FIELD_RE.search(instruction["text"])
        if match:
            field_rows.append(
                {
                    "index": index,
                    "instruction": instruction["text"],
                    "va": instruction["va"],
                    "rva": instruction["rva"],
                    "base_register": match.group(1).upper(),
                    "field_offset": "0x54",
                }
            )
    direct_calls = []
    for index, instruction in enumerate(assembly):
        match = _CALL_RE.search(instruction["text"])
        if match and int(match.group(1), 16) == LOSSES_CALL_VA:
            related = [
                row
                for row in field_rows
                if row["index"] < index and index - row["index"] <= 16
            ]
            direct_calls.append(
                {
                    "call_site_va": instruction["va"],
                    "call_site_rva": instruction["rva"],
                    "target_va": hex(LOSSES_CALL_VA),
                    "target_rva": hex(LOSSES_CALL_RVA),
                    "nearest_losses54_reads": related[-1:] if related else [],
                    "assembly_window": _assembly_window(assembly, index, 8, 5),
                    "assembly_source": "REA raw_result.value.assembly",
                }
            )
    return direct_calls


def _writer_contract(writer_document: dict[str, Any]) -> dict[str, Any]:
    value = writer_document.get("raw_result", {}).get("value", {})
    pseudo = value.get("pseudocode")
    if not isinstance(pseudo, str):
        raise ValueError("writer REA pseudocode is missing")
    pseudo_lines = pseudo.splitlines()
    relevant_pseudo = [
        {"line": index, "text": line}
        for index, line in enumerate(pseudo_lines, 1)
        if any(
            token.lower() in line.lower()
            for token in ("param_3", "15c260", "1d648d8", "dword")
        )
    ]
    assembly = _parse_assembly(value.get("assembly"))
    relevant_assembly = [
        row
        for row in assembly
        if any(
            token in row["text"].lower()
            for token in ("15c260", "1d648d8", "r8d")
        )
    ]
    if not any("15c260" in row["text"].lower() for row in relevant_assembly):
        raise ValueError("writer REA assembly lacks the 15C260 call")
    if not any("param_3" in row["text"].lower() for row in relevant_pseudo):
        raise ValueError("writer REA pseudocode lacks param_3")
    return {
        "procedure_va": hex(WRITER_PROCEDURE_VA),
        "procedure_rva": hex(WRITER_RVA),
        "param_3": {
            "declared_type": "undefined4",
            "evidence": "REA pseudocode parameter declaration; four-byte type only",
        },
        "direct_format_call": {
            "callee_va": hex(LOSSES_CALL_VA),
            "callee_rva": hex(LOSSES_CALL_RVA),
            "format_rva": hex(FORMAT_RVA),
            "format_static_va": hex(IMAGE_BASE + FORMAT_RVA),
        },
        "pseudocode_excerpt": relevant_pseudo,
        "assembly_excerpt": relevant_assembly,
        "semantic_status": "call_and_argument_layout_only",
    }


def build_report(
    executable: Path,
    writer_evidence: Path,
    side_evidence: Path,
) -> dict[str, Any]:
    writer_descriptor, writer_document = _load_evidence(
        writer_evidence,
        "ev_aed48f3663f7c2a170398a4c4685fb3a7d5fab7a0d017d0fbda62c4f3eaae28c",
    )
    side_descriptor, side_document = _load_evidence(
        side_evidence,
        "ev_a6a73a3451166f74c223c8ba501946e47e7c44177756d49c1dbe5fc8fc85f219",
    )
    format_string = _read_format_string(executable.resolve())
    calls, side_assembly = _writer_calls(side_document)
    losses_calls = _losses54_windows(side_assembly)
    writer_contract = _writer_contract(writer_document)
    script_path = Path(__file__).resolve()
    return {
        "schema": "information-battle-scalar-writer-001",
        "status": "static_evidence_collected",
        "read_only": True,
        "runtime_observed": False,
        "native_function_invoked": False,
        "target_build": {
            "version": "1.37.4",
            "executable_sha256": EXPECTED_EXE_SHA256,
            "image_base": hex(IMAGE_BASE),
            "address_convention": "RVA relative to PE image base; REA VAs retain 0x140000000 base",
        },
        "script": {
            "path": _relative(script_path),
            "sha256": _sha256_file(script_path),
        },
        "source_evidence": {
            "writer_1707b30": writer_descriptor,
            "side_writer_1dce20": side_descriptor,
        },
        "rea_evidence": {
            "writer_contract": writer_contract,
            "writer_report_basis": "raw_result.value.pseudocode_and_assembly",
            "side_writer_call_sites": calls,
            "losses54_direct_15c260": losses_calls,
            "assembly_target_check": {
                "writer_rva": hex(WRITER_RVA),
                "losses_callee_rva": hex(LOSSES_CALL_RVA),
                "writer_call_count": len(calls),
                "losses_direct_call_count": len(losses_calls),
                "all_writer_calls_have_field_and_id": all(
                    row["field_read"] is not None and row["id_immediate"] is not None
                    for row in calls
                ),
            },
        },
        "ordinary_pe_evidence": {
            "format_string": format_string,
            "method_scope": "fixed PE header/section mapping and one 16-byte mmap read",
        },
        "mapping_and_limits": {
            "field_offset_determinacy": "direct machine-operand offsets are exact for the listed R8D reads",
            "save_id_determinacy": "direct EDX immediates are exact machine operands; their business names are unknown",
            "unit_scale": "unknown; no runtime value or scale was measured",
            "initial_vs_remaining": "unknown",
            "side_reordering": "unknown; param/register roles are not assigned attacker/defender semantics",
            "business_semantics": "unknown; this report does not turn formatter/writer calls into field claims",
            "runtime_validation": "not_performed",
            "not_done": [
                "no game process or RPM",
                "no native function call or dispatch",
                "no new REA query",
                "no full-image disassembly",
            ],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--writer-evidence", type=Path, default=DEFAULT_WRITER_EVIDENCE)
    parser.add_argument("--side-evidence", type=Path, default=DEFAULT_SIDE_EVIDENCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    report = build_report(args.executable, args.writer_evidence, args.side_evidence)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if len(encoded.encode("utf-8")) > 4 * 1024 * 1024:
        raise ValueError("report exceeds 4 MiB bound")
    output.write_text(encoded, encoding="utf-8", newline="\n")
    # Read back only the generated report to make the CLI's successful result
    # independently checkable by the caller.
    json.loads(output.read_text(encoding="utf-8"))
    print(json.dumps({"output": _relative(output), "bytes": output.stat().st_size}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
