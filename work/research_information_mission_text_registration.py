"""Bounded static registration search for dynamic mission text names.

This is an ordinary PE byte-search probe.  It searches the fixed 1.37.4
executable for the two native mission localisation names, records their PE
coordinates and small byte contexts, then searches for exact absolute
pointer values to those strings.  It does not decompile, disassemble, open a
game process, call a game function, or infer that a pointer is a registration
or UI entry.  Nearby executable pointers are reported only as bounded
function-entry candidates when the PE exception table verifies the target.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
from typing import Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXE = Path(r"D:\Downloads\Europa Universalis IV（1.37.4）\Europa Universalis IV\eu4.exe")
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_IMAGE_BASE = 0x140000000
MAX_EXE_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
CONTEXT_BYTES_BEFORE = 16
CONTEXT_BYTES_AFTER = 16
MAX_STRING_MATCHES = 64
MAX_POINTER_MATCHES = 64
REGISTRATION_WINDOW_BYTES = 192
MAX_FUNCTION_CANDIDATES = 64
SEARCH_TERMS = (
    "GetSelectableMissionTitle",
    "GetSelectableMissionDescription",
)
PREFIX_TERM = "GetSelectableMission"


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + max(self.virtual_size, self.raw_size)

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & 0x40000000)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)

    @property
    def read_only(self) -> bool:
        return self.readable and not self.writable

    @property
    def read_only_data(self) -> bool:
        return self.readable and not self.writable and not self.executable

    def file_contains(self, offset: int) -> bool:
        return self.raw_offset <= offset < self.raw_end

    def rva_from_file(self, offset: int) -> int | None:
        if not self.file_contains(offset):
            return None
        return self.virtual_address + (offset - self.raw_offset)

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_end


@dataclass(frozen=True)
class RuntimeFunction:
    begin_rva: int
    end_rva: int
    unwind_rva: int


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK_BYTES), b""):
            total += len(block)
            if total > MAX_EXE_BYTES:
                raise ValueError(f"executable exceeds bounded size {MAX_EXE_BYTES}: {total}")
            digest.update(block)
    return digest.hexdigest(), total


def _read_exact(stream, offset: int, size: int) -> bytes:
    stream.seek(offset)
    raw = stream.read(size)
    if len(raw) != size:
        raise ValueError(f"short PE read at 0x{offset:x}: wanted {size}, got {len(raw)}")
    return raw


def _parse_pe(path: Path, file_size: int) -> tuple[int, list[Section], list[RuntimeFunction], dict[str, int]]:
    with path.open("rb") as stream:
        dos = _read_exact(stream, 0, 0x40)
        if dos[:2] != b"MZ":
            raise ValueError("missing DOS MZ signature")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        signature = _read_exact(stream, pe_offset, 4)
        if signature != b"PE\0\0":
            raise ValueError("missing PE signature")
        coff = _read_exact(stream, pe_offset + 4, 20)
        machine, section_count, _timestamp, _symbol_ptr, _symbol_count, optional_size, _characteristics = struct.unpack(
            "<HHIIIHH", coff
        )
        if machine != 0x8664 or not (1 <= section_count <= 96):
            raise ValueError(f"unexpected PE machine/section count: 0x{machine:x}/{section_count}")
        optional_offset = pe_offset + 24
        optional = _read_exact(stream, optional_offset, optional_size)
        magic = struct.unpack_from("<H", optional, 0)[0]
        if magic != 0x20B or len(optional) < 112 + 16 * 4:
            raise ValueError("not a bounded PE32+ image with data directories")
        image_base = struct.unpack_from("<Q", optional, 24)[0]
        section_offset = optional_offset + optional_size
        sections: list[Section] = []
        for index in range(section_count):
            header = _read_exact(stream, section_offset + index * 40, 40)
            raw_name = header[:8].split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", header, 8)
            characteristics = struct.unpack_from("<I", header, 36)[0]
            if raw_offset + raw_size > file_size:
                raise ValueError(f"section outside file: {name!r}")
            sections.append(Section(name, virtual_address, virtual_size, raw_offset, raw_size, characteristics))

        directory_count = struct.unpack_from("<I", optional, 108)[0]
        directories: dict[str, int] = {"exception_rva": 0, "exception_size": 0}
        if directory_count > 3:
            directories["exception_rva"], directories["exception_size"] = struct.unpack_from("<II", optional, 112 + 3 * 8)

        functions: list[RuntimeFunction] = []
        exception_rva = directories["exception_rva"]
        exception_size = directories["exception_size"]
        exception_section = next((section for section in sections if section.contains_rva(exception_rva)), None)
        if exception_rva and exception_size and exception_section is not None and exception_size <= 8 * 1024 * 1024:
            exception_file_offset = exception_section.raw_offset + (exception_rva - exception_section.virtual_address)
            count = exception_size // 12
            if exception_file_offset + count * 12 <= file_size:
                raw = _read_exact(stream, exception_file_offset, count * 12)
                for offset in range(0, len(raw), 12):
                    begin_rva, end_rva, unwind_rva = struct.unpack_from("<III", raw, offset)
                    if begin_rva < end_rva and any(section.contains_rva(begin_rva) and section.executable for section in sections):
                        functions.append(RuntimeFunction(begin_rva, end_rva, unwind_rva))
        return image_base, sections, functions, directories


def _section_for_file(sections: Iterable[Section], offset: int) -> Section | None:
    return next((section for section in sections if section.file_contains(offset)), None)


def _section_for_rva(sections: Iterable[Section], rva: int) -> Section | None:
    return next((section for section in sections if section.contains_rva(rva)), None)


def _stream_search(
    path: Path,
    needles: Mapping[str, bytes],
    ranges: Iterable[tuple[int, int]],
    *,
    limit: int,
) -> dict[str, tuple[list[int], int]]:
    """Find several exact byte strings in one bounded streaming pass."""
    states = {
        label: {"needle": needle, "matches": [], "count": 0}
        for label, needle in needles.items()
        if needle
    }
    if not states:
        return {label: ([], 0) for label in needles}
    overlap = max(len(state["needle"]) for state in states.values()) - 1
    for range_start, range_size in ranges:
        if range_size <= 0:
            continue
        carry = b""
        consumed = 0
        with path.open("rb") as stream:
            stream.seek(range_start)
            while consumed < range_size:
                chunk = stream.read(min(CHUNK_BYTES, range_size - consumed))
                if not chunk:
                    raise ValueError(f"short bounded search range at 0x{range_start + consumed:x}")
                data = carry + chunk
                data_base = range_start + consumed - len(carry)
                for state in states.values():
                    needle = state["needle"]
                    search_from = 0
                    while True:
                        index = data.find(needle, search_from)
                        if index < 0:
                            break
                        absolute = data_base + index
                        if absolute >= range_start and absolute + len(needle) <= range_start + range_size:
                            state["count"] += 1
                            if len(state["matches"]) < limit:
                                state["matches"].append(absolute)
                        search_from = index + 1
                carry = data[-overlap:] if overlap else b""
                consumed += len(chunk)
    return {
        label: (list(state["matches"]), int(state["count"]))
        for label, state in states.items()
    }


def _stream_matches(path: Path, needle: bytes, ranges: Iterable[tuple[int, int]], *, limit: int) -> tuple[list[int], int]:
    return _stream_search(path, {"needle": needle}, ranges, limit=limit)["needle"]


def _context(path: Path, offset: int, length: int) -> dict[str, str | int]:
    start = max(0, offset - CONTEXT_BYTES_BEFORE)
    with path.open("rb") as stream:
        stream.seek(start)
        raw = stream.read(CONTEXT_BYTES_BEFORE + length + CONTEXT_BYTES_AFTER)
    before_length = offset - start
    before = raw[:before_length]
    match = raw[before_length:before_length + length]
    after = raw[before_length + length:]
    return {
        "context_policy": "up to 16 bytes before + match + up to 16 bytes after",
        "context_start_file_offset": start,
        "context_before_hex": before.hex(),
        "match_hex": match.hex(),
        "context_after_hex": after.hex(),
        "context_hex": raw.hex(),
        "context_ascii": "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in raw),
    }


def _match_record(path: Path, offset: int, term: str, image_base: int, sections: list[Section]) -> dict[str, object]:
    section = _section_for_file(sections, offset)
    rva = section.rva_from_file(offset) if section else None
    record: dict[str, object] = {
        "file_offset": _hex(offset),
        "file_offset_int": offset,
        "rva": _hex(rva),
        "static_va": _hex(image_base + rva) if rva is not None else None,
        "section": section.name if section else None,
        "section_read_only": section.read_only if section else None,
        "section_read_only_data": section.read_only_data if section else None,
        "term": term,
    }
    record.update(_context(path, offset, len(term)))
    record.pop("file_offset_int", None)
    return record


def _read_pointer_record(path: Path, offset: int, target_va: int, image_base: int, sections: list[Section]) -> dict[str, object]:
    section = _section_for_file(sections, offset)
    rva = section.rva_from_file(offset) if section else None
    with path.open("rb") as stream:
        raw = _read_exact(stream, offset, 8)
    return {
        "file_offset": _hex(offset),
        "rva": _hex(rva),
        "static_va": _hex(image_base + rva) if rva is not None else None,
        "target_static_va": _hex(target_va),
        "raw_hex": raw.hex(),
        "section": section.name if section else None,
        "section_read_only": section.read_only if section else None,
        "section_read_only_data": section.read_only_data if section else None,
        "section_executable": section.executable if section else None,
        "file_offset_aligned_8": offset % 8 == 0,
    }


def _function_entry_for_rva(functions: list[RuntimeFunction], rva: int) -> RuntimeFunction | None:
    for function in functions:
        if function.begin_rva == rva:
            return function
    return None


def _nearby_function_candidates(
    path: Path,
    pointer_records: list[dict[str, object]],
    image_base: int,
    sections: list[Section],
    functions: list[RuntimeFunction],
) -> tuple[list[dict[str, object]], bool]:
    candidates: list[dict[str, object]] = []
    seen: set[tuple[int, int]] = set()
    for pointer in pointer_records:
        if pointer.get("section_read_only_data") is not True:
            continue
        pointer_offset = int(str(pointer["file_offset"]), 16)
        section = _section_for_file(sections, pointer_offset)
        if section is None or not section.read_only_data:
            continue
        start = max(section.raw_offset, pointer_offset - REGISTRATION_WINDOW_BYTES // 2)
        end = min(section.raw_end, pointer_offset + REGISTRATION_WINDOW_BYTES // 2)
        with path.open("rb") as stream:
            stream.seek(start)
            raw = stream.read(max(0, end - start))
        aligned_start = start + ((section.raw_offset - start) % 8)
        for slot in range(aligned_start, max(aligned_start, end - 7), 8):
            rel = slot - start
            if rel < 0 or rel + 8 > len(raw):
                continue
            value = int.from_bytes(raw[rel:rel + 8], "little")
            if not (image_base <= value < image_base + 0x40000000):
                continue
            target_rva = value - image_base
            target_section = _section_for_rva(sections, target_rva)
            if target_section is None or not target_section.executable:
                continue
            function = _function_entry_for_rva(functions, target_rva)
            if function is None:
                continue
            key = (slot, target_rva)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({
                "pointer_file_offset": _hex(slot),
                "pointer_rva": _hex(section.rva_from_file(slot)),
                "pointer_section": section.name,
                "target_static_va": _hex(value),
                "target_rva": _hex(target_rva),
                "target_section": target_section.name,
                "unwind": {
                    "verified": True,
                    "begin_rva": _hex(function.begin_rva),
                    "end_rva_exclusive": _hex(function.end_rva),
                    "unwind_rva": _hex(function.unwind_rva),
                    "verification": "target equals PE exception-table function begin RVA",
                },
                "candidate_only": True,
                "semantic_registration_proven": False,
            })
            if len(candidates) >= MAX_FUNCTION_CANDIDATES:
                return candidates, True
    return candidates, False


def _section_report(section: Section) -> dict[str, object]:
    return {
        "name": section.name,
        "virtual_address": _hex(section.virtual_address),
        "virtual_size": section.virtual_size,
        "raw_offset": _hex(section.raw_offset),
        "raw_size": section.raw_size,
        "characteristics": _hex(section.characteristics),
        "readable": section.readable,
        "writable": section.writable,
        "executable": section.executable,
        "read_only": section.read_only,
        "read_only_data": section.read_only_data,
    }


def build_report(exe: Path) -> dict[str, object]:
    if not exe.is_file():
        raise FileNotFoundError(exe)
    file_hash, file_size = _sha256_and_size(exe)
    if file_hash.lower() != EXPECTED_EXE_SHA256:
        raise ValueError(f"unexpected executable SHA-256: {file_hash}")
    image_base, sections, functions, directories = _parse_pe(exe, file_size)
    if image_base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"unexpected PE image base: 0x{image_base:x}")

    all_range = [(0, file_size)]
    search_terms = {term: term.encode("ascii") for term in (*SEARCH_TERMS, PREFIX_TERM)}
    search_results = _stream_search(exe, search_terms, all_range, limit=MAX_STRING_MATCHES)
    string_offsets = {term: search_results[term][0] for term in SEARCH_TERMS}
    string_counts = {term: search_results[term][1] for term in SEARCH_TERMS}

    section_ranges = [(section.raw_offset, section.raw_size) for section in sections if section.raw_size]
    string_records = {
        term: [_match_record(exe, offset, term, image_base, sections) for offset in offsets]
        for term, offsets in string_offsets.items()
    }
    prefix_offsets, prefix_count = search_results[PREFIX_TERM]

    pointer_refs: dict[str, dict[str, object]] = {}
    function_candidates: dict[str, list[dict[str, object]]] = {term: [] for term in SEARCH_TERMS}
    function_candidate_truncated: dict[str, bool] = {term: False for term in SEARCH_TERMS}
    for term, offsets in string_offsets.items():
        pointer_refs[term] = {"target_static_va": None, "matches": [], "match_count": 0, "truncated": False}
        if not offsets:
            continue
        term_record = string_records[term][0]
        target_va = int(str(term_record["static_va"]), 16)
        needle = target_va.to_bytes(8, "little")
        pointer_offsets, pointer_count = _stream_matches(exe, needle, section_ranges, limit=MAX_POINTER_MATCHES)
        records = [_read_pointer_record(exe, offset, target_va, image_base, sections) for offset in pointer_offsets]
        pointer_refs[term] = {
            "target_static_va": _hex(target_va),
            "matches": records,
            "match_count": pointer_count,
            "truncated": pointer_count > MAX_POINTER_MATCHES,
        }
        candidates, truncated = _nearby_function_candidates(exe, records, image_base, sections, functions)
        function_candidates[term] = candidates
        function_candidate_truncated[term] = truncated

    unknowns = [
        "This is ordinary static file-byte evidence, not REA Evidence and not runtime observation.",
        "A string address or nearby pointer does not establish registration, function ownership, UI use, or rendered text semantics.",
        "No function was disassembled, called, injected, or observed in a game process.",
        "PE exception-table membership verifies only a candidate code-pointer entry; it does not prove the registration record's meaning.",
        "Pointer search is limited to exact absolute 64-bit target VA bytes in PE section raw data; RIP-relative and encoded references remain unknown.",
    ]
    if any(not string_offsets[term] for term in SEARCH_TERMS):
        unknowns.append("One or both exact dynamic mission text names were not found; the bounded prefix search is diagnostic only.")
    if not any(function_candidates.values()):
        unknowns.append("No nearby read-only pointer slot was both executable-targeting and exact at a PE exception-table function begin.")
    return {
        "probe": "information-dynamic-text-registration",
        "probe_version": 1,
        "evidence_kind": "ordinary_static_file_byte_search_not_REA_Evidence",
        "read_only": True,
        "script": {
            "path": str(Path(__file__).resolve()),
            "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "target": {
            "path": str(exe.resolve()),
            "file_size_bytes": file_size,
            "sha256": file_hash,
            "expected_sha256": EXPECTED_EXE_SHA256,
            "game_version": "1.37.4",
            "image_base": _hex(image_base),
            "sha256_verified": True,
        },
        "search": {
            "terms": list(SEARCH_TERMS),
            "prefix_term": PREFIX_TERM,
            "algorithm": "streaming exact ASCII byte search",
            "chunk_bytes": CHUNK_BYTES,
            "string_scan_ranges": [{"file_offset": "0x0", "size_bytes": file_size}],
            "prefix_match_count": prefix_count,
            "prefix_matches": [_match_record(exe, offset, PREFIX_TERM, image_base, sections) for offset in prefix_offsets],
            "context_policy": "16 bytes before + match + 16 bytes after",
            "full_text_disassembly": False,
        },
        "pe": {
            "image_base": _hex(image_base),
            "exception_directory_rva": _hex(directories.get("exception_rva")),
            "exception_directory_size": directories.get("exception_size"),
            "sections": [_section_report(section) for section in sections],
            "runtime_function_entries_parsed": len(functions),
            "runtime_function_parse_bound": "PE exception directory only; no disassembly",
        },
        "strings": [
            {
                "term": term,
                "match_count": string_counts[term],
                "truncated": string_counts[term] > MAX_STRING_MATCHES,
                "matches": string_records[term],
            }
            for term in SEARCH_TERMS
        ],
        "pointer_refs": pointer_refs,
        "function_pointer_candidates": function_candidates,
        "function_pointer_candidate_truncated": function_candidate_truncated,
        "limits": {
            "max_executable_bytes": MAX_EXE_BYTES,
            "max_string_matches_per_term": MAX_STRING_MATCHES,
            "max_pointer_matches_per_term": MAX_POINTER_MATCHES,
            "max_function_candidates_total_per_term": MAX_FUNCTION_CANDIDATES,
            "registration_window_bytes": REGISTRATION_WINDOW_BYTES,
            "no_disassembly_bytes": 0,
            "no_runtime_reads": True,
        },
        "status": "observed_static_candidates",
        "unknown_conditions": unknowns,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=DEFAULT_EXE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    report = build_report(args.exe)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "script_sha256": report["script"]["sha256"],
        "sha256": report["target"]["sha256"],
        "strings": {item["term"]: item["match_count"] for item in report["strings"]},
        "pointer_refs": {term: value["match_count"] for term, value in report["pointer_refs"].items()},
        "function_candidates": {term: len(value) for term, value in report["function_pointer_candidates"].items()},
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
