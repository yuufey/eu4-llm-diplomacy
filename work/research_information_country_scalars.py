"""Locate country-power names in the fixed EU4 1.37.4 image.

This is an ordinary, bounded PE byte survey.  It searches only the explicit
ASCII/UTF-16LE names below and records their file/RVA location and bounded
contexts.  It does not decode the image, open a game process, call RPM/REA, or
claim that a string reference is a value reader.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget, rip_references  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_EXE_BYTES = 64 * 1024 * 1024
MAX_CONTEXT_BYTES = 100
MAX_MATCHES_PER_TARGET = 256
MAX_DISASSEMBLY_FUNCTIONS = 6
MAX_FUNCTION_BYTES = 0x4000
MAX_TOTAL_DECODE_BYTES = 0x18000
MAX_EXCERPT_BYTES = 0x300
MAX_SURVEY_REPORT_BYTES = 4 * 1024 * 1024
DEFAULT_DISASSEMBLY_CANDIDATES = (
    0xCED700,
    0xCED760,
    0xB1B0F0,
    0xF61040,
    0xF601E0,
    0xF9FC80,
)
EXCLUDED_ROOT_CANDIDATES = (0x37F860,)
POWER_OFFSETS = (0x260, 0x264, 0x268)

# The first six names are the exact requested scalar/effect tokens.  The
# explicit DIPLO_* name is an existing static GUI/reason key, included as a
# corroboration target rather than as a guessed country-resource label.
TARGETS = {
    "requested": (
        "add_adm_power",
        "add_mil_power",
        "adm_power",
        "mil_power",
        "ADM_POWER",
        "MIL_POWER",
    ),
    "gui_related_explicit": ("DIPLO_MILITARY_POWER",),
}


def _all_targets() -> Iterable[tuple[str, str]]:
    for category, names in TARGETS.items():
        for name in names:
            yield category, name


def _find_all(data: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    start = 0
    while True:
        position = data.find(needle, start)
        if position < 0:
            return hits
        hits.append(position)
        if len(hits) >= MAX_MATCHES_PER_TARGET:
            return hits
        start = position + 1


def _section_for_offset(pe: PE, offset: int) -> dict | None:
    for section in pe.sections:
        if section["raw"] <= offset < section["raw"] + section["size"]:
            return section
    return None


def _bounded_context(data: bytes, start: int, end: int) -> tuple[int, int, bytes]:
    target_length = end - start
    if target_length > MAX_CONTEXT_BYTES:
        raise ValueError("target is larger than the context bound")
    spare = MAX_CONTEXT_BYTES - target_length
    left = min(start, spare // 2)
    context_start = start - left
    context_end = min(len(data), context_start + MAX_CONTEXT_BYTES)
    if context_end < end:
        context_end = end
        context_start = max(0, context_end - MAX_CONTEXT_BYTES)
    return context_start, context_end, data[context_start:context_end]


def _ascii_context(raw: bytes) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in raw)


def _location(pe: PE, file_offset: int) -> dict[str, object]:
    rva = pe.to_rva(file_offset)
    section = _section_for_offset(pe, file_offset)
    return {
        "file_offset": hex(file_offset),
        "rva": None if rva is None else hex(rva),
        "static_va": None if rva is None else hex(pe.base + rva),
        "section": None if section is None else section["name"],
    }


def _string_hit(
    pe: PE,
    target: str,
    encoding: str,
    data: bytes,
    file_offset: int,
    needle: bytes,
) -> dict[str, object]:
    context_start, context_end, context = _bounded_context(
        data, file_offset, file_offset + len(needle)
    )
    location = _location(pe, file_offset)
    rva = pe.to_rva(file_offset)
    return {
        "target": target,
        "encoding": encoding,
        "byte_length": len(needle),
        **location,
        "nul_terminated": data[
            file_offset + len(needle) : file_offset + len(needle) + (2 if encoding == "utf-16le" else 1)
        ]
        == (b"\x00\x00" if encoding == "utf-16le" else b"\x00"),
        "context_file_offset": [hex(context_start), hex(context_end)],
        "context_hex": context.hex(),
        "context_ascii": _ascii_context(context),
        "candidate_function_rva": None,
        "candidate_function_range": None,
        "xref_candidates": [],
        "absolute_pointer_candidates": [],
        "rva_for_xref": None if rva is None else hex(rva),
    }


def _function_candidate(pe: PE, rva: int) -> tuple[str | None, list[str] | None]:
    function = pe.function(rva)
    if function is None:
        return None, None
    return hex(function[0]), [hex(function[0]), hex(function[1])]


def _rip_xrefs(pe: PE, target_rva: int) -> list[dict[str, object]]:
    # ``rip_references`` is a raw byte-pattern helper.  Its output remains a
    # candidate until an instruction/function boundary is independently
    # reviewed; this report deliberately performs no disassembly.
    raw = rip_references(pe, {target_rva}).get(target_rva, [])
    rows: list[dict[str, object]] = []
    for item in raw:
        instruction_rva = int(item["instruction_rva"], 16)
        function_rva, function_range = _function_candidate(pe, instruction_rva)
        rows.append(
            {
                "instruction_rva": item["instruction_rva"],
                "instruction_file_offset": (
                    None
                    if pe.to_offset(instruction_rva) is None
                    else hex(pe.to_offset(instruction_rva))
                ),
                "candidate_function_rva": function_rva,
                "candidate_function_range": function_range,
                "evidence": "raw_rip_relative_byte_pattern_candidate_no_disassembly",
            }
        )
    return rows


def _absolute_pointer_xrefs(pe: PE, target_rva: int) -> list[dict[str, object]]:
    needle = struct.pack("<Q", pe.base + target_rva)
    rows: list[dict[str, object]] = []
    for file_offset in _find_all(pe.data, needle):
        pointer_rva = pe.to_rva(file_offset)
        function_rva, function_range = (
            (None, None)
            if pointer_rva is None
            else _function_candidate(pe, pointer_rva)
        )
        rows.append(
            {
                "pointer_file_offset": hex(file_offset),
                "pointer_rva": None if pointer_rva is None else hex(pointer_rva),
                "pointer_section": (_section_for_offset(pe, file_offset) or {}).get("name"),
                "candidate_function_rva": function_rva,
                "candidate_function_range": function_range,
                "evidence": "raw_absolute_image_pointer_candidate_no_disassembly",
            }
        )
    return rows


def _prior_context() -> dict[str, object]:
    path = ROOT / "work/runtime/r34-rival-power-structure-20261016-001/evidence.json"
    if not path.exists():
        return {"status": "missing", "path": path.relative_to(ROOT).as_posix()}
    raw = path.read_bytes()
    return {
        "status": "observed_prior_evidence",
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "native_source": "actor+0x264",
        "scope": "DIPLOMATIC_POWER only; powers vector component order remains unverified",
    }


def _prior_static_crosschecks() -> list[dict[str, object]]:
    """Collect exact prior key/string pairs without decoding any function."""
    path = ROOT / "work/native/alliance-reason-metadata.inc"
    if not path.is_file():
        return []
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="strict")
    pattern = re.compile(r'\{(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+),"([^"]+)"\}')
    wanted = {name for _, name in _all_targets()}
    rows: list[dict[str, object]] = []
    for match in pattern.finditer(text):
        caller_rva, string_rva, name = match.groups()
        if name not in wanted:
            continue
        rows.append(
            {
                "source": path.relative_to(ROOT).as_posix(),
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "caller_return_rva": caller_rva.lower(),
                "string_rva": string_rva.lower(),
                "name": name,
                "evidence": "prior_ordinary_static_key_pair_no_new_semantic_claim",
            }
        )
    return rows


def build_report(exe_path: Path, script_sha256: str) -> dict[str, object]:
    if not exe_path.is_file():
        raise FileNotFoundError(exe_path)
    if exe_path.stat().st_size > MAX_EXE_BYTES:
        raise ValueError("refusing an executable larger than the bounded raw-scan limit")
    pe = PE(exe_path)
    digest = hashlib.sha256(pe.data).hexdigest()
    if digest != EXPECTED_EXE_SHA256:
        raise ValueError(f"unsupported executable SHA-256: {digest}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    result: dict[str, object] = {
        "schema": "information_country_scalars_string_entry_survey_v1",
        "evidence_kind": "ordinary_static_raw_string_scan_not_REA_Evidence",
        "analysis": {
            "raw_scan_only": True,
            "whole_image_disassembly": False,
            "rea_called": False,
            "runtime_or_rpm": False,
            "max_context_bytes": MAX_CONTEXT_BYTES,
        },
        "exe": {
            "path": str(exe_path),
            "sha256": digest,
            "bytes": len(pe.data),
            "image_base": hex(pe.base),
        },
        "script_sha256": script_sha256,
        "targets": {category: list(names) for category, names in TARGETS.items()},
        "matches": [],
        "prior_context": _prior_context(),
        "prior_static_crosschecks": _prior_static_crosschecks(),
        "unresolved": [
            "A raw string hit does not prove a country scalar label, storage field, getter, or GUI use.",
            "RIP-relative and absolute-pointer rows are byte-pattern candidates only; no disassembly or ABI claim is made.",
            "The prior actor+0x264 DIP evidence does not establish ADM/MIL component order or the meanings of +0x260/+0x268.",
            "No runtime value, country identity, unit scale, or current-state visibility was observed by this survey.",
        ],
    }

    match_rows: list[dict[str, object]] = []
    for category, target in _all_targets():
        for encoding, needle in (
            ("ascii", target.encode("ascii")),
            ("utf-16le", target.encode("utf-16le")),
        ):
            offsets = _find_all(pe.data, needle)
            for offset in offsets:
                row = _string_hit(pe, target, encoding, pe.data, offset, needle)
                row["category"] = category
                row["hit_index"] = len(match_rows)
                match_rows.append(row)

    # Resolve all distinct string RVAs in one bounded raw-code pass.  Doing
    # this after collection avoids rescanning .text or the PE bytes once per
    # duplicate string occurrence.
    target_rvas = {
        int(row["rva"], 16)
        for row in match_rows
        if isinstance(row.get("rva"), str)
    }
    rip_xrefs = rip_references(pe, target_rvas) if target_rvas else {}
    absolute_xrefs = {
        target_rva: _absolute_pointer_xrefs(pe, target_rva)
        for target_rva in target_rvas
    }
    for row in match_rows:
        rva_value = row.get("rva")
        if not isinstance(rva_value, str):
            continue
        target_rva = int(rva_value, 16)
        row["xref_candidates"] = [
            {
                "instruction_rva": item["instruction_rva"],
                "instruction_file_offset": (
                    None
                    if pe.to_offset(int(item["instruction_rva"], 16)) is None
                    else hex(pe.to_offset(int(item["instruction_rva"], 16)))
                ),
                "candidate_function_rva": (
                    None
                    if pe.function(int(item["instruction_rva"], 16)) is None
                    else hex(pe.function(int(item["instruction_rva"], 16))[0])
                ),
                "candidate_function_range": (
                    None
                    if pe.function(int(item["instruction_rva"], 16)) is None
                    else [
                        hex(pe.function(int(item["instruction_rva"], 16))[0]),
                        hex(pe.function(int(item["instruction_rva"], 16))[1]),
                    ]
                ),
                "evidence": "raw_rip_relative_byte_pattern_candidate_no_disassembly",
            }
            for item in rip_xrefs.get(target_rva, [])
        ]
        row["absolute_pointer_candidates"] = absolute_xrefs[target_rva]
    result["matches"] = match_rows
    result["summary"] = {
        "total_matches": len(match_rows),
        "by_target_encoding": {
            f"{row['target']}:{row['encoding']}": sum(
                1
                for current in match_rows
                if current["target"] == row["target"]
                and current["encoding"] == row["encoding"]
            )
            for row in match_rows
        },
        "targets_with_no_hit": [
            f"{target}:{encoding}"
            for _, target in _all_targets()
            for encoding in ("ascii", "utf-16le")
            if not any(
                row["target"] == target and row["encoding"] == encoding
                for row in match_rows
            )
        ],
    }
    check_memory_budget()
    return result


def _load_json_bounded(path: Path, limit: int) -> tuple[dict[str, object], str]:
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > limit:
        raise ValueError(f"refusing JSON larger than bounded limit: {path}")
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value, hashlib.sha256(raw).hexdigest()


def _candidate_references(
    survey: dict[str, object],
) -> dict[int, list[dict[str, object]]]:
    """Reuse the prior survey's xref candidates without scanning strings again."""
    matches = survey.get("matches")
    if not isinstance(matches, list):
        raise ValueError("source survey has no matches list")
    by_function: dict[int, list[dict[str, object]]] = {}
    for match in matches:
        if not isinstance(match, dict):
            continue
        if match.get("encoding") != "ascii":
            continue
        if match.get("target") not in {"ADM_POWER", "MIL_POWER"}:
            continue
        xrefs = match.get("xref_candidates")
        if not isinstance(xrefs, list):
            continue
        target_rva = match.get("rva")
        if not isinstance(target_rva, str):
            continue
        for xref in xrefs:
            if not isinstance(xref, dict):
                continue
            function_rva = xref.get("candidate_function_rva")
            instruction_rva = xref.get("instruction_rva")
            if not isinstance(function_rva, str) or not isinstance(instruction_rva, str):
                continue
            function = int(function_rva, 16)
            by_function.setdefault(function, []).append(
                {
                    "label": match["target"],
                    "label_rva": target_rva,
                    "instruction_rva": instruction_rva,
                    "source_evidence": "prior_raw_rip_relative_candidate",
                }
            )
    return by_function


def _make_bounded_decoder(deps_dir: Path | None):
    """Prefer Capstone; retain a bounded objdump fallback for this machine."""
    if deps_dir is not None:
        candidate = deps_dir.resolve()
        if candidate.is_dir():
            sys.path.insert(0, str(candidate))
    try:
        import capstone

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        return md, f"capstone {capstone.__version__}", None
    except ImportError as exc:
        return None, "bounded objdump -d -w -Mintel (Capstone unavailable)", str(exc)


def _capstone_rows(md, pe: PE, begin: int, end: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for instruction in md.disasm(pe.bytes_at(begin, end - begin), begin):
        rows.append(
            {
                "rva": hex(instruction.address),
                "static_va": hex(pe.base + instruction.address),
                "bytes": instruction.bytes.hex(),
                "size": instruction.size,
                "mnemonic": instruction.mnemonic,
                "operands": instruction.op_str,
            }
        )
    return rows


def _objdump_rows(pe: PE, begin: int, end: int) -> list[dict[str, object]]:
    command = [
        "objdump",
        "-d",
        "-w",
        "-Mintel",
        f"--start-address={pe.base + begin:#x}",
        f"--stop-address={pe.base + end:#x}",
        str(pe.path),
    ]
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    if len(completed.stdout) > 8 * 1024 * 1024:
        raise ValueError("bounded disassembly output exceeded 8 MiB")
    pattern = re.compile(
        r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)"
        r"(\S+)(?:\s+(.*))?$"
    )
    rows: list[dict[str, object]] = []
    for line in completed.stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        static_va = int(match.group(1), 16)
        rva = static_va - pe.base
        raw_bytes = bytes.fromhex(match.group(2))
        if not begin <= rva < end or not raw_bytes:
            continue
        rows.append(
            {
                "rva": hex(rva),
                "static_va": hex(static_va),
                "bytes": raw_bytes.hex(),
                "size": len(raw_bytes),
                "mnemonic": match.group(3),
                "operands": match.group(4) or "",
            }
        )
    return rows


def _sequential_rows(
    rows: list[dict[str, object]], begin: int, end: int
) -> tuple[list[dict[str, object]], int | None, bool]:
    """Keep only a stream that starts at the unwind entry and has no gaps."""
    by_rva = {int(row["rva"], 16): row for row in rows}
    selected: list[dict[str, object]] = []
    cursor = begin
    while cursor < end:
        row = by_rva.get(cursor)
        if row is None:
            break
        selected.append(row)
        cursor += int(row["size"])
    terminal: int | None = None
    terminal_index: int | None = None
    for index, row in enumerate(selected):
        if str(row["mnemonic"]).lower() in {"ret", "retf", "iret", "int3"}:
            terminal = int(row["rva"], 16)
            terminal_index = index
            break
    # PE unwind ranges may include a jump table or padding after the first
    # terminal instruction.  Keep only the prefix that was reached by
    # sequential instruction decoding; bytes after RET are not instruction
    # excerpts and must not be treated as code.
    if terminal_index is not None:
        selected = selected[: terminal_index + 1]
    return selected, terminal, cursor == end


def _power_offset(row: dict[str, object]) -> int | None:
    operands = str(row.get("operands", "")).lower()
    for value in POWER_OFFSETS:
        if re.search(rf"\+0x{value:x}(?:\b|\])", operands):
            return value
    return None


def _condition_row(row: dict[str, object]) -> bool:
    mnemonic = str(row.get("mnemonic", "")).lower()
    if mnemonic in {"cmp", "test", "cmov", "cmova", "cmovae", "cmovb", "cmovbe", "cmove", "cmovne", "cmovg", "cmovge", "cmovl", "cmovle", "cmovs", "cmovns"}:
        return True
    return mnemonic.startswith("j") and mnemonic not in {"jmp", "jmpq"}


def _excerpt_windows(
    rows: list[dict[str, object]], anchors: list[tuple[int, str, int | None]],
    begin: int, end: int
) -> list[dict[str, object]]:
    """Select bounded rows around verified sequential instruction anchors."""
    if not rows:
        return []
    windows: list[tuple[int, int, list[tuple[int, str, int | None]]]] = []
    for anchor, kind, offset in anchors:
        requested_start = max(begin, anchor - 0x80)
        requested_end = min(end, anchor + 0x100)
        if requested_end - requested_start > MAX_EXCERPT_BYTES:
            requested_end = requested_start + MAX_EXCERPT_BYTES
        windows.append((requested_start, requested_end, [(anchor, kind, offset)]))
    merged: list[tuple[int, int, list[tuple[int, str, int | None]]]] = []
    for start, stop, source in sorted(windows):
        if merged and start <= merged[-1][1]:
            prior_start, prior_stop, prior_sources = merged[-1]
            merged[-1] = (
                prior_start,
                min(end, max(prior_stop, stop)),
                prior_sources + source,
            )
        else:
            merged.append((start, stop, list(source)))
    excerpts: list[dict[str, object]] = []
    for requested_start, requested_end, source in merged:
        selected = [
            row
            for row in rows
            if requested_start <= int(row["rva"], 16) < requested_end
        ]
        if not selected:
            continue
        first = int(selected[0]["rva"], 16)
        last = int(selected[-1]["rva"], 16) + int(selected[-1]["size"])
        excerpts.append(
            {
                "requested_rva_window": [hex(requested_start), hex(requested_end)],
                "instruction_rva_window": [hex(first), hex(last)],
                "bytes": last - first,
                "anchors": [
                    {
                        "rva": hex(anchor),
                        "kind": kind,
                        "offset": None if offset is None else hex(offset),
                    }
                    for anchor, kind, offset in source
                ],
                "instructions": selected,
            }
        )
    return excerpts


def build_disassembly_report(
    exe_path: Path,
    survey_path: Path,
    script_sha256: str,
    deps_dir: Path | None = None,
) -> dict[str, object]:
    """Decode only selected PE unwind ranges from a prior string survey."""
    survey, survey_sha256 = _load_json_bounded(survey_path, MAX_SURVEY_REPORT_BYTES)
    survey_exe = survey.get("exe")
    if not isinstance(survey_exe, dict) or survey_exe.get("sha256") != EXPECTED_EXE_SHA256:
        raise ValueError("source survey is not pinned to the expected executable")
    if not exe_path.is_file() or exe_path.stat().st_size > MAX_EXE_BYTES:
        raise ValueError("unsupported executable path or size")
    pe = PE(exe_path)
    digest = hashlib.sha256(pe.data).hexdigest()
    if digest != EXPECTED_EXE_SHA256 or pe.base != IMAGE_BASE:
        raise ValueError("executable identity mismatch")

    references = _candidate_references(survey)
    selected_rvas = [
        rva
        for rva in DEFAULT_DISASSEMBLY_CANDIDATES
        if rva in references and rva not in EXCLUDED_ROOT_CANDIDATES
    ]
    if len(selected_rvas) > MAX_DISASSEMBLY_FUNCTIONS:
        selected_rvas = selected_rvas[:MAX_DISASSEMBLY_FUNCTIONS]
    if not selected_rvas:
        raise ValueError("no selected ADM/MIL label candidates in source survey")
    if any(rva in EXCLUDED_ROOT_CANDIDATES for rva in selected_rvas):
        raise ValueError("root-owned candidate was selected")

    md, decoder, decoder_error = _make_bounded_decoder(deps_dir)
    functions: list[dict[str, object]] = []
    total_decoded = 0
    top_order = [0xB1B0F0, 0xF61040, 0xF601E0]
    for function_rva in selected_rvas:
        pdata = pe.function(function_rva)
        if pdata is None or pdata[0] != function_rva:
            raise ValueError(f"candidate lacks exact PE unwind entry: {function_rva:#x}")
        begin, end = pdata[:2]
        span = end - begin
        if span <= 0 or span > MAX_FUNCTION_BYTES:
            raise ValueError(f"candidate exceeds per-function bound: {function_rva:#x}")
        if total_decoded + span > MAX_TOTAL_DECODE_BYTES:
            raise ValueError("selected candidate decode budget exceeded")
        total_decoded += span
        raw = pe.bytes_at(begin, span)
        rows = _capstone_rows(md, pe, begin, end) if md else _objdump_rows(pe, begin, end)
        sequential, terminal, reached_end = _sequential_rows(rows, begin, end)
        refs = []
        anchors: list[tuple[int, str, int | None]] = []
        row_by_rva = {int(row["rva"], 16): row for row in sequential}
        for reference in references[function_rva]:
            instruction_rva = int(str(reference["instruction_rva"]), 16)
            row = row_by_rva.get(instruction_rva)
            item = {
                "label": reference["label"],
                "label_rva": reference["label_rva"],
                "instruction_rva": hex(instruction_rva),
                "instruction_boundary_verified": row is not None,
                "evidence": "bounded_sequential_disassembly_from_pdata_entry",
            }
            if row is not None:
                item["instruction"] = row
                anchors.append((instruction_rva, "label_reference", None))
            refs.append(item)
        offset_hits = []
        for row in sequential:
            offset = _power_offset(row)
            if offset is not None:
                offset_hits.append(
                    {
                        "offset": hex(offset),
                        "instruction": row,
                        "evidence": "bounded_instruction_operand_text",
                    }
                )
                anchors.append((int(row["rva"], 16), "power_offset", offset))
        excerpts = _excerpt_windows(sequential, anchors, begin, end)
        conditions = [
            row
            for excerpt in excerpts
            for row in excerpt["instructions"]
            if _condition_row(row)
        ]
        labels = sorted({str(reference["label"]) for reference in references[function_rva]})
        rationale = {
            0xB1B0F0: "small switch/formatter caller with both ADM_POWER and MIL_POWER label references",
            0xF61040: "bounded GUI-style formatter with both labels and enum switch",
            0xF601E0: "bounded GUI-style formatter with both labels and enum switch",
            0xCED700: "small ADM_POWER wrapper into shared label formatter",
            0xCED760: "small MIL_POWER wrapper into shared label formatter",
            0xF9FC80: "bounded formatter with both labels",
        }.get(function_rva, "selected prior label-reference candidate")
        functions.append(
            {
                "function_rva": hex(function_rva),
                "unwind_range_rva": [hex(begin), hex(end)],
                "unwind_span_bytes": span,
                "raw_range_sha256": hashlib.sha256(raw).hexdigest(),
                "selection": {
                    "labels": labels,
                    "rationale": rationale,
                    "excluded_root_owned_candidates": [hex(v) for v in EXCLUDED_ROOT_CANDIDATES],
                },
                "sequential_decode": {
                    "start_rva": hex(begin),
                    "decoded_stream_end_rva": hex(
                        int(sequential[-1]["rva"], 16) + int(sequential[-1]["size"])
                    )
                    if sequential
                    else hex(begin),
                    "reached_unwind_end": reached_end,
                    "first_terminal_instruction_rva": (
                        None if terminal is None else hex(terminal)
                    ),
                    "terminal_before_unwind_end": (
                        terminal is not None
                        and terminal + int(
                            row_by_rva.get(terminal, {}).get("size", 0)
                        )
                        < end
                    ),
                    "instruction_count": len(sequential),
                },
                "label_references": refs,
                "visible_power_offsets": offset_hits,
                "condition_branches_in_excerpts": conditions,
                "bounded_excerpts": excerpts,
                "unresolved": [
                    "PE .pdata range is an unwind metadata range, not a complete semantic C++ function proof.",
                    "Label references and formatter branches do not prove a country scalar read or unit scale.",
                    "No +0x260/+0x264/+0x268 memory operand was visible in the selected label excerpts.",
                ],
            }
        )

    worthwhile = []
    for function_rva in top_order:
        row = next((item for item in functions if int(item["function_rva"], 16) == function_rva), None)
        if row is None:
            continue
        worthwhile.append(
            {
                "priority": len(worthwhile) + 1,
                "function_rva": row["function_rva"],
                "reason": row["selection"]["rationale"],
                "visible_offsets": row["visible_power_offsets"],
                "condition_branches": row["condition_branches_in_excerpts"],
            }
        )
        if len(worthwhile) >= 3:
            break

    return {
        "schema": "information_country_scalars_label_candidate_disassembly_v1",
        "evidence_kind": "ordinary_static_bounded_disassembly_not_REA_Evidence",
        "analysis": {
            "string_rescan": False,
            "whole_image_disassembly": False,
            "rea_called": False,
            "runtime_or_rpm": False,
            "candidate_selection": "prior ADM_POWER/MIL_POWER ASCII xref rows; root-owned 0x37f860 excluded",
            "max_functions": MAX_DISASSEMBLY_FUNCTIONS,
            "max_function_bytes": MAX_FUNCTION_BYTES,
            "max_total_decode_bytes": MAX_TOTAL_DECODE_BYTES,
            "max_excerpt_bytes": MAX_EXCERPT_BYTES,
        },
        "decoder": decoder,
        "decoder_error": decoder_error,
        "exe": {
            "path": str(exe_path),
            "sha256": digest,
            "bytes": len(pe.data),
            "image_base": hex(pe.base),
        },
        "source_survey": {
            "path": survey_path.relative_to(ROOT).as_posix()
            if survey_path.is_relative_to(ROOT)
            else str(survey_path),
            "sha256": survey_sha256,
            "evidence_kind": survey.get("evidence_kind"),
            "script_sha256": survey.get("script_sha256"),
        },
        "script_sha256": script_sha256,
        "selected_functions": functions,
        "worth_rea": worthwhile,
        "unresolved": [
            "This report does not assign ADM/MIL meanings to +0x260/+0x268; prior actor+0x264 remains DIP-only evidence.",
            "No runtime values, country identity, unit scale, or UI visibility were observed.",
            "A raw label reference can identify a formatter path without identifying the scalar reader.",
            *([(
                "Capstone was unavailable in the current Python environment; the bounded GNU objdump fallback "
                "is ordinary static evidence and is not a Capstone/REA result."
            )] if decoder_error else []),
        ],
        "limits_observed": {
            "selected_function_count": len(functions),
            "total_unwind_bytes_decoded": total_decoded,
            "all_excerpts_within_0x300": all(
                int(excerpt["bytes"]) <= MAX_EXCERPT_BYTES
                for function in functions
                for excerpt in function["bounded_excerpts"]
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--disassemble-report",
        type=Path,
        help="reuse an existing string-entry survey; do not rescan strings",
    )
    parser.add_argument(
        "--deps-dir",
        type=Path,
        help="optional directory containing the Capstone Python package",
    )
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError(f"refusing to overwrite existing report: {args.output}")
    script_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if args.disassemble_report:
        report = build_disassembly_report(
            args.exe.resolve(), args.disassemble_report.resolve(), script_sha256, args.deps_dir
        )
    else:
        report = build_report(args.exe.resolve(), script_sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "exe_sha256": report["exe"]["sha256"],
                "bytes": report["exe"]["bytes"],
                "matches": report.get("summary", {}).get("total_matches"),
                "selected_functions": len(report.get("selected_functions", [])),
                "decoder": report.get("decoder"),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
