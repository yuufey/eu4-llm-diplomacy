"""Bounded token-ID candidates for the N04 domestic-pressure survey.

This is ordinary static evidence only.  It rechecks the two ``.data`` token
occurrences already recorded by the domestic-pressure survey, scans only the
two supplemental ASCII names requested for this batch, and searches the
known country-writer byte range for the preceding DWORD byte patterns.  It
does not disassemble, call REA/RPM, or infer a native field/getter.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE, check_memory_budget  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_EXE_BYTES = 38_463_016
EXPECTED_IMAGE_BASE = 0x140000000
EXPECTED_SURVEY_SHA256 = "d16f653a68653e989cf155a6d7670afdf29c3671b0837a78837f4baaec65d6b9"
WRITER_BEGIN_RVA = 0x2DC6E0
WRITER_END_RVA = 0x2E125B
STRING_CONTEXT_SIDE = 64
WRITER_CONTEXT_BYTES = 80
WRITER_CONTEXT_SIDE = (WRITER_CONTEXT_BYTES - 4) // 2
SUPPLEMENTAL_TOKENS = ("corruption", "religious_unity")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _section(pe: PE, offset: int) -> str | None:
    for item in pe.sections:
        if item["raw"] <= offset < item["raw"] + item["size"]:
            return item["name"]
    return None


def _location(pe: PE, offset: int) -> dict[str, Any]:
    rva = pe.to_rva(offset)
    return {
        "file_offset": hex(offset),
        "rva": None if rva is None else hex(rva),
        "static_va": None if rva is None else hex(pe.base + rva),
        "section": _section(pe, offset),
    }


def _ascii(raw: bytes) -> str:
    return "".join(chr(value) if 32 <= value < 127 else "." for value in raw)


def _context(data: bytes, start: int, end: int, *, before: int, after: int) -> dict[str, Any]:
    left = max(0, start - before)
    right = min(len(data), end + after)
    raw = data[left:right]
    return {
        "file_offset": [hex(left), hex(right)],
        "byte_length": len(raw),
        "hex": raw.hex(),
        "ascii": _ascii(raw),
        "target_relative_offset": start - left,
    }


def _identifier(value: int | None) -> bool:
    return value is not None and (
        0x30 <= value <= 0x39
        or 0x41 <= value <= 0x5A
        or 0x61 <= value <= 0x7A
        or value == 0x5F
    )


def _exact_nul(data: bytes, offset: int, length: int) -> bool:
    prefix = data[offset - 1] if offset else None
    end = offset + length
    suffix = data[end] if end < len(data) else None
    return not _identifier(prefix) and suffix == 0


def _string_row(
    pe: PE, data: bytes, target: str, offset: int, *, origin: str,
    source_row: dict[str, Any] | None = None,
) -> dict[str, Any]:
    needle = target.encode("ascii")
    end = offset + len(needle)
    row: dict[str, Any] = {
        "target": target,
        "origin": origin,
        "match_kind": "exact_nul_boundary",
        **_location(pe, offset),
        "prefix_byte": None if offset == 0 else hex(data[offset - 1]),
        "suffix_byte": None if end >= len(data) else hex(data[end]),
        "context": _context(
            data, offset, end, before=STRING_CONTEXT_SIDE, after=STRING_CONTEXT_SIDE
        ),
    }
    if source_row is not None:
        row["source_survey_location"] = {
            key: source_row.get(key)
            for key in ("file_offset", "rva", "static_va", "section")
        }
    return row


def _survey_data_rows(survey: dict[str, Any], pe: PE) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    data = pe.data
    for target in ("stability", "war_exhaustion"):
        candidates = [
            item for item in survey.get("exact_nul_matches", [])
            if isinstance(item, dict)
            and item.get("target") == target
            and item.get("section") == ".data"
        ]
        if len(candidates) != 1:
            raise ValueError(f"expected one existing .data survey hit for {target}")
        source_row = candidates[0]
        offset = int(source_row["file_offset"], 16)
        if pe.to_rva(offset) != int(source_row["rva"], 16):
            raise ValueError(f"survey RVA mismatch for {target}")
        if not _exact_nul(data, offset, len(target)):
            raise ValueError(f"survey hit is no longer NUL-boundary exact for {target}")
        row = _string_row(pe, data, target, offset, origin="existing_survey", source_row=source_row)
        prefix_offset = offset - 4
        if prefix_offset < 0:
            raise ValueError(f"missing prefix DWORD for {target}")
        prefix = data[prefix_offset:offset]
        row["preceding_dword_candidate"] = {
            **_location(pe, prefix_offset),
            "byte_length": 4,
            "raw_hex": prefix.hex(),
            "value_le_uint32": int.from_bytes(prefix, "little", signed=False),
            "candidate_status": "adjacent_bytes_only_not_semantic_proof",
        }
        rows.append(row)
    return rows


def _supplemental_rows(pe: PE) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    counts: list[dict[str, Any]] = []
    data = pe.data
    for target in SUPPLEMENTAL_TOKENS:
        needle = target.encode("ascii")
        occurrences: list[int] = []
        start = 0
        while True:
            offset = data.find(needle, start)
            if offset < 0:
                break
            occurrences.append(offset)
            start = offset + 1
        exact = [offset for offset in occurrences if _exact_nul(data, offset, len(needle))]
        for offset in exact:
            rows.append(_string_row(pe, data, target, offset, origin="supplemental_ascii_scan"))
        counts.append({
            "target": target,
            "occurrences_considered": len(occurrences),
            "exact_nul_count": len(exact),
            "substring_occurrences_not_reported": len(occurrences) - len(exact),
        })
    return rows, {"tokens": counts, "search_scope": "two_explicit_ASCII_tokens_only"}


def _writer_candidates(
    pe: PE, data_rows: list[dict[str, Any]], writer_begin_offset: int, writer_end_offset: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    data = pe.data
    for data_row in data_rows:
        prefix = data_row["preceding_dword_candidate"]
        pattern = bytes.fromhex(prefix["raw_hex"])
        start = writer_begin_offset
        while True:
            offset = data.find(pattern, start, writer_end_offset)
            if offset < 0:
                break
            context = _context(
                data, offset, offset + len(pattern),
                before=WRITER_CONTEXT_SIDE, after=WRITER_CONTEXT_SIDE,
            )
            # The context helper is bounded by the executable image; record
            # the writer range separately so a match at its edge is explicit.
            rows.append({
                "source_target": data_row["target"],
                "source_string_rva": data_row["rva"],
                "candidate_dword_value_le_uint32": prefix["value_le_uint32"],
                "pattern_hex": pattern.hex(),
                **_location(pe, offset),
                "writer_relative_file_offset": hex(offset - writer_begin_offset),
                "context": context,
                "immediate_operand_status": "unresolved_raw_4byte_pattern_only",
                "evidence": "ordinary_static_byte_match_no_disassembly",
            })
            start = offset + 1
    return rows


def build_report(exe_path: Path, survey_path: Path, writer_source: Path) -> dict[str, Any]:
    exe_path = exe_path.resolve()
    survey_path = survey_path.resolve()
    writer_source = writer_source.resolve()
    check_memory_budget()
    if exe_path.stat().st_size != EXPECTED_EXE_BYTES:
        raise ValueError("unexpected fixed executable size")
    exe_sha = _sha256(exe_path)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise ValueError("fixed executable SHA-256 mismatch")
    survey_sha = _sha256(survey_path)
    if survey_sha != EXPECTED_SURVEY_SHA256:
        raise ValueError("existing domestic-pressure survey SHA-256 mismatch")
    survey = json.loads(survey_path.read_text(encoding="utf-8"))
    if survey.get("exe", {}).get("sha256") != EXPECTED_EXE_SHA256:
        raise ValueError("survey is bound to another executable")
    pe = PE(exe_path)
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError("unexpected PE image base")
    data_rows = _survey_data_rows(survey, pe)
    supplemental_rows, supplemental_summary = _supplemental_rows(pe)
    writer_begin_offset = pe.to_offset(WRITER_BEGIN_RVA)
    writer_end_last_offset = pe.to_offset(WRITER_END_RVA - 1)
    if writer_begin_offset is None or writer_end_last_offset is None:
        raise ValueError("country_writer range is not file-backed")
    writer_end_offset = writer_end_last_offset + 1
    if writer_end_offset <= writer_begin_offset:
        raise ValueError("invalid country_writer range")
    writer_source_sha = _sha256(writer_source)
    script_path = Path(__file__).resolve()
    writer_candidates = _writer_candidates(
        pe, data_rows, writer_begin_offset, writer_end_offset
    )
    check_memory_budget()
    return {
        "schema": "information_domestic_pressure_token_id_candidates_v1",
        "evidence_kind": "ordinary_static_bounded_token_context_and_byte_pattern_survey_not_rea_evidence",
        "script": {
            "path": script_path.relative_to(ROOT).as_posix(),
            "sha256": _sha256(script_path),
        },
        "fixed_target": {
            "game_version": "1.37.4",
            "exe_path": str(exe_path.resolve()),
            "exe_sha256": exe_sha,
            "exe_bytes": exe_path.stat().st_size,
            "image_base": hex(pe.base),
            "scope": ["stability", "war_exhaustion", *SUPPLEMENTAL_TOKENS],
        },
        "source_survey": {
            "path": str(survey_path.relative_to(ROOT).as_posix()),
            "sha256": survey_sha,
            "evidence_kind": survey.get("evidence_kind"),
            "used_rows": "exact_nul_matches section=.data for stability/war_exhaustion",
        },
        "country_writer_source": {
            "path": str(writer_source.relative_to(ROOT).as_posix()),
            "sha256": writer_source_sha,
            "range_label": "country_writer",
            "rva_range": [hex(WRITER_BEGIN_RVA), hex(WRITER_END_RVA)],
            "range_semantics": "fixed ordinary byte range named by the prior bounded branch-input survey",
        },
        "data_token_matches": data_rows,
        "supplemental_exact_matches": supplemental_rows,
        "supplemental_scan": supplemental_summary,
        "country_writer_range": {
            **_location(pe, writer_begin_offset),
            "rva_range": [hex(WRITER_BEGIN_RVA), hex(WRITER_END_RVA)],
            "file_offset_range": [hex(writer_begin_offset), hex(writer_end_offset)],
            "byte_length": writer_end_offset - writer_begin_offset,
            "raw_sha256": hashlib.sha256(pe.data[writer_begin_offset:writer_end_offset]).hexdigest(),
            "disassembly_performed": False,
        },
        "writer_prefix_dword_candidates": writer_candidates,
        "summary": {
            "data_token_count": len(data_rows),
            "supplemental_exact_match_count": len(supplemental_rows),
            "writer_prefix_pattern_candidate_count": len(writer_candidates),
            "candidate_values": [
                {
                    "target": row["target"],
                    "value_le_uint32": row["preceding_dword_candidate"]["value_le_uint32"],
                    "raw_hex": row["preceding_dword_candidate"]["raw_hex"],
                }
                for row in data_rows
            ],
        },
        "unresolved": [
            "An adjacent DWORD before a .data token is only a token-ID candidate; it is not proven to be an ID or field mapping.",
            "A writer-range 4-byte match is not proven to be an immediate operand without instruction decoding.",
            "No country object, runtime address, native getter ABI, unit, scale, or live value was observed.",
            "The supplemental token scan reports only exact ASCII NUL-boundary matches; other encodings and generated data remain unresolved.",
            "REA/RPM/game access and full-image disassembly were not performed.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--survey", type=Path, required=True)
    parser.add_argument("--writer-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = build_report(args.exe, args.survey, args.writer_source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite existing report: {args.output}")
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), **report["summary"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
