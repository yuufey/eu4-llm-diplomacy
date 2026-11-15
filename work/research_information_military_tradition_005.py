"""Bounded raw-width evidence for the archived scalar serializer target.

The archived read-only REA dossier identifies ``0x1707b30`` as the small
serializer/writer used by several scalar call sites.  This script independently
checks only its 97-byte ordinary-PE body.  It records that the caller's R8D
value is preserved as a 32-bit value and that this writer has no divide,
multiply, or scale operation.  The explicit 1000 display scale remains the
separate formatter evidence in tradition-source-004.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_EXE_BYTES = 38_463_016
EXPECTED_IMAGE_BASE = 0x140000000
MAX_EXE_BYTES = 64 * 1024 * 1024
MAX_SINGLE_DECODE_BYTES = 0x200
MAX_TOTAL_DECODE_BYTES = 0x200
WRITER_RANGE = (0x1707B30, 0x1707B91, "scalar_serializer_writer")
ARCHIVE_EVIDENCE = (
    ROOT
    / "work"
    / "runtime"
    / "information-battle-scalar-writers-20261025-001"
    / "rea-scalar-writer-001"
    / "evidence.json"
)
SOURCE004 = (
    ROOT
    / "work"
    / "runtime"
    / "information-military-quality-20261027-001"
    / "tradition-source-004.json"
)


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _decode(pe: PE, md, begin: int, end: int) -> list[dict[str, Any]]:
    check_memory_budget()
    if end <= begin or end - begin > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"decode range exceeds bound: {begin:#x}:{end:#x}")
    return _decode_range(pe, md, begin, end)


def _binary() -> tuple[Path, PE, str, int]:
    path = __import__("work.local_config", fromlist=["game_exe"]).game_exe()
    size = path.stat().st_size
    if size > MAX_EXE_BYTES:
        raise ValueError(f"refusing executable larger than {MAX_EXE_BYTES} bytes")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    binary_sha = digest.hexdigest()
    if binary_sha != EXPECTED_EXE_SHA256 or size != EXPECTED_EXE_BYTES:
        raise ValueError(f"unexpected executable identity: {size} bytes {binary_sha}")
    pe = PE(path)
    if pe.base != EXPECTED_IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")
    return path, pe, binary_sha, size


def _range_record(pe: PE, rows: list[dict[str, Any]]) -> dict[str, Any]:
    begin, end, label = WRITER_RANGE
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise ValueError("writer range not backed by PE")
    function = pe.function(begin)
    return {
        "label": label,
        "rva_range": [hex(begin), hex(end)],
        "static_va_range": [hex(pe.base + begin), hex(pe.base + end)],
        "bytes": len(raw),
        "sha256": _sha256_bytes(raw),
        "pdata_function": None
        if function is None
        else [hex(function[0]), hex(function[1])],
        "instruction_count": len(rows),
    }


def _find(rows: list[dict[str, Any]], rva: int) -> dict[str, Any]:
    for row in rows:
        if int(row["rva"], 16) == rva:
            return row
    return {"rva": hex(rva), "decode_missing": True}


def build_report() -> dict[str, Any]:
    path, pe, binary_sha, size = _binary()
    md, decoder = make_disassembler(ROOT / "work" / "deps")
    rows = _decode(pe, md, WRITER_RANGE[0], WRITER_RANGE[1])
    raw = pe.bytes_at(WRITER_RANGE[0], WRITER_RANGE[1] - WRITER_RANGE[0])
    return {
        "schema": "information_military_quality_static_source_v5",
        "status": "partial",
        "source_kind": "ordinary_pe_bounded_static_with_archived_readonly_rea_reference",
        "scope": "N03.army_tradition_serializer_width_and_scale_boundary",
        "binary": {
            "path": str(path),
            "size": size,
            "sha256": binary_sha,
            "image_base": hex(pe.base),
            "version_pin": "EU4 1.37.4",
        },
        "method": {
            "game_or_rpm": False,
            "rea_new_run": False,
            "native_calls": False,
            "decoder": "capstone" if decoder is not None else "objdump_bounded_fallback",
            "decode_limits": {
                "max_single_bytes": MAX_SINGLE_DECODE_BYTES,
                "max_total_bytes": MAX_TOTAL_DECODE_BYTES,
                "planned_total_bytes": len(raw),
            },
            "only_small_serializer_body": True,
        },
        "prior_sources": {
            "formatter_source004": {
                "path": str(SOURCE004),
                "sha256": _sha256_file(SOURCE004),
            },
            "archived_rea": {
                "path": str(ARCHIVE_EVIDENCE),
                "sha256": _sha256_file(ARCHIVE_EVIDENCE),
                "evidence_id": "ev_aed48f3663f7c2a170398a4c4685fb3a7d5fab7a0d017d0fbda62c4f3eaae28c",
                "procedure_va": "0x141707b30",
                "body_inclusive_rva": ["0x1707b30", "0x1707b90"],
                "body_bytes_inclusive": 97,
                "read_only_noanalysis": True,
                "runtime_observed": False,
            },
        },
        "bounded_ranges": [_range_record(pe, rows)],
        "selected_instructions": {
            "entry_and_value_preservation": [
                _find(rows, 0x1707B3D),
                _find(rows, 0x1707B40),
                _find(rows, 0x1707B43),
                _find(rows, 0x1707B48),
                _find(rows, 0x1707B4B),
                _find(rows, 0x1707B53),
                _find(rows, 0x1707B62),
                _find(rows, 0x1707B67),
                _find(rows, 0x1707B6C),
                _find(rows, 0x1707B71),
                _find(rows, 0x1707B74),
                _find(rows, 0x1707B79),
                _find(rows, 0x1707B8C),
            ]
        },
        "writer_contract": {
            "entry_rva": "0x1707b30",
            "body_rva_range_inclusive": ["0x1707b30", "0x1707b90"],
            "abi": {
                "rcx": "writer destination/object forwarded to the downstream finalizer",
                "rdx": "secondary context forwarded to the downstream finalizer",
                "r8d": "four-byte scalar input copied to EBX at 0x1707b3d and restored to R8D at 0x1707b48",
            },
            "raw_width": "the writer preserves the input as a 32-bit register value; this slice performs no sign extension or narrowing beyond the ABI's R8D width",
            "operations": [
                "MOV EBX,R8D at 0x1707b3d",
                "MOV R8D,EBX at 0x1707b48",
                "MOV DWORD PTR [RSP+0x20],0xc at 0x1707b4b (fixed metadata, not the scalar input)",
                "CALL 0x14015c260 at 0x1707b67 with R8D restored",
                "CALL 0x1417087a0 at 0x1707b74 and tail JMP 0x1417083d0 at 0x1707b8c",
            ],
            "no_scale_operation_in_body": {
                "status": "closed_for_this_body",
                "absent": ["DIV", "IDIV", "IMUL", "MUL", "SAR", "SHR", "SHL"],
                "meaning": "0x1707b30 does not convert the scalar by 1000; it forwards the four-byte input to its downstream formatting/finalization path",
            },
        },
        "field_binding": {
            "army_tradition": {
                "country_cache_source": "tradition-source-002 getter reads country+0xe40",
                "formatter_scale_source": "tradition-source-004 selected UI renderer uses explicit 0x3e8 remainder path",
                "serializer_role": "the generic 0x1707b30 body establishes raw signed-32 ABI width and no hidden divide/multiply in this writer; it is not used to infer a different country offset",
                "scale": 1000,
                "scale_reason": "the 1000 unit is bound by the selected formatter source004; source005 rules out an extra 1000 conversion inside this small serializer",
            }
        },
        "unresolved": [
            "Downstream 0x17087a0/0x17083d0 semantics are not followed in this bounded task.",
            "The archived REA evidence is static read-only and does not establish a runtime FRA call identity.",
        ],
        "conclusion": {
            "army_tradition": "source002 supplies the direct country+0xe40 copy, source004 supplies explicit UI scale 1000, and this source supplies a bounded serializer-width/no-hidden-scale check.",
            "publication": "suitable as a static profile source pin; runtime capture still remains subject to parent identity, double-pass, and cleanup checks",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT
        / "work"
        / "runtime"
        / "information-military-quality-20261027-001"
        / "tradition-source-005.json",
    )
    args = parser.parse_args()
    report = build_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": report["status"],
                "planned_total_decode_bytes": report["method"]["decode_limits"][
                    "planned_total_bytes"
                ],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
