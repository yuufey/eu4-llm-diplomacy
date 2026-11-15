"""Produce the bounded merchant-presence/status evidence for batch 48.

This is ordinary static PE analysis only.  It reuses the bounded trade-state
entry contract and decodes three explicit windows: the B58C70 predecessor
predicate, the B5B100 ``STEER_NO_TRADER`` status path, and the B5BE80
follow-up status/container path.  It never opens the game, calls RPM/REA, or
writes a production profile.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, make_disassembler
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range


EXPECTED_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_RANGE_BYTES = 4 * 1024
MAX_TOTAL_DECODE_BYTES = 16 * 1024

CODE_RANGES = (
    (0xB58C70, 0xB58CD0, "predecessor_b58c70"),
    (0xB5B100, 0xB5B318, "steer_status_b5b100"),
    (0xB5BE80, 0xB5C2EC, "steer_status_b5be80"),
)

STRING_RANGES = {
    0x1CE8ED0: "STEER_NO_POWER",
    0x1CE8EE0: "STEER_LATER",
    0x1CE8F30: "STEER_HOME",
    0x1CE8F40: "STEER_NO_TRADER",
}

SELECTED_ADDRESSES = {
    "predecessor_b58c70": (
        0xB58C70, 0xB58C91, 0xB58C97, 0xB58C9E, 0xB58CA0,
        0xB58CA8, 0xB58CB4, 0xB58CB8, 0xB58CCD,
    ),
    "steer_status_b5b100": (
        0xB5B119, 0xB5B11E, 0xB5B120, 0xB5B1E7, 0xB5B205,
        0xB5B20A, 0xB5B212, 0xB5B219, 0xB5B224, 0xB5B229,
        0xB5B244, 0xB5B247, 0xB5B271, 0xB5B2F9,
    ),
    "steer_status_b5be80": (
        0xB5BEA7, 0xB5BEAC, 0xB5BF7F, 0xB5BF99, 0xB5BFAE,
        0xB5C06A, 0xB5C091, 0xB5C0A9, 0xB5C0AC, 0xB5C0D7,
        0xB5C0DE, 0xB5C1AF, 0xB5C1B6, 0xB5C1C1, 0xB5C1C8,
        0xB5C1CF, 0xB5C1D4, 0xB5C1D8, 0xB5C1E2, 0xB5C1E8,
        0xB5C1FE, 0xB5C2BA,
    ),
}

OLD_SOURCE = ROOT / "work/runtime/information-trade-state-20261027-001/merchant-task-source-001.json"


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _va(rva: int) -> str:
    return hex(IMAGE_BASE + rva)


def _cstring(pe: PE, rva: int, expected: str) -> dict[str, str]:
    raw = bytearray()
    for offset in range(512):
        byte = pe.bytes_at(rva + offset, 1)
        if not byte:
            break
        raw.extend(byte)
        if byte == b"\0":
            break
    expected_bytes = expected.encode("ascii") + b"\0"
    if bytes(raw) != expected_bytes:
        raise AssertionError(
            f"literal mismatch at {rva:#x}: {bytes(raw)!r} != {expected_bytes!r}"
        )
    return {
        "rva": hex(rva),
        "va": _va(rva),
        "string": expected,
        "locale": "native ASCII UI literal; language table not followed",
        "bytes_hex": bytes(raw).hex(),
        "bytes_sha256": _sha_bytes(bytes(raw)),
    }


def _range_record(pe: PE, rows, begin: int, end: int, label: str) -> dict[str, object]:
    raw = pe.bytes_at(begin, end - begin)
    function = pe.function(begin)
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": _va(begin),
        "end_va_exclusive": _va(end),
        "byte_length": len(raw),
        "bytes_sha256": _sha_bytes(raw),
        "pdata_function_boundary":
            [hex(function[0]), hex(function[1])] if function else None,
        "decoded_instruction_count": len(rows),
    }


def _selected(rows, addresses):
    by_rva = {int(row["rva"], 16): row for row in rows}
    missing = [hex(address) for address in addresses if address not in by_rva]
    if missing:
        raise AssertionError(f"selected instruction missing: {missing}")
    return [by_rva[address] for address in addresses]


def build_report() -> dict[str, object]:
    pe = PE(game_exe())
    binary_sha256 = _sha_bytes(pe.data)
    if binary_sha256 != EXPECTED_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {binary_sha256}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    md, capstone = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded: dict[str, list[dict[str, object]]] = {}
    ranges: list[dict[str, object]] = []
    total = 0
    for begin, end, label in CODE_RANGES:
        if end <= begin or end - begin > MAX_RANGE_BYTES:
            raise AssertionError(f"range limit failure: {begin:#x}:{end:#x}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"range is not executable: {begin:#x}:{end:#x}")
        total += end - begin
        if total > MAX_TOTAL_DECODE_BYTES:
            raise AssertionError("total decode limit failure")
        rows = _decode_range(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    strings = [_cstring(pe, rva, value) for rva, value in STRING_RANGES.items()]
    old_source = {
        "path": OLD_SOURCE.relative_to(ROOT).as_posix(),
        "sha256": _sha_file(OLD_SOURCE) if OLD_SOURCE.exists() else None,
        "evidence_kind": "reused_bounded_ordinary_static_report",
        "used_for": "entry layout, prior B58C70/B5B100/B5BE80 bounds and raw flag context",
        "new_runtime_or_REA": False,
    }

    report = {
        "schema": "information.trade_merchant_task.merchant_presence_source.v1",
        "stage": "information-trade-merchant-task-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_not_REA_evidence",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; ranges end exclusive",
        },
        "scope": {
            "question": (
                "Direct bounded evidence for the STEER_NO_TRADER label, its B58C70 "
                "predecessor, B5BE80 follow-up, and a country-container candidate"
            ),
            "excluded": [
                "B59550 four callers and merchant-task writers",
                "runtime/RPM/game/UI execution",
                "REA/Ghidra whole-image analysis",
            ],
            "no_game_or_production_access": True,
        },
        "analysis": {
            "decoder": (
                "capstone " + capstone.__version__
                if capstone is not None else "bounded objdump -w -Mintel"
            ),
            "decoded_bytes": total,
            "limits": {
                "single_code_range_bytes": MAX_RANGE_BYTES,
                "total_code_decode_bytes": MAX_TOTAL_DECODE_BYTES,
                "runtime_process_opened": False,
                "rpm_used": False,
                "rea_used": False,
                "production_written": False,
            },
        },
        "reused_sources": [old_source],
        "ranges": ranges,
        "selected_instructions": {
            label: _selected(decoded[label], addresses)
            for label, addresses in SELECTED_ADDRESSES.items()
        },
        "string_literals": strings,
        "bounded_label_references": {
            "STEER_NO_TRADER": {
                "rva": hex(0x1CE8F40),
                "references_in_decoded_windows": [hex(0xB5B271)],
                "b5be80_reference": False,
            },
            "STEER_HOME": {
                "rva": hex(0x1CE8F30),
                "references_in_decoded_windows": [hex(0xB5B153), hex(0xB5BEC3)],
            },
            "STEER_NO_POWER": {
                "rva": hex(0x1CE8ED0),
                "references_in_decoded_windows": [hex(0xB5BFAE), hex(0xB5C0F3)],
            },
            "STEER_LATER": {
                "rva": hex(0x1CE8EE0),
                "references_in_decoded_windows": [hex(0xB5C1FE)],
            },
        },
        "findings": {
            "predecessor_b58c70": {
                "status": "bounded_predicate_closed",
                "rva": "0xb58c70",
                "va": _va(0xB58C70),
                "semantics": (
                    "Direct caller-visible bool predicate. RCX is dereferenced at +0x18; "
                    "the signed low 16 bits of RDX>>32 select a 0xc0-stride entry."
                ),
                "condition": (
                    "For a non-special slot, the observed branch order is "
                    "AE==0 ? AD!=0 : AC==0. The special-slot path returns true "
                    "when its computed entry pointer is non-null before flag tests."
                ),
                "limitations": [
                    "This closes a boolean predicate, not a three-valued merchant task enum.",
                    "The C++ field names and the semantic ownership of AC/AD/AE remain unknown.",
                ],
            },
            "steer_no_trader": {
                "status": "label_path_closed_bounded",
                "function_rva": "0xb5b100",
                "function_va": _va(0xB5B100),
                "label": "STEER_NO_TRADER",
                "label_rva": "0x1ce8f40",
                "direct_reference_rva": "0xb5b271",
                "path": [
                    "B5B100 saves original RCX in R10, RDX in R9, and R8 in RBX.",
                    "B5B119 calls B58C70 with the original RCX/RDX pair.",
                    "If AL is false, B5B1E7 derives the signed selector index and computes [R10+0x18]+index*0xc0.",
                    "A null computed entry reaches B5B244; for a non-special slot, B5B212 tests BYTE [entry+0xAE] and zero also reaches B5B244.",
                    "When the output object RBX is non-null, B5B271 supplies STEER_NO_TRADER to the string builder; otherwise the function returns false without formatting.",
                ],
                "direct_entry_ae_connection": True,
                "interpretation": (
                    "The label is a native steering/status UI branch whose bounded path is "
                    "directly gated by the computed entry and, for ordinary slots, entry+0xAE. "
                    "It is not proof that AE alone means no merchant, and it is not a public "
                    "merchant_task enum value."
                ),
                "formatter_callee": {
                    "rva": "0x1414b33a0",
                    "followed": False,
                    "reason": "outside this narrow label/guard task",
                },
            },
            "steer_status_b5be80": {
                "status": "bounded_followup_partial",
                "function_rva": "0xb5be80",
                "function_va": _va(0xB5BE80),
                "predecessor_call": "B5BEA7 -> B58C70",
                "labels_reached_in_window": [
                    "STEER_HOME",
                    "STEER_NO_POWER",
                    "STEER_LATER",
                ],
                "no_trader_reference_in_window": True,
                "entry_ae_connection": (
                    "After the signed32 power calculation is non-positive, B5C0D7 tests "
                    "BYTE [entry+0xAE]; a nonzero byte enters the candidate container path, "
                    "while zero reaches STEER_NO_POWER."
                ),
                "return_semantics": (
                    "The bounded true return at B5C1E8 is reached only after a nonzero byte "
                    "in the candidate global table; label-formatting paths return false. "
                    "This is not independently named as merchant presence."
                ),
            },
            "country_container_candidate": {
                "status": "candidate_unlabelled",
                "first_rva": "0xb5c1af",
                "first_va": _va(0xB5C1AF),
                "formula": (
                    "global = QWORD [0x14233FE58]; index = signext16(R8) * "
                    "DWORD [global+0x21BC] + DWORD [original_RCX+0x120]"
                ),
                "table": "QWORD [global+0x2228]",
                "count": "DWORD [global+0x2238]",
                "read": "BYTE [table+index] != 0",
                "guards": [
                    "table pointer non-null",
                    "index >= 0",
                    "index < count",
                ],
                "result": "returns AL=1 at B5C1E8 when the byte is nonzero",
                "next_entry": (
                    "Treat this as a country-scoped global presence-table candidate. "
                    "A separate producer/serializer or runtime observation is required "
                    "before naming it merchant presence or exposing merchant_task."
                ),
            },
            "merchant_task": {
                "status": "unknown",
                "decision": "not_exposed",
                "reason": (
                    "STEER_NO_TRADER is a localized status label on one guarded UI path; "
                    "the bounded windows contain no collect/transfer/none enum or direct "
                    "country merchant container contract."
                ),
            },
        },
        "unresolved_conditions": [
            "The exact C++ identity and semantic type of the global table at [0x14233FE58]+0x2228 are unknown.",
            "The relationship between original RCX+0x120, selector R8/RDX, and a country merchant object is not proven.",
            "The formatter callee 0x1414B33A0 and later task writers/callers were intentionally not followed.",
            "Static label reachability does not establish runtime merchant presence or a complete T05 merchant_task value.",
        ],
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "work/runtime/information-trade-merchant-task-20261027-001/merchant-presence-source-001.json",
    )
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output = output.resolve()
    if output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    report = build_report()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({
        "output": output.relative_to(ROOT).as_posix(),
        "sha256": _sha_file(output),
        "bytes": output.stat().st_size,
        "decoded_bytes": report["analysis"]["decoded_bytes"],
        "range_count": len(report["ranges"]),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
