"""Refine the bounded B5E190 serializer finding using its two small callees.

This report keeps the first batch's predecessor evidence intact and does not
decode B5E190 again.  It decodes only the complete ordinary-PE bodies of
17091B0 (the selector/key resolver) and 42C610 (the boolean value formatter),
then searches the fixed image for a few exact candidate token literals.  The
search is a targeted byte search, not a token-table disassembly or a runtime
observation.  No game, RPM, REA, save, or production reader is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
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
MAX_TOTAL_DECODE_BYTES = 8 * 1024

CODE_RANGES = (
    (0x17091B0, 0x1709288, "token_key_resolver"),
    (0x42C610, 0x42C673, "boolean_value_formatter"),
)

TOKEN_TABLE_BASE_RVA = 0x1FD8660
TOKEN_RECORD_STRIDE = 0x208
TARGET_LITERALS = ("has_trader", "has_capital", "type", "is_transfer")

PRIOR_REPORT = (
    ROOT
    / "work/runtime/information-trade-merchant-task-20261027-001/"
    / "merchant-serialization-source-001.json"
)
NUMERIC_WRITER_EVIDENCE = (
    ROOT
    / "work/runtime/information-battle-scalar-writers-20261025-001/"
    / "rea-scalar-writer-001/evidence.json"
)
KEY_RESOLVER_EVIDENCE = (
    ROOT
    / "work/runtime/information-domestic-pressure-20261025-001/"
    / "rea-save-key-resolver-001/evidence.json"
)
TOKEN_DOC = ROOT / "docs/native-diplomacy-inventory.md"
OLD_TRADE_REPORT = ROOT / "work/research_information_trade_merchant_state.py"

OUTPUT = (
    ROOT
    / "work/runtime/information-trade-merchant-task-20261027-001/"
    / "merchant-serialization-source-002.json"
)


def _sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha_range(pe: PE, begin: int, end: int, chunk_size: int = 0x1000) -> str:
    digest = hashlib.sha256()
    for offset in range(begin, end, chunk_size):
        digest.update(pe.bytes_at(offset, min(chunk_size, end - offset)))
    return digest.hexdigest()


def _va(rva: int) -> str:
    return hex(IMAGE_BASE + rva)


def _range_record(
    pe: PE, rows: list[dict[str, object]], begin: int, end: int, label: str
) -> dict[str, object]:
    raw = pe.bytes_at(begin, end - begin)
    boundary = pe.function(begin)
    if len(raw) != end - begin:
        raise AssertionError(f"range is not file-backed: {begin:#x}:{end:#x}")
    return {
        "label": label,
        "start_rva": hex(begin),
        "end_rva_exclusive": hex(end),
        "start_va": _va(begin),
        "end_va_exclusive": _va(end),
        "byte_length": len(raw),
        "bytes_sha256": _sha_bytes(raw),
        "pdata_function_boundary": (
            [hex(boundary[0]), hex(boundary[1])] if boundary else None
        ),
        "decoded_instruction_count": len(rows),
    }


def _by_rva(rows: list[dict[str, object]]) -> dict[int, dict[str, object]]:
    result = {int(row["rva"], 16): row for row in rows}
    if len(result) != len(rows):
        raise AssertionError("duplicate decoded instruction RVA")
    return result


def _row(by_rva: dict[int, dict[str, object]], rva: int) -> dict[str, object]:
    try:
        return by_rva[rva]
    except KeyError as exc:
        raise AssertionError(f"missing decoded instruction {rva:#x}") from exc


def _direct_call_target(row: dict[str, object], base: int) -> str | None:
    if str(row["mnemonic"]).lower() != "call":
        return None
    match = re.search(r"0x([0-9a-fA-F]+)", str(row["operands"]))
    if not match:
        return None
    absolute = int(match.group(1), 16)
    if not base <= absolute < base + 0x40000000:
        return None
    return hex(absolute - base)


def _cstring(pe: PE, rva: int, expected: str) -> dict[str, object]:
    expected_bytes = expected.encode("ascii") + b"\0"
    raw = pe.bytes_at(rva, len(expected_bytes))
    if raw != expected_bytes:
        raise AssertionError(
            f"literal mismatch at {rva:#x}: {raw!r} != {expected_bytes!r}"
        )
    return {
        "rva": hex(rva),
        "va": _va(rva),
        "string": expected,
        "bytes_hex": raw.hex(),
        "bytes_sha256": _sha_bytes(raw),
    }


def _target_literal_records(pe: PE) -> dict[str, list[dict[str, object]]]:
    """Find only named candidate literals and aligned ID/name records."""
    result: dict[str, list[dict[str, object]]] = {}
    for name in TARGET_LITERALS:
        needle = name.encode("ascii") + b"\0"
        hits: list[dict[str, object]] = []
        start = 0
        while True:
            file_offset = pe.data.find(needle, start)
            if file_offset < 0:
                break
            start = file_offset + 1
            string_rva = pe.to_rva(file_offset)
            record_rva = string_rva - 4
            if record_rva < 0:
                continue
            try:
                prefix = pe.bytes_at(record_rva, 4)
            except ValueError:
                continue
            token_id = struct.unpack("<I", prefix)[0]
            if (record_rva - TOKEN_TABLE_BASE_RVA) % TOKEN_RECORD_STRIDE != 0:
                continue
            raw = pe.bytes_at(record_rva, 4 + len(needle))
            hits.append(
                {
                    "record_rva": hex(record_rva),
                    "record_va": _va(record_rva),
                    "record_index": (record_rva - TOKEN_TABLE_BASE_RVA)
                    // TOKEN_RECORD_STRIDE,
                    "token_id": hex(token_id),
                    "name": name,
                    "raw_hex": raw.hex(),
                    "raw_bytes_sha256": _sha_bytes(raw),
                    "record_layout": "DWORD token id followed by NUL-terminated ASCII name; aligned 0x208-byte compiled record",
                }
            )
        result[name] = hits
    return result


def _prior_field_projection() -> dict[str, object]:
    if not PRIOR_REPORT.exists():
        raise FileNotFoundError(PRIOR_REPORT)
    prior = json.loads(PRIOR_REPORT.read_text(encoding="utf-8"))
    projected = []
    for row in prior["predecessor_field_accesses"]:
        projected.append(
            {
                "offset": row["offset"],
                "load": row["load"],
                "selector_instruction": row["selector_instruction"],
                "direct_helper_call": row["direct_helper_call"],
                "following_value_formatter_call": row.get(
                    "following_value_formatter_call"
                ),
            }
        )
    return {
        "path": PRIOR_REPORT.relative_to(ROOT).as_posix(),
        "sha256": _sha_file(PRIOR_REPORT),
        "evidence_kind": "prior_ordinary_static_report_not_redecoded",
        "predecessor_fields": projected,
    }


def _archived_source(path: Path, evidence_id: str, role: str) -> dict[str, object]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": _sha_file(path),
        "evidence_id": evidence_id,
        "evidence_kind": "archived_REA_report_used_as_prior_corroboration",
        "role": role,
        "new_REA_or_runtime": False,
    }


def build_report() -> dict[str, object]:
    pe = PE(game_exe())
    binary_sha256 = _sha_bytes(pe.data)
    if binary_sha256 != EXPECTED_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {binary_sha256}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    expected_boundaries = {
        0x17091B0: (0x17091B0, 0x1709288),
        0x42C610: (0x42C610, 0x42C673),
    }
    for start, expected in expected_boundaries.items():
        actual = pe.function(start)
        if actual is None or tuple(actual[:2]) != expected:
            raise AssertionError(
                f"unexpected pdata boundary at {start:#x}: {actual!r} != {expected!r}"
            )

    md, capstone_module = make_disassembler(ROOT / "work/deps/capstone-5.0.7")
    decoded: dict[str, list[dict[str, object]]] = {}
    ranges: list[dict[str, object]] = []
    total_decoded_bytes = 0
    for begin, end, label in CODE_RANGES:
        if end <= begin or end - begin > MAX_RANGE_BYTES:
            raise AssertionError(f"range limit failure: {begin:#x}:{end:#x}")
        if not pe.executable(begin) or not pe.executable(end - 1):
            raise AssertionError(f"range is not executable: {begin:#x}:{end:#x}")
        total_decoded_bytes += end - begin
        if total_decoded_bytes > MAX_TOTAL_DECODE_BYTES:
            raise AssertionError("total decode limit failure")
        rows = _decode_range(pe, md, begin, end)
        decoded[label] = rows
        ranges.append(_range_record(pe, rows, begin, end, label))

    resolver = _by_rva(decoded["token_key_resolver"])
    formatter = _by_rva(decoded["boolean_value_formatter"])
    resolver_calls = [
        {"instruction": row, "target_rva": _direct_call_target(row, pe.base)}
        for row in decoded["token_key_resolver"]
        if _direct_call_target(row, pe.base) is not None
    ]
    formatter_calls = [
        {"instruction": row, "target_rva": _direct_call_target(row, pe.base)}
        for row in decoded["boolean_value_formatter"]
        if _direct_call_target(row, pe.base) is not None
    ]

    yes_literal = _cstring(pe, 0x1CA9BBC, "yes")
    no_literal = _cstring(pe, 0x1CB83A8, "no")
    token_records = _target_literal_records(pe)
    prior = _prior_field_projection()

    report = {
        "schema": "information.trade_merchant_task.merchant_serialization_source.v2",
        "stage": "information-trade-merchant-task-20261027-001",
        "evidence_kind": "ordinary_static_file_analysis_with_archived_corroboration",
        "target": {
            "game_version": "1.37.4",
            "exe_sha256": binary_sha256,
            "image_base_va": hex(pe.base),
            "address_kind": "RVA; VA=image_base_va+RVA; ranges end exclusive",
        },
        "scope": {
            "question": (
                "Whether B5E190 is an output serializer and whether its already "
                "observed selectors map to named token keys"
            ),
            "excluded": [
                "re-decoding B5E190",
                "full B5EAA0 body",
                "full token-table disassembly or token sweep",
                "indirect helper callees beyond the two selected bodies",
                "game/RPM/save/reload/runtime observation",
                "REA invocation and production changes",
            ],
        },
        "analysis_limits": {
            "decoder": "capstone if available, otherwise bounded objdump",
            "capstone_available": capstone_module is not None,
            "decoded_bytes_total": total_decoded_bytes,
            "max_single_window_bytes": MAX_RANGE_BYTES,
            "max_total_decode_bytes": MAX_TOTAL_DECODE_BYTES,
            "b5e190_redecoded": False,
            "literal_search": "only exact NUL-terminated candidate strings; no code disassembly or token-table sweep",
        },
        "decoded_ranges": ranges,
        "callee_evidence": {
            "token_key_resolver_17091b0": {
                "pdata_range": ["0x17091b0", "0x1709288"],
                "selected_instructions": decoded["token_key_resolver"],
                "selector_abi": {
                    "selector_source": "EDX copied to EBX at 0x17091bd",
                    "context_source": "RCX copied to RDI at 0x17091bf",
                    "vector_global_va": "0x14242b868",
                    "vector_global_rva": hex(0x242B868),
                    "entry_stride_bytes": 0x20,
                    "entry_inline_or_heap": "QWORD entry+0x18 is compared with 0x10; if long, QWORD entry+0 is used as string pointer",
                },
                "output_path": {
                    "resolved_string_call": "0x1709217 -> 0x1708e10 with context RDI and selected vector entry RDX",
                    "final_output_helper_call": "0x1709272 -> 0x17087a0 with context RDI and a local value record",
                    "call_targets": resolver_calls,
                    "interpretation": "The selector is resolved through the runtime key-name vector and then passed into the output path; this is serializer-compatible evidence, not a field-semantic label by itself.",
                },
                "unfollowed": [
                    "0x1708490 context/init helper",
                    "0xcf3d0 long-context branch",
                    "0x1708e10 string assignment helper",
                    "0x1a356b0 local string copy helper",
                    "0x17087a0 output helper",
                ],
            },
            "boolean_value_formatter_42c610": {
                "pdata_range": ["0x42c610", "0x42c673"],
                "selected_instructions": decoded["boolean_value_formatter"],
                "input": "DL is tested at 0x42c617; original output/context RCX is saved in R8 at 0x42c621",
                "selected_literals": {
                    "true_branch": yes_literal,
                    "false_branch": no_literal,
                },
                "selection": "CMOVNE at 0x42c63a chooses yes when DL is nonzero and no otherwise",
                "output_call": {
                    "instruction_rva": "0x42c666",
                    "target_rva": "0x17087a0",
                    "operands": "original context in RCX, copied yes/no string in RDX",
                },
                "call_targets": formatter_calls,
                "interpretation": "This is a boolean value-to-text/output helper; it does not itself embed a key name.",
            },
        },
        "prior_b5e190_bindings": prior,
        "archived_corroboration": [
            _archived_source(
                NUMERIC_WRITER_EVIDENCE,
                "ev_aed48f3663f7c2a170398a4c4685fb3a7d5fab7a0d017d0fbda62c4f3eaae28",
                "archived 0x1707b30 body: calls 0x17091b0 for the selector, formats R8D through %d, then calls 0x17087a0 and 0x17083d0",
            ),
            _archived_source(
                KEY_RESOLVER_EVIDENCE,
                "ev_4b4d559db119a670790af9779328655e84fd8d74dbac6ee56775ee8d8db2de09",
                "archived 0x17091b0 REA pseudocode corroborating the same global-vector selector lookup",
            ),
            {
                "path": TOKEN_DOC.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(TOKEN_DOC),
                "evidence_kind": "prior_ordinary_static_document",
                "role": "independently binds global token 0xe1 to the action-field name type; does not by itself assign trade-domain semantics",
            },
            {
                "path": OLD_TRADE_REPORT.relative_to(ROOT).as_posix(),
                "sha256": _sha_file(OLD_TRADE_REPORT),
                "evidence_kind": "prior_ordinary_static_report_source",
                "role": "preserves the earlier trade flag/parser caveat; not rewritten here",
            },
        ],
        "targeted_token_literal_records": {
            "table_base_rva": hex(TOKEN_TABLE_BASE_RVA),
            "record_stride_bytes": TOKEN_RECORD_STRIDE,
            "records": token_records,
            "mapping": {
                "0x2c09": "has_trader",
                "0x2c94": "has_capital",
                "0x00e1": "type",
                "is_transfer": "no exact NUL-terminated compiled literal found",
            },
            "semantic_limit": "These are global token names; the name does not prove the trade entry flag's business meaning beyond the serializer key binding.",
        },
        "field_serializer_bindings": {
            "0xac": {
                "selector": "0x00e1",
                "key_name": "type",
                "value_path": "B5E190 load -> 0x1707b30 -> archived 0x17091b0 key resolver + %d formatter -> 0x17087a0",
                "status": "key_and_numeric_output_path_closed",
            },
            "0xae": {
                "selector": "0x2c09",
                "key_name": "has_trader",
                "value_path": "B5E190 load -> 0x17091b0 key resolver -> 0x42c610 yes/no formatter -> 0x17087a0",
                "status": "key_and_boolean_output_path_closed",
            },
            "0xad": {
                "selector": "0x2c94",
                "key_name": "has_capital",
                "value_path": "B5E190 load -> 0x17091b0 key resolver -> 0x42c610 yes/no formatter -> 0x17087a0",
                "status": "key_and_boolean_output_path_closed",
            },
            "0xaf": {
                "selector": "0x2f23",
                "key_name": None,
                "value_path": "B5E190 load -> 0x17091b0 key resolver -> 0x42c610 yes/no formatter -> 0x17087a0",
                "status": "output_path_closed_name_unresolved",
            },
        },
        "finding": {
            "serializer_verdict": "reverse_serializer_output_path_supported",
            "confidence": "bounded_static_with_prior_archived_callee_corroboration",
            "reason": (
                "The predecessor's entry reads are inputs to a key resolver and an "
                "external output helper. A serializer need not write back to its "
                "input entry or call the parser. The first report's contrary "
                "exclusion reason is withdrawn."
            ),
            "closed_scope": "B5E190 emits global keys type/has_trader/has_capital for +AC/+AE/+AD and boolean text for the latter two.",
            "not_closed": "The trade-domain business meaning of the fields, +AF's key, runtime vector freshness, and the complete surrounding writer contract.",
        },
        "prior_reason_correction": {
            "prior_report_path": PRIOR_REPORT.relative_to(ROOT).as_posix(),
            "prior_report_sha256": prior["sha256"],
            "withdrawn": [
                "No write to the input entry offsets does not exclude an input-to-output serializer.",
                "No direct B5EAA0 call does not exclude a serializer; parser and serializer are separate functions.",
            ],
            "retained": "The exact B5E190 pdata boundary and its byte-read observations remain valid and are reused without re-decoding.",
        },
        "unresolved_conditions": [
            "No runtime observation was made; the resolved key vector can be initialized or extended at runtime.",
            "The literal key names do not by themselves prove collect/transfer/merchant-task business semantics.",
            "Selector 0x2f23 was not assigned a name in this targeted candidate search.",
            "Indirect output/helper callees were not followed beyond the two selected bodies.",
        ],
        "producer_script": {
            "path": Path(__file__).resolve().relative_to(ROOT).as_posix(),
            "sha256": _sha_bytes(Path(__file__).read_bytes()),
        },
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing report: {output}")
    report = build_report()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": output.relative_to(ROOT).as_posix(),
                "report_sha256": _sha_bytes(output.read_bytes()),
                "decoded_bytes_total": report["analysis_limits"]["decoded_bytes_total"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
