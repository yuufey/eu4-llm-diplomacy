"""Bounded static review of the dynamic-source name lookup.

This batch only rechecks the name lookup body and its small hash-table helper
from the pinned EU4 1.37.4 PE.  It reuses the frozen Batch-46 dynamic-source
and B57700 reports, and never opens a game process, performs RPM, or invokes
REA.  The output is a new Batch-47 research record; frozen Batch-46 files are
read only.
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

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler  # noqa: E402
from work.local_config import game_exe  # noqa: E402
from work.research_information_branch_inputs import _decode_range  # noqa: E402


EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
IMAGE_BASE = 0x140000000
MAX_SINGLE_DECODE_BYTES = 4 * 1024
MAX_TOTAL_DECODE_BYTES = 16 * 1024

STAGE = ROOT / "work" / "runtime" / "information-trade-merchant-state-20261027-001"
OUTPUT = STAGE / "dynamic-lookup-source-001.json"

PRIOR_DYNAMIC_REPORT = (
    ROOT / "work" / "runtime" / "information-trade-source-details-20261027-001"
    / "dynamic-source-001.json"
)
PRIOR_DYNAMIC_SHA256 = "22d4b77e06ff39090bd6f93b57be6206b9860ba11f6d0211dee96a61b672caed"
PRIOR_B57700_REPORT = (
    ROOT / "work" / "runtime" / "information-trade-share-20261027-001"
    / "power-sources-source-001.json"
)
PRIOR_B57700_SHA256 = "d80bed3a2dcf1a6adf80580a632f1864871b3a9c404e32ae45ad4a787a2d3488"
PRIOR_FORMATTER_REPORT = (
    ROOT / "work" / "runtime" / "information-trade-share-20261027-001"
    / "power-sources-source-002.json"
)
PRIOR_FORMATTER_SHA256 = "952d2bfc5e9d9dfb2e0012d834b0d548a281f0ac29d5e6b5fbfa062f99d010e9"

LOCALIZATION_PROFILE = ROOT / "bridge" / "information" / "profiles" / "localization-memory-1374.json"
LOCALIZATION_PROFILE_SHA256 = "8052f51329598bb3baea137dd7694baba53ace7ecef970773a06cfafe0aef6cb"
LOCALIZATION_SOURCE_CONTRACT = (
    ROOT / "work" / "runtime" / "information-localization-20261024-001"
    / "native-localization-contract.json"
)
LOCALIZATION_SOURCE_CONTRACT_SHA256 = "3e1c46bdf5097735fa145626dc953493e5f7e3fffff67b4bdbeba6dc30b2a275"

LOCALE_PATH = "localisation/tradenodes_l_english.yml"
LOCALE_SHA256 = "4fa8b83d9266e7e956f745b490c1fde0c3231ac4557dae4a7e8af125919af6df"

# The name body is a complete pdata function.  The helper has a stable code
# guard in the localization profile but no pdata entry was returned by the
# ordinary PE range lookup, so it is recorded as a bounded helper window.
RANGES = (
    (0x14B33A0, 0x14B35BA, "dynamic_name_lookup_body"),
    (0x16FAF60, 0x16FAFE3, "localization_hash_table_helper"),
)

SELECTED = {
    "dynamic_name_lookup_body": (
        0x14B33BE, 0x14B33C5, 0x14B33CF, 0x14B33D2, 0x14B33D8,
        0x14B33DB, 0x14B33DE, 0x14B33E2, 0x14B33F0, 0x14B33F7,
        0x14B33FB, 0x14B33FE, 0x14B3403, 0x14B3406, 0x14B3409,
        0x14B3429, 0x14B343F, 0x14B344A, 0x14B3460, 0x14B347A,
        0x14B348B, 0x14B34B1, 0x14B34BC, 0x14B34C6, 0x14B34F0,
        0x14B34FB, 0x14B3501, 0x14B3509, 0x14B3515, 0x14B3520,
        0x14B3527, 0x14B3529, 0x14B352E, 0x14B3530, 0x14B3538,
        0x14B3542, 0x14B3548, 0x14B3550, 0x14B3557, 0x14B3559,
        0x14B355E, 0x14B3561, 0x14B356C, 0x14B3570, 0x14B3572,
        0x14B3575, 0x14B357E, 0x14B3582, 0x14B3590, 0x14B3597,
        0x14B3599, 0x14B359C, 0x14B359F, 0x14B35A8, 0x14B35B9,
    ),
    "localization_hash_table_helper": (
        0x16FAF60, 0x16FAF64, 0x16FAF67, 0x16FAF6B, 0x16FAF6E,
        0x16FAF72, 0x16FAF77, 0x16FAF78, 0x16FAF85, 0x16FAF89,
        0x16FAF90, 0x16FAF9C, 0x16FAFA0, 0x16FAFA2, 0x16FAFA6,
        0x16FAFB0, 0x16FAFB4, 0x16FAFB9, 0x16FAFBC, 0x16FAFC1,
        0x16FAFC4, 0x16FAFC6, 0x16FAFC9, 0x16FAFCB, 0x16FAFD2,
        0x16FAFD6, 0x16FAFDA, 0x16FAFDE, 0x16FAFDE,
    ),
}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _hex(value: int) -> str:
    return hex(value)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected object JSON: {path}")
    return value


def _assert_sha(path: Path, expected: str) -> str:
    actual = _sha256_file(path)
    if actual != expected:
        raise RuntimeError(f"unexpected SHA-256 for {path}: {actual}")
    return actual


def _decode_record(pe: PE, md: Any, begin: int, end: int, label: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    size = end - begin
    if size <= 0 or size > MAX_SINGLE_DECODE_BYTES:
        raise ValueError(f"invalid bounded range {begin:#x}..{end:#x}")
    rows = _decode_range(pe, md, begin, end)
    pdata = pe.function(begin)
    return (
        {
            "label": label,
            "rva_range": [_hex(begin), _hex(end)],
            "va_range": [_hex(IMAGE_BASE + begin), _hex(IMAGE_BASE + end)],
            "bytes": size,
            "bytes_sha256": _sha256_bytes(pe.bytes_at(begin, size)),
            "instruction_count": len(rows),
            "pdata": (
                {
                    "function_rva_range": [_hex(pdata[0]), _hex(pdata[1])],
                    "unwind_rva": _hex(pdata[2]),
                    "body_range_semantics": "pdata half-open function range",
                }
                if pdata is not None
                else {"status": "no_entry_returned_by_bounded_pe_function_lookup"}
            ),
            "instructions": rows,
        },
        rows,
    )


def _selected(rows: list[dict[str, Any]], addresses: tuple[int, ...]) -> list[dict[str, Any]]:
    by_rva = {int(row["rva"], 16): row for row in rows}
    missing = sorted({hex(address) for address in addresses if address not in by_rva})
    if missing:
        raise RuntimeError(f"decoder missed selected instruction(s): {missing}")
    return [by_rva[address] for address in addresses]


def _prior_runtime_summary(prior: dict[str, Any]) -> dict[str, Any]:
    runtime = prior.get("runtime_evidence", {})
    return {
        "path": str(PRIOR_DYNAMIC_REPORT.relative_to(ROOT)).replace("\\", "/"),
        "sha256": PRIOR_DYNAMIC_SHA256,
        "evidence_kind": runtime.get("evidence_kind"),
        "status": runtime.get("status"),
        "no_new_sampling": runtime.get("no_new_sampling"),
        "passes": runtime.get("passes"),
        "pass_results": runtime.get("pass_results"),
        "identity": runtime.get("identity"),
        "interpretation": runtime.get("interpretation"),
    }


def _localization_profile_summary(profile: dict[str, Any]) -> dict[str, Any]:
    loc = profile.get("localization", {})
    hashing = profile.get("hash", {})
    guards = profile.get("code_guards", [])
    guard_summary = []
    for guard in guards:
        if guard.get("name") in {"key_hash_lookup_body", "hash_lookup_helper"}:
            guard_summary.append({
                "name": guard.get("name"),
                "rva": guard.get("rva"),
                "end_rva_exclusive": guard.get("end_rva_exclusive"),
                "sha256": guard.get("sha256"),
            })
    return {
        "profile_id": profile.get("profile_id"),
        "profile_sha256": LOCALIZATION_PROFILE_SHA256,
        "global_cell_rva": profile.get("globals", {}).get("localization_global_cell_rva"),
        "table_layout": {
            "inner_table_begin_offset": loc.get("inner_table_begin_offset"),
            "inner_table_end_offset": loc.get("inner_table_end_offset"),
            "value_pool_offset": loc.get("outer_value_pool_offset"),
            "entry_stride": loc.get("table_entry_stride"),
            "entry_hash_offset": loc.get("table_entry_hash_offset"),
            "entry_offset_offset": loc.get("table_entry_offset_offset"),
        },
        "lookup_semantics": loc.get("lookup_semantics"),
        "hash": {
            "algorithm_profile_name": hashing.get("algorithm"),
            "seed": hashing.get("seed"),
            "multiplier": hashing.get("multiplier"),
            "width_bits": hashing.get("width_bits"),
            "helper_rva": hashing.get("helper_rva"),
            "body_rva": hashing.get("hash_body_rva"),
            "body_end_rva_exclusive": hashing.get("hash_body_end_rva_exclusive"),
        },
        "code_guards": guard_summary,
        "reuse_boundary": (
            "The native localization reader has the same bounded hash body/helper and table layout. "
            "A dynamic item may be passed to it only after its NUL bytes are validated as a printable "
            "ASCII key and the same live language/session table is proven; this report does not perform "
            "that runtime read or template substitution."
        ),
    }


def build_report() -> dict[str, Any]:
    check_memory_budget()
    exe = game_exe()
    pe = PE(exe)
    exe_sha = _sha256_file(exe)
    if exe_sha != EXPECTED_EXE_SHA256:
        raise RuntimeError(f"unexpected executable SHA-256: {exe_sha}")
    md, _capstone = make_disassembler(None)

    total = 0
    decoded_ranges: list[dict[str, Any]] = []
    rows_by_label: dict[str, list[dict[str, Any]]] = {}
    for begin, end, label in RANGES:
        total += end - begin
        if total > MAX_TOTAL_DECODE_BYTES:
            raise RuntimeError("bounded decode total exceeded")
        record, rows = _decode_record(pe, md, begin, end, label)
        decoded_ranges.append(record)
        rows_by_label[label] = rows

    dynamic = _load_json(PRIOR_DYNAMIC_REPORT)
    _assert_sha(PRIOR_DYNAMIC_REPORT, PRIOR_DYNAMIC_SHA256)
    _assert_sha(PRIOR_B57700_REPORT, PRIOR_B57700_SHA256)
    _assert_sha(PRIOR_FORMATTER_REPORT, PRIOR_FORMATTER_SHA256)
    profile = _load_json(LOCALIZATION_PROFILE)
    _assert_sha(LOCALIZATION_PROFILE, LOCALIZATION_PROFILE_SHA256)
    _assert_sha(LOCALIZATION_SOURCE_CONTRACT, LOCALIZATION_SOURCE_CONTRACT_SHA256)

    selected = {
        label: _selected(rows_by_label[label], SELECTED[label])
        for label in rows_by_label
    }
    name = dynamic["static_contract"]["name"]
    value = dynamic["static_contract"]["value"]
    chain = dynamic["static_contract"]["chain"]
    locale_hash = LOCALE_SHA256

    return {
        "schema": "information.trade_power.dynamic_lookup_static.v1",
        "report_id": "information-trade-dynamic-lookup-001",
        "batch": 47,
        "stage": "information-trade-merchant-state-20261027-001",
        "generated_on": "2026-10-27",
        "status": "partial_static_lookup_contract",
        "scope": {
            "topic_id": "T04",
            "field": "sources.dynamic_sources",
            "object": "trade_node",
            "questions": [
                "Determine whether 0x14b33a0 is the native localization lookup used by item+0x10.",
                "Bound the meaning and unit of signed DWORD item+0x34 without a non-empty runtime row.",
                "Decide whether the existing NativeLocalizationReader contract is reusable safely.",
            ],
            "mode": "ordinary bounded PE analysis plus frozen Batch-46 evidence",
            "no_game": True,
            "no_rpm": True,
            "no_writes": True,
            "no_rea": True,
            "single_decode_limit_bytes": MAX_SINGLE_DECODE_BYTES,
            "total_decode_limit_bytes": MAX_TOTAL_DECODE_BYTES,
            "decoded_bytes_total": total,
        },
        "target": {
            "game_version": "1.37.4",
            "exe_path": str(exe),
            "exe_sha256": exe_sha,
            "image_base_va": _hex(IMAGE_BASE),
            "address_rule": "RVA and VA are separate; VA=image_base_va+RVA; all ranges are half-open",
        },
        "prior_evidence": [
            {
                "path": str(PRIOR_DYNAMIC_REPORT.relative_to(ROOT)).replace("\\", "/"),
                "sha256": PRIOR_DYNAMIC_SHA256,
                "role": "Batch-46 dynamic list, B57700 caller, formatter and empty-list reuse",
                "evidence_kind": "prior_ordinary_static_report_plus_reused_runtime_summary",
            },
            {
                "path": str(PRIOR_B57700_REPORT.relative_to(ROOT)).replace("\\", "/"),
                "sha256": PRIOR_B57700_SHA256,
                "role": "B57700 linked-list caller and item layout",
                "evidence_kind": "prior_ordinary_static_report",
            },
            {
                "path": str(PRIOR_FORMATTER_REPORT.relative_to(ROOT)).replace("\\", "/"),
                "sha256": PRIOR_FORMATTER_SHA256,
                "role": "14BC950 kind1/kind2 formatter arithmetic and fixed-point boundary",
                "evidence_kind": "prior_ordinary_static_report_plus_disk_localization",
            },
        ],
        "reused_runtime_evidence": _prior_runtime_summary(dynamic),
        "decoded_code_ranges": [
            {key: record[key] for key in record if key != "instructions"}
            for record in decoded_ranges
        ],
        "selected_instructions": selected,
        "localization_evidence": {
            "disk_locale": {
                "path": LOCALE_PATH,
                "sha256": locale_hash,
                "evidence_kind": "pinned_disk_localization_file_hash_only",
                "dynamic_key_text_present": False,
            },
            "existing_profile": _localization_profile_summary(profile),
            "source_contract": {
                "path": str(LOCALIZATION_SOURCE_CONTRACT.relative_to(ROOT)).replace("\\", "/"),
                "sha256": LOCALIZATION_SOURCE_CONTRACT_SHA256,
                "evidence_kind": "frozen_native_localization_contract",
            },
        },
        "caller_contract_reused": {
            "function_rva": "0xb57700",
            "function_range": ["0xb57700", "0xb58354"],
            "head": chain["head"],
            "link": chain["link"],
            "item_name_input": {
                "object_base": name["object_base"],
                "capacity_offset": name["capacity_field"]["effective_item_offset"],
                "threshold": name["capacity_field"]["threshold"],
                "short_pointer": "item+0x10",
                "long_pointer": "QWORD [item+0x10]",
                "termination": name["termination"],
                "lookup_call_rva": name["lookup"]["call_rva"],
                "lookup_target_rva": name["lookup"]["target_rva"],
                "lookup_rcx": name["lookup"]["destination"],
                "lookup_rdx": name["lookup"]["source"],
                "lookup_r8d": name["lookup"]["r8d"],
                "lookup_r9d": name["lookup"]["r9d"],
            },
            "item_value": {
                "source": value["raw_source"],
                "offset": value["offset_from_item"],
                "width_bytes": value["width_bytes"],
                "load_rva": value["load_rva"],
                "formatter_call": value["formatter_call"],
            },
        },
        "findings": {
            "lookup_identity": {
                "classification": "native_hash_table_localization_lookup_with_original_input_fallback",
                "confidence": "strong_static_correspondence",
                "evidence": [
                    "14B33A0 initializes 0x811c9dc5, scans the NUL-terminated RDX bytes, multiplies by 0x1000193 and XORs each byte.",
                    "14B33FE calls 16FAF60 with the computed 32-bit hash and the global object loaded from RVA 0x2357B00.",
                    "16FAF60 binary-searches [map+0x20,map+0x28) at 16-byte stride, compares the stored hash, and returns [global+0x20]+entry_offset on a match.",
                    "The body/helper RVAs, global cell, entry stride and value-pool layout match localization-memory-1374; the existing profile calls this native_fnv1_32_hash_only.",
                ],
                "not_definition_lookup": "The bounded path is keyed by a 32-bit string hash and returns a string-pool pointer; no definition ID or dynamic-source object ID is read here.",
                "hash_nuance": "For printable ASCII keys this is the existing FNV-1/FNV-1a-compatible multiply-then-XOR recurrence; non-ASCII signed-byte behavior and hash-collision handling remain outside this window.",
                "fallback": "A null lookup result or failed result-buffer path copies the original NUL-terminated input into the destination string object; a successful hit is copied/constructed into the same destination before returning it.",
            },
            "item_value_semantics": {
                "raw_contract": "signed DWORD bits loaded from item+0x34 and passed by pointer to 14BC950 kind=2 with r8d=2 and r9b=1",
                "visible_arithmetic": value["numeric_presentation"]["kind2_and_kind1"],
                "visible_scale": value["numeric_presentation"]["scale"],
                "business_unit": "unknown",
                "percentage_vs_absolute": "unknown",
                "trade_power_vs_modifier": "unknown",
                "why_unresolved": "The reused two-pass runtime capture observed zero entry+0x90 heads for all 80 nodes, and no dynamic row label or non-empty value was available to bind the formatter output.",
                "publication_rule": "Do not normalize, sum, or substitute item+0x34 as country_power, total_power, trade_power points, or a percentage.",
            },
            "native_localization_reuse": {
                "answer": "conditionally_reusable",
                "same_contract": True,
                "reusable_components": [
                    "FNV hash body 0x14B33A0..0x14B35BA",
                    "hash-table helper 0x16FAF60..0x16FAFE3",
                    "global localization cell RVA 0x2357B00",
                    "16-byte hash/offset table entries and +0x20 value pool",
                ],
                "safe_adapter_boundary": [
                    "Read raw item+0x10 bytes first and require the existing printable-ASCII key contract before requesting localization.",
                    "Use NativeLocalizationReader/localization_memory only with the same guarded live session, language, codec, date and profile checks.",
                    "Keep raw name bytes and lookup-missing fallback separate from decoded literal text; do not evaluate dynamic templates.",
                ],
                "blocked_until": [
                    "a non-empty dynamic item+0x10 sample",
                    "proof that the item bytes are locale keys rather than already-display text or a dynamic template",
                    "same-session language/table identity for the dynamic source path",
                ],
            },
        },
        "not_followed_callees": [
            {"rva": "0x16faf60", "status": "decoded_bounded_helper_only", "note": "No wider table consumer was followed."},
            {"rva": "0x1a351ec", "status": "not_followed", "role": "lookup-result buffer/record helper"},
            {"rva": "0x1a4b370", "status": "not_followed", "role": "bounded result copy/transform helper"},
            {"rva": "0x14b2b40", "status": "not_followed", "role": "lookup-result composition helper"},
            {"rva": "0x95110", "status": "not_followed", "role": "destination string construction helper"},
            {"rva": "0x142357b00", "status": "data_cell_not_runtime_read", "role": "localization global cell and pool base"},
        ],
        "unknowns": [
            "The dynamic item+0x10 bytes have not been observed because all existing entry+0x90 heads were null.",
            "No non-empty dynamic value binds item+0x34 to a business unit or display label.",
            "The exact result-buffer/record format and locale table merge/language selection remain outside the bounded callee scope.",
            "The fallback means a hash miss can preserve the original key; a successful hash match alone does not prove a localized display string was obtained.",
            "No production reader or profile was changed in this batch.",
        ],
        "verification": {
            "script_path": str(Path(__file__).relative_to(ROOT)).replace("\\", "/"),
            "script_sha256": _sha256_file(Path(__file__)),
            "decoded_bytes_total": total,
            "single_decode_limit_bytes": MAX_SINGLE_DECODE_BYTES,
            "total_decode_limit_bytes": MAX_TOTAL_DECODE_BYTES,
            "ordinary_pe_only": True,
            "game_or_rpm": False,
            "rea_used": False,
            "all_shells_terminal": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    report = build_report()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    print(json.dumps({
        "decoded_bytes_total": report["verification"]["decoded_bytes_total"],
        "name_body_sha256": report["decoded_code_ranges"][0]["bytes_sha256"],
        "helper_sha256": report["decoded_code_ranges"][1]["bytes_sha256"],
        "script_sha256": report["verification"]["script_sha256"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
