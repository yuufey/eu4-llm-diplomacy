"""Bounded ordinary-PE evidence for current alliance/royal-marriage membership.

This report is deliberately narrower than the prior relation-source review.  It
verifies the two selector call instructions and decodes only their direct leaf
predicates.  It never opens a game process, invokes native code, uses REA/RPM,
or treats the remaining bytes of a 16-byte vector element as a date field.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

# This script lives one directory below ``work`` (work/research-next).
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from work.discover_diplomacy import PE
from work.local_config import game_exe


EXPECTED_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
MAX_WINDOW_BYTES = 0x4000
MAX_TOTAL_BYTES = 0x4000

# These are the only four byte windows read from the image.  The selector
# function boundary is obtained from .pdata separately and is not decoded in
# full; the two callsite windows are enough to establish the direct targets.
WINDOWS = (
    (0x35A9E3, 0x35A9F6, "alliance_selector_case"),
    (0x35AC11, 0x35AC24, "royal_marriage_selector_case"),
    (0xA68BC0, 0xA68BFC, "alliance_membership_leaf"),
    (0xA68A10, 0xA68A46, "royal_marriage_membership_leaf"),
)

EXPECTED_CALLS = {
    "alliance": (0x35A9E6, 0xA68BC0, bytes.fromhex("e8d5e17000")),
    "royal_marriage": (0x35AC14, 0xA68A10, bytes.fromhex("e8f7dd7000")),
}

# The leaf bodies are short enough to assert exactly.  The first dword of each
# vector element is the only element field read by these bodies.
LEAF_BYTES = {
    "alliance": bytes.fromhex(
        "488b01488b511048c1ea20488b88800000004c63808c000000"
        "49c1e0044c03c10fbfc2493bc87410390174094883c110493bc8"
        "75f3493bc80f95c0c3"
    ),
    "royal_marriage": bytes.fromhex(
        "488b01488b511048c1ea20488b48684c63407449c1e0044c03c1"
        "0fbfc2493bc87410390174094883c110493bc875f3493bc80f95c0c3"
    ),
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _range_record(pe: PE, begin: int, end: int, label: str) -> dict:
    if not (0 <= begin < end) or end - begin > MAX_WINDOW_BYTES:
        raise AssertionError(f"invalid bounded window {begin:#x}:{end:#x}")
    if not pe.executable(begin) or not pe.executable(end - 1):
        raise AssertionError(f"window is not executable {begin:#x}:{end:#x}")
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise AssertionError("short PE range")
    return {
        "label": label,
        "rva_start": hex(begin),
        "rva_end_exclusive": hex(end),
        "va_start": hex(pe.base + begin),
        "va_end_exclusive": hex(pe.base + end),
        "bytes": len(raw),
        "sha256": _sha256_bytes(raw),
        "raw_hex": raw.hex(),
    }


def _call_target(pe: PE, call_rva: int, expected_target: int, expected_bytes: bytes) -> dict:
    raw = pe.bytes_at(call_rva, len(expected_bytes))
    if raw != expected_bytes or raw[:1] != b"\xe8":
        raise AssertionError(f"call bytes changed at {call_rva:#x}: {raw.hex()}")
    displacement = struct.unpack_from("<i", raw, 1)[0]
    target = call_rva + len(raw) + displacement
    if target != expected_target:
        raise AssertionError(f"unexpected call target {target:#x} != {expected_target:#x}")
    return {
        "call_rva": hex(call_rva),
        "call_va": hex(pe.base + call_rva),
        "bytes": raw.hex(),
        "rel32_signed": displacement,
        "target_rva": hex(target),
        "target_va": hex(pe.base + target),
    }


def _pdata(pe: PE, rva: int) -> dict | None:
    entry = pe.function(rva)
    if entry is None:
        return None
    start, end, unwind = entry
    return {
        "rva_start": hex(start),
        "rva_end_exclusive": hex(end),
        "va_start": hex(pe.base + start),
        "va_end_exclusive": hex(pe.base + end),
        "bytes": end - start,
        "unwind_rva": hex(unwind),
        "unwind_va": hex(pe.base + unwind),
    }


def _build_leaf_evidence(pe: PE, family: str, rva: int) -> dict:
    raw = pe.bytes_at(rva, len(LEAF_BYTES[family]))
    if raw != LEAF_BYTES[family]:
        raise AssertionError(f"leaf bytes changed for {family}: {raw.hex()}")
    if raw[-1:] != b"\xc3":
        raise AssertionError("leaf window does not end in ret")
    if family == "alliance":
        vector_base, count_offset = 0x80, 0x8C
    else:
        vector_base, count_offset = 0x68, 0x74
    return {
        "family": family,
        "entry_rva": hex(rva),
        "entry_va": hex(pe.base + rva),
        "pdata": _pdata(pe, rva),
        "range": {
            "rva_start": hex(rva),
            "rva_end_exclusive": hex(rva + len(raw)),
            "va_start": hex(pe.base + rva),
            "va_end_exclusive": hex(pe.base + rva + len(raw)),
            "bytes": len(raw),
            "sha256": _sha256_bytes(raw),
            "raw_hex": raw.hex(),
        },
        "decoded": [
            {"offset": "0x0", "asm": "mov rax, [rcx]"},
            {"offset": "0x3", "asm": "mov rdx, [rcx+0x10]; shr rdx, 0x20"},
            {"offset": "0xb", "asm": f"mov rcx, [rax+{vector_base:#x}]"},
            {"offset": "0x12", "asm": f"movsxd r8, dword ptr [rax+{count_offset:#x}]"},
            {"offset": "0x1c", "asm": "lea r8, [rcx+r8*0x10]"},
            {"offset": "0x20", "asm": "movsx eax, dx"},
            {"offset": "0x23", "asm": "loop: cmp rcx, r8; je done"},
            {"offset": "0x29", "asm": "cmp dword ptr [rcx], eax; je found"},
            {"offset": "0x2e", "asm": "add rcx, 0x10; loop"},
            {"offset": "0x35", "asm": "setne al; ret"},
        ],
        "reads": {
            "input_relation_row_owner": "[relation_row+0x0]",
            "input_recipient_fullref": "[relation_row+0x10]",
            "recipient_slot_expression": "sign_extend_i16((relation_row[0x10] >> 32) & 0xffff)",
            "vector_begin": f"owner+{vector_base:#x}",
            "vector_count": f"owner+{count_offset:#x} (signed i32)",
            "element_stride": 16,
            "element_compared_field": "element+0, unsigned dword comparison against the sign-extended slot",
            "element_unread_bytes": "element+0x4..0xf",
        },
        "return_semantics": "true iff a vector element has a matching first dword; false iff the bounded scan reaches end without a match",
    }


def build_report() -> dict:
    pe = PE(game_exe())
    digest = _sha256_bytes(pe.data)
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unsupported game binary SHA-256: {digest}")
    if pe.base != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.base:#x}")

    total = sum(end - begin for begin, end, _ in WINDOWS)
    if total > MAX_TOTAL_BYTES:
        raise AssertionError("bounded decode budget exceeded")
    windows = [_range_record(pe, begin, end, label) for begin, end, label in WINDOWS]
    calls = {
        family: _call_target(pe, call_rva, target, raw)
        for family, (call_rva, target, raw) in EXPECTED_CALLS.items()
    }
    callsite_pdata = {
        family: _pdata(pe, call["call_rva"] and int(call["call_rva"], 16))
        for family, call in calls.items()
    }
    leaves = {
        "alliance": _build_leaf_evidence(pe, "alliance", 0xA68BC0),
        "royal_marriage": _build_leaf_evidence(pe, "royal_marriage", 0xA68A10),
    }
    prior = ROOT / "work/runtime/information-relation-current-20261027-001/relation-current-source-001.json"
    source_query = ROOT / "work/native/alliance-query.inc"
    source_execution = ROOT / "work/native/alliance-execution.inc"
    script_sha = _sha256_file(Path(__file__))
    return {
        "schema": "information_relation_current_native_source.v1",
        "stage": "information-relation-current-20261027-001",
        "report_id": "relation-current-source-002",
        "review_scope": {
            "kind": "bounded_ordinary_pe_static_decode",
            "new_game_query": False,
            "rea_or_rpm": False,
            "native_call": False,
            "production_changes": False,
            "decoded_window_count": len(WINDOWS),
            "decoded_total_bytes": total,
            "limits": {"max_functions": 8, "max_total_decode_bytes": MAX_TOTAL_BYTES},
        },
        "target_binary": {
            "path": str(pe.path),
            "version": "1.37.4",
            "sha256": digest,
            "image_base": hex(pe.base),
            "address_note": "RVA values are image-relative; VA is base+RVA and is recorded separately.",
        },
        "selector_calls": {
            family: {
                **call,
                "selector_case_rva": hex(0x35A9E3 if family == "alliance" else 0x35AC11),
                "selector_case_va": hex(pe.base + (0x35A9E3 if family == "alliance" else 0x35AC11)),
                "pdata": callsite_pdata[family],
                "case_context": "mov rcx,rsi; call leaf; movzx edi,al; xor dil,bpl; common return",
            }
            for family, call in calls.items()
        },
        "owner_vector_layout": {
            "relation_row_owner": "relation_row+0x0 is the owner object passed to the leaf",
            "alliance": {"begin_offset": "0x80", "count_offset": "0x8c"},
            "royal_marriage": {"begin_offset": "0x68", "count_offset": "0x74"},
            "element_stride": 16,
            "count_boundary": "bounded by the existing selector helper at 0 <= signed count <= 4096; nonzero count requires nonzero begin",
            "matching": "element[0] (DWORD) == sign_extend_i16((relation_row[0x10] >> 32) & 0xffff)",
            "fullref_rule": "the relation row +0x10 fullref is the recipient endpoint; only its upper-32 low-16 slot is consumed by these leaves",
            "unread_element_bytes": "+0x4..+0xf are not read by either direct leaf",
        },
        "native_boolean": {
            "leaf": "both direct leaves return AL=1 when a matching recipient slot is present, else AL=0",
            "selector_case": "the case XORs that AL with bpl (offer byte) before the common bool return",
            "offer_false_current_read": "execution_read_after uses offer=false, so the resulting predicate is true when the recipient is present and false when absent",
            "scope": "this describes the selector predicate; it does not by itself define a date or action lifecycle",
        },
        "date_and_serializer": {
            "start_date": {"status": "unknown", "reason": "the two direct leaves read no date field"},
            "expiry_date": {"status": "unknown", "reason": "the two direct leaves read no date field"},
            "serializer": {"status": "unresolved", "reason": "no serializer is reached by the bounded selector callsites/leaves; do not infer one from element width"},
        },
        "decoded_windows": windows,
        "leaf_evidence": leaves,
        "source_refs": [
            {"path": "work/native/alliance-query.inc", "sha256": _sha256_file(source_query), "line_range": [44, 89], "role": "prior selector guard, relation row, vector offsets, and bounded count contract"},
            {"path": "work/native/alliance-execution.inc", "sha256": _sha256_file(source_execution), "line_range": [1279, 1333], "role": "offer=false current before/after producer path"},
            {"path": "work/research-next/relation_current_native.py", "sha256": script_sha, "role": "this reproducible bounded ordinary-PE checker"},
            {"path": "work/runtime/information-relation-current-20261027-001/relation-current-source-001.json", "sha256": _sha256_file(prior), "role": "retained prior relation source review; unchanged"},
        ],
        "conclusion": {
            "status": "membership_leaf_closed",
            "alliance": "RVA 0xA68BC0 is the direct owner-vector membership predicate",
            "royal_marriage": "RVA 0xA68A10 is the direct owner-vector membership predicate",
            "public_relation_dates": "not closed; keep start/expiry unknown",
            "public_relation_serializer": "not closed by this bounded source task",
        },
    }


def main() -> None:
    report_path = ROOT / "work/runtime/information-relation-current-20261027-001/relation-current-source-002.json"
    if report_path.exists():
        raise FileExistsError(report_path)
    report = build_report()
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"path": str(report_path), "sha256": _sha256_file(report_path), "bytes": report_path.stat().st_size}, ensure_ascii=False))


if __name__ == "__main__":
    main()
