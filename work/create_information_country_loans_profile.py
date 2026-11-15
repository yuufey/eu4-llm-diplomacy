"""Create the bounded current-country loan-record profile.

The profile is derived from the already pinned ordinary-PE source report and
small RVA windows.  It does not start the game, call native functions, or
disassemble an image broadly.  The runtime child uses these windows as
fail-closed code guards before it follows the loan list.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE
from work.local_config import game_exe


STAGE = ROOT / "work" / "runtime" / "information-loans-20261027-001"
SOURCE_PATH = STAGE / "loans-source-001.json"
PROFILE_PATH = ROOT / "bridge" / "information" / "profiles" / "country-loans-memory-1374.json"
PROFILE_ID = "country-loans-memory-1374"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXE_BYTES = 38_463_016
GAME_VERSION = "1.37.4"
REPORT_LIMIT = 128 * 1024
READ_BUDGET_BYTES = 16 * 1024
IMAGE_RVA_END = 0x25DF8B4
TEXT_RVA_BEGIN = 0x1000
TEXT_RVA_END = 0x1B65E00
RDATA_RVA_BEGIN = 0x1B66000
RDATA_RVA_END = 0x1FAFA00

# Each window is a small instruction-level proof selected by source-001.  The
# runtime does not use these bytes as a decompiler; it only checks that the
# pinned build still has the exact instruction at the expected RVA.
GUARD_RANGES = (
    ("country_writer_container", 0x2DF631, 0x2DF638, "country_writer_loan_container"),
    ("country_writer_payload", 0x2DF650, 0x2DF653, "country_writer_loan_container"),
    ("loan_row_principal", 0xEB158E, 0xEB1592, "loan_row_view_fields"),
    ("loan_row_interest", 0xEB1592, 0xEB1595, "loan_row_view_fields"),
    ("loan_row_due", 0xEB1595, 0xEB1598, "loan_row_view_fields"),
    ("loan_fullref_shift", 0x2892EF, 0x2892F3, "lender_fullref_lookup"),
    ("loan_iterator_next", 0xC00C3, 0xC00C7, "loan_iterator_helpers"),
)


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> tuple[bytes, dict[str, Any]]:
    size = path.stat().st_size
    if size <= 0 or size > REPORT_LIMIT:
        raise ValueError(f"source_report_size_out_of_bound:{size}")
    with path.open("rb") as stream:
        raw = stream.read(REPORT_LIMIT + 1)
    if len(raw) != size or len(raw) > REPORT_LIMIT:
        raise ValueError("source_report_size_changed")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError("source_report_shape_invalid")
    if document.get("binary", {}).get("sha256") != EXE_SHA256:
        raise ValueError("source_report_executable_mismatch")
    if document.get("country_loan_container", {}).get("owner", {}).get("country_offset") != "0xde8":
        raise ValueError("source_report_country_offset_missing")
    fields = document.get("loan_record_fields", {})
    wanted = {"lender": "0x20", "interest": "0x28", "amount": "0x2c", "expiry": "0x30"}
    if any(fields.get(key, {}).get("offset") != offset for key, offset in wanted.items()):
        raise ValueError("source_report_field_offsets_missing")
    if fields.get("interest", {}).get("scale") != 1000:
        raise ValueError("source_report_interest_scale_missing")
    return raw, document


def selected_bytes(document: dict[str, Any], group: str, rva: int) -> bytes:
    rows = document.get("selected_instructions", {}).get(group, [])
    for row in rows:
        if int(str(row.get("rva")), 0) == rva:
            return bytes.fromhex(str(row.get("bytes", "")))
    raise ValueError(f"source_instruction_missing:{group}:{rva:#x}")


def write_exclusive(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main() -> None:
    source_raw, source = read_json(SOURCE_PATH)
    executable = game_exe()
    if executable.stat().st_size != EXE_BYTES or digest_file(executable) != EXE_SHA256:
        raise ValueError("unexpected_executable_identity")
    pe = PE(executable)
    if pe.base != 0x140000000:
        raise ValueError(f"unexpected_image_base:{pe.base:#x}")

    guards: list[dict[str, Any]] = []
    for name, begin, end, group in GUARD_RANGES:
        raw = pe.bytes_at(begin, end - begin)
        if len(raw) != end - begin:
            raise ValueError(f"guard_not_backed_by_executable:{name}")
        selected = selected_bytes(source, group, begin)
        if selected != raw:
            raise ValueError(f"guard_source_mismatch:{name}")
        guards.append(
            {
                "name": name,
                "rva": hex(begin),
                "rva_end_exclusive": hex(end),
                "hex": raw.hex(),
                "sha256": digest_bytes(raw),
                "aslr_invariant": True,
            }
        )

    profile = {
        "profile_id": PROFILE_ID,
        "profile_version": 1,
        "game_version": GAME_VERSION,
        "executable": {"sha256": EXE_SHA256, "image_base": "0x140000000"},
        "source_evidence": [
            {
                "path": SOURCE_PATH.relative_to(ROOT).as_posix(),
                "sha256": digest_bytes(source_raw),
                "bytes": len(source_raw),
                "role": "batch-52 bounded country loan container and current record fields",
            }
        ],
        "layout": {
            "field_key": "loans",
            "country_loans_offset": "0xde8",
            "node_payload_offset": "0x0",
            "node_next_offset": "0x10",
            "loan_record_vtable_offset": "0x0",
            "vtable_guard_entry_offset": "0x0",
            "lender_fullref_offset": "0x20",
            "interest_offset": "0x28",
            "principal_offset": "0x2c",
            "due_offset": "0x30",
            "max_nodes": 64,
            "read_budget_bytes": READ_BUDGET_BYTES,
            "pointer_min": "0x10000",
            "pointer_max": "0x7fffffffffff",
            "image_rva_end": hex(IMAGE_RVA_END),
            "vtable_rva_begin": hex(RDATA_RVA_BEGIN),
            "vtable_rva_end": hex(RDATA_RVA_END),
            "code_rva_begin": hex(TEXT_RVA_BEGIN),
            "code_rva_end": hex(TEXT_RVA_END),
        },
        "static_property": {
            "field_key": "loans",
            "token_rva": "0x2082020",
            "token_id": "0x28ad",
            "country_writer_rva": "0x2df620",
            "iterator_payload_helper_rva": "0x9a010",
            "iterator_next_helper_rva": "0xc00c0",
            "nested_serializer_rva": "0x707920",
            "image_sections": {
                "text_rva_begin": hex(TEXT_RVA_BEGIN),
                "text_rva_end": hex(TEXT_RVA_END),
                "rdata_rva_begin": hex(RDATA_RVA_BEGIN),
                "rdata_rva_end": hex(RDATA_RVA_END),
                "image_rva_end": hex(IMAGE_RVA_END),
            },
            "current_record_fields": {
                "lender_fullref": "0x20",
                "interest_raw": "0x28",
                "principal_raw": "0x2c",
                "due_raw": "0x30",
            },
        },
        "semantics": {
            "field": "loans",
            "basis": "native_country_loan_records",
            "value_origin": "copied_native_country_loan_records",
            "unit": "loan_records",
            "scale": 1,
            "period": "current",
            "complete": False,
            "partial": True,
            "principal_unit": "ducats",
            "principal_scale": 1,
            "interest_unit": "percent",
            "interest_scale": 1000,
            "due_unit": "engine_date_raw",
            "due_scale": 1,
            "lender_mapping": "raw_fullref_only_unresolved",
        },
        "code_guards": guards,
        "read_constraints": {
            "guard_order": "all RVA-relative guards match before country+0xde8 traversal",
            "node_shape": "current_node payload at +0x0 and next at +0x10; null terminates",
            "vtable": "record vtable must lie in this build's .rdata RVA range and its first method must lie in the .text RVA range; exact loan RTTI/type identity remains unresolved",
            "pre_reservation": "every read reserves its full size before invoking reader.read; failed reads consume the reservation",
            "max_nodes": 64,
            "failure": "profile/source mismatch, code mismatch, invalid pointer, vtable failure, cycle, limit, short read, or budget failure remains unknown",
        },
        "unknown_conditions": [
            "Nested loan serialization at RVA 0x707920 is not decoded by this bounded child.",
            "The +0x30 scalar is retained as signed raw engine date; epoch and duration semantics are unresolved.",
            "The lender fullref is retained without guessing bank/foreign-country meaning or display name.",
            "Amount-with-interest helper and cache refresh timing are outside this child; principal +0x2c is the closed whole-ducat field.",
            "The structural vtable guard binds pointers to this executable image and .text/.rdata ranges; it does not prove a unique loan RTTI/type.",
            "The parent owns process identity, country identity, two-pass comparison, lifecycle, and cleanup/retraction.",
        ],
    }
    write_exclusive(PROFILE_PATH, profile)
    print(
        json.dumps(
            {
                "profile": PROFILE_PATH.relative_to(ROOT).as_posix(),
                "profile_sha256": digest_file(PROFILE_PATH),
                "profile_bytes": PROFILE_PATH.stat().st_size,
                "guard_count": len(guards),
                "guard_bytes": sum(len(bytes.fromhex(item["hex"])) for item in guards),
                "source_evidence": profile["source_evidence"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
