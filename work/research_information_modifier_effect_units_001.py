"""Bound two narrow static modifier serializer semantics for batch 51.

This script only consumes the fixed 1.37.4 executable and already archived
bounded evidence.  It never opens a game process or calls an in-game function.
The report deliberately keeps the generic fixed-point display rule separate
from the business unit of each modifier effect, and keeps the date field
label separate from any derived remaining-days calculation.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from work.discover_diplomacy import PE, check_memory_budget, make_disassembler
from work.local_config import game_exe
from work.research_information_branch_inputs import _decode_range


EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
IMAGE_BASE = 0x140000000
STAGE = ROOT / "work/runtime/information-military-modifiers-20261027-001"
REPORT = STAGE / "modifier-effect-date-source-001.json"
SOURCE005 = STAGE / "active-military-modifiers-source-005.json"
DATE_REA = STAGE / "rea-modifier-instance-serialize-fields-001/evidence.json"
FORMAT_REA = ROOT / (
    "work/runtime/information-domestic-pressure-20261025-001/"
    "rea-save-fixed-point-format-001/evidence.json"
)
TOKEN_REA = ROOT / (
    "work/runtime/information-domestic-pressure-20261025-001/"
    "rea-save-key-resolver-001/evidence.json"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_pin(path: Path) -> dict[str, object]:
    return {
        "path": str(path.relative_to(ROOT)),
        "size_bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }


def _load_json(path: Path) -> dict[str, object]:
    # All JSON loaded here is bounded archived evidence (<10 MiB).  The EXE
    # itself is accessed through PE.bytes_at and never materialized by this
    # script.
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise TypeError(f"expected object in {path}")
    return value


def _evidence_pin(path: Path, *, expected_procedure: str | None = None) -> dict[str, object]:
    value = _load_json(path)
    normalized = value.get("normalized_result")
    procedure: dict[str, object] = {}
    body: dict[str, object] = {}
    if isinstance(normalized, dict):
        candidate = normalized.get("procedure")
        if isinstance(candidate, dict):
            procedure = candidate
            candidate_body = candidate.get("body")
            if isinstance(candidate_body, dict):
                body = candidate_body
    if expected_procedure is not None:
        actual = procedure.get("address")
        if actual != expected_procedure:
            raise AssertionError((path, actual, expected_procedure))
    return {
        **_file_pin(path),
        "evidence_id": value.get("evidence_id"),
        "provider": value.get("provider"),
        "subject_sha256": (
            value.get("subject", {}).get("digest", {}).get("sha256")
            if isinstance(value.get("subject"), dict)
            else None
        ),
        "procedure": {
            "address": procedure.get("address"),
            "name": procedure.get("name"),
            "body": body,
        },
    }


def _range_pin(pe: PE, md, start: int, end: int, *, selected: tuple[int, ...] = ()) -> dict[str, object]:
    if end <= start or end - start > 8192:
        raise ValueError((hex(start), hex(end)))
    raw = pe.bytes_at(start, end - start)
    rows = _decode_range(pe, md, start, end)
    selected_rows = [row for row in rows if int(row["rva"], 16) in selected]
    return {
        "start_rva": hex(start),
        "end_rva_exclusive": hex(end),
        "start_static_va": hex(pe.base + start),
        "end_static_va_exclusive": hex(pe.base + end),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "selected_instructions": selected_rows,
    }


def _literal_window(pe: PE, rva: int, length: int) -> dict[str, object]:
    raw = pe.bytes_at(rva, length)
    if len(raw) != length:
        raise AssertionError((hex(rva), length, len(raw)))
    key_id = int.from_bytes(raw[:4], "little", signed=False)
    literal = raw[4:].split(b"\0", 1)[0].decode("ascii")
    return {
        "rva": hex(rva),
        "static_va": hex(pe.base + rva),
        "bytes": len(raw),
        "raw_hex": raw.hex(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "token_id": hex(key_id),
        "literal_ascii": literal,
    }


def main() -> None:
    pe = PE(game_exe())
    digest = hashlib.sha256(pe.data).hexdigest()
    if digest != EXE_SHA256:
        raise AssertionError((digest, EXE_SHA256))
    if pe.base != IMAGE_BASE:
        raise AssertionError((hex(pe.base), hex(IMAGE_BASE)))
    md, _ = make_disassembler(ROOT / "work/deps/capstone-5.0.7")

    # These are existing bounded source-005 ranges.  Decoding is repeated only
    # over the small windows needed to check the selected instructions; the
    # complete source-005 artifact remains the canonical archived instruction
    # record for the two parent functions.
    effect_range = _range_pin(
        pe,
        md,
        0x8E67C0,
        0x8E6A0D,
        selected=(0x8E682B, 0x8E6839, 0x8E683C, 0x8E6840, 0x8E6843),
    )
    formatter_range = _range_pin(
        pe,
        md,
        0x246BF0,
        0x246C7C,
        selected=(0x246BF0, 0x246BFC, 0x246C01, 0x246C0F, 0x246C1F, 0x246C21, 0x246C27, 0x246C2A, 0x246C40, 0x246C61),
    )
    date_range = _range_pin(
        pe,
        md,
        0xB359E0,
        0xB35C1A,
        selected=(
            0xB35ADA,
            0xB35AE1,
            0xB35AE7,
            0xB35AEC,
            0xB35AF7,
            0xB35B09,
            0xB35B10,
            0xB35B16,
            0xB35B1B,
            0xB35B26,
            0xB35B34,
        ),
    )
    date_helper_range = _range_pin(pe, md, 0x15BFA0, 0x15C039)

    token_windows = {
        "0x284d_date": _literal_window(pe, 0x2075D20, 8),
        "0x28e4_start_date": _literal_window(pe, 0x2088FD8, 16),
        "0x28e5_end_date_adjacent": _literal_window(pe, 0x20891E0, 16),
    }
    assert token_windows["0x284d_date"]["token_id"] == "0x284d"
    assert token_windows["0x284d_date"]["literal_ascii"] == "date"
    assert token_windows["0x28e4_start_date"]["token_id"] == "0x28e4"
    assert token_windows["0x28e4_start_date"]["literal_ascii"] == "start_date"
    assert token_windows["0x28e5_end_date_adjacent"]["token_id"] == "0x28e5"
    assert token_windows["0x28e5_end_date_adjacent"]["literal_ascii"] == "end_date"

    effect_selected = {
        row["rva"]: row for row in effect_range["selected_instructions"]
    }
    assert effect_selected["0x8e682b"]["mnemonic"] == "mov"
    assert "[rcx+0x4]" in effect_selected["0x8e682b"]["operands"].lower()
    assert effect_selected["0x8e6843"]["operands"].lower().endswith("0x140246bf0")

    date_selected = {
        row["rva"]: row for row in date_range["selected_instructions"]
    }
    assert "0x29c77f8" in date_selected["0xb35ada"]["operands"].lower()
    assert "0x284d" in date_selected["0xb35aec"]["operands"].lower()
    assert "0x28e4" in date_selected["0xb35b1b"]["operands"].lower()

    formatter_evidence = _evidence_pin(FORMAT_REA, expected_procedure="0x140246bf0")
    date_evidence = _evidence_pin(DATE_REA, expected_procedure="0x140b359e0")
    token_evidence = _evidence_pin(TOKEN_REA, expected_procedure="0x1417091b0")

    report = {
        "schema": "information_modifier_effect_date_source.v1",
        "report_id": "modifier-effect-date-source-001",
        "status": "static_semantics_partially_closed",
        "evidence_kind": "bounded_static_PE_plus_archived_REA",
        "exe": {
            "version": "EU4 1.37.4",
            "sha256": digest,
            "image_base": hex(pe.base),
            "rva_rule": "static_va=image_base+rva",
        },
        "scope": {
            "rpm": False,
            "game_calls": 0,
            "writes_or_saves": 0,
            "functions_decoded": [
                "0x8e67c0",
                "0x246bf0",
                "0xb359e0",
                "0x15bfa0",
                "0x17091b0 (archived REA only)",
            ],
            "bounded_decode_bytes": (0x8E6A0D - 0x8E67C0)
            + (0x246C7C - 0x246BF0)
            + (0xB35C1A - 0xB359E0)
            + (0x15C039 - 0x15BFA0),
        },
        "effect_definition_serializer": {
            "function": {
                "rva": "0x8e67c0",
                "va": "0x1408e67c0",
                "range_end_exclusive": "0x8e6a0d",
                "range_bytes": effect_range["bytes"],
                "range_sha256": effect_range["sha256"],
                "archived_source": _file_pin(SOURCE005),
            },
            "entry_value": {
                "field_offset": "0x4",
                "width": "signed_i32",
                "evidence": [
                    "0x8e682b mov ebx,DWORD PTR [rcx+0x4]",
                    "0x8e6839 mov DWORD PTR [rbp+0x60],ebx",
                    "0x8e6840 mov rcx,rsi",
                    "0x8e6843 call 0x140246bf0",
                ],
                "arithmetic_before_formatter": "none in this bounded path",
                "negative_values": "preserved as signed two's-complement i32; no clamp/abs observed",
            },
            "formatter": {
                "rva": "0x246bf0",
                "va": "0x140246bf0",
                "range_end_exclusive": "0x246c7c",
                "range_bytes": formatter_range["bytes"],
                "range_sha256": formatter_range["sha256"],
                "rea": formatter_evidence,
                "format_strings": ["%d.%03d", "-%d.%03d"],
                "formula": "q=trunc0(signed_i32/1000); r=signed_i32-q*1000; negative r is formatted with its magnitude",
                "scale": 1000,
                "sign": "preserved",
                "unit": "generic_fixed_point_display; effect-specific business unit remains unresolved",
            },
            "token_emitter": {
                "rva": "0x17091b0",
                "va": "0x1417091b0",
                "role": "archived REA resolver selects the literal associated with the numeric token before the writer emits it",
                "rea": token_evidence,
            },
            "conclusion": "The definition effect value is a signed i32 rendered with the native generic /1000 fixed-point formatter. This does not establish that every effect uses one business unit (ducats, morale, or another unit).",
        },
        "modifier_item_date_serializer": {
            "function": {
                "rva": "0xb359e0",
                "va": "0x140b359e0",
                "range_end_exclusive": "0xb35c1a",
                "range_bytes": date_range["bytes"],
                "range_sha256": date_range["sha256"],
                "rea": date_evidence,
                "archived_source": _file_pin(SOURCE005),
            },
            "fields": {
                "+0x44": {
                    "width": "signed_i32_dword",
                    "token_id": "0x284d",
                    "token_name": "date",
                    "token_window": token_windows["0x284d_date"],
                    "writer": "FUN_14015bfa0(field)+virtual_writer_vtable_plus_0x8",
                    "sentinel_check": "omit when value == 0x29c77f8",
                },
                "+0x40": {
                    "width": "signed_i32_dword",
                    "token_id": "0x28e4",
                    "token_name": "start_date",
                    "token_window": token_windows["0x28e4_start_date"],
                    "writer": "FUN_14015bfa0(field)+virtual_writer_vtable_plus_0x8",
                    "sentinel_check": "omit when value == 0x29c77f8",
                },
            },
            "adjacent_static_token": token_windows["0x28e5_end_date_adjacent"],
            "date_representation": {
                "raw_width": 4,
                "raw_signedness": "signed_i32 native date scalar in the existing date contract; B359E0 itself accesses it as a DWORD and passes its address",
                "unit": "game_date_raw",
                "scale": 1,
                "format_contract": "native game-date scalar serialized under date/start_date keys; existing save contracts render the scalar as Y.M.D, but B359E0 itself does not perform that calendar conversion",
                "helper": {
                    "rva": "0x15bfa0",
                    "va": "0x14015bfa0",
                    "range_end_exclusive": "0x15c039",
                    "range_bytes": date_helper_range["bytes"],
                    "range_sha256": date_helper_range["sha256"],
                    "role_observed": "returns/initializes a cached writer object used by the indirect +0x8 writer",
                    "date_arithmetic_observed": False,
                },
            },
            "sentinel": {
                "raw": hex(0x29C77F8),
                "meaning_in_this_serializer": "field is omitted when equal; no value is emitted",
                "cross_domain_existing_contract": "same fixed constant is already documented as native open-ended/no-fixed-end date in bridge/diplomacy.py and the archived peace contracts",
                "modifier_specific_caveat": "the exact modifier lifecycle label for +0x44 remains date (the native token), not an invented end_date alias",
            },
            "remaining_days": {
                "status": "not_computed_here",
                "evidence": "B359E0 only compares two stored DWORDs, conditionally writes date/start_date, and does not read current game date or subtract the fields",
                "contract": "remaining_days must remain unresolved/derived elsewhere; do not treat +0x44 or the sentinel as a remaining-day count",
            },
        },
        "unresolved": [
            "FUN_14015bfa0's indirect writer target is initialized through runtime/TLS state; this static bounded pass does not resolve its vtable implementation or calendar text conversion.",
            "The business meaning of the modifier's +0x44 key named date (expiry, application date, or another date role) is not renamed without an owner/container or consumer proof.",
            "No remaining-days calculation or refresh/update schedule is present in the two serializers.",
        ],
        "source_pins": {
            "effect_and_date_source005": _file_pin(SOURCE005),
            "date_serializer_rea": date_evidence,
            "fixed_point_formatter_rea": formatter_evidence,
            "date_token_resolver_rea": token_evidence,
            "existing_date_token_crosscheck": {
                "path": "docs/native-diplomacy-inventory.md",
                "sha256": _sha256(ROOT / "docs/native-diplomacy-inventory.md"),
                "note": "archived same-EXE token table records token 0x284d as date and a 4-byte date field",
            },
            "existing_open_end_crosscheck": {
                "path": "bridge/diplomacy.py",
                "sha256": _sha256(ROOT / "bridge/diplomacy.py"),
                "note": "existing native contract names 0x29c77f8 as open-ended/no-fixed-end; this is cross-domain corroboration, not a new runtime observation",
            },
        },
        "peak_committed_bytes": check_memory_budget(),
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    with REPORT.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(REPORT)
    print(json.dumps({"effect": effect_range["sha256"], "date": date_range["sha256"], "formatter": formatter_range["sha256"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
