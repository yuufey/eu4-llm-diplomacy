"""Create the bounded army-tradition child profile from pinned source reports.

This script reads only the three small archived source reports and bounded PE
byte windows.  It does not open the game, call native code, or disassemble the
image.  Guards are RVA-relative instruction bytes; no runtime/ASLR pointer is
placed in the executable guard set.
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


STAGE = ROOT / "work" / "runtime" / "information-military-quality-20261027-001"
PROFILE_PATH = ROOT / "bridge" / "information" / "profiles" / "military-tradition-memory-1374.json"
PROFILE_ID = "military-tradition-memory-1374"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_EXE_BYTES = 38_463_016
GAME_VERSION = "1.37.4"
REPORT_LIMIT = 128 * 1024
CODE_GUARD_LIMIT = 4096

REPORTS = (
    (
        "tradition-source-002.json",
        "direct country getter, key registration and static property/vtable evidence",
    ),
    (
        "tradition-source-004.json",
        "bounded UI selector and explicit decimal scale formatter evidence",
    ),
    (
        "tradition-source-005.json",
        "bounded serializer raw-width and no-hidden-scale evidence",
    ),
)

# The static property object/vtable is pinned as an RVA in metadata.  Runtime
# guards below contain only relative code bytes and do not compare the ASLR
# materialized vtable pointer.
GUARD_RANGES = (
    ("army_tradition_key_registration", 0x6A80BA, 0x6A80F0),
    ("army_tradition_getter", 0x6E01B0, 0x6E01BD),
    ("formatter_selector_e40", 0x41048C, 0x4104A7),
    ("formatter_wrapper", 0x4109C0, 0x4109E6),
    ("formatter_scale_1000", 0x4106D8, 0x4106EA),
)


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_report(name: str) -> tuple[Path, bytes, dict[str, Any]]:
    path = STAGE / name
    size = path.stat().st_size
    if size <= 0 or size > REPORT_LIMIT:
        raise ValueError(f"report_size_out_of_bound:{name}:{size}")
    raw = path.read_bytes()
    if len(raw) != size or len(raw) > REPORT_LIMIT:
        raise ValueError(f"report_size_changed:{name}")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict) or document.get("binary", {}).get("sha256", "").lower() != EXE_SHA256:
        raise ValueError(f"report_exe_mismatch:{name}")
    return path, raw, document


def guard_bytes(pe: PE, begin: int, end: int) -> bytes:
    if end <= begin or end - begin > CODE_GUARD_LIMIT:
        raise ValueError(f"guard_range_invalid:{begin:#x}:{end:#x}")
    raw = pe.bytes_at(begin, end - begin)
    if len(raw) != end - begin:
        raise ValueError(f"guard_not_backed_by_exe:{begin:#x}:{end:#x}")
    return raw


def write_exclusive(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main() -> None:
    evidence: list[dict[str, Any]] = []
    for name, role in REPORTS:
        path, raw, _document = read_report(name)
        evidence.append(
            {
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "sha256": digest_bytes(raw),
                "bytes": len(raw),
                "role": role,
            }
        )

    exe = game_exe()
    if exe.stat().st_size != EXPECTED_EXE_BYTES or digest_file(exe) != EXE_SHA256:
        raise ValueError("unexpected_executable_identity")
    pe = PE(exe)
    if pe.base != 0x140000000:
        raise ValueError(f"unexpected_image_base:{pe.base:#x}")

    guards: list[dict[str, Any]] = []
    for name, begin, end in GUARD_RANGES:
        raw = guard_bytes(pe, begin, end)
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
        "source_evidence": evidence,
        "layout": {
            "field_key": "army_tradition",
            "country_army_tradition_offset": "0xe40",
            "value_width": 4,
            "value_signed": True,
            "read_budget_bytes": 4096,
        },
        "static_property": {
            "field_key": "army_tradition",
            "key": "army_tradition",
            "property_object_rva": "0x1ca0240",
            "vtable_slot_offset": "0x10",
            "getter_rva": "0x6e01b0",
            "country_offset": "0xe40",
            "formatter_wrapper_rva": "0x4109c0",
            "formatter_selector": "0x56",
            "formatter_scale": 1000,
            "runtime_vtable_pointer_guarded": False,
        },
        "semantics": {
            "field": "army_tradition",
            "basis": "native_country_army_tradition_cache",
            "value_origin": "copied_native_country_army_tradition_cache",
            "unit": "army_tradition",
            "scale": 1000,
            "period": "current",
            "complete": True,
            "raw_encoding": "signed little-endian int32 copied from country+0xe40; raw_hex preserves four bytes",
        },
        "code_guards": guards,
        "read_constraints": {
            "pointer_min": "0x10000",
            "pointer_max": "0x7fffffffffff",
            "cache": "one bounded signed little-endian DWORD at country+0xe40",
            "guard_order": "all RVA-relative code guards must match before the country cache read",
            "runtime_vtable": "static property/vtable RVA is provenance only; no ASLR materialized vtable pointer is compared",
            "failure": "profile/source mismatch, guard mismatch, invalid pointer, short read, or budget failure remains unknown",
        },
        "unknown_conditions": [
            "This child copies the current country cache and does not claim UI freshness beyond the pinned static formatter evidence.",
            "The parent owns FRA identity, process lifetime, double-pass comparison, and cleanup/retraction.",
        ],
    }
    write_exclusive(PROFILE_PATH, profile)
    print(
        json.dumps(
            {
                "profile": str(PROFILE_PATH.relative_to(ROOT)).replace("\\", "/"),
                "profile_sha256": digest_file(PROFILE_PATH),
                "profile_bytes": PROFILE_PATH.stat().st_size,
                "guard_count": len(guards),
                "guard_bytes": sum(len(bytes.fromhex(item["hex"])) for item in guards),
                "source_evidence": evidence,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
