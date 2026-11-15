"""Create the bounded fixed-build profile for the current morale caches.

Only the pinned source-003 report and four small RVA-relative PE byte windows
are used.  This script does not invoke REA, attach to a game, read process
memory, or disassemble the image.
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


STAGE = ROOT / "work" / "runtime" / "information-military-effective-20261027-001"
SOURCE_REPORT = STAGE / "morale-effective-source-003.json"
SOURCE_REPORT_SHA256 = "6a74f53126ce62d6b616628d549db7b9c30e63a5ac40566db4d908d082bf0cb8"
PROFILE_PATH = ROOT / "bridge" / "information" / "profiles" / "military-morale-memory-1374.json"
PROFILE_ID = "military-morale-memory-1374"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_EXE_BYTES = 38_463_016
GAME_VERSION = "1.37.4"
REPORT_LIMIT = 128 * 1024
CODE_GUARD_LIMIT = 4096

GUARD_RANGES = (
    ("army_writer_core", 0x119FB40, 0x119FC61),
    ("navy_writer_core", 0x119FFD0, 0x11A0100),
    ("army_country_scale_consumer", 0x23E430, 0x23E480),
    ("navy_country_scale_consumer", 0x237593, 0x2375FF),
)


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_source_report() -> tuple[bytes, dict[str, Any]]:
    size = SOURCE_REPORT.stat().st_size
    if size <= 0 or size > REPORT_LIMIT:
        raise ValueError(f"source_report_size_out_of_bound:{size}")
    raw = SOURCE_REPORT.read_bytes()
    if len(raw) != size or digest_bytes(raw) != SOURCE_REPORT_SHA256:
        raise ValueError("source_report_pin_mismatch")
    report = json.loads(raw.decode("utf-8"))
    if not isinstance(report, dict) or report.get("target", {}).get("exe_sha256", "").lower() != EXE_SHA256:
        raise ValueError("source_report_exe_mismatch")
    return raw, report


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
    source_raw, source_report = read_source_report()
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
        "source_evidence": [
            {
                "path": str(SOURCE_REPORT.relative_to(ROOT)).replace("\\", "/"),
                "sha256": digest_bytes(source_raw),
                "bytes": len(source_raw),
                "role": "positive current army/navy morale cache contract with writer, label, signed-scale, and country-alias evidence",
            }
        ],
        "layout": {
            "field_key": "morale",
            "fields": ["army", "navy"],
            "country_offsets": {"army": "0x9874", "navy": "0x987c"},
            "value_width": 4,
            "value_signed": True,
            "read_budget_bytes": 8192,
        },
        "static_property": {
            "field_keys": ["army", "navy"],
            "record_layout": {
                "tag_offset": "0x0",
                "tag": 9,
                "raw_offset": "0x40",
                "kind_offset": "0x4",
                "kind": 2,
            },
            "writers": {
                "army": {"function_rva": "0x119fb40", "case_target_rva": "0x119fc4a", "country_offset": "0x9874"},
                "navy": {"function_rva": "0x119ffd0", "case_target_rva": "0x11a00e9", "country_offset": "0x987c"},
            },
            "signed_scale_consumers": {
                "army": {"rva_start": "0x23e430", "rva_end_exclusive": "0x23e480", "field_offset": "0x9874", "scale": 1000},
                "navy": {"rva_start": "0x237593", "rva_end_exclusive": "0x2375ff", "field_offset": "0x987c", "scale": 1000},
            },
            "labels": {"army_morale": "LAND_MORALE", "navy_morale": "NAVAL_MORALE"},
            "runtime_absolute_pointers_guarded": False,
        },
        "semantics": {
            "field": "morale",
            "basis": "native_country_morale_caches",
            "value_origin": "copied_native_country_morale_cache",
            "unit": "morale",
            "scale": 1000,
            "period": "current",
            "complete": True,
            "raw_encoding": "signed little-endian int32 copied from country+0x9874/+0x987c; raw_hex preserves each four-byte cache",
            "scope": "current copied cache only; complete effective/max formula and refresh timing are outside this contract",
        },
        "code_guards": guards,
        "read_constraints": {
            "pointer_min": "0x10000",
            "pointer_max": "0x7fffffffffff",
            "cache": "two bounded signed little-endian DWORDs at country+0x9874 and country+0x987c",
            "guard_order": "all RVA-relative writer and signed-scale guards must match before either country cache read",
            "runtime_absolute_pointers": "not compared; guards contain only fixed RVA-relative code bytes",
            "failure": "profile/source mismatch, guard mismatch, invalid pointer, short read, or budget failure withdraws both fields",
        },
        "unknown_conditions": [
            "This child copies the current country caches and does not claim UI freshness, refresh timing, or the complete effective/max morale formula.",
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
                "source_evidence": {"sha256": digest_bytes(source_raw), "bytes": len(source_raw)},
                "source_report_id": source_report.get("report_id"),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
