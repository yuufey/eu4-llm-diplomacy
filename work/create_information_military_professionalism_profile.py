"""Create the bounded army-professionalism child profile.

The source-scale report is supplied by the batch-51 bounded research step.
This script only verifies that small report, reads three RVA-relative PE byte
windows, and writes a new profile.  It does not open the game, call native
code, or perform whole-image disassembly.
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


STAGE = ROOT / "work" / "runtime" / "information-military-professionalism-20261027-001"
PROFILE_PATH = ROOT / "bridge" / "information" / "profiles" / "military-professionalism-memory-1374.json"
PROFILE_ID = "military-professionalism-memory-1374"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_EXE_BYTES = 38_463_016
GAME_VERSION = "1.37.4"
REPORT_LIMIT = 128 * 1024
CODE_GUARD_LIMIT = 8192
SCALE = 32768

# The getter proves the direct country+0x50 QWORD copy.  The two short
# windows retain the already-bounded country binding and serializer boundary
# as provenance; guards contain only image-relative code bytes.
GUARD_RANGES = (
    ("professionalism_getter", 0x9A530, 0x9A53B),
    ("professionalism_country_binding", 0x2DFC0E, 0x2DFC46),
    ("professionalism_serializer", 0x1707A50, 0x1707AB1),
)


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _report_candidates() -> list[Path]:
    """Return the new scale report without broad stage enumeration."""

    names = (
        "professionalism-scale-source001.json",
        "professionalism-scale-source-001.json",
        "professionalism-scale-source002.json",
        "professionalism-scale-source-002.json",
    )
    return [STAGE / name for name in names if (STAGE / name).is_file()]


def _read_report(path: Path) -> tuple[Path, bytes, dict[str, Any]]:
    size = path.stat().st_size
    if size <= 0 or size > REPORT_LIMIT:
        raise ValueError(f"report_size_out_of_bound:{path.name}:{size}")
    with path.open("rb") as stream:
        raw = stream.read(REPORT_LIMIT + 1)
    if len(raw) != size or len(raw) > REPORT_LIMIT:
        raise ValueError(f"report_size_changed:{path.name}")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"report_shape_invalid:{path.name}")
    binary = document.get("binary")
    reported_sha = document.get("exe_sha256")
    if isinstance(binary, dict):
        reported_sha = binary.get("sha256", reported_sha)
    if str(reported_sha or "").lower() != EXE_SHA256:
        raise ValueError(f"report_exe_mismatch:{path.name}")
    return path, raw, document


def _scale_values(value: Any, path: str = "") -> list[tuple[str, int]]:
    """Find explicitly named scale values in the small source report."""

    found: list[tuple[str, int]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if key in {"scale", "source_scale", "formatter_scale", "raw_scale"} and type(child) is int:
                found.append((child_path, child))
            found.extend(_scale_values(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_scale_values(child, f"{path}[{index}]"))
    return found


def _require_scale(document: dict[str, Any], report_name: str) -> tuple[str, int]:
    candidates = [(path, value) for path, value in _scale_values(document) if value == SCALE]
    if not candidates:
        raise ValueError(f"professionalism_scale_not_closed:{report_name}")
    # A report may cite the formatter and the public contract separately.  The
    # profile pins the value only after the report explicitly records 32768.
    return candidates[0]


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
    candidates = _report_candidates()
    if not candidates:
        raise FileNotFoundError(f"no_professionalism_scale_report:{STAGE}")
    report_path, report_raw, report = _read_report(candidates[0])
    scale_path, scale = _require_scale(report, report_path.name)

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
                "path": str(report_path.relative_to(ROOT)).replace("\\", "/"),
                "sha256": digest_bytes(report_raw),
                "bytes": len(report_raw),
                "role": "batch-51 bounded source-scale and direct country+0x50 contract",
            }
        ],
        "layout": {
            "field_key": "professionalism",
            "country_army_professionalism_offset": "0x50",
            "value_width": 8,
            "value_signed": True,
            "read_budget_bytes": 8192,
        },
        "static_property": {
            "field_key": "professionalism",
            "key": "army_professionalism",
            "getter_rva": "0x9a530",
            "country_offset": "0x50",
            "formatter_scale": SCALE,
            "scale_evidence_path": scale_path,
            "runtime_vtable_pointer_guarded": False,
        },
        "semantics": {
            "field": "professionalism",
            "basis": "native_country_army_professionalism_cache",
            "value_origin": "copied_native_country_army_professionalism_cache",
            "unit": "ratio",
            "scale": SCALE,
            "period": "current",
            "complete": True,
            "raw_encoding": "signed little-endian int64 copied inline from country+0x50; raw_hex preserves eight bytes",
        },
        "code_guards": guards,
        "read_constraints": {
            "pointer_min": "0x10000",
            "pointer_max": "0x7fffffffffff",
            "cache": "one bounded signed little-endian QWORD at country+0x50; the bytes are inline, not a pointer",
            "guard_order": "all RVA-relative code guards must match before the country cache read",
            "runtime_vtable": "no ASLR materialized vtable pointer is compared",
            "failure": "profile/source mismatch, guard mismatch, invalid pointer, short read, or budget failure remains unknown",
        },
        "unknown_conditions": [
            "This child copies the current country cache and does not claim refresh or increment timing.",
            "The parent owns FRA identity, process lifetime, two-pass comparison, and cleanup/retraction.",
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
                "source_evidence": profile["source_evidence"],
                "scale_path": scale_path,
                "scale": scale,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
