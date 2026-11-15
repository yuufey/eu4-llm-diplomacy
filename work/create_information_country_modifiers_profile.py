"""Create the bounded 1.37.4 country-modifier child profile.

The final storage contract is kept in the small country-records report.  This
script only verifies those pins and reads the four short RVA-relative PE
windows; it never starts the game, invokes native code, or performs a whole
image disassembly.
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


PROFILE_PATH = ROOT / "bridge" / "information" / "profiles" / "country-modifiers-memory-1374-v2.json"
PROFILE_ID = "country-modifiers-memory-1374-v2"
GAME_VERSION = "1.37.4"
EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_EXE_BYTES = 38_463_016
REPORT_LIMIT = 128 * 1024
GUARD_LIMIT = 8192

CONTRACT_PATH = ROOT / "work" / "runtime" / "information-country-records-20261027-001" / "country-modifiers-source-contract-002.json"
INSTANCE_SOURCE_PATH = ROOT / "work" / "runtime" / "information-military-modifiers-20261027-001" / "active-military-modifiers-source-005.json"

GUARD_RANGES = (
    ("country_list_writer", 0x2E0076, 0x2E00D9),
    ("list_iterator", 0xC0170, 0xC0181),
    ("instance_fields_writer", 0xB359E0, 0xB35C1A),
    ("definition_effects_writer", 0x8E67C0, 0x8E6855),
)


def digest_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_pinned_report(path: Path) -> tuple[bytes, dict[str, Any]]:
    size = path.stat().st_size
    if size <= 0 or size > REPORT_LIMIT:
        raise ValueError(f"report_size_out_of_bound:{path}:{size}")
    with path.open("rb") as stream:
        raw = stream.read(REPORT_LIMIT + 1)
    if len(raw) != size or len(raw) > REPORT_LIMIT:
        raise ValueError(f"report_size_changed:{path}")
    document = json.loads(raw.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"report_shape_invalid:{path}")
    target = document.get("target")
    sha = target.get("exe_sha256") if isinstance(target, dict) else document.get("exe_sha256")
    if str(sha or "").lower() != EXE_SHA256:
        raise ValueError(f"report_exe_mismatch:{path}")
    return raw, document


def read_source(path: Path) -> bytes:
    size = path.stat().st_size
    if size <= 0 or size > REPORT_LIMIT:
        raise ValueError(f"source_size_out_of_bound:{path}:{size}")
    with path.open("rb") as stream:
        raw = stream.read(REPORT_LIMIT + 1)
    if len(raw) != size or len(raw) > REPORT_LIMIT:
        raise ValueError(f"source_size_changed:{path}")
    return raw


def guard_bytes(pe: PE, begin: int, end: int) -> bytes:
    if end <= begin or end - begin > GUARD_LIMIT:
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
    if PROFILE_PATH.exists():
        raise FileExistsError(PROFILE_PATH)
    contract_raw, contract = read_pinned_report(CONTRACT_PATH)
    instance_raw = read_source(INSTANCE_SOURCE_PATH)
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
                "path": str(CONTRACT_PATH.relative_to(ROOT)).replace("\\", "/"),
                "sha256": digest_bytes(contract_raw),
                "bytes": len(contract_raw),
                "role": "final bounded country-modifier storage contract",
            },
            {
                "path": str(INSTANCE_SOURCE_PATH.relative_to(ROOT)).replace("\\", "/"),
                "sha256": digest_bytes(instance_raw),
                "bytes": len(instance_raw),
                "role": "bounded instance definition/effect layout evidence",
            },
        ],
        "layout": {
            "field_key": "modifiers",
            "country_list_head_offset": "0x1f0",
            "node_item_offset": "0x0",
            "node_next_offset": "0x10",
            "node_width": 24,
            "item_vtable_offset": "0x0",
            "item_definition_offset": "0x30",
            "item_width": 128,
            "item_start_date_offset": "0x40",
            "item_date_offset": "0x44",
            "item_flag_offsets": {
                "ruler_modifier": "0x48",
                "parliament_modifier": "0x49",
                "permanent": "0x4a",
                "hidden": "0x4b",
            },
            "vtable_entries_width": 24,
            "definition_vtable_rva": "0x1c42ae0",
            "definition_prefix_width": "0x178",
            "definition_effects_pointer_offset": "0x58",
            "definition_effect_count_offset": "0x64",
            "definition_key_offset": "0x158",
            "definition_key_length_offset": "0x168",
            "definition_key_capacity_offset": "0x170",
            "effect_pair_width": 8,
            "effect_index_offset": "0x0",
            "effect_raw_offset": "0x4",
            "modifier_database_global_rva": "0x2358060",
            "modifier_record_stride": "0x60",
            "modifier_selector_offset": "0x50",
            "expected_vtable_rva": "0x1ce7f08",
            "expected_vtable_methods": {
                "0x0": "0xb355e0",
                "0x8": "0xd2f280",
                "0x10": "0xb359e0",
            },
            "max_instances": 128,
            "max_effects": 256,
            "max_key_bytes": 255,
            "read_budget_bytes": 131072,
            "pointer_min": "0x10000",
            "pointer_max": "0x7fffffffffff",
        },
        "static_property": {
            "field_key": "modifiers",
            "list_writer_rva": "0x2e0076",
            "content_writer_rva": "0xb359e0",
            "definition_vtable_rva": "0x1c42ae0",
            "vtable_rva": "0x1ce7f08",
            "selector_global_rva": "0x2358060",
            "instance_width": 128,
            "sso_inline_capacity": 15,
        },
        "semantics": {
            "field": "modifiers",
            "basis": "native_country_modifier_instances",
            "value_origin": "copied_native_country_modifier_instances",
            "unit": "native_modifier",
            "scale": 1,
            "period": "current",
            "complete": True,
            "population": "ordered direct country modifier-instance list only",
            "key": "stable ASCII script identifier; localized display names are not read",
            "date": "raw signed native date bytes only; expiry/end-date meaning remains unresolved",
            "effects": "raw signed definition values paired with native selector IDs",
        },
        "code_guards": guards,
        "read_constraints": {
            "guard_order": "all pinned RVA-relative code guards before target list reads",
            "predebit": True,
            "max_instances": 128,
            "max_effects_total_per_record": 256,
            "max_key_bytes": 255,
            "max_read_budget_bytes": 131072,
            "cycle_policy": "head plus null-terminated next chain, visited-set cycle rejection, maximum 128 nodes",
            "failure": "profile, guard, pointer, topology, SSO, effect, selector or budget failure remains unknown",
        },
        "unknown_conditions": [
            "No display localization, expiry consumer, or aggregate effective attribute is synthesized.",
            "The parent owns FRA identity, lifecycle, two-pass comparison and cleanup/retraction.",
            "The direct country list is complete only for the observed native list scope; other modifier populations are not included.",
        ],
        "contract_digest": digest_bytes(contract_raw),
        "contract_schema": contract.get("schema"),
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
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
