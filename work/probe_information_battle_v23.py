"""Read-only observer entry-patch preflight for legacy v23 and installer-validated builds.

The probe has two deliberately separate inputs.  The build manifest and the
DLL COFF symbol table are ordinary bounded file evidence.  Process identity,
the loaded DLL and the entry/unwind bytes are fresh observations from one
``PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`` handle.  No game function,
control command, injection, or memory write is performed here.

``--expect-patch original`` checks the complete original entry prologue.
``--expect-patch installed`` checks the 21-byte absolute jump (whose target is
derived from the physical DLL's COFF symbol) followed by the remaining 15
original bytes.  The 32-byte unwind prefix must be unchanged in both modes.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from typing import Any, Mapping

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bridge.information import localization_memory as _loc
from work import information_battle_war_memory as _war
from work.local_config import game_exe as _configured_game_exe


ROOT = Path(__file__).resolve().parents[1]
BUILD_ID = "diplomacy-observer-20261025-information-battle-v23-005"
LIVE_BUILD_ID = "diplomacy-observer-20261025-information-battle-live-001"
BUILD_DIR = ROOT / "work" / "runtime" / BUILD_ID
MANIFEST_PATH = BUILD_DIR / "build-manifest.json"
DLL_PATH = BUILD_DIR / "eu4_bridge_diplomacy_observer_v23.dll"
SOURCE_MANIFEST_PATH = MANIFEST_PATH
SOURCE_DLL_PATH = DLL_PATH
DEFAULT_INSTALLATION = BUILD_DIR / "installation.json"
DEFAULT_OUTPUT = ROOT / "work" / "runtime" / "information-battle-live-20261025-001" / "v23-preflight-001" / "report.json"

EXPECTED_VERSION = "1.37.4"
EXPECTED_EXE_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
EXPECTED_DLL_SHA256 = "eaf53986e159bfca7af717228a7bc983a8df03fec32a23eb4a82e5ca503133c3"
EXPECTED_MANIFEST_SHA256 = "c68c317cad4f10aa28652322daa718e7798e1dc363c2399fc467a9c21f074bd7"
EXPECTED_SOURCE_COUNT = 103
EXPECTED_IMAGE_BASE = 0x140000000

PROCESS_ACCESS = 0x410  # PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
MAX_USER_ADDRESS = 0x0000800000000000
MAX_SINGLE_RPM = 64 * 1024
MAX_TOTAL_RPM = 1024 * 1024
MAX_JSON_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SYMBOLS = 200_000
MAX_SECTIONS = 128
MAX_STRING_TABLE_BYTES = 16 * 1024 * 1024
STUB_SYMBOL = "information_battle_entry_stub"

ENTRY_RVA = 0x238620
UNWIND_RVA = 0x1DE6C98
ENTRY_SIZE = 36
UNWIND_SIZE = 32
ENTRY_PREFIX = bytes.fromhex(
    "48895c241048894c24085556574154415541564157488dac2460fbffff4881eca0050000"
)
UNWIND_PREFIX = bytes.fromhex(
    "11240b002434bd002401b40015f013e011d00fc00d700c600b5000009c4da301"
)
PATCH_SIZE = 21
RETREAT_ENTRY_SPECS = (
    {
        "key": "outcome",
        "symbol": "information_battle_outcome_retreat_hook",
        "rva": 0x22BED0,
        "end_rva": 0x22C0A6,
        "unwind_rva": 0x1DE6084,
        "prefix": bytes.fromhex("48895c241048896c241848897424205741544155415641574883ec20"),
        "unwind": bytes.fromhex(
            "111c0c001c640d001c540c001c340b001c3218f016e014d012c010709c4da301"
        ),
        "patch_bytes": 28,
    },
    {
        "key": "unit_path",
        "symbol": "information_battle_unit_retreat_hook",
        "rva": 0xD4FB20,
        "end_rva": 0xD501A3,
        "unwind_rva": 0x1EBB0A4,
        "prefix": bytes.fromhex("48895c24105556574154415541564157488d6c24d94881ece0000000"),
        "unwind": bytes.fromhex(
            "111c0b001c3425001c011c0010f00ee00cd00ac008700760065000009c4da301"
        ),
        "patch_bytes": 28,
    },
)
UNIT_REMOVAL_RETREAT_ENTRY_SPEC = {
    "key": "unit_removal",
    "symbol": "information_battle_unit_removal_retreat_hook",
    "rva": 0x23B200,
    "end_rva": 0x23B397,
    "unwind_rva": 0x1DE6F20,
    "prefix": bytes.fromhex(
        "48895c240848896c24104889742420574883ec20410fb6e8488bfa"),
    "unwind": bytes.fromhex(
        "11140800146409001454070014340600143210709c4da3013c6fde0128dd9add"),
    "patch_bytes": 27,
    "projected_unwind_bytes": 20,
    "stack_delta": 0x28,
    "home_slot_offset": 0x18,
}
RETREAT_UNIT_REMOVAL_KEY = "information_battle_retreat_unit_removal"
RETREAT_MAX_EXTENSION_VERSION_KEY = "information_battle_retreat_max_extension_version"
RETREAT_SUPPORTED_VERSIONS = (37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64)

GAME_RVA = _loc.GAME_RVA
GAME_DATE_OFFSET = _loc.GAME_DATE_OFFSET
GAME_PLAYER_OFFSET = 0x1E60


class V23ProbeError(RuntimeError):
    """A bounded identity, static, or RPM contract check failed."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_file_pin(path: Path, *, max_bytes: int | None = None) -> dict[str, Any]:
    """Hash a file by streaming and reject a concurrent metadata change."""
    try:
        before = path.stat()
        if max_bytes is not None and before.st_size > max_bytes:
            return {"path": str(path), "status": "rejected", "reason": "file_size_limit", "size_bytes": before.st_size}
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            return {"path": str(path), "status": "changed_during_hash"}
        return {
            "path": str(path),
            "status": "observed",
            "size_bytes": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "sha256": digest.hexdigest(),
        }
    except OSError as exc:
        return {"path": str(path), "status": "unavailable", "error": f"{type(exc).__name__}:{exc}"}


def _read_json_bounded(path: Path, limit: int = MAX_JSON_BYTES) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    try:
        size = path.stat().st_size
        if size > limit:
            return None, {"path": str(path), "status": "rejected", "reason": "file_size_limit", "size_bytes": size}
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(value, dict):
            return None, {"path": str(path), "status": "rejected", "reason": "not_object", "size_bytes": size}
        return value, {"path": str(path), "status": "observed", "size_bytes": size, "sha256": hashlib.sha256(raw).hexdigest()}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, {"path": str(path), "status": "unavailable", "error": f"{type(exc).__name__}:{exc}"}


def _int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise V23ProbeError(f"{label}_bool_not_integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise V23ProbeError(f"{label}_invalid") from exc
    raise V23ProbeError(f"{label}_invalid")


def _safe_address(value: Any, *, aligned: bool = False) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0x10000 <= value < MAX_USER_ADDRESS
        and (not aligned or value % 8 == 0)
    )


def _utc_filetime(value: int) -> str | None:
    try:
        return datetime.fromtimestamp(value / 10_000_000 - 11644473600, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _artifact_reuse_contract(manifest: Mapping[str, Any], build_dir: Path) -> dict[str, Any]:
    """Validate the only permitted post-build copy provenance.

    A live directory may have a different experiment id and DLL path, but it
    must point back to the immutable v23-005 manifest and the same DLL hash.
    This check intentionally does not accept a caller-supplied arbitrary
    source manifest or a recompiled artifact.
    """
    reuse = manifest.get("artifact_reuse")
    result: dict[str, Any] = {"status": "unknown", "required": build_dir.resolve() != BUILD_DIR.resolve(), "checks": {}, "unknown_conditions": []}
    if build_dir.resolve() == BUILD_DIR.resolve():
        result.update({"status": "not_required", "checks": {"original_build_directory": True}})
        return result
    if not isinstance(reuse, Mapping):
        result["unknown_conditions"].append("artifact_reuse_missing")
        return result
    source_manifest = reuse.get("source_manifest")
    source_manifest_sha = str(reuse.get("source_manifest_sha256", "")).lower()
    source_dll_sha = str(reuse.get("source_dll_sha256", "")).lower()
    result["declared"] = {
        "source_manifest": source_manifest,
        "source_manifest_sha256": source_manifest_sha,
        "source_dll_sha256": source_dll_sha,
        "compiled_in_this_directory": reuse.get("compiled_in_this_directory"),
    }
    try:
        source_manifest_path = Path(str(source_manifest)).resolve()
    except (TypeError, ValueError, OSError):
        source_manifest_path = None
    result["checks"] = {
        "source_manifest_path": source_manifest_path == SOURCE_MANIFEST_PATH.resolve(),
        "source_manifest_sha256": source_manifest_sha == EXPECTED_MANIFEST_SHA256,
        "source_dll_sha256": source_dll_sha == EXPECTED_DLL_SHA256,
        "compiled_in_this_directory_false": reuse.get("compiled_in_this_directory") is False,
        "live_experiment_id": manifest.get("experiment_id") == LIVE_BUILD_ID,
        "live_directory": build_dir.resolve().name == "diplomacy-observer-20261025-information-battle-live-001",
    }
    failed = [key for key, value in result["checks"].items() if value is not True]
    if failed:
        result["unknown_conditions"].append("artifact_reuse_contract_failed:" + ",".join(failed))
    else:
        result["status"] = "observed"
    return result


def _manifest_static_guard_v23(build_dir: Path = BUILD_DIR) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "source": "source",
        "build_dir": str(build_dir),
        "manifest": None,
        "source_manifest": None,
        "artifact_reuse": None,
        "source_count": None,
        "source_mismatches": [],
        "unknown_conditions": [],
    }
    manifest_path = build_dir / "build-manifest.json"
    manifest, json_pin = _read_json_bounded(manifest_path, MAX_MANIFEST_BYTES)
    result["manifest"] = json_pin
    if manifest is None:
        result["unknown_conditions"].append("manifest_unavailable")
        return result
    reuse = _artifact_reuse_contract(manifest, build_dir)
    result["artifact_reuse"] = reuse
    if reuse.get("status") not in {"not_required", "observed"}:
        result["unknown_conditions"].append("artifact_reuse_not_verified")
    source_manifest_path = SOURCE_MANIFEST_PATH
    if isinstance(manifest.get("artifact_reuse"), Mapping) and isinstance(manifest["artifact_reuse"].get("source_manifest"), str):
        try:
            source_manifest_path = Path(manifest["artifact_reuse"]["source_manifest"]).resolve()
        except (OSError, TypeError, ValueError):
            source_manifest_path = SOURCE_MANIFEST_PATH
    source_manifest, source_pin = _read_json_bounded(source_manifest_path, MAX_MANIFEST_BYTES)
    result["source_manifest"] = source_pin
    if source_manifest is None:
        result["unknown_conditions"].append("source_manifest_unavailable")
        return result
    checks = {
        "manifest_sha256": (
            json_pin.get("sha256") == EXPECTED_MANIFEST_SHA256
            if build_dir.resolve() == BUILD_DIR.resolve()
            else isinstance(json_pin.get("sha256"), str) and len(json_pin["sha256"]) == 64
        ),
        "source_manifest_sha256": source_pin.get("sha256") == EXPECTED_MANIFEST_SHA256,
        "experiment_id": manifest.get("experiment_id") in {BUILD_ID, LIVE_BUILD_ID},
        "version": manifest.get("version") == 23,
        "compiled": manifest.get("compiled") is True,
        "research_lifecycle": manifest.get("information_battle_research_lifecycle") is True,
        "game_sha256": str(manifest.get("game_sha256", "")).lower() == EXPECTED_EXE_SHA256,
        "dll_sha256": str(manifest.get("dll_sha256", "")).lower() == EXPECTED_DLL_SHA256,
        "dll_path": False,
        "artifact_reuse": reuse.get("status") in {"not_required", "observed"},
    }
    try:
        checks["dll_path"] = Path(str(manifest.get("dll", ""))).resolve() == (build_dir / DLL_PATH.name).resolve()
    except (OSError, TypeError, ValueError):
        checks["dll_path"] = False
    records = manifest.get("sources")
    source_records = source_manifest.get("sources")
    result["source_count"] = len(records) if isinstance(records, list) else None
    if not isinstance(records, list) or len(records) != EXPECTED_SOURCE_COUNT:
        result["unknown_conditions"].append("source_count_not_103")
    if not isinstance(source_records, list) or len(source_records) != EXPECTED_SOURCE_COUNT:
        result["unknown_conditions"].append("source_manifest_count_not_103")
    mismatches: list[str] = []
    names: set[str] = set()
    if isinstance(records, list):
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                mismatches.append(f"record_{index}_not_object")
                continue
            name = record.get("name")
            expected = str(record.get("sha256", "")).lower()
            if not isinstance(name, str) or not name or Path(name).name != name or name in names:
                mismatches.append(f"record_{index}_name_invalid_or_duplicate")
                continue
            names.add(name)
            if len(expected) != 64:
                mismatches.append(f"{name}:manifest_sha_invalid")
                continue
            source_record = source_records[index] if isinstance(source_records, list) and index < len(source_records) else None
            if not isinstance(source_record, Mapping) or source_record.get("name") != name or str(source_record.get("sha256", "")).lower() != expected:
                mismatches.append(f"{name}:source_manifest_record_mismatch")
            bases = [build_dir, ROOT / "work" / "native"]
            if source_manifest_path.parent != build_dir.resolve():
                bases.append(source_manifest_path.parent)
            for base in bases:
                source = base / name
                pin = _stable_file_pin(source, max_bytes=8 * 1024 * 1024)
                role = "copy" if base == build_dir else "root" if base == ROOT / "work" / "native" else "source_build"
                if pin.get("status") != "observed" or pin.get("sha256") != expected:
                    mismatches.append(f"{name}:{role}")
    result["source_mismatches"] = mismatches[:256]
    checks["source_count"] = isinstance(records, list) and len(records) == EXPECTED_SOURCE_COUNT and len(names) == EXPECTED_SOURCE_COUNT
    checks["source_manifest_sources"] = isinstance(source_records, list) and len(source_records) == EXPECTED_SOURCE_COUNT
    checks["source_hashes"] = not mismatches
    result["checks"] = checks
    failed = [key for key, value in checks.items() if value is not True]
    if failed:
        result["unknown_conditions"].append("manifest_guard_failed:" + ",".join(failed))
    else:
        result["status"] = "observed"
    return result


def _validate_installer_battle_manifest(manifest: dict[str, Any], build_dir: Path) -> None:
    """Reuse the installer’s strict, version-aware source/hash contract."""
    from tools.start_diplomacy_observer import _validate_information_battle_manifest

    _validate_information_battle_manifest(manifest, build_dir)


def _manifest_static_guard(build_dir: Path = BUILD_DIR) -> dict[str, Any]:
    """Validate a v23 legacy build or a current installer-validated build.

    The v23 artifact retains its separately pinned source-manifest reuse
    contract. Later versions use the same strict manifest validator as the
    installer, then bind the manifest to the expected game executable and the
    exact sibling DLL file. This is file-only validation.
    """
    result: dict[str, Any] = {
        "status": "unknown",
        "source": "source",
        "build_dir": str(build_dir),
        "manifest": None,
        "source_manifest": None,
        "artifact_reuse": None,
        "source_count": None,
        "source_mismatches": [],
        "unknown_conditions": [],
    }
    manifest_path = build_dir / "build-manifest.json"
    manifest, manifest_pin = _read_json_bounded(manifest_path, MAX_MANIFEST_BYTES)
    result["manifest"] = manifest_pin
    if not isinstance(manifest, Mapping):
        result["unknown_conditions"].append("manifest_unavailable")
        return result
    version = manifest.get("version")
    if type(version) is not int or version not in (23, 34, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64):
        result["unknown_conditions"].append("unsupported_observer_build_version")
        return result
    if version == 23:
        return _manifest_static_guard_v23(build_dir)

    result["source"] = "tools.start_diplomacy_observer._validate_information_battle_manifest"
    records = manifest.get("sources")
    result["source_count"] = len(records) if isinstance(records, list) else None
    try:
        _validate_installer_battle_manifest(dict(manifest), build_dir)
    except SystemExit as exc:
        result["unknown_conditions"].append(
            "installer_manifest_validation_failed:" + str(exc))
        return result
    except Exception as exc:
        result["unknown_conditions"].append(
            f"installer_manifest_validation_error:{type(exc).__name__}")
        return result

    dll_name = f"eu4_bridge_diplomacy_observer_v{version}.dll"
    dll_path = build_dir / dll_name
    try:
        declared_dll_path = Path(str(manifest.get("dll", ""))).resolve()
        expected_dll_path = dll_path.resolve()
        dll_path_matches = (declared_dll_path == expected_dll_path
                            or declared_dll_path.samefile(expected_dll_path))
    except (OSError, TypeError, ValueError):
        declared_dll_path = Path()
        expected_dll_path = dll_path
        dll_path_matches = False
    expected_dll_sha = str(manifest.get("dll_sha256", "")).lower()
    dll_pin = _stable_file_pin(dll_path, max_bytes=16 * 1024 * 1024)
    checks = {
        "compiled": manifest.get("compiled") is True,
        "game_sha256": str(manifest.get("game_sha256", "")).lower() == EXPECTED_EXE_SHA256,
        "experiment_id": isinstance(manifest.get("experiment_id"), str)
        and bool(manifest.get("experiment_id")),
        "dll_path": dll_path_matches,
        "dll_sha256_well_formed": len(expected_dll_sha) == 64
        and all(ch in "0123456789abcdef" for ch in expected_dll_sha),
        "dll_file_sha256": dll_pin.get("status") == "observed"
        and dll_pin.get("sha256") == expected_dll_sha,
    }
    result["checks"] = checks
    result["dll"] = dll_pin
    result["observer_version"] = version
    result["experiment_id"] = manifest.get("experiment_id")
    result["dll_path"] = str(expected_dll_path)
    result["dll_sha256"] = expected_dll_sha
    failed = [name for name, passed in checks.items() if passed is not True]
    if failed:
        result["unknown_conditions"].append("build_identity_guard_failed:" + ",".join(failed))
    else:
        result["status"] = "observed"
    return result


def _coff_symbol_from_bytes(raw: bytes, symbol: str = STUB_SYMBOL) -> dict[str, Any]:
    """Parse one bounded PE/COFF symbol without disassembling the image."""
    result: dict[str, Any] = {
        "status": "unknown",
        "source": "ordinary_pe_coff",
        "symbol": symbol,
        "machine": None,
        "section_count": None,
        "symbol_count": None,
        "matches": [],
        "rva": None,
        "unknown_conditions": [],
    }
    if len(raw) < 0x40 or raw[:2] != b"MZ":
        result["unknown_conditions"].append("dos_header_invalid")
        return result
    pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset > min(len(raw) - 24, 1024 * 1024) or raw[pe_offset:pe_offset + 4] != b"PE\0\0":
        result["unknown_conditions"].append("pe_header_invalid")
        return result
    coff = pe_offset + 4
    machine, sections, _, symbol_ptr, symbol_count, optional_size, _ = struct.unpack_from("<HHIIIHH", raw, coff)
    result.update(machine=hex(machine), section_count=sections, symbol_count=symbol_count)
    if machine != 0x8664 or not 0 < sections <= MAX_SECTIONS or symbol_count > MAX_SYMBOLS:
        result["unknown_conditions"].append("pe_coff_header_contract_failed")
        return result
    section_table = coff + 20 + optional_size
    if optional_size < 2 or struct.unpack_from("<H", raw, coff + 20)[0] != 0x20B:
        result["unknown_conditions"].append("pe32_plus_optional_header_required")
        return result
    section_end = section_table + sections * 40
    if optional_size > 0x1000 or section_end > len(raw):
        result["unknown_conditions"].append("section_table_out_of_bounds")
        return result
    sections_info: list[dict[str, int | str]] = []
    for index in range(sections):
        offset = section_table + index * 40
        name = raw[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", raw, offset + 8)
        if raw_pointer > len(raw) or raw_size > len(raw) - raw_pointer:
            result["unknown_conditions"].append(f"section_{index + 1}_raw_range_invalid")
            return result
        sections_info.append({"index": index + 1, "name": name, "virtual_size": virtual_size, "virtual_address": virtual_address, "raw_size": raw_size, "raw_pointer": raw_pointer})
    if symbol_count == 0 or symbol_ptr == 0:
        result["unknown_conditions"].append("coff_symbol_table_missing")
        return result
    symbol_bytes = symbol_count * 18
    if symbol_ptr > len(raw) or symbol_bytes > len(raw) - symbol_ptr:
        result["unknown_conditions"].append("coff_symbol_table_out_of_bounds")
        return result
    string_table = symbol_ptr + symbol_bytes
    if string_table + 4 > len(raw):
        result["unknown_conditions"].append("coff_string_table_missing")
        return result
    string_size = struct.unpack_from("<I", raw, string_table)[0]
    if string_size < 4 or string_size > MAX_STRING_TABLE_BYTES or string_table + string_size > len(raw):
        result["unknown_conditions"].append("coff_string_table_out_of_bounds")
        return result
    matches: list[dict[str, Any]] = []
    index = 0
    offset = symbol_ptr
    while index < symbol_count:
        if offset + 18 > string_table:
            result["unknown_conditions"].append("coff_symbol_record_out_of_bounds")
            return result
        record = raw[offset:offset + 18]
        zeroes, name_value = struct.unpack_from("<II", record, 0)
        if zeroes == 0:
            if name_value < 4 or name_value >= string_size:
                name_bytes = None
            else:
                end = raw.find(b"\0", string_table + name_value, string_table + string_size)
                name_bytes = raw[string_table + name_value:end if end >= 0 else string_table + string_size]
        else:
            name_bytes = record[:8].split(b"\0", 1)[0]
        section_number = struct.unpack_from("<h", record, 12)[0]
        value = struct.unpack_from("<I", record, 8)[0]
        aux_count = record[17]
        if name_bytes == symbol.encode("ascii"):
            matches.append({"symbol_index": index, "value": hex(value), "section_number": section_number, "aux_symbols": aux_count})
        next_index = index + 1 + aux_count
        if next_index > symbol_count:
            result["unknown_conditions"].append("coff_aux_symbols_out_of_bounds")
            return result
        offset += 18 * (1 + aux_count)
        index = next_index
    result["matches"] = matches
    if len(matches) != 1:
        result["unknown_conditions"].append("stub_symbol_not_unique")
        return result
    match = matches[0]
    section_number = int(match["section_number"])
    if section_number <= 0 or section_number > len(sections_info):
        result["unknown_conditions"].append("stub_symbol_section_invalid")
        return result
    section = sections_info[section_number - 1]
    value = int(str(match["value"]), 16)
    span = max(int(section["virtual_size"]), int(section["raw_size"]))
    if value >= span:
        result["unknown_conditions"].append("stub_symbol_value_outside_section")
        return result
    rva = int(section["virtual_address"]) + value
    result["section"] = {key: section[key] for key in ("index", "name", "virtual_size", "virtual_address", "raw_size", "raw_pointer")}
    result["rva"] = hex(rva)
    result["status"] = "observed"
    return result


def _coff_symbol(path: Path, symbol: str = STUB_SYMBOL) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size > 16 * 1024 * 1024:
            return {"status": "rejected", "source": "ordinary_pe_coff", "path": str(path), "reason": "file_size_limit"}
        raw = path.read_bytes()
        result = _coff_symbol_from_bytes(raw, symbol)
        result["path"] = str(path)
        result["file_sha256"] = hashlib.sha256(raw).hexdigest()
        result["file_size_bytes"] = len(raw)
        return result
    except (OSError, MemoryError) as exc:
        return {"status": "unavailable", "source": "ordinary_pe_coff", "path": str(path), "unknown_conditions": [f"read_failed:{type(exc).__name__}:{exc}"]}


def _absolute_patch(stub_va: int) -> bytes:
    if not _safe_address(stub_va):
        raise V23ProbeError("stub_va_invalid")
    return b"\xff\x25\0\0\0\0" + int(stub_va).to_bytes(8, "little") + b"\x90" * 7


def _retreat_absolute_patch(hook_va: int, patch_bytes: int = 28) -> bytes:
    if not _safe_address(hook_va) or patch_bytes < 14 or patch_bytes > 128:
        raise V23ProbeError("retreat_hook_va_or_patch_size_invalid")
    return b"\xff\x25\0\0\0\0" + int(hook_va).to_bytes(8, "little") + b"\x90" * (patch_bytes - 14)


def _retreat_specs_for_manifest(manifest: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    """Select the legacy two-entry contract or its explicit unit-removal extension."""
    present = (RETREAT_UNIT_REMOVAL_KEY in manifest,
               RETREAT_MAX_EXTENSION_VERSION_KEY in manifest)
    if not any(present):
        return RETREAT_ENTRY_SPECS
    if (not all(present)
            or manifest.get(RETREAT_UNIT_REMOVAL_KEY) is not True
            or type(manifest.get(RETREAT_MAX_EXTENSION_VERSION_KEY)) is not int
            or manifest[RETREAT_MAX_EXTENSION_VERSION_KEY] != 2):
        raise V23ProbeError("retreat_unit_removal_manifest_mismatch")
    return RETREAT_ENTRY_SPECS + (UNIT_REMOVAL_RETREAT_ENTRY_SPEC,)


def _installed_entry(stub_va: int) -> bytes:
    return _absolute_patch(stub_va) + ENTRY_PREFIX[PATCH_SIZE:]


def _guard_record(actual: bytes, expected: bytes, rva: int, label: str) -> dict[str, Any]:
    return {
        "label": label,
        "rva": hex(rva),
        "size_bytes": len(expected),
        "expected_sha256": hashlib.sha256(expected).hexdigest(),
        "actual_sha256": hashlib.sha256(actual).hexdigest(),
        "expected_hex": expected.hex(),
        "actual_hex": actual.hex(),
        "matches": actual == expected,
    }


def _file_code_guard(path: Path, *, include_retreat: bool = False,
                     retreat_specs: tuple[Mapping[str, Any], ...] | None = None) -> dict[str, Any]:
    """The on-disk executable remains the original image after a live patch."""
    result: dict[str, Any] = {"status": "unknown", "source": "ordinary_pe_file", "expected_phase": "original_image_on_disk", "records": {}, "unknown_conditions": []}
    try:
        entry = _loc._read_pe_rva_bytes(path, ENTRY_RVA, ENTRY_SIZE)
        unwind = _loc._read_pe_rva_bytes(path, UNWIND_RVA, UNWIND_SIZE)
        result["records"]["entry_238620_original"] = _guard_record(entry, ENTRY_PREFIX, ENTRY_RVA, "entry_original")
        result["records"]["unwind_1de6c98_original"] = _guard_record(unwind, UNWIND_PREFIX, UNWIND_RVA, "unwind_original")
        if include_retreat:
            for spec in RETREAT_ENTRY_SPECS if retreat_specs is None else retreat_specs:
                key = str(spec["key"])
                rva = int(spec["rva"])
                unwind_rva = int(spec["unwind_rva"])
                prefix = _loc._read_pe_rva_bytes(path, rva, len(spec["prefix"]))
                metadata = _loc._read_pe_rva_bytes(path, unwind_rva, len(spec["unwind"]))
                result["records"][f"retreat_{key}_entry_{rva:x}_original"] = _guard_record(
                    prefix, bytes(spec["prefix"]), rva, "retreat_entry_original")
                result["records"][f"retreat_{key}_unwind_{unwind_rva:x}_original"] = _guard_record(
                    metadata, bytes(spec["unwind"]), unwind_rva, "retreat_unwind_original")
        result["status"] = "observed" if all(item["matches"] for item in result["records"].values()) else "mismatch"
        if result["status"] != "observed":
            result["unknown_conditions"].append("on_disk_original_image_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"file_guard_failed:{type(exc).__name__}:{exc}")
    return result


class V23RPM:
    """One process handle, bounded RPM reads, and no write-capable API."""

    def __init__(self, kernel: Any, handle: Any, module_base: int):
        self.kernel = kernel
        self.handle = handle
        self.module_base = module_base
        self.bytes_requested = 0
        self.calls = 0
        self.read_log: list[dict[str, Any]] = []

    def read(self, address: int, size: int, label: str, *, aligned: bool = False) -> bytes:
        if not _safe_address(address, aligned=aligned):
            raise V23ProbeError(f"invalid_address:{label}")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0 or size > MAX_SINGLE_RPM:
            raise V23ProbeError(f"invalid_size:{label}")
        if address + size > MAX_USER_ADDRESS or self.bytes_requested + size > MAX_TOTAL_RPM:
            raise V23ProbeError("RPM_BUDGET_OR_ADDRESS_EXCEEDED")
        self.bytes_requested += size
        self.calls += 1
        item = {"label": label, "address": hex(address), "size": size, "status": "requested"}
        self.read_log.append(item)
        buffer = C.create_string_buffer(size)
        actual = C.c_size_t()
        try:
            ok = self.kernel.ReadProcessMemory(self.handle, C.c_void_p(address), buffer, size, C.byref(actual))
        except Exception as exc:
            item.update(status="error", error=f"{type(exc).__name__}:{exc}")
            raise
        if not ok:
            item.update(status="error", error="ReadProcessMemory_failed")
            raise C.WinError(C.get_last_error())
        if actual.value != size:
            item.update(status="error", error=f"short_read:{actual.value}/{size}")
            raise V23ProbeError(f"short_read:{label}:{actual.value}/{size}")
        item["status"] = "observed"
        return buffer.raw

    def qword(self, address: int, label: str) -> tuple[int, bytes]:
        raw = self.read(address, 8, label, aligned=True)
        return int.from_bytes(raw, "little"), raw

    def dword(self, address: int, label: str, *, signed: bool = False) -> tuple[int, bytes]:
        raw = self.read(address, 4, label)
        return int.from_bytes(raw, "little", signed=signed), raw

    def read_code(self, address: int, size: int, label: str) -> bytes:
        return self.read(address, size, label)


def _player_ref(value: int, raw: bytes) -> dict[str, Any]:
    tag_bytes = (value & 0xFFFFFF).to_bytes(3, "little")
    tag = tag_bytes.decode("ascii") if all(0x41 <= item <= 0x5A or 0x30 <= item <= 0x39 for item in tag_bytes) else None
    return {
        "value": hex(value),
        "raw_hex": raw.hex(),
        "tag": tag,
        "tag_raw_hex": tag_bytes.hex(),
        "slot": (value >> 32) & 0xFFFF,
        "format": "low24_ascii_tag_plus_bits32_47_slot",
        "complete": bool(value and tag is not None),
    }


def _snapshot(reader: V23RPM, module_base: int, phase: str) -> dict[str, Any]:
    result: dict[str, Any] = {"phase": phase, "status": "unknown", "game_pointer": None, "physical_player": None, "game_date": None, "control": None, "unknown_conditions": []}
    try:
        game_address = module_base + GAME_RVA
        game, game_raw = reader.qword(game_address, f"{phase}.game_pointer")
        if not _safe_address(game, aligned=True):
            raise V23ProbeError("game_pointer_invalid")
        date_raw = reader.read(game + GAME_DATE_OFFSET, 4, f"{phase}.game_date")
        player, player_raw = reader.qword(game + GAME_PLAYER_OFFSET, f"{phase}.physical_player")
        control = _war._control_state(reader, module_base, game)
        result.update({
            "game_pointer": {"address": hex(game_address), "rva": hex(GAME_RVA), "value": hex(game), "raw_hex": game_raw.hex()},
            "physical_player": _player_ref(player, player_raw),
            "game_date": {"address": hex(game + GAME_DATE_OFFSET), "offset": hex(GAME_DATE_OFFSET), "raw": int.from_bytes(date_raw, "little", signed=True), "raw_hex": date_raw.hex()},
            "control": control,
        })
        if not result["physical_player"]["complete"]:
            result["unknown_conditions"].append("physical_player_reference_not_complete")
        if control.get("status") != "observed":
            result["unknown_conditions"].append("pause_speed_control_unknown")
        result["status"] = "observed" if not result["unknown_conditions"] else "unknown"
    except Exception as exc:
        result["unknown_conditions"].append(f"snapshot_failed:{type(exc).__name__}:{exc}")
    return result


def _runtime_code_guard(reader: V23RPM, module_base: int, phase: str, expect_patch: str,
                        stub_va: int, retreat_hook_vas: Mapping[str, int] | None = None,
                        retreat_specs: tuple[Mapping[str, Any], ...] | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"phase": phase, "source": "rpm", "status": "unknown", "expect_patch": expect_patch, "records": {}, "unknown_conditions": []}
    try:
        expected_entry = ENTRY_PREFIX if expect_patch == "original" else _installed_entry(stub_va)
        actual_entry = reader.read_code(module_base + ENTRY_RVA, ENTRY_SIZE, f"{phase}.entry_238620")
        actual_unwind = reader.read_code(module_base + UNWIND_RVA, UNWIND_SIZE, f"{phase}.unwind_1de6c98")
        result["records"]["entry_238620"] = _guard_record(actual_entry, expected_entry, ENTRY_RVA, f"{expect_patch}_entry")
        result["records"]["unwind_1de6c98"] = _guard_record(actual_unwind, UNWIND_PREFIX, UNWIND_RVA, "unwind_unchanged")
        if expect_patch == "installed":
            result["installed_shape"] = {
                "ff25": actual_entry[:2].hex(),
                "rip_displacement_zero": actual_entry[2:6] == b"\0" * 4,
                "stub_pointer_raw_hex": actual_entry[6:14].hex(),
                "stub_pointer": hex(int.from_bytes(actual_entry[6:14], "little")),
                "seven_nop": actual_entry[14:21] == b"\x90" * 7,
                "tail_is_original": actual_entry[21:] == ENTRY_PREFIX[21:],
                "stub_pointer_matches_coff": int.from_bytes(actual_entry[6:14], "little") == stub_va,
            }
        if retreat_hook_vas is not None:
            selected_retreat_specs = RETREAT_ENTRY_SPECS if retreat_specs is None else retreat_specs
            expected_keys = {str(spec["key"]) for spec in selected_retreat_specs}
            if set(retreat_hook_vas) != expected_keys:
                raise V23ProbeError("retreat_hook_symbol_set_invalid")
            for spec in selected_retreat_specs:
                key = str(spec["key"])
                rva = int(spec["rva"])
                unwind_rva = int(spec["unwind_rva"])
                hook_va = retreat_hook_vas[key]
                expected_retreat_entry = (
                    bytes(spec["prefix"]) if expect_patch == "original"
                    else _retreat_absolute_patch(hook_va, int(spec["patch_bytes"]))
                )
                actual_retreat_entry = reader.read_code(
                    module_base + rva, int(spec["patch_bytes"]),
                    f"{phase}.retreat_{key}_entry_{rva:x}")
                actual_retreat_unwind = reader.read_code(
                    module_base + unwind_rva, len(spec["unwind"]),
                    f"{phase}.retreat_{key}_unwind_{unwind_rva:x}")
                result["records"][f"retreat_{key}_entry_{rva:x}"] = _guard_record(
                    actual_retreat_entry, expected_retreat_entry, rva,
                    f"{expect_patch}_retreat_entry")
                result["records"][f"retreat_{key}_unwind_{unwind_rva:x}"] = _guard_record(
                    actual_retreat_unwind, bytes(spec["unwind"]), unwind_rva,
                    "retreat_unwind_unchanged")
                if expect_patch == "installed":
                    result.setdefault("retreat_installed_shapes", {})[key] = {
                        "ff25": actual_retreat_entry[:2].hex(),
                        "rip_displacement_zero": actual_retreat_entry[2:6] == b"\0" * 4,
                        "hook_pointer": hex(int.from_bytes(actual_retreat_entry[6:14], "little")),
                        "hook_pointer_matches_coff": int.from_bytes(actual_retreat_entry[6:14], "little") == hook_va,
                        "nops_after_jump": actual_retreat_entry[14:] == b"\x90" * (int(spec["patch_bytes"]) - 14),
                    }
        result["status"] = "observed" if all(item["matches"] for item in result["records"].values()) else "mismatch"
        if result["status"] != "observed":
            result["unknown_conditions"].append("runtime_code_guard_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"runtime_guard_failed:{type(exc).__name__}:{exc}")
    return result


def _module_path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(str(path.resolve())))


def _query_module_records(kernel: Any, handle: Any, expected_path: Path, expected_sha: str) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "unknown", "source": "rpm", "expected_path": str(expected_path.resolve()), "expected_sha256": expected_sha, "loaded_module_count": None, "modules": [], "matching_modules": [], "unknown_conditions": []}
    try:
        modules = (W.HMODULE * 1024)()
        needed = W.DWORD()
        if not kernel.K32EnumProcessModulesEx(handle, modules, C.sizeof(modules), C.byref(needed), 3):
            raise C.WinError(C.get_last_error())
        if not needed.value or needed.value % C.sizeof(W.HMODULE):
            raise V23ProbeError("module_list_invalid")
        count = needed.value // C.sizeof(W.HMODULE)
        if count > 1024:
            raise V23ProbeError("module_list_out_of_bound")
        result["loaded_module_count"] = count
        expected_key = _module_path_key(expected_path)
        name_buffer = C.create_unicode_buffer(32768)
        for index in range(count):
            module = modules[index]
            module_base = int(getattr(module, "value", module))
            length = int(kernel._probe_get_module_name(handle, module, name_buffer, len(name_buffer)))
            if length <= 0 or length >= len(name_buffer):
                result["modules"].append({"index": index, "base": hex(module_base), "status": "unknown", "unknown_reason": "module_path_unavailable"})
                continue
            path = Path(name_buffer.value).resolve()
            record: dict[str, Any] = {"index": index, "base": hex(module_base), "path": str(path), "path_matches_expected": _module_path_key(path) == expected_key}
            if record["path_matches_expected"]:
                pin = _stable_file_pin(path, max_bytes=16 * 1024 * 1024)
                record["sha256"] = pin.get("sha256")
                record["size_bytes"] = pin.get("size_bytes")
                record["sha256_matches_expected"] = pin.get("sha256") == expected_sha
            else:
                record["sha256"] = None
                record["sha256_matches_expected"] = None
            result["modules"].append(record)
            if record.get("path_matches_expected") is True and record.get("sha256_matches_expected") is True:
                result["matching_modules"].append(record)
        if len(result["matching_modules"]) == 1:
            result["status"] = "observed"
        elif not result["matching_modules"]:
            result["unknown_conditions"].append("expected_loaded_observer_dll_not_unique")
        else:
            result["unknown_conditions"].append("expected_loaded_observer_dll_loaded_multiple_times")
    except Exception as exc:
        result["unknown_conditions"].append(f"module_enumeration_failed:{type(exc).__name__}:{exc}")
    return result


def _capture_identity(kernel: Any, handle: Any, document: Mapping[str, Any], expected_exe: Path, phase: str) -> dict[str, Any]:
    result: dict[str, Any] = {"phase": phase, "status": "unknown", "pid": None, "process_creation_filetime": None, "session_id": None, "process_path": None, "process_path_sha256": None, "module_base": None, "unknown_conditions": []}
    try:
        pid = _int(document.get("pid"), "installation_pid")
        expected_creation = _int(document.get("creation_filetime"), "installation_creation_filetime")
        process_name = C.create_unicode_buffer(32768)
        process_length = W.DWORD(len(process_name))
        if not kernel.QueryFullProcessImageNameW(handle, 0, process_name, C.byref(process_length)):
            raise C.WinError(C.get_last_error())
        process_path = Path(process_name.value).resolve()
        process_sha = _sha256_file(process_path)
        created, exited, kernel_time, user_time = (W.FILETIME() for _ in range(4))
        if not kernel.GetProcessTimes(handle, C.byref(created), C.byref(exited), C.byref(kernel_time), C.byref(user_time)):
            raise C.WinError(C.get_last_error())
        creation = (created.dwHighDateTime << 32) | created.dwLowDateTime
        session = f"{pid}-{creation:x}"
        result.update({"pid": pid, "process_creation_filetime": creation, "process_creation_utc": _utc_filetime(creation), "session_id": session, "process_path": str(process_path), "process_path_sha256": process_sha, "process_path_sha256_matches_expected": process_sha.lower() == EXPECTED_EXE_SHA256, "creation_matches_installation": creation == expected_creation, "session_matches_installation": session == document.get("session_id")})
        modules = (W.HMODULE * 1024)(); needed = W.DWORD()
        if not kernel.K32EnumProcessModulesEx(handle, modules, C.sizeof(modules), C.byref(needed), 3):
            raise C.WinError(C.get_last_error())
        if not needed.value or needed.value % C.sizeof(W.HMODULE):
            raise V23ProbeError("module_list_invalid")
        module_count = needed.value // C.sizeof(W.HMODULE)
        if module_count > 1024:
            raise V23ProbeError("module_list_out_of_bound")
        name_buffer = C.create_unicode_buffer(32768)
        matching_exe_modules: list[int] = []
        for index in range(module_count):
            module = modules[index]
            length = int(kernel._probe_get_module_name(handle, module, name_buffer, len(name_buffer)))
            if length <= 0 or length >= len(name_buffer):
                continue
            module_path = Path(name_buffer.value).resolve()
            if module_path == process_path:
                matching_exe_modules.append(int(getattr(module, "value", module)))
        if len(matching_exe_modules) != 1:
            raise V23ProbeError("process_image_module_not_unique")
        game_module = matching_exe_modules[0]
        result["module_base"] = hex(game_module)
        result["module_count"] = module_count
        result["process_image_module_count"] = len(matching_exe_modules)
        result["module_base_canonical_aligned"] = _safe_address(game_module, aligned=True)
        result["status"] = "observed" if (
            process_path.resolve() == expected_exe.resolve()
            and result["process_path_sha256_matches_expected"] is True
            and result["creation_matches_installation"] is True
            and result["session_matches_installation"] is True
            and result["module_base_canonical_aligned"] is True
        ) else "mismatch"
        if result["status"] != "observed":
            result["unknown_conditions"].append("process_identity_or_session_mismatch")
    except Exception as exc:
        result["unknown_conditions"].append(f"identity_capture_failed:{type(exc).__name__}:{exc}")
    return result


def _load_document(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    document, pin = _read_json_bounded(path)
    if document is None:
        raise V23ProbeError("installation_json_unavailable")
    return document, pin


def _base_report(installation: Path, output: Path, expect_patch: str) -> dict[str, Any]:
    return {
        "schema": "information_battle_observer_v23_preflight_v1",
        "probe": "information-battle-v23",
        "probe_version": 1,
        "probe_script": _rel(Path(__file__).resolve()),
        "probe_script_sha256": None,
        "read_only": True,
        "evidence_kind": "fresh_pure_rpm_preflight",
        "request": {"installation": _rel(installation), "output": _rel(output), "expect_patch": expect_patch, "business_query_invoked": False, "native_game_function_invoked": False, "target_memory_writes": False, "dll_injection": False, "dll_unload": False, "control_command_sent": False, "save_or_reload": False, "date_advance": False},
        "target_build": {"version": EXPECTED_VERSION, "expected_exe_sha256": EXPECTED_EXE_SHA256, "expected_dll_sha256": EXPECTED_DLL_SHA256, "build_id": BUILD_ID, "image_base": hex(EXPECTED_IMAGE_BASE), "open_process_mask_hex": hex(PROCESS_ACCESS), "entry_rva": hex(ENTRY_RVA), "unwind_rva": hex(UNWIND_RVA)},
        "provenance": {"source": None, "ordinary_pe_coff": None, "rpm": {"status": "not_run"}},
        "installation": None,
        "identity": {"before": None, "after": None, "binding_verified": False},
        "loaded_dll": {"before": None, "after": None, "same_path_sha": None},
        "module_base": None,
        "stub": None,
        "fixed_file_code_guard": None,
        "runtime_code_guard": {"before": None, "after": None},
        "before": None,
        "after": None,
        "doublepass": {"performed": False, "consistent": None, "mismatches": []},
        "access": {"rpm_total_limit": MAX_TOTAL_RPM, "rpm_single_read_limit": MAX_SINGLE_RPM, "rpm_bytes_requested": 0, "rpm_calls": 0, "read_log": []},
        "cleanup": {"handle_close": {"status": "unknown", "success": None, "closed": False, "calls": 0}},
        "status": "starting",
        "errors": [],
        "completed": False,
    }


def _write_new(path: Path, value: Mapping[str, Any]) -> str:
    if path.exists():
        raise V23ProbeError(f"output_exists:{path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > 2 * 1024 * 1024:
        raise V23ProbeError("report_size_limit")
    temp = path.with_name(path.name + ".tmp")
    try:
        temp.write_bytes(raw)
        temp.replace(path)
    finally:
        if temp.exists():
            temp.unlink()
    return hashlib.sha256(raw).hexdigest()


def _static_prepare(report: dict[str, Any], build_dir: Path = BUILD_DIR) -> dict[str, Any]:
    report["probe_script_sha256"] = _sha256_file(Path(__file__).resolve())
    build_dir = build_dir.resolve()
    build_manifest_path = build_dir / "build-manifest.json"
    source = _manifest_static_guard(build_dir)
    report["provenance"]["source"] = source
    manifest_json, _ = _read_json_bounded(build_manifest_path, MAX_MANIFEST_BYTES)
    if not isinstance(manifest_json, Mapping):
        raise V23ProbeError("battle_build_manifest_unavailable")
    version = manifest_json.get("version")
    if type(version) is not int or version not in (23, 34, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 51, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64):
        raise V23ProbeError("unsupported_observer_build_version")
    if version in RETREAT_SUPPORTED_VERSIONS:
        retreat_specs = _retreat_specs_for_manifest(manifest_json)
    else:
        if (RETREAT_UNIT_REMOVAL_KEY in manifest_json
                or RETREAT_MAX_EXTENSION_VERSION_KEY in manifest_json):
            raise V23ProbeError("retreat_unit_removal_manifest_mismatch")
        retreat_specs = ()
    dll_path = build_dir / f"eu4_bridge_diplomacy_observer_v{version}.dll"
    expected_dll_sha = str(manifest_json.get("dll_sha256", "")).lower()
    dll_pin = _stable_file_pin(dll_path, max_bytes=16 * 1024 * 1024)
    pe = (_coff_symbol(dll_path)
          if dll_pin.get("status") == "observed" and dll_pin.get("sha256") == expected_dll_sha
          else {"status": "unknown", "source": "ordinary_pe_coff",
                "unknown_conditions": ["dll_pin_missing_or_sha_mismatch"]})
    report["provenance"]["ordinary_pe_coff"] = pe
    report["stub"] = {"symbol": STUB_SYMBOL, "rva": pe.get("rva"), "source": "ordinary_pe_coff", "status": pe.get("status")}
    retreat_hooks: dict[str, dict[str, Any]] = {}
    retreat_hook_rvas: dict[str, str] = {}
    if retreat_specs:
        for spec in retreat_specs:
            key = str(spec["key"])
            symbol = str(spec["symbol"])
            hook = (_coff_symbol(dll_path, symbol)
                    if dll_pin.get("status") == "observed"
                    and dll_pin.get("sha256") == expected_dll_sha
                    else {"status": "unknown", "source": "ordinary_pe_coff",
                          "symbol": symbol,
                          "unknown_conditions": ["dll_pin_missing_or_sha_mismatch"]})
            retreat_hooks[key] = hook
            if hook.get("status") != "observed" or not isinstance(hook.get("rva"), str):
                raise V23ProbeError(f"retreat_hook_coff_symbol_unavailable:{key}")
            retreat_hook_rvas[key] = str(hook["rva"])
        report["retreat_hooks"] = retreat_hooks
    manifest_value = source.get("manifest") if isinstance(source.get("manifest"), Mapping) else {}
    report["target_build"].update({
        "build_id": manifest_json.get("experiment_id") if isinstance(manifest_json, Mapping) else None,
        "build_directory": _rel(build_dir),
        "observer_version": version,
        "expected_dll_sha256": expected_dll_sha,
        "dll_path": _rel(dll_path),
        "manifest": {"path": _rel(build_manifest_path), "sha256": manifest_value.get("sha256")},
        "source_manifest": {"path": source.get("source_manifest", {}).get("path") if isinstance(source.get("source_manifest"), Mapping) else None, "sha256": source.get("source_manifest", {}).get("sha256") if isinstance(source.get("source_manifest"), Mapping) else None},
    })
    report["target_build"]["dll"] = dll_pin
    if retreat_specs:
        report["target_build"]["retreat_entry_specs"] = [
            {
                "key": str(spec["key"]),
                "symbol": str(spec["symbol"]),
                "rva": hex(int(spec["rva"])),
                "end_rva": hex(int(spec["end_rva"])),
                "unwind_rva": hex(int(spec["unwind_rva"])),
                "prefix_hex": bytes(spec["prefix"]).hex(),
                "unwind_hex": bytes(spec["unwind"]).hex(),
                **({
                    "projected_unwind_bytes": int(spec["projected_unwind_bytes"]),
                    "stack_delta": hex(int(spec["stack_delta"])),
                    "home_slot_offset": hex(int(spec["home_slot_offset"])),
                    "current_rsp_home_slot_offset": hex(
                        int(spec["stack_delta"]) + int(spec["home_slot_offset"])),
                } if str(spec["key"]) == "unit_removal" else {}),
            }
            for spec in retreat_specs
        ]
        report["target_build"]["retreat_hook_rvas"] = dict(retreat_hook_rvas)
    if source.get("status") != "observed":
        raise V23ProbeError("battle_source_manifest_guard_failed")
    if dll_pin.get("sha256") != expected_dll_sha:
        raise V23ProbeError("battle_dll_sha256_mismatch")
    if pe.get("status") != "observed" or not isinstance(pe.get("rva"), str):
        raise V23ProbeError("entry_stub_coff_symbol_unavailable")
    return {
        "manifest": dict(manifest_json),
        "dll_path": dll_path,
        "dll_sha256": expected_dll_sha,
        "retreat_hook_rvas": retreat_hook_rvas,
        "retreat_entry_specs": retreat_specs,
    }


def _assert_installation_build_binding(document: Mapping[str, Any], build: Mapping[str, Any]) -> None:
    manifest = build.get("manifest")
    if not isinstance(manifest, Mapping):
        raise V23ProbeError("validated_build_manifest_missing")
    if (document.get("experiment_id") != manifest.get("experiment_id")
            or str(document.get("game_sha256", "")).lower() != EXPECTED_EXE_SHA256
            or str(document.get("game_sha256", "")).lower()
                != str(manifest.get("game_sha256", "")).lower()
            or str(document.get("dll_sha256", "")).lower()
                != str(build.get("dll_sha256", "")).lower()):
        raise V23ProbeError("installation_build_identity_mismatch")


def plan_report(output: Path) -> dict[str, Any]:
    """Write a static, explicit not-run report before a v23 installation exists."""
    installation = DEFAULT_INSTALLATION
    report = _base_report(installation, output, "original")
    try:
        _static_prepare(report)
        report["status"] = "not_run_waiting_for_v23_installation"
        report["runtime_accessed"] = False
        report["completed"] = True
        report["errors"].append({"stage": "runtime", "status": "unknown", "error": "no_new_v23_installation_provided; no_process_opened"})
    except Exception as exc:
        report["status"] = "failed_static_preflight"
        report["runtime_accessed"] = False
        report["errors"].append({"stage": "static", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
        report["completed"] = True
    _write_new(output, report)
    return report


def run(installation: Path, output: Path, expect_patch: str) -> dict[str, Any]:
    if expect_patch not in {"original", "installed"}:
        raise V23ProbeError("expect_patch_must_be_original_or_installed")
    report = _base_report(installation, output, expect_patch)
    kernel = None
    handle = None
    reader: V23RPM | None = None
    try:
        document, install_pin = _load_document(installation)
        build_dir = installation.resolve().parent
        build = _static_prepare(report, build_dir)
        observer_version = build["manifest"]["version"]
        report["installation"] = {"file": install_pin, "experiment_id": document.get("experiment_id"), "recorded_pid": document.get("pid"), "recorded_creation_filetime": document.get("creation_filetime"), "recorded_session_id": document.get("session_id"), "recorded_game_sha256": str(document.get("game_sha256", "")).lower(), "recorded_dll_sha256": str(document.get("dll_sha256", "")).lower()}
        _assert_installation_build_binding(document, build)
        expected_dll_sha = str(build["dll_sha256"])
        pid = _int(document.get("pid"), "installation_pid")
        expected_creation = _int(document.get("creation_filetime"), "installation_creation_filetime")
        session = document.get("session_id")
        if not isinstance(session, str) or session != f"{pid}-{expected_creation:x}":
            raise V23ProbeError("installation_session_id_mismatch")
        process_path_declared = document.get("process_path") or document.get("game_path")
        if isinstance(process_path_declared, str) and process_path_declared:
            expected_exe = Path(process_path_declared).resolve()
        else:
            # start_diplomacy_observer.py records the identity returned by
            # bridge.diplomacy_session.probe_identity, which intentionally
            # stores the EXE hash but not its path.  Resolve the operator's
            # configured game path rather than inventing a path from the
            # installation directory.
            expected_exe = Path(_configured_game_exe()).resolve()
        if not expected_exe.is_file():
            raise V23ProbeError("configured_process_path_missing")
        kernel = _loc._configure_kernel()
        handle = kernel.OpenProcess(PROCESS_ACCESS, False, pid)
        if not handle:
            raise C.WinError(C.get_last_error())
        identity_before = _capture_identity(kernel, handle, document, expected_exe, "before")
        report["identity"]["before"] = identity_before
        if identity_before.get("status") != "observed":
            raise V23ProbeError("fresh_process_identity_before_failed")
        module_base = int(str(identity_before["module_base"]), 0)
        report["module_base"] = {"value": hex(module_base), "static_pe_image_base": hex(EXPECTED_IMAGE_BASE), "rvas_resolved_against_runtime_base": True}
        loaded_dll_path = Path(build["dll_path"])
        loaded_before = _query_module_records(kernel, handle, loaded_dll_path, expected_dll_sha)
        report["loaded_dll"]["before"] = loaded_before
        if loaded_before.get("status") != "observed":
            raise V23ProbeError("loaded_observer_dll_before_failed")
        dll_module_base = int(loaded_before["matching_modules"][0]["base"], 0)
        stub_rva = int(str(report["stub"]["rva"]), 0)
        stub_va = dll_module_base + stub_rva
        report["stub"].update({"dll_module_base": hex(dll_module_base), "rva": hex(stub_rva), "expected_runtime_va": hex(stub_va), "runtime_va_is_derived_from_loaded_module": True})
        if not _safe_address(stub_va):
            raise V23ProbeError("derived_stub_va_invalid")
        retreat_hook_vas = None
        retreat_specs = build.get("retreat_entry_specs") or None
        if retreat_specs is not None:
            retreat_hook_vas = {
                key: dll_module_base + int(rva, 0)
                for key, rva in build["retreat_hook_rvas"].items()
            }
            if any(not _safe_address(value) for value in retreat_hook_vas.values()):
                raise V23ProbeError("derived_retreat_hook_va_invalid")
            report["retreat_hooks"].update({
                key: {**value, "dll_module_base": hex(dll_module_base),
                      "expected_runtime_va": hex(retreat_hook_vas[key]),
                      "runtime_va_is_derived_from_loaded_module": True}
                for key, value in report["retreat_hooks"].items()
            })
        report["fixed_file_code_guard"] = _file_code_guard(
            expected_exe, include_retreat=retreat_specs is not None,
            retreat_specs=retreat_specs)
        if report["fixed_file_code_guard"].get("status") != "observed":
            raise V23ProbeError("on_disk_original_code_guard_failed")
        reader = V23RPM(kernel, handle, module_base)
        report["runtime_code_guard"]["before"] = _runtime_code_guard(
            reader, module_base, "before", expect_patch, stub_va, retreat_hook_vas,
            retreat_specs)
        report["before"] = _snapshot(reader, module_base, "before")
        if report["runtime_code_guard"]["before"].get("status") != "observed" or report["before"].get("status") != "observed":
            raise V23ProbeError("before_runtime_guard_or_context_failed")
        identity_after = _capture_identity(kernel, handle, document, expected_exe, "after")
        report["identity"]["after"] = identity_after
        loaded_after = _query_module_records(kernel, handle, loaded_dll_path, expected_dll_sha)
        report["loaded_dll"]["after"] = loaded_after
        report["runtime_code_guard"]["after"] = _runtime_code_guard(
            reader, module_base, "after", expect_patch, stub_va, retreat_hook_vas,
            retreat_specs)
        report["after"] = _snapshot(reader, module_base, "after")
        report["doublepass"]["performed"] = True
        identity_before_compare = {key: value for key, value in identity_before.items() if key != "phase"}
        identity_after_compare = {key: value for key, value in identity_after.items() if key != "phase"}
        comparisons = {
            "identity": identity_before_compare == identity_after_compare,
            "loaded_dll": loaded_before == loaded_after,
            "before_after_snapshot": report["before"] == {**report["after"], "phase": "before"},
            "runtime_guard_before_after": report["runtime_code_guard"]["before"].get("records") == report["runtime_code_guard"]["after"].get("records"),
        }
        report["doublepass"]["checks"] = comparisons
        report["doublepass"]["consistent"] = all(comparisons.values())
        report["identity"]["binding_verified"] = identity_after.get("status") == "observed" and identity_before.get("session_id") == identity_after.get("session_id") == session
        report["loaded_dll"]["same_path_sha"] = loaded_before == loaded_after
        if report["runtime_code_guard"]["after"].get("status") != "observed" or report["after"].get("status") != "observed" or not report["doublepass"]["consistent"] or report["identity"]["binding_verified"] is not True or loaded_after.get("status") != "observed":
            raise V23ProbeError("after_or_doublepass_guard_failed")
        report["provenance"]["rpm"] = {"status": "observed", "process_access": hex(PROCESS_ACCESS), "same_handle_before_after": True}
        report["status"] = "passed_read_only_preflight"
    except Exception as exc:
        report["status"] = "failed_read_only_preflight"
        report["errors"].append({"stage": "preflight", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"})
    finally:
        if reader is not None:
            report["access"].update({"rpm_bytes_requested": reader.bytes_requested, "rpm_calls": reader.calls, "read_log": list(reader.read_log)})
        close = _loc._close_process_handle(kernel, handle)
        close["calls"] = 1 if close.get("status") == "closed" else 0
        report["cleanup"]["handle_close"] = close
        report["completed"] = True
        if report["status"] == "passed_read_only_preflight" and close.get("status") != "closed":
            report["status"] = "failed_read_only_preflight"
            report["errors"].append({"stage": "cleanup", "status": "unknown", "error": "process_handle_not_closed"})
    _write_new(output, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, default=DEFAULT_INSTALLATION)
    parser.add_argument("--expect-patch", choices=("original", "installed"), default="original")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--plan-only", action="store_true", help="write the explicit not-run static report; never opens a process")
    args = parser.parse_args(argv)
    try:
        report = plan_report(args.output.resolve()) if args.plan_only else run(args.installation.resolve(), args.output.resolve(), args.expect_patch)
    except Exception as exc:
        print(json.dumps({"status": "failed_to_write_report", "error": f"{type(exc).__name__}:{exc}"}, ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "output": str(args.output.resolve()), "errors": report["errors"]}, ensure_ascii=False))
    return 0 if report["status"] in {"passed_read_only_preflight", "not_run_waiting_for_v23_installation"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
