"""Resolve the installed observer's registry layout from its verified artifact."""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import struct

from bridge.diplomacy_session import _file_hash_metadata, file_hash
from work.find_native_string_references import (
    _file_offset_for_rva, _read_at, parse_pe, read_coff_symbols,
)

ROOT = Path(__file__).resolve().parents[2]
GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
MAX_JSON_BYTES = 1024 * 1024


def _document(path):
    if not 0 < path.stat().st_size <= MAX_JSON_BYTES:
        raise ValueError("OBSERVER_REGISTRY_DOCUMENT_SIZE")
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("OBSERVER_REGISTRY_DOCUMENT_SHAPE")
    return value


def _static_symbol(name):
    return f"_ZL{len(name)}{name}"


def _code_guard(path, pe, symbols):
    function_starts = dict(pe["runtime_functions"])
    candidates = sorted(set(symbols.values()) & function_starts.keys())
    # Data symbols are excluded by the executable unwind ranges.
    if not candidates:
        raise ValueError("OBSERVER_REGISTRY_CODE_SYMBOL_MISSING")
    start = candidates[0]
    end = function_starts[start]
    if not 0 < end - start <= 16384:
        raise ValueError("OBSERVER_REGISTRY_CODE_SIZE")
    offset = _file_offset_for_rva(pe["sections"], start)
    if offset is None:
        raise ValueError("OBSERVER_REGISTRY_CODE_RANGE")
    with path.open("rb") as stream:
        raw = _read_at(stream, pe["file_size"], offset, end - start)
        relocations = []
        directory = pe["relocation_directory"]
        cursor, size = directory["rva"], directory["size"]
        if size > 2 * 1024 * 1024:
            raise ValueError("OBSERVER_REGISTRY_RELOCATION_SIZE")
        stop = cursor + size
        while cursor < stop:
            block_offset = _file_offset_for_rva(pe["sections"], cursor)
            if block_offset is None:
                raise ValueError("OBSERVER_REGISTRY_RELOCATION_RANGE")
            page, width = struct.unpack("<II", _read_at(stream, pe["file_size"], block_offset, 8))
            if width < 8 or width % 2 or cursor + width > stop:
                raise ValueError("OBSERVER_REGISTRY_RELOCATION_BLOCK")
            entries = _read_at(stream, pe["file_size"], block_offset + 8, width - 8)
            for (entry,) in struct.iter_unpack("<H", entries):
                kind, address = entry >> 12, page + (entry & 0xfff)
                if kind and start <= address < end:
                    if kind != 10 or address + 8 > end:
                        raise ValueError("OBSERVER_REGISTRY_RELOCATION_TYPE")
                    relocations.append(address - start)
            cursor += width
    return {"rva": hex(start), "end_rva_exclusive": hex(end), "bytes": raw.hex(),
            "sha256": hashlib.sha256(raw).hexdigest(), "relocation_offsets": relocations}


# Artifact signatures invalidate the bounded descriptor cache.
@lru_cache(maxsize=16)
def _layout(dll_name, manifest_name, dll_signature, manifest_signature, expected_sha256):
    from tools.start_diplomacy_observer import _validate_information_battle_manifest

    dll, manifest_path = Path(dll_name), Path(manifest_name)
    manifest = _document(manifest_path)
    if (manifest.get("dll_sha256") != expected_sha256 or file_hash(dll) != expected_sha256
            or manifest.get("game_sha256") != GAME_SHA256
            or Path(manifest["dll"]).resolve() != dll):
        raise ValueError("OBSERVER_REGISTRY_ARTIFACT_BINDING")
    try:
        _validate_information_battle_manifest(manifest, manifest_path.parent)
    except SystemExit as exc:
        raise ValueError("OBSERVER_REGISTRY_BUILD_CONTRACT") from exc
    if not 0 < dll.stat().st_size <= 128 * 1024 * 1024:
        raise ValueError("OBSERVER_REGISTRY_DLL_SIZE")
    pe = parse_pe(dll)
    variables = {key: _static_symbol(value) for key, value in (
        ("entries_rva", "peace_war_registry"),
        ("count_rva", "peace_war_registry_size"),
        ("creation_rva", "observation_creation"),
        ("revision_rva", "peace_war_registry_revision"),
    )}
    symbols = read_coff_symbols(dll, pe, names=variables.values(), prefixes=(
        _static_symbol("peace_query_register_war"),
        "_ZN11information12war_registry8Registry12register_warE",
    ))
    descriptor = {key: symbols[name] for key, name in variables.items() if name in symbols}
    if not {"entries_rva", "count_rva", "creation_rva"} <= descriptor.keys():
        raise ValueError("OBSERVER_REGISTRY_DATA_SYMBOL_MISSING")
    header_size = max(512, pe["pe_offset"] + 24 + pe["optional_header_size"])
    if header_size > 4096:
        raise ValueError("OBSERVER_REGISTRY_HEADER_SIZE")
    with dll.open("rb") as stream:
        header = _read_at(stream, pe["file_size"], 0, header_size)
    descriptor.update(
        module_file={"path": dll.relative_to(ROOT).as_posix(),
                     "bytes": pe["file_size"], "sha256": expected_sha256},
        image_size=pe["image_size"], header_raw_hex=header.hex(),
        header_image_base_offset=pe["pe_offset"] + 48,
        preferred_image_base=hex(pe["image_base"]),
        code_guards=[_code_guard(dll, pe, symbols)],
    )
    if "revision_rva" in descriptor:
        descriptor["registry_format"] = "reusable_slots_v1"
    return descriptor


def descriptor_for_installation(installation):
    """Return an admitted current layout, or None for the pinned fallback."""
    try:
        installation = Path(installation).resolve()
        document = _document(installation)
        expected = document["dll_sha256"]
        rows = document.get("modules_after_install", [])
        if not isinstance(rows, list):
            return None
        modules = [row for row in rows if isinstance(row, dict) and row.get("sha256") == expected]
        if len(modules) != 1 or document.get("game_sha256") != GAME_SHA256:
            return None
        dll = Path(modules[0]["path"]).resolve()
        dll.relative_to(ROOT)
        if dll.parent != installation.parent:
            return None
        manifest = installation.parent / "build-manifest.json"
        _, dll_signature = _file_hash_metadata(dll)
        _, manifest_signature = _file_hash_metadata(manifest)
        return deepcopy(_layout(str(dll), str(manifest), dll_signature, manifest_signature, expected))
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, struct.error):
        return None
