"""Bounded proof of the B23 AI-choice predicate address and installed hook.

The proof accepts only the stock native-true stub or the pinned v33 GUI
forwarding hook. It does not verify the whole loaded DLL and does not cover
the AI-turn hold path.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import foreign_quality_visibility_memory as _common


SCHEMA = "information.native_ai_choice_mapping_memory.v1"
ASSET_RELATIVE_PATH = "profiles/native-ai-choice-hook-v33.json"
ASSET_SHA256 = "4efce12378fa3b7fc0a72911243c12b9c2af0ee26b33de6c72b14c3402aa807f"
HOOK_DLL_SHA256 = "74cd03fc970b499adc5202b033add24197835a68147730e3998ee0dc94fb699e"
HOOK_POINTER_DELTA = 0x56850
HOOK_DOS_PREFIX_SIZE = 64
HOOK_COFF_PREFIX_SIZE = 24
HOOK_MAGIC_SIZE = 2
HOOK_SIZE_OF_IMAGE_SIZE = 4
MAX_ASSET_BYTES = 8192


def _unknown(reason: str) -> None:
    raise _common._Unknown(reason)


def _asset() -> tuple[dict[str, Any], bytes]:
    path = Path(__file__).resolve().parent / ASSET_RELATIVE_PATH
    try:
        if path.stat().st_size > MAX_ASSET_BYTES:
            _unknown("CHOICE_MAPPING_ASSET_SIZE_INVALID")
        raw = path.read_bytes()
    except _common._Unknown:
        raise
    except Exception as exc:
        raise _common._Unknown("CHOICE_MAPPING_ASSET_UNAVAILABLE") from exc
    if hashlib.sha256(raw).hexdigest() != ASSET_SHA256:
        _unknown("CHOICE_MAPPING_ASSET_PIN_MISMATCH")
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise _common._Unknown("CHOICE_MAPPING_ASSET_INVALID") from exc
    if (type(value) is not dict
            or value.get("schema") != "information.native_ai_choice_hook_contract.v1"
            or value.get("dll_sha256") != HOOK_DLL_SHA256):
        _unknown("CHOICE_MAPPING_ASSET_INVALID")
    return value, raw


def _asset_bytes(asset: dict[str, Any], key: str, expected_size: int) -> bytes:
    encoded = asset.get(key)
    if type(encoded) is not str:
        _unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID")
    try:
        value = bytes.fromhex(encoded)
    except ValueError as exc:
        raise _common._Unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID") from exc
    if len(value) != expected_size or value.hex() != encoded.lower():
        _unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID")
    return value


def _asset_int(asset: dict[str, Any], key: str) -> int:
    value = asset.get(key)
    if type(value) is not int or value < 0:
        _unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID")
    return value


def _normalized_evidence(trace: Any, start: int) -> list[dict[str, Any]]:
    ignored = {"ordinal", "label"}
    return [{key: value for key, value in row.items() if key not in ignored}
            for row in trace.reads[start:]]


def read_mapping(trace: Any, game_base: Any, actual_pointer: Any, *,
                 phase: str) -> dict[str, Any]:
    """Prove a stock or pinned-hook predicate mapping using the caller's trace.

    `trace` must be the shared `_common._Trace`, so every byte remains inside
    the permission's existing call and byte budgets. Phase-specific labels are
    omitted from the returned proof to allow strict before/after equality when
    the same bytes were observed in both passes.
    """
    if not isinstance(trace, _common._Trace):
        _unknown("CHOICE_MAPPING_TRACE_INVALID")
    if phase not in ("before", "after"):
        _unknown("CHOICE_MAPPING_PHASE_INVALID")
    base = _common._pointer(game_base, "GAME_BASE", alignment=0x1000)
    pointer = _common._pointer(actual_pointer, "CHOICE_POINTER", alignment=1)
    asset, _asset_raw = _asset()
    evidence_start = len(trace.reads)
    native_true_rva = _asset_int(asset, "native_true_predicate_rva")
    native_true_raw = _asset_bytes(asset, "native_true_predicate_hex", 3)
    expected_native_true = _common._checked_add(base, native_true_rva, len(native_true_raw))

    if pointer == expected_native_true:
        body = trace.exact(pointer, len(native_true_raw),
                           f"choice_mapping.native_true_body_{phase}")
        if body != native_true_raw:
            _unknown("NATIVE_TRUE_PREDICATE_BODY_MISMATCH")
        return {
            "schema": SCHEMA,
            "mode": "native_true",
            "game_base": hex(base),
            "actual_pointer": hex(pointer),
            "native_true_predicate_rva": hex(native_true_rva),
            "predicate_body_hex": body.hex(),
            "asset_sha256": ASSET_SHA256,
            "read_evidence": _normalized_evidence(trace, evidence_start),
        }

    if pointer <= HOOK_POINTER_DELTA:
        _unknown("CHOICE_POINTER_NOT_SUPPORTED")
    module_base = pointer - HOOK_POINTER_DELTA
    if (module_base < _common.MIN_USER_ADDRESS
            or module_base % 0x10000 != 0):
        _unknown("HOOK_MODULE_BASE_UNALIGNED")

    preferred_image_base = asset.get("preferred_image_base")
    if type(preferred_image_base) is not str:
        _unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID")
    try:
        int(preferred_image_base, 16)
    except ValueError as exc:
        raise _common._Unknown("CHOICE_MAPPING_ASSET_FIELD_INVALID") from exc

    pe_offset = _asset_int(asset, "pe_header_offset")
    size_of_image_expected = _asset_int(asset, "size_of_image")
    body_rva = _asset_int(asset, "body_rva")
    body_end_rva = _asset_int(asset, "body_end_rva_exclusive")
    body_expected = _asset_bytes(asset, "body_hex", body_end_rva - body_rva)
    body_expected_sha = asset.get("body_sha256")
    if (type(body_expected_sha) is not str
            or hashlib.sha256(body_expected).hexdigest() != body_expected_sha
            or pointer != _common._checked_add(module_base, body_rva, len(body_expected))):
        _unknown("HOOK_BODY_DESCRIPTOR_INVALID")
    image_end = _common._checked_add(module_base, size_of_image_expected, 1)
    if pointer + len(body_expected) > image_end:
        _unknown("HOOK_BODY_OUTSIDE_IMAGE")

    dos_expected = _asset_bytes(asset, "dos_prefix_hex", HOOK_DOS_PREFIX_SIZE)
    coff_expected = _asset_bytes(asset, "coff_prefix_hex", HOOK_COFF_PREFIX_SIZE)
    magic_expected = _asset_bytes(asset, "optional_header_magic_hex", HOOK_MAGIC_SIZE)
    if pe_offset != int.from_bytes(dos_expected[0x3C:0x40], "little"):
        _unknown("HOOK_PE_OFFSET_DESCRIPTOR_MISMATCH")

    dos_address = module_base
    coff_address = _common._checked_add(module_base, pe_offset, HOOK_COFF_PREFIX_SIZE)
    magic_address = _common._checked_add(module_base, pe_offset + HOOK_COFF_PREFIX_SIZE,
                                         HOOK_MAGIC_SIZE)
    size_image_offset = pe_offset + HOOK_COFF_PREFIX_SIZE + 56
    size_image_address = _common._checked_add(module_base, size_image_offset,
                                              HOOK_SIZE_OF_IMAGE_SIZE)
    dos = trace.exact(dos_address, HOOK_DOS_PREFIX_SIZE,
                      f"choice_mapping.hook_dos_header_{phase}")
    coff = trace.exact(coff_address, HOOK_COFF_PREFIX_SIZE,
                       f"choice_mapping.hook_coff_header_{phase}")
    magic = trace.exact(magic_address, HOOK_MAGIC_SIZE,
                        f"choice_mapping.hook_optional_magic_{phase}")
    size_image_raw = trace.exact(size_image_address, HOOK_SIZE_OF_IMAGE_SIZE,
                                 f"choice_mapping.hook_size_of_image_{phase}")
    size_of_image = int.from_bytes(size_image_raw, "little")
    if dos != dos_expected:
        _unknown("HOOK_DOS_HEADER_MISMATCH")
    if coff != coff_expected:
        _unknown("HOOK_COFF_HEADER_MISMATCH")
    if magic != magic_expected:
        _unknown("HOOK_OPTIONAL_MAGIC_MISMATCH")
    if size_of_image != size_of_image_expected:
        _unknown("HOOK_SIZE_OF_IMAGE_MISMATCH")
    if (size_of_image == 0 or size_of_image % 0x1000 != 0
            or module_base + size_of_image > _common.MAX_USER_ADDRESS_EXCLUSIVE):
        _unknown("HOOK_SIZE_OF_IMAGE_RANGE_INVALID")

    body_address = _common._checked_add(module_base, body_rva, len(body_expected))
    body_first_size = min(1024, len(body_expected))
    body_first = trace.exact(body_address, body_first_size,
                             f"choice_mapping.hook_body_0_{phase}")
    body_second_size = len(body_expected) - body_first_size
    if body_second_size <= 0 or body_second_size > 1024:
        _unknown("HOOK_BODY_SPLIT_INVALID")
    body_second_address = _common._checked_add(body_address, body_first_size,
                                               body_second_size)
    body_second = trace.exact(body_second_address, body_second_size,
                              f"choice_mapping.hook_body_1_{phase}")
    body = body_first + body_second
    if body != body_expected:
        _unknown("HOOK_BODY_MISMATCH")

    game_global_rva = _asset_int(asset, "game_module_base_global_rva")
    saved_original_rva = _asset_int(asset, "favor_gold_original_global_rva")
    game_global_address = _common._checked_add(module_base, game_global_rva, 8)
    saved_original_address = _common._checked_add(module_base, saved_original_rva, 8)
    observed_game_base = trace.u64(game_global_address,
                                   f"choice_mapping.hook_game_base_global_{phase}")
    saved_original = trace.u64(saved_original_address,
                               f"choice_mapping.hook_saved_original_global_{phase}")
    expected_original = expected_native_true
    if observed_game_base != base:
        _unknown("HOOK_GAME_BASE_GLOBAL_MISMATCH")
    if saved_original != expected_original:
        _unknown("HOOK_SAVED_ORIGINAL_MAPPING_MISMATCH")
    original_body = trace.exact(saved_original, len(native_true_raw),
                                f"choice_mapping.hook_saved_original_body_{phase}")
    if original_body != native_true_raw:
        _unknown("HOOK_SAVED_ORIGINAL_BODY_MISMATCH")

    return {
        "schema": SCHEMA,
        "mode": "installed_observer_gui_forwarding",
        "game_base": hex(base),
        "actual_pointer": hex(pointer),
        "module_base": hex(module_base),
        "module_size_of_image": size_of_image,
        "module_image_end_exclusive": hex(image_end),
        "preferred_image_base": preferred_image_base.lower(),
        "dll_sha256_from_asset": HOOK_DLL_SHA256,
        "asset_sha256": ASSET_SHA256,
        "body_rva": hex(body_rva),
        "body_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_raw_hex": body.hex(),
        "body_matches_pinned_asset": True,
        "dos_header_matches_pinned_asset": True,
        "pe_header_offset": pe_offset,
        "coff_prefix_matches_pinned_asset": True,
        "optional_header_magic_matches_pinned_asset": True,
        "size_of_image_matches_pinned_asset": True,
        "game_module_base_global_rva": hex(game_global_rva),
        "observed_game_base": hex(observed_game_base),
        "saved_original_global_rva": hex(saved_original_rva),
        "saved_original_pointer": hex(saved_original),
        "saved_original_body_hex": original_body.hex(),
        "whole_loaded_dll_hash_verified": False,
        "proof_scope": "guarded_EF2B00_GUI_caller_only; AI_turn_hold_path_not_in_scope",
        "read_evidence": _normalized_evidence(trace, evidence_start),
    }


__all__ = ["SCHEMA", "ASSET_RELATIVE_PATH", "ASSET_SHA256", "read_mapping"]
