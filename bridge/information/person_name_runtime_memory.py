"""Read the fixed runtime patch/plugin layout used by person-name rendering.

This module is a bounded, value-only reader. It never opens a process, reads
files, follows an unrecognized callback, or invokes native code. A known
``layout`` is only an input for later projection policy; it does not establish
that a name was rendered or that the entire plugin image matches a file.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any, Callable


SCHEMA = "information.person_name_runtime_memory.v1"
BASIS = "fixed_profile_runtime_patch_and_plugin_layout"
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF
MAX_GUARDS = 32
MAX_SINGLE_READ = 65_536
MAX_TOTAL_READ_BYTES = 128 * 1024
MAX_HEADER_BYTES = 4096
MAX_IMAGE_SIZE = 0xFFFFFFFF
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})+\Z")
_SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
_ABSOLUTE_JUMP_PREFIX = bytes.fromhex("ff2500000000")


class _LayoutFailure(ValueError):
    pass


def _integer(value: Any, label: str) -> int:
    if type(value) is int:
        parsed = value
    elif isinstance(value, str) and 1 <= len(value) <= 18:
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise _LayoutFailure(f"{label}_invalid") from exc
    else:
        raise _LayoutFailure(f"{label}_invalid")
    if parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
        raise _LayoutFailure(f"{label}_out_of_range")
    return parsed


def _hex(value: Any, label: str, *, exact_bytes: int | None = None,
         maximum_bytes: int | None = None) -> bytes:
    if not isinstance(value, str) or not value:
        raise _LayoutFailure(f"{label}_hex_invalid")
    if exact_bytes is not None and len(value) != exact_bytes * 2:
        raise _LayoutFailure(f"{label}_width_invalid")
    if maximum_bytes is not None and len(value) > maximum_bytes * 2:
        raise _LayoutFailure(f"{label}_size_exceeded")
    if not _HEX_RE.fullmatch(value):
        raise _LayoutFailure(f"{label}_hex_invalid")
    raw = bytes.fromhex(value)
    if exact_bytes is not None and len(raw) != exact_bytes:
        raise _LayoutFailure(f"{label}_width_invalid")
    if maximum_bytes is not None and len(raw) > maximum_bytes:
        raise _LayoutFailure(f"{label}_size_exceeded")
    return raw


def _user_pointer(value: int, label: str) -> int:
    if type(value) is not int or not MIN_USER_ADDRESS <= value <= MAX_USER_ADDRESS:
        raise _LayoutFailure(f"{label}_not_canonical_user_address")
    return value


def _add(base: int, offset: int, size: int, label: str) -> int:
    if type(offset) is not int or type(size) is not int or offset < 0 or size <= 0:
        raise _LayoutFailure(f"{label}_range_invalid")
    address = base + offset
    end = address + size - 1
    if address < base or end < address or end > MAX_USER_ADDRESS:
        raise _LayoutFailure(f"{label}_range_out_of_bounds")
    return address


def _prepare_spec(spec: Any, exe_base: int) -> dict[str, Any]:
    if not isinstance(spec, Mapping):
        raise _LayoutFailure("spec_invalid")
    patch_rva = _integer(spec.get("patch_rva"), "patch_rva")
    original = _hex(spec.get("original_bytes"), "original_bytes", exact_bytes=14)
    plugin = spec.get("plugin")
    if not isinstance(plugin, Mapping):
        raise _LayoutFailure("plugin_spec_invalid")

    hook_rva = _integer(plugin.get("hook_rva"), "hook_rva")
    callback_rva = _integer(plugin.get("callback_rva"), "callback_rva")
    return_rva = _integer(plugin.get("return_rva"), "return_rva")
    slots_rva = _integer(plugin.get("slots_rva"), "slots_rva")
    image_size = _integer(plugin.get("image_size"), "image_size")
    if not 0 < image_size <= MAX_IMAGE_SIZE:
        raise _LayoutFailure("image_size_out_of_range")
    header = _hex(plugin.get("header_bytes"), "header_bytes",
                  maximum_bytes=MAX_HEADER_BYTES)
    if not 0 < len(header) <= image_size:
        raise _LayoutFailure("header_range_invalid")
    has_image_base_offset = "header_image_base_offset" in plugin
    has_preferred_image_base = "preferred_image_base" in plugin
    if has_image_base_offset != has_preferred_image_base:
        raise _LayoutFailure("header_image_base_spec_incomplete")
    header_image_base_offset = None
    preferred_image_base = None
    if has_image_base_offset:
        header_image_base_offset = _integer(
            plugin.get("header_image_base_offset"), "header_image_base_offset")
        preferred_image_base = _integer(
            plugin.get("preferred_image_base"), "preferred_image_base")
        if header_image_base_offset + 8 > len(header):
            raise _LayoutFailure("header_image_base_offset_outside_header")
        pinned_image_base = int.from_bytes(
            header[header_image_base_offset:header_image_base_offset + 8], "little")
        if pinned_image_base != preferred_image_base:
            raise _LayoutFailure("header_preferred_image_base_mismatch")
    guards = plugin.get("code_guards")
    if not isinstance(guards, list) or not 1 <= len(guards) <= MAX_GUARDS:
        raise _LayoutFailure("code_guards_shape_invalid")

    prepared_guards = []
    names: set[str] = set()
    total = 14 + len(header) + 16
    for index, item in enumerate(guards):
        if not isinstance(item, Mapping):
            raise _LayoutFailure(f"code_guard_{index}_invalid")
        name = item.get("name")
        if not isinstance(name, str) or not 1 <= len(name) <= 128 or name in names:
            raise _LayoutFailure(f"code_guard_{index}_name_invalid")
        names.add(name)
        rva = _integer(item.get("rva"), f"code_guard_{name}_rva")
        expected = _hex(item.get("bytes"), f"code_guard_{name}_bytes",
                        maximum_bytes=MAX_SINGLE_READ)
        digest = item.get("sha256")
        if not isinstance(digest, str) or not _SHA_RE.fullmatch(digest):
            raise _LayoutFailure(f"code_guard_{name}_sha_invalid")
        actual_expected_digest = hashlib.sha256(expected).hexdigest()
        if digest != actual_expected_digest:
            raise _LayoutFailure(f"code_guard_{name}_sha_pin_mismatch")
        if rva + len(expected) > image_size:
            raise _LayoutFailure(f"code_guard_{name}_outside_image")
        total += len(expected)
        prepared_guards.append({
            "name": name,
            "rva": rva,
            "expected": expected,
            "expected_sha256": digest,
        })

    if hook_rva >= image_size or callback_rva >= image_size:
        raise _LayoutFailure("plugin_entry_outside_image")
    if slots_rva + 16 > image_size:
        raise _LayoutFailure("slots_outside_image")
    if total > MAX_TOTAL_READ_BYTES:
        raise _LayoutFailure("planned_read_budget_exceeded")

    _user_pointer(exe_base, "exe_base")
    if exe_base & 0xFFF:
        raise _LayoutFailure("exe_base_unaligned")
    _add(exe_base, patch_rva, 14, "exe_patch")
    _add(exe_base, return_rva, 1, "exe_return")
    return {
        "patch_rva": patch_rva,
        "original": original,
        "hook_rva": hook_rva,
        "callback_rva": callback_rva,
        "return_rva": return_rva,
        "slots_rva": slots_rva,
        "image_size": image_size,
        "header": header,
        "header_image_base_offset": header_image_base_offset,
        "preferred_image_base": preferred_image_base,
        "guards": prepared_guards,
        "planned_read_bytes": total,
    }


def _read_exact(read: Callable[[int, int, str], bytes], address: int, size: int,
                label: str, trace: list[dict[str, Any]]) -> bytes:
    row = {"address": hex(address), "size": size, "label": label}
    try:
        raw = read(address, size, label)
    except Exception as exc:
        row.update({"status": "error", "error_type": type(exc).__name__,
                    "error": str(exc)[:160]})
        trace.append(row)
        raise _LayoutFailure(f"{label}_read_failed") from exc
    if type(raw) is not bytes:
        row.update({"status": "invalid", "error": "read_result_not_bytes"})
        trace.append(row)
        raise _LayoutFailure(f"{label}_read_result_invalid")
    if len(raw) != size:
        row.update({"status": "short", "actual_size": len(raw), "raw_hex": raw.hex()})
        trace.append(row)
        raise _LayoutFailure(f"{label}_short_read")
    row.update({"status": "observed", "raw_hex": raw.hex()})
    trace.append(row)
    return raw


def _unknown(reason: str, raw_inputs: dict[str, Any]) -> dict[str, Any]:
    return {"schema": SCHEMA, "status": "unknown", "reason": reason,
            "raw_inputs": raw_inputs, "basis": BASIS}


def read_person_name_layout(read: Callable[[int, int, str], bytes],
                            base: Any, spec: Any) -> dict[str, Any]:
    """Identify the pinned vanilla or plugin64 name-layout input snapshot.

    The vanilla path reads only the 14-byte EXE patch window. The plugin path
    validates the exact absolute jump, derives the DLL base from its pinned
    hook RVA, and compares only the profile-pinned header, code guards and two
    data slots. It does not rehash the full DLL or invoke its callback.
    """
    raw_inputs: dict[str, Any] = {"read_trace": []}
    if not callable(read):
        return _unknown("reader_not_callable", raw_inputs)
    try:
        exe_base = _integer(base, "exe_base")
        normalized_base = _user_pointer(exe_base, "exe_base")
        if normalized_base & 0xFFF:
            raise _LayoutFailure("exe_base_unaligned")
        prepared = _prepare_spec(spec, normalized_base)
        patch_address = _add(normalized_base, prepared["patch_rva"], 14, "exe_patch")
        raw_inputs["exe_base"] = hex(normalized_base)
        raw_inputs["spec"] = {
            "patch_rva": hex(prepared["patch_rva"]),
            "original_bytes_hex": prepared["original"].hex(),
            "plugin_hook_rva": hex(prepared["hook_rva"]),
            "plugin_callback_rva": hex(prepared["callback_rva"]),
            "exe_return_rva": hex(prepared["return_rva"]),
            "plugin_slots_rva": hex(prepared["slots_rva"]),
            "plugin_image_size": prepared["image_size"],
            "plugin_header_bytes_hex": prepared["header"].hex(),
            "plugin_header_image_base_offset": (
                hex(prepared["header_image_base_offset"])
                if prepared["header_image_base_offset"] is not None else None),
            "plugin_preferred_image_base": (
                hex(prepared["preferred_image_base"])
                if prepared["preferred_image_base"] is not None else None),
            "code_guards": [{"name": guard["name"], "rva": hex(guard["rva"]),
                             "expected_bytes_hex": guard["expected"].hex(),
                             "expected_sha256": guard["expected_sha256"]}
                            for guard in prepared["guards"]],
            "planned_read_bytes": prepared["planned_read_bytes"],
        }
        patch = _read_exact(read, patch_address, 14,
                            "person.name_runtime.exe_patch", raw_inputs["read_trace"])
        raw_inputs["exe_patch"] = {
            "address": hex(patch_address),
            "expected_original_hex": prepared["original"].hex(),
            "raw_hex": patch.hex(),
            "matches_original": patch == prepared["original"],
        }
        if patch == prepared["original"]:
            raw_inputs["plugin"] = {"status": "not_read", "reason": "vanilla_patch"}
            return {"schema": SCHEMA, "status": "known", "layout": "vanilla",
                    "raw_inputs": raw_inputs, "basis": BASIS}

        if patch[:6] != _ABSOLUTE_JUMP_PREFIX:
            raise _LayoutFailure("person.name_runtime.patch_encoding_unknown")
        target_raw = patch[6:14]
        target = int.from_bytes(target_raw, "little")
        _user_pointer(target, "plugin_hook_target")
        plugin_base = target - prepared["hook_rva"]
        _user_pointer(plugin_base, "plugin_base")
        if plugin_base & 0xFFF:
            raise _LayoutFailure("plugin_base_unaligned")
        if plugin_base + prepared["image_size"] - 1 > MAX_USER_ADDRESS:
            raise _LayoutFailure("plugin_image_range_out_of_bounds")

        plugin_record: dict[str, Any] = {
            "status": "checking",
            "hook_target_raw_hex": target_raw.hex(),
            "hook_target": hex(target),
            "derived_base": hex(plugin_base),
            "hook_rva": hex(prepared["hook_rva"]),
            "header": None,
            "code_guards": [],
            "slots": None,
        }
        raw_inputs["plugin"] = plugin_record

        header_address = _add(plugin_base, 0, len(prepared["header"]), "plugin_header")
        actual_header = _read_exact(read, header_address, len(prepared["header"]),
                                    "person.name_runtime.plugin_header",
                                    raw_inputs["read_trace"])
        expected_runtime_header = prepared["header"]
        header_image_base_record = None
        image_base_offset = prepared["header_image_base_offset"]
        if image_base_offset is not None:
            expected_runtime_header = bytearray(prepared["header"])
            image_base_end = image_base_offset + 8
            expected_runtime_header[image_base_offset:image_base_end] = plugin_base.to_bytes(
                8, "little")
            expected_runtime_header = bytes(expected_runtime_header)
            observed_image_base = int.from_bytes(
                actual_header[image_base_offset:image_base_offset + 8], "little")
            header_image_base_record = {
                "offset": hex(image_base_offset),
                "preferred_image_base": hex(prepared["preferred_image_base"]),
                "observed_image_base": hex(observed_image_base),
                "derived_expected_image_base": hex(plugin_base),
                "matches_derived_base": observed_image_base == plugin_base,
            }
        plugin_record["header"] = {
            "address": hex(header_address),
            "expected_hex": expected_runtime_header.hex(),
            "pinned_file_header_hex": prepared["header"].hex(),
            "raw_hex": actual_header.hex(),
            "matches": actual_header == expected_runtime_header,
            "image_base": header_image_base_record,
        }
        if (header_image_base_record is not None
                and not header_image_base_record["matches_derived_base"]):
            raise _LayoutFailure("person.name_runtime.plugin_header_image_base_mismatch")
        if actual_header != expected_runtime_header:
            raise _LayoutFailure("person.name_runtime.plugin_header_mismatch")

        for guard in prepared["guards"]:
            address = _add(plugin_base, guard["rva"], len(guard["expected"]),
                           f"plugin_guard_{guard['name']}")
            actual = _read_exact(read, address, len(guard["expected"]),
                                 f"person.name_runtime.guard.{guard['name']}",
                                 raw_inputs["read_trace"])
            actual_sha = hashlib.sha256(actual).hexdigest()
            record = {
                "name": guard["name"], "rva": hex(guard["rva"]),
                "address": hex(address),
                "expected_hex": guard["expected"].hex(), "raw_hex": actual.hex(),
                "expected_sha256": guard["expected_sha256"],
                "raw_sha256": actual_sha,
                "matches_bytes": actual == guard["expected"],
                "matches_sha256": actual_sha == guard["expected_sha256"],
            }
            plugin_record["code_guards"].append(record)
            if not record["matches_bytes"] or not record["matches_sha256"]:
                raise _LayoutFailure(f"person.name_runtime.guard_mismatch:{guard['name']}")

        slots_address = _add(plugin_base, prepared["slots_rva"], 16, "plugin_slots")
        slots = _read_exact(read, slots_address, 16,
                            "person.name_runtime.slots", raw_inputs["read_trace"])
        return_raw, callback_raw = slots[:8], slots[8:]
        return_pointer = int.from_bytes(return_raw, "little")
        callback_pointer = int.from_bytes(callback_raw, "little")
        expected_return = _add(normalized_base, prepared["return_rva"], 1,
                               "exe_return_expected")
        expected_callback = _add(plugin_base, prepared["callback_rva"], 1,
                                 "plugin_callback_expected")
        for value, label in ((return_pointer, "plugin_return_pointer"),
                             (callback_pointer, "plugin_callback_pointer")):
            _user_pointer(value, label)
        plugin_record["slots"] = {
            "address": hex(slots_address), "raw_hex": slots.hex(),
            "return_pointer_raw_hex": return_raw.hex(),
            "return_pointer": hex(return_pointer),
            "expected_return_pointer": hex(expected_return),
            "return_matches": return_pointer == expected_return,
            "callback_pointer_raw_hex": callback_raw.hex(),
            "callback_pointer": hex(callback_pointer),
            "expected_callback_pointer": hex(expected_callback),
            "callback_matches": callback_pointer == expected_callback,
        }
        if return_pointer != expected_return:
            raise _LayoutFailure("person.name_runtime.return_pointer_mismatch")
        if callback_pointer != expected_callback:
            raise _LayoutFailure("person.name_runtime.callback_pointer_mismatch")

        plugin_record["status"] = "verified_profiled_ranges"
        return {"schema": SCHEMA, "status": "known", "layout": "plugin64",
                "raw_inputs": raw_inputs, "basis": BASIS}
    except _LayoutFailure as exc:
        return _unknown(str(exc), raw_inputs)
    except Exception as exc:
        return _unknown(f"unexpected_{type(exc).__name__}", raw_inputs)


__all__ = ["read_person_name_layout"]
