"""Offline replay of the retained trade-league raw capture.

This helper reads only the completed raw004 JSON and two small PE windows.  It
does not import a production reader, open a process, call a native function,
run REA, or use the discarded raw001--003 projections as evidence.  Predicate
AL values, vector members, and the first vector element are reconstructed from
the retained bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work/runtime/information-relation-remaining-20261027-001"
RAW_INPUT = STAGE / "trade-league-current-inputs-004.json"
EXPECTED_OUTPUT = STAGE / "expected-trade-league-current-001.json"
CODE_OUTPUT = STAGE / "code-source004.json"

EXPECTED_VERSION = "1.37.4"
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_SESSION = "31460-1dd653f69242d7b"
EXPECTED_DATE = 56557728
EXPECTED_PID = 31460
EXPECTED_CREATION_FILETIME = 134374886912306555
IMAGE_BASE_EXPECTED = 0x140000000
METHOD_SLOT_OFFSET = 0x40
FULLREF_WIDTH = 8
MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_MEMBERS = 4096


def _sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pin(path: Path, role: str) -> dict[str, Any]:
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": _sha_file(path),
        "role": role,
    }


def _load_json(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size <= 0 or size > MAX_INPUT_BYTES:
        raise ValueError(f"input_size_out_of_bound:{path}:{size}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"json_root_not_object:{path}")
    return value


def _hex_bytes(value: Any, label: str, *, width: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise ValueError(f"raw_hex_invalid:{label}")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"raw_hex_invalid:{label}") from exc
    if width is not None and len(raw) != width:
        raise ValueError(f"raw_hex_width_invalid:{label}:{len(raw)}")
    return raw


def _hex_int(raw: bytes, *, signed: bool = False) -> int:
    return int.from_bytes(raw, "little", signed=signed)


def _tag_slot(fullref: bytes) -> tuple[str | None, int | None]:
    if len(fullref) != FULLREF_WIDTH:
        return None, None
    tag_raw = fullref[:3]
    if not all(0x41 <= byte <= 0x5A or 0x30 <= byte <= 0x39 for byte in tag_raw):
        return None, None
    return tag_raw.decode("ascii"), int.from_bytes(fullref[4:6], "little")


def _raw_table(pass_record: Mapping[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    context = pass_record.get("context")
    if not isinstance(context, Mapping):
        raise ValueError("pass_context_missing")
    binding = context.get("country_table_binding")
    if not isinstance(binding, Mapping):
        raise ValueError("country_table_binding_missing")
    count_raw = _hex_bytes(binding.get("count_raw_hex"), "country_table.count", width=4)
    count = _hex_int(count_raw, signed=True)
    if count <= 0 or count > MAX_MEMBERS:
        raise ValueError(f"country_table_count_invalid:{count}")
    entries = binding.get("entries")
    if not isinstance(entries, list) or len(entries) != count:
        raise ValueError("country_table_entries_count_mismatch")
    by_fullref: dict[str, list[dict[str, Any]]] = {}
    null_sentinels = 0
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or entry.get("index") != index:
            raise ValueError(f"country_table_entry_index_invalid:{index}")
        pointer_raw = _hex_bytes(entry.get("table_entry_raw_hex"), f"country_table.pointer[{index}]", width=8)
        pointer = _hex_int(pointer_raw)
        if pointer == 0:
            continue
        fullref = _hex_bytes(entry.get("fullref_raw_hex"), f"country_table.fullref[{index}]", width=8)
        tag, slot = _tag_slot(fullref)
        # The native table keeps one non-null placeholder at index 0.  It is
        # a raw "---" sentinel, not a country and must not become a member.
        if fullref[:4] == b"---\x00":
            null_sentinels += 1
            continue
        if tag is None or slot is None:
            raise ValueError(f"country_table_fullref_invalid:{index}")
        row = {
            "index": index,
            "country_pointer_raw_hex": pointer_raw.hex(),
            "fullref_raw_hex": fullref.hex(),
            "country": tag,
            "slot": slot,
        }
        by_fullref.setdefault(fullref.hex(), []).append(row)
    return by_fullref, {
        "count": count,
        "count_raw_hex": count_raw.hex(),
        "table_raw_hex": _hex_bytes(binding.get("table_raw_hex"), "country_table.table", width=8).hex(),
        "entries": len(entries),
        "nonempty_entries": sum(len(values) for values in by_fullref.values()),
        "null_sentinels": null_sentinels,
    }


def _raw_item(item: Mapping[str, Any], country: str, by_fullref: Mapping[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Decode one country from raw bytes, ignoring probe status/value fields."""
    obj = item.get("object")
    if not isinstance(obj, Mapping):
        raise ValueError(f"object_missing:{country}")
    prefix = _hex_bytes(obj.get("prefix_raw_hex"), f"{country}.object_prefix", width=0x40)
    vtable_raw = prefix[:8]
    slot_raw = _hex_bytes(obj.get("vtable_plus_0x40_raw_hex"), f"{country}.vtable_slot", width=8)
    method_raw = _hex_bytes(obj.get("method_code_prefix_16_hex"), f"{country}.method_code", width=16)
    vector = obj.get("vector")
    if not isinstance(vector, Mapping):
        raise ValueError(f"vector_missing:{country}")
    begin_raw = _hex_bytes(vector.get("begin_raw_hex"), f"{country}.vector_begin", width=8)
    end_raw = _hex_bytes(vector.get("end_raw_hex"), f"{country}.vector_end", width=8)
    begin = _hex_int(begin_raw)
    end = _hex_int(end_raw)
    if end < begin or (end - begin) % FULLREF_WIDTH:
        raise ValueError(f"vector_bounds_invalid:{country}")
    count = (end - begin) // FULLREF_WIDTH
    if count > MAX_MEMBERS:
        raise ValueError(f"vector_count_invalid:{country}:{count}")
    vector_raw = _hex_bytes(vector.get("raw_hex"), f"{country}.vector", width=count * FULLREF_WIDTH)
    elements: list[dict[str, Any]] = []
    stale: list[str] = []
    duplicates: list[str] = []
    seen_fullrefs: set[str] = set()
    seen_tags: set[str] = set()
    for index in range(count):
        chunk = vector_raw[index * FULLREF_WIDTH:(index + 1) * FULLREF_WIDTH]
        raw_hex = chunk.hex()
        candidates = by_fullref.get(raw_hex, [])
        if len(candidates) != 1:
            stale.append(raw_hex if not candidates else f"ambiguous:{raw_hex}")
            continue
        row = candidates[0]
        if raw_hex in seen_fullrefs or row["country"] in seen_tags:
            duplicates.append(row["country"] if row["country"] in seen_tags else raw_hex)
        seen_fullrefs.add(raw_hex)
        seen_tags.add(row["country"])
        elements.append({
            "index": index,
            "country": row["country"],
            "slot": row["slot"],
            "fullref_raw_hex": raw_hex,
        })
    if method_raw[:3] == b"\xB0\x01\xC3":
        active = True
        predicate = "al_1"
    elif method_raw[:3] == b"\x32\xC0\xC3":
        active = False
        predicate = "al_0"
    else:
        active = None
        predicate = "unknown"
    reasons: list[str] = []
    if stale:
        reasons.append("stale_or_ambiguous_fullref")
    if duplicates:
        reasons.append("duplicate_member")
    if active is False and count != 0:
        reasons.append("false_predicate_vector_nonempty")
    if active is True and count == 0:
        reasons.append("active_predicate_vector_empty")
    if active is None:
        reasons.append("predicate_leaf_unrecognized")
    self_rows = [row for row in elements if row["country"] == country]
    if active is True and len(self_rows) != 1:
        reasons.append("active_member_self_count_invalid")
    members_value: list[dict[str, Any]] | None = elements if not reasons else None
    if active is False and count == 0 and not reasons:
        members_value = []
    first = elements[0] if elements and not stale and not duplicates else None
    active_member_known = active is True and len(self_rows) == 1 and not reasons
    return {
        "status": "known" if not reasons else "unknown",
        "complete": not reasons,
        "country": country,
        "predicate": {
            "status": "known" if active is not None else "unknown",
            "value": active,
            "predicate": predicate,
            "method_code_prefix_3_hex": method_raw[:3].hex(),
        },
        "members": {
            "status": "known" if members_value is not None else "unknown",
            "value": members_value,
            "count": count,
            "raw_hex": vector_raw.hex(),
        },
        "active_member": {
            "status": "known" if active_member_known else ("not_applicable" if active is False and count == 0 and not reasons else "unknown"),
            "value": self_rows[0] if active_member_known else None,
            "self_occurrences": len(self_rows),
        },
        "first_leader": {
            "status": "known" if first is not None else ("not_applicable" if active is False and count == 0 else "unknown"),
            "value": first,
            "semantics": "first vector element retained by the native source; role label is not otherwise inferred",
        },
        "raw": {
            "object_prefix_hex": prefix.hex(),
            "vtable_pointer_raw_hex": vtable_raw.hex(),
            "vtable_plus_0x40_raw_hex": slot_raw.hex(),
            "method_code_prefix_16_hex": method_raw.hex(),
            "vector_begin_raw_hex": begin_raw.hex(),
            "vector_end_raw_hex": end_raw.hex(),
            "vector_raw_hex": vector_raw.hex(),
        },
        "unknown_reasons": reasons,
        "stale_fullrefs": stale,
        "duplicates": duplicates,
    }


def _raw_pass_digest(pass_record: Mapping[str, Any]) -> str:
    context = pass_record.get("context")
    if not isinstance(context, Mapping):
        raise ValueError("pass_context_missing_for_digest")
    binding = context.get("country_table_binding")
    if not isinstance(binding, Mapping):
        raise ValueError("table_binding_missing_for_digest")
    table_bytes = {
        "table_raw_hex": binding.get("table_raw_hex"),
        "count_raw_hex": binding.get("count_raw_hex"),
        "entries": [
            {
                "pointer_raw_hex": e.get("table_entry_raw_hex"),
                "fullref_raw_hex": e.get("fullref_raw_hex"),
            }
            for e in binding.get("entries", [])
            if isinstance(e, Mapping)
        ],
    }
    rows = []
    for item in pass_record.get("items", []):
        if not isinstance(item, Mapping):
            raise ValueError("pass_item_not_object")
        obj = item.get("object") or {}
        vec = obj.get("vector") or {}
        rows.append({
            "country": item.get("country"),
            "country_1948_raw_hex": item.get("country_1948_raw_hex"),
            "prefix_raw_hex": obj.get("prefix_raw_hex"),
            "vtable_slot_raw_hex": obj.get("vtable_plus_0x40_raw_hex"),
            "method_code_prefix_16_hex": obj.get("method_code_prefix_16_hex"),
            "vector_begin_raw_hex": vec.get("begin_raw_hex"),
            "vector_end_raw_hex": vec.get("end_raw_hex"),
            "vector_raw_hex": vec.get("raw_hex"),
        })
    payload = {"table": table_bytes, "rows": rows}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _pe_layout(path: Path) -> tuple[int, list[tuple[int, int, int, int]]]:
    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("pe_dos_header_invalid")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        stream.seek(pe_offset)
        header = stream.read(24)
        if len(header) != 24 or header[:4] != b"PE\0\0":
            raise ValueError("pe_header_invalid")
        section_count, optional_size = struct.unpack_from("<HH", header, 6), struct.unpack_from("<H", header, 20)[0]
        section_count = section_count[0]
        optional = stream.read(optional_size)
        if len(optional) != optional_size or struct.unpack_from("<H", optional, 0)[0] != 0x20B:
            raise ValueError("pe64_optional_header_invalid")
        image_base = struct.unpack_from("<Q", optional, 24)[0]
        sections = []
        for _ in range(section_count):
            raw = stream.read(40)
            if len(raw) != 40:
                raise ValueError("pe_section_header_truncated")
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", raw, 8)
            sections.append((virtual_address, virtual_size, raw_size, raw_pointer))
    return image_base, sections


def _read_pe_rva(path: Path, image_base: int, sections: list[tuple[int, int, int, int]], rva: int, size: int) -> bytes:
    if rva < 0 or size <= 0:
        raise ValueError("pe_rva_read_invalid")
    for virtual_address, virtual_size, raw_size, raw_pointer in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            offset = rva - virtual_address
            if offset + size > raw_size:
                raise ValueError(f"pe_rva_not_backed:{hex(rva)}")
            with path.open("rb") as stream:
                stream.seek(raw_pointer + offset)
                value = stream.read(size)
            if len(value) != size:
                raise ValueError("pe_rva_short_read")
            return value
    raise ValueError(f"pe_rva_unmapped:{hex(rva)}")


def _code_source(raw: Mapping[str, Any]) -> dict[str, Any]:
    identity = raw.get("identity")
    if not isinstance(identity, Mapping):
        raise ValueError("raw_identity_missing")
    exe = Path(str(identity.get("process_path")))
    if not exe.is_file():
        raise FileNotFoundError(exe)
    exe_sha = _sha_file(exe)
    if exe_sha.lower() != EXPECTED_EXE_SHA256:
        raise ValueError("static_exe_sha_mismatch")
    image_base, sections = _pe_layout(exe)
    if image_base != IMAGE_BASE_EXPECTED:
        raise ValueError(f"image_base_unexpected:{hex(image_base)}")
    module_value = raw.get("module_base", {}).get("va") if isinstance(raw.get("module_base"), Mapping) else None
    runtime_module_base = int(str(module_value), 0)
    methods: dict[str, dict[str, Any]] = {}
    first_pass = raw["trade_league_inputs"][0]
    for item in first_pass["items"]:
        obj = item.get("object")
        if not isinstance(obj, Mapping):
            raise ValueError(f"object_missing_for_code:{item.get('country')}")
        prefix = _hex_bytes(obj.get("prefix_raw_hex"), f"{item.get('country')}.prefix", width=0x40)
        vtable_runtime = _hex_int(prefix[:8])
        slot_runtime = _hex_bytes(obj.get("vtable_plus_0x40_raw_hex"), f"{item.get('country')}.slot", width=8)
        method_runtime = _hex_int(slot_runtime)
        vtable_rva = vtable_runtime - runtime_module_base
        method_rva = method_runtime - runtime_module_base
        static_slot_rva = vtable_rva + METHOD_SLOT_OFFSET
        static_slot = _read_pe_rva(exe, image_base, sections, static_slot_rva, 8)
        static_target = _hex_int(static_slot)
        static_leaf = _read_pe_rva(exe, image_base, sections, method_rva, 6)
        if static_target != image_base + method_rva:
            raise ValueError(f"vtable_target_mismatch:{item.get('country')}")
        if static_leaf[:3] == b"\xB0\x01\xC3":
            predicate = "al_1"
            al_value = 1
        elif static_leaf[:3] == b"\x32\xC0\xC3":
            predicate = "al_0"
            al_value = 0
        else:
            raise ValueError(f"predicate_leaf_unrecognized:{hex(method_rva)}")
        raw_code = _hex_bytes(obj.get("method_code_prefix_16_hex"), f"{item.get('country')}.method", width=16)
        key = predicate
        current = {
            "predicate": predicate,
            "al_value": al_value,
            "runtime_vtable_pointer": hex(vtable_runtime),
            "runtime_vtable_rva": hex(vtable_rva),
            "runtime_vtable_plus_0x40_pointer": hex(vtable_runtime + METHOD_SLOT_OFFSET),
            "vtable_plus_0x40_rva": hex(static_slot_rva),
            "runtime_method_pointer": hex(method_runtime),
            "runtime_method_rva": hex(method_rva),
            "static_vtable_slot_raw_hex": static_slot.hex(),
            "static_target_va": hex(static_target),
            "static_target_rva": hex(static_target - image_base),
            "static_leaf_bytes_hex": static_leaf.hex(),
            "retained_runtime_leaf_bytes_hex": raw_code[:6].hex(),
            "checks": {
                "static_vtable_slot_points_to_method": True,
                "retained_runtime_code_prefix_matches_static": raw_code[:6] == static_leaf,
                "leaf_returns_expected_al": True,
            },
        }
        if not current["checks"]["retained_runtime_code_prefix_matches_static"]:
            raise ValueError(f"runtime_static_code_mismatch:{item.get('country')}")
        old = methods.get(key)
        if old is not None and old != current:
            raise ValueError(f"predicate_code_conflict:{key}")
        methods[key] = current
    if set(methods) != {"al_0", "al_1"}:
        raise ValueError(f"predicate_code_set_invalid:{sorted(methods)}")
    return {
        "schema": "information_trade_league_code_source.v1",
        "status": "observed",
        "source_kind": "bounded_static_pe_read_plus_retained_runtime_code_bytes",
        "executable": {
            "path": str(exe),
            "sha256": exe_sha,
            "image_base": hex(image_base),
        },
        "runtime_module_base": hex(runtime_module_base),
        "window_contract": {
            "vtable_slot_offset": hex(METHOD_SLOT_OFFSET),
            "vtable_slot_read_bytes": 8,
            "predicate_leaf_read_bytes": 6,
            "virtual_invoked": False,
        },
        "methods": methods,
        "unknown_conditions": [
            "The leaf proves the returned AL predicate only; it does not by itself name the business relation.",
        ],
    }


def _build_reference(raw: dict[str, Any], code: dict[str, Any], raw_path: Path, code_path: Path) -> dict[str, Any]:
    if raw.get("target_build", {}).get("version") != EXPECTED_VERSION:
        raise ValueError("raw_version_mismatch")
    if raw.get("target_build", {}).get("expected_exe_sha256", "").lower() != EXPECTED_EXE_SHA256:
        raise ValueError("raw_expected_exe_sha_mismatch")
    identity = raw.get("identity")
    if not isinstance(identity, Mapping):
        raise ValueError("raw_identity_missing")
    identity_checks = {
        "pid": identity.get("installation_pid") == EXPECTED_PID,
        "creation_filetime": identity.get("installation_creation_filetime") == EXPECTED_CREATION_FILETIME,
        "session_id": identity.get("installation_session_id") == EXPECTED_SESSION,
        "exe_sha": identity.get("process_path_sha256") == EXPECTED_EXE_SHA256,
        "process_creation": identity.get("process_creation_matches_installation") is True,
        "module_binding": identity.get("module_path_matches_process") is True,
    }
    if not all(identity_checks.values()):
        raise ValueError(f"raw_identity_checks_failed:{identity_checks}")
    passes = raw.get("trade_league_inputs")
    contexts = raw.get("pass_context")
    if not isinstance(passes, list) or len(passes) != 2 or not isinstance(contexts, list) or len(contexts) != 2:
        raise ValueError("raw_two_pass_shape_invalid")
    pass_maps = []
    table_summaries = []
    digests = []
    for pass_record, context_record in zip(passes, contexts, strict=True):
        if not isinstance(pass_record, Mapping) or not isinstance(context_record, Mapping):
            raise ValueError("raw_pass_record_invalid")
        items = pass_record.get("items")
        if not isinstance(items, list):
            raise ValueError("raw_pass_items_invalid")
        pass_map = {item.get("country"): item for item in items if isinstance(item, Mapping)}
        if set(pass_map) != set(raw.get("country_scope", [])):
            raise ValueError("raw_country_scope_mismatch")
        pass_maps.append(pass_map)
        table, summary = _raw_table(context_record)
        table_summaries.append(summary)
        digests.append(_raw_pass_digest(context_record))
    if digests[0] != digests[1]:
        raise ValueError("two_pass_raw_bytes_mismatch")
    if table_summaries[0] != table_summaries[1]:
        raise ValueError("two_pass_country_table_summary_mismatch")
    game_dates = []
    for context in contexts:
        game_date = context.get("context", {}).get("game_date") if isinstance(context.get("context"), Mapping) else None
        if not isinstance(game_date, Mapping) or game_date.get("value") != EXPECTED_DATE:
            raise ValueError("game_date_guard_failed")
        game_dates.append(game_date.get("raw_hex"))
    if game_dates[0] != game_dates[1]:
        raise ValueError("two_pass_game_date_bytes_mismatch")
    if raw.get("doublepass", {}).get("consistent") is not True:
        raise ValueError("retained_doublepass_not_consistent")
    cleanup = raw.get("cleanup", {}).get("handle_close", {})
    cleanup_ok = cleanup.get("status") == "closed" and cleanup.get("success") is True and cleanup.get("closed") is True
    if not cleanup_ok:
        raise ValueError("retained_handle_not_closed")

    fields: dict[str, Any] = {}
    per_country_checks: dict[str, Any] = {}
    for country in raw["country_scope"]:
        replayed = []
        for pass_map in pass_maps:
            item = pass_map[country]
            table, _ = _raw_table(contexts[len(replayed)])
            replayed.append(_raw_item(item, country, table))
        if replayed[0] != replayed[1]:
            raise ValueError(f"country_replay_mismatch:{country}")
        field = replayed[0]
        method_rva = None
        obj = field["raw"]
        slot_runtime = _hex_int(_hex_bytes(obj["vtable_plus_0x40_raw_hex"], f"{country}.slot", width=8))
        runtime_base = int(str(raw["module_base"]["va"]), 0)
        method_rva = slot_runtime - runtime_base
        predicate_source = code["methods"]["al_1" if field["predicate"]["value"] is True else "al_0"] if field["predicate"]["value"] is not None else None
        if predicate_source is None or predicate_source["runtime_method_rva"] != hex(method_rva):
            raise ValueError(f"predicate_code_source_mismatch:{country}")
        field["raw"]["method_rva"] = hex(method_rva)
        fields[country] = field
        per_country_checks[country] = {
            "two_pass_bytes_equal": True,
            "predicate_replayed_from_code": field["predicate"]["status"] == "known",
            "vector_replayed_from_raw": field["members"]["raw_hex"] is not None,
            "no_duplicate_or_stale_member": not field["duplicates"] and not field["stale_fullrefs"],
        }

    checks = {
        "raw004_identity_bound": all(identity_checks.values()),
        "raw004_game_date_bound": all(date == game_dates[0] for date in game_dates),
        "raw004_two_pass_bytes_equal": digests[0] == digests[1],
        "raw004_country_table_complete": table_summaries[0]["entries"] == table_summaries[0]["count"],
        "raw004_handle_closed": cleanup_ok,
        "static_predicate_code_source": code.get("status") == "observed",
        "probe_status_and_value_not_used_for_projection": True,
        "native_function_invoked": raw.get("native_function_invoked") is False,
    }
    checks.update({f"{country}.{name}": value for country, values in per_country_checks.items() for name, value in values.items()})
    return {
        "schema": "information_independent_trade_league_reference.v1",
        "status": "observed" if all(checks.values()) else "unknown",
        "reference_kind": "offline_raw004_replay",
        "build": {"version": EXPECTED_VERSION, "exe_sha256": EXPECTED_EXE_SHA256},
        "identity": {
            "pid": EXPECTED_PID,
            "creation_filetime": EXPECTED_CREATION_FILETIME,
            "session_id": EXPECTED_SESSION,
            "game_date": EXPECTED_DATE,
            "observer": "FRA",
        },
        "source_contract": {
            "country_trade_league_offset": "0x1948",
            "object_prefix_size": "0x40",
            "vtable_method_slot": "0x40",
            "vector_begin_offset": "0x20",
            "vector_end_offset": "0x28",
            "vector_stride": 8,
            "virtual_invoked": False,
        },
        "fields": fields,
        "checks": checks,
        "per_country_checks": per_country_checks,
        "raw_replay": {
            "input": _pin(raw_path, "two-pass native trade-league raw capture"),
            "raw_pass_digests": digests,
            "country_table": table_summaries[0],
            "code_source": _pin(code_path, "independent static predicate source"),
            "no_new_capture": True,
            "no_native_call": True,
            "no_game_access": True,
        },
        "unknown_conditions": [
            "The first vector element is retained as first_leader; no additional role or expiry semantics are inferred.",
            "A future duplicate or stale fullref must remain unknown rather than falling back to the tag bytes.",
        ],
    }


def _write_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"refusing_to_overwrite:{path}")
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def run(raw_path: Path = RAW_INPUT, expected_path: Path = EXPECTED_OUTPUT, code_path: Path = CODE_OUTPUT) -> dict[str, Any]:
    if expected_path.exists() or code_path.exists():
        raise FileExistsError("reference_outputs_already_exist")
    raw = _load_json(raw_path)
    code = _code_source(raw)
    _write_exclusive(code_path, code)
    expected = _build_reference(raw, code, raw_path, code_path)
    _write_exclusive(expected_path, expected)
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="replay retained raw004 and write the two exclusive reports")
    parser.add_argument("--raw", type=Path, default=RAW_INPUT)
    parser.add_argument("--expected", type=Path, default=EXPECTED_OUTPUT)
    parser.add_argument("--code-source", type=Path, default=CODE_OUTPUT)
    args = parser.parse_args()
    if not args.run:
        parser.print_help()
        return 0
    result = run(args.raw, args.expected, args.code_source)
    print(json.dumps({"status": result["status"], "expected": str(args.expected), "code_source": str(args.code_source), "checks": len(result["checks"])}, ensure_ascii=False))
    return 0 if result["status"] == "observed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
