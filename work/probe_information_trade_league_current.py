"""Prepare a bounded raw probe for current trade-league objects.

The probe is intentionally inert unless ``--run`` is supplied.  It reuses the
existing installation identity and VM_READ-only bounded reader, then captures
the country ``+0x1948`` object pointer, its prefix, the vtable ``+0x40``
function pointer and code prefix, and the raw ``+0x20/+0x28`` fullref vector.
It never invokes the virtual function, infers leader/active semantics, or
writes to the game.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.information import domestic_pressure_memory as memory


DEFAULT_INSTALLATION = ROOT / (
    "work/runtime/diplomacy-observer-20261026-information-battle-v27-002/"
    "installation.json"
)
DEFAULT_OUTPUT = ROOT / (
    "work/runtime/information-relation-remaining-20261027-001/"
    "trade-league-current-inputs-003.json"
)
DEFAULT_COUNTRIES = ("FRA", "HSA", "VEN", "GEN")

EXPECTED_VERSION = "1.37.4"
EXPECTED_EXE_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
EXPECTED_PID = 31460
EXPECTED_CREATION_FILETIME = 134374886912306555
EXPECTED_SESSION_ID = "31460-1dd653f69242d7b"
EXPECTED_GAME_DATE = 56557728

COUNTRY_TRADE_LEAGUE_OFFSET = 0x1948
COUNTRY_TABLE_OFFSET = 0x118
COUNTRY_TABLE_COUNT_OFFSET = 0x124
COUNTRY_FULLREF_OFFSET = 0x20
OBJECT_PREFIX_SIZE = 0x40
VTABLE_METHOD_OFFSET = 0x40
VECTOR_BEGIN_OFFSET = 0x20
VECTOR_END_OFFSET = 0x28
MAX_VECTOR_ENTRIES = 4096
MAX_COUNTRIES = 16
FULLREF_WIDTH = 8
METHOD_PREFIX_SIZE = 16


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _hex(value: int | None) -> str | None:
    return hex(value) if isinstance(value, int) else None


def _read_qword(reader: Any, address: int, label: str) -> tuple[int, bytes]:
    raw = reader.read(address, FULLREF_WIDTH, label)
    return int.from_bytes(raw, "little", signed=False), raw


def _checked_pointer(value: int, label: str) -> int:
    if not memory._valid_pointer(value):
        raise memory.ProbeError(f"invalid_pointer:{label}")
    return value


def _parse_countries(raw: Sequence[str]) -> list[str]:
    if isinstance(raw, (str, bytes)):
        raise ValueError("countries_must_be_sequence")
    countries = [str(item).upper() for item in raw]
    if not countries or len(countries) > MAX_COUNTRIES:
        raise ValueError(f"country_count_out_of_bound:{len(countries)}")
    if len(set(countries)) != len(countries):
        raise ValueError("duplicate_country")
    if any(re.fullmatch(r"[A-Z0-9]{3}", country) is None for country in countries):
        raise ValueError("country_tag_must_be_three_ascii_alnum")
    return countries


def _country_table_binding(
    reader: Any,
    database: int,
    module_base: int,
    profile: Mapping[str, Any],
    *,
    label_prefix: str,
) -> dict[str, Any]:
    """Read the complete native country table and bind exact fullrefs.

    The domestic-pressure profile deliberately limits its own country scan to
    256 entries.  That is not a valid bound for this independent probe: the
    live database count is at ``database+0x124`` and may include slots such as
    HSA=668.  Keep the table layout local here and record every entry,
    including empty and invalid entries, so a bad entry cannot silently turn
    into a complete observation.
    """
    del module_base, profile  # global profile layout is intentionally not used for this table
    result: dict[str, Any] = {
        "status": "unknown",
        "database_pointer": _hex(database),
        "table_address": None,
        "table_raw_hex": None,
        "table_pointer": None,
        "count_address": None,
        "count_raw_hex": None,
        "count": None,
        "entries_scanned": 0,
        "entries": [],
        "matches": {},
        "invalid_entries": [],
        "unknown_conditions": [],
        "layout": {
            "table_offset": hex(COUNTRY_TABLE_OFFSET),
            "count_offset": hex(COUNTRY_TABLE_COUNT_OFFSET),
            "country_fullref_offset": hex(COUNTRY_FULLREF_OFFSET),
            "fullref_width": FULLREF_WIDTH,
        },
    }
    table_address = memory._safe_add(
        database, COUNTRY_TABLE_OFFSET, f"{label_prefix}.table_address", aligned=True
    )
    count_address = memory._safe_add(
        database, COUNTRY_TABLE_COUNT_OFFSET, f"{label_prefix}.count_address"
    )
    result["table_address"] = _hex(table_address)
    result["count_address"] = _hex(count_address)
    table, table_raw = _read_qword(reader, table_address, f"{label_prefix}.table_pointer")
    result["table_raw_hex"] = table_raw.hex()
    result["table_pointer"] = _hex(table)
    if not memory._valid_pointer(table):
        result["unknown_conditions"].append("country_table_pointer_invalid")
        return result

    count_raw = reader.read(count_address, 4, f"{label_prefix}.count")
    count = int.from_bytes(count_raw, "little", signed=True)
    result["count_raw_hex"] = count_raw.hex()
    result["count"] = count
    if count <= 0 or count > MAX_VECTOR_ENTRIES:
        result["unknown_conditions"].append("country_table_count_out_of_bound")
        return result

    entries_raw = reader.read(
        table, count * FULLREF_WIDTH, f"{label_prefix}.table_entries"
    )
    matches: dict[str, list[dict[str, Any]]] = {}
    entries: list[dict[str, Any]] = []
    invalid_entries: list[dict[str, Any]] = []
    for index in range(count):
        entry_address = table + index * FULLREF_WIDTH
        pointer_raw = entries_raw[index * FULLREF_WIDTH:(index + 1) * FULLREF_WIDTH]
        pointer = int.from_bytes(pointer_raw, "little", signed=False)
        entry: dict[str, Any] = {
            "index": index,
            "table_entry_address": _hex(entry_address),
            "table_entry_raw_hex": pointer_raw.hex(),
            "country_pointer": _hex(pointer),
            "status": "empty" if pointer == 0 else "unknown",
            "fullref_address": None,
            "fullref_raw_hex": None,
            "fullref_value": None,
            "tag": None,
            "slot": None,
        }
        if pointer == 0:
            entries.append(entry)
            continue
        if not memory._valid_pointer(pointer):
            entry["status"] = "invalid_pointer"
            invalid_entries.append(entry)
            entries.append(entry)
            continue
        try:
            fullref_address = memory._safe_add(
                pointer,
                COUNTRY_FULLREF_OFFSET,
                f"{label_prefix}.country[{index}].fullref",
                aligned=True,
            )
            fullref, fullref_raw = _read_qword(
                reader, fullref_address, f"{label_prefix}.country[{index}].fullref"
            )
        except Exception as exc:
            entry.update(
                {
                    "status": "invalid_fullref_read",
                    "reason": f"{type(exc).__name__}:{exc}",
                }
            )
            invalid_entries.append(entry)
            entries.append(entry)
            continue
        tag, slot = memory._tag_and_slot(fullref)
        if index == 0 and fullref_raw.hex() == "2d2d2d0000000000":
            entry.update(status="known_null_country_sentinel", fullref_address=_hex(fullref_address),
                         fullref_raw_hex=fullref_raw.hex(), fullref_value=fullref)
            entries.append(entry)
            continue
        entry.update(
            {
                "status": "observed" if tag is not None and slot == index else "invalid_fullref",
                "fullref_address": _hex(fullref_address),
                "fullref_raw_hex": fullref_raw.hex(),
                "fullref_value": fullref,
                "tag": tag,
                "slot": slot,
            }
        )
        if entry["status"] != "observed":
            invalid_entries.append(entry)
        else:
            matches.setdefault(fullref_raw.hex(), []).append(entry)
        entries.append(entry)

    duplicate_keys = [key for key, values in matches.items() if len(values) > 1]
    if invalid_entries:
        result["unknown_conditions"].append("country_table_invalid_entry")
    if duplicate_keys:
        result["unknown_conditions"].append("country_table_duplicate_fullref")
    result["entries_scanned"] = count
    result["entries"] = entries
    result["invalid_entries"] = invalid_entries
    result["matches"] = matches
    if not result["unknown_conditions"]:
        result["status"] = "observed"
    return result


def _bind_fullref(
    raw: bytes,
    table_binding: Mapping[str, Any],
) -> dict[str, Any]:
    raw_hex = raw.hex()
    value = int.from_bytes(raw, "little", signed=False)
    tag, slot = memory._tag_and_slot(value)
    matches = table_binding.get("matches", {})
    candidates = matches.get(raw_hex, []) if isinstance(matches, Mapping) else []
    result: dict[str, Any] = {
        "raw_hex": raw_hex,
        "raw_value": value,
        "tag_from_bytes": tag,
        "slot_from_high_word": slot,
        "status": "unknown",
        "country_tag": None,
        "country_slot": None,
        "country_pointer": None,
        "table_match": None,
    }
    if len(candidates) == 1:
        match = deepcopy(candidates[0])
        result.update(
            status="matched_country_table",
            country_tag=match.get("tag"),
            country_slot=match.get("slot"),
            country_pointer=match.get("country_pointer"),
            table_match=match,
        )
    elif len(candidates) > 1:
        result["status"] = "ambiguous_country_table_match"
    else:
        result["reason"] = "fullref_not_found_in_country_table"
    return result


def _capture_pass_context(
    reader: Any,
    module_base: int,
    profile: Mapping[str, Any],
    *,
    pass_name: str,
) -> dict[str, Any]:
    """Capture globals, date, and the complete country table once per pass."""
    layout = memory._profile_layout(profile)
    game_address = memory._safe_add(
        module_base, int(layout["game_rva"]), f"{pass_name}.game_pointer"
    )
    game, game_raw = _read_qword(reader, game_address, f"{pass_name}.game_pointer")
    database_address = memory._safe_add(
        module_base, int(layout["database_rva"]), f"{pass_name}.database_pointer"
    )
    database, database_raw = _read_qword(
        reader, database_address, f"{pass_name}.database_pointer"
    )
    if not memory._valid_pointer(game) or not memory._valid_pointer(database):
        raise memory.ProbeError(f"game_or_database_pointer_invalid:{pass_name}")
    date_address = memory._safe_add(
        game, int(layout["game_date_offset"]), f"{pass_name}.game_date"
    )
    date_raw = reader.read(date_address, 4, f"{pass_name}.game_date")
    game_date = int.from_bytes(date_raw, "little", signed=True)
    game_date_record = {
        "address": _hex(date_address),
        "value": game_date,
        "raw_hex": date_raw.hex(),
    }
    table_binding = _country_table_binding(
        reader,
        database,
        module_base,
        profile,
        label_prefix=f"{pass_name}.country_table",
    )
    return {
        "status": "observed" if table_binding.get("status") == "observed" else "unknown",
        "pass": pass_name,
        "game_pointer": {
            "address": _hex(game_address),
            "raw_hex": game_raw.hex(),
            "value": _hex(game),
        },
        "database_pointer": {
            "address": _hex(database_address),
            "raw_hex": database_raw.hex(),
            "value": _hex(database),
        },
        "game_date": game_date_record,
        "country_table_binding": table_binding,
    }


def _resolve_country_table_entry(
    country: str,
    table_binding: Mapping[str, Any],
) -> dict[str, Any] | None:
    if table_binding.get("status") != "observed":
        return None
    entries = table_binding.get("entries")
    if not isinstance(entries, list):
        return None
    matches = [
        entry for entry in entries
        if isinstance(entry, Mapping)
        and entry.get("status") == "observed"
        and entry.get("tag") == country
    ]
    if len(matches) != 1:
        return None
    return deepcopy(dict(matches[0]))


def _capture_country_trade_league(
    reader: Any,
    module_base: int,
    country: str,
    country_entry: Mapping[str, Any] | None,
    pass_context: Mapping[str, Any],
    *,
    pass_name: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unknown",
        "country": country,
        "country_pointer": None,
        "country_1948_address": None,
        "country_1948_raw_hex": None,
        "country_1948_pointer": None,
        "virtual_call": {
            "invoked": False,
            "method_slot": "0x40",
            "return_al": None,
            "semantics": "not_interpreted",
        },
        "object": None,
        "country_table_binding": deepcopy(dict(country_entry)) if country_entry else None,
        "source_context": {
            "game_date": deepcopy(pass_context.get("game_date")),
            "database_pointer": deepcopy(pass_context.get("database_pointer")),
            "country_table_status": (pass_context.get("country_table_binding") or {}).get("status"),
            "country_table_match": deepcopy(dict(country_entry)) if country_entry else None,
        },
    }
    if not country_entry:
        result["reason"] = "country_fullref_binding_not_unique"
        return result
    country_pointer = memory._va(country_entry.get("country_pointer"))
    result["country_pointer"] = _hex(country_pointer)
    if country_pointer is None or not memory._valid_pointer(country_pointer):
        result["reason"] = "country_pointer_invalid"
        return result
    try:
        prefix_address = memory._safe_add(
            country_pointer,
            COUNTRY_TRADE_LEAGUE_OFFSET,
            f"{pass_name}.{country}.country_trade_league_pointer",
            aligned=True,
        )
        object_pointer, object_pointer_raw = _read_qword(
            reader, prefix_address, f"{pass_name}.{country}.country_1948"
        )
        result["country_1948_address"] = _hex(prefix_address)
        result["country_1948_raw_hex"] = object_pointer_raw.hex()
        result["country_1948_pointer"] = _hex(object_pointer)
        if object_pointer == 0:
            result.update(status="empty", reason="country_1948_null")
            return result
        object_pointer = _checked_pointer(object_pointer, f"{country}.trade_league_object")
        prefix = reader.read(
            object_pointer,
            OBJECT_PREFIX_SIZE,
            f"{pass_name}.{country}.trade_league_object_prefix",
        )
        vtable_pointer = int.from_bytes(prefix[:8], "little", signed=False)
        # Publish the raw object prefix as soon as it is read.  If a later
        # vtable/code/vector read fails, the country item still retains the
        # original bytes and is not lost with the rest of the pass.
        result["object"] = {
            "address": _hex(object_pointer),
            "prefix_end_exclusive": "+0x40",
            "prefix_raw_hex": prefix.hex(),
            "vtable_pointer_raw_hex": prefix[:8].hex(),
            "vtable_pointer": _hex(vtable_pointer),
        }
        vtable_pointer = _checked_pointer(vtable_pointer, f"{country}.trade_league_vtable")
        method_address = memory._safe_add(
            vtable_pointer,
            VTABLE_METHOD_OFFSET,
            f"{pass_name}.{country}.trade_league_vtable_plus_40",
            aligned=True,
        )
        method_pointer, method_pointer_raw = _read_qword(
            reader, method_address, f"{pass_name}.{country}.trade_league_method_plus_40"
        )
        if not (module_base <= method_pointer < module_base + 0x4000000):
            raise memory.ProbeError(f"trade_league_method_not_in_module:{country}")
        result["object"].update(
            {
                "vtable_pointer": _hex(vtable_pointer),
                "vtable_plus_0x40_address": _hex(method_address),
                "vtable_plus_0x40_raw_hex": method_pointer_raw.hex(),
                "method_pointer": _hex(method_pointer),
                "method_rva": _hex(method_pointer - module_base),
            }
        )
        method_prefix = reader.read_code(
            method_pointer,
            METHOD_PREFIX_SIZE,
            f"{pass_name}.{country}.trade_league_method_code_prefix",
        )
        result["object"]["method_code_prefix_16_hex"] = method_prefix.hex()

        begin_raw = prefix[VECTOR_BEGIN_OFFSET:VECTOR_BEGIN_OFFSET + FULLREF_WIDTH]
        end_raw = prefix[VECTOR_END_OFFSET:VECTOR_END_OFFSET + FULLREF_WIDTH]
        begin = int.from_bytes(begin_raw, "little", signed=False)
        end = int.from_bytes(end_raw, "little", signed=False)
        if end < begin or (end - begin) % FULLREF_WIDTH:
            raise memory.ProbeError(f"trade_league_vector_order:{country}")
        count = (end - begin) // FULLREF_WIDTH
        if count > MAX_VECTOR_ENTRIES:
            raise memory.ProbeError(f"trade_league_vector_count_out_of_bound:{country}")
        if count and (begin % FULLREF_WIDTH or not memory._valid_pointer(begin)):
            raise memory.ProbeError(f"trade_league_vector_pointer_invalid:{country}")
        vector_raw = (b"" if count == 0 else reader.read(
            begin,
            count * FULLREF_WIDTH,
            f"{pass_name}.{country}.trade_league_fullref_vector",
        ))
        table_binding = pass_context.get("country_table_binding")
        if not isinstance(table_binding, Mapping):
            raise memory.ProbeError(f"country_table_binding_missing:{country}")
        elements = [
            _bind_fullref(
                vector_raw[index * FULLREF_WIDTH:(index + 1) * FULLREF_WIDTH],
                table_binding,
            )
            for index in range(count)
        ]
        result["object"]["vector"] = {
            "begin_offset": "+0x20",
            "end_offset": "+0x28",
            "begin_raw_hex": begin_raw.hex(),
            "end_raw_hex": end_raw.hex(),
            "begin": _hex(begin),
            "end": _hex(end),
            "count": count,
            "element_stride": FULLREF_WIDTH,
            "raw_hex": vector_raw.hex(),
            "first_fullref_index": 0 if count else None,
            "first_fullref_role": "LEADER display input observed by source contract; business meaning not inferred here",
            "elements": elements,
        }
        result["status"] = "observed"
    except Exception as exc:
        result["status"] = "unknown"
        result["reason"] = f"{type(exc).__name__}:{exc}"
    return result


def _canonical_inputs(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Exclude only log/context noise when comparing the two raw passes."""
    canonical: list[dict[str, Any]] = []
    for item in items:
        copy = deepcopy(dict(item))
        copy.pop("source_context", None)
        copy.pop("read_log_range", None)
        copy.pop("read_log", None)
        canonical.append(copy)
    return canonical


def _identity_guard(report: Mapping[str, Any]) -> None:
    identity = report.get("identity")
    if not isinstance(identity, Mapping):
        raise memory.ProbeError("identity_missing")
    checks = {
        "installation_pid": identity.get("installation_pid") == EXPECTED_PID,
        "installation_creation_filetime": identity.get("installation_creation_filetime") == EXPECTED_CREATION_FILETIME,
        "installation_session_id": identity.get("installation_session_id") == EXPECTED_SESSION_ID,
        "process_path_sha256": identity.get("process_path_sha256_matches_expected") is True,
        "process_creation": identity.get("process_creation_matches_installation") is True,
        "module_binding": identity.get("module_path_matches_process") is True,
    }
    if not all(checks.values()):
        raise memory.ProbeError("strict_identity_guard_failed:" + ",".join(key for key, ok in checks.items() if not ok))


def probe(
    installation: Path,
    *,
    countries: Sequence[str] = DEFAULT_COUNTRIES,
    output_path: Path | None = None,
) -> dict[str, Any]:
    selected = _parse_countries(countries)
    report = memory._base_report(installation, "FRA", [])
    report.update(
        {
            "schema": "information_independent_trade_league_inputs.v1",
            "probe": "information-trade-league-current-raw",
            "probe_version": 1,
            "probe_script": str(Path(__file__).resolve()),
            "probe_script_sha256": _file_sha256(Path(__file__).resolve()),
            "request": {
                "installation": str(installation),
                "countries": selected,
                "field": "trade_league",
            },
            "country_scope": selected,
            "target_build": {
                "version": EXPECTED_VERSION,
                "expected_exe_sha256": EXPECTED_EXE_SHA256,
                "native_source_contract": {
                    "country_trade_league_offset": hex(COUNTRY_TRADE_LEAGUE_OFFSET),
                    "object_prefix_size": hex(OBJECT_PREFIX_SIZE),
                    "vtable_method_slot": hex(VTABLE_METHOD_OFFSET),
                    "vector_begin_offset": hex(VECTOR_BEGIN_OFFSET),
                    "vector_end_offset": hex(VECTOR_END_OFFSET),
                    "virtual_invoked": False,
                },
            },
            "trade_league_inputs": [],
            "pass_context": [],
            "raw_capture": {
                "limits": {
                    "rpm_total_bytes": 512 * 1024,
                    "rpm_single_read_bytes": 64 * 1024,
                    "max_vector_entries": MAX_VECTOR_ENTRIES,
                    "max_countries": MAX_COUNTRIES,
                },
                "identity_strict": {
                    "pid": EXPECTED_PID,
                    "creation_filetime": EXPECTED_CREATION_FILETIME,
                    "session_id": EXPECTED_SESSION_ID,
                    "game_date": EXPECTED_GAME_DATE,
                },
                "two_passes": True,
                "no_native_call": True,
                "no_game_write": True,
                "no_save_restart_date_advance": True,
                "fullref_binding": "exact eight-byte equality against every country database entry country+0x20 record",
                "country_table_layout": {
                    "table_pointer_offset": "+0x118",
                    "signed_count_offset": "+0x124",
                    "country_fullref_offset": "+0x20",
                    "count_bound": MAX_VECTOR_ENTRIES,
                    "profile_country_scan_entries_ignored": True,
                },
            },
        }
    )
    kernel = None
    handle = None
    reader = None
    try:
        report["static_contract_guard"] = memory._static_contract_guard()
        if report["static_contract_guard"].get("status") != "observed":
            raise memory.ProbeError("static_contract_guard_failed")
        profile = memory._load_profile()
        document = memory._load_installation(Path(installation))
        kernel = memory._configure_kernel()
        pid = _as_int(document.get("pid"))
        if pid != EXPECTED_PID:
            raise memory.ProbeError(f"installation_pid_unexpected:{pid}")
        handle = kernel.OpenProcess(memory.PROCESS_ACCESS, False, pid)
        if not handle:
            raise memory.C.WinError(memory.C.get_last_error())
        module_base = memory._capture_identity(report, document, kernel, handle)
        _identity_guard(report)
        report["module_base"] = memory._address(module_base)
        process_path = Path(report["identity"]["process_path"])
        report["file_code_guard"] = memory._file_code_guard(process_path, profile)
        if report["file_code_guard"].get("status") != "observed":
            raise memory.ProbeError("file_code_guard_failed")
        reader = memory.AddressBoundedRPM(kernel, handle, module_base)
        for pass_index, pass_name in enumerate(("before", "after"), 1):
            pass_read_start = len(reader.read_log)
            runtime_guard = memory._runtime_code_guard(reader, module_base, profile)
            pass_inputs: list[dict[str, Any]] = []
            pass_record: dict[str, Any] = {
                "name": pass_name,
                "status": "unknown",
                "context": None,
                "runtime_code_guard": runtime_guard,
                "items": pass_inputs,
                "read_log_range": [pass_read_start, pass_read_start],
                "read_log": [],
                "error": None,
            }
            pass_context: dict[str, Any] = {}

            def append_unknown(country: str, reason: str) -> None:
                item = _capture_country_trade_league(
                    reader,
                    module_base,
                    country,
                    None,
                    pass_context,
                    pass_name=pass_name,
                )
                item["status"] = "unknown"
                item["reason"] = reason
                item_read_start = len(reader.read_log)
                item["read_log_range"] = [item_read_start, item_read_start]
                item["read_log"] = []
                pass_inputs.append(item)

            if runtime_guard.get("status") != "observed":
                pass_record["error"] = f"runtime_code_guard_failed:{pass_name}"
                for country in selected:
                    append_unknown(country, pass_record["error"])
            else:
                try:
                    pass_context = _capture_pass_context(
                        reader,
                        module_base,
                        profile,
                        pass_name=pass_name,
                    )
                    pass_record["context"] = pass_context
                    if pass_context.get("game_date", {}).get("value") != EXPECTED_GAME_DATE:
                        pass_record["error"] = f"game_date_mismatch:{pass_name}:{pass_context.get('game_date')}"
                    elif pass_context.get("status") != "observed":
                        pass_record["error"] = f"country_table_binding_failed:{pass_name}"
                    if pass_record["error"]:
                        for country in selected:
                            append_unknown(country, pass_record["error"])
                    else:
                        table_binding = pass_context.get("country_table_binding", {})
                        for country in selected:
                            country_read_start = len(reader.read_log)
                            entry = _resolve_country_table_entry(country, table_binding)
                            item = _capture_country_trade_league(
                                reader,
                                module_base,
                                country,
                                entry,
                                pass_context,
                                pass_name=pass_name,
                            )
                            if item.get("status") == "unknown" and not item.get("reason"):
                                item["reason"] = "country_observation_unknown"
                            item["read_log_range"] = [country_read_start, len(reader.read_log)]
                            item["read_log"] = deepcopy(reader.read_log[country_read_start:])
                            pass_inputs.append(item)
                except Exception as exc:
                    pass_record["error"] = f"{type(exc).__name__}:{exc}"
                    pass_record["context"] = pass_context or None
                    # Preserve any already captured country records and append
                    # only missing countries after a pass-level failure.
                    captured = {item.get("country") for item in pass_inputs}
                    for country in selected:
                        if country not in captured:
                            append_unknown(country, pass_record["error"])

            pass_record["status"] = "observed" if not pass_record["error"] and all(
                item.get("status") in {"observed", "empty"} for item in pass_inputs
            ) else "unknown"
            pass_record["read_log_range"] = [pass_read_start, len(reader.read_log)]
            pass_record["read_log"] = deepcopy(reader.read_log[pass_read_start:])
            if pass_record["error"]:
                report["errors"].append(
                    {
                        "stage": f"trade_league_probe.{pass_name}",
                        "status": "unknown",
                        "error": pass_record["error"],
                    }
                )
            report["pass_context"].append(pass_record)
            report["trade_league_inputs"].append({"pass": pass_name, "items": pass_inputs})
        before_items = report["trade_league_inputs"][0]["items"]
        after_items = report["trade_league_inputs"][1]["items"]
        mismatches = memory._diff_paths(
            _canonical_inputs(before_items), _canonical_inputs(after_items)
        )
        before_context = report["pass_context"][0]
        after_context = report["pass_context"][1]
        before_context_value = {
            "context": deepcopy(before_context.get("context")),
            "runtime_code_guard": deepcopy(before_context.get("runtime_code_guard")),
        }
        after_context_value = {
            "context": deepcopy(after_context.get("context")),
            "runtime_code_guard": deepcopy(after_context.get("runtime_code_guard")),
        }
        for context_value in (before_context_value.get("context"), after_context_value.get("context")):
            if isinstance(context_value, dict):
                context_value.pop("pass", None)
        context_mismatches = memory._diff_paths(
            before_context_value,
            after_context_value,
        )
        mismatches.extend(f"pass_context.{path}" for path in context_mismatches)
        report["doublepass"] = {
            "performed": True,
            "consistent": not mismatches,
            "mismatches": mismatches[:256],
            "atomic": False,
            "native_call": False,
        }
        if mismatches:
            report["status"] = "doublepass_mismatch"
            report["errors"].append(
                {
                    "stage": "doublepass",
                    "status": "unknown",
                    "error": "trade_league raw inputs changed between passes",
                    "paths": mismatches[:256],
                }
            )
        elif all(
            item.get("status") in {"observed", "empty"}
            for pass_items in (before_items, after_items)
            for item in pass_items
        ) and all(
            context.get("status") == "observed"
            for context in report["pass_context"]
        ):
            report["status"] = "observed"
            report["completed"] = True
        else:
            report["status"] = "partial_unknown"
            report["completed"] = False
    except Exception as exc:
        report["status"] = "error"
        report["errors"].append(
            {"stage": "trade_league_probe", "status": "unknown", "error": f"{type(exc).__name__}:{exc}"}
        )
    finally:
        if reader is not None:
            report["access"]["rpm_bytes_requested"] = reader.bytes_requested
            report["access"]["rpm_calls"] = reader.calls
        memory._apply_cleanup(report, kernel, handle)
    if output_path is not None:
        report["output_path"] = str(output_path)
    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly start the read-only two-pass capture")
    parser.add_argument("--installation", type=Path, default=DEFAULT_INSTALLATION)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--countries", nargs="+", default=list(DEFAULT_COUNTRIES), metavar="TAG")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not args.run:
        parser.print_help()
        return 0
    output = args.output if args.output.is_absolute() else ROOT / args.output
    if output.exists():
        raise SystemExit("refusing_to_overwrite_output")
    countries = _parse_countries(args.countries)
    report = probe(args.installation, countries=countries, output_path=output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "status": report.get("status"),
                "completed": report.get("completed"),
                "countries": countries,
                "passes": len(report.get("trade_league_inputs", [])),
                "rpm_bytes": report.get("access", {}).get("rpm_bytes_requested"),
                "rpm_calls": report.get("access", {}).get("rpm_calls"),
                "output": str(output),
            },
            ensure_ascii=False,
        )
    )
    return 0 if report.get("completed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
