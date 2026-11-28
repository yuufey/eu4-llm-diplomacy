"""Read land forces for the live military map using a conservative scope.

Without a selected war only the observer's forces are emitted. With one,
same-side forces are included and enemies are limited to land provinces that
also contain an observer army. Discovery alone is not army visibility. The
co-location rule is a conservative projection, not a verified native display
predicate; the result remains partial. See the research receipts in work/runtime.
"""
from __future__ import annotations

from pathlib import Path
from time import perf_counter
from typing import Any, Iterable, Mapping

from . import map_live_capture as _map
from .information import country_forces_memory as _forces
from .information import foreign_technology_capture as _owner
from .information import province_reference_memory as _provinces
from .information import province_state_capture as _province_capture
from .information.truce_date_math import decode_date


SCHEMA = "eu4.map_military_armies.v1"
_LAND_VTABLE_RVA = 0x1C42540
_NAVAL_VTABLE_RVA = 0x1CCA618
_GROUP_LOCATION_OFFSET = 0xE8
_LOCATION_CODE_RVA = 0x1A2D7C
_LOCATION_CODE = bytes.fromhex("488b97e8000000")


def _read_environment(reader: Any, base: int) -> tuple[int, int]:
    """Read the shared province array and check the group-type guards."""
    world = _map._u64(reader, base + _provinces.PROVINCE_GLOBAL_RVA, "military.world")
    begin = _map._u64(reader, world + _provinces.ARRAY_BEGIN_OFFSET, "military.province_begin")
    end = _map._u64(reader, world + _provinces.ARRAY_END_OFFSET, "military.province_end")
    provinces = _map._u64(reader, world + _provinces.RECORDS_POINTER_OFFSET, "military.province_records")
    if (not _map._state._is_user_address(world) or not _map._state._is_user_address(begin)
            or not _map._state._is_user_address(end) or not _map._state._is_user_address(provinces)
            or end < begin or (end - begin) % 8 or not 1 < (end - begin) // 8 <= 65536):
        raise ValueError("MILITARY_PROVINCE_ARRAY_INVALID")
    province_count = (end - begin) // 8
    # Vtable methods 0x80/0x88 are the reviewed mutually exclusive land/naval
    # discriminator. Check their current entries and machine bytes before use.
    for vtable, expected_80, expected_88 in (
        (_LAND_VTABLE_RVA, 0x8F440, 0x8F450),
        (_NAVAL_VTABLE_RVA, 0x8F450, 0x8F440),
    ):
        if (_map._u64(reader, base + vtable + 0x80, "military.vtable80") != base + expected_80
                or _map._u64(reader, base + vtable + 0x88, "military.vtable88") != base + expected_88):
            raise ValueError("MILITARY_VTABLE_GUARD_MISMATCH")
    if (_map._read(reader, base + 0x8F440, 3, "military.true_method") != bytes.fromhex("b001c3")
            or _map._read(reader, base + 0x8F450, 3, "military.false_method") != bytes.fromhex("32c0c3")
            or _map._read(reader, base + _LOCATION_CODE_RVA, len(_LOCATION_CODE),
                          "military.location_code") != _LOCATION_CODE):
        raise ValueError("MILITARY_CODE_GUARD_MISMATCH")

    return provinces, province_count


def _read_country_groups(reader: Any, base: int, country: str, relation: str,
                         ids: frozenset[int], profile: Mapping[str, Any], budget: Any,
                         country_pointer: int, binding: Mapping[str, Any],
                         provinces: int, province_count: int) -> dict[str, Any]:
    """Apply the reviewed group, regiment and location joins to one country."""
    chain = _forces._read_force_chain(reader, country_pointer, country, profile, budget)
    by_group: dict[int, list[Mapping[str, Any]]] = {}
    for record in chain["records"]:
        by_group.setdefault(record["group_index"], []).append(record)
    records: list[dict[str, Any]] = []
    details: list[dict[str, Any]] = []
    omissions: set[str] = set()
    for index, group in enumerate(chain["groups"]):
        group_ptr = int(group["group_object"], 16)
        vtable = _map._u64(reader, group_ptr, f"military.group[{index}].vtable")
        if vtable == base + _NAVAL_VTABLE_RVA:
            continue
        if vtable != base + _LAND_VTABLE_RVA:
            omissions.add(f"UNRECOGNIZED_{relation.upper()}_GROUP_TYPE")
            details.append({"group": group["group_object"], "vtable": vtable})
            continue
        members = by_group.get(index, [])
        if not members:
            # An empty group has no displayed soldiers, but keep it in the
            # stability comparison so a newly populated vector is detected.
            details.append({"group": group["group_object"], "empty": True})
            continue
        if any(row.get("type_kind") not in (0, 1, 2) for row in members):
            omissions.add(f"{relation.upper()}_GROUP_CONTAINS_UNRECOGNIZED_RECORD")
            details.append({"group": group["group_object"], "invalid_kinds": True})
            continue
        location = _map._u64(reader, group_ptr + _GROUP_LOCATION_OFFSET,
                            f"military.group[{index}].location")
        delta = location - provinces
        if (not _map._state._is_user_address(location) or delta <= 0
                or delta % _provinces.RECORD_STRIDE
                or delta // _provinces.RECORD_STRIDE >= province_count):
            omissions.add(f"{relation.upper()}_GROUP_LOCATION_UNAVAILABLE")
            details.append({"group": group["group_object"], "location": location})
            continue
        province_id = delta // _provinces.RECORD_STRIDE
        actual_id = int.from_bytes(_map._read(reader, location + _provinces.RECORD_ID_OFFSET, 4,
                                              f"military.group[{index}].province_id"),
                                   "little", signed=True)
        if actual_id != province_id:
            raise ValueError("MILITARY_PROVINCE_RECORD_MISMATCH")
        men = sum(row["strength_raw"] for row in members)
        details.append({"group": group["group_object"], "location": location,
                        "province_id": province_id, "men": men})
        if province_id in ids:
            records.append({"province_id": province_id, "owner": country,
                            "men": men, "relation": relation})
    return {"binding": binding, "chain": chain, "province_records": provinces,
            "province_count": province_count, "details": details,
            "records": records, "omissions": sorted(omissions)}


def _read_pass(reader: Any, base: int, observer: str, ids: frozenset[int],
               profile: Mapping[str, Any], budget: Any) -> dict[str, Any]:
    """Read the complete own group chain, then restrict its output to ids."""
    country_pointer, binding = _forces._find_country(reader, base, observer, profile, budget)
    provinces, province_count = _read_environment(reader, base)
    return _read_country_groups(reader, base, observer, "own", ids, profile, budget,
                                country_pointer, binding, provinces, province_count)


def _find_countries(reader: Any, base: int, countries: frozenset[str],
                    profile: Mapping[str, Any], budget: Any) -> dict[str, Any]:
    """Resolve every requested country in one guarded country-table scan.

    This mirrors the slot/fullref/handle checks used by ``_find_country``.
    Including the table header and each match in the pass comparison detects
    rebinding between passes without re-scanning the table for each country.
    """
    layout = _forces._profile_layout(profile)
    add = _forces._add_address
    read_u64 = _forces._read_u64
    database, database_raw = read_u64(reader, add(base, layout["database_global_rva"], layout),
                                      "country_forces.database", budget, layout)
    if not _forces._valid_address(database, layout):
        raise _forces.ReadError("country_database_invalid")
    table, table_raw = read_u64(reader, add(database, layout["database_table_offset"], layout),
                                "country_forces.country_table", budget, layout)
    if not _forces._valid_address(table, layout):
        raise _forces.ReadError("country_table_invalid")
    count, count_raw = _forces._read_i32(
        reader, add(database, layout["database_table_count_offset"], layout),
        "country_forces.country_count", budget, layout)
    if not 1 <= count <= layout["database_max_slots"] + 1:
        raise _forces.ReadError("country_count_invalid")
    matches: dict[str, list[dict[str, Any]]] = {country: [] for country in sorted(countries)}
    for slot in range(count):
        ptr, ptr_raw = read_u64(reader, add(table, slot * 8, layout),
                                f"country_forces.country_table[{slot}]", budget, layout)
        if not ptr:
            continue
        if not _forces._valid_address(ptr, layout):
            raise _forces.ReadError("country_pointer_invalid")
        fullref, fullref_raw = read_u64(
            reader, add(ptr, layout["country_fullref_offset"], layout),
            f"country_forces.country_fullref[{slot}]", budget, layout)
        tag = _forces._tag_from_fullref(fullref)
        if tag in matches and ((fullref >> 32) & 0xFFFF) == slot:
            handle, handle_raw = read_u64(
                reader, add(ptr, layout["country_fullref_offset"], layout),
                f"country_forces.country_handle[{slot}]", budget, layout)
            if handle != fullref:
                raise _forces.ReadError("country_identity_changed_during_scan")
            matches[tag].append({"slot": slot, "pointer": hex(ptr),
                                 "fullref_raw_hex": fullref_raw.hex(), "tag": tag,
                                 "table_entry_raw_hex": ptr_raw.hex(),
                                 "country_handle": hex(handle),
                                 "country_handle_raw_hex": handle_raw.hex()})
    if any(len(items) != 1 for items in matches.values()):
        raise _forces.ReadError("country_identity_match_count_invalid")
    return {"database": hex(database), "database_raw_hex": database_raw.hex(),
            "table_pointer": hex(table), "table_raw_hex": table_raw.hex(),
            "country_count": count, "country_count_raw_hex": count_raw.hex(),
            "matches": {tag: items[0] for tag, items in matches.items()}}


def _read_war_pass(reader: Any, base: int, observer: str, ids: frozenset[int],
                   profile: Mapping[str, Any], budget: Any, *,
                   allies: frozenset[str], enemies: frozenset[str],
                   land_ids: frozenset[int]) -> dict[str, Any]:
    countries = _find_countries(reader, base, allies | enemies, profile, budget)
    provinces, province_count = _read_environment(reader, base)
    chains: dict[str, dict[str, Any]] = {}

    def read_country(tag: str, relation: str) -> None:
        binding = countries["matches"][tag]
        chains[tag] = _read_country_groups(
            reader, base, tag, relation, ids, profile, budget,
            int(binding["pointer"], 16), binding, provinces, province_count)

    for tag in sorted(allies):
        read_country(tag, "own" if tag == observer else "ally")
    own_provinces = {row["province_id"] for row in chains[observer]["records"]
                     if row["men"] > 0 and row["province_id"] in land_ids}
    # No enemy can pass the projection if there is no eligible own province.
    if own_provinces:
        for tag in sorted(enemies):
            read_country(tag, "enemy")
    basis = {"own": "observer_country", "ally": "selected_war_same_side",
             "enemy": "observer_army_same_land_province"}
    records = []
    omissions = set()
    for tag in sorted(chains):
        chain = chains[tag]
        omissions.update(chain["omissions"])
        records.extend({**row, "visibility_basis": basis[row["relation"]]}
                       for row in chain["records"]
                       if row["relation"] != "enemy" or row["province_id"] in own_provinces)
    return {"countries": countries, "chains": chains, "enemy_chains_read": bool(own_provinces),
            "records": records,
            "omissions": sorted(omissions)}


def _observe(reader: Any, base: int, observer: str, ids: frozenset[int],
             province_profile: Mapping[str, Any], *,
             war_scope: tuple[frozenset[str], frozenset[str], frozenset[int]] | None = None
             ) -> dict[str, Any]:
    force_profile = _forces._load_profile()
    budget = _forces._ReadBudget()
    before_context = _owner._context(reader, base)
    before_guard = _owner._guards(reader, base, province_profile)
    force_guard_before = _forces._runtime_code_guard(reader, base, force_profile, budget)
    if war_scope is None:
        first = _read_pass(reader, base, observer, ids, force_profile, budget)
        second = _read_pass(reader, base, observer, ids, force_profile, budget)
    else:
        allies, enemies, land_ids = war_scope
        first = _read_war_pass(reader, base, observer, ids, force_profile, budget,
                               allies=allies, enemies=enemies, land_ids=land_ids)
        second = _read_war_pass(reader, base, observer, ids, force_profile, budget,
                                allies=allies, enemies=enemies, land_ids=land_ids)
    force_guard_after = _forces._runtime_code_guard(reader, base, force_profile, budget)
    after_context = _owner._context(reader, base)
    after_guard = _owner._guards(reader, base, province_profile)
    stable = (before_context == after_context and before_guard == after_guard
              and force_guard_before == force_guard_after
              and force_guard_before.get("status") == "observed" and first == second)
    return {"stable": stable, "context_after": after_context,
            "records": second["records"] if stable else [],
            "omissions": second["omissions"] if stable else []}


def _war_scope(observer: str, allies: Iterable[str] | None, enemies: Iterable[str] | None,
               land_province_ids: Iterable[int] | None
               ) -> tuple[frozenset[str], frozenset[str], frozenset[int]] | None:
    if allies is None and enemies is None and land_province_ids is None:
        return None
    if allies is None or enemies is None or land_province_ids is None:
        raise _map.MapLiveCaptureError("MAP_MILITARY_ARMY_SCOPE_INVALID")
    if any(isinstance(value, (str, bytes)) for value in (allies, enemies, land_province_ids)):
        raise _map.MapLiveCaptureError("MAP_MILITARY_ARMY_SCOPE_INVALID")
    try:
        sides = (tuple(allies), tuple(enemies))
        land = tuple(land_province_ids)
    except TypeError as exc:
        raise _map.MapLiveCaptureError("MAP_MILITARY_ARMY_SCOPE_INVALID") from exc
    # The reviewed war source allows at most 256 country members per side.
    if any(not 1 <= len(side) <= 256 or any(
            not isinstance(tag, str) or _map._TAG.fullmatch(tag) is None for tag in side)
            or len(set(side)) != len(side) for side in sides):
        raise _map.MapLiveCaptureError("MAP_MILITARY_ARMY_SCOPE_INVALID")
    if (observer not in sides[0] or set(sides[0]) & set(sides[1])
            or len(land) > _map.MAX_PROVINCES
            or any(type(value) is not int or not 1 <= value <= 65535 for value in land)
            or len(set(land)) != len(land)):
        raise _map.MapLiveCaptureError("MAP_MILITARY_ARMY_SCOPE_INVALID")
    return frozenset(sides[0]), frozenset(sides[1]), frozenset(land)


def capture_armies(installation: str | Path, observer: str,
                   province_ids: Iterable[int], *, allies: Iterable[str] | None = None,
                   enemies: Iterable[str] | None = None,
                   land_province_ids: Iterable[int] | None = None) -> dict[str, Any]:
    """Return own forces or a partial projection of a selected war's forces.

    No game function is invoked, no state is written, and records outside the
    requested province IDs are omitted. If a war scope is supplied, it must
    contain both sides and land IDs from the current map projection. The caller
    must bind that scope to the same game date, process session and world as
    this capture. Enemy locations are emitted only where an observer land army
    with positive strength is also present; this is not a native visibility
    predicate and cannot establish complete coverage.
    """
    path, observer, ids = _map._validate_request(installation, observer, province_ids)
    scope = _war_scope(observer, allies, enemies, land_province_ids)
    started = perf_counter()
    report = _owner._capture_common(
        path, observer, observer=observer, schema="eu4.map_military_armies.inner.v1",
        profile_sha256=_province_capture.PROFILE_SHA256,
        load_profile=_province_capture._load_profile,
        observe=lambda reader, base, country, profile: _observe(
            reader, base, country, frozenset(ids), profile, war_scope=scope),
        allow_observer_target=True, observer_scoped=True,
    )
    if report.get("status") != "observed" or report.get("completed") is not True:
        errors = report.get("errors") or []
        reason = errors[0].get("reason") if errors else "MILITARY_ARMY_CAPTURE_FAILED"
        return {"schema": SCHEMA, "status": "unavailable", "records": [],
                "date": None, "date_raw": None, "identity": None, "reason": reason}
    observation = report.get("observation")
    if not isinstance(observation, Mapping) or observation.get("stable") is not True:
        return {"schema": SCHEMA, "status": "unavailable", "records": [],
                "date": None, "date_raw": None, "identity": None,
                "reason": "MILITARY_ARMY_OBSERVATION_UNSTABLE"}
    context = observation["context_after"]
    date_raw = context["game_date"]
    year, month, day, _ = decode_date(date_raw)
    gaps = ["FOREIGN_ARMY_VISIBILITY_UNVERIFIED", *observation["omissions"]]
    if scope is not None:
        gaps.append("WAR_ENEMIES_OUTSIDE_OBSERVER_ARMY_PROVINCES_NOT_INCLUDED")
    result = {
        "schema": SCHEMA, "status": "partial", "observer": observer,
        "date": f"{year}.{month}.{day}", "date_raw": date_raw,
        "identity": {key: report["request"].get(key) for key in
                     ("pid", "creation_filetime", "session_id")},
        "world_token": _map._world_token(context),
        "records": observation["records"], "reason": ", ".join(gaps), "gaps": gaps,
        "source": {"read_only": True, "native_function_invoked": False,
                   "writes": False, "two_pass": True,
                   "location_validation": "one_saved_live_scene_by_regiment_identity",
                   "foreign_armies": ("not_read" if scope is None else
                                      "selected_war_same_side_and_colocated_enemies")},
        "timings": {"total_seconds": round(perf_counter() - started, 6),
                    "rpm_calls": report.get("access", {}).get("calls"),
                    "rpm_bytes": report.get("access", {}).get("bytes_requested")},
    }
    if scope is not None:
        result["fields"] = {"visibility": {
            "status": "partial",
            "own": "observer_country",
            "allies": "selected_war_same_side",
            "enemies": "observer_army_same_land_province",
            "native_visibility_rule_verified": False,
        }}
    return result


__all__ = ["SCHEMA", "capture_armies"]
