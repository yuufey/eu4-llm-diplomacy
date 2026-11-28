"""Read the observer's land forces for the live military map.

Foreign units are deliberately excluded: diplomatic force-statistics access and
province discovery do not establish battlefield visibility. The group-location
join has been checked against a single saved/live scene, not movement or native
UI visibility; results therefore remain partial even when every own group is
read. See the corresponding research receipt under work/runtime.
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


def _read_pass(reader: Any, base: int, observer: str, ids: frozenset[int],
               profile: Mapping[str, Any], budget: Any) -> dict[str, Any]:
    """Read the complete own group chain, then restrict its output to ids."""
    country_pointer, binding = _forces._find_country(reader, base, observer, profile, budget)
    chain = _forces._read_force_chain(reader, country_pointer, observer, profile, budget)
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
            omissions.add("UNRECOGNIZED_OWN_GROUP_TYPE")
            details.append({"group": group["group_object"], "vtable": vtable})
            continue
        members = by_group.get(index, [])
        if not members:
            # An empty group has no displayed soldiers, but keep it in the
            # stability comparison so a newly populated vector is detected.
            details.append({"group": group["group_object"], "empty": True})
            continue
        if any(row.get("type_kind") not in (0, 1, 2) for row in members):
            omissions.add("OWN_GROUP_CONTAINS_UNRECOGNIZED_RECORD")
            details.append({"group": group["group_object"], "invalid_kinds": True})
            continue
        location = _map._u64(reader, group_ptr + _GROUP_LOCATION_OFFSET,
                            f"military.group[{index}].location")
        delta = location - provinces
        if (not _map._state._is_user_address(location) or delta <= 0
                or delta % _provinces.RECORD_STRIDE
                or delta // _provinces.RECORD_STRIDE >= province_count):
            omissions.add("OWN_GROUP_LOCATION_UNAVAILABLE")
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
            records.append({"province_id": province_id, "owner": observer,
                            "men": men, "relation": "own"})
    return {"binding": binding, "chain": chain, "province_records": provinces,
            "province_count": province_count, "details": details,
            "records": records, "omissions": sorted(omissions)}


def _observe(reader: Any, base: int, observer: str, ids: frozenset[int],
             province_profile: Mapping[str, Any]) -> dict[str, Any]:
    force_profile = _forces._load_profile()
    budget = _forces._ReadBudget()
    before_context = _owner._context(reader, base)
    before_guard = _owner._guards(reader, base, province_profile)
    force_guard_before = _forces._runtime_code_guard(reader, base, force_profile, budget)
    first = _read_pass(reader, base, observer, ids, force_profile, budget)
    second = _read_pass(reader, base, observer, ids, force_profile, budget)
    force_guard_after = _forces._runtime_code_guard(reader, base, force_profile, budget)
    after_context = _owner._context(reader, base)
    after_guard = _owner._guards(reader, base, province_profile)
    stable = (before_context == after_context and before_guard == after_guard
              and force_guard_before == force_guard_after
              and force_guard_before.get("status") == "observed" and first == second)
    return {"stable": stable, "context_after": after_context,
            "records": second["records"] if stable else [],
            "omissions": second["omissions"] if stable else []}


def capture_armies(installation: str | Path, observer: str,
                   province_ids: Iterable[int]) -> dict[str, Any]:
    """Return refreshed own forces and explicitly mark foreign coverage missing.

    No game function is invoked, no state is written, and records outside the
    requested province IDs are omitted after the complete own-chain read.
    """
    path, observer, ids = _map._validate_request(installation, observer, province_ids)
    started = perf_counter()
    report = _owner._capture_common(
        path, observer, observer=observer, schema="eu4.map_military_armies.inner.v1",
        profile_sha256=_province_capture.PROFILE_SHA256,
        load_profile=_province_capture._load_profile,
        observe=lambda reader, base, country, profile: _observe(reader, base, country, frozenset(ids), profile),
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
    return {
        "schema": SCHEMA, "status": "partial", "observer": observer,
        "date": f"{year}.{month}.{day}", "date_raw": date_raw,
        "identity": {key: report["request"].get(key) for key in
                     ("pid", "creation_filetime", "session_id")},
        "world_token": _map._world_token(context),
        "records": observation["records"], "reason": ", ".join(gaps), "gaps": gaps,
        "source": {"read_only": True, "native_function_invoked": False,
                   "writes": False, "two_pass": True,
                   "location_validation": "one_saved_live_scene_by_regiment_identity",
                   "foreign_armies": "not_read"},
        "timings": {"total_seconds": round(perf_counter() - started, 6),
                    "rpm_calls": report.get("access", {}).get("calls"),
                    "rpm_bytes": report.get("access", {}).get("bytes_requested")},
    }


__all__ = ["SCHEMA", "capture_armies"]
