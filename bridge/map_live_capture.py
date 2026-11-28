"""Read a bounded political map snapshot from a running EU4 process.

The static province raster stays in :mod:`bridge.map_geometry`. This module
only supplies dynamic owner, controller and discovery values for requested
province IDs. It reuses the reviewed province-state read path and the common
identity guards. No game function is called and no process memory is written.
"""
from __future__ import annotations

from pathlib import Path
from hashlib import sha256
import re
from time import perf_counter
from typing import Any, Iterable, Mapping

from .information import foreign_technology_capture as _owner
from .information import country_reference_memory as _country
from .information import province_reference_memory as _province_ref
from .information import province_state_capture as _province_capture
from .information import province_state_memory as _state
from .information.truce_date_math import decode_date


SCHEMA = "eu4.map_live_capture.v1"
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
MAX_PROVINCES = 65535


class MapLiveCaptureError(ValueError):
    """Raised for invalid map requests or an unavailable live source."""


def _validate_request(installation: str | Path, observer: str,
                      province_ids: Iterable[int]) -> tuple[Path, str, tuple[int, ...]]:
    path = Path(installation).expanduser()
    if not path.is_file():
        raise MapLiveCaptureError("MAP_LIVE_INSTALLATION_MISSING")
    if not isinstance(observer, str) or _TAG.fullmatch(observer) is None:
        raise MapLiveCaptureError("MAP_LIVE_OBSERVER_INVALID")
    if isinstance(province_ids, (str, bytes)):
        raise MapLiveCaptureError("MAP_LIVE_PROVINCES_INVALID")
    try:
        values = tuple(province_ids)
    except TypeError as exc:
        raise MapLiveCaptureError("MAP_LIVE_PROVINCES_INVALID") from exc
    if not values or len(values) > MAX_PROVINCES:
        raise MapLiveCaptureError("MAP_LIVE_PROVINCES_COUNT_INVALID")
    if any(type(value) is not int or not 1 <= value <= 65535 for value in values):
        raise MapLiveCaptureError("MAP_LIVE_PROVINCE_ID_INVALID")
    if len(set(values)) != len(values):
        raise MapLiveCaptureError("MAP_LIVE_PROVINCES_DUPLICATE")
    return path, observer, values


def _read(reader: Any, address: int, size: int, label: str) -> bytes:
    if not _state._is_user_address(address) or not 0 < size <= 65536:
        raise MapLiveCaptureError("MAP_LIVE_ADDRESS_INVALID")
    raw = reader.read(address, size, label)
    if not isinstance(raw, bytes) or len(raw) != size:
        raise MapLiveCaptureError("MAP_LIVE_SHORT_READ")
    return raw


def _u64(reader: Any, address: int, label: str) -> int:
    return int.from_bytes(_read(reader, address, 8, label), "little", signed=False)


def _province_records(reader: Any, module_base: int, province_ids: tuple[int, ...]) -> dict[int, int]:
    global_address = module_base + _province_ref.PROVINCE_GLOBAL_RVA
    world = _u64(reader, global_address, "map_live.province_world")
    begin = _u64(reader, world + _province_ref.ARRAY_BEGIN_OFFSET, "map_live.province_begin")
    end = _u64(reader, world + _province_ref.ARRAY_END_OFFSET, "map_live.province_end")
    records = _u64(reader, world + _province_ref.RECORDS_POINTER_OFFSET, "map_live.province_records")
    if (not _state._is_user_address(world) or not _state._is_user_address(begin)
            or not _state._is_user_address(end) or not _state._is_user_address(records)
            or end < begin or (end - begin) % 8):
        raise MapLiveCaptureError("MAP_LIVE_PROVINCE_ARRAY_INVALID")
    count = (end - begin) // 8
    if not 1 < count <= 65536:
        raise MapLiveCaptureError("MAP_LIVE_PROVINCE_COUNT_INVALID")
    result: dict[int, int] = {}
    for province_id in province_ids:
        if province_id >= count:
            raise MapLiveCaptureError("MAP_LIVE_PROVINCE_ID_OUT_OF_RANGE")
        record = records + province_id * _province_ref.RECORD_STRIDE
        if not _state._is_user_address(record):
            raise MapLiveCaptureError("MAP_LIVE_PROVINCE_RECORD_INVALID")
        stored = int.from_bytes(_read(reader, record + _province_ref.RECORD_ID_OFFSET, 4,
                                      f"map_live.province_id[{province_id}]"), "little", signed=True)
        if stored != province_id:
            raise MapLiveCaptureError("MAP_LIVE_PROVINCE_RECORD_MISMATCH")
        result[province_id] = record
    return result


def _tag_from_fullref(fullref: int, known_refs: Mapping[str, int]) -> str | None:
    tag = _country._tag_from_fullref(fullref)
    if tag is None or tag not in known_refs or known_refs[tag] != fullref:
        return None
    return tag


def _verified_tag(reader: Any, module_base: int, fullref: int,
                  known_refs: Mapping[str, int], cache: dict[int, str | None]) -> str | None:
    """Resolve each observed fullref against the canonical country table once per pass."""
    if fullref not in cache:
        tag = _tag_from_fullref(fullref, known_refs)
        if tag is not None:
            proof = _state._resolve_country_reference(
                reader, module_base, fullref.to_bytes(8, "little"), "map_live_country")
            if proof.get("status") != "known" or proof.get("value") != tag:
                tag = None
        cache[fullref] = tag
    return cache[fullref]


def _world_token(context: Mapping[str, Any]) -> str | None:
    world = context.get("world_pointer")
    return sha256(world.encode("ascii")).hexdigest() if isinstance(world, str) else None


def _read_pass(reader: Any, module_base: int, observer: str,
               province_ids: tuple[int, ...]) -> dict[str, Any]:
    country_scan = _country.resolve_countries(reader.read, module_base, [observer])
    requested = country_scan.get("requested", {}) if isinstance(country_scan, Mapping) else {}
    binding = requested.get(observer) if isinstance(requested, Mapping) else None
    if not isinstance(binding, Mapping):
        raise MapLiveCaptureError("MAP_LIVE_OBSERVER_BINDING_MISSING")
    records = _province_records(reader, module_base, province_ids)
    known_refs = {
        row.get("tag"): int(row["fullref"], 16)
        for row in country_scan.get("rows", [])
        if isinstance(row, Mapping) and isinstance(row.get("tag"), str)
        and isinstance(row.get("fullref"), str)
    }
    slot = binding.get("slot")
    if type(slot) is not int or not 0 <= slot < _country.MAX_COUNTRY_SLOTS:
        raise MapLiveCaptureError("MAP_LIVE_OBSERVER_SLOT_INVALID")
    result: dict[int, dict[str, Any]] = {}
    raw_references: dict[int, tuple[int | None, int | None]] = {}
    verified_refs: dict[int, str | None] = {}
    for province_id, record in records.items():
        discovery_pointer = _u64(reader, record + _state.DISCOVERY_BITSET_POINTER_OFFSET,
                                 f"map_live.discovery_pointer[{province_id}]")
        word_address = discovery_pointer + (slot >> 5) * _state.DISCOVERY_WORD_STRIDE
        discovered = bool((int.from_bytes(_read(reader, word_address, 4,
                                                f"map_live.discovery_word[{province_id}]"),
                                          "little") >> (slot & 0x1F)) & 1)
        owner = None
        controller = None
        owner_ref = None
        controller_ref = None
        if discovered:
            owner_ref = _u64(reader, record + _state.OWNER_FULLREF_OFFSET, "map_live.owner")
            controller_ref = _u64(reader, record + _state.CONTROLLER_FULLREF_OFFSET,
                                  "map_live.controller")
            owner = _verified_tag(reader, module_base, owner_ref, known_refs, verified_refs)
            controller = _verified_tag(reader, module_base, controller_ref, known_refs, verified_refs)
        result[province_id] = {
            "discovered": discovered,
            "owner": owner,
            "controller": controller,
        }
        raw_references[province_id] = (owner_ref, controller_ref)
    return {"status": "observed", "values": result, "raw_references": raw_references}


def _observe_many(reader: Any, module_base: int, observer: str,
                  province_ids: tuple[int, ...], profile: Mapping[str, Any]) -> dict[str, Any]:
    before_guard = _owner._guards(reader, module_base, profile)
    before_context = _owner._context(reader, module_base)
    first = _read_pass(reader, module_base, observer, province_ids)
    second = _read_pass(reader, module_base, observer, province_ids)
    after_context = _owner._context(reader, module_base)
    after_guard = _owner._guards(reader, module_base, profile)
    stable_context = before_context == after_context and before_guard == after_guard
    stable_targets = (first["values"] == second["values"]
                      and first["raw_references"] == second["raw_references"])
    return {
        "status": "observed" if stable_context and stable_targets else "unknown",
        "observer": observer,
        "values": second["values"] if stable_targets else {},
        "requested_count": len(province_ids),
        "context_before": before_context,
        "context_after": after_context,
        "runtime_code_before": before_guard,
        "runtime_code_after": after_guard,
        "stable": stable_context and stable_targets,
    }


def capture_live(installation: str | Path, observer: str,
                 province_ids: Iterable[int]) -> dict[str, Any]:
    """Capture owners and occupations for requested provinces from the running game.

    ``installation`` is the existing observer ``installation.json``.  The
    process ID and creation time are read from that file and revalidated by the
    shared capture implementation before and after the read.  A returned owner
    is present only when the observer's discovery bit and the two-pass owner
    read are both known. ``controllers`` contains only positively discovered
    provinces with known, different owners and controllers. ``timings`` are
    local monotonic measurements.
    """
    path, observer, ids = _validate_request(installation, observer, province_ids)
    started = perf_counter()

    def observe(reader: Any, module_base: int, _country: str,
                profile: Mapping[str, Any]) -> dict[str, Any]:
        return _observe_many(reader, module_base, observer, ids, profile)

    report = _owner._capture_common(
        path, observer, observer=observer,
        schema="information.map_live_capture.inner.v1",
        profile_sha256=_province_capture.PROFILE_SHA256,
        load_profile=_province_capture._load_profile,
        observe=observe,
        allow_observer_target=True,
        observer_scoped=True,
    )
    elapsed = perf_counter() - started
    if report.get("status") != "observed" or report.get("completed") is not True:
        reason = (report.get("errors") or [{"reason": "MAP_LIVE_CAPTURE_FAILED"}])[0].get("reason")
        raise MapLiveCaptureError(str(reason))
    observation = report.get("observation")
    if not isinstance(observation, Mapping) or observation.get("stable") is not True:
        raise MapLiveCaptureError("MAP_LIVE_OBSERVATION_UNSTABLE")
    values = observation.get("values")
    if not isinstance(values, Mapping):
        raise MapLiveCaptureError("MAP_LIVE_RESULT_SHAPE_INVALID")
    discovered_province_ids = [
        int(province_id) for province_id, value in values.items()
        if isinstance(value, Mapping) and value.get("discovered") is True
    ]
    owners = {
        int(province_id): value.get("owner")
        for province_id, value in values.items()
        if isinstance(value, Mapping) and value.get("discovered") is True
    }
    controllers = {
        int(province_id): value["controller"]
        for province_id, value in values.items()
        if isinstance(value, Mapping) and value.get("discovered") is True
        and isinstance(value.get("owner"), str)
        and isinstance(value.get("controller"), str)
        and value["controller"] != value["owner"]
    }
    raw_date = observation["context_after"]["game_date"]
    year, month, day, _ = decode_date(raw_date)
    return {
        "schema": SCHEMA,
        "status": "known",
        "observer": observer,
        "date": f"{year}.{month}.{day}",
        "date_raw": raw_date,
        "world_token": _world_token(observation["context_after"]),
        "owners": owners,
        "controllers": controllers,
        "discovered_province_ids": discovered_province_ids,
        "requested_province_ids": list(ids),
        "identity": {
            "pid": report["request"].get("pid"),
            "creation_filetime": report["request"].get("creation_filetime"),
            "session_id": report.get("request", {}).get("session_id"),
        },
        "timings": {
            "total_seconds": round(elapsed, 6),
            "rpm_calls": report.get("access", {}).get("calls"),
            "rpm_bytes": report.get("access", {}).get("bytes_requested"),
        },
        "source": {
            "read_only": True,
            "native_function_invoked": False,
            "writes": False,
            "date_consistency": "before_after_equal",
            "two_pass_per_province": True,
        },
    }


__all__ = ["MAX_PROVINCES", "MapLiveCaptureError", "SCHEMA", "capture_live"]
