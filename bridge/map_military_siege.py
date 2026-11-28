"""Read verified elapsed siege days for discovered, optionally scoped provinces.

The value is the NUM argument to the game's ``SIEGE_TIME_DESC`` tooltip.
This read-only source does not reconstruct the map badge, success probability,
phase progress, or next-stage timer. A null province siege pointer is not
reported as proof that every possible form of siege is absent.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from . import map_live_capture as _map
from . import map_military_forts as _forts
from .information import foreign_technology_capture as _owner
from .information import province_fort_capture as _fort_capture
from .information import province_state_memory as _state
from .information.truce_date_math import decode_date

SCHEMA = "eu4.map_military_sieges.v1"
ELAPSED_BASIS = "native_siege_time_desc_num"
_SIEGE_POINTER_OFFSET = 0x388
_ELAPSED_DAYS_OFFSET = 0x68
_SIEGE_VTABLE_RVA = 0x1C4A168
_SERIALIZER_RVA = 0x23C4A0
_CODE_GUARDS = (
    (0x13B0AF4, bytes.fromhex("488b4f408b7968")),
    (0x13B0B7F, bytes.fromhex(
        "4c8d05964289004c8985c8000000c785f00000000500000089bd28010000"
        "41b9020000004c8d4560488d15e2e69c00488d4c2440e8e8271000")),
    (0x23C719, bytes.fromhex("8b5e68ba152a0000")),
)


def _siege_guards(reader: Any, base: int) -> tuple[bytes, ...]:
    actual = tuple(_map._read(reader, base + rva, len(expected), "siege.code")
                   for rva, expected in _CODE_GUARDS)
    if any(value != expected for value, (_, expected) in zip(actual, _CODE_GUARDS)):
        raise ValueError("SIEGE_CODE_GUARD_MISMATCH")
    slot = _map._u64(reader, base + _SIEGE_VTABLE_RVA + 0x10, "siege.vtable_slot")
    if slot != base + _SERIALIZER_RVA:
        raise ValueError("SIEGE_VTABLE_GUARD_MISMATCH")
    return (*actual, slot.to_bytes(8, "little"))


def _read_pass(reader: Any, base: int, observer: str, ids: tuple[int, ...],
               participants: tuple[str, ...] | None) -> dict[str, Any]:
    # Reuse the fort path's observer admission, canonical owner check, and
    # discovery predicate before reading any province's siege pointer.
    scopes = _forts._read_pass(reader, base, observer, ids, participants)
    rows: dict[int, dict[str, Any]] = {}
    for province_id in ids:
        scope = scopes["values"][province_id]
        if scope["discovery"].get("value") is not True:
            continue
        if participants is not None and scope.get("participant") is not True:
            continue
        record = int(scope["binding"]["record_pointer"], 0)
        pointer = _map._u64(reader, record + _SIEGE_POINTER_OFFSET, "siege.pointer")
        row: dict[str, Any] = {"pointer": pointer, "elapsed_days": None}
        if participants is not None:
            row.update(owner=scope["owner"], owner_fullref=scope["owner_fullref"])
        if pointer:
            if not _state._is_user_address(pointer) or pointer & 7:
                raise ValueError("SIEGE_OBJECT_POINTER_INVALID")
            vtable = _map._u64(reader, pointer, "siege.object_vtable")
            if vtable != base + _SIEGE_VTABLE_RVA:
                raise ValueError("SIEGE_OBJECT_VTABLE_UNVERIFIED")
            raw = _map._read(reader, pointer + _ELAPSED_DAYS_OFFSET, 4, "siege.elapsed")
            elapsed = int.from_bytes(raw, "little", signed=True)
            if elapsed < 0:
                raise ValueError("SIEGE_ELAPSED_INVALID")
            row["elapsed_days"] = elapsed
        rows[province_id] = row
    return {"scope": scopes, "rows": rows}


def _observe(reader: Any, base: int, observer: str, ids: tuple[int, ...],
             profile: Mapping[str, Any], participants: tuple[str, ...] | None) -> dict[str, Any]:
    guards_before = _owner._guards(reader, base, profile)
    siege_guards_before = _siege_guards(reader, base)
    context_before = _owner._context(reader, base)
    first = _read_pass(reader, base, observer, ids, participants)
    second = _read_pass(reader, base, observer, ids, participants)
    context_after = _owner._context(reader, base)
    siege_guards_after = _siege_guards(reader, base)
    guards_after = _owner._guards(reader, base, profile)
    stable = (guards_before == guards_after and siege_guards_before == siege_guards_after
              and context_before == context_after and first == second)
    return {"stable": stable, "context_after": context_after,
            "rows": second["rows"] if stable else {}}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"schema": SCHEMA, "status": "unavailable", "reason": reason,
            "date": None, "date_raw": None, "identity": None, "world_token": None,
            "records": []}


def capture_sieges(installation: str | Path, observer: str, province_ids: Iterable[int],
                   *, participants: Iterable[str] | None = None) -> dict[str, Any]:
    """Capture elapsed days, bound to process identity, date, and observer.

    Only positively discovered provinces with a verified object are returned.
    With ``participants``, current owner membership is verified per pass and an
    owner is included in each record. Null pointers yield no record and are
    explicitly not classified as a verified absence. Data is not atomic.
    """
    path, observer, ids = _map._validate_request(installation, observer, province_ids)
    tags = _forts._participant_tags(participants, observer)
    report = _owner._capture_common(
        path, observer, observer=observer, schema="information.map_military_sieges.inner.v1",
        profile_sha256=_fort_capture.PROFILE_SHA256, load_profile=_fort_capture._load_profile,
        observe=lambda reader, base, country, profile: _observe(reader, base, country, ids, profile, tags),
        allow_observer_target=True, observer_scoped=True,
    )
    observation = report.get("observation")
    if (report.get("status") != "observed" or report.get("completed") is not True
            or not isinstance(observation, Mapping) or observation.get("stable") is not True):
        return _unavailable("SIEGE_CAPTURE_FAILED_OR_UNSTABLE")
    try:
        context = observation["context_after"]
        date_raw = context["game_date"]
        if type(date_raw) is not int:
            raise ValueError("invalid date")
        year, month, day, _ = decode_date(date_raw)
        identity = {key: report["request"].get(key) for key in ("pid", "creation_filetime", "session_id")}
        if (type(identity["pid"]) is not int or type(identity["creation_filetime"]) is not int
                or not isinstance(identity["session_id"], str) or not identity["session_id"]):
            raise ValueError("invalid identity")
        records = []
        rows = observation["rows"]
        for province_id in ids:
            row = rows.get(province_id)
            if row is None or row.get("pointer") == 0:
                continue
            elapsed = row.get("elapsed_days")
            if type(elapsed) is not int or elapsed < 0:
                raise ValueError("invalid elapsed days")
            result = {"province_id": province_id, "elapsed_days": elapsed}
            if tags is not None:
                owner = row.get("owner")
                if owner not in tags:
                    raise ValueError("invalid owner")
                result["owner"] = owner
            records.append(result)
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return _unavailable("SIEGE_CAPTURE_RESULT_INVALID")
    return {
        "schema": SCHEMA, "status": "partial", "observer": observer,
        "date": f"{year}.{month}.{day}", "date_raw": date_raw,
        "identity": identity, "world_token": _map._world_token(context), "records": records,
        "reason": "SIEGE_PERCENT_AND_NEXT_PHASE_UNVERIFIED",
        "field_metadata": {
            "elapsed_days": {"status": "known", "basis": ELAPSED_BASIS,
                             "scope": "positive_verified_objects"},
            "siege_percent": {"status": "unavailable"},
            "days_to_next_phase": {"status": "unavailable"},
            "null_pointer_proves_absence": False,
        },
        "source": {"read_only": True, "native_function_invoked": False, "writes": False,
                   "two_pass_per_province": True, "date_consistency": "before_after_equal"},
    }


__all__ = ["SCHEMA", "ELAPSED_BASIS", "capture_sieges"]
