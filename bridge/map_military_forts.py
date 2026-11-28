"""Read the G03 fort-level input for a set of discovered provinces.

This is a separate, read-only collection from the political map snapshot.
Consumers must compare the date and process/session identity before joining
the two.  The signed value is the input to the native ``fort_level`` scope
trigger, not a complete model of forts, garrisons, or siege progress.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from . import map_live_capture as _map
from .information import country_reference_memory as _country
from .information import foreign_technology_capture as _owner
from .information import province_fort_capture as _fort_capture
from .information import province_fort_memory as _fort
from .information import province_reference_memory as _province
from .information import province_state_memory as _state
from .information.truce_date_math import decode_date


SCHEMA = "eu4.map_military_forts.v1"
FIELD_BASIS = "native_fort_level_scope_trigger_input"
TERRAIN_BASIS = "configured_static_explicit_terrain_override"
_TERRAIN_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z", re.ASCII)
_INTEGER = re.compile(r"-?[0-9]+\Z", re.ASCII)


class FortCaptureError(ValueError):
    """A guard, identity, admission, or field read was not established."""


def _participant_tags(participants: Iterable[str] | None, observer: str) -> tuple[str, ...] | None:
    if participants is None:
        return None
    if isinstance(participants, (str, bytes, bytearray, Mapping)):
        raise FortCaptureError("FORT_PARTICIPANTS_INVALID")
    try:
        iterator = iter(participants)
    except TypeError as exc:
        raise FortCaptureError("FORT_PARTICIPANTS_INVALID") from exc
    tags: set[str] = set()
    for count, tag in enumerate(iterator, 1):
        if (count > _country.MAX_REQUESTED_TAGS or not isinstance(tag, str)
                or _map._TAG.fullmatch(tag) is None):
            raise FortCaptureError("FORT_PARTICIPANTS_INVALID")
        tags.add(tag)
    if len(tags | {observer}) > _country.MAX_REQUESTED_TAGS:
        raise FortCaptureError("FORT_PARTICIPANTS_INVALID")
    return tuple(sorted(tags))


def _read_pass(reader: Any, module_base: int, observer: str,
               province_ids: tuple[int, ...],
               participants: tuple[str, ...] | None = None) -> dict[str, Any]:
    """Resolve one pass using the same province and self-admission leaves as G03."""
    country_tags = [observer]
    if participants is not None:
        country_tags.extend(tag for tag in participants if tag != observer)
    countries = _country.resolve_countries(reader.read, module_base, country_tags)
    if not isinstance(countries, Mapping) or countries.get("status") != "observed":
        raise FortCaptureError("FORT_OBSERVER_RESOLUTION_FAILED")
    binding = _state._binding(countries, observer)
    if not isinstance(binding, Mapping):
        raise FortCaptureError("FORT_OBSERVER_BINDING_MISSING")
    slot = binding.get("slot")
    if type(slot) is not int or not 0 <= slot < _country.MAX_COUNTRY_SLOTS:
        raise FortCaptureError("FORT_OBSERVER_SLOT_INVALID")

    admission = _owner._bound_admission(reader.read, module_base, countries, observer, observer)
    gate_observer = admission.get("observer") if isinstance(admission, Mapping) else None
    gate_binding = gate_observer.get("binding") if isinstance(gate_observer, Mapping) else None
    if (not isinstance(admission, Mapping) or admission.get("status") != "known"
            or admission.get("admitted") is not True
            or not isinstance(gate_observer, Mapping) or gate_observer.get("tag") != observer
            or not isinstance(gate_binding, Mapping) or gate_binding.get("tag") != observer
            or gate_binding.get("slot") != slot
            or gate_binding.get("fullref_raw_hex") != binding.get("fullref_raw_hex")):
        raise FortCaptureError("FORT_SELF_ADMISSION_UNVERIFIED")

    participant_refs: dict[int, str] = {}
    participant_bindings: dict[str, dict[str, Any]] = {}
    if participants is not None:
        for tag in participants:
            participant_binding = _state._binding(countries, tag)
            if not isinstance(participant_binding, Mapping):
                raise FortCaptureError("FORT_PARTICIPANT_BINDING_UNVERIFIED")
            try:
                raw = bytes.fromhex(participant_binding["fullref_raw_hex"])
            except (KeyError, TypeError, ValueError):
                raise FortCaptureError("FORT_PARTICIPANT_BINDING_UNVERIFIED") from None
            # Confirm the table binding also satisfies the province-owner
            # canonical fullref checks, including all generation/flag bits.
            verified = _state._resolve_country_reference(reader, module_base, raw,
                                                          "map_fort_participant")
            ref = int.from_bytes(raw, "little", signed=False)
            if (len(raw) != 8 or verified.get("status") != "known"
                    or verified.get("value") != tag or ref in participant_refs):
                raise FortCaptureError("FORT_PARTICIPANT_BINDING_UNVERIFIED")
            participant_refs[ref] = tag
            participant_bindings[tag] = dict(participant_binding)

    # The identity resolver is bounded to 32 IDs; keep its full range, record
    # alignment and echoed-ID checks while sharing the observer scan per pass.
    header: dict[str, Any] | None = None
    values: dict[int, dict[str, Any]] = {}
    for start in range(0, len(province_ids), _province.MAX_REQUESTED_PROVINCES):
        ids = province_ids[start:start + _province.MAX_REQUESTED_PROVINCES]
        scan = _province.resolve_provinces(reader.read, module_base, ids)
        if not isinstance(scan, Mapping) or scan.get("status") != "observed":
            raise FortCaptureError("FORT_PROVINCE_RESOLUTION_FAILED")
        identity = {"world": scan.get("world"), "header": scan.get("header")}
        if header is None:
            header = identity
        elif not _owner._same(header, identity):
            raise FortCaptureError("FORT_PROVINCE_ARRAY_CHANGED")
        requested = scan.get("requested")
        if not isinstance(requested, Mapping):
            raise FortCaptureError("FORT_PROVINCE_BINDING_MISSING")
        for province_id in ids:
            province_binding = requested.get(str(province_id))
            if not isinstance(province_binding, Mapping):
                raise FortCaptureError("FORT_PROVINCE_BINDING_MISSING")
            record = int(province_binding["record_pointer"], 0)
            discovery = _state._read_discovery(reader, record, slot)
            if (not isinstance(discovery, Mapping) or discovery.get("status") != "known"
                    or type(discovery.get("value")) is not bool):
                raise FortCaptureError("FORT_DISCOVERY_UNVERIFIED")
            value: dict[str, Any] = {
                "binding": dict(province_binding),
                "discovery": dict(discovery),
                "level": None,
            }
            if discovery["value"]:
                if participants is not None:
                    # A nonmatching or unresolvable owner cannot prove scope
                    # membership, so do not read that province's fort level.
                    owner_ref = _map._u64(reader, record + _state.OWNER_FULLREF_OFFSET,
                                          f"map_fort.owner[{province_id}]")
                    owner_tag = participant_refs.get(owner_ref)
                    value.update({"owner_fullref": owner_ref, "owner": owner_tag,
                                  "participant": owner_tag is not None})
                    if owner_tag is None:
                        values[province_id] = value
                        continue
                leaf = _fort.read_fields(reader, module_base, province_binding,
                                         (_fort.FIELD_FORT_LEVEL,)).get(_fort.FIELD_FORT_LEVEL)
                if (not isinstance(leaf, Mapping) or leaf.get("status") != "known"
                        or leaf.get("basis") != FIELD_BASIS
                        or leaf.get("complete") is not False
                        or type(leaf.get("value")) is not int):
                    raise FortCaptureError("FORT_LEVEL_UNVERIFIED")
                value["level"] = leaf["value"]
            values[province_id] = value
    return {"observer_binding": binding, "admission": admission, "province_array": header,
            "participant_bindings": participant_bindings, "values": values}


def _observe_many(reader: Any, module_base: int, observer: str,
                  province_ids: tuple[int, ...], profile: Mapping[str, Any],
                  participants: tuple[str, ...] | None = None) -> dict[str, Any]:
    before_guard = _owner._guards(reader, module_base, profile)
    before_context = _owner._context(reader, module_base)
    if participants is None:
        first = _read_pass(reader, module_base, observer, province_ids)
        second = _read_pass(reader, module_base, observer, province_ids)
    else:
        first = _read_pass(reader, module_base, observer, province_ids, participants)
        second = _read_pass(reader, module_base, observer, province_ids, participants)
    after_context = _owner._context(reader, module_base)
    after_guard = _owner._guards(reader, module_base, profile)
    stable = (_owner._same(before_guard, after_guard)
              and _owner._same(before_context, after_context)
              and _owner._same(first, second))
    return {"stable": stable, "context_after": after_context,
            "values": second["values"] if stable else {}}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"schema": SCHEMA, "status": "unavailable", "reason": reason,
            "date": None, "date_raw": None, "identity": None, "records": []}


@lru_cache(maxsize=4)
def _parse_terrain_overrides(raw: bytes) -> Mapping[int, Mapping[str, Any]]:
    """Extract unambiguous explicitly configured overrides, not auto terrain."""
    from tools.build_diplomacy_catalog import parse_script

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252")
    nodes = parse_script(text)
    categories = [node for node in nodes if node.key == "categories"]
    if len(categories) != 1 or not categories[0].children:
        raise ValueError("TERRAIN_CATEGORIES_INVALID")
    result: dict[int, dict[str, Any]] = {}
    conflicts: set[int] = set()
    names: set[str] = set()
    for category in categories[0].children:
        name = category.key
        if (not isinstance(name, str) or not _TERRAIN_NAME.fullmatch(name)
                or name in names or not category.children):
            raise ValueError("TERRAIN_CATEGORY_INVALID")
        names.add(name)
        defence_nodes = [node for node in category.children if node.key == "defence"]
        bonus: int | None = None
        if len(defence_nodes) == 1:
            value = defence_nodes[0].value
            if (isinstance(value, str) and _INTEGER.fullmatch(value)
                    and not defence_nodes[0].children and -1000 <= int(value) <= 1000):
                bonus = int(value)
        for override in (node for node in category.children if node.key == "terrain_override"):
            for item in override.children or []:
                value = item.value if item.value is not None else item.key
                if (item.children or not isinstance(value, str) or not value.isascii()
                        or not value.isdigit() or not 1 <= int(value) <= 65535):
                    raise ValueError("TERRAIN_OVERRIDE_INVALID")
                province_id = int(value)
                row: dict[str, Any] = {"terrain": name}
                if bonus is not None:
                    row["terrain_bonus"] = bonus
                prior = result.get(province_id)
                if prior is not None and prior != row:
                    conflicts.add(province_id)
                else:
                    result[province_id] = row
    for province_id in conflicts:
        result.pop(province_id, None)
    return MappingProxyType({key: MappingProxyType(value) for key, value in result.items()})


def _terrain_overrides(game_root: str | Path | None,
                       user_data: str | Path | None) -> tuple[Mapping[int, Mapping[str, Any]], dict[str, Any]]:
    """Resolve selected mod layers and read the configured override file."""
    from . import map_geometry as geometry
    from .information.strait_definitions import StraitDefinitionIndex
    from tools.build_diplomacy_catalog import parse_script

    unavailable = {"status": "unavailable", "reason": "TERRAIN_OVERRIDE_SOURCE_UNAVAILABLE"}
    try:
        index = StraitDefinitionIndex(game_root=game_root, user_data=user_data)
        if index.context().get("status") != "ready":
            return {}, unavailable
        default_path = index._resolve_file("map/default.map")
        if default_path is None:
            return {}, unavailable
        default_raw = geometry._read_bounded(default_path, 4 * 1024 * 1024)
        default_nodes = parse_script(default_raw.decode("utf-8-sig"))
        terrain_path = geometry._resolve(index, default_nodes, "terrain_definition")
        terrain_raw = geometry._read_bounded(terrain_path, 4 * 1024 * 1024)
        overrides = _parse_terrain_overrides(terrain_raw)
        # Confirm both selected files and the mod configuration stayed fixed.
        if (index.context().get("status") != "ready"
                or geometry._read_bounded(default_path, 4 * 1024 * 1024) != default_raw
                or geometry._read_bounded(terrain_path, 4 * 1024 * 1024) != terrain_raw):
            return {}, unavailable
        return overrides, {
            "status": "partial", "basis": TERRAIN_BASIS,
            "terrain_definition_sha256": hashlib.sha256(terrain_raw).hexdigest(),
            "bonus_semantics": "explicit_defence_combat_dice_modifier",
            "not_included": ["automatic_terrain_assignment", "runtime_terrain_verification",
                             "implicit_defence_default"],
        }
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
        return {}, unavailable


def capture_forts(installation: str | Path, observer: str, province_ids: Iterable[int],
                  *, game_root: str | Path | None = None,
                  user_data: str | Path | None = None,
                  participants: Iterable[str] | None = None) -> dict[str, Any]:
    """Collect current fort-level inputs for positively discovered provinces.

    One bound read-only process handle, two independent passes, the pinned
    G03 profile and before/after identity and date checks are used.  Unknown
    discovery, failed reads, or any change reject the batch.  Undiscovered
    provinces have no record; zero is retained for discovered provinces. When
    participants are supplied, only provinces with a current, verified owner
    in that set are read and returned. An empty set returns no fort records.
    Explicit unambiguous static terrain overrides are added when the selected
    map assets can be read; they are not a runtime terrain observation.
    """
    path, observer, ids = _map._validate_request(installation, observer, province_ids)
    participant_tags = _participant_tags(participants, observer)

    def observe(reader: Any, base: int, _country_tag: str,
                profile: Mapping[str, Any]) -> dict[str, Any]:
        if participant_tags is None:
            return _observe_many(reader, base, observer, ids, profile)
        return _observe_many(reader, base, observer, ids, profile, participant_tags)

    report = _owner._capture_common(
        path, observer, observer=observer,
        schema="information.map_military_fort_capture.inner.v1",
        profile_sha256=_fort_capture.PROFILE_SHA256,
        load_profile=_fort_capture._load_profile,
        observe=observe,
        allow_observer_target=True, observer_scoped=True,
    )
    observation = report.get("observation")
    if (report.get("status") != "observed" or report.get("completed") is not True
            or not isinstance(observation, Mapping) or observation.get("stable") is not True):
        return _unavailable("FORT_CAPTURE_FAILED_OR_UNSTABLE")
    values = observation.get("values")
    context = observation.get("context_after")
    request = report.get("request")
    if not isinstance(values, Mapping) or not isinstance(context, Mapping) or not isinstance(request, Mapping):
        return _unavailable("FORT_CAPTURE_RESULT_INVALID")
    date_raw = context.get("game_date")
    try:
        if type(date_raw) is not int:
            raise ValueError("invalid date")
        year, month, day, _ = decode_date(date_raw)
        records = []
        for province_id in ids:
            row = values[province_id]
            if not isinstance(row, Mapping) or not isinstance(row.get("discovery"), Mapping):
                raise ValueError("invalid row")
            if row["discovery"].get("value") is True:
                if participant_tags is not None:
                    participant = row.get("participant")
                    owner_ref = row.get("owner_fullref")
                    owner_tag = row.get("owner")
                    if (type(participant) is not bool or type(owner_ref) is not int
                            or not 0 <= owner_ref < 1 << 64
                            or (participant and (owner_tag not in participant_tags
                                or _country._tag_from_fullref(owner_ref) != owner_tag))
                            or (not participant and owner_tag is not None)):
                        raise ValueError("invalid owner scope")
                    if not participant:
                        continue
                if type(row.get("level")) is not int:
                    raise ValueError("invalid level")
                record = {"province_id": province_id, "level": row["level"]}
                if participant_tags is not None:
                    record["owner"] = row["owner"]
                records.append(record)
        identity = {key: request.get(key) for key in ("pid", "creation_filetime", "session_id")}
        if (type(identity["pid"]) is not int or type(identity["creation_filetime"]) is not int
                or not isinstance(identity["session_id"], str) or not identity["session_id"]):
            raise ValueError("invalid identity")
    except (KeyError, TypeError, ValueError, OverflowError):
        return _unavailable("FORT_CAPTURE_RESULT_INVALID")
    terrain, terrain_metadata = _terrain_overrides(game_root, user_data)
    for row in records:
        row.update(terrain.get(row["province_id"], {}))
    return {
        "schema": SCHEMA,
        "status": "partial",
        "observer": observer,
        "date": f"{year}.{month}.{day}",
        "date_raw": date_raw,
        "world_token": _map._world_token(context),
        "identity": identity,
        "records": records,
        "requested_count": len(ids),
        "field_metadata": {
            "level": {"status": "known", "basis": FIELD_BASIS, "complete": False,
                      "scope": ("discovered_provinces" if participant_tags is None else
                                "discovered_provinces_owned_by_participants"), "signed": True},
            "terrain": terrain_metadata,
            "siege_progress": {"status": "unavailable", "reason": "SIEGE_PROGRESS_UNVERIFIED"},
        },
        "source": {"read_only": True, "native_function_invoked": False, "writes": False,
                   "two_pass_per_province": True, "date_consistency": "before_after_equal"},
    }


__all__ = ["SCHEMA", "FIELD_BASIS", "TERRAIN_BASIS", "FortCaptureError", "capture_forts"]
