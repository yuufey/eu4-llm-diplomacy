"""Capture a bounded country's native owned-province vector.

This reuses the verified foreign-country admission and occupation profile.  It
only copies the owned ID vector.  Province discovery and G02 field reads stay
in the public country-province adapter, where pagination can bound the work.
"""
from __future__ import annotations

import re

from . import foreign_pressure as _pressure
from . import foreign_country_memory as _countries
from . import foreign_technology_capture as _owner


SCHEMA = "information.country_province_ids_capture.v1"
FIELD = "G06.province_ids"
PROFILE_SHA256 = _pressure._OCCUPATION_PROFILE_SHA256
_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_MAX_ID = 65535


def _load_profile():
    return _pressure._load_occupation_profile()


def _read_owned_ids(read, binding, spec):
    pointer = int(binding["country_pointer"], 0)
    vector = int.from_bytes(read.read(pointer + spec["owned_vector_offset"], 8,
                                      "country_province_ids.owned_vector"), "little")
    count = int.from_bytes(read.read(pointer + spec["owned_count_offset"], 4,
                                     "country_province_ids.owned_count"), "little", signed=True)
    if not 0 <= count <= spec["max_owned_provinces"]:
        raise ValueError("COUNTRY_PROVINCE_IDS_COUNT_INVALID")
    raw = read.read(vector, count * 4, "country_province_ids.owned_ids") if count else b""
    ids = [int.from_bytes(raw[offset:offset + 4], "little", signed=True)
           for offset in range(0, len(raw), 4)]
    if (len(ids) != count or len(set(ids)) != count
            or any(type(province) is not int or not 1 <= province <= _MAX_ID for province in ids)):
        raise ValueError("COUNTRY_PROVINCE_IDS_VECTOR_INVALID")
    return {"status": "known", "value": sorted(ids), "count": count,
            "unit": "province_id", "scale": 1, "complete": True,
            "basis": "native_country_owned_province_vector"}


def _observe_for(observer="FRA"):
    def observe(reader, base, country, profile):
        def read_fields(read, module_base, binding, selected):
            return {FIELD: _read_owned_ids(read, binding, profile["occupation"])}

        def backend(read, module_base, target):
            return _countries.read_two_pass(
                read, module_base, observer, [target], fields=[FIELD],
                admission_reader=_owner._bound_admission, read_fields=read_fields,
            )

        return _owner._observe(reader, base, country, profile, backend_reader=backend,
                               observer=observer)
    return observe


def capture(installation, country, *, observer="FRA"):
    if not isinstance(country, str) or _TAG.fullmatch(country) is None:
        raise ValueError("COUNTRY_PROVINCE_IDS_COUNTRY_INVALID")
    if not isinstance(observer, str) or _TAG.fullmatch(observer) is None:
        raise ValueError("COUNTRY_PROVINCE_IDS_OBSERVER_INVALID")
    return _owner._capture_common(
        installation, country, observer=observer, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(observer), allow_observer_target=True,
        observer_scoped=True,
    )


def validate_capture(report, context, creation, country):
    if not isinstance(context, dict) or not isinstance(country, str):
        return False
    observer = context.get("observer")
    return _owner._validate_capture_common(
        report, context, creation, country, schema=SCHEMA,
        profile_sha256=PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(observer), allow_observer_target=True,
        require_access=True, observer_scoped=True,
    )


def project_fields(report):
    try:
        fields = report["observation"]["backend"]["targets"][0]["fields"]
        item = fields[FIELD]
    except (KeyError, IndexError, TypeError):
        raise ValueError("COUNTRY_PROVINCE_IDS_CAPTURE_SHAPE") from None
    if (not isinstance(item, dict) or item.get("status") != "known"
            or item.get("complete") is not True or item.get("unit") != "province_id"
            or not isinstance(item.get("value"), list)
            or any(type(value) is not int or not 1 <= value <= _MAX_ID for value in item["value"])
            or item["value"] != sorted(set(item["value"]))):
        raise ValueError("COUNTRY_PROVINCE_IDS_CAPTURE_INVALID")
    return {FIELD: {"status": "known", "value": list(item["value"]),
                    "count": len(item["value"]), "unit": "province_id", "scale": 1,
                    "complete": True, "basis": "native_country_owned_province_vector"}}


__all__ = ["capture", "validate_capture", "project_fields", "FIELD", "SCHEMA", "PROFILE_SHA256"]
