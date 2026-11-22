"""Country-scoped counts and strength of existing native unit records.

The memory reader owns identity, code guards and complete two-pass traversal.
Only validated records enter this projection. Composition rows also retain
anonymous, sorted strength distributions within the current capture.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re
from typing import Any, Mapping

from .country_state import _parameter_schema
from .model import InformationError, canonical
from .observation_time import context_identity, dates_match
from .sources import _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource, _VERSION, _observer_context_reason, _session_binding,
)


FIELDS = ("army_size", "navy_size", "army_composition", "navy_composition")
BASIS = "native_country_existing_unit_records"
GAPS = ["COMBAT_READY_STATUS_UNREAD", "UNIT_TYPE_NAME_LOCALIZATION_MAY_BE_UNAVAILABLE"]
_CONTEXT_IDENTITY_KEYS = ("session_id", "game_sha256", "observer", "game_date", "game_version")
# The type object's +0x50 member feeds kind to ad8cd0, which maps 0..6.
# c159b0 passes kind 5 and country+d18 to d72790's shared record traversal.
_KINDS = {0: "infantry", 1: "cavalry", 2: "artillery",
          3: "heavy_ship", 4: "light_ship", 5: "galley",
          6: "transport"}


def _metadata(field):
    army = field.startswith("army")
    return {"coverage": "partial", "complete": False,
            "source": "NativeCountryForcesSource", "basis": BASIS,
            "unit": ("regiments" if army else "ships") if field.endswith("size") else "unit_category_counts",
            "scale": 1, "period": "current",
            "description": {
                "army_size": "本国现存陆军团记录数量，附原生 strength 总和及单位",
                "navy_size": "本国现存舰船记录数量，附原生 strength 总和及单位",
                "army_composition": "本国现存陆军团的类别、兵种定义key、strength及匿名记录分布",
                "navy_composition": "本国现存舰船的类别、兵种定义key、strength及匿名记录分布",
            }[field], "gaps": list(GAPS), "triggers": ["query", "periodic"]}


def _unit_types(records, strength_unit):
    by_key = {}
    unresolved = []
    reasons = set()
    for row in records:
        unit_type = row.get("unit_type")
        if (isinstance(unit_type, Mapping) and unit_type.get("status") == "known"
                and isinstance(unit_type.get("key"), str)
                and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", unit_type["key"])):
            by_key.setdefault(unit_type["key"], []).append(row["strength_raw"])
        else:
            unresolved.append(row["strength_raw"])
            reasons.add("UNIT_TYPE_KEY_NOT_CAPTURED" if unit_type is None else "UNIT_TYPE_KEY_UNAVAILABLE")
    values = [{"key": key, "name": {"status": "unknown", "key": key,
                                   "reason": "UNIT_TYPE_NAME_NOT_READ"},
               "count": len(strengths),
               "strength": {"raw": sum(strengths), "scale": 1000, "unit": strength_unit},
               "record_strengths": {"raw_values": sorted(strengths), "scale": 1000,
                                    "unit": strength_unit, "ordering": "ascending_strength",
                                    "identity_scope": "anonymous_records_current_capture"}}
              for key, strengths in sorted(by_key.items())]
    status = "known"
    if unresolved:
        status = "partial" if values else "unknown"
    return {"status": status, "complete": not unresolved, "value": values,
            "basis": "native_type_definition_key", "unresolved_records": len(unresolved),
            "unresolved_record_strengths": {"raw_values": sorted(unresolved), "scale": 1000,
                                            "unit": strength_unit}, "gaps": sorted(reasons)}


def _projection(records):
    if not isinstance(records, list) or len(records) > 1024:
        raise ValueError("COUNTRY_FORCES_RECORDS_INVALID")
    records_by_kind = {kind: [] for kind in _KINDS}
    seen = set()
    for row in records:
        if not isinstance(row, Mapping):
            raise ValueError("COUNTRY_FORCES_RECORD_INVALID")
        kind, strength = row.get("type_kind"), row.get("strength_raw")
        identity = (row.get("id_type"), row.get("id"))
        if (type(kind) is not int or kind not in _KINDS
                or type(strength) is not int or not 0 <= strength < (1 << 31)
                or any(type(v) is not int or not 0 < v <= 0xffffffff for v in identity)
                or identity in seen):
            raise ValueError("COUNTRY_FORCES_RECORD_INVALID")
        seen.add(identity)
        records_by_kind[kind].append(row)
    record_strengths = {kind: [row["strength_raw"] for row in rows]
                        for kind, rows in records_by_kind.items()}
    counts = {kind: len(values) for kind, values in record_strengths.items()}
    strengths = {kind: sum(values) for kind, values in record_strengths.items()}
    fields = {}
    for family, kinds, unit, strength_unit in (
        ("army", (0, 1, 2), "regiments", "serialized_regiment_strength"),
        ("navy", (3, 4, 5, 6), "ships", "serialized_ship_strength"),
    ):
        rows = [{"category": _KINDS[k], "native_kind": k,
                 "category_name_status": "known",
                 "count": counts[k], "count_unit": unit,
                 "strength": {"raw": strengths[k], "scale": 1000, "unit": strength_unit},
                 "record_strengths": {
                     "raw_values": sorted(record_strengths[k]),
                     "scale": 1000, "unit": strength_unit,
                     "ordering": "ascending_strength",
                     "identity_scope": "anonymous_records_current_capture"},
                 "unit_types": _unit_types(records_by_kind[k], strength_unit)}
                for k in kinds]
        base = {"status": "known", "scale": 1, "period": "current",
                "basis": BASIS, "partial": True, "complete": False,
                "scope": "direct_country_existing_unit_records", "gaps": list(GAPS)}
        fields[family + "_size"] = dict(
            deepcopy(base), value=sum(counts[k] for k in kinds), unit=unit,
            strength={"raw": sum(strengths[k] for k in kinds),
                      "scale": 1000, "unit": strength_unit})
        fields[family + "_composition"] = dict(
            deepcopy(base), value=rows, unit="unit_category_counts")
    return fields


class NativeCountryForcesSource(NativeTradeIncomeSource):
    """Expose the configured observer country's native unit records through N02."""

    event_types = ()

    def __init__(self, base_source, *, capture=None, localization_reader=None):
        super().__init__(base_source, capture=capture)
        self.localization_reader = localization_reader

    def _localize_types(self, fields, context):
        rows = [unit_type for name, field in fields.items() if name.endswith("_composition")
                for category in field["value"] for unit_type in category["unit_types"]["value"]]
        keys = sorted({row["key"] for row in rows})
        if not keys or self.localization_reader is None:
            return
        try:
            localized = self.localization_reader.localized_text(context["observer"], context, keys)
            entries = localized["entries"] if localized.get("status") == "known" else {}
            if not isinstance(entries, Mapping):
                entries = {}
        except Exception:
            localized, entries = {}, {}
        for row in rows:
            entry = entries.get(row["key"], {})
            name = {"status": "unknown", "key": row["key"], "reason": "UNIT_TYPE_NAME_UNAVAILABLE"}
            if (isinstance(entry, Mapping) and entry.get("status") == "known"
                    and isinstance(entry.get("text"), str)
                    and not any(marker in entry["text"] for marker in "[]$")):
                name = {"status": "known", "key": row["key"], "value": entry["text"],
                        "language": localized.get("language"), "source": "native_literal_localization_cache",
                        "native_widget_text_verified": False, "dynamic_substitution_evaluated": False,
                        "reader_provenance": deepcopy(localized.get("provenance", {}))}
            row["name"] = name

    def catalog(self):
        return [{"topic_id": "N02", "catalog_ids": ["N02"],
                 "title": "本国军队与人力（现存单位）", "status": "available",
                 "fields": {f: _metadata(f) for f in FIELDS},
                 "parameters": _parameter_schema("N02"),
                 "object_types": ["country"], "observer_roles": ["country"],
                 "observer_scope": [], "supported_versions": [_VERSION],
                 "triggers": ["query", "periodic"], "context_scope": "country_scope",
                 "visibility": "country_scope", "source": type(self).__name__}]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or set(query) - {"topic", "object", "fields", "parameters"}
                or query.get("topic") != "N02"):
            raise InformationError("invalid_parameters", "Expected an N02 country forces query")
        obj, fields = query.get("object"), query.get("fields")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"} or obj.get("type") != "country":
            raise InformationError("invalid_object", "A country object is required")
        country = obj.get("country")
        if not isinstance(country, str) or not re.fullmatch(r"[A-Z0-9]{3}", country):
            raise InformationError("invalid_object", "Expected a country tag")
        if (not isinstance(fields, list) or not fields or any(not isinstance(f, str) for f in fields)
                or len(set(fields)) != len(fields) or set(fields) - set(FIELDS)):
            raise InformationError("invalid_fields", "Expected unique supported forces fields")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or set(parameters) - {"reference_recipient"}:
            raise InformationError("invalid_parameters", "Unknown country forces parameters")
        if "reference_recipient" in parameters:
            ref = parameters["reference_recipient"]
            if not isinstance(ref, str) or not re.fullmatch(r"[A-Z0-9]{3}", ref) or ref == country:
                raise InformationError("invalid_parameters", "reference_recipient must be a distinct country tag")
        if context is not None and (not isinstance(context, dict) or context.get("observer", country) != country):
            raise InformationError("observer_scope_mismatch", "Unit records are limited to the configured observer country")
        return {"topic": "N02", "object": deepcopy(obj), "fields": list(fields),
                "parameters": deepcopy(parameters)}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        country = normalized["object"]["country"]
        provenance = {"read_only": True, "native_function_invoked": False,
                      "adapter": "bridge.information.country_forces_memory.capture",
                      "country": country, "basis": BASIS}

        def result(fields):
            source = _source_info(type(self).__name__, current, complete=False, provenance=provenance)
            source["context_scope"] = "country_scope"
            source["projection_version"] = 4
            return _result(normalized, current, fields, False, source)

        def failure(reason, unavailable=False):
            return result({f: {"status": "unavailable" if unavailable else "unknown", "reason": reason}
                           for f in normalized["fields"]})

        reason = _observer_context_reason(current)
        if reason:
            return failure(reason.replace("TRADE_INCOME", "COUNTRY_FORCES"), True)
        try:
            before = self.context()
        except Exception:
            before = {}
        if (_observer_context_reason(before) or
                context_identity(before, _CONTEXT_IDENTITY_KEYS) !=
                context_identity(current, _CONTEXT_IDENTITY_KEYS)):
            return failure("COUNTRY_FORCES_CONTEXT_STALE", True)
        installation, creation, reason = _session_binding(self.base_source)
        if reason or installation is None or creation is None:
            return failure("COUNTRY_FORCES_INSTALLATION_UNAVAILABLE", True)
        try:
            module = import_module(".country_forces_memory", __package__)
            if self.capture is None:
                report = module.capture(
                    installation, country=country,
                    include_type_keys=any(field.endswith("_composition") for field in normalized["fields"]))
            else:
                report = self.capture(installation, country=country)
        except Exception as exc:
            return failure("COUNTRY_FORCES_CAPTURE_FAILED:" + type(exc).__name__)
        try:
            after = self.context()
        except Exception:
            after = {}
        if (_observer_context_reason(after) or
                context_identity(after, _CONTEXT_IDENTITY_KEYS) !=
                context_identity(before, _CONTEXT_IDENTITY_KEYS) or
                not dates_match(current.get("game_date"), before.get("game_date"),
                                after.get("game_date"))):
            return failure("COUNTRY_FORCES_CONTEXT_CHANGED_DURING_CAPTURE")
        try:
            valid = module.validate_capture(report, before, creation, country)
        except Exception:
            valid = False
        if valid is not True:
            return failure("COUNTRY_FORCES_CAPTURE_INVALID")
        provenance["capture_report_sha256"] = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
        try:
            fields = _projection(report["before"]["record"]["records"])
        except (TypeError, ValueError, KeyError):
            return failure("COUNTRY_FORCES_RECORDS_INVALID")
        fields = {field: fields[field] for field in normalized["fields"]}
        if self.localization_reader is not None and any(field.endswith("_composition") for field in fields):
            self._localize_types(fields, after)
            try:
                final_context = self.context()
            except Exception:
                final_context = {}
            if (_observer_context_reason(final_context) or
                    context_identity(final_context, _CONTEXT_IDENTITY_KEYS) !=
                    context_identity(after, _CONTEXT_IDENTITY_KEYS) or
                    not dates_match(after.get("game_date"), final_context.get("game_date"))):
                return failure("COUNTRY_FORCES_CONTEXT_CHANGED_DURING_LOCALIZATION")
        return result(fields)


__all__ = ["NativeCountryForcesSource"]
