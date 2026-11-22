"""Expose bounded current loan and direct country modifier records.

Each topic uses one country capture and its real child validator.  A native
definition effect is kept separate from a final effective country attribute.
"""
from __future__ import annotations

from copy import deepcopy
from importlib import import_module
import re
from typing import Any, Mapping

from .country_state import NativeCountryStateSource, _parameter_schema
from .military_quality import _pointer_hex, _snapshot_country_pointer
from .model import InformationError, canonical
from .sources import _copy, _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource, _VERSION, _GAME_SHA256, _identity,
    _observer_context_reason, _session_binding,
)


_TOPICS = {
    "N01": ("本国财政（已核对字段）", "country_loans", "loans", ("loans", "loan_summary")),
    "N07": ("本国当前修正", "country_modifiers", "modifiers",
            ("modifier_id", "target", "effects", "name", "description")),
    "N08": ("修正期限与持续条件", "country_modifiers", "modifiers",
            ("modifier_start_date", "modifier_end_date", "remaining_days", "duration_type")),
}
_UNITS = {"loans": ("loan_records", 1), "loan_summary": ("loan_summary", 1),
          "modifier_id": ("identifier_collection", 1),
          "name": ("localized_text", 1), "description": ("localized_text", 1),
          "target": ("object_collection", 1), "effects": ("modifier_effect_records", 1),
          "modifier_start_date": ("game_date_raw", 1), "modifier_end_date": ("game_date_raw", 1),
          "remaining_days": ("days", 24), "duration_type": ("state_collection", 1)}
_DEFAULT_DATE = 0x29C77F8
_UNBOUNDED_DATE = 43800000


def _field_metadata(topic, field):
    unit, scale = _UNITS[field]
    value_origin = "copied_native_country_records"
    if topic == "N08":
        value_origin = "derived_from_copied_native_modifier_dates"
    elif field == "loan_summary":
        value_origin = "derived_from_validated_native_loan_principals"
    return {"coverage": "partial", "complete": False, "source": "NativeCountryRecordsSource",
            "runtime_validation": "validated_native_records", "unit": unit, "scale": scale,
            "period": "current", "raw": field != "loan_summary",
            "basis": "native_country_loan_records" if topic == "N01" else "native_direct_country_modifier_records",
            "value_origin": value_origin,
            "gaps": (["FOREIGN_LENDER_RUNTIME_SAMPLE_UNAVAILABLE", "NATIVE_LOAN_DISPLAY_TEXT_UNREAD",
                      "EXACT_LOAN_RTTI_UNRESOLVED"] if topic == "N01" else
                     ["DIRECT_COUNTRY_MODIFIER_LIST_ONLY", "MODIFIER_SOURCE_AND_ACTIVATION_NOT_CLOSED"]
                     + (["MODIFIER_UI_TEXT_BINDING_UNVERIFIED", "LITERAL_LOCALIZATION_ONLY"]
                        if field in {"name", "description"} else []))}


def _catalog_item(topic):
    title, _record, _child, fields = _TOPICS[topic]
    return {"topic_id": topic, "catalog_ids": [topic], "title": title, "status": "available",
            "fields": {f: _field_metadata(topic, f) for f in fields}, "object_types": ["country"],
            "parameters": _parameter_schema("N01") if topic == "N01" else
                          {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
            "supported_versions": [_VERSION], "triggers": ["query", "periodic"],
            "observer_roles": ["country"], "observer_scope": [],
            "visibility": "country_scope", "context_scope": "country_scope",
            "source": "NativeCountryRecordsSource", "scope_note":
            ("当前原生贷款列表；本金、利率、贷款方类型及到期日期的已证语义可读，缺项逐条保留。" if topic == "N01" else
             "当前国家直接修正实例及定义效果；不等同于理念、宗教、省份等全部修正来源或最终属性，结果保留partial。")}


def _child_reason(report, key, field):
    try:
        module = import_module(f".{key}_memory", __package__)
    except Exception:
        return "COUNTRY_RECORDS_VALIDATOR_UNAVAILABLE"
    expected_module = _pointer_hex(report.get("module_base"))
    before, after = report.get("before"), report.get("after")
    pointers = (_snapshot_country_pointer(before), _snapshot_country_pointer(after))
    if expected_module is None or any(p is None for p in pointers):
        return "COUNTRY_RECORDS_PARENT_POINTER_BINDING_INVALID"
    children = (report.get(key), before.get(key), after.get(key))
    for label, child, pointer in zip(("TOP", "BEFORE", "AFTER"), children, (pointers[0], *pointers)):
        if not isinstance(child, Mapping):
            return f"COUNTRY_RECORDS_{label}_MISSING"
        try:
            valid = module.validate_record(child)
        except Exception:
            valid = False
        if valid is not True:
            item = child.get("fields", {}).get(field, {})
            return item.get("reason") or f"COUNTRY_RECORDS_{label}_INVALID"
        if child.get("module_base") != expected_module or child.get("country_pointer") != pointer:
            return f"COUNTRY_RECORDS_{label}_CONTEXT_BINDING_INVALID"
        item = child.get("fields", {}).get(field)
        if not isinstance(item, Mapping) or item.get("status") != "known":
            return f"COUNTRY_RECORDS_{label}_FIELD_UNKNOWN"
    if canonical(children[0]) != canonical(children[1]) or canonical(children[0]) != canonical(children[2]):
        return "COUNTRY_RECORDS_CHILD_SNAPSHOT_MISMATCH"
    return None


def _modifier_projection(field, records, current_date, country):
    """Preserve native order; a default/unknown date stays explicit per row."""
    if field == "modifier_id":
        return [r["key"] for r in records]
    if field == "target":
        return [{"modifier_id": r["key"], "type": "country", "country": country} for r in records]
    if field == "effects":
        return [{"modifier_id": r["key"], "effects": [dict(deepcopy(e), scale=1000,
                                                          unit="native_fixed_point", business_unit="unknown")
                                                      for e in r["effects"]],
                 "basis": "native_modifier_definition_entries", "final_effective_value": False} for r in records]
    values = []
    for record in records:
        item = {"modifier_id": record["key"]}
        raw = record["start_date_raw"] if field == "modifier_start_date" else record["date_raw"]
        if field == "duration_type":
            if record.get("flags", {}).get("ruler_modifier") == 1:
                item.update(status="known", value="ruler_modifier")
            elif raw == _UNBOUNDED_DATE:
                item.update(status="known", value="no_fixed_end_date")
            elif raw != _DEFAULT_DATE and raw >= 0:
                item.update(status="known", value="fixed_term")
            else:
                item.update(status="unknown", reason="NATIVE_DURATION_CONDITION_UNRESOLVED")
        elif raw == _DEFAULT_DATE:
            item.update(status="unknown", reason="NATIVE_DATE_DEFAULT_OMITTED")
        elif raw == _UNBOUNDED_DATE and field != "modifier_start_date":
            item.update(status="not_applicable", reason="NATIVE_NEGATIVE_DURATION_HAS_NO_FIXED_END_DATE")
        elif raw < 0:
            item.update(status="unknown", reason="NATIVE_DATE_SENTINEL_UNRESOLVED", raw=raw)
        elif field == "remaining_days":
            item.update(status="known", value=raw-current_date, raw=raw-current_date,
                        unit="days", scale=24, basis="native_expiry_minus_current_game_date")
        else:
            item.update(status="known", value=raw, raw=raw,
                        raw_hex=raw.to_bytes(4, "little", signed=True).hex(), unit="game_date_raw", scale=1)
        values.append(item)
    return values


def _loan_summary(records):
    principal_values = [record.get("principal", {}) for record in records]
    known_values = [item["value"] for item in principal_values
                    if item.get("status") == "known" and type(item.get("value")) is int
                    and item["value"] >= 0]
    total = {"unit": "ducats", "scale": 1}
    if len(known_values) == len(records):
        total.update(status="known", value=sum(known_values))
    else:
        total.update(status="unknown", reason="LOAN_PRINCIPAL_INCOMPLETE",
                     known_subtotal=sum(known_values))
    return {"loan_count": len(records), "total_principal": total,
            "unknown_principal_count": len(records) - len(known_values)}


class NativeCountryRecordsSource(NativeTradeIncomeSource):
    event_types = ()

    def __init__(self, base_source, *, capture=None, localization_reader=None, modifier_definitions=None):
        super().__init__(base_source, capture=capture)
        self.localization_reader = localization_reader
        self.modifier_definitions = modifier_definitions

    def _named_effects(self, modifier_id):
        """Use configured effect names for the live direct-modifier instance."""
        try:
            if self.modifier_definitions is None:
                from .opinion_definitions import OpinionModifierDefinitionIndex
                self.modifier_definitions = OpinionModifierDefinitionIndex(
                    directory="common/event_modifiers", fields=None)
            definition = self.modifier_definitions.lookup(modifier_id)
        except Exception as exc:
            return {"status": "unknown", "reason": "MODIFIER_EFFECT_DEFINITION_UNAVAILABLE",
                    "error_type": type(exc).__name__}
        if definition.get("status") != "known":
            return definition
        effects = {}
        for name, declaration in definition["declarations"].items():
            if name in {"picture", "religion"}:
                continue
            if declaration.get("status") == "declared":
                effects[name] = {"status": "known", "value": float(declaration["value"])}
            else:
                effects[name] = deepcopy(declaration)
        return {"status": "known", "value": effects, "source_basis": "disk_configuration",
                "definition": definition.get("definition"), "source_pins": definition.get("source_pins")}

    def catalog(self):
        return [_catalog_item(t) for t in _TOPICS]

    def validate_query(self, query, context=None):
        if not isinstance(query, dict) or set(query)-{"topic", "object", "fields", "parameters"}:
            raise InformationError("invalid_parameters", "country record query must be an object with known keys")
        topic = query.get("topic")
        if topic not in _TOPICS:
            raise InformationError("unknown_topic", "Unsupported country record topic")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"} or obj.get("type") != "country":
            raise InformationError("invalid_object", "A country object is required")
        country = obj.get("country")
        if not isinstance(country, str) or not re.fullmatch(r"[A-Z0-9]{3}", country):
            raise InformationError("invalid_object", "Expected a country tag")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields or any(not isinstance(f, str) for f in fields)
                or len(set(fields)) != len(fields) or set(fields)-set(_TOPICS[topic][3])):
            raise InformationError("invalid_fields", "Fields must be unique supported country-record fields")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or set(parameters)-({"reference_recipient"} if topic == "N01" else set()):
            raise InformationError("invalid_parameters", "Unknown country-record parameters")
        if "reference_recipient" in parameters:
            if not isinstance(parameters["reference_recipient"], str) or not re.fullmatch(r"[A-Z0-9]{3}", parameters["reference_recipient"]):
                raise InformationError("invalid_parameters", "reference_recipient must be a country tag")
        if context is not None and (not isinstance(context, dict) or context.get("observer", country) != country):
            raise InformationError("observer_scope_mismatch", "Country records are limited to the configured observer country")
        return {"topic": topic, "object": deepcopy(obj), "fields": list(fields), "parameters": deepcopy(parameters)}

    def read(self, query, context=None):
        supplied = _copy(context) if isinstance(context, dict) else None
        current = supplied if supplied is not None else self.context()
        normalized = self.validate_query(query, current)
        topic = normalized["topic"]
        country = normalized["object"]["country"]
        _title, key, field, _fields = _TOPICS[topic]
        provenance = {"read_only": True, "native_function_invoked": False,
                      "adapter": "bridge.information.country_resources_memory.capture", "record_key": key}
        def result(fields, ctx=current):
            source = _source_info(type(self).__name__, ctx, complete=False, provenance=provenance)
            source["context_scope"] = "country_scope"
            return _result(normalized, ctx, fields, False, source)
        def failed(reason, unavailable=False, ctx=current):
            return result({f: {"status": "unavailable" if unavailable else "unknown", "reason": reason}
                           for f in normalized["fields"]}, ctx)
        reason = _observer_context_reason(current)
        if reason:
            return failed(reason.replace("TRADE_INCOME", "COUNTRY_RECORDS"), True)
        try:
            before = self.context() if supplied is not None else current
        except Exception:
            before = {}
        if _observer_context_reason(before) or _identity(before) != _identity(current):
            return failed("COUNTRY_RECORDS_CONTEXT_STALE", True)
        installation, creation, reason = _session_binding(self.base_source)
        if reason or installation is None or creation is None:
            return failed(reason or "COUNTRY_RECORDS_INSTALLATION_UNAVAILABLE", True)
        capture = self.capture
        if capture is None:
            from .country_resources_memory import capture
        report = None
        try:
            report = capture(installation, country, **{f"include_{key}": True})
        except Exception as exc:
            provenance["capture_error"] = type(exc).__name__
        try:
            after = self.context()
        except Exception:
            after = {}
        if _observer_context_reason(after) or _identity(before) != _identity(after):
            return failed("COUNTRY_RECORDS_CONTEXT_CHANGED_DURING_CAPTURE")
        reason = NativeCountryStateSource._capture_report_reason(report, before, country, creation)
        if reason:
            return failed(reason.replace("MONARCH_POINTS", "COUNTRY_RECORDS_PARENT"))
        if (report.get("target_build", {}).get("version") != _VERSION
                or report.get("target_build", {}).get("expected_exe_sha256") != _GAME_SHA256
                or report.get("request", {}).get(f"include_{key}") is not True):
            return failed("COUNTRY_RECORDS_PARENT_REQUEST_OR_BUILD_INVALID")
        reason = _child_reason(report, key, field)
        if reason:
            return failed(reason)
        provenance["capture_report_sha256"] = NativeCountryStateSource._capture_report_sha256(report)
        child = report[key]
        provenance["profile_sha256"] = child.get("profile_sha256")
        records = child["fields"][field]["value"]
        localized = None
        if topic == "N07" and set(normalized["fields"]) & {"name", "description"}:
            from .country_record_localization import NativeCountryModifierLocalizationSource
            localizer = NativeCountryModifierLocalizationSource(
                self.base_source, localization_reader=self.localization_reader)
            localized = localizer.localize_records(child, before, country=country)
            provenance["localization"] = deepcopy(localized.get("source", {}))
            provenance["native_records_and_text_atomic"] = False
            # A language-cache read is independent of the country capture.
            # Withdraw the whole mixed result if its session/date changed.
            try:
                final_context = self.context()
            except Exception:
                final_context = {}
            if _observer_context_reason(final_context) or _identity(before) != _identity(final_context):
                return failed("COUNTRY_RECORDS_CONTEXT_CHANGED_DURING_LOCALIZATION")
        fields = {}
        for name in normalized["fields"]:
            if name == "loan_summary":
                item = {"status": "known", "value": _loan_summary(records),
                        "unit": "loan_summary", "scale": 1, "period": "current",
                        "basis": "native_country_loan_records",
                        "value_origin": "derived_from_validated_native_loan_principals"}
            elif topic == "N01":
                item = deepcopy(child["fields"][field])
            elif name in {"name", "description"}:
                item = deepcopy(localized["fields"][name])
            else:
                value = _modifier_projection(name, records, before["game_date"], country)
                if name == "effects":
                    for modifier in value:
                        modifier["named_effects"] = self._named_effects(modifier["modifier_id"])
                unit, scale = _UNITS[name]
                item = {"status": "known", "value": value, "raw": deepcopy(value),
                        "unit": unit, "scale": scale, "period": "current",
                        "basis": "native_direct_country_modifier_records",
                        "value_origin": "derived_from_copied_native_modifier_dates" if topic == "N08" else "copied_native_country_records"}
            item.update(complete=False, partial=True, gaps=_field_metadata(topic, name)["gaps"])
            fields[name] = item
        return result(fields, before)

    def poll_events(self, context, cursor):
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {"events": [], "cursor": deepcopy(cursor) if cursor else {}, "complete": True, "gaps": []}


__all__ = ["NativeCountryRecordsSource"]
