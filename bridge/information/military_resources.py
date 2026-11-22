"""N02 current sailor reserve and native land/naval force limits."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re
import struct
from typing import Mapping

from .country_state import _parameter_schema
from .model import InformationError, canonical
from .observation_time import context_identity, dates_match
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _VERSION, _observer_context_reason, _session_binding


FIELDS = ("sailors", "force_limits")
_CONTEXT_IDENTITY_KEYS = ("session_id", "game_sha256", "observer", "game_date", "game_version")
_FORCE_GAPS = ["DYNAMIC_PROCESSOR_VARIANTS_NOT_QUALIFIED", "NAVAL_GUI_SAMPLE_NOT_AUDITED",
               "CACHE_FRESHNESS_NOT_ATOMIC"]


def _display_sailors(raw):
    # Match cvtdq2ps -> divss 1000.0f -> mulss 1.0f -> cvttss2si.
    # Integer division differs near float32 rounding boundaries.
    float32 = lambda value: struct.unpack("<f", struct.pack("<f", value))[0]
    return int(float32(float32(raw) / 1000.0))


def _metadata(field):
    water = field == "sailors"
    return {"coverage": "available" if water else "partial", "complete": water,
            "source": "bridge.information.military_resources_memory.capture",
            "description": "本国当前水手储备；保留千分位原值及界面整数" if water else
                           "本国原生陆军与海军上限，分别标明团与舰船单位",
            "unit": "sailors" if water else "force_limit_counts", "scale": 1000 if water else 1,
            "period": "current",
            "basis": "native_country_sailors_reserve" if water else "native_country_land_naval_force_limits",
            "gaps": [] if water else list(_FORCE_GAPS)}


def _public_field(name, field):
    accepted = {"known"} if name == "sailors" else {"known", "partial"}
    if not isinstance(field, Mapping) or field.get("status") not in accepted:
        reason = field.get("reason") if isinstance(field, Mapping) else None
        if not isinstance(reason, str) or not re.fullmatch(r"[A-Z0-9_]{1,120}", reason):
            reason = "MILITARY_RESOURCES_FIELD_UNAVAILABLE"
        return {"status": "unknown", "reason": reason}
    if name == "sailors":
        raw = field.get("raw")
        if type(raw) is not int or not 0 <= raw < (1 << 31):
            raise ValueError("invalid_sailors")
        return {"status": "known", "value": raw, "raw": raw,
                "raw_hex": raw.to_bytes(4, "little", signed=True).hex(),
                "display_value": _display_sailors(raw), "unit": "sailors", "scale": 1000,
                "period": "current", "basis": "native_country_sailors_reserve",
                "value_origin": "copied_native_cache", "complete": True, "partial": False}
    values = field.get("value")
    if not isinstance(values, Mapping) or set(values) != {"land", "naval"}:
        raise ValueError("invalid_force_limits")
    public = {}
    for key, unit in (("land", "regiments"), ("naval", "ships")):
        row = values[key]
        if isinstance(row, Mapping) and row.get("status") == "unknown":
            reason = row.get("reason")
            if not isinstance(reason, str) or not re.fullmatch(r"[A-Z0-9_]{1,120}", reason):
                reason = "MILITARY_RESOURCES_FIELD_UNAVAILABLE"
            return {"status": "unknown", "reason": reason}
        if (not isinstance(row, Mapping) or type(row.get("value")) is not int
                or not 1 <= row["value"] <= 2147483 or type(row.get("raw")) is not int
                or row["raw"] != row["value"] * 1000
                or row.get("unit") != unit or type(row.get("scale")) is not int or row["scale"] != 1000):
            raise ValueError("invalid_force_limit_value")
        public[key] = {"value": row["value"], "raw": row["raw"], "unit": unit, "scale": 1000}
    return {"status": "known", "value": public, "unit": "force_limit_counts", "scale": 1,
            "period": "current", "basis": "native_country_land_naval_force_limits",
            "value_origin": "derived_from_copied_native_inputs", "complete": False,
            "partial": True, "gaps": list(_FORCE_GAPS)}


class NativeMilitaryResourcesSource(NativeTradeIncomeSource):
    event_types = ()

    def catalog(self):
        return [{"topic_id": "N02", "catalog_ids": ["N02"], "title": "本国军队与人力（资源与上限）",
                 "status": "available", "fields": {f: _metadata(f) for f in FIELDS},
                 "parameters": _parameter_schema("N02"), "object_types": ["country"],
                 "observer_roles": ["country"], "observer_scope": [],
                 "supported_versions": [_VERSION], "triggers": ["query", "periodic"],
                 "context_scope": "country_scope", "visibility": "country_scope",
                 "source": type(self).__name__}]

    def validate_query(self, query, context=None):
        if (not isinstance(query, dict) or set(query) - {"topic", "object", "fields", "parameters"}
                or query.get("topic") != "N02"):
            raise InformationError("invalid_parameters", "Expected an N02 military resources query")
        obj, fields = query.get("object"), query.get("fields")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"} or obj.get("type") != "country":
            raise InformationError("invalid_object", "A country object is required")
        country = obj.get("country")
        if not isinstance(country, str) or not re.fullmatch(r"[A-Z0-9]{3}", country):
            raise InformationError("invalid_object", "Expected a country tag")
        if (not isinstance(fields, list) or not fields or any(not isinstance(f, str) for f in fields)
                or len(set(fields)) != len(fields) or set(fields) - set(FIELDS)):
            raise InformationError("invalid_fields", "Expected unique supported military resource fields")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or set(parameters) - {"reference_recipient"}:
            raise InformationError("invalid_parameters", "Unknown military resource parameters")
        if "reference_recipient" in parameters:
            ref = parameters["reference_recipient"]
            if not isinstance(ref, str) or not re.fullmatch(r"[A-Z0-9]{3}", ref) or ref == country:
                raise InformationError("invalid_parameters", "reference_recipient must be a distinct country tag")
        if context is not None and (not isinstance(context, dict) or context.get("observer", country) != country):
            raise InformationError("observer_scope_mismatch", "N02 military resources are limited to the configured observer country")
        return {"topic": "N02", "object": deepcopy(obj), "fields": list(fields), "parameters": deepcopy(parameters)}

    def read(self, query, context=None):
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        country = normalized["object"]["country"]
        provenance = {"read_only": True, "native_function_invoked": False,
                      "adapter": "bridge.information.military_resources_memory.capture", "country": country}

        def result(fields):
            complete = bool(fields) and all(f.get("status") == "known" and f.get("complete") is True
                                            for f in fields.values())
            source = _source_info(type(self).__name__, current, complete=complete, provenance=provenance)
            source["context_scope"] = "country_scope"
            return _result(normalized, current, fields, complete, source)

        def failure(reason, unavailable=False):
            return result({f: {"status": "unavailable" if unavailable else "unknown", "reason": reason}
                           for f in normalized["fields"]})

        reason = _observer_context_reason(current)
        if reason:
            return failure(reason.replace("TRADE_INCOME", "MILITARY_RESOURCES"), True)
        try:
            before = self.context()
        except Exception:
            before = {}
        if (_observer_context_reason(before) or
                context_identity(before, _CONTEXT_IDENTITY_KEYS) !=
                context_identity(current, _CONTEXT_IDENTITY_KEYS)):
            return failure("MILITARY_RESOURCES_CONTEXT_STALE", True)
        installation, creation, reason = _session_binding(self.base_source)
        if reason or installation is None or creation is None:
            return failure("MILITARY_RESOURCES_INSTALLATION_UNAVAILABLE", True)
        try:
            module = import_module(".military_resources_memory", __package__)
            capture = self.capture if self.capture is not None else module.capture
            report = capture(installation, country=country)
        except Exception as exc:
            return failure("MILITARY_RESOURCES_CAPTURE_FAILED:" + type(exc).__name__)
        try:
            after = self.context()
        except Exception:
            after = {}
        if (_observer_context_reason(after) or
                context_identity(after, _CONTEXT_IDENTITY_KEYS) !=
                context_identity(before, _CONTEXT_IDENTITY_KEYS) or
                not dates_match(current.get("game_date"), before.get("game_date"),
                                after.get("game_date"))):
            return failure("MILITARY_RESOURCES_CONTEXT_CHANGED_DURING_CAPTURE")
        try:
            valid = module.validate_capture(report, before, creation, country)
        except Exception:
            valid = False
        if valid is not True:
            return failure("MILITARY_RESOURCES_CAPTURE_INVALID")
        provenance["capture_report_sha256"] = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
        fields = {}
        for name in normalized["fields"]:
            try:
                fields[name] = _public_field(name, report["before"]["record"]["fields"].get(name))
            except (ValueError, TypeError, KeyError):
                fields[name] = {"status": "unknown", "reason": "MILITARY_RESOURCES_FIELD_INVALID"}
        return result(fields)


__all__ = ["NativeMilitaryResourcesSource"]
