"""Read verified pair relations and the observer's supported relation networks."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
from typing import Any

from .model import InformationError, canonical
from .observation_time import active as observation_window_active, dates_match
from .relation_records import SUPPORTED_FAMILIES, project
from .sources import _result, _source_info
from .subject_relations import (
    NativeSubjectRelationSource, _identity_reason, _identity_snapshot, _is_country,
)


_ACTIONS = dict(zip(SUPPORTED_FAMILIES, (
    "offer_vassalization", "proclaim_guarantee", "support_independence",
    "ask_military_access", "set_rival",
)))
_LEGACY_MEMORY_FAMILIES = ("alliance", "royal_marriage")
_EXTENSION_FAMILIES = ("fleet_basing", "trade_league")
_MEMORY_FAMILIES = (*_LEGACY_MEMORY_FAMILIES, *_EXTENSION_FAMILIES)
_DIRECTED_NETWORK_FAMILIES = ("guarantee", "military_access")
_NETWORK_FAMILIES = (*_MEMORY_FAMILIES, *_DIRECTED_NETWORK_FAMILIES)
_FAMILIES = (*_ACTIONS, *_MEMORY_FAMILIES)
_FIELDS = ("relation_type", "status", "grantor", "recipient")
_SCOPE_GAPS = ["SELECTED_COUNTRY_PAIR_ONLY", "RELATION_FAMILIES_NOT_EXHAUSTIVE"]
_CATALOG_GAPS = ["COUNTRY_NETWORK_FAMILIES_NOT_EXHAUSTIVE", "RELATION_EXPIRY_NOT_IMPLEMENTED"]


def _capture_validation_context(context, report):
    """Rebind a validated capture to the context date without relaxing identity."""
    if not observation_window_active():
        return context
    context_before = report.get("context_before") if isinstance(report, dict) else None
    context_after = report.get("context_after") if isinstance(report, dict) else None

    def value(source):
        if not isinstance(source, dict):
            return None
        item = source.get("game_date")
        date = item.get("value") if isinstance(item, dict) else item
        return date if type(date) is int else None

    after_date = value(context_after)
    if after_date is None:
        return None
    dates = [context.get("game_date")]
    before_date = value(context_before)
    if isinstance(context_before, dict) and "game_date" in context_before:
        if before_date is None:
            return None
        dates.append(before_date)
    dates.append(after_date)
    if not dates_match(*dates):
        return None
    validator_context = deepcopy(context)
    validator_context.pop("game_date", None)
    return validator_context


def _parameters():
    return {
        "type": "object", "required": [], "additionalProperties": False,
        "properties": {"relation_types": {
            "type": "array", "minItems": 1, "maxItems": len(_FAMILIES),
            "uniqueItems": True, "items": {"type": "string", "enum": list(_FAMILIES)},
        }},
    }


class NativeRelationSource(NativeSubjectRelationSource):
    """Reuse native read-only inspections without dispatching diplomatic actions.

    Existing inspections and bounded cache captures are separate observations.
    Context checks withdraw stale results without claiming an atomic snapshot.
    """

    def __init__(self, base_source, *, relation_capture=None, network_capture=None,
                 fleet_basing_capture=None, trade_league_capture=None,
                 directed_relation_capture=None):
        super().__init__(base_source)
        self.relation_capture = relation_capture
        self.network_capture = network_capture
        self.extension_captures = {"fleet_basing": fleet_basing_capture, "trade_league": trade_league_capture}
        self.directed_relation_capture = directed_relation_capture

    def catalog(self):
        return [{
            "topic_id": "R01", "catalog_ids": ["R01"],
            "title": "本国关系网与选定国家对（部分类型）", "status": "available",
            "object_types": ["country_pair", "country"], "parameters": _parameters(),
            "relation_types_by_object": {"country_pair": list(_FAMILIES), "country": list(_NETWORK_FAMILIES)},
            "observer_roles": ["country"], "observer_scope": [],
            "supported_versions": ["1.37.4"], "triggers": ["query", "periodic", "change"],
            "change_detection": "sampled_state_comparison_not_lossless_events",
            "source": "NativeRelationSource",
            "visibility": "visible_scope", "context_scope": "adapter_managed",
            "scope_note": "国家对支持九类。观察国关系网支持联盟、联姻、贸易联盟、驻港权、保证和显式军事访问，共六类。",
            "fields": {field: {
                "coverage": "partial", "complete": False, "unit": "relation_records",
                "source": "native_diplomacy_inspections_and_current_relation_caches",
                "direction": "selected_country_pair_or_country_network", "relation_types": list(_FAMILIES),
                "relation_types_by_object": {"country_pair": list(_FAMILIES), "country": list(_NETWORK_FAMILIES)},
                "gaps": list(_CATALOG_GAPS),
            } for field in _FIELDS},
        }]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict) or set(query) != {"topic", "object", "fields", "parameters"}:
            raise InformationError("invalid_parameters", "R01 requires topic, object, fields and parameters")
        if query["topic"] != "R01":
            raise InformationError("unknown_topic", "NativeRelationSource supports R01 only")
        obj = query["object"]
        if not isinstance(obj, dict):
            raise InformationError("invalid_object", "R01 requires a country or country_pair object")
        network = obj.get("type") == "country"
        if network:
            if set(obj) != {"type", "country"} or not _is_country(obj.get("country")):
                raise InformationError("invalid_object", "R01 country requires a country tag")
            actor = obj["country"]
        else:
            if (set(obj) != {"type", "actor", "recipient"} or obj.get("type") != "country_pair"
                    or not _is_country(obj.get("actor")) or not _is_country(obj.get("recipient"))
                    or obj["actor"] == obj["recipient"]):
                raise InformationError("invalid_object", "R01 requires two distinct country_pair endpoints")
            actor = obj["actor"]
        fields = query["fields"]
        if (not isinstance(fields, list) or not fields or any(not isinstance(f, str) for f in fields)
                or len(set(fields)) != len(fields) or set(fields) - set(_FIELDS)):
            raise InformationError("invalid_fields", "R01 requires unique supported relation fields")
        parameters = query["parameters"]
        if not isinstance(parameters, dict) or set(parameters) - {"relation_types"}:
            raise InformationError("invalid_parameters", "R01 supports relation_types only")
        supported = _NETWORK_FAMILIES if network else _FAMILIES
        families = parameters.get("relation_types", list(supported))
        if (not isinstance(families, list) or not 1 <= len(families) <= len(_FAMILIES)
                or any(not isinstance(f, str) for f in families)
                or len(set(families)) != len(families) or set(families) - set(supported)):
            raise InformationError("invalid_parameters", "relation_types must be a nonempty unique list supported by this object view")
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            if context.get("observer") is not None and context["observer"] != actor:
                raise InformationError("observer_scope_mismatch", "R01 actor must match the configured observer country")
        normalized = {"topic": "R01", "object": deepcopy(obj), "fields": list(fields),
                      "parameters": {"relation_types": list(families)}}
        canonical(normalized)
        return normalized

    @staticmethod
    def _assemble(query, context, fields, calls, *, reason=None, unavailable=False):
        scope = "country_relation_network" if query["object"]["type"] == "country" else "selected_country_pair"
        provenance = {
            "adapter": "NativeRelationSource", "read_only": True,
            "public_adapter": "DiplomacyTools.inspect_diplomatic_action",
            "read_adapters": ["native_diplomacy_inspections", "relation_memory.capture",
                              "fleet_basing_memory.capture", "trade_league_memory.capture",
                              "directed_relation_memory.capture"],
            "inspection_calls": deepcopy(calls), "phase": "initiate",
            "scope": scope, "observer_scope": context.get("observer"), "global_relation_claim": False,
            "atomic_snapshot_claim": False,
        }
        if reason:
            provenance["reason"] = reason
        source = _source_info("NativeRelationSource", context, complete=False, provenance=provenance)
        if unavailable:
            source["status"] = "unavailable"
        source["context_scope"] = scope
        return _result(query, context, fields, False, source)

    def _memory_report(self, actor, recipient, families, context):
        """Read both membership families once, with the real capture validator."""
        from .trade_income import _session_binding

        installation, creation, reason = _session_binding(self.base_source)
        if reason:
            return None, reason.replace("TRADE_INCOME_", "RELATION_MEMORY_")
        try:
            from . import relation_memory
            if recipient is None:
                capture = self.network_capture or relation_memory.capture_network
                report = capture(installation, actor, families)
                validation_context = _capture_validation_context(context, report)
                valid = (validation_context is not None and relation_memory.validate_network_capture(
                    report, validation_context, creation, actor, families))
            else:
                capture = self.relation_capture or relation_memory.capture
                report = capture(installation, actor, recipient, families)
                validation_context = _capture_validation_context(context, report)
                valid = (validation_context is not None and relation_memory.validate_capture(
                    report, validation_context, creation, actor, recipient, families))
            if valid is not True:
                return None, "RELATION_MEMORY_CAPTURE_INVALID"
            return report, None
        except Exception as exc:
            return None, "RELATION_MEMORY_READ_FAILED:" + type(exc).__name__

    def _extension_report(self, family, actor, recipient, context):
        from .trade_income import _session_binding

        installation, creation, reason = _session_binding(self.base_source)
        if reason:
            return None, reason.replace("TRADE_INCOME_", "RELATION_MEMORY_")
        try:
            module = import_module("." + family + "_memory", __package__)
            capture = self.extension_captures.get(family) or module.capture
            report = capture(installation, actor, recipient)
            validation_context = _capture_validation_context(context, report)
            if (validation_context is None or module.validate_capture(
                    report, validation_context, creation, actor, recipient) is not True):
                return None, "RELATION_MEMORY_CAPTURE_INVALID"
            return report, None
        except Exception as exc:
            return None, "RELATION_MEMORY_READ_FAILED:" + type(exc).__name__

    def _current_memory_report(self, actor, recipient, families, context):
        """Validate each capture independently, preserving stable siblings."""
        fields, captures = {}, []
        legacy = [family for family in families if family in _LEGACY_MEMORY_FAMILIES]
        groups = ([legacy] if legacy else []) + [[family] for family in families if family in _EXTENSION_FAMILIES]
        directed = [family for family in families if family in _DIRECTED_NETWORK_FAMILIES]
        if directed:
            groups.append(directed)
        for group in groups:
            family = group[0]
            if family in _DIRECTED_NETWORK_FAMILIES:
                report, reason = self._directed_report(actor, group, context, recipient)
                reader = "directed_relation_memory.capture"
            elif family in _EXTENSION_FAMILIES:
                report, reason = self._extension_report(family, actor, recipient, context)
                reader = family + "_memory.capture"
            else:
                report, reason = self._memory_report(actor, recipient, group, context)
                reader = "relation_memory.capture_network" if recipient is None else "relation_memory.capture"
            call = {"reader": reader, "relation_types": list(group), "native_function_invoked": False}
            if report is None:
                call["reason"] = reason
                for member in group:
                    fields[member] = {"status": "unknown", "value": [] if recipient is None else None,
                                      "reason": reason or "RELATION_MEMORY_UNAVAILABLE"}
            else:
                fields.update({member: deepcopy(report.get("fields", {}).get(member, {})) for member in group})
                call.update(capture_sha256=hashlib.sha256(canonical(report).encode("utf-8")).hexdigest(),
                            profile_sha256=report.get("profile", {}).get("sha256"))
            captures.append(call)
        return {"fields": fields, "captures": captures}

    def _directed_report(self, actor, families, context, recipient=None):
        from .trade_income import _session_binding

        installation, creation, reason = _session_binding(self.base_source)
        if reason:
            return None, reason.replace("TRADE_INCOME_", "RELATION_MEMORY_")
        try:
            from . import directed_relation_memory
            capture = self.directed_relation_capture or directed_relation_memory.capture
            report = capture(installation, actor, recipient, families=families)
            validation_context = _capture_validation_context(context, report)
            if (validation_context is None or directed_relation_memory.validate_capture(
                    report, validation_context, creation, actor, recipient) is not True
                    or report.get("request", {}).get("families") != list(families)):
                return None, "RELATION_MEMORY_CAPTURE_INVALID"
            return report, None
        except Exception as exc:
            return None, "RELATION_MEMORY_READ_FAILED:" + type(exc).__name__

    @staticmethod
    def _memory_row(family, item):
        if not isinstance(item, dict) or item.get("status") != "known" or type(item.get("value")) is not bool:
            reason = item.get("reason", "RELATION_MEMORY_FIELD_UNKNOWN") if isinstance(item, dict) else "RELATION_MEMORY_FIELD_UNKNOWN"
            return {field: {"status": "unknown", "reason": reason} for field in _FIELDS}
        active = item["value"]
        role_reason = ("GROUP_MEMBERSHIP_NO_GRANTOR_ROLE" if family == "trade_league"
                       else "SYMMETRIC_RELATION_NO_GRANTOR_ROLE") if active else "NO_ACTIVE_RELATION_FOR_SELECTED_PAIR"
        return {
            "relation_type": {"status": "known", "value": family},
            "status": {"status": "known", "value": "active" if active else "inactive"},
            "grantor": {"status": "not_applicable", "reason": role_reason},
            "recipient": {"status": "not_applicable", "reason": role_reason},
        }

    @staticmethod
    def _fleet_rows(item, actor, partner):
        return NativeRelationSource._direction_rows("fleet_basing", item, actor, partner)

    @staticmethod
    def _direction_rows(family, item, actor, partner):
        values = item.get("value") if isinstance(item, dict) else None
        records = []
        for direction in ("received", "granted"):
            value = values.get(direction) if isinstance(values, dict) else None
            if not isinstance(value, dict) or value.get("status") != "known" or type(value.get("value")) is not bool:
                reason = value.get("reason") if isinstance(value, dict) else None
                reason = reason or (item.get("reason") if isinstance(item, dict) else None) or family.upper() + "_DIRECTION_UNKNOWN"
                row = {field: {"status": "unknown", "reason": reason, "direction": direction} for field in _FIELDS}
            else:
                active = value["value"]
                grantor, beneficiary = (partner, actor) if direction == "received" else (actor, partner)
                row = {"relation_type": {"status": "known", "value": family},
                       "status": {"status": "known", "value": "active" if active else "inactive"}}
                for field, country in (("grantor", grantor), ("recipient", beneficiary)):
                    row[field] = ({"status": "known", "value": country} if active else
                                  {"status": "not_applicable", "reason": "NO_ACTIVE_RELATION_FOR_SELECTED_PAIR"})
                for field in _FIELDS:
                    row[field]["direction"] = direction
            records.append((direction, row))
        return records

    def _read_network(self, query, before):
        actor = query["object"]["country"]
        families = query["parameters"]["relation_types"]
        report = self._current_memory_report(actor, None, families, before)
        calls = deepcopy(report["captures"])
        after, after_reason = self._base_context()
        if (after is None or after_reason or _identity_snapshot(before) != _identity_snapshot(after)
                or not dates_match(before["game_date"], after["game_date"])):
            reason = "CONTEXT_CHANGED_DURING_QUERY"
            return self._assemble(query, after or before,
                                  self._failure_fields(query["fields"], reason, unavailable=False), calls, reason=reason)
        records = []
        family_status = {}
        for family in families:
            item = report.get("fields", {}).get(family, {})
            members = item.get("value", [])
            family_status[family] = {"status": item.get("status", "unknown"),
                                     "active_partner_count": len(members) if isinstance(members, list) else None}
            if isinstance(members, list):
                for member in members:
                    if (isinstance(member, dict) and _is_country(member.get("country"))
                            and member.get("active") is True and member["country"] != actor):
                        if family == "fleet_basing" or family in _DIRECTED_NETWORK_FAMILIES:
                            direction = member.get("direction")
                            if direction not in {"received", "granted"}:
                                continue
                            rows = self._direction_rows(family, {"value": {direction: {"status": "known", "value": True}}}, actor, member["country"])
                            row = next(value for key, value in rows if key == direction)
                            if member.get("operand_direction") in {"forward", "reverse"}:
                                for value in row.values():
                                    value["operand_direction"] = member["operand_direction"]
                        else:
                            row = self._memory_row(family, {"status": "known", "value": True})
                        if family == "trade_league" and member.get("league_leader"):
                            for value in row.values():
                                value["league_leader"] = member["league_leader"]
                        records.append((family, member["country"], row))
            if item.get("status") != "known":
                failure = item.get("reason") or "RELATION_NETWORK_ENUMERATION_INCOMPLETE"
                unknown_rows = item.get("unknown_rows")
                if isinstance(unknown_rows, list) and unknown_rows:
                    for unknown in unknown_rows:
                        if not isinstance(unknown, dict):
                            continue
                        partner = unknown.get("country") if _is_country(unknown.get("country")) else None
                        row = {field: {"status": "unknown", "reason": unknown.get("reason") or failure} for field in _FIELDS}
                        if unknown.get("direction") in {"received", "granted"}:
                            for value in row.values():
                                value["direction"] = unknown["direction"]
                        records.append((family, partner, row))
                else:
                    records.append((family, None, {field: {"status": "unknown", "reason": failure} for field in _FIELDS}))
        for call in calls:
            call["families"] = {family: family_status[family] for family in call["relation_types"]}
        fields = {}
        for field in query["fields"]:
            values = [{"relation_type": family, "actor": actor, "partner": partner, **deepcopy(row[field])}
                      for family, partner, row in records]
            gaps = ["COUNTRY_NETWORK_SUPPORTED_FAMILIES_ONLY", "RELATION_FAMILIES_NOT_EXHAUSTIVE"]
            gaps.extend(value["reason"] for value in values if value["status"] == "unknown")
            fields[field] = {"status": "known", "value": values, "unit": "relation_records", "scale": 1,
                             "period": "current", "complete": False, "partial": True,
                             "gaps": list(dict.fromkeys(gaps)), "basis": "native_country_relation_member_vectors",
                             "value_origin": "derived_from_copied_native_relation_inputs"}
        return self._assemble(query, after, fields, calls)

    def read(self, query: dict, context: dict | None = None) -> dict:
        normalized = self.validate_query(query, context)
        before, reason = self._base_context()
        current = before or deepcopy(context) or {"status": "unready", "mode": "live", "complete": False}
        calls = []

        def fail(failure, *, unavailable=False, ctx=None):
            fields = self._failure_fields(normalized["fields"], failure, unavailable=unavailable)
            return self._assemble(normalized, ctx or current, fields, calls,
                                  reason=failure, unavailable=unavailable)

        if reason or before is None:
            return fail(reason or "BASE_CONTEXT_UNAVAILABLE", unavailable=True)
        if context is not None:
            supplied_reason = _identity_reason(context)
            if supplied_reason:
                return fail(supplied_reason, unavailable=True)
            if (_identity_snapshot(context) != _identity_snapshot(before)
                    or not dates_match(context["game_date"], before["game_date"])):
                return fail("BASE_CONTEXT_CHANGED_BEFORE_QUERY", unavailable=True)
        obj = normalized["object"]
        if obj.get("actor", obj.get("country")) != before["observer"]:
            return fail("OBSERVER_SCOPE_MISMATCH", unavailable=True)
        if obj["type"] == "country":
            return self._read_network(normalized, before)
        inspector = getattr(getattr(self.base_source, "diplomacy_tools", None), "inspect_diplomatic_action", None)

        actor, recipient = normalized["object"]["actor"], normalized["object"]["recipient"]
        memory_families = [family for family in normalized["parameters"]["relation_types"]
                           if family in _MEMORY_FAMILIES or family in _DIRECTED_NETWORK_FAMILIES]
        memory_report = self._current_memory_report(actor, recipient, memory_families, before)
        rows = []
        for family in normalized["parameters"]["relation_types"]:
            if family in _DIRECTED_NETWORK_FAMILIES:
                call = next(deepcopy(value) for value in memory_report["captures"]
                            if family in value["relation_types"])
                call["relation_type"] = family
                calls.append(call)
                item = memory_report.get("fields", {}).get(family)
                if (isinstance(item, dict) and item.get("status") == "known"
                        and type(item.get("value")) is bool):
                    direction = "granted" if family == "guarantee" else "received"
                    directed = self._direction_rows(family, {"value": {direction: item}}, actor, recipient)
                    row = next(value for key, value in directed if key == direction)
                    rows.append((family, row))
                    continue
            if family in _MEMORY_FAMILIES:
                call = next(deepcopy(value) for value in memory_report["captures"] if family in value["relation_types"])
                call["relation_type"] = family
                item = memory_report.get("fields", {}).get(family)
                if family == "fleet_basing":
                    rows.extend((family, row) for _direction, row in self._fleet_rows(item, actor, recipient))
                else:
                    row = self._memory_row(family, item)
                    if family == "trade_league" and isinstance(item, dict) and item.get("league_leader"):
                        for value in row.values():
                            value["league_leader"] = item["league_leader"]
                    rows.append((family, row))
                calls.append(call)
                continue
            action = _ACTIONS[family]
            call = {"relation_type": family, "action_id": action}
            calls.append(call)
            inspected: Any = None
            failure = None
            try:
                if not callable(inspector):
                    raise InformationError("INSPECT_ADAPTER_UNAVAILABLE", "No native inspection adapter")
                inspected = inspector(action, actor, recipient, "initiate", {})
            except Exception as exc:
                failure = "INSPECT_ADAPTER_UNAVAILABLE" if not callable(inspector) else "INSPECT_CALL_FAILED:" + type(exc).__name__
            if failure is None:
                if not isinstance(inspected, dict):
                    failure = "INSPECT_RESULT_INVALID"
                elif inspected.get("error_code"):
                    failure = str(inspected["error_code"])
                elif any(inspected.get(k) != v for k, v in (
                        ("action_id", action), ("phase", "initiate"), ("actor", actor), ("recipient", recipient))):
                    failure = "PUBLIC_PROJECTION_IDENTITY_MISMATCH"
                elif "submitted" in inspected and inspected["submitted"] is not False:
                    failure = "PUBLIC_PROJECTION_SUBMISSION_MARKER_INVALID"
            if failure:
                call["reason"] = failure
                rows.append((family, {f: {"status": "unknown", "reason": failure} for f in _FIELDS}))
                continue
            projected = project(action, inspected, actor, recipient)
            call["source_refs"] = projected["source_refs"]
            call["missing"] = projected["missing"]
            if len(projected["records"]) != 1:
                row = {f: {"status": "unknown", "reason": "RELATION_PROJECTION_INVALID"} for f in _FIELDS}
            else:
                row = projected["records"][0]
                call["visibility"] = deepcopy(row["visibility"])
            rows.append((family, row))

        after, after_reason = self._base_context()
        if (after is None or after_reason or _identity_snapshot(before) != _identity_snapshot(after)
                or not dates_match(before["game_date"], after["game_date"])):
            return fail("CONTEXT_CHANGED_DURING_QUERY", ctx=after)
        fields = {}
        for field in normalized["fields"]:
            values = [{"relation_type": family, **deepcopy(row[field])} for family, row in rows]
            gaps = list(_SCOPE_GAPS)
            gaps.extend(v["reason"] for v in values if v["status"] == "unknown" and v.get("reason"))
            fields[field] = {
                "status": "known", "value": values, "unit": "relation_records", "scale": 1,
                "period": "current", "complete": False, "partial": True,
                "gaps": list(dict.fromkeys(gaps)), "basis": "native_family_relationship_state",
                "value_origin": "native_diplomacy_inspections_and_copied_relation_inputs",
            }
        return self._assemble(normalized, after, fields, calls)


__all__ = ["NativeRelationSource"]
