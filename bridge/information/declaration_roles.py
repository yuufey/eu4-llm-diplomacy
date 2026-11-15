"""Classify declaration candidates with existing current relation readers."""
from __future__ import annotations

from copy import deepcopy

from . import subject_pressure
from . import observation_time
from .relation_state import NativeRelationSource
from .trade_income import _context_reason, _identity, _session_binding


_ROLE_FIELDS = ("guarantors", "subjects")


class DeclarationParticipantRoles:
    """Add current relation roles to an already captured declaration preview.

    A guarantee is read in the candidate-to-related-country direction. Subject
    roles retain the current bound overlord. These are current relations of
    the preview candidates, without assigning a native join-reason enum.
    """

    def __init__(self, base_source, relation_source=None, *, subject_capture=None):
        self.base_source = base_source
        self.relation_source = relation_source or NativeRelationSource(base_source)
        self.subject_capture = subject_capture

    def _guarantee(self, candidate, context):
        report, reason = self.relation_source._directed_report(
            candidate["country"], ["guarantee"], context, candidate["related_country"])
        item = report.get("fields", {}).get("guarantee") if report is not None else None
        if (not isinstance(item, dict) or item.get("status") != "known"
                or type(item.get("value")) is not bool):
            field_reason = item.get("reason") if isinstance(item, dict) else None
            return {"status": "unknown", "reason": reason or field_reason or
                    "PARTICIPANT_GUARANTEE_UNAVAILABLE"}
        return {"status": "known", "value": item["value"]}

    def _subjects(self, candidates, context):
        countries = list(dict.fromkeys(candidate["country"] for candidate in candidates))
        installation, creation, reason = _session_binding(self.base_source)
        if reason:
            return {country: {"status": "unknown", "reason": reason} for country in countries}
        result = {}
        size = subject_pressure._countries.MAX_TARGETS
        for offset in range(0, len(countries), size):
            batch = countries[offset:offset + size]
            try:
                report = (self.subject_capture or subject_pressure.capture_bindings)(installation, batch)
                valid = subject_pressure.validate_binding_capture(report, context, creation, batch)
                targets = report["observation"]["backend"]["targets"] if valid else []
                bindings = {target["tag"]: target["fields"][subject_pressure._BINDING_FIELD]
                            for target in targets}
                for country in batch:
                    binding = bindings.get(country, {"status": "unknown",
                        "reason": "SUBJECT_PRESSURE_CAPTURE_INVALID"})
                    if binding.get("status") != "known" or binding.get("value") is None:
                        result[country] = deepcopy(binding)
                    elif binding["value"]["subject"] != country:
                        result[country] = {"status": "unknown", "reason": "PARTICIPANT_SUBJECT_BINDING_MISMATCH"}
                    else:
                        result[country] = {"status": "known", "value": binding["value"]["overlord"]}
            except Exception as exc:
                for country in batch:
                    result[country] = {"status": "unknown",
                        "reason": "PARTICIPANT_SUBJECT_READ_FAILED:" + type(exc).__name__}
        return result

    def fields(self, inspection, context, requested_fields):
        participants = inspection.get("participants", {})
        requested = [name for name in _ROLE_FIELDS
                     if name in requested_fields and name not in participants]
        if not requested:
            return {}

        def failure(reason):
            return {name: {"status": "unknown", "reason": reason} for name in requested}

        reason = _context_reason(context)
        if reason:
            return failure(reason)
        candidates = participants.get("candidates")
        if participants.get("called") is not True or not isinstance(candidates, list):
            return failure("DECLARE_WAR_PARTICIPANTS_UNAVAILABLE")
        values = {name: [] for name in requested}
        missing = {name: [] for name in requested}
        observed = {name: 0 for name in requested}
        subjects = self._subjects(candidates, context) if "subjects" in requested else {}
        for candidate in candidates:
            row = {key: candidate[key] for key in
                   ("country", "side", "automatic", "selected", "related_country")}
            for name in requested:
                item = (self._guarantee(candidate, context) if name == "guarantors"
                        else subjects[candidate["country"]])
                if item.get("status") != "known":
                    missing[name].append({"country": candidate["country"],
                        "related_country": candidate["related_country"],
                        "reason": item.get("reason", "PARTICIPANT_RELATION_UNAVAILABLE")})
                    continue
                observed[name] += 1
                if item["value"]:
                    value = deepcopy(row)
                    if name == "subjects":
                        value["overlord"] = item["value"]
                    values[name].append(value)
        try:
            after = self.base_source.context()
        except Exception:
            return failure("PARTICIPANT_RELATION_CONTEXT_UNAVAILABLE")
        if (_context_reason(after) or _identity(context) != _identity(after)
                or not observation_time.dates_match(context["game_date"], after["game_date"])):
            return failure("PARTICIPANT_RELATION_CONTEXT_CHANGED")
        result = {}
        for name in requested:
            if candidates and observed[name] == 0:
                result[name] = {"status": "unknown", "reason": "PARTICIPANT_RELATIONS_UNAVAILABLE",
                                "unresolved": missing[name]}
                continue
            complete = participants.get("enumeration_complete") is True and not missing[name]
            result[name] = {"status": "known", "value": values[name], "complete": complete,
                "partial": not complete, "scope": "participant_candidates_current_relations",
                "source_path": ("R01.guarantee" if name == "guarantors" else "S03.subject_binding"),
                "read_only": True, "native_function_invoked": False}
            if missing[name]:
                result[name]["unresolved"] = missing[name]
        return result
