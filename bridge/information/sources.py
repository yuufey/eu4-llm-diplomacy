"""Reusable read-only adapters for the information catalog.

The live adapter calls only ObserverSession health/read methods,
DiplomacyTools inspection, inbound observation and journal readers. It never
calls an execution method. RecordedSource keeps archived fixture provenance
explicit so a replay cannot be mistaken for a live observation.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .catalog import get_topic, list_topics, validate_query
from .model import InformationError, canonical
from .event_replay import unknown_event_projection
from .declaration_cost_rules import declaration_allowed_terms
from .beneficiary_projection import declaration_beneficiaries, peace_fields
from .observation_time import dates_match
from . import cooldown_expiry
from ..war_participants import project_war_participants
from .. import support_roles
from .. import proposal_expiry
from .. import country_modifier_observation
from .. import subsidy_expiry_observation
from .. import truce_expiry_observation
from .. import claim_expiry_observation
from .. import land_promise_observation
from .. import rival_observation
from .. import war_declaration_observation
from .. import relation_observation
from .. import mission_observation
from .. import mission_availability_observation
from .. import mission_condition_observation


_MISSING = object()
_VERSION_BY_GAME_SHA = {
    # Fixed identities already used by the repository's verified fixtures and
    # manifests.  An unknown executable hash remains unready.
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77": "1.37.4",
    "9ad3efe1af169f40ee577f9dae5debbc87af6fb8b5450fb345ebf110dc4d771a": "1.37.5",
}
_DYNAMIC_TOPICS = frozenset({
    "R05", "D01", "D02", "D03", "D04", "D05", "D06",
    "W01", "W02", "P01", "P02", "P03", "P04", "P05",
    "A01", "A02", "A03",
})
_JOURNAL_TOPICS = frozenset({"A05", "C04", "H01", "H02"})
_LIVE_INBOUND_TOPICS = frozenset({"A04"})
_TERMINAL_RESULTS = frozenset({"accepted", "rejected", "executed"})
_CURRY_ACTIONS = frozenset({"curry_favors", "stop_curry_favors"})
_INSPECTION_CONTEXT_KEYS = (
    "status", "mode", "complete", "observer", "game_version", "game_sha256",
    "dll_sha256", "session_id", "game_date", "game_date_raw",
)
# ENROUTE is the game's relation-message waiting tooltip. Match its complete
# sentence so dates from other rules never become diplomacy cooldowns.
_ENROUTE_PATTERNS = (
    re.compile(r"^(?:- )?最近已经派遣过外交官，所以直到(?P<date>\d+年\d+月\d+日)我们才能再次派遣。$", re.MULTILINE),
    re.compile(r"^(?:- )?We have recently sent a diplomat, so we cannot send another until (?P<date>[^\n]{1,80})\.$", re.MULTILINE),
)


def _copy(value: Any) -> Any:
    return deepcopy(value)


def _recorded_event_type(value: Any) -> str:
    """Use one event identity for archived discovery cases and polling."""
    containers = []
    if isinstance(value, dict) and isinstance(value.get("raw"), dict):
        containers.append(value["raw"])
    if isinstance(value, dict):
        containers.append(value)
    for item in containers:
        for key in ("event_type", "event", "name"):
            candidate = item.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
    return "recorded_case"


def _at(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


def _first(value: Any, paths: list[str] | tuple[str, ...]) -> Any:
    for path in paths:
        candidate = _at(value, path)
        if candidate is not _MISSING and candidate is not None:
            return candidate
    return _MISSING


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _safe_status(value: Any) -> str:
    return value if value in {"known", "unknown", "invisible", "not_applicable",
                              "unavailable", "stale", "unsupported"} else "unknown"


def _record_of(session: Any) -> dict:
    value = getattr(session, "record", None)
    return _copy(value) if isinstance(value, dict) else {}


def _inspection_context_identity(context: Any) -> tuple[Any, ...]:
    if not isinstance(context, dict):
        return ()
    return tuple(context.get(key) for key in _INSPECTION_CONTEXT_KEYS)


def _module_hash(record: dict) -> str | None:
    value = record.get("dll_sha256")
    if isinstance(value, str) and value:
        return value
    for key in ("modules_after_install", "modules"):
        modules = record.get(key)
        if isinstance(modules, list):
            for item in modules:
                if isinstance(item, dict) and isinstance(item.get("sha256"), str):
                    return item["sha256"]
    return None


def _observer_hint(session: Any, tools: Any = None, record: dict | None = None) -> str | None:
    """Extract a controlled country only from an explicit trusted binding."""

    record = record or _record_of(session)
    candidates = [
        getattr(session, "observer", None),
        getattr(session, "controlled_country", None),
        getattr(session, "decision_country", None),
        getattr(tools, "observer", None),
        getattr(tools, "controlled_country", None),
        getattr(tools, "decision_country", None),
        record.get("observer"), record.get("controlled_country"),
        record.get("decision_country"), record.get("country"),
    ]
    for candidate in candidates:
        if isinstance(candidate, str) and re.fullmatch(r"[A-Z0-9]{3}", candidate):
            return candidate

    # ObserverSession's installation acknowledgement is operator-owned and
    # bounded.  Its authority scope is usable when it explicitly names the
    # controlled country; registry/catalog entries are intentionally ignored.
    ack_reader = getattr(session, "_installation_ack", None)
    if callable(ack_reader):
        try:
            ack = ack_reader()
        except Exception:
            ack = None
        if isinstance(ack, dict):
            for key in ("observer", "controlled_country", "decision_country"):
                candidate = ack.get(key)
                if isinstance(candidate, str) and re.fullmatch(r"[A-Z0-9]{3}", candidate):
                    return candidate
            scope = ack.get("authority_scope")
            if isinstance(scope, str):
                match = re.search(
                    r"(?:outbound|controlled|decision_country|observer)\s*[:= ]\s*([A-Z0-9]{3})",
                    scope,
                )
                if match:
                    return match.group(1)
    return None


def _context_from_health(session: Any, health: Any, *, mode: str,
                         observer: str | None = None) -> dict:
    health = health if isinstance(health, dict) else {}
    record = _record_of(session)
    raw_date = health.get("game_date", health.get("date_raw"))
    if raw_date is None:
        raw_date = record.get("game_date", record.get("date_raw"))
    session_id = getattr(session, "session_id", None) or record.get("session_id")
    status = health.get("status")
    if status not in {"ready", "unready"}:
        status = "ready" if mode == "recorded" and session_id else "unready"
    game_version = (health.get("game_version") or record.get("game_version")
                    or record.get("version"))
    game_sha = health.get("game_sha256") or record.get("game_sha256")
    dll_sha = health.get("dll_sha256") or _module_hash(record)
    observer = (health.get("observer") or observer
                or _observer_hint(session, record=record))
    if not isinstance(observer, str) or re.fullmatch(r"[A-Z0-9]{3}", observer) is None:
        observer = None
    if not isinstance(game_version, str) or not game_version:
        game_version = _VERSION_BY_GAME_SHA.get(game_sha)
    world_id = health.get("world_id", record.get("world_id"))
    paused = health.get("paused", record.get("paused"))
    game_day = health.get("game_day", record.get("game_day"))
    if type(game_day) is not int and type(raw_date) is int:
        # Native EU4 date_raw is a 24-hour tick count.  Keep the raw value as
        # game_date and expose the monotonic day separately.
        game_day = raw_date // 24
    reasons = _copy(health.get("reasons", [])) if isinstance(health.get("reasons", []), list) else []
    if mode == "live" and status == "ready":
        if not isinstance(session_id, str) or not session_id:
            reasons.append({"code": "SESSION_ID_UNAVAILABLE"})
        if not isinstance(game_version, str) or not game_version:
            reasons.append({"code": "GAME_VERSION_UNAVAILABLE"})
        if observer is None:
            reasons.append({"code": "OBSERVER_IDENTITY_UNAVAILABLE"})
        if reasons and any(item.get("code") in {
                "SESSION_ID_UNAVAILABLE", "GAME_VERSION_UNAVAILABLE",
                "OBSERVER_IDENTITY_UNAVAILABLE"} for item in reasons
                if isinstance(item, dict)):
            status = "unready"
    if isinstance(world_id, int):
        world_id = str(world_id)
    return {
        "status": status,
        "session_id": session_id if isinstance(session_id, str) else None,
        "game_version": game_version if isinstance(game_version, str) else None,
        "game_sha256": game_sha if isinstance(game_sha, str) else None,
        "dll_sha256": dll_sha if isinstance(dll_sha, str) else None,
        "observer": observer,
        "game_date": raw_date,
        "game_day": game_day if type(game_day) is int else None,
        "world_id": world_id if isinstance(world_id, str) else None,
        "paused": paused if isinstance(paused, bool) else None,
        "mode": mode,
        "complete": bool(health.get("complete", status == "ready")) and status == "ready",
        "reasons": reasons,
        "game_date_raw": raw_date,
        "game_date_kind": "eu4_hour_tick" if type(raw_date) is int else "source_value",
    }


def _source_info(name: str, context: dict, *, mode: str | None = None,
                 complete: bool | None = None, provenance: Any = None) -> dict:
    result = {
        "name": name,
        "mode": mode or context.get("mode", "live"),
        "status": "observed" if context.get("status") == "ready" else "unavailable",
        "session_id": context.get("session_id"),
        "observer": context.get("observer"),
        "complete": bool(context.get("complete", False) if complete is None else complete),
    }
    if provenance is not None:
        result["provenance"] = _copy(provenance)
    return result


def _selected_declare_war_cost(field: str, payload: dict) -> dict | None:
    resource = {"stability_cost": "stability_loss", "war_exhaustion_cost": "war_exhaustion"}.get(field)
    costs = payload.get("costs")
    if resource is None or not isinstance(costs, dict) or costs.get("context") != "selected_parameters":
        return None
    items = costs.get("items")
    if not isinstance(items, list):
        return None
    matches = [item for item in items if isinstance(item, dict) and item.get("resource") == resource]
    if len(matches) != 1:
        return None
    item = matches[0]
    if (item.get("unit") != resource or item.get("unit_verified") is not True
            or item.get("scale_verified") is not True or item.get("scale") != 1000
            or item.get("complete") is not True or type(item.get("amount_raw")) is not int
            or type(item.get("amount")) not in (int, float)
            or item["amount"] != item["amount_raw"] / 1000):
        return None
    return {"status": "known", "value": item["amount"], "unit": resource, "scale": 1,
            "complete": True, "context": "selected_parameters", "basis": "native_declare_war_cost_item"}


def _declare_war_participant_field(field: str, payload: dict) -> dict | None:
    participants = payload.get('participants')
    if (field not in {'ally', 'willingness', 'reasons', 'land_promise_available'}
            or not isinstance(participants, dict) or field in participants
            or 'candidates' not in participants):
        return None
    candidates = participants['candidates']
    if participants.get('called') is not True or not isinstance(candidates, list):
        return {'status': 'unknown', 'reason': 'DECLARE_WAR_PARTICIPANTS_UNAVAILABLE'}
    allies, willingness, reasons, promises = [], {}, {}, {}
    score_complete = reasons_complete = promise_complete = True
    for candidate in candidates:
        country = candidate['country']
        allies.append({key: candidate[key] for key in ('country', 'side', 'automatic')})
        native = candidate['willingness']
        available = native['score_available'] is True
        willingness[country] = {
            'score': native['native_total_raw'] if available else None,
            'threshold': native['acceptance_threshold_raw'] if available else None,
        }
        reasons[country] = _copy(native['reasons'])
        promises[country] = candidate['promise_available'] if candidate['context_complete'] else None
        score_complete = score_complete and available
        reasons_complete = reasons_complete and native['reasons_complete'] and all(
            reason['complete'] for reason in native['reasons'])
        promise_complete = promise_complete and candidate['context_complete']
    values = {'ally': allies, 'willingness': willingness, 'reasons': reasons,
              'land_promise_available': promises}
    completeness = {'ally': True, 'willingness': score_complete, 'reasons': reasons_complete,
                    'land_promise_available': promise_complete}
    complete = participants.get('enumeration_complete') is True and bool(completeness[field])
    return {'status': 'known', 'value': values[field], 'complete': complete,
            'source_path': 'participants.candidates', 'partial': not complete}


def _declare_war_plan_field(field: str, payload: dict) -> dict | None:
    participants = payload.get('participants')
    if not isinstance(participants, dict) or 'candidates' not in participants:
        return None
    if participants.get('called') is not True:
        return {'status': 'unknown', 'reason': 'DECLARE_WAR_PARTICIPANTS_UNAVAILABLE'}
    if field in {'guarantors', 'subjects'}:
        return {'status': 'unknown', 'reason': 'PARTICIPANT_RELATION_KIND_UNVERIFIED'}
    candidates = participants['candidates']
    if field == 'automatic_participants':
        selected = [candidate for candidate in candidates if candidate['automatic']]
        scope = 'automatic_participant_candidates'
    else:
        key = 'call_allies' if field == 'allies' else 'co_belligerents'
        selection = participants.get('selection', {})
        if not isinstance(selection.get(key), list):
            return {'status': 'unknown', 'reason': 'DECLARE_WAR_PARTICIPANT_SELECTION_UNAVAILABLE'}
        selected = [candidate for candidate in candidates if candidate['country'] in selection[key]]
        scope = 'selected_preview'
    value = [{key: candidate[key] for key in ('country', 'side', 'automatic', 'selected')}
             for candidate in selected]
    complete = participants.get('enumeration_complete') is True
    return {'status': 'known', 'value': value, 'complete': complete, 'partial': not complete,
            'scope': scope, 'source_path': 'participants.candidates'}


def _declare_war_forbidden_terms(payload: dict) -> dict | None:
    if _first(payload, ('peace_rules.forbidden_terms',)) is not _MISSING:
        return None
    rules = payload.get('peace_term_rules')
    if not isinstance(rules, dict):
        return None
    table = rules.get('disabled')
    if (rules.get('called') is not True or not isinstance(table, dict)
            or table.get('available') is not True or not isinstance(table.get('disabled_actions'), list)):
        return {'status': 'unknown', 'reason': 'DECLARE_WAR_DISABLED_TERMS_UNAVAILABLE'}
    complete = (table.get('complete') is True and not table.get('unmapped')
                and table.get('target_evaluation_required') is not True)
    return {'status': 'known', 'value': _copy(table['disabled_actions']),
            'complete': complete, 'partial': not complete, 'table': _copy(table),
            'source_path': 'peace_term_rules.disabled.disabled_actions'}


def _field_result(fields: list[str], payload: dict | None, topic: dict,
                  *, unavailable: str | None = None,
                  unsupported: bool = False) -> tuple[dict, bool]:
    payload = payload if isinstance(payload, dict) else {}
    output: dict[str, dict] = {}
    complete = True
    for field in fields:
        paths = topic["fields"][field].get("paths", [field])
        value = _first(payload, paths)
        inspection_field = None
        if topic['topic_id'] == 'D04':
            inspection_field = _declare_war_participant_field(field, payload)
        elif topic['topic_id'] == 'D03' and value is _MISSING:
            inspection_field = _declare_war_plan_field(field, payload)
        elif topic['topic_id'] == 'D06' and field == 'forbidden_terms':
            inspection_field = _declare_war_forbidden_terms(payload)
        if unsupported:
            item = {"status": "unsupported", "reason": "TOPIC_NOT_ADAPTED"}
        elif unavailable is not None:
            item = {"status": "unavailable", "reason": unavailable}
        elif inspection_field is not None:
            item = inspection_field
        elif value is _MISSING:
            item = _selected_declare_war_cost(field, payload) if topic["topic_id"] == "D02" else None
            if item is None:
                item = {"status": "unknown", "reason": "FIELD_NOT_PRESENT_IN_SOURCE"}
        elif topic["topic_id"] == "A04" and field == "deadline":
            item = (_copy(value) if isinstance(value, dict)
                    and value.get("status") in ("known", "unknown") else
                    {"status": "unknown", "reason": "PROPOSAL_DEADLINE_INVALID"})
        else:
            item = {"status": "known", "value": _copy(value)}
        if (item["status"] != "known"
                or (inspection_field is not None and item.get('complete') is False)):
            complete = False
        output[field] = item
    return output, complete


def _action_cooldown_field(inspected: dict) -> dict:
    """Read the waiting cause already returned by the selected native preview."""
    diagnostic = inspected.get("native_diagnostic")
    text = diagnostic.get("text") if isinstance(diagnostic, dict) else None
    if not isinstance(text, str):
        text = inspected.get("native_diagnostic_text")
    if not isinstance(text, str):
        diagnostics = inspected.get('diagnostics')
        common = diagnostics.get('common_action_gate') if isinstance(diagnostics, dict) else None
        text = common.get('text') if isinstance(common, dict) else None
    if isinstance(text, str):
        text = re.sub(r"§.", "", text).replace("\r\n", "\n")
        for pattern in _ENROUTE_PATTERNS:
            match = pattern.search(text)
            if match:
                return {"status": "known", "value": {
                    "blocked": True, "available_on": match["date"],
                }, "basis": "native_enroute_tooltip"}
    components = inspected.get("native_rule_components")
    if isinstance(components, dict) and components.get("common_action_gate") is True:
        return {"status": "known", "value": {"blocked": False, "available_on": None},
                "basis": "native_common_action_gate_passed"}
    return {"status": "unknown", "reason": "ACTION_COOLDOWN_NOT_IDENTIFIED"}


def _favor_tasks_field(
        inspected: dict[str, Any], action_id: str,
        actor: str, recipient: str,
        *, reason: str | None = None) -> dict[str, Any]:
    """Project only the verified selected-pair Curry state.

    The normal R05 inspector also serves trust/favor-balance actions.  Those
    payloads must never be interpreted as a task state, so this projection
    requires the dedicated Curry family and both native verification layers.
    """
    if reason is not None:
        return {"status": "unknown", "reason": reason}
    if action_id not in _CURRY_ACTIONS:
        return {"status": "unknown", "reason": "FAVOR_TASKS_REQUIRES_CURRY_INSPECTION"}
    expected = {
        "action_id": action_id,
        "actor": actor,
        "recipient": recipient,
        "phase": "initiate",
        "family": "curry_favors",
    }
    if any(inspected.get(key) != value for key, value in expected.items()):
        return {"status": "unknown", "reason": "FAVOR_TASKS_IDENTITY_UNVERIFIED"}
    if "submitted" in inspected and inspected.get("submitted") is not False:
        return {"status": "unknown", "reason": "FAVOR_TASKS_SUBMISSION_MARKER_INVALID"}
    active = inspected.get("task_active")
    if type(active) is not bool:
        return {"status": "unknown", "reason": "FAVOR_TASKS_ACTIVE_NOT_EXACT_BOOL"}
    if inspected.get("task_state_verified") is not True:
        return {"status": "unknown", "reason": "FAVOR_TASKS_STATE_NOT_VERIFIED"}
    relation = inspected.get("relationship_state")
    if not isinstance(relation, dict):
        return {"status": "unknown", "reason": "FAVOR_TASKS_RELATIONSHIP_STATE_MISSING"}
    relation_active = relation.get("task_active")
    if type(relation_active) is not bool:
        return {"status": "unknown", "reason": "FAVOR_TASKS_RELATIONSHIP_ACTIVE_NOT_EXACT_BOOL"}
    if relation_active != active:
        return {"status": "unknown", "reason": "FAVOR_TASKS_RELATIONSHIP_ACTIVE_MISMATCH"}
    if relation.get("complete") is not True:
        return {"status": "unknown", "reason": "FAVOR_TASKS_RELATIONSHIP_STATE_INCOMPLETE"}
    native_session = inspected.get("session")
    if not isinstance(native_session, dict):
        return {"status": "unknown", "reason": "FAVOR_TASKS_NATIVE_SESSION_MISSING"}
    if native_session.get("status") != "ready":
        return {"status": "unknown", "reason": "FAVOR_TASKS_NATIVE_SESSION_UNREADY"}
    if type(native_session.get("date_raw")) is not int:
        return {"status": "unknown", "reason": "FAVOR_TASKS_NATIVE_DATE_INVALID"}
    return {
        "status": "known",
        "value": {
            "action_id": action_id,
            "family": "curry_favors",
            "phase": "initiate",
            "actor": actor,
            "recipient": recipient,
            "direction": "actor_to_recipient",
            "task_active": active,
            "task_state_verified": True,
            "relationship_state": {
                "task_active": active,
                "complete": True,
            },
        },
        "unit": "task_state",
        "scale": 1,
        "period": "current",
        "basis": "native_curry_favors_pair_state",
        "value_origin": "copied_native_pair_inspection",
        "complete": False,
    }


def _result(normalized: dict, context: dict, fields: dict, complete: bool,
            source: dict, objects: list[dict] | None = None) -> dict:
    return {
        "topic": normalized["topic"],
        "fields": fields,
        "source": source,
        "complete": bool(complete),
        "game_date": context.get("game_date"),
        "objects": _copy(objects if objects is not None else [normalized["object"]]),
    }


def _public_record(record: Any, evidence: list[Any] | None = None) -> dict:
    payload = getattr(record, "payload", None)
    payload = payload if isinstance(payload, dict) else {}
    status = getattr(record, "status", None)
    result = getattr(record, "result", None)
    request_id = getattr(record, "request_id", None)
    public = {
        "request_id": request_id,
        "action_id": payload.get("action_id"),
        "status": status,
        "submitted": getattr(record, "submitted_at", None) is not None,
        "game_outcome": status if status in _TERMINAL_RESULTS else "unknown",
        "result": _copy(result),
        "updated_at": getattr(record, "updated_at", None),
        "payload": {key: _copy(value) for key, value in payload.items()
                    if key not in {"submission_token", "claim_token", "native_token"}},
    }
    if evidence is not None:
        public["evidence"] = [
            {
                "event_id": getattr(item, "event_id", None),
                "type": getattr(item, "evidence_type", None),
                "layer": getattr(item, "arrival_layer", None),
                "sha256": getattr(item, "content_sha256", None),
                "observed_at": getattr(item, "observed_at", None),
            }
            for item in evidence
        ]
    return public


def _journal_event_id(kind: str, identity: dict[str, Any]) -> str:
    """Build a bounded event id while retaining the journal identity in payload.

    Request timestamps are ISO strings and can contain ``+`` and enough
    characters to exceed the information contract's identifier limit.  The
    journal identity is therefore hashed for the external event id; callers
    still receive the original scoped identity in the event payload.
    """

    material = {"kind": kind, **identity}
    return "journal:" + hashlib.sha256(canonical(material).encode("utf-8")).hexdigest()


def _journal_historical_date(record: Any) -> Any:
    """Return a date explicitly stored with a journal record, if any.

    A heartbeat date describes when the adapter collected an event.  It must
    not be used as the event's historical game date when the journal did not
    record one.
    """

    payload = getattr(record, "payload", None)
    result = getattr(record, "result", None)
    for container in (payload, result):
        if not isinstance(container, dict):
            continue
        for key in ("game_date", "date_raw"):
            if container.get(key) is not None:
                return _copy(container[key])
    return None


def _journal_actor_recipient(record: Any) -> dict[str, Any]:
    payload = getattr(record, "payload", None)
    if not isinstance(payload, dict):
        return {}
    return {
        key: _copy(payload[key])
        for key in ("actor", "recipient")
        if key in payload
    }


class DiplomacySource:
    """Read-only adapter over an existing DiplomacyTools instance."""

    # These are the event identities emitted by the readers below.  They are
    # deliberately narrower than the complete EU4 event universe: an event
    # type is advertised only when this adapter can preserve its payload and
    # provenance.
    event_types = ("diplomatic_proposal", "diplomatic_request_result", "evidence")
    cooldown_reader = None
    _modifier_events_enabled = False
    _modifier_removals_enabled = False
    _modifier_expiry_enabled = False
    _subsidy_expiry_enabled = False
    _truce_expiry_enabled = False
    _claim_expiry_enabled = False
    _land_promise_enabled = False
    _rival_events_enabled = False
    _rival_records_enabled = False
    _war_declarations_enabled = False
    _relation_events_enabled = False
    _mission_events_enabled = False
    _mission_availability_enabled = False
    _mission_condition_enabled = False
    _mission_province_condition_enabled = False

    def __init__(self, diplomacy_tools=None, *, observer: str | None = None,
                 declaration_rules=None, declaration_roles=None):
        if observer is not None and (not isinstance(observer, str) or re.fullmatch(r"[A-Z0-9]{3}", observer) is None):
            raise InformationError("invalid_observer", "Operator observer must be a country tag")
        self.diplomacy_tools = diplomacy_tools
        self.operator_observer = observer
        self.declaration_rules = declaration_rules
        self.declaration_roles = declaration_roles
        capability_reader = getattr(self.session, 'installation_capabilities', None)
        try:
            capabilities = capability_reader() if callable(capability_reader) else ()
            self._modifier_events_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and country_modifier_observation.CAPABILITY in capabilities)
            self._modifier_removals_enabled = (self._modifier_events_enabled
                and country_modifier_observation.REMOVE_CAPABILITY in capabilities)
            self._modifier_expiry_enabled = (self._modifier_removals_enabled
                and country_modifier_observation.EXPIRY_CAPABILITY in capabilities)
            self._subsidy_expiry_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and subsidy_expiry_observation.CAPABILITY in capabilities)
            self._truce_expiry_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and truce_expiry_observation.CAPABILITY in capabilities)
            self._claim_expiry_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and claim_expiry_observation.CAPABILITY in capabilities)
            self._land_promise_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and land_promise_observation.CAPABILITY in capabilities)
            self._rival_events_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and rival_observation.CAPABILITY in capabilities)
            self._rival_records_enabled = (self._rival_events_enabled
                and rival_observation.RECORD_CAPABILITY in capabilities)
            self._war_declarations_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and war_declaration_observation.CAPABILITY in capabilities)
            self._relation_events_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and relation_observation.CAPABILITY in capabilities)
            self._mission_events_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and mission_observation.CAPABILITY in capabilities)
            self._mission_availability_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and mission_availability_observation.CAPABILITY in capabilities)
            self._mission_condition_enabled = (
                (observer or _observer_hint(self.session, diplomacy_tools)) == 'FRA'
                and mission_condition_observation.CAPABILITY in capabilities)
            self._mission_province_condition_enabled = (self._mission_condition_enabled
                and mission_condition_observation.PROVINCE_CAPABILITY in capabilities)
        except Exception:
            self._modifier_events_enabled = False
            self._subsidy_expiry_enabled = False
            self._truce_expiry_enabled = False
            self._claim_expiry_enabled = False
            self._land_promise_enabled = False
            self._rival_events_enabled = False
            self._rival_records_enabled = False
            self._war_declarations_enabled = False
            self._relation_events_enabled = False
            self._mission_events_enabled = False
            self._mission_availability_enabled = False
            self._mission_condition_enabled = False
            self._mission_province_condition_enabled = False
        if self._modifier_events_enabled:
            self.event_types = (*self.event_types, country_modifier_observation.EVENT_TYPE)
        if self._modifier_removals_enabled:
            self.event_types = (*self.event_types, country_modifier_observation.REMOVE_EVENT_TYPE)
        if self._modifier_expiry_enabled:
            self.event_types = (*self.event_types, country_modifier_observation.EXPIRY_EVENT_TYPE)
        if self._subsidy_expiry_enabled:
            self.event_types = (*self.event_types, subsidy_expiry_observation.EVENT_TYPE)
        if self._truce_expiry_enabled:
            self.event_types = (*self.event_types, truce_expiry_observation.EVENT_TYPE)
        if self._claim_expiry_enabled:
            self.event_types = (*self.event_types, claim_expiry_observation.EVENT_TYPE)
        if self._land_promise_enabled:
            self.event_types = (*self.event_types, land_promise_observation.EVENT_TYPE)
        if self._rival_events_enabled:
            self.event_types = (*self.event_types, rival_observation.EVENT_TYPE)
        if self._war_declarations_enabled:
            self.event_types = (*self.event_types, war_declaration_observation.EVENT_TYPE)
        if self._relation_events_enabled:
            self.event_types = (*self.event_types, relation_observation.EVENT_TYPE)
        if self._mission_events_enabled:
            self.event_types = (*self.event_types, mission_observation.EVENT_TYPE)
        if self._mission_availability_enabled:
            self.event_types = (*self.event_types, mission_availability_observation.EVENT_TYPE)
        if self._mission_condition_enabled:
            self.event_types = (*self.event_types, mission_condition_observation.EVENT_TYPE)

    @property
    def session(self):
        return getattr(self.diplomacy_tools, "session", None)

    def catalog(self) -> list[dict]:
        topics = list_topics()
        reader = getattr(self.session, "installation_capabilities", None)
        try:
            capabilities = reader() if callable(reader) else ()
        except Exception:
            capabilities = ()
        for topic in topics:
            if topic['topic_id'] == 'C04':
                topic['native_subsidy_expiry'] = {
                    'capture_available': self._subsidy_expiry_enabled,
                    'event_type': subsidy_expiry_observation.EVENT_TYPE,
                    'scope': subsidy_expiry_observation.SCOPE,
                    'mode': 'live', 'projection': 'event_snapshot',
                    'date_semantics': subsidy_expiry_observation.DATE_SEMANTICS,
                }
                topic['native_truce_expiry'] = {
                    'capture_available': self._truce_expiry_enabled,
                    'event_type': truce_expiry_observation.EVENT_TYPE,
                    'scope': truce_expiry_observation.SCOPE,
                    'mode': 'live', 'projection': 'event_snapshot',
                    'date_semantics': truce_expiry_observation.DATE_SEMANTICS,
                }
                topic['native_claim_expiry'] = {
                    'capture_available': self._claim_expiry_enabled,
                    'event_type': claim_expiry_observation.EVENT_TYPE,
                    'scope': claim_expiry_observation.SCOPE,
                    'mode': 'live', 'projection': 'event_snapshot',
                    'date_semantics': claim_expiry_observation.DATE_SEMANTICS,
                }
                topic['native_land_promise'] = {
                    'capture_available': self._land_promise_enabled,
                    'event_type': land_promise_observation.EVENT_TYPE,
                    'scope': land_promise_observation.SCOPE,
                    'mode': 'live', 'projection': 'event_snapshot',
                    'date_semantics': land_promise_observation.DATE_SEMANTICS,
                }
                topic['native_mission_condition'] = {
                    'capture_available': self._mission_condition_enabled,
                    'event_type': mission_condition_observation.EVENT_TYPE,
                    'scope': (mission_condition_observation.COMBINED_SCOPE
                              if self._mission_province_condition_enabled else mission_condition_observation.SCOPE),
                    'mode': 'live', 'projection': 'event_snapshot',
                    'sampling': 'native_root_condition_return', 'initial_observation': 'baseline_only',
                    'event_date_semantics': 'after_observation_date',
                    'previous_observation_date_field': 'previous_observed_date_raw',
                    'nested_condition_progress_covered': False, 'full_condition_progress_covered': False,
                    'unvisited_conditions': 'unknown', 'player_country_required': False,
                    'max_root_conditions_per_task': 128, 'max_tracked_tasks': 4096,
                    'native_gap_on_limit': True, 'eligibility_may_remain_false': True,
                    'direct_area_province_holding_covered': self._mission_province_condition_enabled,
                    'province_condition_scope': (mission_condition_observation.PROVINCE_SCOPE
                                                 if self._mission_province_condition_enabled else None),
                    'max_province_observations_per_evaluation': 128,
                }
                topic['native_mission_availability'] = {
                    'capture_available': self._mission_availability_enabled,
                    'event_type': mission_availability_observation.EVENT_TYPE,
                    'scope': mission_availability_observation.SCOPE,
                    'mode': 'live', 'projection': 'event_snapshot',
                    'sampling': 'native_predicate_return', 'initial_observation': 'baseline_only',
                    'event_date_semantics': 'after_observation_date',
                    'previous_observation_date_field': 'previous_observed_date_raw',
                    'full_condition_progress_covered': False, 'branch_visibility_verified': False,
                    'all_state_changes_covered': False, 'player_country_required': False,
                }
                topic['native_mission_completion'] = {
                    'capture_available': self._mission_events_enabled,
                    'event_type': mission_observation.EVENT_TYPE,
                    'scope': mission_observation.scope_for_capabilities(capabilities) or mission_observation.SCOPE,
                    'mode': 'live', 'projection': 'event_snapshot', 'completed_transition': 'false_to_true',
                    'player_country_required': False, 'direct_bypass_coverage_verified': False,
                    'verified_script_effect_source': mission_observation.SET_CAPABILITY in capabilities,
                    'all_direct_writes_covered': False,
                    'condition_progress_covered': False,
                }
                topic['native_relation_change'] = {
                    'capture_available': self._relation_events_enabled,
                    'event_type': relation_observation.EVENT_TYPE,
                    'scope': relation_observation.scope_for_capabilities(capabilities) or relation_observation.SCOPE,
                    'mode': 'live', 'projection': 'event_snapshot', 'relation_kinds': list(relation_observation.KINDS),
                    'actor_role': ('command_actor_or_record_endpoint'
                                   if relation_observation.RECORD_CAPABILITY in capabilities else 'command_actor'),
                    'recipient_role': ('command_target_or_record_endpoint'
                                       if relation_observation.RECORD_CAPABILITY in capabilities else 'command_target'),
                    'alliance_record_writes_covered': relation_observation.RECORD_CAPABILITY in capabilities,
                    'royal_record_writes_covered': relation_observation.ROYAL_RECORD_CAPABILITY in capabilities,
                    'guarantee_record_writes_covered': relation_observation.DIRECTED_RECORD_CAPABILITY in capabilities,
                    'military_access_record_writes_covered': relation_observation.DIRECTED_RECORD_CAPABILITY in capabilities,
                    'support_independence_record_writes_covered': relation_observation.SUPPORT_SUBJECT_RECORD_CAPABILITY in capabilities,
                    'subject_record_writes_covered': relation_observation.SUPPORT_SUBJECT_RECORD_CAPABILITY in capabilities,
                    'direct_writes_covered': False, 'within_command_intermediate_states_covered': False,
                }
                topic['native_war_declaration'] = {
                    'capture_available': self._war_declarations_enabled,
                    'event_type': war_declaration_observation.EVENT_TYPE, 'scope': war_declaration_observation.SCOPE,
                    'mode': 'live', 'projection': 'event_snapshot', 'participant_snapshot': 'native_war_side_vectors',
                    'actor_role': 'command_actor', 'recipient_role': 'command_target',
                    'attacker_defender_labels_verified': True,
                    'role_basis': war_declaration_observation.ROLE_BASIS,
                    'direct_handlers_covered': False,
                    'pre_registered_wars_supported': False,
                }
                topic['native_rival_change'] = {
                    'capture_available': self._rival_events_enabled,
                    'event_type': rival_observation.EVENT_TYPE,
                    'scope': rival_observation.COMBINED_SCOPE if self._rival_records_enabled else rival_observation.SCOPE,
                    'mode': 'live', 'projection': 'event_snapshot',
                    'complete_scope': ('observed_membership_changes_at_command_or_record_returns'
                                       if self._rival_records_enabled else 'observed_membership_changes_at_three_command_returns'),
                    'actor_role': 'rival_owner' if self._rival_records_enabled else 'command_actor',
                    'recipient_role': 'rival_target' if self._rival_records_enabled else 'command_target',
                    'old_rival_role': 'separate_replaced_country',
                    'direct_country_writes_covered': False,
                    'country_record_returns_covered': self._rival_records_enabled,
                    'record_count_basis': rival_observation.COUNT_BASIS if self._rival_records_enabled else None,
                }
                topic['native_country_modifier_addition'] = {
                    'capture_available': self._modifier_events_enabled,
                    'event_type': country_modifier_observation.EVENT_TYPE,
                    'scope': country_modifier_observation.SCOPE,
                    'mode': 'live', 'complete_scope': 'single_added_record',
                    'projection': 'event_snapshot',
                    'removal_or_expiry_available': self._modifier_removals_enabled,
                }
                topic['native_country_modifier_removal'] = {
                    'capture_available': self._modifier_removals_enabled,
                    'event_type': country_modifier_observation.REMOVE_EVENT_TYPE,
                    'scope': country_modifier_observation.SCOPE,
                    'mode': 'live', 'complete_scope': 'single_removed_record',
                    'projection': 'event_snapshot', 'expiry_available': self._modifier_expiry_enabled,
                }
                topic['native_country_modifier_expiry'] = {
                    'capture_available': self._modifier_expiry_enabled,
                    'event_type': country_modifier_observation.EXPIRY_EVENT_TYPE,
                    'scope': country_modifier_observation.SCOPE,
                    'mode': 'live', 'complete_scope': 'single_native_expired_record',
                    'projection': 'event_snapshot',
                }
            if topic["topic_id"] == "A04":
                consequence_field = topic['fields']['response_consequences']
                role_available = support_roles.CAPABILITY in capabilities
                consequence_field['support_role_context_available'] = role_available
                if not role_available:
                    consequence_field['supported_actions'].remove('support_independence')
                topic["inbound_observation_families"] = {"call_to_arms": {
                    "capture_available": "native_call_to_arms_observation" in capabilities,
                    "capture_stage": "before_native_executor", "identity_scope": "captured_observation",
                    "ai_response_held": False, "response_execution_supported": False,
                }}
                topic['proposal_lifecycle'] = {
                    'expiry_capture_available': 'native_proposal_expiry_observation' in capabilities,
                    'event_type': 'diplomatic_proposal', 'status': 'expired',
                    'statuses': ['expired', 'inactive'],
                    'correlation': 'previously_verified_original_proposal',
                    'delivery_order': 'original_before_terminal',
                    'withdrawal_capture_available': False,
                    'inactivation_capture_available': 'native_proposal_expiry_observation' in capabilities,
                    'inactivation_basis': 'native_pending_queue_removal',
                }
            if topic['topic_id'] == 'A05':
                topic['result_date'] = {
                    'capture_available': 'native_result_game_date_observation' in capabilities,
                    'basis': 'original_executor_same_game_date',
                    'deferred_confirmation_date': 'unknown',
                }
        return topics

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        normalized = validate_query(query, context)
        parameters = normalized["parameters"]
        if normalized["topic"].startswith("D") and "selection" in parameters:
            if set(parameters) - {"action_id", "phase", "selection"}:
                raise InformationError("object_parameter_conflict", "Use one declare-war selection context")
            if parameters.get("action_id", "declare_war") != "declare_war":
                raise InformationError("invalid_parameters", "Declare-war selection requires declare_war")
            from ..diplomacy import DiplomacyTools
            obj = normalized["object"]
            try:
                DiplomacyTools._validate("declare_war", obj["actor"], obj["recipient"],
                                         parameters.get("phase", "initiate"), parameters["selection"])
            except ValueError as exc:
                raise InformationError("invalid_parameters", str(exc)) from exc
        return normalized

    def change_comparison(self, query, sample, context):
        if query.get("topic") != "A04":
            return None
        from .inbound_current import pending_change_comparison
        return pending_change_comparison(query, sample, context)

    def validate_event_filter(self, event_filter):
        if (claim_expiry_observation.EVENT_TYPE in event_filter.get('types', [])
                and any(key in event_filter for key in ('actors', 'recipients'))):
            raise InformationError('unsupported_event_filter',
                                   'Claim expiry identifies claimant and province owner roles')
        if (subsidy_expiry_observation.EVENT_TYPE in event_filter.get('types', [])
                and 'actors' in event_filter):
            raise InformationError('unsupported_event_filter',
                                   'Subsidy expiry identifies a payer and recipient without an acting country')
        if (any(kind in country_modifier_observation.EVENT_SEMANTICS for kind in event_filter.get('types', []))
                and any(key in event_filter for key in ('actors', 'recipients'))):
            raise InformationError('unsupported_event_filter',
                                   'Country modifier changes do not establish actor/recipient roles')

    def context(self) -> dict:
        session = self.session
        if session is None:
            return _context_from_health(None, {"status": "unready", "complete": False}, mode="live", observer=self.operator_observer)
        try:
            health_reader = getattr(session, 'information_health', session.health)
            health = health_reader()
        except Exception as exc:
            health = {"status": "unready", "complete": False,
                      "reasons": [{"code": "SESSION_HEALTH_FAILED",
                                   "message": str(exc)}]}
        hint = _observer_hint(session, self.diplomacy_tools)
        context = _context_from_health(
            session, health, mode="live",
            observer=self.operator_observer or hint,
        )
        context["observer_binding"] = "operator_configuration" if self.operator_observer else "installation_binding"
        if self.operator_observer and ((hint and hint != self.operator_observer)
                or (health.get("observer") is not None and health["observer"] != self.operator_observer)):
            context.update(status="unready", complete=False)
            context.setdefault("reasons", []).append({"code": "OBSERVER_AUTHORITY_SCOPE_MISMATCH"})
        return context

    def _context_result(self, normalized: dict, context: dict) -> dict:
        fields, complete = _field_result(normalized["fields"], context,
                                         get_topic("C01"))
        # Health is exposed only after the session identity, supported build
        # version and controlled observer have been verified.  Missing fields
        # remain unknown in the result rather than being filled with labels.
        return _result(normalized, context, fields, complete,
                       _source_info("ObserverSession.health", context))

    def _unavailable(self, normalized: dict, context: dict, reason: str) -> dict:
        fields, _ = _field_result(normalized["fields"], {}, get_topic(normalized["topic"]),
                                  unavailable=reason)
        return _result(normalized, context, fields, False,
                       _source_info(get_topic(normalized["topic"])["source"], context,
                                    complete=False))

    def _unsupported(self, normalized: dict, context: dict) -> dict:
        fields, _ = _field_result(normalized["fields"], {}, get_topic(normalized["topic"]),
                                  unsupported=True)
        return _result(normalized, context, fields, False,
                       _source_info("catalog", context, complete=False))

    def _identity(self, normalized: dict) -> tuple[str | None, str | None, str | None, dict]:
        params = normalized["parameters"]
        obj = normalized["object"]
        action_id = params.get("action_id") or obj.get("action_id")
        actor = params.get("actor") or obj.get("actor")
        recipient = params.get("recipient") or obj.get("recipient")
        phase = params.get("phase") or "initiate"
        # R05 ``kind`` is an adapter selector for the concrete favor action;
        # DiplomacyTools validates favor initiation with an empty parameter
        # object, so the selector must never cross the native boundary.
        selector_keys = {"kind"} if normalized["topic"] == "R05" else set()
        inspection_parameters = {
            key: _copy(value) for key, value in params.items()
            if key not in {"action_id", "actor", "recipient", "phase"} | selector_keys
        }
        if normalized["topic"].startswith("D") and "selection" in inspection_parameters:
            inspection_parameters = inspection_parameters["selection"]
        return action_id, actor, recipient, inspection_parameters

    def _default_action(self, topic_id: str, action_id: str | None,
                        parameters: dict, fields: list[str] | None = None) -> str | None:
        if action_id:
            return action_id
        if topic_id.startswith("D"):
            return "declare_war"
        if topic_id.startswith("P") or topic_id.startswith("W"):
            return "white_peace"
        if topic_id == "R05":
            if "favor_tasks" in (fields or ()) and not parameters.get("kind"):
                # An R05 query that includes favor_tasks without an exchange
                # kind has no other read action to select. Use the read-only
                # stop predicate, whose task_active result is meaningful for
                # both active and inactive pairs.
                return "stop_curry_favors"
            kind = parameters.get("kind")
            return {"trust": "trade_favors_for_trust", "men": "trade_favors_for_men",
                    "gold": "trade_favors_for_gold"}.get(kind)
        return None

    def _read_war_discovery(self, normalized: dict, context: dict) -> dict:
        """Discover one pair's session-scoped wars without constructing an offer."""
        provenance = {"scope": "selected_country_pair", "identity_scope": "observer_session",
                      "same_date_reload_verified": False, "enumeration_complete": False,
                      "candidate_count": None, "selected_war_id": None}
        fields = {field: {"status": "unknown", "reason": "WAR_CONTEXT_FIELD_UNVERIFIED"}
                  for field in normalized["fields"]}
        objects = []

        def finish(reason=None, *, status="unknown"):
            if reason:
                for field in fields:
                    fields[field] = {"status": status, "reason": reason}
            complete = all(value["status"] in {"known", "not_applicable"}
                           for value in fields.values())
            return _result(normalized, context, fields, complete,
                           _source_info("ObserverSession.inspect_peace_contexts", context,
                                        complete=complete, provenance=provenance), objects)

        obj, params = normalized["object"], normalized["parameters"]
        actor, recipient = obj.get("actor"), obj.get("recipient")
        if (obj.get("war_id") is not None and params.get("war_id") is not None
                and obj["war_id"] != params["war_id"]):
            raise InformationError("object_parameter_conflict", "Conflicting war_id in object and parameters")
        selected = obj.get("war_id", params.get("war_id"))
        if not isinstance(actor, str) or not isinstance(recipient, str) or actor == recipient:
            return finish("WAR_COUNTRY_PAIR_REQUIRED", status="unavailable")
        if params.get("action_id", "white_peace") != "white_peace" or params.get("phase", "initiate") != "initiate":
            return finish("WAR_DISCOVERY_REQUIRES_WHITE_PEACE_INITIATE", status="unavailable")
        if self.session is None:
            return finish("NO_SESSION", status="unavailable")
        if context.get("status") != "ready":
            return finish("SESSION_UNREADY", status="unavailable")
        if actor != context.get("observer"):
            return finish("WAR_DISCOVERY_OBSERVER_SCOPE_MISMATCH", status="unavailable")
        reader = getattr(self.session, "inspect_peace_contexts", None)
        if not callable(reader):
            return finish("WAR_DISCOVERY_ADAPTER_UNAVAILABLE", status="unavailable")
        try:
            native = reader("white_peace", actor, recipient, "initiate")
        except Exception:
            return finish("WAR_DISCOVERY_CALL_FAILED", status="unavailable")
        try:
            after = self.context()
        except Exception:
            return finish("WAR_DISCOVERY_POST_CONTEXT_UNAVAILABLE")
        if any(after.get(key) != context.get(key) for key in _INSPECTION_CONTEXT_KEYS
               if key not in ("game_date", "game_date_raw")):
            return finish("WAR_DISCOVERY_CONTEXT_CHANGED")
        if not isinstance(native, dict):
            return finish("WAR_DISCOVERY_RESULT_INVALID")
        if native.get("error_code"):
            code = native["error_code"]
            if isinstance(code, str) and re.fullmatch(r"[A-Z0-9_]{1,80}", code):
                provenance["source_error"] = code
            return finish("WAR_DISCOVERY_SOURCE_UNAVAILABLE", status="unavailable")
        identity = {"event": "native_peace_context_inspection", "family": "peace",
                    "action_id": "white_peace", "actor": actor, "recipient": recipient,
                    "phase": "initiate", "session_id": context.get("session_id")}
        if (any(native.get(key) != value for key, value in identity.items())
                or type(native.get("date_raw")) is not int
                or not dates_match(context.get("game_date"), native["date_raw"], after.get("game_date"))
                or native.get("context_discovery") is not True
                or native.get("submitted") is not False
                or native.get("native_offer_inspected") is not False):
            return finish("WAR_DISCOVERY_IDENTITY_MISMATCH")
        rows = native.get("war_contexts")
        if not isinstance(rows, list) or len(rows) > 32:
            return finish("WAR_DISCOVERY_RESULT_INVALID")
        seen = set()
        for row in rows:
            if (not isinstance(row, dict)
                    or not isinstance(row.get("war_id"), str)
                    or re.fullmatch(r"war_[0-9a-f]{16}_[0-9a-f]{8}", row["war_id"]) is None
                    or row["war_id"] in seen
                    or row.get("actor") != actor or row.get("recipient") != recipient
                    or row.get("identity_scope") != "observer_session"
                    or row.get("pair_at_war") is not True):
                objects.clear()
                return finish("WAR_DISCOVERY_RESULT_INVALID")
            seen.add(row["war_id"])
            # Only public selection identities leave the reader. Pair roles
            # and two country tags are not an all-participant or leader map.
            objects.append({"type": "war", "war_id": row["war_id"],
                            "actor": actor, "recipient": recipient})
        provenance.update(enumeration_complete=native.get("war_context_enumeration_complete") is True,
                          candidate_count=len(objects), query_complete=native.get("query_complete") is True)
        if isinstance(native.get("query_id"), str) and len(native["query_id"]) <= 128:
            provenance["query_id"] = native["query_id"]
        if not provenance["enumeration_complete"] or not provenance["query_complete"]:
            return finish("WAR_ENUMERATION_INCOMPLETE")
        if selected is not None and selected not in seen:
            return finish("WAR_NOT_FOUND_IN_CURRENT_CONTEXT")
        if not objects:
            return finish("NO_MATCHING_WAR", status="not_applicable")
        if selected is None and len(objects) != 1:
            return finish("WAR_SELECTION_REQUIRED")
        selected = selected or objects[0]["war_id"]
        objects[:] = [obj for obj in objects if obj["war_id"] == selected]
        provenance["selected_war_id"] = selected
        if "war_id" in fields:
            fields["war_id"] = {"status": "known", "value": selected}
        if "participants" in fields or "leaders" in fields:
            row = next(row for row in rows if row["war_id"] == selected)
            participants = project_war_participants(row.get("participants"), actor, recipient)
            try:
                capabilities = self.session.installation_capabilities()
            except Exception:
                capabilities = ()
            acknowledged = (isinstance(capabilities, (set, frozenset, tuple, list))
                            and "native_war_participants_query" in capabilities)
            if not acknowledged:
                participant_field = {"status": "unknown", "reason": "WAR_PARTICIPANTS_CAPABILITY_UNAVAILABLE"}
            elif participants is None:
                participant_field = {"status": "unknown", "reason": "WAR_PARTICIPANTS_SOURCE_UNAVAILABLE"}
            elif participants["status"] == "unknown":
                participant_field = {"status": "unknown", "reason": participants["reason"]}
            else:
                participant_field = {"status": "known", "value": participants}
                provenance.update(participants_source=participants["source"], participant_lists_complete=True,
                                  side_roles_verified=False, leaders_verified=False)
            if "participants" in fields:
                fields["participants"] = participant_field
            if "leaders" in fields:
                if participant_field["status"] == "known":
                    # QUERY1 preserves native vector order. The existing
                    # current-leader getter returns each side's first member.
                    fields["leaders"] = {"status": "known", "value": {
                        "our_side": participants[participants["actor_side"]][0],
                        "opposing_side": participants[participants["recipient_side"]][0]}}
                    provenance.update(leaders_verified=True, leaders_source="native_current_side_first_member")
                else:
                    fields["leaders"] = dict(participant_field)
        return finish()

    def _read_war_score(self, normalized: dict, context: dict) -> dict:
        """Read the bound native score companion of one empty peace preview."""
        fields = {field: {"status": "unknown", "reason": "WAR_SCORE_FIELD_UNIMPLEMENTED"}
                  for field in normalized["fields"]}
        field_complete = {field: False for field in fields}
        obj, params = normalized["object"], normalized["parameters"]
        actor, recipient = obj.get("actor"), obj.get("recipient")
        provenance = {"scope": "selected_war", "identity_scope": "observer_session",
                      "same_date_reload_verified": False, "capability": "native_live_war_score_query",
                      "business_dispatch": False, "empty_peace_preview": True}
        objects = []

        def finish(reason=None, *, status="unknown"):
            if reason:
                for field in fields:
                    fields[field] = {"status": status, "reason": reason}
                    field_complete[field] = False
            complete = all(field_complete.values())
            return _result(normalized, context, fields, complete,
                           _source_info("DiplomacyTools.inspect_diplomatic_action", context,
                                        complete=complete, provenance=provenance), objects)

        if not isinstance(actor, str) or not isinstance(recipient, str) or actor == recipient:
            return finish("WAR_COUNTRY_PAIR_REQUIRED", status="unavailable")
        selected_context = params.get("peace_context", {})
        if (not isinstance(selected_context, dict)
                or set(selected_context) - {"war_id", "direction", "terms"}
                or selected_context.get("terms", []) != []):
            return finish("WAR_SCORE_CONTEXT_UNSUPPORTED", status="unavailable")
        selections = [value for value in (obj.get("war_id"), params.get("war_id"), selected_context.get("war_id"))
                      if value is not None]
        if len(set(selections)) > 1:
            raise InformationError("object_parameter_conflict", "Conflicting selected war_id")
        if not selections:
            return finish("WAR_SELECTION_REQUIRED", status="unavailable")
        war_id = selections[0]
        if not isinstance(war_id, str) or re.fullmatch(r"war_[0-9a-f]{16}_[0-9a-f]{8}", war_id) is None:
            return finish("WAR_ID_INVALID", status="unavailable")
        direction = selected_context.get("direction", "demand")
        if direction not in {"demand", "offer"}:
            return finish("WAR_SCORE_CONTEXT_UNSUPPORTED", status="unavailable")
        if params.get("action_id", "white_peace") != "white_peace" or params.get("phase", "initiate") != "initiate":
            return finish("WAR_SCORE_REQUIRES_WHITE_PEACE_INITIATE", status="unavailable")
        if self.session is None or self.diplomacy_tools is None:
            return finish("NO_SESSION", status="unavailable")
        if context.get("status") != "ready":
            return finish("SESSION_UNREADY", status="unavailable")
        if actor != context.get("observer"):
            return finish("WAR_SCORE_OBSERVER_SCOPE_MISMATCH", status="unavailable")
        try:
            capabilities = self.session.installation_capabilities()
        except Exception:
            capabilities = ()
        if (not isinstance(capabilities, (set, frozenset, list, tuple))
                or "native_live_war_score_query" not in capabilities):
            return finish("WAR_SCORE_CAPABILITY_UNAVAILABLE", status="unavailable")
        inspector = getattr(self.diplomacy_tools, "inspect_diplomatic_action", None)
        if not callable(inspector):
            return finish("INSPECT_ADAPTER_UNAVAILABLE", status="unavailable")
        provenance.update(war_id=war_id, actor=actor, recipient=recipient, direction=direction)
        objects.append({"type": "war", "war_id": war_id, "actor": actor, "recipient": recipient})
        selected = {"peace_context": {"war_id": war_id, "direction": direction, "terms": []}}
        try:
            inspected = inspector("white_peace", actor, recipient, "initiate", selected)
        except Exception:
            return finish("WAR_SCORE_CALL_FAILED", status="unavailable")
        try:
            after = self.context()
        except Exception:
            return finish("WAR_SCORE_POST_CONTEXT_UNAVAILABLE")
        if _inspection_context_identity(after) != _inspection_context_identity(context):
            return finish("WAR_SCORE_CONTEXT_CHANGED")
        if not isinstance(inspected, dict) or inspected.get("error_code"):
            return finish("WAR_SCORE_SOURCE_UNAVAILABLE", status="unavailable")
        if (any(inspected.get(key) != value for key, value in {
                "action_id": "white_peace", "actor": actor, "recipient": recipient, "phase": "initiate"}.items())
                or not isinstance(inspected.get("session"), dict)
                or type(inspected["session"].get("date_raw")) is not int
                or inspected["session"]["date_raw"] != context.get("game_date")
                or inspected.get("submitted", False) is not False):
            return finish("WAR_SCORE_IDENTITY_MISMATCH")
        war_context = inspected.get("war_context")
        peace_context = inspected.get("peace_context")
        if (not isinstance(war_context, dict) or war_context.get("war_id") != war_id
                or (isinstance(peace_context, dict) and peace_context.get("war_id") != war_id)):
            return finish("WAR_SCORE_WAR_ID_MISMATCH")
        score = war_context.get("war_score")
        if not isinstance(score, dict):
            return finish("WAR_SCORE_EVENT_MISSING")
        if (score.get("source") != "war_score_query"
                or score.get("status") not in {"available", "partial", "truncated"}
                or score.get("verified") is not True or score.get("error") is not None):
            return finish("WAR_SCORE_NOT_VERIFIED")
        if score.get("mode") != "whole_war" or score.get("perspective") != "actor":
            return finish("WAR_SCORE_MODE_OR_PERSPECTIVE_UNSUPPORTED")

        def metric_valid(metric, scale):
            return (isinstance(metric, dict) and type(metric.get("raw")) is int
                    and -(1 << 31) <= metric["raw"] < (1 << 31)
                    and type(metric.get("scale")) is int and metric["scale"] == scale
                    and metric.get("unit") == "war_score_point" and metric.get("scale_verified") is True
                    and type(metric.get("value")) in (int, float) and metric["value"] == metric["raw"] / scale)

        if not metric_valid(score.get("total"), 1):
            return finish("WAR_SCORE_TOTAL_UNVERIFIED")
        provenance.update(mode=score["mode"], perspective=score["perspective"],
                          native_score_complete=score.get("complete") is True)
        if "war_score" in fields:
            fields["war_score"] = {"status": "known", "value": _copy(score)}
            field_complete["war_score"] = score.get("complete") is True
        if "cumulative_goal_score" in fields:
            goal = score.get("goal")
            if not isinstance(goal, dict):
                fields["cumulative_goal_score"] = {"status": "unknown", "reason": "WAR_GOAL_SCORE_UNAVAILABLE"}
            elif (goal.get("presence_verified") is True and goal.get("present") is False
                  and goal.get("inapplicable") is True and goal.get("available") is False):
                fields["cumulative_goal_score"] = {"status": "not_applicable", "reason": "WAR_GOAL_NOT_CONFIGURED"}
                field_complete["cumulative_goal_score"] = True
            elif (goal.get("available") is True and goal.get("complete") is True
                  and goal.get("presence_verified") is True and goal.get("present") is True
                  and goal.get("inapplicable") is False and metric_valid(goal.get("cumulative"), 1000)):
                fields["cumulative_goal_score"] = {"status": "known", "value": _copy(goal["cumulative"])}
                field_complete["cumulative_goal_score"] = True
            else:
                fields["cumulative_goal_score"] = {"status": "unknown", "reason": "WAR_GOAL_SCORE_UNAVAILABLE"}
        return finish()

    def _read_inspection(self, normalized: dict, context: dict) -> dict:
        topic = get_topic(normalized["topic"])
        favor_tasks_requested = (
            normalized["topic"] == "R05"
            and "favor_tasks" in normalized["fields"]
        )
        if favor_tasks_requested and normalized["object"].get("type") == "country":
            fields = {
                field: {"status": "unavailable",
                        "reason": "FAVOR_TASKS_COUNTRY_NETWORK_UNAVAILABLE"}
                for field in normalized["fields"]
            }
            source = _source_info(
                topic["source"], context, complete=False,
                provenance={
                    "scope": "country_network",
                    "network_enumeration": "unavailable",
                    "reason": "FAVOR_TASKS_COUNTRY_NETWORK_UNAVAILABLE",
                },
            )
            source["status"] = "unavailable"
            return _result(
                normalized, context, fields, False, source,
                [deepcopy(normalized["object"])],
            )
        if self.diplomacy_tools is None or self.session is None:
            return self._unavailable(normalized, context, "NO_SESSION")
        if context.get("status") != "ready":
            return self._unavailable(normalized, context, "SESSION_UNREADY")
        action_id, actor, recipient, parameters = self._identity(normalized)
        action_id = self._default_action(
            normalized["topic"], action_id, normalized["parameters"],
            normalized["fields"],
        )
        if not isinstance(action_id, str) or not isinstance(actor, str) or not isinstance(recipient, str):
            fields, _ = _field_result(normalized["fields"], {}, topic,
                                      unavailable="ACTION_CONTEXT_REQUIRED")
            return _result(normalized, context, fields, False,
                           _source_info(topic["source"], context, complete=False))
        phase = normalized["parameters"].get("phase", "initiate")
        if normalized["topic"] in ("A01", "A03") and phase in ("accept", "reject"):
            return self._read_response_preview(normalized, context, action_id, actor, recipient, phase)
        inspector = getattr(self.diplomacy_tools, "inspect_diplomatic_action", None)
        if not callable(inspector):
            return self._unavailable(normalized, context, "INSPECT_ADAPTER_UNAVAILABLE")
        try:
            # The adapter contract passes the validated parameter object on
            # every call. Do not retry without it after a TypeError: that
            # could turn a malformed proposal into a different query and
            # silently discard the caller's selection.
            inspected = inspector(action_id, actor, recipient, phase, parameters)
        except Exception as exc:
            inspected = {"error_code": "INSPECT_CALL_FAILED", "error": str(exc)}
        if not isinstance(inspected, dict):
            inspected = {"error_code": "INSPECT_RESULT_INVALID"}
        if inspected.get("error_code"):
            fields, _ = _field_result(normalized["fields"], {}, topic,
                                      unavailable=str(inspected.get("error_code")))
            return _result(normalized, context, fields, False,
                           _source_info(topic["source"], context, complete=False))
        fields, complete = _field_result(normalized["fields"], inspected, topic)
        projected = {}
        if normalized["topic"] == "D06":
            if "allowed_terms" in fields and fields["allowed_terms"]["status"] == "unknown":
                projected["allowed_terms"] = declaration_allowed_terms(inspected, self.declaration_rules)
            if "beneficiaries" in fields and fields["beneficiaries"]["status"] == "unknown":
                projected["beneficiaries"] = declaration_beneficiaries(inspected)
        elif normalized["topic"] == "P01":
            consequences = inspected.get("peace_consequences")
            if ("terms" in fields and isinstance(consequences, dict)
                    and consequences.get("requested_terms_applied") is False):
                fields["terms"] = {"status": "unknown", "reason": "REQUESTED_PEACE_TERMS_NOT_APPLIED"}
            missing = [name for name, value in fields.items() if value["status"] == "unknown"]
            projected = peace_fields(inspected, missing)
        if projected:
            fields.update(projected)
            complete = all(value["status"] == "known" and value.get("complete") is not False
                           for value in fields.values())
        if normalized["topic"] == "D03" and self.declaration_roles is not None:
            fields.update(self.declaration_roles.fields(inspected, context, normalized["fields"]))
            complete = all(value["status"] == "known" and value.get("complete") is not False
                           for value in fields.values())
        if (normalized["topic"] == "D04" and "favor_requirement" in fields
                and fields["favor_requirement"]["status"] == "unknown" and self.declaration_rules is not None):
            fields["favor_requirement"] = self.declaration_rules.favor_requirement()
            complete = all(value["status"] == "known" and value.get("complete") is not False
                           for value in fields.values())
        if (normalized["topic"] == "D06" and "cost_rules" in fields
                and fields["cost_rules"]["status"] == "unknown" and self.declaration_rules is not None):
            cb = _first(inspected, ("parameters.actual.casus_belli",))
            if isinstance(cb, str):
                fields["cost_rules"] = self.declaration_rules.read(cb)
            else:
                fields["cost_rules"] = {"status": "unknown", "reason": "SELECTED_CB_REQUIRED"}
            complete = all(value["status"] == "known" and value.get("complete") is not False
                           for value in fields.values())
        if normalized["topic"] == "A01" and "cooldown" in fields:
            # Preserve structured results supplied by existing/recorded adapters.
            if fields["cooldown"]["status"] == "unknown":
                fields["cooldown"] = _action_cooldown_field(inspected)
                complete = all(value["status"] == "known" for value in fields.values())
        provenance = None
        if favor_tasks_requested:
            # Do not append a second inspection for a mixed R05 request.  The
            # selected exchange action may provide the other fields, while a
            # non-Curry action leaves favor_tasks explicitly unknown.
            fields["favor_tasks"] = _favor_tasks_field(
                inspected, action_id, actor, recipient,
            )
            complete = False
            provenance = {
                "favor_tasks": {
                    "scope": "selected_country_pair",
                    "network_enumeration": "unavailable",
                    "inspection_action": action_id,
                    "direction": "actor_to_recipient",
                    "task_state_verified": (
                        inspected.get("task_state_verified") is True
                    ),
                },
            }
        objects = [{"type": "country_pair", "actor": actor, "recipient": recipient,
                    "action_id": action_id, "phase": phase}]
        if favor_tasks_requested:
            # The existing DiplomacySource has no post-inspection identity
            # check.  Add it only to the new task projection so existing R05
            # exchange fields retain their established behavior.
            try:
                after = self.context()
            except Exception:
                after = None
            if not isinstance(after, dict):
                fields["favor_tasks"] = {
                    "status": "unknown",
                    "reason": "FAVOR_TASKS_POST_CONTEXT_UNAVAILABLE",
                }
            elif _inspection_context_identity(after) != _inspection_context_identity(context):
                fields["favor_tasks"] = {
                    "status": "unknown",
                    "reason": "FAVOR_TASKS_CONTEXT_CHANGED_DURING_QUERY",
                }
            else:
                native_session = inspected.get("session")
                native_date = (
                    native_session.get("date_raw")
                    if isinstance(native_session, dict) else None
                )
                context_date = context.get("game_date")
                if type(native_date) is not int:
                    fields["favor_tasks"] = {
                        "status": "unknown",
                        "reason": "FAVOR_TASKS_NATIVE_DATE_INVALID",
                    }
                elif (type(context_date) is int
                      and native_date != context_date):
                    fields["favor_tasks"] = {
                        "status": "unknown",
                        "reason": "FAVOR_TASKS_NATIVE_DATE_MISMATCH",
                    }
        return _result(normalized, context, fields, complete,
                       _source_info(topic["source"], context, complete=complete,
                                    provenance=provenance),
                       objects)

    def _read_response_preview(self, normalized, context, action, actor, recipient, phase):
        from .inbound_current import read_response_inspection

        topic = get_topic(normalized['topic'])
        public_id = normalized['parameters']['proposal_id']
        finder = getattr(self.session, 'find_native_alliance_inbound_offer', None)
        if not callable(finder):
            return self._unavailable(normalized, context, 'INBOUND_RESPONSE_OBSERVATION_READER_UNAVAILABLE')
        try:
            proposal = finder(public_id)
        except Exception:
            return self._unavailable(normalized, context, 'INBOUND_RESPONSE_OBSERVATION_READ_FAILED')
        if (not isinstance(proposal, dict) or any(proposal.get(key) != value for key, value in (
                ('proposal_id', public_id), ('action_id', action), ('actor', actor), ('recipient', recipient)))):
            return self._unavailable(normalized, context, 'INBOUND_RESPONSE_PROPOSAL_NOT_FOUND_OR_MISMATCH')
        status, provenance, inspected = read_response_inspection(self, proposal, context, phase)
        if inspected is None:
            fields = {name: {'status': status['status'], 'reason': status['reason']}
                      for name in normalized['fields']}
            return _result(normalized, context, fields, False,
                           _source_info(topic['source'], context, complete=False, provenance=provenance))
        fields, complete = _field_result(normalized['fields'], inspected, topic)
        proof = provenance['native_status_proof']
        if (fields.get('legality_status', {}).get('value') == 'available'
                and not all(proof.get(key) is True for key in (
                    'pending_active', 'decision_country_verified', 'native_validity', 'response_rules_complete'))):
            fields['legality_status'] = {'status': 'unknown', 'reason': 'INBOUND_RESPONSE_LEGALITY_PROOF_CONFLICT'}
            complete = False
        if (phase == 'reject' and action.startswith('trade_favors_for_') and 'costs' in fields):
            fields['costs'] = {'status': 'unknown', 'reason': 'REJECTION_COSTS_NOT_PROVEN_BY_ACCEPTANCE_QUOTE'}
            complete = False
        objects = [{'type': 'country_pair', 'actor': actor, 'recipient': recipient, 'proposal_id': public_id}]
        return _result(normalized, context, fields, complete,
                       _source_info(topic['source'], context, complete=complete, provenance=provenance), objects)

    def _read_inbound(self, normalized: dict, context: dict) -> dict:
        topic = get_topic(normalized["topic"])
        session = self.session
        if session is None:
            return self._unavailable(normalized, context, "NO_SESSION")
        reader = getattr(session, "read_native_alliance_inbound_offers", None)
        if not callable(reader):
            reader = getattr(session, "read_native_inbound_offers", None)
        if not callable(reader):
            return self._unavailable(normalized, context, "INBOUND_READER_UNAVAILABLE")
        try:
            items = reader()
        except Exception as exc:
            return self._unavailable(normalized, context, "INBOUND_READ_FAILED:" + type(exc).__name__)
        if not isinstance(items, (list, tuple)):
            return self._unavailable(normalized, context, "INBOUND_RESULT_INVALID")
        obj, params = normalized["object"], normalized["parameters"]
        wanted_id = params.get("proposal_id")
        wanted_actor, wanted_recipient = obj.get("actor"), obj.get("recipient")
        selected = None
        for item in items:
            if not isinstance(item, dict):
                continue
            if wanted_id is not None and item.get("proposal_id") != wanted_id:
                continue
            if wanted_actor is not None and item.get("actor") != wanted_actor:
                continue
            if wanted_recipient is not None and item.get("recipient") != wanted_recipient:
                continue
            selected = item
            break
        if selected is None:
            fields, _ = _field_result(normalized["fields"], {}, topic,
                                      unavailable="PROPOSAL_NOT_FOUND")
            return _result(normalized, context, fields, False,
                           _source_info(topic["source"], context, complete=False))
        return self._project_inbound(normalized, context, selected)

    def _project_inbound(self, normalized: dict, context: dict, selected: dict, *, allow_fresh=True) -> dict:
        from ..diplomacy import _FAVOR_ACTIONS

        topic = get_topic(normalized["topic"])
        params = normalized["parameters"]
        fields, complete = _field_result(normalized["fields"], selected, topic)
        complete = complete and selected.get("complete", True) is True
        provenance = None
        observation_window = None
        lifecycle = proposal_expiry.ended_lifecycle(selected)
        end_status = selected.get('observer_status')
        ended_snapshot = lifecycle is not None
        if ended_snapshot:
            for name, value, unit in (('proposal_status', end_status, 'proposal_state'),
                                      ('currently_pending', False, 'boolean')):
                if name in fields:
                    fields[name] = {'status': 'known', 'value': value, 'unit': unit, 'scale': 1,
                                    'period': 'observed', 'complete': False, 'partial': True,
                                    'observation_game_date': lifecycle['game_date_raw'],
                                    'proposal_id': selected.get('proposal_id')}
        if "proposal_status" in fields and not ended_snapshot:
            fields["proposal_status"].update(complete=False, partial=True, period="observed",
                currently_pending={"status": "unknown", "reason": "OBSERVATION_IS_NOT_CURRENT_PENDING_PROOF"})
            complete = False
        fresh_terms = ("parameters" in fields and fields["parameters"]["status"] != "known"
                       and selected.get("action_id") in ("peace_offer", *_FAVOR_ACTIONS)
                       and params.get("fresh_pending") is True)
        fresh_consequences = ("response_consequences" in fields
                              and selected.get("action_id") in topic['fields']['response_consequences']['supported_actions']
                              and params.get("fresh_pending") is True)
        if fresh_consequences and selected.get('action_id') == 'support_independence':
            capability_reader = getattr(self.session, 'installation_capabilities', None)
            try:
                fresh_consequences = (callable(capability_reader)
                                      and support_roles.CAPABILITY in capability_reader())
            except Exception:
                fresh_consequences = False
            if not fresh_consequences:
                fields['response_consequences'] = {
                    'status': 'unknown', 'reason': 'NATIVE_SUPPORT_ROLE_CONTEXT_UNAVAILABLE'}
        if (not ended_snapshot
                and ("proposal_status" in fields or "currently_pending" in fields
                     or fresh_terms or fresh_consequences)):
            status = {"status": "unknown", "reason": "CURRENT_PENDING_REQUIRES_EXPLICIT_FRESH_INSPECTION"}
            if params.get("fresh_pending") is True and allow_fresh:
                from .inbound_current import read_current_status
                status, provenance = read_current_status(
                    self, selected, context, include_parameters=fresh_terms,
                    include_consequences=fresh_consequences)
                if status.get("status") == "known":
                    from .observation_time import ObservationWindow
                    observation_window = ObservationWindow([
                        context["game_date"], status["observation_game_date"],
                    ]).metadata()
                refreshed_terms = status.pop('proposal_parameters', None)
                if refreshed_terms is not None:
                    fields["parameters"] = refreshed_terms
                consequences = status.pop('response_consequences', None)
                if consequences is not None:
                    fields["response_consequences"] = consequences
                if "proposal_status" in fields:
                    fields["proposal_status"] = status
            elif params.get("fresh_pending") is True:
                status = {"status": "unknown", "reason": "CURRENT_PENDING_NOT_IN_EVENT_SNAPSHOT"}
                if "proposal_status" in fields:
                    fields["proposal_status"] = status
            if "currently_pending" in fields:
                from .inbound_current import project_pending_flag
                fields["currently_pending"] = project_pending_flag(status, selected.get("proposal_id"))
            complete = False
        objects = [{"type": "country_pair",
                    "actor": selected.get("actor"), "recipient": selected.get("recipient"),
                    "proposal_id": selected.get("proposal_id")}]
        source = _source_info(topic["source"], context, complete=complete, provenance=provenance)
        if selected.get("gaps"):
            source["gaps"] = _copy(selected["gaps"])
        result = _result(normalized, context, fields, complete, source, objects)
        if observation_window is not None:
            result["observation_window"] = observation_window
        return result

    def _get_record(self, request_id: str, context: dict | None = None):
        journal = getattr(self.diplomacy_tools, "journal", None)
        if journal is None or not isinstance(request_id, str) or not request_id:
            return None, None
        try:
            record = journal.lookup_request(request_id)
            context = context if isinstance(context, dict) else {}
            session = self.session
            expected_session = context.get("session_id") or getattr(journal, "session_id", None)
            expected_experiment = (
                context.get("experiment_id")
                or getattr(journal, "experiment_id", None)
                or getattr(session, "experiment_id", None)
                or _record_of(session).get("experiment_id")
                or getattr(self.diplomacy_tools, "experiment_id", None)
            )
            if (expected_session is not None
                    and getattr(record, "session_id", None) != expected_session):
                return None, None
            if (expected_experiment is not None
                    and getattr(record, "experiment_id", None) != expected_experiment):
                return None, None
            evidence = journal.list_evidence_for_record(record)
            return record, evidence
        except Exception:
            return None, None

    def _refresh_native_record(self, record: Any, context: dict):
        getter = getattr(self.diplomacy_tools, "get_diplomatic_result", None)
        payload = getattr(record, "payload", {})
        journal = getattr(self.diplomacy_tools, "journal", None)
        if (not callable(getter) or context.get("status") != "ready"
                or getattr(record, "status", None) not in {"submitted", "unknown", "executing", "waiting_response"}
                or getattr(record, "submitted_at", None) is None
                or getattr(record, "session_id", None) != context.get("session_id")
                or getattr(record, "experiment_id", None) != getattr(journal, "experiment_id", None)
                or context.get("observer") not in (payload.get("actor"), payload.get("recipient"))):
            return record
        getter(record.request_id)
        return journal.lookup_request(record.request_id)

    def _read_journal(self, normalized: dict, context: dict) -> dict:
        topic = get_topic(normalized["topic"])
        request_id = normalized["parameters"].get("request_id")
        if request_id:
            record, evidence = self._get_record(request_id, context)
            if record is None:
                fields, _ = _field_result(normalized["fields"], {}, topic,
                                          unavailable="REQUEST_NOT_FOUND")
                return _result(normalized, context, fields, False,
                               _source_info("DurableJournal", context, mode="recorded", complete=False))
            if normalized["topic"] in {"A05", "C04"}:
                pair = _journal_actor_recipient(record)
                obj = normalized["object"]
                if (context.get("observer") not in pair.values()
                        or (obj.get("type") == "country_pair" and any(
                            obj.get(key) != pair.get(key) for key in ("actor", "recipient")))):
                    return self._unavailable(normalized, context, "REQUEST_OBSERVER_SCOPE_MISMATCH")
            try:
                record = self._refresh_native_record(record, context)
                evidence = self.diplomacy_tools.journal.list_evidence_for_record(record)
            except Exception:
                return self._unavailable(normalized, context, "NATIVE_RESULT_REFRESH_FAILED")
            if normalized["topic"] == "C04":
                event = self._journal_event(record, context, evidence)
                return self.replay_event(normalized, context, event)
            payload = _public_record(record, evidence)
            fields, complete = _field_result(normalized["fields"], payload, topic)
            return _result(normalized, context, fields, complete,
                           _source_info("DurableJournal", context, mode="recorded", complete=complete),
                           [{"type": normalized["object"].get("type"), "request_id": request_id}])
        return self._unavailable(normalized, context, "REQUEST_ID_REQUIRED")

    def read(self, query: dict, context: dict | None = None) -> dict:
        normalized = self.validate_query(query, context)
        current = _copy(context) if isinstance(context, dict) else self.context()
        topic_id = normalized["topic"]
        if topic_id == "C01":
            return self._context_result(normalized, current)
        if topic_id in _LIVE_INBOUND_TOPICS:
            return self._read_inbound(normalized, current)
        if topic_id == "A05":
            return self._read_journal(normalized, current)
        if topic_id == "W01":
            return self._read_war_discovery(normalized, current)
        if topic_id == "W02":
            return self._read_war_score(normalized, current)
        if topic_id in _DYNAMIC_TOPICS:
            return self._read_inspection(normalized, current)
        if topic_id in _JOURNAL_TOPICS:
            return self._read_journal(normalized, current)
        return self._unsupported(normalized, current)

    def read_event(self, query: dict, context: dict, event: dict) -> dict:
        if (query.get('topic') == 'C04' and isinstance(event.get('event_type'), str)
                and (event['event_type'] in country_modifier_observation.EVENT_SEMANTICS
                     or event['event_type'] == subsidy_expiry_observation.EVENT_TYPE
                     or event['event_type'] == truce_expiry_observation.EVENT_TYPE
                     or event['event_type'] == claim_expiry_observation.EVENT_TYPE
                     or event['event_type'] == land_promise_observation.EVENT_TYPE
                     or event['event_type'] == cooldown_expiry.EVENT_TYPE
                     or event['event_type'] in (rival_observation.EVENT_TYPE, war_declaration_observation.EVENT_TYPE,
                                               relation_observation.EVENT_TYPE, mission_observation.EVENT_TYPE,
                                               mission_availability_observation.EVENT_TYPE, mission_condition_observation.EVENT_TYPE))):
            return self.replay_event(query, context, event)
        if query.get("topic") in {"A04", "C04"} and event.get("event_type") == "diplomatic_proposal":
            return self.replay_event(query, context, event)
        if query.get("topic") not in {"A05", "C04"} or event.get("event_type") != "diplomatic_request_result":
            return self.read(query, context)
        return self.replay_event(query, context, event)

    def replay_event(self, query: dict, context: dict, event: dict) -> dict:
        if query.get('topic') == 'C04' and event.get('event_type') == cooldown_expiry.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not cooldown_expiry.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'COOLDOWN_EXPIRY_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('RecordedActionCooldownDeadline', context, complete=complete)
            source.update(event_id=event['event_id'], projection='event_snapshot',
                          coverage=cooldown_expiry.SCOPE, date_semantics=cooldown_expiry.DATE_SEMANTICS)
            return _result(normalized, dict(context, game_date=event['game_date']),
                           fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == subsidy_expiry_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not subsidy_expiry_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'SUBSIDY_EXPIRY_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeSubsidyExpiryObservation', context, complete=complete)
            source.update(event_id=event['event_id'], projection='event_snapshot',
                          coverage=subsidy_expiry_observation.SCOPE,
                          collected_game_date=context.get('game_date'),
                          date_semantics=subsidy_expiry_observation.DATE_SEMANTICS)
            return _result(normalized, dict(context, game_date=event['game_date']),
                           fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == truce_expiry_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not truce_expiry_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'TRUCE_EXPIRY_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeTruceExpiryObservation', context, complete=complete)
            source.update(event_id=event['event_id'], projection='event_snapshot',
                          coverage=truce_expiry_observation.SCOPE,
                          collected_game_date=context.get('game_date'),
                          date_semantics=truce_expiry_observation.DATE_SEMANTICS)
            return _result(normalized, dict(context, game_date=event['game_date']),
                           fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == claim_expiry_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not claim_expiry_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'CLAIM_EXPIRY_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeClaimExpiryObservation', context, complete=complete)
            source.update(event_id=event['event_id'], projection='event_snapshot',
                          coverage=claim_expiry_observation.SCOPE,
                          collected_game_date=context.get('game_date'),
                          date_semantics=claim_expiry_observation.DATE_SEMANTICS)
            return _result(normalized, dict(context, game_date=event['game_date']),
                           fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == land_promise_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not land_promise_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'LAND_PROMISE_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeLandPromiseObservation', context, complete=complete)
            source.update(event_id=event['event_id'], projection='event_snapshot',
                          coverage=land_promise_observation.SCOPE,
                          collected_game_date=context.get('game_date'),
                          date_semantics=land_promise_observation.DATE_SEMANTICS)
            return _result(normalized, dict(context, game_date=event['game_date']),
                           fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == mission_condition_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not mission_condition_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'MISSION_CONDITION_EVENT_SCOPE_MISMATCH')
            fields, _ = _field_result(normalized['fields'], event, get_topic('C04'))
            complete = False
            source = _source_info('NativeMissionConditionObservation', context, complete=complete)
            source.update(event_id=event['event_id'], projection='event_snapshot',
                          coverage=mission_condition_observation.SCOPE,
                          collected_game_date=context.get('game_date'),
                          date_semantics=mission_condition_observation.DATE_SEMANTICS)
            snapshot_context = dict(context, game_date=event['game_date'])
            return _result(normalized, snapshot_context, fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == mission_availability_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not mission_availability_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'MISSION_AVAILABILITY_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeMissionAvailabilityObservation', context, complete=complete)
            source.update(event_id=event['event_id'], projection='event_snapshot',
                          coverage=mission_availability_observation.SCOPE,
                          collected_game_date=context.get('game_date'),
                          date_semantics=mission_availability_observation.DATE_SEMANTICS)
            snapshot_context = dict(context, game_date=event['game_date'])
            return _result(normalized, snapshot_context, fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == mission_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not mission_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'MISSION_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeMissionCompletionObservation', context, complete=complete)
            scope = event['payload']['scope']
            source.update(event_id=event['event_id'], projection='event_snapshot', coverage=scope,
                          collected_game_date=context.get('game_date'),
                          date_semantics=mission_observation.DATE_SEMANTICS_BY_SCOPE[scope])
            snapshot_context = dict(context, game_date=event['game_date'])
            return _result(normalized, snapshot_context, fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == relation_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not relation_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'RELATION_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeRelationObservation', context, complete=complete)
            source.update(event_id=event['event_id'], projection='event_snapshot',
                          coverage=event['payload']['scope'], collected_game_date=context.get('game_date'),
                          date_semantics=relation_observation.DATE_SEMANTICS_BY_SCOPE[event['payload']['scope']])
            snapshot_context = dict(context, game_date=event['game_date'])
            return _result(normalized, snapshot_context, fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == war_declaration_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not war_declaration_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'WAR_DECLARATION_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeWarDeclarationObservation', context, complete=complete)
            if 'event_payload' in fields:
                fields['event_payload']['value'] = war_declaration_observation.project_role_labels(event['payload'])
            source.update(event_id=event['event_id'], projection='event_snapshot',
                          coverage=war_declaration_observation.SCOPE, collected_game_date=context.get('game_date'),
                          date_semantics=war_declaration_observation.DATE_SEMANTICS,
                          role_basis=war_declaration_observation.ROLE_BASIS)
            snapshot_context = dict(context, game_date=event['game_date'])
            return _result(normalized, snapshot_context, fields, complete, source, _copy(event['objects']))
        if query.get('topic') == 'C04' and event.get('event_type') == rival_observation.EVENT_TYPE:
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not rival_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'RIVAL_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeRivalObservation', context, complete=complete)
            source.update(event_id=event.get('event_id'), projection='event_snapshot',
                          coverage=event['payload']['scope'], collected_game_date=context.get('game_date'),
                          date_semantics=rival_observation.DATE_SEMANTICS_BY_SCOPE[event['payload']['scope']])
            snapshot_context = dict(context, game_date=event['game_date'])
            return _result(normalized, snapshot_context, fields, complete, source, _copy(event['objects']))
        if (query.get('topic') == 'C04' and isinstance(event.get('event_type'), str)
                and event['event_type'] in country_modifier_observation.EVENT_SEMANTICS):
            normalized = self.validate_query(query, context)
            params = normalized['parameters']
            if (not country_modifier_observation.valid_event_snapshot(event, context)
                    or params.get('request_id') is not None or params.get('case') is not None
                    or params.get('event_type', event['event_type']) != event['event_type']):
                return self._unavailable(normalized, context, 'COUNTRY_MODIFIER_EVENT_SCOPE_MISMATCH')
            fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
            source = _source_info('NativeCountryModifierObservation', context, complete=complete)
            source.update(event_id=event.get('event_id'), projection='event_snapshot',
                          coverage=country_modifier_observation.SCOPE,
                          collected_game_date=context.get('game_date'),
                          date_semantics=event['source']['date_semantics'])
            snapshot_context = dict(context, game_date=event.get('game_date'))
            return _result(normalized, snapshot_context, fields, complete, source, _copy(event.get('objects', [])))
        if query.get("topic") in {"A04", "C04"} and event.get("event_type") == "diplomatic_proposal":
            normalized = self.validate_query(query, context)
            payload = event.get("payload", {})
            obj = normalized["object"]
            params = normalized["parameters"]
            wanted_id = params.get("proposal_id")
            if (not isinstance(payload, dict)
                    or event.get("session_id") != context.get("session_id")
                    or event.get("observer") != context.get("observer")
                    or payload.get("recipient") != context.get("observer")
                    or not payload.get("proposal_id")
                    or (wanted_id is not None and wanted_id != payload.get("proposal_id"))
                    or (obj.get("type") == "country_pair" and any(
                        obj.get(key) != payload.get(key) for key in ("actor", "recipient")))):
                return self._unavailable(normalized, context, "EVENT_PROPOSAL_SCOPE_MISMATCH")
            if normalized['topic'] == 'C04':
                lifecycle = proposal_expiry.ended_lifecycle(payload)
                event_date = event.get('game_date')
                if (params.get('request_id') is not None or params.get('case') is not None
                        or params.get('event_type', event['event_type']) != event['event_type']
                        or (event_date is not None and
                            (type(event_date) is not int or not 0 <= event_date <= 0x7fffffff))
                        or (payload.get('observer_status') in {'expired', 'inactive'} and lifecycle is None)
                        or (lifecycle is not None and event_date != lifecycle['game_date_raw'])):
                    return self._unavailable(normalized, context, 'EVENT_PROPOSAL_SCOPE_MISMATCH')
                fields, complete = _field_result(normalized['fields'], event, get_topic('C04'))
                source = _source_info('ObserverSession.read_native_alliance_inbound_offers', context,
                                      complete=complete)
                source.update(event_id=event.get('event_id'), projection='event_snapshot')
                snapshot_context = dict(context, game_date=event_date)
                return _result(normalized, snapshot_context, fields, complete, source,
                               _copy(event.get('objects', [])))
            result = self._project_inbound(normalized, context, payload, allow_fresh=False)
            result["source"].update(event_id=event.get("event_id"), projection="event_snapshot")
            return result
        if query.get("topic") not in {"A05", "C04"} or event.get("event_type") != "diplomatic_request_result":
            return unknown_event_projection(query, self)
        normalized = self.validate_query(query, context)
        payload = event.get("payload", {})
        request = payload.get("request", {})
        obj = normalized["object"]
        params = normalized["parameters"]
        requested_id = params.get("request_id") or request.get("request_id")
        if (event.get("session_id") != context.get("session_id")
                or event.get("observer") != context.get("observer")
                or context.get("observer") not in (payload.get("actor"), payload.get("recipient"))
                or payload.get("identity", {}).get("experiment_id") != getattr(
                    getattr(self.diplomacy_tools, "journal", None), "experiment_id", None)
                or requested_id != request.get("request_id")
                or params.get("event_type", event["event_type"]) != event["event_type"]
                or params.get("case") is not None
                or (obj.get("type") == "country_pair" and any(
                    obj.get(key) != payload.get(key) for key in ("actor", "recipient")))):
            return self._unavailable(normalized, context, "EVENT_REQUEST_SCOPE_MISMATCH")
        topic = normalized["topic"]
        snapshot = event if topic == "C04" else request
        fields, complete = _field_result(normalized["fields"], snapshot, get_topic(topic))
        source = _source_info("DurableJournal", context, mode="recorded", complete=complete)
        source["event_id"] = event.get("event_id")
        source["projection"] = "event_snapshot"
        objects = (_copy(event.get("objects", [])) if topic == "C04" else
                   [{"type": obj.get("type"), "request_id": requested_id}])
        return _result(normalized, context, fields, complete, source, objects)

    def _journal_items(self, context: dict) -> tuple[list[Any], list[Any], list[str]]:
        journal = getattr(self.diplomacy_tools, "journal", None)
        if journal is None:
            return [], [], ["JOURNAL_UNAVAILABLE"]
        try:
            records = journal.list_requests()
        except Exception:
            return [], [], ["JOURNAL_READ_FAILED"]
        evidence = []
        gaps = []
        refreshed = []
        for record in records:
            try:
                record = self._refresh_native_record(record, context)
            except Exception:
                gaps.append("NATIVE_RESULT_REFRESH_FAILED:" + str(getattr(record, "request_id", "unknown")))
            refreshed.append(record)
            try:
                evidence.extend(journal.list_evidence_for_record(record))
            except Exception:
                gaps.append(
                    "EVIDENCE_READ_FAILED:" + str(getattr(record, "request_id", "unknown"))
                )
        return refreshed, evidence, gaps

    @staticmethod
    def _journal_event(record: Any, context: dict, evidence: list | None = None) -> dict:
        from ..native_result_date import for_record

        public = _public_record(record, evidence)
        identity = {
            "experiment_id": getattr(record, "experiment_id", None),
            "session_id": getattr(record, "session_id", None),
            "request_id": public.get("request_id"),
            "updated_at": public.get("updated_at"),
        }
        event_id = _journal_event_id("request", identity)
        payload = {"request": public, "identity": identity}
        payload.update(_journal_actor_recipient(record))
        collected_date = context.get("game_date")
        native_date = for_record(record)
        if native_date is not None:
            event_date, date_semantics = native_date, 'native_executor_result_date'
        elif getattr(record, 'submitted_at', None):
            event_date, date_semantics = None, 'response_time_unknown'
        else:
            event_date, date_semantics = _journal_historical_date(record), 'recorded_date'
        return {"event_id": event_id, "event_type": "diplomatic_request_result",
                "session_id": context.get("session_id"), "observer": context.get("observer"),
                "game_date": event_date,
                "collected_game_date": collected_date,
                "objects": [{"type": "session", "session_id": context.get("session_id")}],
                "payload": payload,
                "source": {"name": "DurableJournal", "mode": "recorded",
                           "session_id": context.get("session_id"),
                           "date_semantics": date_semantics,
                           "collected_game_date": collected_date, "complete": True},
                "complete": True}

    @staticmethod
    def _evidence_event(record: Any, evidence: Any, context: dict) -> dict:
        identity = {
            "experiment_id": getattr(record, "experiment_id", None),
            "session_id": getattr(record, "session_id", None),
            "request_id": getattr(record, "request_id", None),
            "event_id": getattr(evidence, "event_id", None),
        }
        event_id = _journal_event_id("evidence", identity)
        payload = {"request_id": getattr(record, "request_id", None),
                   "evidence_event_id": getattr(evidence, "event_id", None),
                   "evidence_type": getattr(evidence, "evidence_type", None),
                   "arrival_layer": getattr(evidence, "arrival_layer", None),
                   "sha256": getattr(evidence, "content_sha256", None),
                   "identity": identity}
        payload.update(_journal_actor_recipient(record))
        collected_date = context.get("game_date")
        return {"event_id": event_id, "event_type": "evidence",
                "session_id": context.get("session_id"), "observer": context.get("observer"),
                "game_date": _journal_historical_date(record),
                "collected_game_date": collected_date,
                "objects": [{"type": "session", "session_id": context.get("session_id"),
                             "request_id": getattr(record, "request_id", None)}],
                "payload": payload,
                "source": {"name": "DurableJournal", "mode": "recorded",
                           "session_id": context.get("session_id"),
                           "collected_game_date": collected_date, "complete": True},
                "complete": True}

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        current = _copy(context) if isinstance(context, dict) else self.context()
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        cursor = cursor or {}
        events: list[dict] = []
        gaps: list[str] = []
        sequence = int(cursor.get("sequence", 0)) if type(cursor.get("sequence", 0)) is int else 0
        seen_inbound = set(cursor.get("inbound_ids", [])) if isinstance(cursor.get("inbound_ids", []), list) else set()
        inbound_ids = set(seen_inbound)
        if self.session is not None and current.get("status") == "ready":
            reader = getattr(self.session, "read_native_alliance_inbound_offers", None)
            if not callable(reader):
                reader = getattr(self.session, "read_native_inbound_offers", None)
            if callable(reader):
                try:
                    items = reader()
                    if not isinstance(items, (list, tuple)):
                        raise ValueError("INBOUND_RESULT_INVALID")
                    gap_reader = getattr(self.session, "read_native_inbound_capture_gaps", None)
                    if callable(gap_reader):
                        gaps.extend(gap_reader())
                    event_reader = getattr(self.session, 'read_native_inbound_events', None)
                    if callable(event_reader):
                        observations = event_reader(refresh=False)
                        if not isinstance(observations, (list, tuple)):
                            raise ValueError('INBOUND_EVENTS_INVALID')
                    else:
                        observations = [{'payload': item} for item in items]
                    for observation in observations:
                        if not isinstance(observation, dict):
                            continue
                        item = observation.get('payload')
                        if not isinstance(item, dict) or item.get('recipient') != current.get('observer'):
                            continue
                        identity = observation.get('identity') or item.get("proposal_id") or hashlib.sha256(canonical(item).encode()).hexdigest()
                        identity = str(identity)
                        inbound_ids.add(identity)
                        if identity in seen_inbound:
                            continue
                        event_date = observation.get('date_raw')
                        if event_date is None:
                            event_date = item.get('date_raw')
                        if type(event_date) is not int or not 0 <= event_date <= 0x7fffffff:
                            event_date = None
                        date_semantics = 'proposal_time_unknown' if event_date is None else 'proposal_source_date'
                        sequence += 1
                        events.append({
                            "event_id": observation.get('event_id') or "inbound:" + identity,
                            "event_type": "diplomatic_proposal",
                            "session_id": current.get("session_id"), "observer": current.get("observer"),
                            "game_date": event_date,
                            "collected_game_date": current.get("game_date"),
                            "objects": [{"type": "country_pair", "actor": item.get("actor"),
                                         "recipient": item.get("recipient"),
                                         "proposal_id": item.get("proposal_id")}],
                            "payload": _copy(item),
                            "source": {"name": "ObserverSession.read_native_alliance_inbound_offers",
                                       "mode": "live", "session_id": current.get("session_id"),
                                       "date_semantics": date_semantics,
                                       "collected_game_date": current.get("game_date"),
                                       "complete": item.get("complete", True) is True,
                                       "gaps": _copy(item.get("gaps", []))},
                            "complete": item.get("complete", True) is True, "sequence": sequence,
                        })
                except Exception:
                    gaps.append("INBOUND_READ_FAILED")
            elif self.session is not None:
                gaps.append("INBOUND_READER_UNAVAILABLE")
        elif self.session is None:
            gaps.append("NO_SESSION")
        else:
            gaps.append("SESSION_UNREADY")

        subsidy_expiry_sequence = cursor.get('subsidy_expiry_sequence', 0)
        if self._subsidy_expiry_enabled:
            if type(subsidy_expiry_sequence) is not int or not 0 <= subsidy_expiry_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'subsidy_expiry_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_subsidy_expiry_events(
                        after_sequence=subsidy_expiry_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': subsidy_expiry_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': True, 'sequence': sequence + 1,
                            'source': {'name': 'ObserverSession.read_native_subsidy_expiry_events',
                                       'mode': 'live', 'session_id': current['session_id'],
                                       'native_sequence': native_sequence, 'complete': True,
                                       'scope': subsidy_expiry_observation.SCOPE,
                                       'date_semantics': subsidy_expiry_observation.DATE_SEMANTICS},
                        }
                        if not subsidy_expiry_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'SUBSIDY_EXPIRY_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        subsidy_expiry_sequence = native_sequence
                except Exception:
                    gaps.append('SUBSIDY_EXPIRY_READ_FAILED')
            else:
                gaps.append('SUBSIDY_EXPIRY_SOURCE_UNAVAILABLE')

        truce_expiry_sequence = cursor.get('truce_expiry_sequence', 0)
        if self._truce_expiry_enabled:
            if type(truce_expiry_sequence) is not int or not 0 <= truce_expiry_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'truce_expiry_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_truce_expiry_events(
                        after_sequence=truce_expiry_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': truce_expiry_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': True, 'sequence': sequence + 1,
                            'source': {'name': 'ObserverSession.read_native_truce_expiry_events',
                                       'mode': 'live', 'session_id': current['session_id'],
                                       'native_sequence': native_sequence, 'complete': True,
                                       'scope': truce_expiry_observation.SCOPE,
                                       'date_semantics': truce_expiry_observation.DATE_SEMANTICS},
                        }
                        if not truce_expiry_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'TRUCE_EXPIRY_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        truce_expiry_sequence = native_sequence
                except Exception:
                    gaps.append('TRUCE_EXPIRY_READ_FAILED')
            else:
                gaps.append('TRUCE_EXPIRY_SOURCE_UNAVAILABLE')

        claim_expiry_sequence = cursor.get('claim_expiry_sequence', 0)
        if self._claim_expiry_enabled:
            if type(claim_expiry_sequence) is not int or not 0 <= claim_expiry_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'claim_expiry_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_claim_expiry_events(
                        after_sequence=claim_expiry_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': claim_expiry_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': True, 'sequence': sequence + 1,
                            'source': {'name': 'ObserverSession.read_native_claim_expiry_events',
                                       'mode': 'live', 'session_id': current['session_id'],
                                       'native_sequence': native_sequence, 'complete': True,
                                       'scope': claim_expiry_observation.SCOPE,
                                       'date_semantics': claim_expiry_observation.DATE_SEMANTICS},
                        }
                        if not claim_expiry_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'CLAIM_EXPIRY_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        claim_expiry_sequence = native_sequence
                except Exception:
                    gaps.append('CLAIM_EXPIRY_READ_FAILED')
            else:
                gaps.append('CLAIM_EXPIRY_SOURCE_UNAVAILABLE')
        land_promise_sequence = cursor.get('land_promise_sequence', 0)
        if self._land_promise_enabled:
            if type(land_promise_sequence) is not int or not 0 <= land_promise_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'land_promise_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_land_promise_events(
                        after_sequence=land_promise_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': land_promise_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'actor': observation['payload']['promisor'],
                            'recipient': observation['payload']['beneficiary'],
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': True, 'sequence': sequence + 1,
                            'source': {'name': 'ObserverSession.read_native_land_promise_events',
                                       'mode': 'live', 'session_id': current['session_id'],
                                       'native_sequence': native_sequence, 'complete': True,
                                       'scope': land_promise_observation.SCOPE,
                                       'date_semantics': land_promise_observation.DATE_SEMANTICS},
                        }
                        if not land_promise_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'LAND_PROMISE_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        land_promise_sequence = native_sequence
                except Exception:
                    gaps.append('LAND_PROMISE_READ_FAILED')
            else:
                gaps.append('LAND_PROMISE_SOURCE_UNAVAILABLE')

        modifier_sequence = cursor.get('country_modifier_sequence', 0)
        if self._modifier_events_enabled:
            if type(modifier_sequence) is not int or not 0 <= modifier_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'country_modifier_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_country_modifier_events(after_sequence=modifier_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        event_type = country_modifier_observation.CHANGE_EVENT_TYPES.get(observation['payload'].get('change'))
                        if event_type is None:
                            raise InformationError('invalid_source_result', 'COUNTRY_MODIFIER_CHANGE_INVALID')
                        if event_type == country_modifier_observation.REMOVE_EVENT_TYPE and not self._modifier_removals_enabled:
                            raise InformationError('invalid_source_result', 'COUNTRY_MODIFIER_REMOVAL_NOT_AVAILABLE')
                        if event_type == country_modifier_observation.EXPIRY_EVENT_TYPE and not self._modifier_expiry_enabled:
                            raise InformationError('invalid_source_result', 'COUNTRY_MODIFIER_EXPIRY_NOT_AVAILABLE')
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': event_type,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': [{'type': 'country', 'country': 'FRA'}],
                            'payload': _copy(observation['payload']), 'complete': True, 'sequence': sequence + 1,
                            'source': {'name': 'ObserverSession.read_native_country_modifier_events',
                                       'mode': 'live', 'session_id': current['session_id'],
                                       'native_sequence': native_sequence, 'complete': True,
                                       'scope': country_modifier_observation.SCOPE,
                                       'date_semantics': country_modifier_observation.EVENT_SEMANTICS[event_type][1]},
                        }
                        if not country_modifier_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'COUNTRY_MODIFIER_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        modifier_sequence = native_sequence
                except Exception:
                    gaps.append('COUNTRY_MODIFIER_READ_FAILED')
            else:
                gaps.append('COUNTRY_MODIFIER_SOURCE_UNAVAILABLE')

        rival_sequence = cursor.get('rival_sequence', 0)
        if self._rival_events_enabled:
            if type(rival_sequence) is not int or not 0 <= rival_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'rival_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_rival_events(after_sequence=rival_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': rival_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': True, 'sequence': sequence + 1,
                            'source': {'name': 'ObserverSession.read_native_rival_events', 'mode': 'live',
                                       'session_id': current['session_id'], 'native_sequence': native_sequence,
                                       'complete': True, 'scope': observation['payload']['scope'],
                                       'date_semantics': rival_observation.DATE_SEMANTICS_BY_SCOPE[observation['payload']['scope']]},
                        }
                        if not rival_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'RIVAL_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        rival_sequence = native_sequence
                except Exception:
                    gaps.append('RIVAL_READ_FAILED')
            else:
                gaps.append('RIVAL_SOURCE_UNAVAILABLE')

        war_sequence = cursor.get('war_declaration_sequence', 0)
        if self._war_declarations_enabled:
            if type(war_sequence) is not int or not 0 <= war_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'war_declaration_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_war_declaration_events(after_sequence=war_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': war_declaration_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': True, 'sequence': sequence + 1,
                            'source': {'name': 'ObserverSession.read_native_war_declaration_events', 'mode': 'live',
                                       'session_id': current['session_id'], 'native_sequence': native_sequence,
                                       'complete': True, 'scope': war_declaration_observation.SCOPE,
                                       'date_semantics': war_declaration_observation.DATE_SEMANTICS},
                        }
                        if not war_declaration_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'WAR_DECLARATION_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        war_sequence = native_sequence
                except Exception:
                    gaps.append('WAR_DECLARATION_READ_FAILED')
            else:
                gaps.append('WAR_DECLARATION_SOURCE_UNAVAILABLE')

        relation_sequence = cursor.get('relation_sequence', 0)
        if self._relation_events_enabled:
            if type(relation_sequence) is not int or not 0 <= relation_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'relation_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_relation_events(after_sequence=relation_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': relation_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': True, 'sequence': sequence + 1,
                            'source': {'name': 'ObserverSession.read_native_relation_events', 'mode': 'live',
                                       'session_id': current['session_id'], 'native_sequence': native_sequence,
                                       'complete': True, 'scope': observation['payload']['scope'],
                                       'date_semantics': relation_observation.DATE_SEMANTICS_BY_SCOPE[observation['payload']['scope']]},
                        }
                        if not relation_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'RELATION_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        relation_sequence = native_sequence
                except Exception:
                    gaps.append('RELATION_READ_FAILED')
            else:
                gaps.append('RELATION_SOURCE_UNAVAILABLE')

        mission_sequence = cursor.get('mission_sequence', 0)
        if self._mission_events_enabled:
            if type(mission_sequence) is not int or not 0 <= mission_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'mission_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_mission_events(after_sequence=mission_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': mission_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': True, 'sequence': sequence + 1,
                            'source': {'name': 'ObserverSession.read_native_mission_events', 'mode': 'live',
                                       'session_id': current['session_id'], 'native_sequence': native_sequence,
                                       'complete': True, 'scope': observation['payload']['scope'],
                                       'date_semantics': mission_observation.DATE_SEMANTICS_BY_SCOPE[
                                           observation['payload']['scope']]},
                        }
                        if not mission_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'MISSION_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        mission_sequence = native_sequence
                except Exception:
                    gaps.append('MISSION_READ_FAILED')
            else:
                gaps.append('MISSION_SOURCE_UNAVAILABLE')

        mission_availability_sequence = cursor.get('mission_availability_sequence', 0)
        if self._mission_availability_enabled:
            if type(mission_availability_sequence) is not int or not 0 <= mission_availability_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'mission_availability_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_mission_availability_events(
                        after_sequence=mission_availability_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': mission_availability_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': True, 'sequence': sequence+1,
                            'source': {'name': 'ObserverSession.read_native_mission_availability_events', 'mode': 'live',
                                       'session_id': current['session_id'], 'native_sequence': native_sequence,
                                       'complete': True, 'scope': mission_availability_observation.SCOPE,
                                       'date_semantics': mission_availability_observation.DATE_SEMANTICS},
                        }
                        if not mission_availability_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'MISSION_AVAILABILITY_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        mission_availability_sequence = native_sequence
                except Exception:
                    gaps.append('MISSION_AVAILABILITY_READ_FAILED')
            else:
                gaps.append('MISSION_AVAILABILITY_SOURCE_UNAVAILABLE')

        mission_condition_sequence = cursor.get('mission_condition_sequence', 0)
        if self._mission_condition_enabled:
            if type(mission_condition_sequence) is not int or not 0 <= mission_condition_sequence <= 2**63 - 1:
                raise InformationError('invalid_cursor', 'mission_condition_sequence must be a nonnegative integer')
            if (current.get('status') == 'ready' and current.get('observer') == 'FRA'
                    and current.get('session_id') == getattr(self.session, 'session_id', None)):
                try:
                    batch = self.session.read_native_mission_condition_events(
                        after_sequence=mission_condition_sequence, refresh=False)
                    gaps.extend(batch['gaps'])
                    for observation in batch['events']:
                        native_sequence = observation['native_sequence']
                        candidate = {
                            'event_id': observation['event_id'], 'event_type': mission_condition_observation.EVENT_TYPE,
                            'session_id': current['session_id'], 'observer': 'FRA',
                            'game_date': observation['game_date'], 'collected_game_date': current.get('game_date'),
                            'objects': _copy(observation['objects']), 'payload': _copy(observation['payload']),
                            'complete': False, 'sequence': sequence+1,
                            'source': {'name': 'ObserverSession.read_native_mission_condition_events', 'mode': 'live',
                                       'session_id': current['session_id'], 'native_sequence': native_sequence,
                                       'complete': False, 'scope': observation['payload']['scope'],
                                       'date_semantics': mission_condition_observation.DATE_SEMANTICS},
                        }
                        if not mission_condition_observation.valid_event_snapshot(candidate, current):
                            raise InformationError('invalid_source_result', 'MISSION_CONDITION_EVENT_INVALID')
                        sequence += 1
                        events.append(candidate)
                        mission_condition_sequence = native_sequence
                except Exception:
                    gaps.append('MISSION_CONDITION_READ_FAILED')
            else:
                gaps.append('MISSION_CONDITION_SOURCE_UNAVAILABLE')

        records, evidence, journal_gaps = self._journal_items(current)
        gaps.extend(journal_gaps)
        seen_records = cursor.get("journal_records", {})
        if not isinstance(seen_records, dict):
            seen_records = {}
        next_records = {}
        seen_evidence = set(cursor.get("journal_evidence", [])) if isinstance(cursor.get("journal_evidence", []), list) else set()
        next_evidence = set(seen_evidence)
        by_request = {getattr(record, "request_id", ""): record for record in records}
        for request_id, record in by_request.items():
            signature = str(getattr(record, "updated_at", ""))
            next_records[request_id] = signature
            if seen_records.get(request_id) != signature:
                sequence += 1
                event = self._journal_event(record, current, [
                    item for item in evidence if getattr(item, "request_id", None) == request_id])
                event["sequence"] = sequence
                events.append(event)
            for item in [entry for entry in evidence if getattr(entry, "request_id", None) == request_id]:
                evidence_id = str(getattr(item, "event_id", ""))
                next_evidence.add(evidence_id)
                if evidence_id in seen_evidence:
                    continue
                sequence += 1
                event = self._evidence_event(record, item, current)
                event["sequence"] = sequence
                events.append(event)
        cooldown_cursor = cursor.get('action_cooldowns')
        if callable(self.cooldown_reader):
            try:
                batch = self.cooldown_reader(current, cooldown_cursor)
                for event in batch['events']:
                    if not cooldown_expiry.valid_event_snapshot(event, current):
                        raise InformationError('invalid_source_result', 'COOLDOWN_EXPIRY_EVENT_INVALID')
                for event in batch['events']:
                    sequence += 1
                    events.append(dict(event, sequence=sequence))
                cooldown_cursor = batch['cursor']
                gaps.extend(batch['gaps'])
            except Exception:
                gaps.append('COOLDOWN_EXPIRY_READ_FAILED')
        next_cursor = {"sequence": sequence, "inbound_ids": sorted(inbound_ids),
                       "journal_records": next_records, "journal_evidence": sorted(next_evidence)}
        if callable(self.cooldown_reader):
            next_cursor['action_cooldowns'] = _copy(cooldown_cursor)
        if self._subsidy_expiry_enabled:
            next_cursor['subsidy_expiry_sequence'] = subsidy_expiry_sequence
        if self._truce_expiry_enabled:
            next_cursor['truce_expiry_sequence'] = truce_expiry_sequence
        if self._claim_expiry_enabled:
            next_cursor['claim_expiry_sequence'] = claim_expiry_sequence
        if self._land_promise_enabled:
            next_cursor['land_promise_sequence'] = land_promise_sequence
        if self._modifier_events_enabled:
            next_cursor['country_modifier_sequence'] = modifier_sequence
        if self._rival_events_enabled:
            next_cursor['rival_sequence'] = rival_sequence
        if self._war_declarations_enabled:
            next_cursor['war_declaration_sequence'] = war_sequence
        if self._relation_events_enabled:
            next_cursor['relation_sequence'] = relation_sequence
        if self._mission_events_enabled:
            next_cursor['mission_sequence'] = mission_sequence
        if self._mission_availability_enabled:
            next_cursor['mission_availability_sequence'] = mission_availability_sequence
        if self._mission_condition_enabled:
            next_cursor['mission_condition_sequence'] = mission_condition_sequence
        # Native producers own separate sequences. Merge their captured dates
        # while preserving proposal original-before-terminal delivery.
        macro_types = {
            cooldown_expiry.EVENT_TYPE,
            subsidy_expiry_observation.EVENT_TYPE,
            truce_expiry_observation.EVENT_TYPE,
            claim_expiry_observation.EVENT_TYPE,
            land_promise_observation.EVENT_TYPE,
            *country_modifier_observation.EVENT_SEMANTICS,
            rival_observation.EVENT_TYPE, war_declaration_observation.EVENT_TYPE,
            relation_observation.EVENT_TYPE, mission_observation.EVENT_TYPE,
            mission_availability_observation.EVENT_TYPE, mission_condition_observation.EVENT_TYPE,
        }
        def observed_date(event):
            value = event.get('game_date')
            return value if type(value) is int else float('inf')

        positions = [index for index, event in enumerate(events) if event.get('event_type') in macro_types]
        ordered = sorted((events[index] for index in positions), key=observed_date)
        for index, event in zip(positions, ordered):
            events[index] = event
        return {"events": events,
                "cursor": next_cursor,
                "complete": not gaps, "gaps": gaps}


class RecordedSource(DiplomacySource):
    """Read-only source backed by a JSON archive or a fixture object."""

    def __init__(self, archive: str | Path | dict | list):
        self.archive_path = str(archive) if isinstance(archive, (str, Path)) else None
        if isinstance(archive, (str, Path)):
            path = Path(archive)
            try:
                self.archive = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise InformationError("recorded_source", f"Cannot read archive: {exc}") from exc
        elif isinstance(archive, (dict, list)):
            self.archive = _copy(archive)
        else:
            raise InformationError("recorded_source", "archive must be a path, object or list")
        self.diplomacy_tools = None
        self._digest = hashlib.sha256(canonical(self.archive).encode("utf-8")).hexdigest()
        self.event_types = self._archive_event_types()

    def _archive_event_types(self) -> tuple[str, ...]:
        if isinstance(self.archive, dict) and isinstance(self.archive.get("events"), list):
            values = self.archive["events"]
        else:
            values = self._cases()
        result = []
        for item in values:
            event_type = _recorded_event_type(item)
            if event_type not in result:
                result.append(event_type)
        return tuple(result or ["recorded_case"])

    def context(self) -> dict:
        data = self.archive if isinstance(self.archive, dict) else {}
        manifest = data.get("manifest", {}) if isinstance(data.get("manifest", {}), dict) else {}
        health = data.get("context", data.get("health", manifest.get("context", manifest)))
        if not isinstance(health, dict):
            health = {}
        # Real query archives often keep identity on each native case rather
        # than duplicating it in a top-level manifest.  Derive only stable
        # provenance fields from the first case; this remains recorded data
        # and is never presented as a live session.
        first_case = self._cases()[0] if self._cases() else {}
        first_raw = first_case.get("raw") if isinstance(first_case, dict) else {}
        if not isinstance(first_raw, dict):
            first_raw = {}
        explicit_status = data.get("status", manifest.get("status", health.get("status")))
        status = explicit_status if explicit_status in {"ready", "unready"} else "unready"
        session = {
            "session_id": data.get("session_id") or manifest.get("session_id") or health.get("session_id"),
            "game_version": data.get("game_version") or manifest.get("game_version") or health.get("game_version"),
            "game_sha256": data.get("game_sha256") or manifest.get("game_sha256") or health.get("game_sha256"),
            "dll_sha256": data.get("dll_sha256") or manifest.get("dll_sha256") or health.get("dll_sha256"),
            "observer": data.get("observer") or manifest.get("observer") or health.get("observer"),
            "world_id": data.get("world_id") or manifest.get("world_id") or health.get("world_id"),
            "paused": data.get("paused") if isinstance(data.get("paused"), bool) else health.get("paused"),
            "game_date": data.get("game_date", data.get("date_raw", health.get("game_date", health.get("date_raw", first_case.get("game_date", first_raw.get("date_raw")))))),
            "game_day": data.get("game_day", manifest.get("game_day", health.get("game_day"))),
            "status": status,
            "mode": "recorded", "complete": bool(health.get("complete", True)),
            "reasons": _copy(health.get("reasons", [])) if isinstance(health.get("reasons", []), list) else [],
        }
        if not isinstance(session["game_version"], str) or not session["game_version"]:
            mapped = _VERSION_BY_GAME_SHA.get(session["game_sha256"])
            if mapped:
                session["game_version"] = mapped
        if session["status"] == "ready":
            missing = {
                "session_id": not isinstance(session["session_id"], str) or not session["session_id"],
                "game_version": not isinstance(session["game_version"], str) or not session["game_version"],
                "observer": not (isinstance(session["observer"], str)
                                  and re.fullmatch(r"[A-Z0-9]{3}", session["observer"])),
            }
            for key, absent in missing.items():
                if absent:
                    session["reasons"].append({"code": key.upper() + "_UNAVAILABLE"})
            if any(missing.values()):
                session["status"] = "unready"
        if not (isinstance(session["observer"], str)
                and re.fullmatch(r"[A-Z0-9]{3}", session["observer"])):
            session["observer"] = None
        if session["game_day"] is None and type(session["game_date"]) is int:
            session["game_day"] = session["game_date"] // 24
        if isinstance(session["world_id"], int):
            session["world_id"] = str(session["world_id"])
        session["game_date_raw"] = session["game_date"]
        session["game_date_kind"] = (
            "eu4_hour_tick" if type(session["game_date"]) is int else "source_value"
        )
        session["complete"] = bool(session["complete"]) and session["status"] == "ready"
        return session

    def _context_result(self, normalized: dict, context: dict) -> dict:
        fields, complete = _field_result(normalized["fields"], context,
                                         get_topic("C01"))
        return _result(
            normalized, context, fields, complete,
            _source_info("RecordedSource", context, mode="recorded",
                         complete=complete,
                         provenance={"sha256": self._digest,
                                     "archive": self.archive_path}),
        )

    def _cases(self) -> list[dict]:
        if isinstance(self.archive, dict) and isinstance(self.archive.get("cases"), list):
            return [item for item in self.archive["cases"] if isinstance(item, dict)]
        if isinstance(self.archive, list):
            return [item for item in self.archive if isinstance(item, dict)]
        return []

    def _select_case(self, normalized: dict) -> dict | None:
        params, obj = normalized["parameters"], normalized["object"]
        wanted = {key: params.get(key) or obj.get(key)
                  for key in ("case", "request_id", "proposal_id", "actor", "recipient", "action_id", "war_id")
                  if params.get(key) is not None or obj.get(key) is not None}
        for case in self._cases():
            payload = case.get("raw") if isinstance(case.get("raw"), dict) else case
            merged = dict(case)
            if isinstance(payload, dict):
                merged.update(payload)
            if all(merged.get(key) == value or payload.get(key) == value
                   for key, value in wanted.items()):
                return case
        return None

    def _payload_for_case(self, case: dict) -> dict:
        payload = case.get("raw") if isinstance(case.get("raw"), dict) else case
        merged = _copy(payload)
        if isinstance(merged, dict):
            for key, value in case.items():
                if key not in {"raw"} and key not in merged:
                    merged[key] = _copy(value)
        return merged if isinstance(merged, dict) else {}

    def read(self, query: dict, context: dict | None = None) -> dict:
        normalized = validate_query(query, context)
        current = _copy(context) if isinstance(context, dict) else self.context()
        if normalized["topic"] == "C01":
            return self._context_result(normalized, current)
        case = self._select_case(normalized)
        if case is None:
            if normalized["topic"] in {"C04", "H01", "H02"}:
                return self._read_journal(normalized, current)
            topic = get_topic(normalized["topic"])
            fields, _ = _field_result(normalized["fields"], {}, topic,
                                      unavailable="RECORDED_CASE_NOT_FOUND")
            return _result(normalized, current, fields, False,
                           _source_info("RecordedSource", current, mode="recorded",
                                        complete=False, provenance={"sha256": self._digest}))
        payload = self._payload_for_case(case)
        topic = get_topic(normalized["topic"])
        fields, complete = _field_result(normalized["fields"], payload, topic)
        return _result(normalized, current, fields, complete,
                       _source_info("RecordedSource", current, mode="recorded",
                                    complete=complete,
                                    provenance={"sha256": self._digest, "archive": self.archive_path}),
                       [normalized["object"]])

    def replay_event(self, query: dict, context: dict | None, event: dict) -> dict:
        """Rebuild from the archive without polling or live reads."""
        # Path input is snapshotted at construction and object input is copied,
        # so the archive projection is deterministic for this source instance.
        # Event-specific correlation remains the caller's responsibility.
        return self.read(_copy(query), _copy(context) if isinstance(context, dict) else None)

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        current = _copy(context) if isinstance(context, dict) else self.context()
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        cursor = cursor or {}
        index = cursor.get("index", 0)
        if type(index) is not int or index < 0:
            raise InformationError("invalid_cursor", "cursor.index must be a non-negative integer")
        raw_events = self.archive.get("events", []) if isinstance(self.archive, dict) else []
        if not isinstance(raw_events, list) or not raw_events:
            raw_events = self._cases()
        events = []
        for offset, raw in enumerate(raw_events[index:], index):
            if not isinstance(raw, dict):
                continue
            payload = _copy(raw)
            event_id = raw.get("event_id") or raw.get("request_id") or raw.get("name") or f"recorded:{offset}"
            event_type = _recorded_event_type(raw)
            game_date = raw.get("game_date", raw.get("date_raw", current.get("game_date")))
            events.append({
                "event_id": str(event_id), "event_type": str(event_type),
                "session_id": raw.get("session_id", current.get("session_id")),
                "observer": current.get("observer"), "game_date": game_date,
                "objects": [{"type": "session", "session_id": current.get("session_id")}],
                "payload": payload,
                "source": {"name": "RecordedSource", "mode": "recorded",
                           "session_id": current.get("session_id"), "complete": True,
                           "provenance": {"sha256": self._digest, "archive": self.archive_path}},
                "complete": True, "sequence": offset + 1,
            })
        return {"events": events, "cursor": {"index": len(raw_events)},
                "complete": True, "gaps": []}


__all__ = ["DiplomacySource", "RecordedSource"]

