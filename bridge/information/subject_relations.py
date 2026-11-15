"""Read-only selected-pair subject relation projection.

The information catalog describes R02 as a country-pair topic, but the
existing native query only proves the relation for the explicitly requested
pair.  This adapter keeps that boundary visible: it queries the public
``offer_vassalization`` inspection, derives the two endpoints when the native
state is active, and never turns an inactive selected pair into a claim about
all subjects or all subject types.
"""
from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from .model import InformationError, canonical
from .observation_time import context_identity, dates_match
from .sources import _copy, _result, _source_info


_COUNTRY = re.compile(r"[A-Z0-9]{3}\Z")
_SUBJECT_TYPE = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
_GAME_SHA256 = "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
_VERSION = "1.37.4"
_ACTION_ID = "offer_vassalization"
_FAMILY = "vassalization"
_PHASE = "initiate"
_FIELDS = ("overlord", "subject", "subject_type")
_IDENTITY_KEYS = (
    "status", "mode", "complete", "observer", "game_version", "game_sha256",
    "dll_sha256", "session_id", "game_date",
)


def _is_country(value: Any) -> bool:
    return isinstance(value, str) and _COUNTRY.fullmatch(value) is not None


def _known(value: Any) -> dict[str, Any]:
    return {"status": "known", "value": deepcopy(value)}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _not_applicable(reason: str) -> dict[str, Any]:
    return {"status": "not_applicable", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _identity_snapshot(context: dict[str, Any]) -> tuple[Any, ...]:
    return context_identity(context, _IDENTITY_KEYS)


def _identity_reason(context: Any) -> str | None:
    if not isinstance(context, dict):
        return "BASE_CONTEXT_INVALID"
    if context.get("status") != "ready":
        return "SESSION_UNREADY"
    if context.get("mode") != "live":
        return "LIVE_CONTEXT_REQUIRED"
    if context.get("complete") is not True:
        return "BASE_CONTEXT_INCOMPLETE"
    if context.get("observer") != "FRA":
        return "OBSERVER_FRA_REQUIRED"
    if context.get("game_version") != _VERSION:
        return "UNSUPPORTED_GAME_VERSION"
    if context.get("game_sha256") != _GAME_SHA256:
        return "GAME_IDENTITY_MISMATCH"
    dll_sha = context.get("dll_sha256")
    if not isinstance(dll_sha, str) or re.fullmatch(r"[0-9a-fA-F]{64}", dll_sha) is None:
        return "DLL_IDENTITY_UNAVAILABLE"
    session_id = context.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return "SESSION_ID_UNAVAILABLE"
    game_date = context.get("game_date")
    game_date_raw = context.get("game_date_raw")
    if type(game_date) is not int or type(game_date_raw) is not int:
        return "GAME_DATE_UNAVAILABLE"
    if game_date != game_date_raw:
        return "GAME_DATE_IDENTITY_MISMATCH"
    return None


def _field_metadata(field: str) -> dict[str, Any]:
    descriptions = {
        "overlord": "选定国家对中已验证的宗主端点；无属宗关系时为 not_applicable",
        "subject": "选定国家对中已验证的属国端点；无属宗关系时为 not_applicable",
        "subject_type": "原生关系记录提供的 ASCII 属国类型；无属宗关系时为 not_applicable",
    }
    return {
        "coverage": "partial",
        "source": "DiplomacyTools.inspect_diplomatic_action",
        "description": descriptions[field],
        "unit": "country_tag" if field != "subject_type" else "subject_type_id",
        "direction": "selected_country_pair",
        "paths": (["subject_type"] if field == "subject_type"
                  else ["actor", "recipient", "actor_is_overlord", "actor_is_subject"]),
        "derivation": ("native_subject_type_id" if field == "subject_type"
                       else "selected_pair_endpoint_from_verified_role_flags"),
    }


_CATALOG_ITEM = {
    "topic_id": "R02",
    "catalog_ids": ["R02"],
    "title": "选定国家对的宗主与属国关系（部分字段）",
    # The topic is routable by the information service.  Its individual
    # fields remain partial because this adapter proves only an explicit pair.
    "status": "available",
    "fields": {field: _field_metadata(field) for field in _FIELDS},
    "object_types": ["country_pair"],
    "observer_roles": ["country"],
    "parameters": {
        "type": "object",
        "properties": {},
        "required": [],
        "additionalProperties": False,
    },
    "supported_versions": [_VERSION],
    "observer_scope": ["FRA"],
    "triggers": ["query", "periodic", "change"],
    "change_detection": "sampled_state_comparison_not_lossless_events",
    "source": "DiplomacyTools.inspect_diplomatic_action",
    "visibility": "visible_scope",
    "context_scope": "selected_country_pair",
    "scope_note": (
        "只证明显式请求的国家对；不声称完整属国列表、全类型枚举或全局无关系。"
    ),
}


class NativeSubjectRelationSource:
    """Expose the verified selected-pair R02 native projection.

    ``base_source`` supplies the trusted live context and the existing
    ``diplomacy_tools.inspect_diplomatic_action`` reader.  This adapter calls
    the reader only; it has no submission, execution, date-advance, save, or
    game-start path.
    """

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source):
        self.base_source = base_source

    def context(self) -> dict[str, Any]:
        try:
            context = self.base_source.context()
        except Exception as exc:
            raise InformationError("source_context", f"base source context failed: {type(exc).__name__}") from exc
        if not isinstance(context, dict):
            raise InformationError("source_context", "base source context must be an object")
        canonical(context)
        return _copy(context)

    def catalog(self) -> list[dict[str, Any]]:
        return [deepcopy(_CATALOG_ITEM)]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "query must be an object")
        allowed = {"topic", "object", "fields", "parameters"}
        missing = {"topic", "object", "fields", "parameters"} - set(query)
        extra = set(query) - allowed
        if missing or extra:
            raise InformationError(
                "invalid_parameters",
                f"query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != "R02":
            raise InformationError("unknown_topic", "NativeSubjectRelationSource supports R02 only")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) != {"type", "actor", "recipient"}:
            raise InformationError(
                "invalid_object",
                "R02 queries require type, actor, and recipient only",
            )
        actor, recipient = obj.get("actor"), obj.get("recipient")
        if obj.get("type") != "country_pair" or not _is_country(actor) or not _is_country(recipient):
            raise InformationError("invalid_object", "R02 country_pair has invalid country tags")
        if actor != "FRA":
            raise InformationError("observer_scope_mismatch", "R02 actor must be the verified FRA observer")
        if actor == recipient:
            raise InformationError("invalid_object", "R02 actor and recipient must differ")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(field, str) for field in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError("invalid_fields", "fields must be a non-empty list of strings")
        unknown = set(fields) - set(_FIELDS)
        if unknown:
            raise InformationError("unknown_field", f"R02: unknown fields {sorted(unknown)}")
        parameters = query.get("parameters")
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "R02 parameters must be an empty object")
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            observer = context.get("observer")
            if observer is not None and observer != "FRA":
                raise InformationError(
                    "observer_scope_mismatch",
                    "R02 query is outside the verified FRA observer scope",
                )
        normalized = {
            "topic": "R02",
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": {},
        }
        canonical(normalized)
        return normalized

    def _base_context(self) -> tuple[dict[str, Any] | None, str | None]:
        try:
            context = self.context()
        except InformationError as exc:
            return None, exc.code.upper()
        reason = _identity_reason(context)
        return context, reason

    @staticmethod
    def _result(
            normalized: dict[str, Any], context: dict[str, Any],
            fields: dict[str, dict[str, Any]], complete: bool,
            *, reason: str | None = None, public: dict[str, Any] | None = None,
            unavailable: bool = False) -> dict[str, Any]:
        provenance: dict[str, Any] = {
            "adapter": "NativeSubjectRelationSource",
            "public_adapter": "DiplomacyTools.inspect_diplomatic_action",
            "action_id": _ACTION_ID,
            "family": _FAMILY,
            "phase": _PHASE,
            "read_only": True,
            "scope": "selected_country_pair",
            "observer_scope": "FRA",
            "global_relation_claim": False,
        }
        if reason is not None:
            provenance["reason"] = reason
        if public is not None:
            provenance["public_projection"] = deepcopy(public)
        source = _source_info(
            "NativeSubjectRelationSource", context,
            complete=complete,
            provenance=provenance,
        )
        if unavailable:
            source["status"] = "unavailable"
        return _result(normalized, context, fields, complete, source)

    @staticmethod
    def _failure_fields(fields: list[str], reason: str, *, unavailable: bool) -> dict[str, dict[str, Any]]:
        factory = _unavailable if unavailable else _unknown
        return {field: factory(reason) for field in fields}

    @staticmethod
    def _public_guard(
            inspected: dict[str, Any], actor: str, recipient: str
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        expected = {
            "action_id": _ACTION_ID,
            "family": _FAMILY,
            "phase": _PHASE,
            "actor": actor,
            "recipient": recipient,
        }
        for key, value in expected.items():
            if inspected.get(key) != value:
                return False, "PUBLIC_PROJECTION_IDENTITY_MISMATCH", None
        # The public projection may omit ``submitted`` (the real R35 adapter
        # does); if present, a true/non-boolean marker is a guard failure.
        if "submitted" in inspected and inspected.get("submitted") is not False:
            return False, "PUBLIC_PROJECTION_SUBMISSION_MARKER_INVALID", None
        relation = inspected.get("relationship_state")
        if not isinstance(relation, dict):
            return False, "RELATIONSHIP_STATE_MISSING", None
        active = inspected.get("vassal_active")
        nested_active = relation.get("vassal_active")
        if type(active) is not bool or type(nested_active) is not bool:
            return False, "VASSAL_ACTIVE_NOT_EXACT_BOOL", None
        if active != nested_active:
            return False, "VASSAL_ACTIVE_LAYERS_MISMATCH", None
        if inspected.get("vassal_state_verified") is not True:
            return False, "VASSAL_STATE_NOT_VERIFIED", None
        if relation.get("complete") is not True:
            return False, "RELATIONSHIP_STATE_INCOMPLETE", None
        roles = {
            "actor_is_overlord": inspected.get("actor_is_overlord"),
            "actor_is_subject": inspected.get("actor_is_subject"),
        }
        if any(type(value) is not bool for value in roles.values()):
            return False, "RELATION_ROLES_NOT_EXACT_BOOL", None
        subject_type = inspected.get("subject_type")
        public = {
            "action_id": inspected.get("action_id"),
            "family": inspected.get("family"),
            "phase": inspected.get("phase"),
            "actor": inspected.get("actor"),
            "recipient": inspected.get("recipient"),
            "vassal_active": active,
            "relationship_state_vassal_active": nested_active,
            "vassal_state_verified": True,
            "relationship_state_complete": True,
            **roles,
            "subject_type": subject_type,
        }
        return True, None, public

    @classmethod
    def _derive_fields(
            cls, inspected: dict[str, Any], actor: str, recipient: str,
            fields: list[str]
    ) -> tuple[dict[str, dict[str, Any]], bool, str | None, dict[str, Any]]:
        ok, reason, public = cls._public_guard(inspected, actor, recipient)
        if not ok or public is None:
            return {}, False, reason or "PUBLIC_PROJECTION_INVALID", {}
        active = public["vassal_active"]
        actor_is_overlord = public["actor_is_overlord"]
        actor_is_subject = public["actor_is_subject"]
        if active:
            if actor_is_overlord == actor_is_subject:
                return {}, False, "RELATION_ROLE_AMBIGUOUS", public
            subject_type = public["subject_type"]
            if not isinstance(subject_type, str) or _SUBJECT_TYPE.fullmatch(subject_type) is None:
                return {}, False, "SUBJECT_TYPE_INVALID_ASCII", public
            if actor_is_overlord:
                values = {"overlord": actor, "subject": recipient, "subject_type": subject_type}
            else:
                values = {"overlord": recipient, "subject": actor, "subject_type": subject_type}
            return {field: _known(values[field]) for field in fields}, True, None, public
        if actor_is_overlord or actor_is_subject:
            return {}, False, "INACTIVE_RELATION_ROLE_CONFLICT", public
        # The selected pair has no verified vassal relation.  This is a
        # pair-scoped not-applicable result, never a global absence claim.
        if public["subject_type"] is not None:
            return {}, False, "INACTIVE_SUBJECT_TYPE_NOT_EMPTY", public
        public["subject_type"] = None
        reason = "SELECTED_PAIR_HAS_NO_VASSAL_RELATION"
        return {field: _not_applicable(reason) for field in fields}, True, None, public

    def read(self, query: dict, context: dict | None = None) -> dict:
        normalized = self.validate_query(query, context)
        supplied_context = _copy(context) if isinstance(context, dict) else None
        before, reason = self._base_context()
        if before is None:
            fallback = supplied_context or {"mode": "live", "status": "unready", "complete": False}
            fields = self._failure_fields(normalized["fields"], reason or "BASE_CONTEXT_UNAVAILABLE", unavailable=True)
            return self._result(normalized, fallback, fields, False,
                                reason=reason or "BASE_CONTEXT_UNAVAILABLE", unavailable=True)
        if supplied_context is not None:
            supplied_reason = _identity_reason(supplied_context)
            if supplied_reason is not None:
                fields = self._failure_fields(normalized["fields"], supplied_reason, unavailable=True)
                return self._result(normalized, before, fields, False,
                                    reason=supplied_reason, unavailable=True)
            if (_identity_snapshot(supplied_context) != _identity_snapshot(before)
                    or not dates_match(supplied_context["game_date"], before["game_date"])):
                fields = self._failure_fields(normalized["fields"], "BASE_CONTEXT_CHANGED_BEFORE_QUERY", unavailable=True)
                return self._result(normalized, before, fields, False,
                                    reason="BASE_CONTEXT_CHANGED_BEFORE_QUERY", unavailable=True)
        if reason is not None:
            fields = self._failure_fields(normalized["fields"], reason, unavailable=True)
            return self._result(normalized, before, fields, False, reason=reason, unavailable=True)

        actor = normalized["object"]["actor"]
        recipient = normalized["object"]["recipient"]
        tools = getattr(self.base_source, "diplomacy_tools", None)
        inspector = getattr(tools, "inspect_diplomatic_action", None)
        if not callable(inspector):
            fields = self._failure_fields(normalized["fields"], "INSPECT_ADAPTER_UNAVAILABLE", unavailable=True)
            return self._result(normalized, before, fields, False,
                                reason="INSPECT_ADAPTER_UNAVAILABLE", unavailable=True)
        try:
            inspected = inspector(_ACTION_ID, actor, recipient, _PHASE, {})
        except Exception as exc:
            failure = "INSPECT_CALL_FAILED:" + type(exc).__name__
            fields = self._failure_fields(normalized["fields"], failure, unavailable=True)
            return self._result(normalized, before, fields, False, reason=failure, unavailable=True)
        if not isinstance(inspected, dict):
            fields = self._failure_fields(normalized["fields"], "INSPECT_RESULT_INVALID", unavailable=False)
            return self._result(normalized, before, fields, False,
                                reason="INSPECT_RESULT_INVALID")
        if inspected.get("error_code"):
            failure = str(inspected.get("error_code"))
            fields = self._failure_fields(normalized["fields"], failure, unavailable=True)
            return self._result(normalized, before, fields, False,
                                reason=failure, unavailable=True)

        after, after_reason = self._base_context()
        if after is None:
            fields = self._failure_fields(normalized["fields"], after_reason or "POST_CONTEXT_UNAVAILABLE", unavailable=False)
            return self._result(normalized, before, fields, False,
                                reason=after_reason or "POST_CONTEXT_UNAVAILABLE")
        if after_reason is not None:
            fields = self._failure_fields(normalized["fields"], "POST_CONTEXT_INVALID:" + after_reason, unavailable=False)
            return self._result(normalized, after, fields, False,
                                reason="POST_CONTEXT_INVALID:" + after_reason)
        if (_identity_snapshot(before) != _identity_snapshot(after)
                or not dates_match(before["game_date"], after["game_date"])):
            fields = self._failure_fields(normalized["fields"], "CONTEXT_CHANGED_DURING_QUERY", unavailable=False)
            return self._result(normalized, after, fields, False,
                                reason="CONTEXT_CHANGED_DURING_QUERY")

        fields, complete, derive_reason, public = self._derive_fields(
            inspected, actor, recipient, normalized["fields"])
        if derive_reason is not None:
            fields = self._failure_fields(normalized["fields"], derive_reason, unavailable=False)
            return self._result(normalized, after, fields, False,
                                reason=derive_reason, public=public)
        return self._result(normalized, after, fields, complete, public=public)

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {
            "events": [],
            "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {},
            "complete": True,
            "gaps": [],
        }


__all__ = ["NativeSubjectRelationSource"]
