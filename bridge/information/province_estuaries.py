"""Internal current estuary classification bound to the effective static rule."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from importlib import import_module
import hashlib
import re
from typing import Any

from .model import canonical
from .trade_income import (
    NativeTradeIncomeSource,
    _observer_context_reason as _base_context_reason,
    _identity,
    _session_binding,
)


SCHEMA = "information.province_estuary_classification.v1"
CAPTURE_SCHEMA = "information.province_modifiers_capture.v1"
INNER_SCHEMA = "information.province_modifiers_observer_snapshot.v1"
RULE_NAME = "has_river_estuary_trigger"
FIELD_PREDICATES = "G02.province_modifier_predicates"
BASIS = "native_province_modifiers_under_effective_disk_estuary_rule"
PREDICATE_BASIS = "native_has_province_modifier_predicates"
MAX_PROVINCE_ID = 0xFFFF
MAX_MODIFIER_KEYS = 64
MAX_MODIFIER_KEY_BYTES = 255
_KEY = re.compile(r"[A-Za-z0-9_-]{1,255}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PASSPHASES = ("pass1", "pass2")


def _safe_reason(code: str) -> str:
    """Only return fixed public reason codes; capture details may contain addresses."""
    return code


def _rule_identity(context: Mapping[str, Any]) -> str | None:
    # ``reasons`` may contain per-call diagnostics. All configuration,
    # definition, AST, parser, and identity fields remain in the digest.
    snapshot = deepcopy(dict(context))
    snapshot.pop("reasons", None)
    try:
        return hashlib.sha256(canonical(snapshot).encode("utf-8")).hexdigest()
    except Exception:
        return None


def _valid_rule_context(value: Any) -> tuple[dict[str, Any] | None, tuple[str, ...] | None]:
    if not isinstance(value, Mapping):
        return None, None
    context = deepcopy(dict(value))
    if (context.get("status") != "known" or context.get("complete") is not True
            or context.get("game_fact") is not False
            or context.get("context_scope") != "static_rules"
            or context.get("rule_name", context.get("name")) != RULE_NAME
            or not isinstance(context.get("scriptedtrigger_ast"), Mapping)):
        return context, None
    for name in ("configuration_sha256", "definitions_sha256", "scriptedtrigger_ast_sha256"):
        digest = context.get(name)
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            return context, None
    identity = context.get("identity")
    if (not isinstance(identity, Mapping) or identity.get("stable_before_after") is not True):
        return context, None
    hashes = [identity.get(key) for key in ("before_sha256", "after_sha256", "current_sha256")]
    if (any(not isinstance(item, str) or not _SHA256.fullmatch(item) for item in hashes)
            or len(set(hashes)) != 1):
        return context, None
    raw_keys = context.get("known_modifier_keys")
    if (not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= MAX_MODIFIER_KEYS
            or any(type(key) is not str or not _KEY.fullmatch(key) for key in raw_keys)
            or len(set(raw_keys)) != len(raw_keys)):
        return context, None
    try:
        if any(len(key.encode("ascii")) > MAX_MODIFIER_KEY_BYTES for key in raw_keys):
            return context, None
    except UnicodeEncodeError:
        return context, None
    return context, tuple(raw_keys)


def _positive_admission(value: Any, observer: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    role = value.get("observer_nonplayer_role")
    return (
        value.get("status") == "known"
        and type(value.get("admitted")) is bool
        and value["admitted"] is True
        and isinstance(role, Mapping)
        and role.get("observer") == observer
        and role.get("verified") is True
    )


def _positive_discovery(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("status") == "known"
        and type(value.get("value")) is bool
        and value["value"] is True
    )


def _access_valid(inner: Mapping[str, Any]) -> bool:
    access = inner.get("access")
    rows = inner.get("raw_reads")
    if not isinstance(access, Mapping) or not isinstance(rows, list):
        return False
    expected = {
        "read_only": True, "native_function_invoked": False, "writes": False,
        "UI_control": False, "date_advance": False, "save_or_reload": False,
    }
    if any(access.get(key) is not value for key, value in expected.items()):
        return False
    limit = access.get("limit_bytes")
    calls = access.get("calls")
    requested = access.get("bytes_requested")
    if (type(limit) is not int or not 0 < limit <= 16 * 1024 * 1024
            or type(calls) is not int or calls != len(rows)
            or type(requested) is not int or not 0 < requested <= limit):
        return False
    sizes = [row.get("size") for row in rows if isinstance(row, Mapping)]
    if len(sizes) != len(rows) or any(type(size) is not int or size <= 0 for size in sizes):
        return False
    return requested == sum(sizes)


def _capture_target(
    report: Any,
    context: Mapping[str, Any],
    province_id: int,
    keys: tuple[str, ...],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    if not isinstance(report, Mapping) or set(report) != {
        "schema", "observer", "object", "modifier_keys", "capture",
    }:
        return None, None, "PROVINCE_ESTUARY_CAPTURE_ENVELOPE_INVALID"
    observer = context.get("observer")
    if report.get("schema") != CAPTURE_SCHEMA or report.get("observer") != observer:
        return None, None, "PROVINCE_ESTUARY_CAPTURE_IDENTITY_INVALID"
    object_value = report.get("object")
    if (not isinstance(object_value, Mapping) or set(object_value) != {"type", "province_id"}
            or object_value.get("type") != "province"
            or type(object_value.get("province_id")) is not int
            or object_value.get("province_id") != province_id):
        return None, None, "PROVINCE_ESTUARY_CAPTURE_PROVINCE_MISMATCH"
    if report.get("modifier_keys") != list(keys):
        return None, None, "PROVINCE_ESTUARY_CAPTURE_KEYS_MISMATCH"
    inner = report.get("capture")
    if (not isinstance(inner, Mapping) or inner.get("schema") != INNER_SCHEMA
            or inner.get("status") != "observed" or inner.get("completed") is not True
            or not _access_valid(inner)):
        return None, None, "PROVINCE_ESTUARY_CAPTURE_UNVERIFIED"
    observation = inner.get("observation")
    if not isinstance(observation, Mapping) or observation.get("stable") is not True:
        return None, None, "PROVINCE_ESTUARY_CAPTURE_UNSTABLE"
    before = observation.get("context_before")
    after = observation.get("context_after")
    if (not isinstance(before, Mapping) or not isinstance(after, Mapping)
            or type(context.get("game_date")) is not int
            or type(before.get("game_date")) is not int
            or type(after.get("game_date")) is not int
            or before.get("game_date") != context.get("game_date")
            or after.get("game_date") != context.get("game_date")):
        return None, None, "PROVINCE_ESTUARY_CAPTURE_DATE_MISMATCH"
    backend = observation.get("backend")
    consistency = backend.get("consistency") if isinstance(backend, Mapping) else None
    backend_observer = backend.get("observer") if isinstance(backend, Mapping) else None
    if (not isinstance(backend, Mapping) or backend.get("status") != "observed"
            or not isinstance(consistency, Mapping) or consistency.get("status") != "stable"
            or not isinstance(backend_observer, Mapping) or backend_observer.get("tag") != observer):
        return None, None, "PROVINCE_ESTUARY_BACKEND_UNSTABLE"
    targets = backend.get("targets")
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(targets[0], Mapping):
        return None, None, "PROVINCE_ESTUARY_TARGET_INVALID"
    target = targets[0]
    if type(target.get("province_id")) is not int or target.get("province_id") != province_id:
        return None, None, "PROVINCE_ESTUARY_TARGET_PROVINCE_MISMATCH"
    admissions = target.get("admission_by_pass")
    discoveries = target.get("discovery_by_pass")
    if (not isinstance(admissions, Mapping) or not isinstance(discoveries, Mapping)
            or any(not _positive_admission(admissions.get(phase), observer) for phase in _PASSPHASES)
            or any(not _positive_discovery(discoveries.get(phase)) for phase in _PASSPHASES)):
        return None, None, "PROVINCE_ESTUARY_ADMISSION_OR_DISCOVERY_UNVERIFIED"
    field_consistency = target.get("field_consistency")
    if not isinstance(field_consistency, Mapping):
        return None, None, "PROVINCE_ESTUARY_FIELD_CONSISTENCY_MISSING"
    field_state = field_consistency.get(FIELD_PREDICATES)
    if not isinstance(field_state, Mapping) or field_state.get("status") != "stable":
        return None, None, "PROVINCE_ESTUARY_FIELD_NOT_STABLE"
    fields = target.get("fields")
    if not isinstance(fields, Mapping) or set(fields) != {FIELD_PREDICATES}:
        return None, None, "PROVINCE_ESTUARY_FIELD_MISSING"
    return dict(target), dict(inner), None


def _typed_predicates(field: Any, keys: tuple[str, ...]) -> tuple[dict[str, bool] | None, list[str]]:
    if (not isinstance(field, Mapping) or field.get("basis") != PREDICATE_BASIS
            or field.get("complete") is not False
            or field.get("status") not in {"known", "partial", "unknown"}):
        return None, list(keys)
    value = field.get("value")
    predicates = value.get("predicates") if isinstance(value, Mapping) else None
    if not isinstance(predicates, Mapping) or set(predicates) != set(keys):
        return None, list(keys)
    known: dict[str, bool] = {}
    unknown: list[str] = []
    for key in keys:
        item = predicates.get(key)
        if not isinstance(item, Mapping):
            return None, list(keys)
        if item.get("status") == "known" and type(item.get("value")) is bool:
            known[key] = item["value"]
        elif item.get("status") == "unknown" and isinstance(item.get("reason"), str) and item["reason"]:
            unknown.append(key)
        else:
            return None, list(keys)
    return known, unknown


class NativeProvinceEstuaryReader(NativeTradeIncomeSource):
    """Classify one province visible to the observer using the bound estuary rule."""

    def __init__(self, base_source: Any, rule_source: Any, *, capture=None):
        super().__init__(base_source, capture=capture)
        self.rule_source = rule_source

    def _live_reason(self, context: Any) -> str | None:
        reason = _base_context_reason(context)
        return reason.replace("TRADE_INCOME_", "PROVINCE_ESTUARY_", 1) if reason else None

    def _rule_context(self) -> tuple[dict[str, Any] | None, tuple[str, ...] | None]:
        try:
            value = self.rule_source.context()
        except Exception:
            return None, None
        return _valid_rule_context(value)

    def _classification(
        self,
        status: str,
        province_id: int,
        context: Mapping[str, Any],
        rule_binding: Mapping[str, Any] | None,
        reason: str | None = None,
        *,
        value: bool | None = None,
        matched: list[str] | None = None,
        unknown: list[str] | None = None,
        capture_sha256: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema": SCHEMA,
            "status": status,
            "province_id": province_id,
            "game_date": context.get("game_date"),
            "basis": BASIS,
            "partial": True,
            "complete": False,
            "game_fact": False,
            "engine_loaded_rule_verified": False,
            "matched_modifier_keys": list(matched or []),
            "unknown_modifier_keys": list(unknown or []),
            "rule_binding": deepcopy(dict(rule_binding)) if isinstance(rule_binding, Mapping) else None,
            "source": {
                "name": "NativeProvinceEstuaryReader",
                "status": "observed" if status == "known" else status,
                "mode": "live",
                "observer": context.get("observer"),
                "session_id": context.get("session_id"),
                "provenance": {
                    "observer": context.get("observer"),
                    "session_id": context.get("session_id"),
                    "game_date": context.get("game_date"),
                    "province_id": province_id,
                    "read_only": True,
                    "native_function_invoked": False,
                },
            },
        }
        if value is not None and status == "known":
            result["value"] = value
        if reason is not None:
            result["reason"] = _safe_reason(reason)
        if capture_sha256 is not None:
            result["source"]["provenance"]["capture_report_sha256"] = capture_sha256
        return result

    def _failure(
        self, status: str, reason: str, province_id: int, context: Mapping[str, Any],
        rule_binding: Mapping[str, Any] | None, keys: tuple[str, ...] = (),
        *, capture_sha256: str | None = None,
    ) -> dict[str, Any]:
        return self._classification(
            status, province_id, context, rule_binding, reason,
            unknown=list(keys), capture_sha256=capture_sha256,
        )

    def read(self, province_id: int, context: dict[str, Any]) -> dict[str, Any]:
        if type(province_id) is not int or not 1 <= province_id <= MAX_PROVINCE_ID:
            return self._failure(
                "unknown", "PROVINCE_ESTUARY_INVALID_PROVINCE_ID",
                province_id if type(province_id) is int else 0,
                context if isinstance(context, Mapping) else {}, None,
            )
        supplied = deepcopy(context) if isinstance(context, dict) else {}
        initial_rule, keys = self._rule_context()
        if initial_rule is None or keys is None:
            return self._failure(
                "unavailable", "PROVINCE_ESTUARY_RULE_BINDING_INVALID",
                province_id, supplied, initial_rule,
            )
        current_rule_id = _rule_identity(initial_rule)
        if current_rule_id is None:
            return self._failure(
                "unavailable", "PROVINCE_ESTUARY_RULE_BINDING_INVALID",
                province_id, supplied, initial_rule, keys,
            )
        live_reason = self._live_reason(supplied)
        if live_reason:
            return self._failure("unavailable", live_reason, province_id, supplied, initial_rule, keys)
        try:
            before = self.context()
        except Exception:
            return self._failure(
                "unavailable", "PROVINCE_ESTUARY_CONTEXT_UNAVAILABLE",
                province_id, supplied, initial_rule, keys,
            )
        live_reason = self._live_reason(before)
        if live_reason:
            return self._failure("unavailable", live_reason, province_id, before, initial_rule, keys)
        if _identity(supplied) != _identity(before):
            return self._failure(
                "unavailable", "PROVINCE_ESTUARY_CONTEXT_STALE",
                province_id, before, initial_rule, keys,
            )
        installation, creation, binding_reason = _session_binding(self.base_source)
        if binding_reason or installation is None or creation is None:
            return self._failure(
                "unavailable", binding_reason or "PROVINCE_ESTUARY_SESSION_UNAVAILABLE",
                province_id, before, initial_rule, keys,
            )
        try:
            module = import_module(".province_modifiers_capture", __package__)
        except Exception:
            return self._failure(
                "unavailable", "PROVINCE_ESTUARY_CAPTURE_UNAVAILABLE",
                province_id, before, initial_rule, keys,
            )
        capture = self.capture if self.capture is not None else getattr(module, "capture", None)
        if not callable(capture):
            return self._failure(
                "unavailable", "PROVINCE_ESTUARY_CAPTURE_UNAVAILABLE",
                province_id, before, initial_rule, keys,
            )
        report = None
        try:
            report = capture(installation, province_id=province_id, keys=keys, observer=before["observer"])
        except Exception:
            pass
        try:
            after = self.context()
        except Exception:
            after = {}
        live_reason = self._live_reason(after)
        if live_reason or _identity(before) != _identity(after):
            return self._failure(
                "unavailable", live_reason or "PROVINCE_ESTUARY_CONTEXT_CHANGED_DURING_CAPTURE",
                province_id, before, initial_rule, keys,
            )
        final_installation, final_creation, final_reason = _session_binding(self.base_source)
        if (final_reason or final_installation != installation or final_creation != creation):
            return self._failure(
                "unavailable", "PROVINCE_ESTUARY_SESSION_CHANGED_DURING_CAPTURE",
                province_id, before, initial_rule, keys,
            )
        final_rule, final_keys = self._rule_context()
        if (final_rule is None or final_keys != keys
                or _rule_identity(final_rule) != current_rule_id):
            return self._failure(
                "unavailable", "PROVINCE_ESTUARY_RULE_CHANGED_DURING_CAPTURE",
                province_id, before, initial_rule, keys,
            )
        if report is None:
            return self._failure(
                "unknown", "PROVINCE_ESTUARY_CAPTURE_FAILED",
                province_id, before, initial_rule, keys,
            )
        try:
            target, inner, envelope_reason = _capture_target(report, before, province_id, keys)
        except Exception:
            target, inner, envelope_reason = None, None, "PROVINCE_ESTUARY_CAPTURE_UNVERIFIED"
        if target is None or inner is None:
            return self._failure(
                "unknown", envelope_reason or "PROVINCE_ESTUARY_CAPTURE_UNVERIFIED",
                province_id, before, initial_rule, keys,
            )
        try:
            valid = module.validate_capture(report, before, creation, province_id, keys)
        except Exception:
            valid = False
        if valid is not True:
            return self._failure(
                "unknown", "PROVINCE_ESTUARY_CAPTURE_INVALID",
                province_id, before, initial_rule, keys,
            )
        try:
            capture_sha256 = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
        except Exception:
            return self._failure(
                "unknown", "PROVINCE_ESTUARY_CAPTURE_INVALID",
                province_id, before, initial_rule, keys,
            )
        fields = target["fields"]
        predicates, unknown_keys = _typed_predicates(fields[FIELD_PREDICATES], keys)
        if predicates is None:
            return self._classification(
                "unknown", province_id, before, initial_rule,
                "PROVINCE_ESTUARY_PREDICATES_INVALID", unknown=unknown_keys,
                capture_sha256=capture_sha256,
            )
        matched = [key for key in keys if predicates.get(key) is True]
        unknown_set = set(unknown_keys)
        if matched:
            return self._classification(
                "known", province_id, before, initial_rule,
                value=True, matched=matched, unknown=unknown_keys,
                capture_sha256=capture_sha256,
            )
        if not unknown_set and all(predicates.get(key) is False for key in keys):
            return self._classification(
                "known", province_id, before, initial_rule,
                value=False, matched=[], unknown=[], capture_sha256=capture_sha256,
            )
        return self._classification(
            "unknown", province_id, before, initial_rule,
            "PROVINCE_ESTUARY_PREDICATE_UNKNOWN", matched=[], unknown=unknown_keys,
            capture_sha256=capture_sha256,
        )


__all__ = ["BASIS", "FIELD_PREDICATES", "NativeProvinceEstuaryReader"]
