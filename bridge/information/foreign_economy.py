"""Public F03 foreign economy source with independent contract scopes.

Principal totals, observer-lent loans, income and fiscal relations use one
identity-bound memory capture. A requested total also requires a fresh native
UI-selector query bound to the same session and date. Bankruptcy risk remains
planned. Private fields and query evidence are never exposed publicly.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
import re
from typing import Any, Mapping

from . import foreign_economy_projection_v7 as _projection
from .model import InformationError, canonical
from .sources import _result, _source_info
from .trade_income import NativeTradeIncomeSource, _identity, _observer_context_reason, _session_binding

_TAG = re.compile(r"[A-Z0-9]{3}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_CAPTURE_SCHEMA = "information.foreign_economy_capture.v4"
_CAPTURE_MODULE = ".foreign_economy_capture_v7"
_RISK_REASON = "NATIVE_BANKRUPTCY_RISK_AND_FOREIGN_VISIBILITY_NOT_ESTABLISHED"
_PUBLIC_TO_PRIVATE = {
    "income": "F03.income",
    "debt": "F03.debt",
    "reparations": "F03.reparations",
    "subsidies": "F03.subsidies",
}


def _reason(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", value) else fallback


class NativeForeignEconomySource(NativeTradeIncomeSource):
    """Expose the supported foreign economy pages within the configured observer view."""

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source: Any, *, capture=None):
        super().__init__(base_source, capture=capture)

    def catalog(self) -> list[dict[str, Any]]:
        common = {
            "supported_versions": ["1.37.4"],
            "supported_observers": [],
            "supported_object_types": ["country"],
            "source": "bridge.information.foreign_economy_capture_v7.capture",
            "complete": False,
        }
        fields = {
            "income": {**deepcopy(common), "coverage": "partial", "unit": "ducats",
                "scale": 1000, "raw": True, "period": "month", "reference": "previous_month",
                "basis": "native_country_income_comparison_cache",
                "paths": ["observation.backend.targets[0].fields.F03.income.value"],
                "runtime_validation": "pinned_native_cache_and_page_conditions",
                "description": "目标国家上一月原生收入总额和已证实展示类别；总额按原生公式计算，不保证等于可见类别之和",
                "gaps": ["ACTUAL_UI_RENDER_NOT_OBSERVED", "CACHE_FRESHNESS_NOT_PROVEN",
                         "VISIBLE_CATEGORY_SUM_EQUALITY_NOT_ESTABLISHED"]},
            "debt": {**deepcopy(common), "coverage": "partial", "unit": "debt_information",
                "scale": 1, "raw": True, "period": "current",
                "basis": "native_debt_independent_scopes",
                "paths": ["observation.backend.targets[0].fields.F03.target_debt_principal.value.diplomatic_principal_total",
                          "observation.backend.targets[0].fields.F03.debt.value.loans_to_observer"],
                "components": {
                    "total_debt": {"unit": "ducats", "scale": 1000, "period": "current",
                                   "scope": "native_ai_accept_principal_amount",
                                   "includes_remaining_interest": False},
                    "loans_to_observer": {"unit": "observed_loan_records", "scale": 1,
                                          "period": "current", "scope": "observer_lent_loans_only"}},
                "runtime_validation": "pinned_native_principal_and_independent_disclosure_scopes",
                "description": "分别提供原生外交理由使用的目标贷款总本金与FRA放贷子集；总本金不含剩余利息，两项分别验证可见范围",
                "gaps": ["ACTUAL_UI_RENDER_NOT_OBSERVED", "REMAINING_INTEREST_NOT_INCLUDED",
                         "LOAN_LIST_COMPLETENESS_NOT_ESTABLISHED"]},
            "bankruptcy_risk": {**deepcopy(common), "coverage": "planned",
                "runtime_validation": "not_implemented",
                "description": "尚无已验证的外国破产风险字段来源",
                "gaps": ["NATIVE_BANKRUPTCY_RISK_AND_FOREIGN_VISIBILITY_NOT_ESTABLISHED"]},
            "reparations": {**deepcopy(common), "coverage": "partial",
                "unit": "reparations_information", "scale": 1, "raw": False,
                "period": "mixed", "basis": "native_reparations_independent_scopes",
                "paths": [
                    "observation.backend.targets[0].fields.F03.reparations.value.received_previous_month",
                    "observation.backend.targets[0].fields.F03.reparations.value.observer_involved_contracts"],
                "components": {
                    "received_previous_month": {
                        "unit": "ducats", "scale": 1000, "period": "month",
                        "reference": "previous_month", "scope": "income_page"},
                    "observer_involved_contracts": {
                        "unit": "bilateral_reparations_relation", "scale": 1,
                        "period": "current",
                        "scope": "observer_economy_bilateral_reparations"}},
                "runtime_validation": "pinned_native_cache_and_independent_pair_scope",
                "description": "分别提供上一月赔款收入与FRA参与的当前双边关系；关系子项只覆盖观察方参与的国家对，不代表目标全部合同",
                "gaps": ["CURRENT_PAYMENT_OBLIGATIONS_NOT_CAPTURED",
                         "TARGET_COMPLETE_ACTIVE_CONTRACTS_NOT_ESTABLISHED",
                         "PAYMENT_AMOUNT_OR_PERCENTAGE_NOT_CAPTURED",
                         "ACTUAL_UI_RENDER_NOT_OBSERVED"]},
            "subsidies": {**deepcopy(common), "coverage": "partial",
                "unit": "subsidies_information", "scale": 1, "raw": False,
                "period": "mixed", "basis": "native_subsidies_independent_scopes",
                "paths": [
                    "observation.backend.targets[0].fields.F03.subsidies.value.received_previous_month",
                    "observation.backend.targets[0].fields.F03.subsidies.value.observer_involved_contracts"],
                "components": {
                    "received_previous_month": {
                        "unit": "ducats", "scale": 1000, "period": "month",
                        "reference": "previous_month", "scope": "income_page"},
                    "observer_involved_contracts": {
                        "unit": "bilateral_subsidies_relation", "scale": 1,
                        "period": "current",
                        "scope": "observer_fiscal_bilateral_subsidies"}},
                "runtime_validation": "pinned_native_cache_and_independent_pair_scope",
                "description": "分别提供上一月补贴收入与FRA参与的当前双边关系；关系子项只覆盖观察方参与的国家对，不代表目标全部合同",
                "gaps": ["CURRENT_PAYMENT_OBLIGATIONS_NOT_CAPTURED",
                         "TARGET_COMPLETE_ACTIVE_CONTRACTS_NOT_ESTABLISHED",
                         "SUBSIDY_TERM_LEGALITY_NOT_ESTABLISHED",
                         "ACTUAL_UI_RENDER_NOT_OBSERVED"]},
        }
        return [{
            "topic_id": _projection.TOPIC,
            "catalog_ids": [_projection.TOPIC],
            "title": "外国国家收入、债务与财政义务",
            "status": "available",
            "fields": fields,
            "object_types": ["country"],
            "observer_roles": [],
            "observer_scope": [],
            "parameters": {"type": "object", "properties": {}, "required": [],
                            "additionalProperties": False},
            "supported_versions": ["1.37.4"],
            "supported_observers": [],
            "triggers": ["query", "periodic"],
            "source": type(self).__name__,
            "context_scope": "visible_scope",
            "visibility": "visible_scope",
            "scope_note": "按逻辑FRA观察方分别验证收入页、借贷页、原生外交债务理由和FRA自身双边财政关系范围；物理客户端国家不替代FRA，实际渲染未观察",
        }]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "F03 query must be an object")
        allowed = {"topic", "object", "fields", "parameters"}
        missing = {"topic", "object", "fields"} - set(query)
        extra = set(query) - allowed
        if missing or extra:
            raise InformationError("invalid_parameters",
                f"F03 query: missing={sorted(missing)}, unknown={sorted(extra)}")
        if query.get("topic") != _projection.TOPIC:
            raise InformationError("unknown_topic", "NativeForeignEconomySource supports F03 only")
        obj = query.get("object")
        if (not isinstance(obj, dict) or set(obj) != {"type", "country"}
                or obj.get("type") != "country" or not isinstance(obj.get("country"), str)
                or not _TAG.fullmatch(obj["country"])):
            raise InformationError("invalid_object", "F03 requires a three-character country object")
        if context is not None and not isinstance(context, dict):
            raise InformationError("invalid_context", "The F03 context must be an object")
        if isinstance(context, dict) and obj["country"] == context.get("observer"):
            raise InformationError("invalid_object", "Use N01 for the configured observer economy")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields or len(fields) > len(_projection.PUBLIC_FIELDS)
                or any(not isinstance(field, str) or field not in _projection.PUBLIC_FIELDS for field in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError("invalid_fields", "F03 fields must be a non-empty unique subset of its five public fields")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "F03 has no extra parameters")
        normalized = {"topic": _projection.TOPIC, "object": deepcopy(obj),
                      "fields": list(fields), "parameters": {}}
        canonical(normalized)
        return normalized

    @staticmethod
    def _result(normalized: dict[str, Any], context: dict[str, Any],
                fields: dict[str, dict[str, Any]], provenance: dict[str, Any]) -> dict[str, Any]:
        source = _source_info("NativeForeignEconomySource", context,
                              complete=False, provenance=deepcopy(provenance))
        source["context_scope"] = "visible_scope"
        source["projection_version"] = 4
        return _result(normalized, context, fields, False, source)

    def read(self, query: dict, context: dict | None = None) -> dict[str, Any]:
        supplied = deepcopy(context) if isinstance(context, dict) else None
        try:
            current = supplied if supplied is not None else self.context()
        except Exception:
            current = {}
        normalized = self.validate_query(query, current)
        target = normalized["object"]["country"]
        requested = normalized["fields"]
        provenance: dict[str, Any] = {
            "read_only": True,
            "native_function_invoked": False,
            "native_debt_visibility_queries": 0,
            "observer": current.get("observer"),
            "target": target,
            "actual_UI_observed": False,
            "capture_report_sha256_by_source": {},
        }

        def result(fields: dict[str, dict[str, Any]]) -> dict[str, Any]:
            return self._result(normalized, current, fields, provenance)

        def fail(reason: str) -> dict[str, Any]:
            fields = {name: _projection.failure_field(name, reason)
                      for name in requested_financial}
            if "bankruptcy_risk" in requested:
                fields["bankruptcy_risk"] = _projection.failure_field(
                    "bankruptcy_risk", _RISK_REASON)
            return result(fields)

        # Bankruptcy risk remains planned and does not trigger a capture.
        requested_financial = [name for name in requested if name != "bankruptcy_risk"]
        if not requested_financial:
            return result({"bankruptcy_risk": _projection.failure_field(
                "bankruptcy_risk", _RISK_REASON)})

        reason = _observer_context_reason(current)
        if reason is not None:
            return fail("FOREIGN_ECONOMY_CONTEXT_UNAVAILABLE")
        try:
            before = self.context()
        except Exception:
            before = {}
        before_reason = _observer_context_reason(before)
        if before_reason is not None:
            return fail("FOREIGN_ECONOMY_CONTEXT_UNAVAILABLE")
        if _identity(current) != _identity(before):
            return fail("FOREIGN_ECONOMY_CONTEXT_STALE")

        installation, creation, session_error = _session_binding(self.base_source)
        if session_error is not None or installation is None or creation is None:
            provenance["capture_failures"] = {"economy": "FOREIGN_ECONOMY_SESSION_UNAVAILABLE"}
            return fail("FOREIGN_ECONOMY_SESSION_UNAVAILABLE")

        try:
            module = import_module(_CAPTURE_MODULE, __package__)
            validate = getattr(module, "validate_capture", None)
            capture = self.capture if self.capture is not None else getattr(module, "capture", None)
            schema = getattr(module, "SCHEMA", None)
            profile_sha = getattr(module, "PROFILE_SHA256", None)
            exe_sha = getattr(module, "EXE_SHA256", None)
            if (schema != _CAPTURE_SCHEMA or not callable(validate) or not callable(capture)
                    or not isinstance(profile_sha, str) or not _SHA256.fullmatch(profile_sha)
                    or not isinstance(exe_sha, str) or not _SHA256.fullmatch(exe_sha)):
                raise ValueError("FOREIGN_ECONOMY_CAPTURE_MODULE_CONTRACT")
        except Exception:
            provenance["capture_failures"] = {"economy": "FOREIGN_ECONOMY_CAPTURE_UNAVAILABLE"}
            return fail("FOREIGN_ECONOMY_CAPTURE_UNAVAILABLE")

        try:
            call_before = self.context()
        except Exception:
            call_before = {}
        if (_observer_context_reason(call_before) is not None
                or _identity(call_before) != _identity(before)):
            return fail("FOREIGN_ECONOMY_CONTEXT_STALE")

        report = None
        capture_error = None
        try:
            report = capture(installation, country=target, observer=before["observer"])
        except Exception:
            capture_error = "FOREIGN_ECONOMY_CAPTURE_FAILED"
        try:
            call_after = self.context()
        except Exception:
            call_after = {}
        if (_observer_context_reason(call_after) is not None
                or _identity(call_after) != _identity(call_before)
                or _identity(call_after) != _identity(before)):
            provenance["capture_failures"] = {"economy": "FOREIGN_ECONOMY_CONTEXT_CHANGED_DURING_CAPTURE"}
            return fail("FOREIGN_ECONOMY_CONTEXT_CHANGED_DURING_CAPTURE")
        if capture_error is not None:
            provenance["capture_failures"] = {"economy": capture_error}
            return fail(capture_error)

        request = report.get("request") if isinstance(report, Mapping) else None
        identity = report.get("identity") if isinstance(report, Mapping) else None
        identity_after = report.get("identity_after") if isinstance(report, Mapping) else None
        report_reason = None
        try:
            envelope_valid = (
                isinstance(report, Mapping) and report.get("schema") == schema
                and report.get("status") == "observed" and report.get("completed") is True
                and report.get("profile_sha256") == profile_sha
                and isinstance(request, Mapping) and request.get("country") == target
                and request.get("observer") == before["observer"]
                and request.get("session_id") == before.get("session_id")
                and type(request.get("creation_filetime")) is int
                and request.get("creation_filetime") == creation
                and isinstance(identity, Mapping) and identity.get("binding_verified") is True
                and identity.get("installation_session_id") == before.get("session_id")
                and identity.get("installation_creation_filetime") == creation
                and identity.get("process_creation_filetime") == creation
                and identity.get("process_path_sha256") == exe_sha
                and isinstance(identity_after, Mapping)
                and canonical(dict(identity)) == canonical(dict(identity_after)))
        except Exception:
            envelope_valid = False
        if not envelope_valid:
            report_reason = "FOREIGN_ECONOMY_CAPTURE_IDENTITY_INVALID"
        else:
            try:
                if validate(report, call_before, creation, target) is not True:
                    report_reason = "FOREIGN_ECONOMY_CAPTURE_INVALID"
            except Exception:
                report_reason = "FOREIGN_ECONOMY_CAPTURE_INVALID"
        if report_reason is not None:
            provenance["capture_failures"] = {"economy": report_reason}
            return fail(report_reason)

        try:
            digest = hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
        except Exception:
            provenance["capture_failures"] = {"economy": "FOREIGN_ECONOMY_CAPTURE_CANONICAL_INVALID"}
            return fail("FOREIGN_ECONOMY_CAPTURE_CANONICAL_INVALID")
        provenance["capture_report_sha256"] = digest
        provenance["capture_report_sha256_by_source"] = {"economy": digest}

        item = _backend_item(report, target)
        debt_scope = None
        if "debt" in requested_financial and _debt_candidate_ready(item):
            from . import foreign_debt_disclosure as disclosure
            try:
                scope = disclosure.read_scope(self.base_source, call_after, target)
                count = scope.get("native_inspection_calls") if isinstance(scope, Mapping) else None
                if type(count) is int and count in (0, 1):
                    provenance["native_function_invoked"] = count == 1
                    provenance["native_debt_visibility_queries"] = count
                else:
                    provenance["native_function_invoked"] = None
                    provenance["native_debt_visibility_queries"] = None
                if (disclosure.validate_scope(scope)
                        and scope.get("session_id") == before.get("session_id")
                        and type(scope.get("creation_filetime")) is int
                        and scope["creation_filetime"] == creation
                        and type(scope.get("game_date")) is int
                        and scope["game_date"] == before.get("game_date")
                        and scope.get("target") == target
                        and scope.get("observer") == before.get("observer")):
                    debt_scope = scope
                    provenance["debt_disclosure"] = {
                        "status": scope["status"], "admitted": scope["admitted"],
                        "reason": scope["reason"],
                        "proof_sha256": hashlib.sha256(canonical(scope).encode("utf-8")).hexdigest(),
                    }
                else:
                    provenance["debt_disclosure"] = {"status": "unknown", "reason": "DEBT_DISCLOSURE_BINDING_INVALID"}
            except Exception:
                provenance["native_function_invoked"] = None
                provenance["native_debt_visibility_queries"] = None
                provenance["debt_disclosure"] = {"status": "unknown", "reason": "DEBT_DISCLOSURE_READ_FAILED"}
            try:
                disclosure_after = self.context()
            except Exception:
                disclosure_after = {}
            if (_observer_context_reason(disclosure_after) is not None
                    or _identity(disclosure_after) != _identity(call_after)):
                provenance["capture_failures"] = {"economy": "FOREIGN_ECONOMY_CONTEXT_CHANGED_DURING_DISCLOSURE"}
                return fail("FOREIGN_ECONOMY_CONTEXT_CHANGED_DURING_DISCLOSURE")

        fields = _projection.project(item, target, requested_financial, debt_scope=debt_scope,
                                     observer=before["observer"])
        if "bankruptcy_risk" in requested:
            fields["bankruptcy_risk"] = _projection.failure_field(
                "bankruptcy_risk", _RISK_REASON)
        for name in requested:
            fields.setdefault(name, _projection.failure_field(name,
                "FOREIGN_ECONOMY_FIELD_NOT_PROJECTED"))
        return result(fields)


def _debt_candidate_ready(item: Mapping[str, Any]) -> bool:
    view = _projection._country_view(item)
    fields = item.get("fields")
    record = fields.get("F03.target_debt_principal") if isinstance(fields, Mapping) else None
    return (view.get("status") == "known" and view.get("admitted") is True
            and _projection._stable(item, "F03.target_debt_principal")
            and isinstance(record, Mapping) and record.get("status") == "known")


def _backend_item(report: Mapping[str, Any], target: str) -> Mapping[str, Any]:
    observation = report.get("observation")
    backend = observation.get("backend") if isinstance(observation, Mapping) else None
    targets = backend.get("targets") if isinstance(backend, Mapping) else None
    if (not isinstance(targets, list) or len(targets) != 1
            or not isinstance(targets[0], Mapping) or targets[0].get("tag") != target):
        return {}
    return targets[0]


__all__ = ["NativeForeignEconomySource"]
