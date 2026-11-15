"""Expose a partial, validated public projection of selected F01 country fields.

Capture/session ownership and raw reads live in ``country_scale_capture`` and
the bounded memory leaves. This adapter exposes five narrow values and keeps
the logical FRA observer separate from the physical client country.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib import import_module
from collections.abc import Mapping
import re

from .model import InformationError, canonical
from .observation_time import dates_match
from .sources import _result, _source_info
from .trade_income import (
    NativeTradeIncomeSource,
    _context_reason as _base_context_reason,
    _identity,
    _session_binding,
)


_TAG = re.compile(r"[A-Z0-9]{3}\Z")
_REASON = re.compile(r"[A-Z0-9_:-]{1,128}\Z")
_WAR_ID = re.compile(r"war_([0-9a-f]{16})_([0-9a-f]{8})\Z")
_POINTER_LIKE = re.compile(r"0x[0-9a-fA-F]{6,}")
_TOPIC = "F01"
_OBSERVER = "FRA"
_VERSION = "1.37.4"
_SCHEMA = "information.country_scale_capture.v1"

_FIELD_IDS = {
    "development": "F01.development",
    "territory": "F01.territory",
    "subject_scale": "F01.subject_scale",
    "major_power": "F01.major_power",
    "wars": "F01.wars",
}
_BACKEND_FIELDS = {name: field_id for name, field_id in _FIELD_IDS.items()}
_SPECS = {
    "development": {
        "unit": "development_raw",
        "scale": 1000,
        "basis": "native_country_own_development_cache",
        "value_origin": "copied_country_development_i32_cache",
        "gaps": [
            "FULL_DEVELOPMENT_TOOLTIP_NOT_CAPTURED",
            "NONATOMIC_READ_AND_CACHE_FRESHNESS",
            "COUNTRY_ADMISSION_IS_EXPORT_BOUNDARY_NOT_WIDGET_VISIBILITY",
        ],
    },
    "territory": {
        "unit": "native_city_count",
        "scale": 1,
        "basis": "bounded_country_num_of_cities_cache_i32",
        "value_origin": "bounded_country_num_of_cities_cache_i32",
        "gaps": [
            "COMPLETE_OWNED_PROVINCE_COUNT_AND_LIST_NOT_CONNECTED",
            "SCRIPT_NUM_OF_CITIES_GETTER_AND_COUNTRY_SCOPE_ABI_STATIC_ONLY",
            "ACTUAL_UI_NOT_OBSERVED",
            "CITY_COUNT_CACHE_FRESHNESS_NOT_GUARANTEED",
            "COUNTRY_ADMISSION_IS_EXPORT_BOUNDARY_NOT_WIDGET_VISIBILITY",
        ],
    },
    "subject_scale": {
        "unit": "weighted_development_raw",
        "scale": 1000,
        "basis": "native_subject_vector_weighted_development",
        "value_origin": "bounded_native_subject_vector_projection",
        "gaps": [
            "SUBJECT_VECTOR_IS_NOT_PROVEN_COMPLETE_FOR_ALL_DEPENDENCIES",
            "SUBJECT_RELATION_FILTERS_AND_WEIGHTING_ARE_PARTIAL",
            "NONATOMIC_READ_AND_CACHE_FRESHNESS",
            "COUNTRY_ADMISSION_IS_EXPORT_BOUNDARY_NOT_WIDGET_VISIBILITY",
        ],
    },
    "major_power": {
        "unit": "native_great_power_feature_flag",
        "scale": 1,
        "basis": "bounded_great_power_feature_predicate_inputs",
        "value_origin": "native_great_power_glow_eligibility_projection",
        "gaps": [
            "FEATURE_FLAG_IS_NOT_GREAT_POWER_RANK_MEMBERSHIP",
            "NEGATIVE_TLS_BRANCH_REMAINS_UNKNOWN",
            "ACTUAL_UI_RENDERING_NOT_OBSERVED",
            "COUNTRY_ADMISSION_IS_EXPORT_BOUNDARY_NOT_WIDGET_VISIBILITY",
        ],
    },
    "wars": {
        "unit": "native_country_wars",
        "scale": 1,
        "basis": "current_country_war_index_and_side_vector_projection",
        "value_origin": "current_country_war_index_and_side_vector_projection",
        "gaps": [
            "CURRENT_OPPONENT_INDEX_IS_NOT_GLOBAL_WAR_MEMBERSHIP",
            "OBSERVER_SESSION_REGISTRY_POINTER_MATCH_DOES_NOT_VERIFY_LIFETIME",
            "SIDE_A_AND_SIDE_B_ARE_NOT_ATTACK_AND_DEFEND_ROLES",
            "COUNTRY_ADMISSION_IS_EXPORT_BOUNDARY_NOT_WIDGET_VISIBILITY",
            "COUNTRY_ADMISSION_REDACTS_UNVERIFIED_MEMBER_IDENTITIES",
            "ACTUAL_UI_AND_COMPLETE_VISIBILITY_NOT_OBSERVED",
        ],
    },
}
_SUBJECT_KEYS = {
    "reference_count",
    "included_count",
    "excluded_count",
    "weighted_development_raw",
    "development_scale",
    "weight_raw",
    "weight_scale",
}
_I32_MIN = -(1 << 31)
_I32_MAX = (1 << 31) - 1
_MAX_SUBJECTS = 256


class NativeCountryScaleSource(NativeTradeIncomeSource):
    """Project selected F01 scale, city-count, and current-war-index fields."""

    event_types: tuple[str, ...] = ()

    def catalog(self) -> list[dict]:
        fields = {}
        for name, field_id in _FIELD_IDS.items():
            spec = _SPECS[name]
            fields[name] = {
                "coverage": "partial",
                "complete": False,
                "source": "bridge.information.country_scale_capture.capture",
                "unit": spec["unit"],
                "scale": spec["scale"],
                "period": "current",
                "basis": spec["basis"],
                "value_origin": spec["value_origin"],
                "paths": [f"observation.backend.targets[0].fields['{field_id}']"],
                "supported_observers": [_OBSERVER],
                "runtime_validation": "country_scale_capture.validate_capture",
                "gaps": list(spec["gaps"]),
            }
        fields["development"]["raw_semantics"] = (
            "signed native country development cache in thousandths; it is not a full tooltip"
        )
        fields["development"]["paths"] = [
            "observation.backend.targets[0].fields['F01.development'].value"
        ]
        fields["territory"].update({
            "raw_semantics": (
                "country-scope num_of_cities signed cache integer only; this is not a complete "
                "owned-province count or list, and the script multiplier is not a displayed-value claim"
            ),
            "paths": [
                "observation.backend.targets[0].fields['F01.territory'].value.city_count"
            ],
        })
        fields["subject_scale"].update({
            "raw_semantics": (
                "bounded native subject-vector weighted-development projection; counts and both "
                "raw scales are preserved, but the vector is not proven to cover every dependency"
            ),
            "paths": [
                f"observation.backend.targets[0].fields['F01.subject_scale'].value.{key}"
                for key in (
                    "reference_count", "included_count", "excluded_count",
                    "weighted_development_raw", "development_scale", "weight_raw", "weight_scale",
                )
            ],
        })
        fields["major_power"]["raw_semantics"] = (
            "partial native great-power glow eligibility predicate only, not great-power ranking"
        )
        fields["major_power"]["paths"] = [
            "observation.backend.targets[0].fields['F01.major_power'].value"
        ]
        fields["wars"].update({
            "raw_semantics": (
                "current country opponent-index and side-vector projection only; it is not a global "
                "war census, war lifetime proof, attack/defend role assignment, or observed UI"
            ),
            "paths": [
                "observation.backend.targets[0].fields['F01.wars'].value.at_war",
                "observation.backend.targets[0].fields['F01.wars'].value.war_count",
                "observation.backend.targets[0].fields['F01.wars'].value.wars",
            ],
        })
        return [{
            "topic_id": _TOPIC,
            "catalog_ids": [_TOPIC],
            "title": "外国实力规模",
            "status": "available",
            "fields": fields,
            "object_types": ["country"],
            "observer_roles": [],
            "observer_scope": [_OBSERVER],
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            "supported_versions": [_VERSION],
            "triggers": ["query", "periodic"],
            "source": type(self).__name__,
            "context_scope": "visible_scope",
            "visibility": "visible_scope",
            "scope_note": (
                "仅支持 development、territory、subject_scale、major_power、wars 五个部分字段；"
                "territory限于country-scope num_of_cities缓存值，不是完整owned-province数量或列表；"
                "FRA是逻辑观察方，"
                "country对象可为FRA或其他国家，物理客户端身份不会替换。major_power只反映已证"
                "明的glow功能条件，不等于完整列强排名；未闭合TLS分支返回unknown，实际UI未观察。"
                "pass2 country admission只作为保守export boundary，不证明每个native widget可见；"
                "wars仅投影当前country opponent index和side vectors；每个成员按FRA country-view gate保守redact，"
                "未验证成员不公开TAG。side_a/side_b不是进攻/防守角色，observer_session war_id不证明对象生命周期，"
                "不代表全球战争清单或实际UI可见性。"
            ),
        }]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "query must be an object")
        allowed = {"topic", "object", "fields", "parameters"}
        missing = {"topic", "object", "fields"} - set(query)
        extra = set(query) - allowed
        if missing or extra:
            raise InformationError(
                "invalid_parameters",
                f"F01 query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        if query.get("topic") != _TOPIC:
            raise InformationError("unknown_topic", "NativeCountryScaleSource supports F01 only")
        obj = query.get("object")
        if (
            not isinstance(obj, dict)
            or set(obj) != {"type", "country"}
            or obj.get("type") != "country"
            or not isinstance(obj.get("country"), str)
            or _TAG.fullmatch(obj["country"]) is None
        ):
            raise InformationError("invalid_object", "F01 requires one three-character country tag")
        fields = query.get("fields")
        if (
            not isinstance(fields, list)
            or not fields
            or len(fields) > len(_FIELD_IDS)
            or any(not isinstance(field, str) or field not in _FIELD_IDS for field in fields)
            or len(set(fields)) != len(fields)
        ):
            raise InformationError(
                "invalid_fields", "F01 supports development, territory, subject_scale, major_power, and wars only"
            )
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict) or parameters:
            raise InformationError("invalid_parameters", "F01 has no extra parameters")
        if context is not None and (
            not isinstance(context, dict) or context.get("observer") != _OBSERVER
        ):
            raise InformationError("observer_scope_mismatch", "The verified logical observer is FRA")
        return {
            "topic": _TOPIC,
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": {},
        }

    @staticmethod
    def _context_reason(context: dict) -> str | None:
        reason = _base_context_reason(context, _OBSERVER)
        return reason.replace("TRADE_INCOME_", "COUNTRY_SCALE_", 1) if reason else None

    @staticmethod
    def _safe_reason(value: object, fallback: str) -> str:
        if isinstance(value, str) and _POINTER_LIKE.search(value) is None:
            bounded = value[:128]
            if _REASON.fullmatch(bounded) is not None:
                return bounded
        return fallback

    @staticmethod
    def _field(name: str, status: str, reason: str | None = None, value: object = None) -> dict:
        spec = _SPECS[name]
        item = {
            "status": status,
            "period": "current",
            "basis": spec["basis"],
            "value_origin": spec["value_origin"],
            "partial": True,
            "complete": False,
        }
        if name in {"territory", "wars"}:
            item.update({
                "unit": spec["unit"],
                "scale": spec["scale"],
                "gaps": list(spec["gaps"]),
            })
        if reason is not None:
            item["reason"] = reason
        if status == "known" and value is not None:
            item["value"] = value
        return item

    @classmethod
    def _project_value(cls, name: str, field: Any) -> dict:
        invalid = lambda: cls._field(name, "unknown", "COUNTRY_SCALE_FIELD_INVALID")
        if not isinstance(field, Mapping):
            return invalid()
        status = field.get("status")
        if status == "invisible":
            reason = cls._safe_reason(field.get("reason"), "COUNTRY_SCALE_NOT_ADMITTED_FOR_OBSERVER")
            return cls._field(name, "invisible", reason)
        if status == "unknown":
            reason = cls._safe_reason(field.get("reason"), "COUNTRY_SCALE_BACKEND_UNKNOWN")
            return cls._field(name, "unknown", reason)
        if status != "known":
            return invalid()

        value = field.get("value")
        if name == "development":
            if (
                type(value) is not int
                or not _I32_MIN <= value <= _I32_MAX
                or field.get("unit") != "development_raw"
                or type(field.get("scale")) is not int
                or field.get("scale") != 1000
            ):
                return invalid()
            return cls._field(name, "known", value=value)
        if name == "territory":
            if (
                not isinstance(value, Mapping)
                or set(value) != {"city_count"}
                or type(value.get("city_count")) is not int
                or not 0 <= value["city_count"] <= 65535
                or field.get("unit") != "native_city_count"
                or type(field.get("scale")) is not int
                or field.get("scale") != 1
                or field.get("basis") != "bounded_country_num_of_cities_cache_i32"
                or field.get("partial") is not True
                or field.get("complete") is not False
            ):
                return invalid()
            return cls._field(name, "known", value={"city_count": value["city_count"]})
        if name == "subject_scale":
            if not isinstance(value, Mapping) or set(value) != _SUBJECT_KEYS:
                return invalid()
            reference = value.get("reference_count")
            included = value.get("included_count")
            excluded = value.get("excluded_count")
            weighted = value.get("weighted_development_raw")
            development_scale = value.get("development_scale")
            weight = value.get("weight_raw")
            weight_scale = value.get("weight_scale")
            if (
                any(type(count) is not int or count < 0 for count in (reference, included, excluded))
                or reference > _MAX_SUBJECTS
                or included + excluded != reference
                or type(weighted) is not int or not _I32_MIN <= weighted <= _I32_MAX
                or type(development_scale) is not int or development_scale != 1000
                or type(weight) is not int or not _I32_MIN <= weight <= _I32_MAX
                or type(weight_scale) is not int or weight_scale != 1000
            ):
                return invalid()
            public_value = {
                "reference_count": reference,
                "included_count": included,
                "excluded_count": excluded,
                "weighted_development_raw": weighted,
                "development_scale": development_scale,
                "weight_raw": weight,
                "weight_scale": weight_scale,
            }
            return cls._field(name, "known", value=public_value)
        if name == "major_power":
            if type(value) is not bool:
                return invalid()
            return cls._field(name, "known", value=value)
        if name == "wars":
            return cls._project_wars(field, invalid)
        return invalid()

    @classmethod
    def _project_wars(cls, field: Mapping[str, Any], invalid) -> dict:
        value = field.get("value")
        expected_value_keys = {
            "at_war", "war_count", "wars", "enumeration_scope",
            "global_membership_verified", "lifetime_verified",
        }
        if (not isinstance(value, Mapping) or set(value) != expected_value_keys
                or type(value.get("at_war")) is not bool
                or type(value.get("war_count")) is not int
                or not 0 <= value["war_count"] <= 32
                or not isinstance(value.get("wars"), list)
                or value["war_count"] != len(value["wars"])
                or value.get("at_war") is not (value["war_count"] > 0)
                or value.get("enumeration_scope") != "current_country_opponent_index"
                or value.get("global_membership_verified") is not False
                or value.get("lifetime_verified") is not False
                or field.get("unit") != "native_country_wars"
                or type(field.get("scale")) is not int or field.get("scale") != 1
                or field.get("basis") != "current_country_war_index_and_side_vector_projection"
                or field.get("partial") is not True or field.get("complete") is not False):
            return invalid()

        projected_wars = []
        known_ids = set()

        def project_side(members, seen_tags):
            if not isinstance(members, list) or not 1 <= len(members) <= 256:
                raise ValueError("war_side_shape")
            output = []
            for member in members:
                if not isinstance(member, Mapping):
                    raise ValueError("war_member_shape")
                status = member.get("status")
                if status == "known":
                    if set(member) != {"status", "country"}:
                        raise ValueError("war_member_known_keys")
                    country = member.get("country")
                    if not isinstance(country, str) or _TAG.fullmatch(country) is None:
                        raise ValueError("war_member_tag")
                    if country in seen_tags:
                        raise ValueError("war_member_duplicate_tag")
                    seen_tags.add(country)
                    output.append({"status": "known", "country": country})
                elif status in {"unknown", "invisible"}:
                    if (set(member) != {"status", "reason"}
                            or not isinstance(member.get("reason"), str)
                            or _REASON.fullmatch(member["reason"]) is None):
                        raise ValueError("war_member_redaction")
                    output.append({"status": status, "reason": member["reason"]})
                else:
                    raise ValueError("war_member_status")
            return output

        try:
            for war in value["wars"]:
                expected_war_keys = {
                    "war_id", "target_side", "side_a", "side_b",
                    "membership_complete", "identities_complete", "roles_verified",
                }
                if (not isinstance(war, Mapping) or set(war) != expected_war_keys
                        or war.get("target_side") not in {"side_a", "side_b"}
                        or war.get("membership_complete") is not True
                        or type(war.get("identities_complete")) is not bool
                        or war.get("roles_verified") is not False):
                    raise ValueError("war_shape")
                seen_tags = set()
                side_a = project_side(war.get("side_a"), seen_tags)
                side_b = project_side(war.get("side_b"), seen_tags)
                identities_complete = all(
                    member["status"] == "known" for member in (*side_a, *side_b)
                )
                if war["identities_complete"] is not identities_complete:
                    raise ValueError("war_identity_completeness")

                identity = war.get("war_id")
                if not isinstance(identity, Mapping):
                    raise ValueError("war_id_shape")
                identity_status = identity.get("status")
                if identity_status == "known":
                    if (set(identity) != {"status", "value", "identity_scope", "lifetime_verified"}
                            or identity.get("identity_scope") != "observer_session"
                            or identity.get("lifetime_verified") is not False):
                        raise ValueError("war_id_known_metadata")
                    war_id = identity.get("value")
                    match = _WAR_ID.fullmatch(war_id) if isinstance(war_id, str) else None
                    if match is None or not 1 <= int(match.group(2), 16) <= 256:
                        raise ValueError("war_id_format_or_serial")
                    if war_id in known_ids:
                        raise ValueError("war_id_duplicate")
                    known_ids.add(war_id)
                    projected_id = {
                        "status": "known", "value": war_id,
                        "identity_scope": "observer_session", "lifetime_verified": False,
                    }
                elif identity_status == "unknown":
                    if (set(identity) != {"status", "reason"}
                            or not isinstance(identity.get("reason"), str)
                            or _REASON.fullmatch(identity["reason"]) is None):
                        raise ValueError("war_id_unknown_metadata")
                    projected_id = {"status": "unknown", "reason": identity["reason"]}
                else:
                    raise ValueError("war_id_status")

                projected_wars.append({
                    "war_id": projected_id,
                    "target_side": war["target_side"],
                    "side_a": side_a,
                    "side_b": side_b,
                    "membership_complete": True,
                    "identities_complete": identities_complete,
                    "roles_verified": False,
                })
        except (KeyError, TypeError, ValueError):
            return invalid()

        public_value = {
            "at_war": value["at_war"],
            "war_count": value["war_count"],
            "wars": projected_wars,
            "enumeration_scope": "current_country_opponent_index",
            "global_membership_verified": False,
            "lifetime_verified": False,
        }
        return cls._field("wars", "known", value=public_value)

    def read(self, query: dict, context: dict | None = None) -> dict:
        current = deepcopy(context) if isinstance(context, dict) else self.context()
        normalized = self.validate_query(query, current)
        target = normalized["object"]["country"]
        provenance = {
            "read_only": True,
            "native_function_invoked": False,
            "observer": _OBSERVER,
            "target": target,
            "basis": "validated_partial_foreign_country_scale_projection",
            "actual_UI_observed": False,
            "ranking_membership_observed": False,
            "physical_client_country": current.get("physical_client_country"),
        }

        def result(fields: dict, result_context: dict = current) -> dict:
            source = _source_info(
                type(self).__name__, result_context, complete=False,
                provenance=deepcopy(provenance),
            )
            source["context_scope"] = "visible_scope"
            source["projection_version"] = 3
            return _result(normalized, result_context, fields, False, source)

        def failure(reason: str, *, unavailable: bool = False,
                    result_context: dict = current) -> dict:
            status = "unavailable" if unavailable else "unknown"
            return result({
                name: self._field(name, status, reason)
                for name in normalized["fields"]
            }, result_context)

        reason = self._context_reason(current)
        if reason is not None:
            return failure(reason, unavailable=True)
        try:
            before = self.context()
        except Exception:
            return failure("COUNTRY_SCALE_CONTEXT_UNAVAILABLE", unavailable=True)
        before_reason = self._context_reason(before)
        if before_reason is not None:
            return failure(before_reason, unavailable=True, result_context=before)
        if _identity(current) != _identity(before):
            return failure("COUNTRY_SCALE_CONTEXT_STALE", unavailable=True, result_context=before)

        installation, creation_filetime, binding_reason = _session_binding(self.base_source)
        if binding_reason is not None or installation is None or creation_filetime is None:
            return failure(
                binding_reason or "COUNTRY_SCALE_INSTALLATION_UNAVAILABLE",
                unavailable=True,
            )

        try:
            module = import_module(".country_scale_capture", __package__)
        except Exception:
            return failure("COUNTRY_SCALE_CAPTURE_UNAVAILABLE", unavailable=True)
        capture = self.capture if self.capture is not None else getattr(module, "capture", None)
        if not callable(capture):
            return failure("COUNTRY_SCALE_CAPTURE_UNAVAILABLE", unavailable=True)

        report = None
        capture_error: str | None = None
        try:
            report = capture(installation, country=target, observer=_OBSERVER)
        except Exception as exc:
            capture_error = "COUNTRY_SCALE_CAPTURE_FAILED:" + type(exc).__name__

        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = self._context_reason(after)
        if (after_reason is not None or _identity(before) != _identity(after) or
                not dates_match(current.get("game_date"), before.get("game_date"),
                                after.get("game_date"))):
            return failure(
                "COUNTRY_SCALE_CONTEXT_CHANGED_DURING_CAPTURE",
                unavailable=True,
                result_context=before,
            )
        installation_after, creation_after, binding_after_reason = _session_binding(self.base_source)
        if (
            binding_after_reason is not None
            or installation_after != installation
            or creation_after != creation_filetime
        ):
            return failure(
                "COUNTRY_SCALE_SESSION_CHANGED_DURING_CAPTURE",
                unavailable=True,
                result_context=before,
            )
        if capture_error is not None:
            return failure(capture_error, result_context=before)
        try:
            valid = module.validate_capture(report, before, creation_filetime, target)
        except Exception:
            valid = False
        if valid is not True:
            return failure("COUNTRY_SCALE_CAPTURE_INVALID", result_context=before)

        try:
            if not isinstance(report, Mapping) or report.get("schema") != _SCHEMA:
                raise ValueError("capture schema")
            backend = report["observation"]["backend"]
            if not isinstance(backend, Mapping):
                raise ValueError("backend")
            observer = backend["observer"]
            if not isinstance(observer, Mapping) or observer.get("tag") != _OBSERVER:
                raise ValueError("observer")
            targets = backend["targets"]
            if not isinstance(targets, list) or len(targets) != 1:
                raise ValueError("target list")
            item = targets[0]
            if not isinstance(item, Mapping) or item.get("tag") != target:
                raise ValueError("target mismatch")

            provenance["capture_report_sha256"] = hashlib.sha256(
                canonical(report).encode("utf-8")
            ).hexdigest()
            admission_by_pass = item.get("admission_by_pass")
            admission = admission_by_pass.get("pass2") if isinstance(admission_by_pass, Mapping) else None
            if (
                not isinstance(admission, Mapping)
                or admission.get("status") != "known"
                or type(admission.get("admitted")) is not bool
            ):
                reason = self._safe_reason(
                    admission.get("reason") if isinstance(admission, Mapping) else None,
                    "COUNTRY_SCALE_VIEW_ADMISSION_UNKNOWN",
                )
                return result({
                    name: self._field(name, "unknown", reason)
                    for name in normalized["fields"]
                }, before)
            if admission["admitted"] is False:
                return result({
                    name: self._field(name, "invisible", "COUNTRY_SCALE_NOT_ADMITTED_FOR_OBSERVER")
                    for name in normalized["fields"]
                }, before)

            raw_fields = item.get("fields")
            if not isinstance(raw_fields, Mapping):
                raise ValueError("field map")
            projected = {}
            for name in normalized["fields"]:
                projected[name] = self._project_value(name, raw_fields.get(_BACKEND_FIELDS[name]))
            return result(projected, before)
        except (KeyError, TypeError, ValueError, IndexError):
            return failure("COUNTRY_SCALE_CAPTURE_SHAPE_INVALID", result_context=before)


__all__ = ["NativeCountryScaleSource"]
