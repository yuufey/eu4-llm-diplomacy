"""Read-only native country-state projections.

``NativeCountryStateSource`` reuses the already audited diplomacy inspection
entry point for public projections and a separate bounded native capture for
the verified monarch-point field.  The source deliberately exposes only
values that carry an explicit country and unit.  A country-state query
therefore never turns the counterparty fields of a pair inspection into a
second country's private state.
"""

from __future__ import annotations
from . import observation_time as _time

from copy import deepcopy
import hashlib
from pathlib import Path
import re
from typing import Any

from .model import InformationError, canonical
from .sources import _copy, _result, _source_info


_COUNTRY = re.compile(r"[A-Z0-9]{3}\Z")
_PRESTIGE_GAME_VERSION = "1.37.4"
_PRESTIGE_GAME_SHA256 = (
    "b23fa0e1f698d31b01cdd1c3817a675805d8c6286cb66f9c231e6e2a42544d77"
)
_MONARCH_POINTS_COUNTRY = "FRA"
_MONTHLY_ECONOMY_COUNTRY = "FRA"
_MONTHLY_ECONOMY_FIELDS = (
    "monthly_income", "monthly_expenses", "monthly_balance",
)
_N01_LEDGER_FIELDS = (*_MONTHLY_ECONOMY_FIELDS, "war_income")
_WAR_INCOME_BASIS = "native_previous_month_war_related_income_slots"
_MONTHLY_ECONOMY_BASIS = "native_recurring_monthly_ledger"
_MONTHLY_ECONOMY_REFERENCE_PERIOD = "previous_month"
_MONTHLY_ECONOMY_VALUE_SEMANTICS = "previous_month_recurring_ledger"
_MONTHLY_ECONOMY_VALUE_ORIGIN = "derived_from_copied_native_ledger"
_PRESTIGE_CONTEXT_KEYS = (
    "session_id", "game_sha256", "observer", "game_date",
)
_TOPIC_FIELDS = {
    # Keep a local monthly field first so CompositeSource can validate a
    # query containing only an unimplemented planned field without requiring
    # the treasury pair recipient as a probe side effect.
    "N01": (*_N01_LEDGER_FIELDS, "treasury"),
    "N02": ("manpower", "max_manpower", "max_sailors"),
    "N05": ("diplomats_available",),
    # Keep the native points field first.  CompositeSource uses the first
    # implemented field when it validates a query that contains only planned
    # fields; that probe must not accidentally acquire the prestige pair
    # parameter.
    "N06": ("monarch_points", "prestige"),
}

# These are the exact public projections used by the existing diplomacy
# adapter.  ``send_gift`` is a read-only 25-ducat probe because its public
# projection contains the controlled actor's treasury.  The probe is never
# submitted by this source.
_INSPECTIONS = {
    "N01": {
        "action_id": "send_gift",
        "parameters": {"ducats": 25},
        "path": "gift.controlled_treasury.raw",
    },
    "N02": {
        "action_id": "trade_favors_for_men",
        "parameters": {},
        "path": "favor_trade.manpower.actor_raw",
    },
    "N05": {
        "action_id": "trade_favors_for_men",
        "parameters": {},
        "path": "resources.diplomats.available_count",
    },
    "N06": {
        "action_id": "offer_vassalization",
        "parameters": {},
        "path": "prestige_raw",
    },
}


def _parameter_schema(topic_id: str) -> dict[str, Any]:
    schema = {
        "type": "object",
        "properties": {
            "reference_recipient": {
                "type": "string", "pattern": r"^[A-Z0-9]{3}$",
            },
        },
        # Country caches and monthly ledgers need no pair recipient. An
        # explicit recipient remains available for legacy public projections.
        "required": [] if topic_id in {"N01", "N02", "N05", "N06"} else ["reference_recipient"],
        "additionalProperties": False,
    }
    if topic_id == "N06":
        schema["properties"]["reference_recipient"]["description"] = (
            "请求 prestige 时必填；只请求 monarch_points 时可省略"
        )
    elif topic_id == "N01":
        schema["properties"]["reference_recipient"]["description"] = (
            "可省略；国库及月度账目直接读取本国数据。"
            "显式提供时可在国库缓存不可用后沿用原国家对预览回退"
        )
    elif topic_id == "N02":
        schema["properties"]["reference_recipient"]["description"] = (
            "manpower 单独请求或与其它字段混合时必填；只请求 max_manpower，或只组合 "
            "manpower 与 max_manpower 时可省略；army_size/navy_size/army_composition/"
            "navy_composition/sailors/force_limits 也可单独请求而省略"
        )
    elif topic_id == "N05":
        schema["properties"]["reference_recipient"]["description"] = (
            "请求 diplomats_available 时必填；只请求 diplomat_tasks、relations_count 或 relations_limit 时可省略；"
            "与 diplomats_available 混合请求时仍须提供"
        )
    return schema


def _field_metadata(topic_id: str, field: str) -> dict[str, Any]:
    values = {
        ("N01", "treasury"): {
            "description": "本国可用国库余额；原生公共 projection 的 raw 值",
            "unit": "ducats", "scale": 1000,
            "paths": ["gift.controlled_treasury.raw"],
        },
        ("N01", "war_income"): {
            "description": (
                "本国上一月原生收入账本中的赔款、战利品、封锁和劫掠分项；"
                "不表示完整战争收入、当前收款或某场战争的归因"
            ),
            "unit": "war_income_information", "scale": 1,
            "period": "month", "reference_period": _MONTHLY_ECONOMY_REFERENCE_PERIOD,
            "basis": _WAR_INCOME_BASIS,
            "value_origin": "projected_named_native_income_slots",
            "paths": ["monthly_economy.income_slots"],
            "source": "NativeCountryStateSource",
            "supported_countries": [_MONTHLY_ECONOMY_COUNTRY],
            "complete": False,
            "gaps": ["WAR_INCOME_CATEGORY_COVERAGE_NOT_EXHAUSTIVE",
                     "CURRENT_WAR_ATTRIBUTION_NOT_ESTABLISHED",
                     "CURRENT_PAYMENT_OBLIGATIONS_NOT_ESTABLISHED"],
        },
        ("N01", "monthly_income"): {
            "description": (
                "本国上月原生经常性月度收入账本聚合；"
                "GUI动态月度预估尚未闭合"
            ),
            "unit": "ducats", "scale": 1000, "raw": True,
            "raw_semantics": "monthly_economy.fields.monthly_income.raw / 1000",
            "period": "month", "reference_period": _MONTHLY_ECONOMY_REFERENCE_PERIOD,
            "basis": _MONTHLY_ECONOMY_BASIS,
            "value_semantics": _MONTHLY_ECONOMY_VALUE_SEMANTICS,
            "value_origin": _MONTHLY_ECONOMY_VALUE_ORIGIN,
            "paths": ["monthly_economy.fields.monthly_income.raw"],
            "source": "NativeCountryStateSource",
            "supported_countries": [_MONTHLY_ECONOMY_COUNTRY],
            "gaps": ["GUI_DYNAMIC_MONTHLY_ESTIMATE_NOT_CLOSED"],
        },
        ("N01", "monthly_expenses"): {
            "description": (
                "本国上月原生经常性月度支出账本聚合；"
                "GUI动态月度预估尚未闭合"
            ),
            "unit": "ducats", "scale": 1000, "raw": True,
            "raw_semantics": "monthly_economy.fields.monthly_expenses.raw / 1000",
            "period": "month", "reference_period": _MONTHLY_ECONOMY_REFERENCE_PERIOD,
            "basis": _MONTHLY_ECONOMY_BASIS,
            "value_semantics": _MONTHLY_ECONOMY_VALUE_SEMANTICS,
            "value_origin": _MONTHLY_ECONOMY_VALUE_ORIGIN,
            "paths": ["monthly_economy.fields.monthly_expenses.raw"],
            "source": "NativeCountryStateSource",
            "supported_countries": [_MONTHLY_ECONOMY_COUNTRY],
            "gaps": ["GUI_DYNAMIC_MONTHLY_ESTIMATE_NOT_CLOSED"],
        },
        ("N01", "monthly_balance"): {
            "description": (
                "本国上月原生经常性月度收入减支出账本结余；"
                "GUI动态月度预估尚未闭合"
            ),
            "unit": "ducats", "scale": 1000, "raw": True,
            "raw_semantics": "monthly_economy.fields.monthly_balance.raw / 1000",
            "period": "month", "reference_period": _MONTHLY_ECONOMY_REFERENCE_PERIOD,
            "basis": _MONTHLY_ECONOMY_BASIS,
            "value_semantics": _MONTHLY_ECONOMY_VALUE_SEMANTICS,
            "value_origin": _MONTHLY_ECONOMY_VALUE_ORIGIN,
            "paths": ["monthly_economy.fields.monthly_balance.raw"],
            "source": "NativeCountryStateSource",
            "supported_countries": [_MONTHLY_ECONOMY_COUNTRY],
            "gaps": ["GUI_DYNAMIC_MONTHLY_ESTIMATE_NOT_CLOSED"],
        },
        ("N02", "manpower"): {
            "description": "本国后备人力；只取 manpower.actor_raw",
            "unit": "men", "scale": 1,
            "paths": ["favor_trade.manpower.actor_raw"],
        },
        ("N02", "max_manpower"): {
            "description": "本国最大人力；从已验证的本国最大人力缓存读取，不回退到当前人力",
            "unit": "men", "scale": 1, "period": "current",
            "basis": "native_country_max_manpower_cache",
            "paths": ["own_resource_cache.N02.max_manpower"],
            "source": "bridge.information.own_resource_caches.capture",
            "supported_countries": ["FRA"],
        },
        ("N02", "max_sailors"): {
            "description": "本国最大水手数，从原生最大水手缓存读取",
            "unit": "sailors", "scale": 1000, "period": "current",
            "basis": "native_country_max_sailors_cache",
            "paths": ["own_resource_cache.N02.max_sailors"],
            "source": "bridge.information.own_resource_caches.capture",
            "supported_countries": ["FRA"],
        },
        ("N05", "diplomats_available"): {
            "description": "本国当前可用外交官数量；实时宏观查询复用已验证任务图中状态为0的实例计数",
            "unit": "diplomats", "scale": 1,
            "paths": ["resources.diplomats.available_count", "diplomat_tasks.available_count_observed"],
        },
        ("N06", "prestige"): {
            "description": (
                "本国当前威望；只取 offer_vassalization 公共 projection "
                "的 prestige_raw，不取取消附庸费用"
            ),
            "unit": "prestige", "scale": 1000,
            "raw": True,
            "raw_semantics": "prestige_raw / 1000",
            "paths": ["prestige_raw"],
        },
        ("N06", "monarch_points"): {
            "description": (
                "本国当前行政、外交、军事君主点数；只取固定版本的有界"
                "纯 RPM capture values"
            ),
            "unit": "monarch_points", "scale": 1,
            "raw": True,
            "raw_semantics": "values.administrative/diplomatic/military / 1",
            "paths": ["values"],
            "source": "bridge.information.country_resources_memory.capture",
            "supported_countries": ["FRA"],
        },
    }
    return {
        "coverage": (
            "partial"
            if topic_id == "N01" and field in _N01_LEDGER_FIELDS
            else "available"
        ),
        "source": values[(topic_id, field)].get(
            "source", "DiplomacyTools.inspect_diplomatic_action"
        ),
        **deepcopy(values[(topic_id, field)]),
    }


def _topic(topic_id: str) -> dict[str, Any]:
    titles = {
        "N01": "本国财政（已核对字段）",
        "N02": "本国军队与人力（已核对字段）",
        "N05": "本国外交官与关系容量（已核对字段）",
        "N06": "本国点数与外交负担（已核对字段）",
    }
    fields = {field: _field_metadata(topic_id, field)
              for field in _TOPIC_FIELDS[topic_id]}
    return {
        "topic_id": topic_id,
        "catalog_ids": [topic_id],
        "title": titles[topic_id],
        # A partial field can still be queried and delivered through the
        # service; topic availability is reserved for whether the route is
        # callable at all.
        "status": "available",
        "fields": fields,
        "object_types": ["country"],
        "observer_roles": ["country"],
        "parameters": _parameter_schema(topic_id),
        # The country-state adapter is based on the same 1.37.4 public
        # projections as the wrapped diplomacy source.
        "supported_versions": ["1.37.4"],
        "triggers": ["query", "periodic", "change"],
        "source": (
            "NativeCountryStateSource"
            if topic_id in {"N01", "N06"}
            else "DiplomacyTools.inspect_diplomatic_action"
        ),
        "visibility": "country_scope",
        "context_scope": "country_scope",
        **({
            "scope_note": (
                "月度收入、支出、结余仅覆盖固定版本上月原生经常性账本；"
                "GUI动态月度预估尚未闭合；war_income提供四类上一月收入分项，"
                "完整战争收入和具体战争归因仍未知，结果保持partial。"
            )
        } if topic_id == "N01" else {}),
    }


_CATALOG = tuple(_topic(topic_id) for topic_id in _TOPIC_FIELDS)


def _is_country(value: Any) -> bool:
    return isinstance(value, str) and _COUNTRY.fullmatch(value) is not None


def _known(value: Any) -> dict[str, Any]:
    return {"status": "known", "value": deepcopy(value)}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


class NativeCountryStateSource:
    """Expose verified local country fields through a ``DiplomacySource``.

    ``base_source`` must provide the normal information-source context and a
    ``diplomacy_tools.inspect_diplomatic_action`` reader.  The points reader
    is imported lazily (or injected for tests) and receives only the bounded
    ``installation.json`` path plus the observer country.  The adapter never
    calls an execution, submission, date-advance, or game-start method.
    """

    event_types: tuple[str, ...] = ()

    def __init__(self, base_source, *, capture=None,
                 monarch_points_capture=None, monthly_economy_capture=None):
        self.base_source = base_source
        if capture is not None and monarch_points_capture is not None:
            raise InformationError(
                "invalid_capture", "capture and monarch_points_capture are aliases"
            )
        # The low-level module is deliberately imported only when a points
        # query is read.  Tests and callers may inject the bounded reader
        # without importing or starting any native component.
        self.monarch_points_capture = (
            capture if capture is not None else monarch_points_capture
        )
        # Monthly economy is deliberately a separate seam.  Its default is
        # lazy so constructing an adapter never imports or touches the native
        # reader; a live, supported query opts into one parent capture which
        # includes all three monthly fields.
        self.monthly_economy_capture = monthly_economy_capture

    def context(self) -> dict[str, Any]:
        context = self.base_source.context()
        if not isinstance(context, dict):
            raise InformationError("source_context", "base source context must be an object")
        canonical(context)
        return _copy(context)

    def catalog(self) -> list[dict[str, Any]]:
        """Return only the fields this adapter can read from public projections."""

        return [deepcopy(item) for item in _CATALOG]

    def validate_query(self, query: dict, context: dict | None = None) -> dict:
        """Validate a country-scoped query and its explicit pair context."""

        if not isinstance(query, dict):
            raise InformationError("invalid_parameters", "query must be an object")
        allowed = {"topic", "object", "fields", "parameters"}
        missing = {"topic", "object", "fields"} - set(query)
        extra = set(query) - allowed
        if missing or extra:
            raise InformationError(
                "invalid_parameters",
                f"query: missing={sorted(missing)}, unknown={sorted(extra)}",
            )
        topic_id = query.get("topic")
        if topic_id not in _TOPIC_FIELDS:
            raise InformationError("unknown_topic", f"Unknown country-state topic: {topic_id!r}")
        obj = query.get("object")
        if not isinstance(obj, dict) or set(obj) != {"type", "country"}:
            raise InformationError(
                "invalid_object",
                "country-state queries require type and country only",
            )
        if obj.get("type") != "country" or not _is_country(obj.get("country")):
            raise InformationError("invalid_object", "country object has an invalid country tag")
        fields = query.get("fields")
        if (not isinstance(fields, list) or not fields
                or any(not isinstance(field, str) for field in fields)
                or len(set(fields)) != len(fields)):
            raise InformationError("invalid_fields", "fields must be a non-empty list of strings")
        unknown = set(fields) - set(_TOPIC_FIELDS[topic_id])
        if unknown:
            raise InformationError("unknown_field", f"{topic_id}: unknown fields {sorted(unknown)}")
        parameters = query.get("parameters", {})
        if not isinstance(parameters, dict):
            raise InformationError(
                "invalid_parameters", "parameters must be an object"
            )
        points_only = topic_id == "N06" and fields == ["monarch_points"]
        max_resource_cache_only = (
            topic_id == "N02"
            and bool(set(fields) & {"max_manpower", "max_sailors"})
            and set(fields) <= {"manpower", "max_manpower", "max_sailors"}
        )
        finance_query = topic_id == "N01"
        if points_only or finance_query or max_resource_cache_only:
            if set(parameters) not in (set(), {"reference_recipient"}):
                raise InformationError(
                    "invalid_parameters",
                    (
                        "points-only parameters may be empty or contain "
                        "reference_recipient"
                        if points_only else
                        "max-resource cache-only parameters may be empty or contain "
                        "reference_recipient"
                        if max_resource_cache_only else
                        "finance parameters may be empty or contain "
                        "reference_recipient"
                    ),
                )
        elif set(parameters) != {"reference_recipient"}:
            raise InformationError(
                "invalid_parameters",
                "parameters must contain reference_recipient only",
            )
        if "reference_recipient" in parameters:
            reference_recipient = parameters["reference_recipient"]
            if not _is_country(reference_recipient):
                raise InformationError(
                    "invalid_parameters", "reference_recipient must be a country tag"
                )
            if reference_recipient == obj["country"]:
                raise InformationError(
                    "invalid_parameters",
                    "reference_recipient must differ from the observed country",
                )
        if context is not None:
            if not isinstance(context, dict):
                raise InformationError("invalid_context", "context must be an object")
            observer = context.get("observer")
            if isinstance(observer, str) and observer != obj["country"]:
                raise InformationError(
                    "observer_scope_mismatch",
                    "country-state query is outside the observer scope",
                )
        normalized = {
            "topic": topic_id,
            "object": deepcopy(obj),
            "fields": list(fields),
            "parameters": deepcopy(parameters),
        }
        canonical(normalized)
        return normalized

    @staticmethod
    def _inspect(base_source, action_id: str, actor: str, recipient: str,
                 parameters: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
        tools = getattr(base_source, "diplomacy_tools", None)
        inspector = getattr(tools, "inspect_diplomatic_action", None)
        if not callable(inspector):
            return None, "INSPECT_ADAPTER_UNAVAILABLE"
        try:
            result = inspector(action_id, actor, recipient, "initiate", deepcopy(parameters))
        except Exception as exc:
            return None, "INSPECT_CALL_FAILED:" + type(exc).__name__
        if not isinstance(result, dict):
            return None, "INSPECT_RESULT_INVALID"
        if result.get("error_code"):
            return None, str(result["error_code"])
        return result, None

    @staticmethod
    def _extract(topic_id: str, inspected: dict[str, Any], actor: str,
                 recipient: str) -> tuple[Any, str | None]:
        """Read one value from the existing public projection.

        Returning ``(None, reason)`` keeps malformed or differently directed
        projections unknown; it never falls back to a raw counterparty field.
        """

        if inspected.get("actor") != actor or inspected.get("recipient") != recipient:
            return None, "PUBLIC_PROJECTION_IDENTITY_MISMATCH"
        if topic_id == "N01":
            gift = inspected.get("gift")
            treasury = gift.get("controlled_treasury") if isinstance(gift, dict) else None
            if (not isinstance(gift, dict) or gift.get("complete") is not True
                    or not isinstance(treasury, dict)
                    or treasury.get("country") != actor
                    or treasury.get("unit") != "ducats"
                    or treasury.get("scale") != 1000
                    or type(treasury.get("raw")) is not int):
                return None, "PUBLIC_TREASURY_PROJECTION_UNAVAILABLE"
            return treasury["raw"], None
        if topic_id == "N02":
            favor = inspected.get("favor_trade")
            manpower = favor.get("manpower") if isinstance(favor, dict) else None
            if (not isinstance(favor, dict) or favor.get("kind") != "men"
                    or favor.get("complete") is not True
                    or not isinstance(manpower, dict)
                    or manpower.get("actor") != actor
                    or manpower.get("recipient") != recipient
                    or manpower.get("unit") != "men"
                    or manpower.get("scale") != 1
                    or type(manpower.get("actor_raw")) is not int):
                return None, "PUBLIC_MANPOWER_PROJECTION_UNAVAILABLE"
            return manpower["actor_raw"], None
        if topic_id == "N05":
            resources = inspected.get("resources")
            diplomats = resources.get("diplomats") if isinstance(resources, dict) else None
            if (not isinstance(diplomats, dict)
                    or diplomats.get("availability_verified") is not True
                    or type(diplomats.get("available_count")) is not int
                    or not 0 <= diplomats["available_count"] <= 256):
                return None, "PUBLIC_DIPLOMAT_PROJECTION_UNAVAILABLE"
            return diplomats["available_count"], None
        if topic_id == "N06":
            if (inspected.get("action_id") != "offer_vassalization"
                    or inspected.get("family") != "vassalization"
                    or inspected.get("phase") != "initiate"):
                return None, "PUBLIC_PRESTIGE_ACTION_IDENTITY_MISMATCH"
            raw = inspected.get("prestige_raw")
            scale = inspected.get("prestige_scale")
            if (type(raw) is not int or not -(1 << 31) <= raw <= (1 << 31) - 1
                    or type(scale) is not int or scale != 1000):
                return None, "PUBLIC_PRESTIGE_PROJECTION_UNAVAILABLE"
            return raw, None
        return None, "COUNTRY_FIELD_UNIMPLEMENTED"

    @staticmethod
    def _prestige_context_reason(context: dict[str, Any], country: str) -> str | None:
        if not isinstance(context, dict):
            return "PRESTIGE_CONTEXT_UNAVAILABLE"
        if context.get("status") != "ready" or context.get("mode") != "live":
            return "PRESTIGE_LIVE_CONTEXT_UNAVAILABLE"
        if context.get("game_version") != _PRESTIGE_GAME_VERSION:
            return "PRESTIGE_GAME_VERSION_MISMATCH"
        if (not isinstance(context.get("game_sha256"), str)
                or context["game_sha256"].lower() != _PRESTIGE_GAME_SHA256):
            return "PRESTIGE_GAME_IDENTITY_MISMATCH"
        if context.get("observer") != country:
            return "PRESTIGE_OBSERVER_SCOPE_MISMATCH"
        if (not isinstance(context.get("session_id"), str)
                or not context["session_id"]):
            return "PRESTIGE_SESSION_ID_UNAVAILABLE"
        if type(context.get("game_date")) is not int:
            return "PRESTIGE_GAME_DATE_UNAVAILABLE"
        return None

    @staticmethod
    def _prestige_context_identity(context: dict[str, Any]) -> tuple[Any, ...]:
        return _time.context_identity(context, _PRESTIGE_CONTEXT_KEYS)

    @staticmethod
    def _monarch_points_context_reason(context: dict[str, Any], country: str) -> str | None:
        """Validate the live identity required by the native points reader."""

        if not isinstance(context, dict):
            return "MONARCH_POINTS_CONTEXT_UNAVAILABLE"
        if country != _MONARCH_POINTS_COUNTRY:
            return "MONARCH_POINTS_COUNTRY_UNSUPPORTED"
        if context.get("status") != "ready" or context.get("mode") != "live":
            return "MONARCH_POINTS_LIVE_CONTEXT_UNAVAILABLE"
        if context.get("game_version") != _PRESTIGE_GAME_VERSION:
            return "MONARCH_POINTS_GAME_VERSION_MISMATCH"
        if (not isinstance(context.get("game_sha256"), str)
                or context["game_sha256"].lower() != _PRESTIGE_GAME_SHA256):
            return "MONARCH_POINTS_GAME_IDENTITY_MISMATCH"
        if context.get("observer") != country:
            return "MONARCH_POINTS_OBSERVER_SCOPE_MISMATCH"
        if (not isinstance(context.get("session_id"), str)
                or not context["session_id"]):
            return "MONARCH_POINTS_SESSION_ID_UNAVAILABLE"
        if type(context.get("game_date")) is not int:
            return "MONARCH_POINTS_GAME_DATE_UNAVAILABLE"
        return None

    @staticmethod
    def _monarch_points_context_identity(context: dict[str, Any]) -> tuple[Any, ...]:
        return _time.context_identity(context, (
            'session_id', 'game_sha256', 'observer', 'game_date', 'game_version'))

    @staticmethod
    def _capture_report_reason(report: Any, context: dict[str, Any],
                               country: str, creation_filetime: int) -> str | None:
        """Return a bounded contract error for a native points capture.

        This adapter treats the low-level report as untrusted input.  In
        particular, ``bool`` is never accepted as an integer and a report
        with a mismatched process/session binding cannot become a value.
        """

        if not isinstance(report, dict):
            return "MONARCH_POINTS_CAPTURE_INVALID"
        if (report.get("status") != "observed"
                or report.get("read_only") is not True
                or report.get("native_function_invoked") is not False
                or report.get("country") != country
                or report.get("unit") != "monarch_points"
                or type(report.get("scale")) is not int
                or report.get("scale") != 1
                or report.get("completed") is not True):
            return "MONARCH_POINTS_CAPTURE_INVALID"

        values = report.get("values")
        if (not isinstance(values, dict)
                or set(values) != {"administrative", "diplomatic", "military"}):
            return "MONARCH_POINTS_VALUES_INVALID"
        if any(type(values[key]) is not int
               or not -(1 << 31) <= values[key] <= (1 << 31) - 1
               for key in ("administrative", "diplomatic", "military")):
            return "MONARCH_POINTS_VALUES_INVALID"

        identity = report.get("identity")
        if not isinstance(identity, dict):
            return "MONARCH_POINTS_IDENTITY_INVALID"
        if (identity.get("binding_verified") is not True
                or not isinstance(identity.get("process_path_sha256"), str)
                or identity["process_path_sha256"].lower() != _PRESTIGE_GAME_SHA256
                or identity.get("installation_session_id") != context.get("session_id")
                or type(identity.get("installation_creation_filetime")) is not int
                or identity.get("installation_creation_filetime") != creation_filetime
                or type(identity.get("process_creation_filetime")) is not int
                or identity.get("process_creation_filetime") != creation_filetime):
            return "MONARCH_POINTS_IDENTITY_INVALID"

        for guard_name in (
                "static_contract_guard", "file_code_guard", "runtime_code_guard"):
            guard = report.get(guard_name)
            if not isinstance(guard, dict) or guard.get("status") != "observed":
                return "MONARCH_POINTS_GUARD_INVALID"

        doublepass = report.get("doublepass")
        if (not isinstance(doublepass, dict)
                or doublepass.get("performed") is not True
                or doublepass.get("consistent") is not True):
            return "MONARCH_POINTS_DOUBLEPASS_INVALID"

        cleanup = report.get("cleanup")
        handle_close = cleanup.get("handle_close") if isinstance(cleanup, dict) else None
        if (not isinstance(handle_close, dict)
                or handle_close.get("status") != "closed"
                or ("closed" in handle_close and handle_close.get("closed") is not True)):
            return "MONARCH_POINTS_CLEANUP_INVALID"

        for snapshot_name in ("before", "after"):
            snapshot = report.get(snapshot_name)
            game_date = snapshot.get("game_date") if isinstance(snapshot, dict) else None
            if (not isinstance(snapshot, dict)
                    or snapshot.get("status") != "observed"
                    or not isinstance(game_date, dict)
                    or type(game_date.get("value")) is not int
                    or not _time.dates_match(context.get('game_date'), game_date.get('value'))
                    or not isinstance(game_date.get("raw_hex"), str)
                    or not game_date["raw_hex"]
                    or len(game_date["raw_hex"]) > 64):
                return "MONARCH_POINTS_DATE_INVALID"
            raw_hex = game_date["raw_hex"]
            try:
                if raw_hex.lower().startswith("0x"):
                    raw_value = int(raw_hex, 16)
                else:
                    raw_bytes = bytes.fromhex(raw_hex)
                    raw_value = int.from_bytes(raw_bytes, "little", signed=True)
            except (TypeError, ValueError):
                return "MONARCH_POINTS_DATE_INVALID"
            if raw_value != game_date["value"]:
                return "MONARCH_POINTS_DATE_INVALID"
        if not _time.dates_match(context.get('game_date'), report['before']['game_date']['value'],
                                 report['after']['game_date']['value']):
            return 'MONARCH_POINTS_DATE_INVALID'
        return None

    @staticmethod
    def _hex_digest(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        try:
            raw = bytes.fromhex(value)
        except ValueError:
            return None
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def _compact_code_guard(cls, guard: Any) -> dict[str, Any]:
        """Retain guard results and addresses while dropping code bytes."""

        if not isinstance(guard, dict):
            return {"status": None, "checks": {}, "records": {}}
        records: dict[str, Any] = {}
        raw_records = guard.get("records")
        if isinstance(raw_records, dict):
            for name, raw_record in raw_records.items():
                if not isinstance(name, str) or not isinstance(raw_record, dict):
                    continue
                address = raw_record.get("address")
                compact: dict[str, Any] = {}
                if "rva" in raw_record:
                    compact["rva"] = deepcopy(raw_record["rva"])
                if isinstance(address, dict):
                    compact["address"] = deepcopy(address)
                    compact.setdefault("rva", deepcopy(address.get("rva")))
                elif address is not None:
                    compact["address"] = deepcopy(address)
                expected = raw_record.get("expected_sha256")
                actual = raw_record.get("actual_sha256")
                if expected is None:
                    expected = cls._hex_digest(raw_record.get("expected_hex"))
                if actual is None:
                    actual = cls._hex_digest(raw_record.get("actual_hex"))
                compact["expected_sha256"] = expected
                compact["actual_sha256"] = actual
                records[name] = compact
        result: dict[str, Any] = {
            "status": guard.get("status"),
            "checks": deepcopy(guard.get("checks", {}))
            if isinstance(guard.get("checks", {}), dict) else {},
            "records": records,
        }
        if "module_base" in guard:
            result["module_base"] = deepcopy(guard["module_base"])
        unknown = guard.get("unknown_conditions")
        if isinstance(unknown, list):
            result["unknown_conditions"] = deepcopy(unknown[:256])
        return result

    @staticmethod
    def _compact_static_guard(guard: Any) -> dict[str, Any]:
        if not isinstance(guard, dict):
            return {"status": None, "checks": {}, "dependencies": []}
        dependencies: list[dict[str, Any]] = []
        raw_dependencies = guard.get("source_dependencies")
        if isinstance(raw_dependencies, list):
            for item in raw_dependencies:
                if not isinstance(item, dict):
                    continue
                dependencies.append({
                    "path": item.get("path"),
                    "sha256": item.get("sha256"),
                })
        result = {
            "status": guard.get("status"),
            "profile": guard.get("profile"),
            "profile_sha256": guard.get("profile_sha256"),
            "checks": deepcopy(guard.get("checks", {}))
            if isinstance(guard.get("checks", {}), dict) else {},
            "dependency_hash_checks": deepcopy(
                guard.get("dependency_hash_checks", {})
            ) if isinstance(guard.get("dependency_hash_checks", {}), dict) else {},
            "dependencies": dependencies,
        }
        unknown = guard.get("unknown_conditions")
        if isinstance(unknown, list):
            result["unknown_conditions"] = deepcopy(unknown[:256])
        return result

    @staticmethod
    def _compact_country_scan(scan: Any) -> dict[str, Any] | None:
        if not isinstance(scan, dict):
            return None
        result: dict[str, Any] = {}
        for key in (
                "status", "requested_country", "scanned_entries", "country_pointer",
                "country_handle", "unknown_reason"):
            if key in scan:
                result[key] = deepcopy(scan[key])
        return result

    @classmethod
    def _compact_snapshot(cls, snapshot: Any) -> dict[str, Any] | None:
        if not isinstance(snapshot, dict):
            return None
        result: dict[str, Any] = {
            "status": snapshot.get("status"),
            "game_date": deepcopy(snapshot.get("game_date")),
            "country_scan": cls._compact_country_scan(snapshot.get("country_scan")),
            "values": deepcopy(snapshot.get("values")),
            "value_raw_hex": deepcopy(snapshot.get("value_raw_hex")),
        }
        return result

    @staticmethod
    def _capture_report_sha256(report: Any) -> str | None:
        try:
            material = canonical(report).encode("utf-8")
        except Exception:
            return None
        return hashlib.sha256(material).hexdigest()

    @classmethod
    def _capture_audit(cls, report: dict[str, Any]) -> dict[str, Any]:
        """Keep compact provenance without duplicating native read payloads."""

        profile = report.get("profile")
        compact_profile = None
        if isinstance(profile, dict):
            compact_profile = {
                "path": profile.get("path"),
                "sha256": profile.get("sha256"),
                "max_bytes": profile.get("max_bytes"),
            }
        access = report.get("access")
        compact_access = None
        if isinstance(access, dict):
            compact_access = {
                key: deepcopy(access.get(key))
                for key in (
                    "rpm_bytes_requested", "rpm_calls", "rpm_total_limit",
                    "rpm_single_read_limit",
                ) if key in access
            }
        result: dict[str, Any] = {
            "status": report.get("status"),
            "read_only": report.get("read_only"),
            "native_function_invoked": report.get("native_function_invoked"),
            "country": report.get("country"),
            "unit": report.get("unit"),
            "scale": report.get("scale"),
            "completed": report.get("completed"),
            "probe_script_sha256": report.get("probe_script_sha256"),
            "profile": compact_profile,
            "identity": deepcopy(report.get("identity")),
            "static_contract_guard": cls._compact_static_guard(
                report.get("static_contract_guard")
            ),
            "file_code_guard": cls._compact_code_guard(
                report.get("file_code_guard")
            ),
            "runtime_code_guard": cls._compact_code_guard(
                report.get("runtime_code_guard")
            ),
            "doublepass": deepcopy(report.get("doublepass")),
            "access": compact_access,
            "cleanup": deepcopy(report.get("cleanup")),
            "before": cls._compact_snapshot(report.get("before")),
            "after": cls._compact_snapshot(report.get("after")),
        }
        return result

    @classmethod
    def _record_capture_provenance(cls, provenance: dict[str, Any],
                                   report: dict[str, Any]) -> None:
        provenance["capture"] = cls._capture_audit(report)
        provenance["capture_report_sha256"] = cls._capture_report_sha256(report)
        provenance["capture_report_hash_algorithm"] = (
            "sha256(canonical_json_utf8;information.model.canonical)"
        )

    def _read_monarch_points(self, normalized: dict[str, Any],
                             current: dict[str, Any], *,
                             context_supplied: bool) -> dict[str, Any]:
        """Read the three native monarch-point components as one country field."""

        actor = normalized["object"]["country"]
        provenance: dict[str, Any] = {
            "adapter": "bridge.information.country_resources_memory.capture",
            "country": actor,
            "read_only": True,
            "native_function_invoked": False,
            "unit": "monarch_points",
            "scale": 1,
            "context_guard": {
                "mode": "live",
                "game_version": _PRESTIGE_GAME_VERSION,
                "game_sha256": _PRESTIGE_GAME_SHA256,
                "identity_keys": [
                    "session_id", "game_sha256", "observer", "game_date",
                    "game_version",
                ],
            },
        }

        def unavailable(reason: str, context: dict[str, Any] = current) -> dict[str, Any]:
            provenance["context_guard"]["status"] = "unavailable"
            fields = {"monarch_points": _unavailable(reason)}
            return _result(
                normalized, context, fields, False,
                _source_info("NativeCountryStateSource", context,
                             complete=False, provenance=provenance),
            )

        reason = self._monarch_points_context_reason(current, actor)
        if reason is not None:
            return unavailable(reason)

        before = current
        if context_supplied:
            try:
                before = self.context()
            except Exception:
                before = {}
            reason = self._monarch_points_context_reason(before, actor)
            if reason is not None:
                return unavailable(reason)
            if (self._monarch_points_context_identity(current)
                    != self._monarch_points_context_identity(before)):
                provenance["context_guard"]["status"] = "stale"
                return _result(
                    normalized, current,
                    {"monarch_points": _unavailable("MONARCH_POINTS_CONTEXT_STALE")},
                    False,
                    _source_info("NativeCountryStateSource", current,
                                 complete=False, provenance=provenance),
                )

        session = getattr(self.base_source, "session", None)
        if session is None:
            return unavailable("MONARCH_POINTS_SESSION_UNAVAILABLE", before)
        try:
            directory = getattr(session, "directory", None)
            if directory is None:
                raise ValueError("session directory is missing")
            installation = Path(directory) / "installation.json"
            record = getattr(session, "record", None)
            if not isinstance(record, dict):
                raise ValueError("session record is missing")
            creation_filetime = record.get("creation_filetime")
            if type(creation_filetime) is not int:
                raise ValueError("session creation_filetime is missing")
            session_creation = getattr(session, "creation_filetime", None)
            if (session_creation is not None
                    and (type(session_creation) is not int
                         or session_creation != creation_filetime)):
                raise ValueError("session creation_filetime differs from record")
        except Exception:
            return unavailable("MONARCH_POINTS_INSTALLATION_UNAVAILABLE", before)

        capture = self.monarch_points_capture
        if capture is None:
            try:
                from .country_resources_memory import capture as capture
            except Exception:
                return unavailable("MONARCH_POINTS_CAPTURE_UNAVAILABLE", before)
        if not callable(capture):
            return unavailable("MONARCH_POINTS_CAPTURE_UNAVAILABLE", before)
        try:
            report = capture(installation, actor)
        except Exception as exc:
            provenance["context_guard"]["status"] = "capture_failed"
            return _result(
                normalized, before,
                {"monarch_points": _unavailable(
                    "MONARCH_POINTS_CAPTURE_FAILED:" + type(exc).__name__)},
                False,
                _source_info("NativeCountryStateSource", before,
                             complete=False, provenance=provenance),
            )

        report_reason = self._capture_report_reason(
            report, before, actor, creation_filetime)
        if report_reason is not None:
            provenance["context_guard"]["status"] = "capture_invalid"
            if isinstance(report, dict):
                self._record_capture_provenance(provenance, report)
            return _result(
                normalized, before,
                {"monarch_points": _unknown(report_reason)}, False,
                _source_info("NativeCountryStateSource", before,
                             complete=False, provenance=provenance),
            )

        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = self._monarch_points_context_reason(after, actor)
        if (after_reason is not None
                or self._monarch_points_context_identity(before)
                != self._monarch_points_context_identity(after)):
            provenance["context_guard"]["status"] = "changed"
            self._record_capture_provenance(provenance, report)
            return _result(
                normalized, before,
                {"monarch_points": _unknown(
                    after_reason or "MONARCH_POINTS_CONTEXT_CHANGED")}, False,
                _source_info("NativeCountryStateSource", before,
                             complete=False, provenance=provenance),
            )

        provenance["context_guard"]["status"] = "passed"
        self._record_capture_provenance(provenance, report)
        return _result(
            normalized, before,
            {"monarch_points": _known(deepcopy(report["values"]))}, True,
            _source_info("NativeCountryStateSource", before,
                         complete=True, provenance=provenance),
        )

    @staticmethod
    def _monthly_economy_context_reason(
        context: dict[str, Any], country: str,
    ) -> str | None:
        """Validate the live identity required by the monthly ledger reader."""
        reason = NativeCountryStateSource._monarch_points_context_reason(
            context, country
        )
        if reason is None:
            return None
        return reason.replace("MONARCH_POINTS", "MONTHLY_ECONOMY", 1)

    @staticmethod
    def _monthly_economy_context_identity(context: dict[str, Any]) -> tuple[Any, ...]:
        return NativeCountryStateSource._monarch_points_context_identity(context)

    @staticmethod
    def _monthly_record_shape_reason(record: Any) -> str | None:
        """Check the public monthly record shape after its memory validator."""

        if not isinstance(record, dict) or record.get("status") != "observed":
            reason = record.get("reason") if isinstance(record, dict) else None
            return "MONTHLY_ECONOMY_RECORD_INVALID" + (
                ":" + reason if isinstance(reason, str) and reason else ""
            )
        if (record.get("basis") != _MONTHLY_ECONOMY_BASIS
                or record.get("reference_period") != _MONTHLY_ECONOMY_REFERENCE_PERIOD
                or record.get("period") != "month"
                or record.get("value_semantics") != _MONTHLY_ECONOMY_VALUE_SEMANTICS
                or record.get("unit") != "ducats"
                or type(record.get("scale")) is not int
                or record.get("scale") != 1000
                or record.get("value_origin") != _MONTHLY_ECONOMY_VALUE_ORIGIN):
            return "MONTHLY_ECONOMY_RECORD_CONTRACT_INVALID"
        for guard_name in ("static_contract_guard", "runtime_code_guard"):
            guard = record.get(guard_name)
            if not isinstance(guard, dict) or guard.get("status") != "observed":
                return "MONTHLY_ECONOMY_RECORD_GUARD_INVALID"
        raw_ledger_hex = record.get("raw_ledger_hex")
        if (not isinstance(raw_ledger_hex, str) or len(raw_ledger_hex) != 228 * 2):
            return "MONTHLY_ECONOMY_RECORD_RAW_INVALID"
        try:
            if len(bytes.fromhex(raw_ledger_hex)) != 228:
                return "MONTHLY_ECONOMY_RECORD_RAW_INVALID"
        except (TypeError, ValueError):
            return "MONTHLY_ECONOMY_RECORD_RAW_INVALID"
        for key, count in (("income_slots", 19), ("expense_slots", 38)):
            values = record.get(key)
            if (not isinstance(values, list) or len(values) != count
                    or any(type(value) is not int for value in values)):
                return "MONTHLY_ECONOMY_RECORD_RAW_INVALID"
        if ("raw_payload_hex" in record
                and record.get("raw_payload_hex") != raw_ledger_hex):
            return "MONTHLY_ECONOMY_RECORD_RAW_INVALID"
        values = record.get("values")
        fields = record.get("fields")
        if (not isinstance(values, dict) or not isinstance(fields, dict)
                or set(values) != set(_MONTHLY_ECONOMY_FIELDS)
                or set(fields) != set(_MONTHLY_ECONOMY_FIELDS)):
            return "MONTHLY_ECONOMY_RECORD_FIELDS_INVALID"
        raw_hex_map = record.get("raw_hex")
        if not isinstance(raw_hex_map, dict):
            return "MONTHLY_ECONOMY_RECORD_RAW_INVALID"
        for field in _MONTHLY_ECONOMY_FIELDS:
            value = values.get(field)
            item = fields.get(field)
            if (type(value) is not int
                    or not -(1 << 31) <= value <= (1 << 31) - 1
                    or not isinstance(item, dict)
                    or item.get("status") != "known"
                    or type(item.get("value")) is not int
                    or type(item.get("raw")) is not int
                    or item.get("value") != value
                    or item.get("raw") != value
                    or item.get("complete") is not False
                    or item.get("reference_period") != _MONTHLY_ECONOMY_REFERENCE_PERIOD
                    or item.get("period") != "month"
                    or item.get("value_semantics") != _MONTHLY_ECONOMY_VALUE_SEMANTICS
                    or item.get("value_origin") != _MONTHLY_ECONOMY_VALUE_ORIGIN):
                return "MONTHLY_ECONOMY_RECORD_FIELD_INVALID:" + field
            encoded = item.get("raw_hex")
            if (not isinstance(encoded, str) or len(encoded) != 8
                    or encoded != encoded.lower()
                    or encoded.lower() != str(raw_hex_map.get(field, "")).lower()):
                return "MONTHLY_ECONOMY_RECORD_RAW_INVALID:" + field
            try:
                if len(bytes.fromhex(encoded)) != 4:
                    return "MONTHLY_ECONOMY_RECORD_RAW_INVALID:" + field
                if encoded != (value & 0xFFFFFFFF).to_bytes(4, "little").hex():
                    return "MONTHLY_ECONOMY_RECORD_RAW_INVALID:" + field
            except (TypeError, ValueError):
                return "MONTHLY_ECONOMY_RECORD_RAW_INVALID:" + field
        return None

    @classmethod
    def _monthly_record_reason(cls, record: Any) -> str | None:
        """Run the low-level validator and then enforce adapter semantics."""

        if not isinstance(record, dict) or record.get("status") != "observed":
            # Preserve a reader's explicit unknown/retraction reason instead
            # of collapsing it into a generic validator failure.
            return cls._monthly_record_shape_reason(record)
        try:
            from . import monthly_economy_memory
        except Exception as exc:
            return "MONTHLY_ECONOMY_VALIDATOR_UNAVAILABLE:" + type(exc).__name__
        validator = getattr(monthly_economy_memory, "validate_record", None)
        if not callable(validator):
            return "MONTHLY_ECONOMY_VALIDATOR_UNAVAILABLE"
        try:
            valid = validator(record)
        except Exception as exc:
            return "MONTHLY_ECONOMY_RECORD_VALIDATION_FAILED:" + type(exc).__name__
        if valid is not True:
            return "MONTHLY_ECONOMY_RECORD_INVALID"
        expected_profile = getattr(
            monthly_economy_memory, "EXPECTED_PROFILE_SHA256", None
        )
        if (isinstance(expected_profile, str)
                and len(expected_profile) == 64
                and expected_profile != "pending-profile"
                and record.get("profile_sha256") != expected_profile):
            return "MONTHLY_ECONOMY_PROFILE_PIN_INVALID"
        if (isinstance(expected_profile, str)
                and len(expected_profile) == 64
                and expected_profile != "pending-profile"):
            static_guard = record.get("static_contract_guard")
            if (isinstance(static_guard, dict)
                    and static_guard.get("profile_sha256") not in {
                        expected_profile, None,
                    }):
                return "MONTHLY_ECONOMY_PROFILE_PIN_INVALID"
        return cls._monthly_record_shape_reason(record)

    @classmethod
    def _monthly_capture_report_reason(cls, report: Any) -> str | None:
        """Validate top and double-pass monthly records from one parent capture."""

        if not isinstance(report, dict):
            return "MONTHLY_ECONOMY_PARENT_CAPTURE_INVALID"
        top = report.get("monthly_economy")
        reason = cls._monthly_record_reason(top)
        if reason is not None:
            return reason
        snapshots: list[dict[str, Any]] = []
        for snapshot_name in ("before", "after"):
            snapshot = report.get(snapshot_name)
            record = snapshot.get("monthly_economy") if isinstance(snapshot, dict) else None
            reason = cls._monthly_record_reason(record)
            if reason is not None:
                return "MONTHLY_ECONOMY_" + snapshot_name.upper() + "_" + reason.removeprefix(
                    "MONTHLY_ECONOMY_"
                )
            snapshots.append(record)
        try:
            top_canonical = canonical(top)
            if any(canonical(record) != top_canonical for record in snapshots):
                return "MONTHLY_ECONOMY_SNAPSHOT_MISMATCH"
        except Exception:
            return "MONTHLY_ECONOMY_RECORD_CANONICAL_INVALID"
        return None

    @staticmethod
    def _monthly_record_provenance(record: dict[str, Any]) -> dict[str, Any]:
        """Retain the monthly contract and raw ledger without parent read logs."""

        return {
            key: deepcopy(record.get(key))
            for key in (
                "status", "profile_sha256", "raw_ledger_hex", "raw_hex",
                "income_slots", "expense_slots", "values", "basis", "unit", "scale", "value_origin",
                "reference_period", "period", "value_semantics",
                "static_contract_guard", "runtime_code_guard", "observation",
            ) if key in record
        }

    def _read_monthly_economy(
        self, normalized: dict[str, Any], current: dict[str, Any], *,
        context_supplied: bool,
    ) -> dict[str, Any]:
        """Read all requested monthly fields with one guarded parent capture."""

        actor = normalized["object"]["country"]
        requested = [
            field for field in normalized["fields"]
            if field in _N01_LEDGER_FIELDS
        ]
        provenance: dict[str, Any] = {
            "adapter": "bridge.information.country_resources_memory.capture",
            "country": actor,
            "read_only": True,
            "native_function_invoked": False,
            "unit": "ducats",
            "scale": 1000,
            "period": "month",
            "reference_period": _MONTHLY_ECONOMY_REFERENCE_PERIOD,
            "basis": _MONTHLY_ECONOMY_BASIS,
            "value_semantics": _MONTHLY_ECONOMY_VALUE_SEMANTICS,
            "value_origin": _MONTHLY_ECONOMY_VALUE_ORIGIN,
            "context_guard": {
                "mode": "live",
                "game_version": _PRESTIGE_GAME_VERSION,
                "game_sha256": _PRESTIGE_GAME_SHA256,
                "identity_keys": [
                    "session_id", "game_sha256", "observer", "game_date",
                    "game_version",
                ],
            },
        }

        def result(
            context: dict[str, Any], fields: dict[str, dict[str, Any]],
        ) -> dict[str, Any]:
            public_provenance = provenance
            if "war_income" in requested:
                # The new component query does not publish its input ledger,
                # addresses or ROM bytes through source metadata. The complete
                # record remains in the private capture archive. Existing
                # monthly-only response metadata retains its prior contract.
                public_provenance = {
                    key: deepcopy(provenance[key]) for key in (
                        "adapter", "country", "read_only", "native_function_invoked",
                        "unit", "scale", "period", "reference_period", "basis",
                        "value_semantics", "value_origin", "context_guard",
                        "capture_reason", "war_income_projection",
                        "capture_report_sha256", "capture_report_hash_algorithm",
                    ) if key in provenance
                }
                record_provenance = provenance.get("monthly_economy")
                if isinstance(record_provenance, dict):
                    summary = {
                        key: deepcopy(record_provenance[key]) for key in (
                            "status", "profile_sha256", "basis", "unit", "scale",
                            "period", "reference_period", "value_semantics", "value_origin",
                        ) if key in record_provenance
                    }
                    summary["raw_record_disclosed"] = False
                    try:
                        summary["private_provenance_sha256"] = hashlib.sha256(
                            canonical(record_provenance).encode("utf-8")
                        ).hexdigest()
                    except Exception:
                        summary["private_provenance_hash_status"] = "unavailable"
                    public_provenance["monthly_economy"] = summary
            source = _source_info(
                "NativeCountryStateSource", context,
                complete=False, provenance=public_provenance,
            )
            if fields and all(
                    isinstance(item, dict)
                    and item.get("status") == "unavailable"
                    for item in fields.values()):
                source["status"] = "unavailable"
            return _result(
                normalized, context, fields, False,
                source,
            )

        def unavailable(reason: str, context: dict[str, Any] = current) -> dict[str, Any]:
            provenance["context_guard"]["status"] = "unavailable"
            return result(context, {field: _unavailable(reason) for field in requested})

        reason = self._monthly_economy_context_reason(current, actor)
        if reason is not None:
            return unavailable(reason)

        before = current
        if context_supplied:
            try:
                before = self.context()
            except Exception:
                before = {}
            reason = self._monthly_economy_context_reason(before, actor)
            if reason is not None:
                return unavailable(reason)
            if (self._monthly_economy_context_identity(current)
                    != self._monthly_economy_context_identity(before)):
                provenance["context_guard"]["status"] = "stale"
                return result(
                    current, {
                        field: _unavailable("MONTHLY_ECONOMY_CONTEXT_STALE")
                        for field in requested
                    },
                )

        session = getattr(self.base_source, "session", None)
        if session is None:
            return unavailable("MONTHLY_ECONOMY_SESSION_UNAVAILABLE", before)
        try:
            directory = getattr(session, "directory", None)
            if directory is None:
                raise ValueError("session directory is missing")
            installation = Path(directory) / "installation.json"
            record = getattr(session, "record", None)
            if not isinstance(record, dict):
                raise ValueError("session record is missing")
            creation_filetime = record.get("creation_filetime")
            if type(creation_filetime) is not int:
                raise ValueError("session creation_filetime is missing")
            session_creation = getattr(session, "creation_filetime", None)
            if (session_creation is not None
                    and (type(session_creation) is not int
                         or session_creation != creation_filetime)):
                raise ValueError("session creation_filetime differs from record")
        except Exception:
            return unavailable("MONTHLY_ECONOMY_INSTALLATION_UNAVAILABLE", before)

        capture = self.monthly_economy_capture
        if capture is None:
            try:
                from .country_resources_memory import capture as capture
            except Exception:
                capture = None
        if not callable(capture):
            return unavailable("MONTHLY_ECONOMY_CAPTURE_UNAVAILABLE", before)

        report: Any = None
        capture_error: str | None = None
        try:
            report = capture(installation, actor, include_monthly_economy=True)
        except Exception as exc:
            capture_error = "MONTHLY_ECONOMY_CAPTURE_FAILED:" + type(exc).__name__

        # Always re-read the live context after an attempted capture.  A
        # failed/unknown reader must not skip this identity check.
        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = self._monthly_economy_context_reason(after, actor)
        if (after_reason is not None
                or self._monthly_economy_context_identity(before)
                != self._monthly_economy_context_identity(after)):
            provenance["context_guard"]["status"] = "changed"
            if isinstance(report, dict):
                self._record_capture_provenance(provenance, report)
            return result(
                before,
                {field: _unknown(after_reason or "MONTHLY_ECONOMY_CONTEXT_CHANGED")
                 for field in requested},
            )

        if capture_error is not None:
            provenance["context_guard"]["status"] = "capture_failed"
            return result(
                before,
                {field: _unknown(capture_error) for field in requested},
            )

        provenance["context_guard"]["status"] = "capture_invalid"
        if isinstance(report, dict):
            self._record_capture_provenance(provenance, report)
            monthly_record = report.get("monthly_economy")
            if isinstance(monthly_record, dict):
                provenance["monthly_economy"] = self._monthly_record_provenance(
                    monthly_record
                )
        reason = self._capture_report_reason(
            report, before, actor, creation_filetime
        )
        if reason is not None:
            provenance["capture_reason"] = (
                "MONTHLY_ECONOMY_PARENT_"
                + reason.removeprefix("MONARCH_POINTS_")
            )
            return result(
                before,
                {field: _unknown(provenance["capture_reason"])
                 for field in requested},
            )
        reason = self._monthly_capture_report_reason(report)
        if reason is not None:
            provenance["capture_reason"] = reason
            return result(
                before,
                {field: _unknown(reason) for field in requested},
            )

        monthly_record = report["monthly_economy"]
        provenance["context_guard"]["status"] = "passed"
        provenance["monthly_economy"] = self._monthly_record_provenance(
            monthly_record
        )
        fields: dict[str, dict[str, Any]] = {}
        for field in requested:
            if field == "war_income":
                # This is another projection of the same fully validated
                # ledger. It does not initiate a second capture or a pair
                # inspection, and does not change the three recurring totals.
                try:
                    from .war_income_projection import project
                    fields[field] = project(monthly_record)
                except Exception as exc:
                    fields[field] = _unknown(
                        "WAR_INCOME_PROJECTION_FAILED:" + type(exc).__name__
                    )
                provenance["war_income_projection"] = {
                    "basis": _WAR_INCOME_BASIS,
                    "status": fields[field].get("status", "unknown"),
                    "component_scope": "four_named_previous_month_income_slots",
                    "complete": False,
                }
                continue
            item = monthly_record["fields"][field]
            # All numeric/raw/guard checks have already passed through the
            # low-level validator and _monthly_record_shape_reason.
            fields[field] = {
                "status": "known",
                "value": item["value"],
                "raw": item["raw"],
                "raw_hex": item["raw_hex"],
                "unit": "ducats",
                "scale": 1000,
                "period": "month",
                "reference_period": _MONTHLY_ECONOMY_REFERENCE_PERIOD,
                "basis": _MONTHLY_ECONOMY_BASIS,
                "value_semantics": _MONTHLY_ECONOMY_VALUE_SEMANTICS,
                "value_origin": _MONTHLY_ECONOMY_VALUE_ORIGIN,
                "complete": False,
            }
        return result(before, fields)

    def _read_n01(self, normalized: dict[str, Any], current: dict[str, Any], *,
                  context_supplied: bool) -> dict[str, Any]:
        """Read treasury and/or ledger projections without cross-field fallback."""

        requested = normalized["fields"]
        monthly_requested = [
            field for field in requested if field in _N01_LEDGER_FIELDS
        ]
        if not monthly_requested:
            return self._read_public_projection_topic(
                normalized, current, context_supplied=context_supplied,
            )

        field_values: dict[str, dict[str, Any]] = {}
        field_sources: dict[str, Any] = {}

        if "treasury" in requested:
            treasury_query = dict(normalized, fields=["treasury"])
            treasury_result = self._read_public_projection_topic(
                treasury_query, current, context_supplied=context_supplied,
            )
            field_values["treasury"] = treasury_result["fields"]["treasury"]
            field_sources["treasury"] = deepcopy(treasury_result.get("source", {}))

        monthly_query = dict(normalized, fields=monthly_requested, parameters={})
        monthly_result = self._read_monthly_economy(
            monthly_query, current, context_supplied=context_supplied,
        )
        for field in monthly_requested:
            field_values[field] = monthly_result["fields"][field]
        field_sources["monthly_economy"] = deepcopy(monthly_result.get("source", {}))
        fields = {field: deepcopy(field_values[field]) for field in requested}
        monthly_source = monthly_result.get("source", {})
        monthly_source_provenance = (
            monthly_source.get("provenance", {})
            if isinstance(monthly_source, dict)
            else {}
        )
        combined_provenance: dict[str, Any] = {
            "mode": "mixed" if "treasury" in requested else "monthly",
            "field_sources": field_sources,
            "unit": "ducats",
            "scale": 1000,
            "period": "month",
            "reference_period": _MONTHLY_ECONOMY_REFERENCE_PERIOD,
            "basis": _MONTHLY_ECONOMY_BASIS,
            "value_semantics": _MONTHLY_ECONOMY_VALUE_SEMANTICS,
            "value_origin": _MONTHLY_ECONOMY_VALUE_ORIGIN,
            "gui_dynamic_estimate": "not_closed",
        }
        if (isinstance(monthly_source_provenance, dict)
                and "monthly_economy" in monthly_source_provenance):
            combined_provenance["monthly_economy"] = deepcopy(
                monthly_source_provenance["monthly_economy"]
            )
        return _result(
            normalized, current, fields, False,
            _source_info(
                "NativeCountryStateSource", current, complete=False,
                provenance=combined_provenance,
            ),
        )

    def _read_public_projection_topic(
        self, normalized: dict[str, Any], current: dict[str, Any], *,
        context_supplied: bool,
    ) -> dict[str, Any]:
        """Read native cache routes or the original public-projection path."""

        if normalized['topic'] == 'N02' and set(normalized['fields']) & {'max_manpower', 'max_sailors'}:
            if _time.active():
                from .own_resource_caches import read as read_caches
                sampled = read_caches(self.base_source, normalized, current)
                if sampled is not None:
                    return sampled
            reason = ('MAX_MANPOWER_CACHE_UNAVAILABLE' if _time.active()
                      else 'MAX_MANPOWER_SAMPLE_INACTIVE')
            fields = {field: _unknown(reason.replace('MAX_MANPOWER_', 'MAX_SAILORS_')
                                     if field == 'max_sailors' else reason)
                      for field in normalized['fields']}
            return _result(
                normalized, current, fields, False,
                _source_info(
                    'NativeCountryStateSource', current, complete=False,
                    provenance={'basis': 'native_country_max_manpower_cache',
                                'read_only': True, 'native_function_invoked': False},
                ),
            )
        if _time.active() and normalized['topic'] in ('N01', 'N02'):
            from .own_resource_caches import read as read_caches
            sampled = read_caches(self.base_source, normalized, current)
            if sampled is not None:
                return sampled
        actor = normalized["object"]["country"]
        recipient = normalized["parameters"].get("reference_recipient")
        if recipient is None:
            fields = {field: _unavailable("COUNTRY_RESOURCE_CACHE_UNAVAILABLE")
                      for field in normalized["fields"]}
            return _result(normalized, current, fields, False,
                _source_info("NativeCountryStateSource", current, complete=False,
                    provenance={"basis": "native_country_resource_caches",
                                "read_only": True, "native_function_invoked": False}))
        spec = _INSPECTIONS[normalized["topic"]]
        provenance = {
            "adapter": "DiplomacySource.inspect_diplomatic_action",
            "action_id": spec["action_id"],
            "phase": "initiate",
            "reference_recipient": recipient,
            "public_path": spec["path"],
            "read_only": True,
        }
        if current.get("status") != "ready":
            fields = {
                field: _unavailable("SESSION_UNREADY")
                for field in normalized["fields"]
            }
            return _result(
                normalized, current, fields, False,
                _source_info("NativeCountryStateSource", current,
                             complete=False, provenance=provenance),
            )
        inspected, error = self._inspect(
            self.base_source, spec["action_id"], actor, recipient,
            spec["parameters"],
        )
        if error is not None or inspected is None:
            fields = {
                field: _unavailable(error or "INSPECT_RESULT_INVALID")
                for field in normalized["fields"]
            }
            return _result(
                normalized, current, fields, False,
                _source_info("NativeCountryStateSource", current,
                             complete=False, provenance=provenance),
            )
        value, reason = self._extract(
            normalized["topic"], inspected, actor, recipient,
        )
        fields = {
            field: (_known(value) if reason is None else _unknown(reason))
            for field in normalized["fields"]
        }
        complete = all(item["status"] == "known" for item in fields.values())
        return _result(
            normalized, current, fields, complete,
            _source_info("NativeCountryStateSource", current,
                         complete=complete, provenance=provenance),
        )

    def _read_n06(self, normalized: dict[str, Any], current: dict[str, Any],
                  *, context_supplied: bool) -> dict[str, Any]:
        fields = normalized["fields"]
        if fields == ["monarch_points"]:
            return self._read_monarch_points(
                normalized, current, context_supplied=context_supplied)
        if fields == ["prestige"]:
            return self._read_prestige(
                normalized, current, context_supplied=context_supplied)

        # A mixed request is evaluated field by field.  A failure in one
        # reader remains explicit while the other reader may still provide a
        # value; neither reader is allowed to substitute the other's value.
        prestige_query = dict(normalized, fields=["prestige"])
        points_query = dict(normalized, fields=["monarch_points"])
        prestige_result = self._read_prestige(
            prestige_query, current, context_supplied=context_supplied)
        points_result = self._read_monarch_points(
            points_query, current, context_supplied=context_supplied)
        field_values = {
            "prestige": prestige_result["fields"]["prestige"],
            "monarch_points": points_result["fields"]["monarch_points"],
        }
        fields_result = {
            field: deepcopy(field_values[field]) for field in normalized["fields"]
        }
        complete = all(
            fields_result[field].get("status") == "known"
            for field in normalized["fields"]
        )
        provenance = {
            "mode": "mixed",
            "field_sources": {
                "prestige": deepcopy(prestige_result.get("source", {})),
                "monarch_points": deepcopy(points_result.get("source", {})),
            },
        }
        return _result(
            normalized, current, fields_result, complete,
            _source_info("NativeCountryStateSource", current,
                         complete=complete, provenance=provenance),
        )

    @staticmethod
    def _prestige_fields(normalized: dict[str, Any], status: str,
                         reason: str) -> dict[str, dict[str, str]]:
        return {
            field: {"status": status, "reason": reason}
            for field in normalized["fields"]
        }

    def _read_prestige(self, normalized: dict[str, Any], current: dict[str, Any],
                       *, context_supplied: bool) -> dict[str, Any]:
        """Read N06 only after an independent live identity revalidation."""

        actor = normalized["object"]["country"]
        recipient = normalized["parameters"]["reference_recipient"]
        provenance = {
            "adapter": "DiplomacySource.inspect_diplomatic_action",
            "action_id": "offer_vassalization",
            "phase": "initiate",
            "reference_recipient": recipient,
            "public_path": "prestige_raw",
            "read_only": True,
            "context_guard": {
                "mode": "live",
                "game_version": _PRESTIGE_GAME_VERSION,
                "game_sha256": _PRESTIGE_GAME_SHA256,
                "identity_keys": list(_PRESTIGE_CONTEXT_KEYS),
            },
        }

        reason = self._prestige_context_reason(current, actor)
        if reason is not None:
            fields = self._prestige_fields(normalized, "unavailable", reason)
            provenance["context_guard"]["status"] = "unavailable"
            return _result(
                normalized, current, fields, False,
                _source_info("NativeCountryStateSource", current,
                             complete=False, provenance=provenance),
            )

        before = current
        if context_supplied:
            try:
                before = self.context()
            except Exception:
                before = {}
            reason = self._prestige_context_reason(before, actor)
            if reason is not None:
                fields = self._prestige_fields(normalized, "unavailable", reason)
                provenance["context_guard"]["status"] = "unavailable"
                return _result(
                    normalized, current, fields, False,
                    _source_info("NativeCountryStateSource", current,
                                 complete=False, provenance=provenance),
                )
            if (self._prestige_context_identity(current)
                    != self._prestige_context_identity(before)):
                fields = self._prestige_fields(
                    normalized, "unavailable", "PRESTIGE_CONTEXT_STALE")
                provenance["context_guard"]["status"] = "stale"
                return _result(
                    normalized, current, fields, False,
                    _source_info("NativeCountryStateSource", current,
                                 complete=False, provenance=provenance),
                )

        inspected, error = self._inspect(
            self.base_source, "offer_vassalization", actor, recipient, {})
        if error is not None or inspected is None:
            fields = self._prestige_fields(
                normalized, "unavailable", error or "INSPECT_RESULT_INVALID")
            provenance["context_guard"]["status"] = "passed_before_query"
            return _result(
                normalized, before, fields, False,
                _source_info("NativeCountryStateSource", before,
                             complete=False, provenance=provenance),
            )

        try:
            after = self.context()
        except Exception:
            after = {}
        after_reason = self._prestige_context_reason(after, actor)
        if (after_reason is not None
                or self._prestige_context_identity(before)
                != self._prestige_context_identity(after)):
            fields = self._prestige_fields(
                normalized, "unknown",
                after_reason or "PRESTIGE_CONTEXT_CHANGED")
            provenance["context_guard"]["status"] = "changed"
            return _result(
                normalized, before, fields, False,
                _source_info("NativeCountryStateSource", before,
                             complete=False, provenance=provenance),
            )

        value, extract_reason = self._extract(
            "N06", inspected, actor, recipient)
        fields = {
            field: (_known(value) if extract_reason is None
                    else _unknown(extract_reason))
            for field in normalized["fields"]
        }
        complete = all(item["status"] == "known" for item in fields.values())
        provenance["context_guard"]["status"] = "passed"
        return _result(
            normalized, before, fields, complete,
            _source_info("NativeCountryStateSource", before,
                         complete=complete, provenance=provenance),
        )

    def read(self, query: dict, context: dict | None = None) -> dict:
        context_supplied = isinstance(context, dict)
        current = _copy(context) if context_supplied else self.context()
        normalized = self.validate_query(query, current)
        topic_id = normalized["topic"]
        if topic_id == "N06":
            return self._read_n06(
                normalized, current, context_supplied=context_supplied)
        if topic_id == "N01":
            return self._read_n01(
                normalized, current, context_supplied=context_supplied)
        if topic_id == "N02":
            return self._read_public_projection_topic(
                normalized, current, context_supplied=context_supplied)
        if topic_id == 'N05' and _time.active() and normalized['object']['country'] == 'FRA':
            from .diplomat_tasks import NativeDiplomatTasksSource
            task_query = dict(normalized, fields=['diplomat_tasks'], parameters={})
            sample = NativeDiplomatTasksSource(self.base_source).read(task_query, current)
            tasks = sample['fields'].get('diplomat_tasks', {})
            value = tasks.get('value', {})
            available = value.get('available_count_observed') if isinstance(value, dict) else None
            if tasks.get('status') == 'known' and type(available) is int and 0 <= available <= 256:
                return _result(normalized, current, {'diplomats_available': _known(available)}, True,
                    _source_info('NativeCountryStateSource', current, complete=True,
                        provenance={'basis': 'native_idle_diplomat_instance_count',
                                    'task_graph_source': deepcopy(sample.get('source', {})),
                                    'read_only': True, 'native_function_invoked': False}))
        actor = normalized["object"]["country"]
        recipient = normalized["parameters"]["reference_recipient"]
        spec = _INSPECTIONS[topic_id]
        provenance = {
            "adapter": "DiplomacySource.inspect_diplomatic_action",
            "action_id": spec["action_id"],
            "phase": "initiate",
            "reference_recipient": recipient,
            "public_path": spec["path"],
            "read_only": True,
        }
        if current.get("status") != "ready":
            fields = {field: _unavailable("SESSION_UNREADY") for field in normalized["fields"]}
            return _result(
                normalized, current, fields, False,
                _source_info("NativeCountryStateSource", current,
                             complete=False, provenance=provenance),
            )
        inspected, error = self._inspect(
            self.base_source, spec["action_id"], actor, recipient, spec["parameters"])
        if error is not None or inspected is None:
            fields = {field: _unavailable(error or "INSPECT_RESULT_INVALID")
                      for field in normalized["fields"]}
            return _result(
                normalized, current, fields, False,
                _source_info("NativeCountryStateSource", current,
                             complete=False, provenance=provenance),
            )
        value, reason = self._extract(topic_id, inspected, actor, recipient)
        fields = {
            field: (_known(value) if reason is None else _unknown(reason))
            for field in normalized["fields"]
        }
        complete = all(item["status"] == "known" for item in fields.values())
        return _result(
            normalized, current, fields, complete,
            _source_info("NativeCountryStateSource", current,
                         complete=complete, provenance=provenance),
        )

    def poll_events(self, context: dict | None, cursor: Any) -> dict:
        """This adapter is sampled state only; the wrapped source owns events."""

        if not isinstance(cursor, (dict, type(None))):
            raise InformationError("invalid_cursor", "cursor must be an object or null")
        return {
            "events": [],
            "cursor": deepcopy(cursor) if isinstance(cursor, dict) else {},
            "complete": True,
            "gaps": [],
        }


__all__ = ["NativeCountryStateSource"]
