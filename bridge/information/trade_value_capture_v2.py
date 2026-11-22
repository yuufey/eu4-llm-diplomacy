"""T03 v2 capture with node retention amount and explicit v1 saved replay."""
from __future__ import annotations

from copy import deepcopy

from . import trade_value_capture as legacy
from . import trade_value_memory_v2 as values

SCHEMA = "information.trade_value_capture.v2"
INNER_SCHEMA = "information.trade_value_observer_snapshot.v2"
FIELDS = legacy.FIELDS


def _load_profile():
    values.load_profile()
    # New tooltip guards qualify only collected_value inside the leaf.  A
    # missing tooltip path does not withdraw four independently guarded fields.
    profile = legacy._load_profile()
    profile["trade_collected_profile_sha256"] = values.PROFILE_SHA256
    return profile


def _observe_for(node_id, observer="FRA"):
    def observe(reader, base, country, profile):
        if country != observer or not legacy._valid_id(node_id):
            raise ValueError("TRADE_VALUE_OBSERVER_SCOPE")

        def backend(read, module_base, bound_observer):
            identity = legacy._values.find_node(read, module_base, node_id)
            center = identity.get("center_province_id")
            if (bound_observer != observer or identity.get("status") != "known"
                    or identity.get("node_id") != node_id or type(center) is not int or not 1 <= center < 65536):
                raise ValueError("TRADE_VALUE_NODE_IDENTITY_UNKNOWN")

            def field_reader(limiter, value_base, binding, selected):
                if tuple(selected) != legacy._GATE_FIELDS:
                    raise ValueError("TRADE_VALUE_GATE_FIELD_SCOPE")
                fields = values.read_fields(limiter, value_base, binding, FIELDS, node_id=node_id)
                return {alias: fields[name] for alias, name in zip(legacy._GATE_FIELDS, FIELDS)}

            result = legacy._province.read_two_pass(read, module_base, center, observer=observer,
                fields=legacy._GATE_FIELDS, read_fields=field_reader, observer_scoped=True)
            for target in result.get("targets", []):
                for key in ("fields", "field_consistency"):
                    rows = target.get(key, {})
                    target[key] = {name: rows[alias] for alias, name in zip(legacy._GATE_FIELDS, FIELDS)}
            result["trade_node"] = {"node_id": node_id, "center_province_id": center,
                                    "selection_identity": identity}
            result["trade_node_scope_rule"] = deepcopy(profile["trade_node_scope_rule"])
            return result

        return legacy._owner._observe(reader, base, country, profile, backend_reader=backend)
    return observe


def capture(installation, node_id, *, observer="FRA"):
    if (not isinstance(observer, str) or not legacy._owner._TAG.fullmatch(observer)
            or not legacy._valid_id(node_id)):
        raise ValueError("TRADE_VALUE_REQUEST_SCOPE")
    inner = legacy._owner._capture_common(
        installation, observer, observer=observer, schema=INNER_SCHEMA,
        profile_sha256=values.PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(node_id, observer), allow_observer_target=True, observer_scoped=True)
    return {"schema": SCHEMA, "observer": observer, "object": {"type": "trade_node", "node_id": node_id},
            "capture": inner}


def validate_capture(report, context, creation, node_id):
    if isinstance(report, dict) and report.get("schema") == legacy.SCHEMA:
        return legacy.validate_capture(report, context, creation, node_id)
    observer = context.get("observer") if isinstance(context, dict) else None
    if (not legacy._valid_id(node_id) or not isinstance(report, dict)
            or set(report) != {"schema", "observer", "object", "capture"}
            or report["schema"] != SCHEMA or report["observer"] != observer
            or not legacy._owner._same(report["object"], {"type": "trade_node", "node_id": node_id})):
        return False
    inner = report['capture']
    profile_sha256 = values.PROFILE_SHA256
    if (observer == 'FRA' and isinstance(inner, dict)
            and inner.get('profile_sha256') == values.LEGACY_PROFILE_SHA256):
        profile_sha256 = values.LEGACY_PROFILE_SHA256
    return legacy._owner._validate_capture_common(
        inner, context, creation, observer, schema=INNER_SCHEMA,
        profile_sha256=profile_sha256, load_profile=_load_profile,
        observe=_observe_for(node_id, observer), allow_observer_target=True,
        require_access=True, observer_scoped=True)


def project_fields(report):
    if isinstance(report, dict) and report.get("schema") == legacy.SCHEMA:
        return legacy.project_fields(report)
    if (not isinstance(report, dict) or report.get("schema") != SCHEMA
            or not isinstance(report.get("capture"), dict)
            or report["capture"].get("schema") != INNER_SCHEMA):
        return {name.removeprefix("T03."): legacy._unknown("TRADE_VALUE_CAPTURE_SHAPE_INVALID") for name in FIELDS}
    view = {**report, "schema": legacy.SCHEMA,
            "capture": {**report["capture"], "schema": legacy.INNER_SCHEMA}}
    result = legacy.project_fields(view, observer_scoped=True)
    target = legacy._target(view, observer_scoped=True)
    if target is None:
        result["collected_value"] = legacy._unknown("TRADE_VALUE_ADMISSION_NOT_ESTABLISHED")
        return result
    field = target.get("fields", {}).get("T03.collected_value") or {}
    consistency = target.get("field_consistency", {}).get("T03.collected_value", {})
    if field.get("status") == "known" and consistency.get("status") == "stable" and legacy._int32(field.get("value")):
        raw = field["value"]
        result["collected_value"] = {"status": "known", "value": raw, "raw": raw,
                                    "raw_hex": raw.to_bytes(4, "little", signed=True).hex(),
                                    "scale": 1000, "unit": "ducats", "period": "current", "complete": False,
                                    "basis": "native_trade_node_retention_tooltip_amount",
                                    "value_origin": "derived_from_native_ui_cache_inputs"}
    else:
        reason = field.get("reason", "NODE_RETENTION_VALUE_NOT_STABLE")
        result["collected_value"] = legacy._unknown(
            reason if isinstance(reason, str) and legacy._REASON.fullmatch(reason) else "NODE_RETENTION_VALUE_UNKNOWN")
    return result


__all__ = ["capture", "validate_capture", "project_fields"]
