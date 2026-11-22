"""Own a readonly node-value observation for a positively discovered center.

CWTools supplies script scope metadata.  Runtime admission comes from the
existing non-player FRA and positive province-discovery checks.  This partial
path does not establish every native trade visibility predicate or cache age.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import re

from . import foreign_technology_capture as _owner
from . import province_state_capture as _province_capture
from . import province_state_memory as _province
from . import trade_value_memory as _values
from .cwtools_rules import trade_node_scope_rule


SCHEMA = "information.trade_value_capture.v1"
INNER_SCHEMA = "information.trade_value_observer_snapshot.v1"
FIELDS = tuple("T03." + name for name in (
    "local_value", "incoming_value", "total_value", "outgoing_value", "collected_value"))
# The existing province callback contract accepts G02-prefixed private slots.
# Adapt those slots locally rather than changing the archived G02 reader.
_GATE_FIELDS = tuple("G02.t03_" + name.removeprefix("T03.") for name in FIELDS)
_NODE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_REASON = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")


def _valid_id(value):
    return isinstance(value, str) and value != "Null" and _NODE_ID.fullmatch(value) is not None


def _load_profile():
    # The source index remains historical evidence. Accept the audited live
    # revisions that bind trade-income and province reads to the configured country.
    reviewed_live_sources = {
        "bridge/information/trade_income_memory.py": (49815, "94620284bf2c35efde5499763972ee69bac62a16bfad3c7b179181e8ff818f5e"),
        "bridge/information/province_state_memory.py": (33452, "220a084f624200781aa8afa7c12d83fe34e35f6d7b019b664135a41273f747f5"),
    }
    value_profile = _values.load_profile()
    for item in value_profile["_validated_source_index"]["document"]["inputs"]:
        path = (_province_capture.ROOT / item["path"]).resolve()
        path.relative_to(_province_capture.ROOT)
        actual = (path.stat().st_size, _owner._sha(path))
        if actual != (item["bytes"], item["sha256"]) and actual != reviewed_live_sources.get(item["path"]):
            raise ValueError("TRADE_VALUE_PROFILE_DEPENDENCY")
    profile = deepcopy(_province_capture._load_profile())
    scope = trade_node_scope_rule()
    if (scope["name"] != "Trade Node" or scope["parents"] != ["Province"]
            or set(scope["aliases"]) != {"trade_node", "tradenode"}):
        raise ValueError("TRADE_VALUE_SCOPE_METADATA")
    guards = list(profile["code_guards"])
    seen = {(int(item["rva"], 0), item["bytes"]) for item in guards}
    for index, item in enumerate(_values.code_guards()):
        rva = int(item["rva"], 0) if isinstance(item["rva"], str) else item["rva"]
        raw = bytes.fromhex(item["bytes"])
        if type(rva) is not int or rva < 0 or not 0 < len(raw) <= 65536:
            raise ValueError("TRADE_VALUE_CODE_GUARD")
        if (rva, raw.hex()) in seen:
            continue
        guards.append({"name": f"trade_value_{index}", "rva": hex(rva),
                       "end_rva_exclusive": hex(rva + len(raw)),
                       "bytes": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest()})
        seen.add((rva, raw.hex()))
    if len(guards) == len(profile["code_guards"]):
        raise ValueError("TRADE_VALUE_CODE_GUARDS_MISSING")
    profile["code_guards"] = guards
    profile["trade_node_scope_rule"] = scope
    return profile


def _observe_for(node_id):
    def observe(reader, base, country, profile):
        if country != "FRA" or not _valid_id(node_id):
            raise ValueError("TRADE_VALUE_OBSERVER_SCOPE")

        def backend(read, module_base, observer):
            if observer != "FRA":
                raise ValueError("TRADE_VALUE_OBSERVER_SCOPE")
            # Identity resolution reads no financial caches.  The financial
            # leaf is invoked only after the province reader admits discovery.
            identity = _values.find_node(read, module_base, node_id)
            center = identity.get("center_province_id")
            if (identity.get("status") != "known" or identity.get("node_id") != node_id
                    or type(center) is not int or not 1 <= center < 65536):
                raise ValueError("TRADE_VALUE_NODE_IDENTITY_UNKNOWN")

            def fields(limiter, value_base, province_binding, selected):
                if tuple(selected) != _GATE_FIELDS:
                    raise ValueError("TRADE_VALUE_GATE_FIELD_SCOPE")
                values = _values.read_fields(limiter, value_base, province_binding,
                                            FIELDS, node_id=node_id)
                return {alias: values[name] for alias, name in zip(_GATE_FIELDS, FIELDS)}

            result = _province.read_two_pass(read, module_base, center, observer="FRA",
                                             fields=_GATE_FIELDS, read_fields=fields)
            for target in result.get("targets", []):
                for key in ("fields", "field_consistency"):
                    rows = target.get(key, {})
                    target[key] = {name: rows[alias] for alias, name in zip(_GATE_FIELDS, FIELDS)}
            result["trade_node"] = {"node_id": node_id, "center_province_id": center,
                                    "selection_identity": identity}
            result["trade_node_scope_rule"] = deepcopy(profile["trade_node_scope_rule"])
            return result

        return _owner._observe(reader, base, country, profile, backend_reader=backend)
    return observe


def capture(installation, node_id, *, observer="FRA"):
    if observer != "FRA" or not _valid_id(node_id):
        raise ValueError("TRADE_VALUE_REQUEST_SCOPE")
    inner = _owner._capture_common(
        installation, "FRA", observer=observer, schema=INNER_SCHEMA,
        profile_sha256=_values.PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(node_id), allow_observer_target=True)
    return {"schema": SCHEMA, "observer": "FRA",
            "object": {"type": "trade_node", "node_id": node_id}, "capture": inner}


def validate_capture(report, context, creation, node_id):
    if not _valid_id(node_id) or not isinstance(report, dict):
        return False
    if (set(report) != {"schema", "observer", "object", "capture"}
            or report["schema"] != SCHEMA or report["observer"] != "FRA"
            or not _owner._same(report["object"], {"type": "trade_node", "node_id": node_id})):
        return False
    return _owner._validate_capture_common(
        report["capture"], context, creation, "FRA", schema=INNER_SCHEMA,
        profile_sha256=_values.PROFILE_SHA256, load_profile=_load_profile,
        observe=_observe_for(node_id), allow_observer_target=True, require_access=True)


def _unknown(reason):
    return {"status": "unknown", "reason": reason}


def _int32(value):
    return type(value) is int and -(1 << 31) <= value < (1 << 31)


def _target(report, *, observer_scoped=False):
    observer = report.get("observer") if isinstance(report, Mapping) else None
    if (not isinstance(observer, str) or not _owner._TAG.fullmatch(observer)
            or report.get("schema") != SCHEMA or (not observer_scoped and observer != "FRA")):
        return None
    obj = report.get("object", {})
    if (not isinstance(obj, Mapping) or obj.get("type") != "trade_node"
            or not _valid_id(obj.get("node_id"))):
        return None
    inner = report.get("capture", {})
    if (inner.get("schema") != INNER_SCHEMA or inner.get("status") != "observed"
            or inner.get("completed") is not True):
        return None
    observation = inner.get("observation", {})
    backend = observation.get("backend", {})
    targets = backend.get("targets")
    node = backend.get("trade_node", {})
    if (observation.get("stable") is not True or backend.get("status") != "observed"
            or backend.get("consistency", {}).get("status") != "stable"
            or node.get("node_id") != obj["node_id"]
            or type(node.get("center_province_id")) is not int
            or not isinstance(targets, list) or len(targets) != 1):
        return None
    target = targets[0]
    if target.get("province_id") != node["center_province_id"]:
        return None
    for phase in ("pass1", "pass2"):
        admission = target.get("admission_by_pass", {}).get(phase) or {}
        discovery = target.get("discovery_by_pass", {}).get(phase) or {}
        if (admission.get("status") != "known" or admission.get("admitted") is not True
                or admission.get("observer_nonplayer_role", {}).get("verified") is not True
                or discovery.get("status") != "known" or discovery.get("value") is not True):
            return None
    return target


def project_fields(report, *, observer_scoped=False):
    """Whitelist values after strict saved-trace validation by the caller.

    No addresses, raw-input dictionaries or destination province details pass
    through this boundary. Unknown collected value is independent of capture.
    """
    projected = {name.removeprefix("T03."): _unknown("TRADE_VALUE_ADMISSION_NOT_ESTABLISHED")
                 for name in FIELDS}
    projected["collected_value"] = _unknown("NODE_COLLECTED_VALUE_NOT_PROVEN")
    target = _target(report, observer_scoped=observer_scoped)
    if target is None:
        return projected
    for name in FIELDS[:-1]:
        public_name = name.removeprefix("T03.")
        field = target.get("fields", {}).get(name) or {}
        if target.get("field_consistency", {}).get(name, {}).get("status") != "stable":
            projected[public_name] = _unknown("TRADE_VALUE_FIELD_NOT_STABLE")
            continue
        if field.get("status") != "known":
            reason = field.get("reason")
            projected[public_name] = _unknown(reason if isinstance(reason, str) and _REASON.fullmatch(reason)
                                             else "TRADE_VALUE_FIELD_UNKNOWN")
            continue
        value = field.get("value")
        if public_name == "outgoing_value":
            if not isinstance(value, Mapping) or not _int32(value.get("total_raw")):
                projected[public_name] = _unknown("TRADE_VALUE_OUTGOING_INVALID")
                continue
            routes = value.get("routes")
            if (not isinstance(routes, list) or len(routes) > 32
                    or any(not isinstance(row, Mapping) or not _valid_id(row.get("node_id"))
                           or not _int32(row.get("raw")) for row in routes)):
                projected[public_name] = _unknown("TRADE_VALUE_OUTGOING_INVALID")
                continue
            raw = value["total_raw"]
            safe_value = {"total_raw": raw,
                          "routes": [{"node_id": row["node_id"], "raw": row["raw"]} for row in routes]}
        else:
            if not _int32(value):
                projected[public_name] = _unknown("TRADE_VALUE_SIGNED_RAW_INVALID")
                continue
            raw = value
            safe_value = value
        projected[public_name] = {
            "status": "known", "value": safe_value, "raw": raw,
            "raw_hex": raw.to_bytes(4, "little", signed=True).hex(),
            "scale": 1000, "unit": "ducats", "period": "current",
            "basis": "native_trade_node_cache", "complete": False}
    return projected


__all__ = ["capture", "validate_capture", "project_fields"]
