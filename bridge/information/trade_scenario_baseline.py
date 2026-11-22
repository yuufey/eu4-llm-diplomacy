"""Project the trade-scenario baseline from one validated T04 capture.

This reader deliberately does not invoke T05.  T04 already captures and
validates both native trade children from one country-resources report, so the
income and collection values below are projected from that same validated
report and never cached between reads.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Mapping

from .model import canonical
from .trade_income import NativeTradeIncomeSource
from .trade_power import NativeTradePowerSource
from . import trade_power_memory


_POWER_FIELDS = ("country_power", "total_power")
_BASELINE_FIELDS = ("income", "collection", "country_power", "total_power")
_COMPONENT_KEYS = ("0x44", "0x48", "0x4c", "0x50", "0x54")
_INCOME_CALCULATION_BASIS = "native_current_trade_income_cache_arithmetic"
_INCOME_CALCULATION_INPUTS = {
    "share_raw", "node_cash_raw", "country_base_raw", "modifier_raw", "bonus_raw", "bonus_applies",
}
_INCOME_CALCULATION_OUTPUTS = {
    "clamped_modifier_raw", "multiplier_raw", "income_before_multiplier_raw", "income_raw",
}
_INCOME_CALCULATION_CACHE = {"income_before_multiplier_raw", "income_raw"}


def _native_components(source, fields, node_id):
    """Project only the components already admitted by the T04 validator."""
    failure = _unknown("TRADE_SCENARIO_NATIVE_COMPONENTS_INVALID")
    provenance = source.get("provenance", {})
    guard = provenance.get("context_guard", {})
    power = provenance.get("trade_power", {})
    if (not isinstance(guard, Mapping) or guard.get("status") != "passed"
            or not isinstance(power, Mapping)
            or power.get("profile_sha256") != trade_power_memory.EXPECTED_PROFILE_SHA256):
        return failure
    node = power.get("node")
    if not isinstance(node, Mapping) or node.get("node_id") != node_id:
        return failure
    components = node.get("entry_power_components_raw")
    if (not isinstance(components, Mapping) or set(components) != set(_COMPONENT_KEYS)
            or any(type(components[k]) is not int or not -(1 << 31) <= components[k] < (1 << 31)
                   for k in _COMPONENT_KEYS)):
        return failure
    encoded = b"".join(components[k].to_bytes(4, "little", signed=True) for k in _COMPONENT_KEYS).hex()
    if node.get("entry_power_components_raw_hex") != encoded:
        return failure
    for name in _POWER_FIELDS:
        field = fields.get(name)
        if (not isinstance(field, Mapping) or field.get("status") != "known"
                or type(field.get("raw")) is not int or field.get("value") != field["raw"]
                or node.get(name + "_raw") != field["raw"]):
            return failure
    return {"status": "known", "value": dict(zip(
        ("multiplier_raw", "cap_raw", "base_raw", "subtract_raw", "add_raw"),
        (components[k] for k in _COMPONENT_KEYS))),
        "basis": "native_trade_node_power_caches", "scale": 1000,
        "period": "current", "complete": False}


def _unknown(reason: str) -> dict[str, Any]:
    return {"status": "unknown", "reason": reason}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _sum_membership(report):
    """Admit only a replayed child tied to each real parent pass."""
    failure = _unknown("TRADE_SCENARIO_SUM_MEMBERSHIP_UNVERIFIED")
    try:
        from . import trade_power_sum_capture as sum_capture
        if report.get("request", {}).get("include_trade_power_sum") is not True:
            return failure
        records = []
        for phase in ("before", "after"):
            snapshot = report[phase]
            record = snapshot["trade_power_sum"]
            if not sum_capture.validate_record(record, snapshot["trade_income"],
                    snapshot["country_scan"], snapshot["read_log"]):
                return failure
            records.append(record)
        if canonical(records[0]) != canonical(records[1]) or canonical(report["trade_power_sum"]) != canonical(records[1]):
            return failure
        observed = records[1]["observation"]
        membership = observed["membership"]
        country = report["after"]["trade_income"]["country"]
        value = {"observer": country, "country_slot": observed["country_slot"],
            "member_count": membership["member_count"],
            "observer_occurrences": membership["observer_occurrences"],
            "fullref_occurrences": membership["fullref_occurrences"],
            "slot_occurrences": membership["slot_occurrences"],
            "observer_nonplayer_verified": observed["observer_nonplayer_verified"],
            "canonical_observer_verified": observed["canonical_observer_verified"],
            "stable": observed["stable"]}
        return {"status": "known", "basis": "native_global_country_power_sum_membership",
                "period": "current", "complete": False, "value": value}
    except Exception:
        return failure


def _income_calculation_value(observation: Any, node_id: str) -> dict[str, Any] | None:
    if (not isinstance(observation, Mapping) or observation.get("status") != "observed"
            or observation.get("node_id") != node_id or observation.get("stable") is not True
            or observation.get("basis") != _INCOME_CALCULATION_BASIS
            or observation.get("period") != "current" or observation.get("complete") is not False):
        return None
    value = observation.get("value")
    if not isinstance(value, Mapping) or set(value) != {"inputs", "outputs", "cache", "matches_cache"}:
        return None
    inputs = value.get("inputs")
    outputs = value.get("outputs")
    cache = value.get("cache")
    if (not isinstance(inputs, Mapping) or set(inputs) != _INCOME_CALCULATION_INPUTS
            or type(inputs.get("bonus_applies")) is not bool
            or not isinstance(outputs, Mapping) or set(outputs) != _INCOME_CALCULATION_OUTPUTS
            or not isinstance(cache, Mapping) or set(cache) != _INCOME_CALCULATION_CACHE
            or type(value.get("matches_cache")) is not bool):
        return None
    int32 = lambda item: type(item) is int and -(1 << 31) <= item < (1 << 31)
    if (any(not int32(inputs[key]) for key in _INCOME_CALCULATION_INPUTS - {"bonus_applies"})
            or any(not int32(item) for item in outputs.values())
            or any(not int32(item) for item in cache.values())
            or not 10 <= outputs["clamped_modifier_raw"] <= 2000):
        return None
    if value["matches_cache"] is not all(
            outputs[key] == cache[key] for key in _INCOME_CALCULATION_CACHE):
        return None
    return deepcopy(dict(value))


def _native_income_calculation(report: Any, node_id: str):
    unknown_reason = "TRADE_SCENARIO_INCOME_CALCULATION_UNVERIFIED"
    proof = {"status": "unknown", "basis": _INCOME_CALCULATION_BASIS,
             "node_id": node_id, "parent_trace_bound": False,
             "doublepass_consistent": False, "reason": unknown_reason}

    def fail(reason: str = unknown_reason):
        failed_proof = dict(proof, reason=reason)
        return _unknown(reason), failed_proof

    try:
        if not isinstance(report, Mapping):
            return fail()
        request = report.get("request")
        if (not isinstance(request, Mapping)
                or request.get("trade_income_node_id") != node_id
                or request.get("include_trade_power_sum") is not True):
            return fail("TRADE_SCENARIO_INCOME_SELECTOR_UNVERIFIED")
        doublepass = report.get("doublepass")
        if not isinstance(doublepass, Mapping) or doublepass.get("consistent") is not True:
            return fail("TRADE_SCENARIO_INCOME_DOUBLEPASS_UNVERIFIED")
        sum_result = _sum_membership(report)
        if sum_result.get("status") != "known":
            return fail("TRADE_SCENARIO_SUM_MEMBERSHIP_UNVERIFIED")

        from . import trade_income_calculation_capture as income_capture
        records = []
        for phase in ("before", "after"):
            snapshot = report.get(phase)
            if not isinstance(snapshot, Mapping):
                return fail()
            record = snapshot.get("trade_income_calculation")
            trade_record = snapshot.get("trade_income")
            country_scan = snapshot.get("country_scan")
            sum_record = snapshot.get("trade_power_sum")
            parent_read_log = snapshot.get("read_log")
            if (not isinstance(record, Mapping)
                    or record.get("node_id") != node_id
                    or not income_capture.validate_record(
                        record, trade_record, country_scan, sum_record,
                        node_id=node_id, parent_read_log=parent_read_log)):
                return fail("TRADE_SCENARIO_INCOME_CHILD_UNVERIFIED")
            records.append(record)
        top_record = report.get("trade_income_calculation")
        if (not isinstance(top_record, Mapping)
                or canonical(records[0]) != canonical(records[1])
                or canonical(top_record) != canonical(records[1])):
            return fail("TRADE_SCENARIO_INCOME_CHILD_DOUBLEPASS_MISMATCH")

        record = records[1]
        observation = record.get("observation")
        value = _income_calculation_value(observation, node_id)
        if value is None or record.get("complete") is not False:
            return fail("TRADE_SCENARIO_INCOME_VALUE_UNVERIFIED")
        digest = hashlib.sha256(canonical(record).encode("utf-8")).hexdigest()
        known = {
            "status": "known", "value": value,
            "basis": _INCOME_CALCULATION_BASIS,
            "period": "current", "complete": False,
        }
        proof = {
            "status": "known", "basis": _INCOME_CALCULATION_BASIS,
            "node_id": node_id, "profile_sha256": record["profile_sha256"],
            "record_canonical_sha256": digest,
            "parent_trace_bound": True, "doublepass_consistent": True,
        }
        return known, proof
    except Exception:
        return fail()


def _report_sha256(report: Any) -> str | None:
    if not isinstance(report, Mapping):
        return None
    try:
        return hashlib.sha256(canonical(report).encode("utf-8")).hexdigest()
    except Exception:
        return None


def _failure_reason(power_result: Mapping[str, Any], power_fields: Mapping[str, Any]) -> str:
    for field in _POWER_FIELDS:
        item = power_fields.get(field)
        if isinstance(item, Mapping):
            reason = item.get("reason")
            if isinstance(reason, str) and reason:
                return reason
    source = power_result.get("source")
    provenance = source.get("provenance") if isinstance(source, Mapping) else None
    reason = provenance.get("capture_reason") if isinstance(provenance, Mapping) else None
    if isinstance(reason, str) and reason:
        return reason
    return "TRADE_SCENARIO_BASELINE_VALIDATION_REQUIRED"


def _failure_status(power_result: Mapping[str, Any], power_fields: Mapping[str, Any]) -> str:
    source = power_result.get("source")
    if isinstance(source, Mapping) and source.get("status") == "unavailable":
        return "unavailable"
    if all(
        isinstance(power_fields.get(field), Mapping)
        and power_fields[field].get("status") == "unavailable"
        for field in _POWER_FIELDS
    ):
        return "unavailable"
    return "unknown"


def _source_with_baseline_provenance(
    power_result: Mapping[str, Any], report: Any, capture_calls: int,
) -> dict[str, Any]:
    value = power_result.get("source")
    source = deepcopy(dict(value)) if isinstance(value, Mapping) else {
        "name": "NativeTradePowerSource",
        "mode": "live",
        "status": "unavailable",
        "complete": False,
    }
    provenance = source.get("provenance")
    if not isinstance(provenance, dict):
        provenance = {}
        source["provenance"] = provenance
    provenance["single_parent_capture"] = capture_calls == 1
    provenance["capture_calls"] = capture_calls
    provenance["atomic_snapshot"] = False
    provenance["report_canonical_sha256"] = _report_sha256(report)
    return source


class TradeScenarioBaselineReader:
    """Read income, collection, and power using a single validated T04 report."""

    supports_native_power_components = True
    supports_native_power_sum = True
    supports_native_income_calculation = True

    def __init__(self, power_source: NativeTradePowerSource):
        self.power_source = power_source

    def context(self) -> dict[str, Any]:
        return self.power_source.context()

    def read(self, node_id: str, context: dict[str, Any] | None = None,
             *, with_power_components: bool = False, with_sum_membership: bool = False,
             with_income_calculation: bool = False) -> dict[str, Any]:
        capture_reader = self.power_source._capture_reader()
        capture_state: dict[str, Any] = {"calls": 0, "report": None}

        def capture_wrapper(*args: Any, **kwargs: Any) -> Any:
            if capture_state["calls"] != 0:
                raise RuntimeError("TRADE_SCENARIO_BASELINE_MULTIPLE_CAPTURE")
            capture_state["calls"] = 1
            if not callable(capture_reader):
                raise RuntimeError("TRADE_SCENARIO_BASELINE_CAPTURE_UNAVAILABLE")
            if with_sum_membership or with_income_calculation:
                kwargs["include_trade_power_sum"] = True
            if with_income_calculation:
                kwargs["trade_income_node_id"] = node_id
            report = capture_reader(*args, **kwargs)
            capture_state["report"] = report
            return report

        # The temporary source keeps the production T04 validation path intact
        # while isolating the report tap to this one read.
        power_reader = NativeTradePowerSource(
            self.power_source.base_source,
            capture=capture_wrapper,
        )
        query = {
            "topic": "T04",
            "object": {"type": "trade_node", "node_id": node_id},
            "fields": list(_POWER_FIELDS),
            "parameters": {},
        }
        power_result = power_reader.read(query, context)
        report = capture_state["report"]
        source = _source_with_baseline_provenance(power_result, report, capture_state["calls"])
        power_fields_value = power_result.get("fields")
        power_fields = power_fields_value if isinstance(power_fields_value, Mapping) else {}

        fields: dict[str, Any] = {}
        guard = source.get("provenance", {}).get("context_guard")
        guard_passed = isinstance(guard, Mapping) and guard.get("status") == "passed"
        power_fields_known = all(
            isinstance(power_fields.get(name), Mapping)
            and power_fields[name].get("status") == "known"
            for name in _POWER_FIELDS
        )

        if not guard_passed or not power_fields_known:
            reason = _failure_reason(power_result, power_fields)
            status = _failure_status(power_result, power_fields)
            factory = _unavailable if status == "unavailable" else _unknown
            for name in _BASELINE_FIELDS:
                item = power_fields.get(name)
                if guard_passed and name in _POWER_FIELDS and isinstance(item, Mapping):
                    # Preserve T04's field-specific safe reason/status.
                    fields[name] = deepcopy(dict(item))
                else:
                    fields[name] = factory(reason)
            result = {
                "status": status,
                "reason": reason,
                "node_id": node_id,
                "fields": fields,
                "source": source,
                "complete": False,
            }
            if with_power_components:
                result["native_power_components"] = _unknown(reason)
            if with_sum_membership:
                result["native_power_sum_membership"] = _unknown(reason)
            if with_income_calculation:
                result["native_income_calculation"] = _unknown(reason)
                source["provenance"]["trade_income_calculation"] = {
                    "status": "unknown", "basis": _INCOME_CALCULATION_BASIS,
                    "node_id": node_id, "parent_trace_bound": False,
                    "doublepass_consistent": False, "reason": reason,
                }
            return result

        record = report.get("trade_income") if isinstance(report, Mapping) else None
        nodes = record.get("nodes") if isinstance(record, Mapping) else None
        if not isinstance(nodes, list):
            reason = "TRADE_INCOME_NODES_INVALID"
            fields["income"] = _unknown(reason)
            fields["collection"] = _unknown(reason)
        else:
            matches = [
                node for node in nodes
                if isinstance(node, Mapping) and node.get("node_id") == node_id
            ]
            if len(matches) == 0:
                fields["income"] = _unknown("NODE_NOT_FOUND")
                fields["collection"] = _unknown("NODE_NOT_FOUND")
            elif len(matches) != 1:
                fields["income"] = _unknown("NODE_ID_NOT_UNIQUE")
                fields["collection"] = _unknown("NODE_ID_NOT_UNIQUE")
            else:
                node = matches[0]
                try:
                    fields["income"] = NativeTradeIncomeSource._field_from_node(
                        power_reader, node,
                    )
                except Exception:
                    fields["income"] = _unknown("TRADE_INCOME_PROJECTION_INVALID")
                try:
                    fields["collection"] = NativeTradeIncomeSource._field_from_collection_node(node)
                except Exception:
                    fields["collection"] = _unknown("TRADE_INCOME_COLLECTION_PROJECTION_INVALID")

        for name in _POWER_FIELDS:
            item = power_fields.get(name)
            fields[name] = deepcopy(dict(item)) if isinstance(item, Mapping) else _unknown(
                "TRADE_POWER_FIELD_MISSING"
            )

        status = "known" if all(
            isinstance(fields.get(name), Mapping)
            and fields[name].get("status") == "known"
            for name in _BASELINE_FIELDS
        ) else "unknown"
        result = {
            "status": status,
            "node_id": node_id,
            "fields": fields,
            "source": source,
            "complete": False,
        }
        if with_power_components:
            result["native_power_components"] = _native_components(source, fields, node_id)
        if with_sum_membership:
            result["native_power_sum_membership"] = _sum_membership(report)
            qualified = result["native_power_sum_membership"]
            proof = {"status": qualified["status"], "basis": "native_global_country_power_sum_membership"}
            if qualified["status"] == "known":
                proof.update(profile_sha256=report["trade_power_sum"]["profile_sha256"],
                    record_canonical_sha256=hashlib.sha256(canonical(report["trade_power_sum"]).encode("utf-8")).hexdigest(),
                    doublepass_consistent=True, parent_trace_bound=True,
                    native_country_view_admission_invoked=False)
            else:
                proof["reason"] = qualified["reason"]
            source["provenance"]["trade_power_sum"] = proof
        if with_income_calculation:
            result["native_income_calculation"], proof = _native_income_calculation(report, node_id)
            source["provenance"]["trade_income_calculation"] = proof
        if status != "known":
            result["reason"] = next((field.get("reason") for field in fields.values()
                                     if isinstance(field, Mapping) and field.get("reason")),
                                    "TRADE_SCENARIO_BASELINE_PROJECTION_INCOMPLETE")
        return result


__all__ = ["TradeScenarioBaselineReader"]
