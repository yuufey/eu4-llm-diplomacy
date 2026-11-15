from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import trade_income_calculation_capture as income_capture
from bridge.information import trade_power_sum_capture as sum_capture
from bridge.information import trade_scenario_baseline as baseline_module
from bridge.information.trade_income import NativeTradeIncomeSource
from bridge.information.trade_scenario_baseline import TradeScenarioBaselineReader
from bridge.information.trade_scenarios import TradeScenarioSource
from bridge.tests import test_information_trade_scenarios_integration as scenario_fixtures


NODE_ID = "alpha"
INCOME_BASIS = "native_current_trade_income_cache_arithmetic"
SUM_BASIS = "native_global_country_power_sum_membership"
INPUTS = {
    "share_raw": 408,
    "node_cash_raw": 9221,
    "country_base_raw": 120,
    "modifier_raw": 0,
    "bonus_raw": 100,
    "bonus_applies": True,
}
OUTPUTS = {
    "clamped_modifier_raw": 120,
    "multiplier_raw": 1220,
    "income_before_multiplier_raw": 3762,
    "income_raw": 4589,
}
CACHE = {"income_before_multiplier_raw": 3762, "income_raw": 4589}
INCOME_VALUE = {"inputs": INPUTS, "outputs": OUTPUTS, "cache": CACHE, "matches_cache": True}
PROFILE_SHA256 = "d" * 64
TRADE_RECORD = {"status": "observed", "nodes": [{"node_id": NODE_ID, "income_raw": 1000}]}
COUNTRY_SCAN = {"status": "observed", "requested_country": "FRA", "fixture": "canonical-country"}
SUM_RECORD = {
    "status": "observed",
    "profile_sha256": "s" * 64,
    "_fixture_valid": True,
    "observation": {
        "country_slot": 42,
        "stable": True,
        "canonical_observer_verified": True,
        "observer_nonplayer_verified": True,
        "membership": {
            "member_count": 256,
            "observer_occurrences": 1,
            "fullref_occurrences": 1,
            "slot_occurrences": 1,
        },
    },
}
CHILD_READS = [{
    "address": "0x1000", "size": 4,
    "label": "trade_income_calculation.country_base", "raw_hex": "78000000",
}]


def _child_record(node_id: str = NODE_ID) -> dict:
    return {
        "schema": "information.trade_income_calculation_capture.v1",
        "status": "observed",
        "profile_sha256": PROFILE_SHA256,
        "node_id": node_id,
        "complete": False,
        "raw_reads": deepcopy(CHILD_READS),
        "observation": {
            "status": "observed",
            "basis": INCOME_BASIS,
            "period": "current",
            "node_id": node_id,
            "stable": True,
            "complete": False,
            "value": deepcopy(INCOME_VALUE),
        },
    }


def _report_builder(*, selector_override=None, child_status="observed",
                    alter_before_child=False, tamper_after_log=False):
    def capture(_installation, _country, **kwargs):
        node_id = kwargs.get("trade_income_node_id")
        requested_node = selector_override if selector_override is not None else node_id
        request = {
            "include_trade_power_sum": kwargs.get("include_trade_power_sum", False),
            "trade_income_node_id": requested_node,
        }
        child = _child_record(node_id if isinstance(node_id, str) else NODE_ID)
        child["status"] = child_status
        snapshots = {}
        for phase in ("before", "after"):
            child_phase = deepcopy(child)
            if alter_before_child and phase == "before":
                child_phase["observation"]["value"]["outputs"]["income_raw"] += 1
            read_log = [
                {"address": "0x2000", "size": 8, "label": "world.identity", "raw_hex": "0010000002000000"},
                *deepcopy(CHILD_READS),
            ]
            if tamper_after_log and phase == "after":
                read_log[-1]["raw_hex"] = "79000000"
            snapshots[phase] = {
                "trade_income": deepcopy(TRADE_RECORD),
                "country_scan": deepcopy(COUNTRY_SCAN),
                "trade_power_sum": deepcopy(SUM_RECORD) if request["include_trade_power_sum"] else None,
                "trade_income_calculation": child_phase if node_id is not None else None,
                "read_log": read_log,
            }
        report = {
            "status": "observed",
            "request": request,
            "before": snapshots["before"],
            "after": snapshots["after"],
            "doublepass": {"consistent": True},
            "trade_income": deepcopy(TRADE_RECORD),
            "country_scan": deepcopy(COUNTRY_SCAN),
        }
        if request["include_trade_power_sum"]:
            report["trade_power_sum"] = deepcopy(SUM_RECORD)
        if node_id is not None:
            report["trade_income_calculation"] = deepcopy(snapshots["after"]["trade_income_calculation"])
        return report
    return capture


class _FakeOriginalPowerSource:
    def __init__(self, capture):
        self.base_source = object()
        self.capture = capture
        self._context = {"status": "ready", "observer": "FRA", "session_id": "s1"}

    def context(self):
        return deepcopy(self._context)

    def _capture_reader(self):
        return self.capture


class _FakePowerReader:
    def __init__(self, base_source, capture=None):
        self.base_source = base_source
        self.capture = capture

    def read(self, _query, _context):
        report = self.capture("fixture-installation", "FRA",
                              include_trade_income=True, include_trade_power=True)
        assert report["status"] == "observed"
        return {
            "status": "observed",
            "source": {"name": "fake-native-power", "provenance": {
                "context_guard": {"status": "passed"}}},
            "fields": {
                "country_power": {"status": "known", "raw": 1000, "value": 1000,
                                  "unit": "trade_power", "scale": 1000, "period": "current"},
                "total_power": {"status": "known", "raw": 4000, "value": 4000,
                                "unit": "trade_power", "scale": 1000, "period": "current"},
            },
        }


@pytest.fixture
def baseline_stubs(monkeypatch: pytest.MonkeyPatch):
    sum_calls = []
    child_calls = []

    def validate_sum(record, trade_record, country_scan, parent_read_log):
        sum_calls.append((record, trade_record, country_scan, parent_read_log))
        return (isinstance(record, dict) and record.get("_fixture_valid") is True
                and isinstance(trade_record, dict) and trade_record.get("status") == "observed"
                and isinstance(country_scan, dict) and country_scan.get("requested_country") == "FRA"
                and isinstance(parent_read_log, list))

    def validate_child(record, trade_record, country_scan, sum_record, *, node_id, parent_read_log=None):
        child_calls.append({
            "record": record, "trade_record": trade_record, "country_scan": country_scan,
            "sum_record": sum_record, "node_id": node_id, "parent_read_log": parent_read_log,
        })
        selected = [row for row in parent_read_log or []
                    if str(row.get("label", "")).startswith("trade_income_calculation.")]
        observation = record.get("observation") if isinstance(record, dict) else None
        return (
            isinstance(record, dict) and record.get("status") == "observed"
            and record.get("node_id") == node_id
            and isinstance(observation, dict) and observation.get("node_id") == node_id
            and trade_record == TRADE_RECORD and country_scan == COUNTRY_SCAN
            and isinstance(sum_record, dict) and sum_record.get("_fixture_valid") is True
            and isinstance(parent_read_log, list) and selected == record.get("raw_reads")
        )

    monkeypatch.setattr(sum_capture, "validate_record", validate_sum)
    monkeypatch.setattr(income_capture, "validate_record", validate_child)
    monkeypatch.setattr(baseline_module, "NativeTradePowerSource", _FakePowerReader)
    monkeypatch.setattr(
        NativeTradeIncomeSource, "_field_from_node",
        staticmethod(lambda _source, _node: {"status": "known", "raw": 1000, "value": 1000,
            "unit": "ducats", "scale": 1000, "period": "current", "eligible": True}),
    )
    monkeypatch.setattr(
        NativeTradeIncomeSource, "_field_from_collection_node",
        staticmethod(lambda _node: {"status": "known", "value": True}),
    )
    return sum_calls, child_calls


def _baseline_reader(monkeypatch, *, report_options=None):
    builder = _report_builder(**(report_options or {}))
    original = _FakeOriginalPowerSource(builder)
    return TradeScenarioBaselineReader(original), original


def test_baseline_default_uses_no_new_child_kw_and_opt_in_binds_exact_node(baseline_stubs, monkeypatch):
    sum_calls, child_calls = baseline_stubs
    reader, original = _baseline_reader(monkeypatch)

    default = reader.read(NODE_ID, original.context())
    assert default["status"] == "known"
    assert "native_income_calculation" not in default

    opted = reader.read(NODE_ID, original.context(), with_income_calculation=True)

    assert opted["status"] == "known"
    assert opted["fields"]["country_power"]["value"] == 1000
    assert opted["fields"]["total_power"]["value"] == 4000
    assert opted["native_income_calculation"] == {
        "status": "known", "value": INCOME_VALUE, "basis": INCOME_BASIS,
        "period": "current", "complete": False,
    }
    assert len(sum_calls) == 2  # one validated SUM child in each parent pass
    assert len(child_calls) == 2
    assert [call["node_id"] for call in child_calls] == [NODE_ID, NODE_ID]
    assert all(call["parent_read_log"][-1]["label"].startswith("trade_income_calculation.")
               for call in child_calls)
    provenance = opted["source"]["provenance"]["trade_income_calculation"]
    assert provenance["status"] == "known"
    assert provenance["profile_sha256"] == PROFILE_SHA256
    assert len(provenance["record_canonical_sha256"]) == 64
    assert provenance["parent_trace_bound"] is True
    assert provenance["doublepass_consistent"] is True


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        ({"selector_override": "beta"}, "TRADE_SCENARIO_INCOME_SELECTOR_UNVERIFIED"),
        ({"child_status": "unknown"}, "TRADE_SCENARIO_INCOME_CHILD_UNVERIFIED"),
        ({"alter_before_child": True}, "TRADE_SCENARIO_INCOME_CHILD_DOUBLEPASS_MISMATCH"),
        ({"tamper_after_log": True}, "TRADE_SCENARIO_INCOME_CHILD_UNVERIFIED"),
    ],
)
def test_bad_income_child_stays_local_to_baseline_child(baseline_stubs, monkeypatch, options, reason):
    reader, original = _baseline_reader(monkeypatch, report_options=options)

    result = reader.read(NODE_ID, original.context(), with_income_calculation=True)

    assert result["status"] == "known"
    assert result["fields"]["income"]["status"] == "known"
    assert result["fields"]["collection"]["status"] == "known"
    assert result["fields"]["country_power"]["value"] == 1000
    assert result["fields"]["total_power"]["value"] == 4000
    assert result["native_income_calculation"] == {"status": "unknown", "reason": reason}
    proof = result["source"]["provenance"]["trade_income_calculation"]
    assert proof["status"] == "unknown"
    assert proof["parent_trace_bound"] is False


def _scalar(raw: int, unit: str) -> dict:
    return {"status": "known", "raw": raw, "value": raw, "unit": unit,
            "scale": 1000, "period": "current"}


def _known_income_calculation() -> dict:
    return {"status": "known", "value": deepcopy(INCOME_VALUE), "basis": INCOME_BASIS,
            "period": "current", "complete": False}


def _auto_baseline(*, income_calculation=None) -> dict:
    result = {
        "status": "known", "node_id": NODE_ID,
        "fields": {
            "income": {**_scalar(1000, "ducats"), "eligible": True},
            "collection": {"status": "known", "value": True},
            "country_power": _scalar(1000, "trade_power"),
            "total_power": _scalar(4000, "trade_power"),
        },
        "native_power_components": {
            "status": "known", "value": {"multiplier_raw": 1000, "cap_raw": 1000,
                "base_raw": 1000, "subtract_raw": 0, "add_raw": 0},
            "basis": "native_trade_node_power_caches", "scale": 1000,
            "period": "current", "complete": False,
        },
        "native_power_sum_membership": {
            "status": "known", "basis": SUM_BASIS, "period": "current", "complete": False,
            "value": {"observer": "FRA", "country_slot": 42, "member_count": 256,
                "observer_occurrences": 1, "fullref_occurrences": 1, "slot_occurrences": 1,
                "observer_nonplayer_verified": True, "canonical_observer_verified": True,
                "stable": True},
        },
        "source": {"name": "FakeNativeBaseline", "mode": "live", "observer": "FRA"},
        "complete": False,
    }
    if income_calculation is not None:
        result["native_income_calculation"] = deepcopy(income_calculation)
    return result


class _ScenarioBaseline:
    supports_native_power_components = True
    supports_native_power_sum = True
    supports_native_income_calculation = True

    def __init__(self, *, income_calculation=None, income_supported=True):
        self._context = scenario_fixtures.live_context()
        self.result = _auto_baseline(income_calculation=income_calculation)
        self.supports_native_income_calculation = income_supported
        self.calls = []

    def context(self):
        return deepcopy(self._context)

    def read(self, node_id, _context, **kwargs):
        self.calls.append({"node_id": node_id, "kwargs": deepcopy(kwargs)})
        result = deepcopy(self.result)
        result["node_id"] = node_id
        return result


def _query(scenario: dict) -> dict:
    return {"topic": "T06", "object": {"type": "trade_node", "node_id": NODE_ID},
            "fields": ["expected_trade", "assumptions"],
            "parameters": {"scenarios": [deepcopy(scenario)]}}


def _manual() -> dict:
    return {"id": "manual", "country_power_delta_raw": 0, "total_power_delta_raw": 0}


def _explicit() -> dict:
    return {"id": "explicit", "power_input_model": "province_source_fixed_other_inputs",
            "province_power_delta_raw": 0, "total_power_delta_raw": 0}


def _automatic() -> dict:
    return {"id": "auto", "power_input_model": "province_source_fixed_other_inputs",
            "province_power_delta_raw": 0, "total_power_input_model": "fixed_other_country_power"}


def test_t06_requests_income_calculation_only_for_supported_auto_total_mode():
    baseline = _ScenarioBaseline(income_calculation=_known_income_calculation())
    source = TradeScenarioSource(baseline)
    context = baseline.context()

    source.read(_query(_manual()), context)
    source.read(_query(_explicit()), context)
    result = source.read(_query(_automatic()), context)

    assert [call["kwargs"] for call in baseline.calls] == [
        {},
        {"with_power_components": True},
        {"with_power_components": True, "with_sum_membership": True,
         "with_income_calculation": True},
    ]
    assumptions = result["fields"]["assumptions"]["value"]
    assert assumptions["native_income_calculation"]["basis"] == INCOME_BASIS
    assert assumptions["native_income_calculation"]["period"] == "current"
    assert assumptions["native_income_calculation"]["complete"] is False
    assert assumptions["native_income_calculation"]["value"]["matches_cache"] is True
    assert assumptions["native_income_calculation"]["value"]["outputs"]["income_raw"] == 4589
    annotation = next(row for row in assumptions["system_assumptions"]
                      if row["id"] == "native_current_income_calculation")
    assert "当前" in annotation["description"] and "未来收入预测" in annotation["description"]


def test_auto_annotation_survives_unknown_child_and_future_proxy_is_unchanged():
    known_reader = _ScenarioBaseline(income_calculation=_known_income_calculation())
    unknown_reader = _ScenarioBaseline(income_calculation={
        "status": "unknown", "reason": "TRADE_SCENARIO_INCOME_CALCULATION_UNVERIFIED"})
    known = TradeScenarioSource(known_reader).read(_query(_automatic()), known_reader.context())
    unknown = TradeScenarioSource(unknown_reader).read(_query(_automatic()), unknown_reader.context())

    known_expected = known["fields"]["expected_trade"]
    unknown_expected = unknown["fields"]["expected_trade"]
    assert known_expected["value"]["scenarios"] == unknown_expected["value"]["scenarios"]
    assert known_expected["value"]["actual_future_income"] == "unknown"
    assert unknown_expected["value"]["actual_future_income"] == "unknown"
    assumptions = unknown["fields"]["assumptions"]["value"]
    assert assumptions["native_income_calculation"] == {
        "status": "unknown", "reason": "TRADE_SCENARIO_INCOME_CALCULATION_UNVERIFIED",
    }


def test_auto_mode_without_reader_capability_keeps_calculation_unknown():
    baseline = _ScenarioBaseline(income_supported=False)
    source = TradeScenarioSource(baseline)

    result = source.read(_query(_automatic()), baseline.context())

    assert baseline.calls[0]["kwargs"] == {
        "with_power_components": True, "with_sum_membership": True,
    }
    assert result["fields"]["assumptions"]["value"]["native_income_calculation"] == {
        "status": "unknown", "reason": "NATIVE_INCOME_CALCULATION_UNAVAILABLE",
    }

