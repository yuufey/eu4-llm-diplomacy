"""Integration seams for opt-in node-cash capture and target projection.

Synthetic capture reports and callbacks in this file test wiring and public
projection only; they do not claim an observed game-memory capture.
"""
from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import province_trade_power as power_module
from bridge.information.trade_scenarios import TradeScenarioSource
from bridge.information.trade_targets import TradeTargetsReader
from bridge.tests import test_information_province_state as g02
from bridge.tests import test_information_province_trade_power as power_fixtures
from bridge.tests import test_information_province_trade_value_integration as value_fixtures
from bridge.tests import test_information_trade_scenarios_integration as scenario_fixtures
from bridge.tests import test_information_trade_targets as target_fixtures
from bridge.tests import test_information_trade_target_power as target_power_fixtures


PROVINCE_ID = 183
NODE_FIELD = "G02.node_cash_aggregate"
NODE_BASIS = "native_node_province_value_input_reconstruction"
_FULL_CHAIN = dict(value_fixtures._FULL_CHAIN)


def _combined_report(context):
    """Extend the existing batch-210 synthetic report with one local unknown."""
    report = value_fixtures._report(context)
    target = report["capture"]["observation"]["backend"]["targets"][0]
    assert len(target["fields"]) == 9
    target["fields"][NODE_FIELD] = {
        "status": "unknown",
        "complete": False,
        "period": "current",
        "basis": NODE_BASIS,
        "reason": "NODE_CASH_PARENT_UNVERIFIED",
        "raw_inputs": {"shared_valid": True, "synthetic_private_trace": "fixture-only"},
    }
    target["field_consistency"][NODE_FIELD] = {"status": "unknown"}
    return report


def _node_capture_reader(tmp_path, monkeypatch, *, validation=True):
    """Use a synthetic report while exercising the real reader selector/projector."""
    from bridge.information import node_cash_aggregate_capture as capture_module

    context = g02.make_context()
    report = _combined_report(context)
    _old_reader, base, _old_calls = power_fixtures._make_reader(
        tmp_path, monkeypatch, report=report, context=context, capture_override=False)
    calls = {"capture": [], "validate": [], "imports": []}

    def synthetic_capture(installation, *, province_id, observer):
        calls["capture"].append((installation, province_id, observer))
        return deepcopy(report)

    def replay_verdict(report_arg, context_arg, creation, province_id):
        calls["validate"].append((deepcopy(report_arg), deepcopy(context_arg), creation, province_id))
        return validation

    monkeypatch.setattr(capture_module, "capture", synthetic_capture)
    monkeypatch.setattr(capture_module, "validate_capture", replay_verdict)

    def tracked_import(name, package):
        calls["imports"].append(name)
        assert name == ".node_cash_aggregate_capture"
        return capture_module

    monkeypatch.setattr(power_module, "import_module", tracked_import)
    reader = power_module.NativeProvinceTradePowerReader(
        base, **(_FULL_CHAIN | {"with_node_cash": True}))
    return reader, context, report, calls


def test_default_reader_never_selects_the_node_cash_capture_module(tmp_path, monkeypatch):
    context = g02.make_context()
    report = power_fixtures._capture_report(context)
    reader, _base, calls = power_fixtures._make_reader(
        tmp_path, monkeypatch, report=report, context=context)
    original_import = power_module.import_module
    imported = []

    def tracked_import(name, package):
        imported.append(name)
        return original_import(name, package)

    monkeypatch.setattr(power_module, "import_module", tracked_import)
    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert result["value"] == {"raw": 1250, "scale": 1000, "unit": "trade_power"}
    assert "node_cash_aggregate" not in result
    assert imported == [".province_trade_power_capture"]
    assert len(calls["capture"]) == len(calls["validate"]) == 1


def test_node_cash_mode_uses_one_combined_capture_and_keeps_old_values_when_new_field_is_unknown(
        tmp_path, monkeypatch):
    reader, context, report, calls = _node_capture_reader(tmp_path, monkeypatch, validation=True)

    result = reader.read(PROVINCE_ID, context)

    assert len(report["capture"]["observation"]["backend"]["targets"][0]["fields"]) == 10
    assert result["status"] == "known"
    assert result["value"] == {"raw": 1250, "scale": 1000, "unit": "trade_power"}
    assert result["value_calculation"]["status"] == "known"
    assert result["node_allocation"]["status"] == "known"
    assert result["node_cash_aggregate"] == {
        "status": "unknown", "basis": NODE_BASIS, "period": "current",
        "partial": True, "complete": False, "native_function_invoked": False,
        "reason": "NODE_CASH_INPUT_UNKNOWN",
    }
    assert len(calls["capture"]) == len(calls["validate"]) == 1
    assert calls["capture"][0][1:] == (PROVINCE_ID, "FRA")
    assert calls["validate"][0][1:] == (context, g02.CREATION, PROVINCE_ID)
    assert calls["imports"] == [".node_cash_aggregate_capture"]
    assert "synthetic_private_trace" not in repr(result)
    assert "raw_inputs" not in repr(result)


def test_node_cash_reader_withholds_combined_report_when_replay_verdict_is_false(
        tmp_path, monkeypatch):
    reader, context, _report, calls = _node_capture_reader(tmp_path, monkeypatch, validation=False)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "unknown"
    assert result["reason"] == "PROVINCE_TRADE_POWER_CAPTURE_INVALID"
    assert "value" not in result and "node_cash_aggregate" not in result
    assert len(calls["capture"]) == len(calls["validate"]) == 1
    assert calls["imports"] == [".node_cash_aggregate_capture"]


def test_node_cash_capture_scope_checks_precede_profile_and_capture_work(monkeypatch):
    from bridge.information import node_cash_aggregate_capture as capture_module

    capture_calls = []
    monkeypatch.setattr(capture_module._owner, "_capture_common",
                        lambda *args, **kwargs: capture_calls.append((args, kwargs)))

    with pytest.raises(ValueError, match="NODE_CASH_SCOPE"):
        capture_module.capture(object(), 0, observer="FRA")
    with pytest.raises(ValueError, match="NODE_CASH_SCOPE"):
        capture_module.capture(object(), PROVINCE_ID, observer="por")
    assert capture_module.validate_capture({}, g02.make_context(), g02.CREATION, 0) is False
    assert capture_calls == []


def _node_summary():
    from bridge.information.province_trade_value_calculation import aggregate_node_inputs

    input_raw = 1200
    node_raw = aggregate_node_inputs([input_raw])["node_input_raw"]
    return {
        "status": "known",
        "basis": NODE_BASIS,
        "period": "current",
        "partial": True,
        "complete": False,
        "native_function_invoked": False,
        "value": {
            "node_id": target_fixtures.NODE_ID,
            "center_province_id": 1293,
            "member_count": 1,
            "valued_member_count": 1,
            "unresolved_province_ids": [],
            "all_member_values_known": True,
            "province_input_sum_raw": input_raw,
            "calculated_node_cash_raw": node_raw,
            "cached_node_cash_raw": node_raw,
            "matches_cache": True,
            "scale": 1000,
            "unit": "node_cash",
            "current_only": True,
            "cache_refresh_verified": False,
            "future_income_claimed": False,
        },
    }


class _CashPowerReader:
    with_node_cash = True

    def __init__(self, annotation):
        self.annotation = deepcopy(annotation)
        self.base = target_power_fixtures.PowerReader()

    @property
    def calls(self):
        return self.base.calls

    def read(self, province_id, context):
        result = self.base.read(province_id, context)
        result["node_cash_aggregate"] = deepcopy(self.annotation)
        return result


def _target_rows(power_reader, province_ids=(183, 183)):
    graph = target_fixtures.FakeTradeGraph([
        target_fixtures._member(pid, index) for index, pid in enumerate(province_ids)
    ])
    reader = TradeTargetsReader(graph, target_fixtures.FakeProvinceSource(),
                                power_reader=power_reader)
    result = reader.read(target_fixtures.NODE_ID, target_fixtures.LIVE_CONTEXT,
                         {"offset": 0, "limit": len(province_ids)})
    return reader, result


def test_trade_targets_validates_node_summary_after_one_power_read():
    power = _CashPowerReader(_node_summary())
    _reader, result = _target_rows(power)

    assert result["status"] == "known"
    assert result["value"]["power_reads"] == 1
    assert power.calls == [183]
    first, duplicate = result["value"]["rows"]
    assert first["current_trade_power"]["status"] == "known"
    assert first["current_trade_power"]["value"]["raw"] == 0
    assert first["current_trade_power"]["node_cash_aggregate"] == _node_summary()
    assert duplicate["current_trade_power"] == first["current_trade_power"]
    assert "raw_inputs" not in repr(result)


def test_invalid_node_summary_is_local_and_does_not_hide_power():
    invalid = _node_summary()
    invalid["raw_inputs"] = {"private_pointer": "0x123456789abcdef0"}
    power = _CashPowerReader(invalid)
    _reader, result = _target_rows(power, province_ids=(183,))

    assert result["value"]["power_reads"] == 1
    row = result["value"]["rows"][0]
    assert row["current_trade_power"]["status"] == "known"
    summary = row["current_trade_power"]["node_cash_aggregate"]
    assert summary["status"] == "unknown"
    assert summary["reason"] == "NODE_CASH_ANNOTATION_INVALID"
    assert "0x123456789abcdef0" not in repr(result)


def test_t06_discovery_reports_node_cash_path_and_completeness_limits():
    flags = SimpleNamespace(with_numeric_inputs=True, with_country_inputs=True,
        with_calculation=True, with_node_allocation=True, with_value_calculation=True,
        with_node_cash=True)
    targets = SimpleNamespace(power_reader=flags)
    source = TradeScenarioSource(scenario_fixtures.FakeTradeBaseline(), target_reader=targets)

    field = source.catalog()[0]["fields"]["targets"]
    annotation = field["current_trade_power_annotation"]
    assert annotation["province_value_calculation"] is True
    assert annotation["province_value_path"] == "rows[].current_trade_power.value_calculation"
    assert annotation["node_cash_aggregate"] is True
    assert annotation["node_cash_path"] == "rows[].current_trade_power.node_cash_aggregate"
    assert annotation["node_cash_all_members_required_for_cache_comparison"] is True
    assert annotation["node_cash_cache_refresh_verified"] is False
    assert field["coverage"] == "partial" and field["complete"] is False


def test_built_profile_loader_accepts_the_final_node_cash_profile_pin():
    from bridge.information import node_cash_aggregate_capture as capture_module
    from bridge.information import node_cash_aggregate_memory as leaf
    from bridge.information import province_trade_value_capture as previous

    profile = capture_module._load_profile()

    assert profile["profile_id"] == "node-cash-aggregate-memory-1374"
    assert profile["profile_version"] == 1 and profile["game_version"] == "1.37.4"
    assert profile["semantics"]["supported_fields"] == [*previous.FIELDS, leaf.FIELD]
    assert profile["layout"]["node_cash_aggregate"] == capture_module.LAYOUT


def test_live_static_information_runtime_opts_in_node_cash_mode(tmp_path, monkeypatch):
    from tools.serve_information import _build_runtime, build_parser

    import bridge.information.province_estuaries as estuary_module
    import bridge.information.province_estuary_definitions as definition_module
    import bridge.information.static_data as static_module
    import bridge.information.straits as straits_module
    import bridge.information.trade_target_graph as graph_module
    import bridge.information.trade_targets as targets_module

    class StaticTrade:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.game_root = kwargs.get("game_root")
            self.user_data = kwargs.get("user_data")
            self.enabled_mods = []

        def catalog(self):
            return []

    class StaticStraits:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def catalog(self):
            return []

    class TargetReader:
        def __init__(self, graph, provinces, ports, estuaries, power_reader):
            self.graph = graph
            self.province_source = provinces
            self.port_source = ports
            self.estuary_reader = estuaries
            self.power_reader = power_reader

    monkeypatch.setattr(static_module, "StaticTradeSource", StaticTrade)
    monkeypatch.setattr(straits_module, "StaticStraitsSource", StaticStraits)
    monkeypatch.setattr(graph_module, "TradeTargetGraphReader",
                        lambda static_trade: ("synthetic_graph", static_trade))
    monkeypatch.setattr(definition_module, "BoundEstuaryDefinition",
                        lambda *args, **kwargs: ("synthetic_estuary_rules", args, kwargs))
    monkeypatch.setattr(estuary_module, "NativeProvinceEstuaryReader",
                        lambda source, rules: ("synthetic_estuary_reader", source, rules))
    monkeypatch.setattr(targets_module, "TradeTargetsReader", TargetReader)

    args = build_parser().parse_args([
        "--database", str(tmp_path / "information.sqlite3"),
        "--observer", "FRA",
        "--static-game-data",
        "--static-game-root", str(tmp_path / "game"),
        "--static-user-data", str(tmp_path / "user"),
    ])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        scenario_source = next(adapter for adapter in service.source.adapters
                               if isinstance(adapter, TradeScenarioSource))
        power_reader = scenario_source.target_reader.power_reader
        assert power_reader.with_numeric_inputs is True
        assert power_reader.with_country_inputs is True
        assert power_reader.with_calculation is True
        assert power_reader.with_node_allocation is True
        assert power_reader.with_value_calculation is True
        assert power_reader.with_node_cash is True
    finally:
        service.close()
