"""Public projection tests for the optional province-to-node annotation."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import province_trade_power as module
from bridge.tests import test_information_province_state as g02
from bridge.tests import test_information_province_trade_power as power_fixtures
from bridge.tests import test_information_province_trade_power_calculation_inputs as calculation_fixtures
from bridge.tests import test_information_province_trade_power_country_inputs as country_fixtures
from bridge.tests import test_information_province_trade_power_inputs as numeric_fixtures


PROVINCE_ID = 183
FIELD = "G02.province_node_allocation"
BASIS = "native_trade_node_province_component_reconstruction"


def _value(**changes):
    value = {
        "node_id": "bordeaux",
        "center_province_id": 2,
        "province_id": PROVINCE_ID,
        "recipient_country": "SWE",
        "contribution_raw": 1250,
        "observer_country": "FRA",
        "observer_contribution_raw": 0,
        "observer_node_province_power_cache_raw": 2200,
        "observed_observer_province_power_sum_raw": 0,
        "observer_sum_complete": False,
        "matches_observer_cache": None,
        "member_count": 5,
        "observed_member_count": 1,
        "owner_present": True,
        "scale": 1000,
        "unit": "trade_power",
    }
    value.update(changes)
    return value


def _field(value=None, *, status="known", consistency="stable"):
    item = {
        "status": status,
        "complete": False,
        "period": "current",
        "basis": BASIS,
        "raw_inputs": {"private_pointer": "0x123456789abcdef0", "secret_trace": "private"},
    }
    if status == "known":
        item["value"] = deepcopy(value if value is not None else _value())
    else:
        item["reason"] = "PRIVATE_NODE_ALLOCATION_FAILURE"
    return item, {"status": consistency}


def _report(context, value=None):
    report = calculation_fixtures._report(context)
    target = report["capture"]["observation"]["backend"]["targets"][0]
    item, state = _field(value)
    target["fields"][FIELD] = item
    target["field_consistency"][FIELD] = state
    return report


def _make_reader(tmp_path, monkeypatch, *, report=None, validator_result=True,
                 capture_override=True, context=None, node_allocation=True):
    current = deepcopy(context or g02.make_context())
    old, base, calls = power_fixtures._make_reader(
        tmp_path,
        monkeypatch,
        report=report if report is not None else _report(current),
        validator_result=validator_result,
        capture_override=capture_override,
        context=current,
    )
    reader = module.NativeProvinceTradePowerReader(
        base,
        capture=old.capture if capture_override else None,
        with_numeric_inputs=True,
        with_country_inputs=True,
        with_calculation=True,
        with_node_allocation=node_allocation,
    )
    return reader, base, calls, current


def _read(reader, context):
    return reader.read(PROVINCE_ID, context)


def test_node_allocation_projects_safe_typed_annotation_without_private_trace(tmp_path, monkeypatch):
    context = g02.make_context()
    value = _value()
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=_report(context, value), context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert result["province_id"] == PROVINCE_ID
    assert result["value"] == {"raw": 1250, "scale": 1000, "unit": "trade_power"}
    annotation = result["node_allocation"]
    assert annotation == {
        "status": "known",
        "basis": BASIS,
        "period": "current",
        "partial": True,
        "complete": False,
        "component": "TP_PROVINCE_POWER",
        "cache_refresh_timing_verified": False,
        "atomic_game_snapshot": False,
        "acquisition_delta_evaluated": False,
        "value": value,
    }
    assert result["partial"] is True and result["complete"] is False
    assert result["acquisition_delta_evaluated"] is False
    assert result["cache_refresh_timing_verified"] is False
    assert result["source"]["name"] == "NativeProvinceTradePowerReader"
    assert result["source"]["observer"] == "FRA"
    assert result["source"]["status"] == "observed"
    assert len(result["source"]["provenance"]["capture_report_sha256"]) == 64
    assert "raw_inputs" not in repr(result)
    assert "secret_trace" not in repr(result)
    assert "0x123456789abcdef0" not in repr(result)


@pytest.mark.parametrize(
    ("value", "expected_contribution", "expected_observer_contribution", "expected_match"),
    [
        (_value(), 1250, 0, None),
        (_value(owner_present=False, contribution_raw=0), 0, 0, None),
        (_value(recipient_country="FRA", observer_contribution_raw=1250,
                observer_sum_complete=True, member_count=2, observed_member_count=2,
                observer_node_province_power_cache_raw=2500,
                observed_observer_province_power_sum_raw=2500,
                matches_observer_cache=True), 1250, 1250, True),
        (_value(recipient_country="FRA", observer_contribution_raw=1250,
                observer_sum_complete=True, member_count=2, observed_member_count=2,
                observer_node_province_power_cache_raw=2500,
                observed_observer_province_power_sum_raw=2499,
                matches_observer_cache=False), 1250, 1250, False),
    ],
)
def test_controller_and_observer_contribution_rules_are_projected(
        tmp_path, monkeypatch, value, expected_contribution,
        expected_observer_contribution, expected_match):
    context = g02.make_context()
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=_report(context, value), context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    projected = result["node_allocation"]
    assert projected["status"] == "known"
    assert projected["value"]["contribution_raw"] == expected_contribution
    assert projected["value"]["observer_contribution_raw"] == expected_observer_contribution
    assert projected["value"]["matches_observer_cache"] is expected_match


@pytest.mark.parametrize("mutation", [
    lambda v: v.update(contribution_raw=True),
    lambda v: v.update(contribution_raw=1251),
    lambda v: v.update(owner_present=False),
    lambda v: v.update(observer_contribution_raw=1),
    lambda v: v.update(matches_observer_cache=False),
    lambda v: v.update(observer_sum_complete=True),
    lambda v: v.update(observer_sum_complete=True, matches_observer_cache=True,
                        observed_member_count=2, member_count=3),
    lambda v: v.update(observer_sum_complete=True, matches_observer_cache=True,
                        observed_member_count=5, member_count=5,
                        observed_observer_province_power_sum_raw=2,
                        observer_node_province_power_cache_raw=1),
    lambda v: v.update(observer_country="POR"),
    lambda v: v.update(secret_extra="not part of the schema"),
])
def test_invalid_node_child_is_local_and_preserves_main_power(
        tmp_path, monkeypatch, mutation):
    context = g02.make_context()
    value = _value()
    mutation(value)
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=_report(context, value), context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert result["value"] == {"raw": 1250, "scale": 1000, "unit": "trade_power"}
    assert result["node_allocation"]["status"] == "unknown"
    assert result["node_allocation"]["reason"] == "PROVINCE_NODE_ALLOCATION_INPUT_UNKNOWN"
    assert "secret_extra" not in repr(result)


def test_unknown_child_or_changed_field_state_only_withholds_node_annotation(
        tmp_path, monkeypatch):
    context = g02.make_context()
    report = _report(context)
    target = report["capture"]["observation"]["backend"]["targets"][0]
    target["fields"][FIELD], target["field_consistency"][FIELD] = _field(
        status="unknown", consistency="unknown")
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    assert result["node_allocation"]["status"] == "unknown"
    assert "PRIVATE_NODE_ALLOCATION_FAILURE" not in repr(result)


def test_strict_capture_replay_failure_withholds_entire_annotation(tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _base, calls, context = _make_reader(
        tmp_path, monkeypatch, validator_result=False, context=context)

    result = _read(reader, context)

    assert calls["validate"]
    assert result["status"] == "unknown"
    assert "node_allocation" not in result


def test_node_allocation_mode_selects_owner_capture_and_strict_replay(
        tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _base, calls, context = _make_reader(
        tmp_path, monkeypatch, capture_override=False, context=context)
    original = module.import_module
    names = []

    def importing(name, package):
        names.append(name)
        return original(name, package)

    monkeypatch.setattr(module, "import_module", importing)
    result = _read(reader, context)

    assert result["status"] == "known"
    assert names == [".province_node_allocation_capture"]
    assert len(calls["module_capture"]) == 1
    assert len(calls["validate"]) == 1
    assert calls["validate"][0][1:] == (context, g02.CREATION, PROVINCE_ID)


def test_node_allocation_requires_the_full_parent_input_chain(tmp_path):
    context = g02.make_context()
    base = g02.Base(tmp_path, context)

    with pytest.raises(ValueError, match="PROVINCE_NODE_ALLOCATION_OPTION_INVALID"):
        module.NativeProvinceTradePowerReader(base, with_node_allocation=True)


@pytest.mark.parametrize("mode", ["default", "numeric", "country", "calculation"])
def test_existing_projection_modes_keep_their_original_field_sets(
        tmp_path, monkeypatch, mode):
    context = g02.make_context()
    if mode == "default":
        report = power_fixtures._capture_report(context)
        options = {}
        expected_count = 1
    elif mode == "numeric":
        report = numeric_fixtures.report_for(context)
        options = {"with_numeric_inputs": True}
        expected_count = 4
    elif mode == "country":
        report = country_fixtures._report(context)
        options = {"with_numeric_inputs": True, "with_country_inputs": True}
        expected_count = 6
    else:
        report = calculation_fixtures._report(context)
        options = {"with_numeric_inputs": True, "with_country_inputs": True,
                   "with_calculation": True}
        expected_count = 7

    old, base, _calls = power_fixtures._make_reader(
        tmp_path, monkeypatch, report=report, context=context)
    reader = module.NativeProvinceTradePowerReader(
        base, capture=old.capture, **options)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    backend_target = report["capture"]["observation"]["backend"]["targets"][0]
    assert len(backend_target["fields"]) == expected_count
    assert "node_allocation" not in result
