"""Opt-in projection of the current province value input in T06 target rows."""
from copy import deepcopy

import pytest

from bridge.information import province_trade_power as power_module
from bridge.information.trade_targets import TradeTargetsReader
from bridge.tests import test_information_province_node_allocation_inputs as allocation_fixtures
from bridge.tests import test_information_province_state as g02
from bridge.tests import test_information_province_trade_power as power_fixtures
from bridge.tests import test_information_trade_targets as target_fixtures


PROVINCE_ID = 183
FIELD = "G02.province_trade_value_calculation"
BASIS = "native_province_trade_value_processor_absent"
POWER_BASIS = "native_province_trade_power_trigger_cache"


def _value(**changes):
    value = {
        "province_id": PROVINCE_ID,
        "owner": "FRA",
        "resource": {"localization_key": "grain", "icon_index": 3},
        "inputs": {
            "province_goods_base_raw": 1200,
            "owner_goods_base_raw": 200,
            "province_goods_modifier_raw": 50,
            "owner_goods_modifier_raw": -25,
            "goods_price_raw": 900,
            "province_value_add_raw": 75,
            "province_value_modifier_raw": 100,
        },
        "calculation": {
            "goods_base_raw": 1400,
            "combined_goods_modifier_raw": 25,
            "goods_factor_raw": 1025,
            "goods_raw": 1435,
            "priced_raw": 1291,
            "subtotal_raw": 1366,
            "value_factor_raw": 1100,
            "value_raw": 1502,
        },
        "scale": 1000,
        "unit": "native_trade_value_input",
        "extra_arguments_zero": True,
        "description_absent": True,
        "current_only": True,
        "individual_monthly_contribution_claimed": False,
    }
    value.update(deepcopy(changes))
    return value


def _field(value=None, *, status="known", consistency=None):
    item = {
        "status": status,
        "complete": False,
        "period": "current",
        "basis": BASIS,
        "raw_inputs": {"private_pointer": "0x123456789abcdef0", "trace": "private"},
    }
    if status == "known":
        item["value"] = deepcopy(value if value is not None else _value())
    else:
        item["reason"] = "PRIVATE_VALUE_LEAF_FAILURE"
    state = consistency or ("stable" if status == "known" else "unknown")
    return item, {"status": state}


def _report(context, value=None, *, status="known", consistency=None):
    report = allocation_fixtures._report(context)
    target = report["capture"]["observation"]["backend"]["targets"][0]
    item, state = _field(value, status=status, consistency=consistency)
    target["fields"][FIELD] = item
    target["field_consistency"][FIELD] = state
    return report


_FULL_CHAIN = {
    "with_numeric_inputs": True,
    "with_country_inputs": True,
    "with_calculation": True,
    "with_node_allocation": True,
    "with_value_calculation": True,
}


def _make_reader(tmp_path, monkeypatch, *, report=None, context=None,
                 capture_override=True, options=None):
    current = deepcopy(context or g02.make_context())
    old_reader, base, calls = power_fixtures._make_reader(
        tmp_path, monkeypatch,
        report=report if report is not None else _report(current),
        context=current, capture_override=capture_override)
    reader = power_module.NativeProvinceTradePowerReader(
        base,
        capture=old_reader.capture if capture_override else None,
        **(options if options is not None else _FULL_CHAIN),
    )
    return reader, base, calls, current


def _known_annotation(value=None, province_id=PROVINCE_ID):
    candidate = {
        "status": "known",
        "basis": BASIS,
        "period": "current",
        "partial": True,
        "complete": False,
        "native_function_invoked": False,
        "value": deepcopy(value if value is not None else _value()),
    }
    return power_module._validate_value_calculation_annotation(candidate, province_id)


def test_opt_in_projection_selects_strict_value_capture_and_keeps_private_trace_local(
        tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _base, calls, context = _make_reader(
        tmp_path, monkeypatch, report=_report(context), context=context,
        capture_override=False)
    original_import = power_module.import_module
    imported = []

    def tracked_import(name, package):
        imported.append(name)
        return original_import(name, package)

    monkeypatch.setattr(power_module, "import_module", tracked_import)
    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert result["value"] == {"raw": 1250, "scale": 1000, "unit": "trade_power"}
    assert result["value_calculation"] == _known_annotation()
    assert imported == [".province_trade_value_capture"]
    assert len(calls["module_capture"]) == len(calls["validate"]) == 1
    assert calls["validate"][0][1:] == (context, g02.CREATION, PROVINCE_ID)
    assert "raw_inputs" not in repr(result)
    assert "private_pointer" not in repr(result)
    assert "0x123456789abcdef0" not in repr(result)


def test_default_reader_keeps_the_existing_capture_and_result_seam(tmp_path, monkeypatch):
    context = g02.make_context()
    report = power_fixtures._capture_report(context)
    old_reader, base, calls = power_fixtures._make_reader(
        tmp_path, monkeypatch, report=report, context=context)
    reader = power_module.NativeProvinceTradePowerReader(base, capture=old_reader.capture)
    original_import = power_module.import_module
    imported = []

    def tracked_import(name, package):
        imported.append(name)
        return original_import(name, package)

    monkeypatch.setattr(power_module, "import_module", tracked_import)
    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert result["value"] == {"raw": 1250, "scale": 1000, "unit": "trade_power"}
    assert "value_calculation" not in result
    assert imported == [".province_trade_power_capture"]
    assert len(calls["validate"]) == 1


@pytest.mark.parametrize("options", [
    {"with_value_calculation": True},
    {"with_numeric_inputs": True, "with_value_calculation": True},
    {"with_numeric_inputs": True, "with_country_inputs": True,
     "with_value_calculation": True},
    {"with_numeric_inputs": True, "with_country_inputs": True,
     "with_calculation": True, "with_value_calculation": True},
])
def test_value_calculation_requires_the_entire_existing_capture_chain(tmp_path, options):
    base = g02.Base(tmp_path, g02.make_context())
    with pytest.raises(ValueError):
        power_module.NativeProvinceTradePowerReader(base, **options)


def test_value_calculation_option_requires_an_exact_boolean(tmp_path):
    base = g02.Base(tmp_path, g02.make_context())
    with pytest.raises(ValueError, match="PROVINCE_TRADE_VALUE_OPTION_INVALID"):
        power_module.NativeProvinceTradePowerReader(base, **(_FULL_CHAIN | {
            "with_value_calculation": 1,
        }))


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(province_id=True),
    lambda value: value.update(province_id=227),
    lambda value: value["resource"].update(icon_index=True),
    lambda value: value["resource"].update(localization_key="bad key"),
    lambda value: value["inputs"].update(goods_price_raw=True),
    lambda value: value["calculation"].update(value_raw=1 << 31),
    lambda value: value.update(scale=True),
    lambda value: value.update(extra_arguments_zero=1),
    lambda value: value.update(description_absent=False),
    lambda value: value.update(individual_monthly_contribution_claimed=True),
])
def test_invalid_value_field_is_withheld_locally_without_leaking_raw_data(
        tmp_path, monkeypatch, mutate):
    context = g02.make_context()
    value = _value()
    mutate(value)
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=_report(context, value), context=context)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert result["value"] == {"raw": 1250, "scale": 1000, "unit": "trade_power"}
    assert result["value_calculation"]["status"] == "unknown"
    assert result["value_calculation"]["reason"] == "PROVINCE_TRADE_VALUE_CALCULATION_INVALID"
    assert "raw_inputs" not in repr(result)
    assert "private_pointer" not in repr(result)
    assert "0x123456789abcdef0" not in repr(result)


def test_unknown_or_changed_value_child_does_not_hide_the_power_result(tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch,
        report=_report(context, status="unknown"), context=context)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert result["value_calculation"]["status"] == "unknown"
    assert result["value_calculation"]["reason"] == "PROVINCE_TRADE_VALUE_CALCULATION_INPUT_UNKNOWN"
    assert "PRIVATE_VALUE_LEAF_FAILURE" not in repr(result)

    changed_reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch,
        report=_report(context, consistency="changed"), context=context)
    changed = changed_reader.read(PROVINCE_ID, context)
    assert changed["status"] == "known"
    assert changed["value_calculation"]["status"] == "unknown"


class _PowerReader:
    with_value_calculation = True

    def __init__(self, *, child_province_id=None, outer_province_id=None):
        self.calls = []
        self.child_province_id = child_province_id
        self.outer_province_id = outer_province_id

    def read(self, province_id, context):
        self.calls.append(province_id)
        child = _value(province_id=(self.child_province_id
                                    if self.child_province_id is not None else province_id))
        child_annotation = _known_annotation(child, province_id)
        return {
            "status": "known",
            "province_id": (self.outer_province_id
                            if self.outer_province_id is not None else province_id),
            "value": {"raw": 0 if province_id == 183 else 34104,
                      "scale": 1000, "unit": "trade_power"},
            "game_date": context["game_date"],
            "period": "current", "partial": True, "complete": False,
            "basis": POWER_BASIS, "acquisition_delta_evaluated": False,
            "cache_refresh_timing_verified": False,
            "source": {"name": "NativeProvinceTradePowerReader", "mode": "live",
                "status": "observed", "observer": "FRA", "session_id": context["session_id"],
                "provenance": {"observer": "FRA", "province_id": province_id,
                    "read_only": True, "native_function_invoked": False,
                    "capture_report_sha256": "a" * 64}},
            "value_calculation": child_annotation,
        }


def _targets(power_reader, province_ids=(183, 183, 227)):
    graph = target_fixtures.FakeTradeGraph([
        target_fixtures._member(pid, index) for index, pid in enumerate(province_ids)
    ])
    reader = TradeTargetsReader(graph, target_fixtures.FakeProvinceSource(),
                                power_reader=power_reader)
    return reader, reader.read(target_fixtures.NODE_ID, target_fixtures.LIVE_CONTEXT,
                               {"offset": 0, "limit": len(province_ids)})


def test_t06_rows_keep_typed_child_without_a_second_province_read():
    power = _PowerReader()
    _, result = _targets(power)

    assert result["status"] == "known"
    assert result["value"]["power_reads"] == 2
    assert power.calls == [183, 227]
    first, duplicate, second = result["value"]["rows"]
    assert first["current_trade_power"]["value_calculation"]["status"] == "known"
    assert first["current_trade_power"]["value_calculation"]["value"]["province_id"] == 183
    assert duplicate["current_trade_power"] == first["current_trade_power"]
    assert second["current_trade_power"]["value_calculation"]["value"]["province_id"] == 227
    assert all(row["classification"]["expected_benefit"]["status"] == "unknown"
               for row in result["value"]["rows"])
    assert "raw_inputs" not in repr(result)


def test_t06_child_binding_failure_is_local_but_outer_province_mismatch_rejects_power():
    _, child_mismatch = _targets(_PowerReader(child_province_id=227), province_ids=(183,))
    row = child_mismatch["value"]["rows"][0]
    assert row["current_trade_power"]["status"] == "known"
    assert row["current_trade_power"]["value_calculation"]["status"] == "unknown"
    assert row["current_trade_power"]["value_calculation"]["reason"] == \
        "PROVINCE_TRADE_VALUE_CALCULATION_INVALID"

    _, outer_mismatch = _targets(_PowerReader(outer_province_id=227), province_ids=(183,))
    row = outer_mismatch["value"]["rows"][0]
    assert row["current_trade_power"]["status"] == "unknown"
    assert row["current_trade_power"]["reason"] == "TRADE_TARGET_POWER_BINDING_INVALID"
    assert "value_calculation" not in row["current_trade_power"]
