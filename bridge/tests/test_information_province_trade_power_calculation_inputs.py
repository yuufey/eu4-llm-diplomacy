"""Public projection tests for current cache-writer calculation inputs."""
from copy import deepcopy

import pytest

from bridge.information import province_trade_power as module
from bridge.information.province_trade_power_calculation import calculate_current
from bridge.tests import test_information_province_trade_power as fixtures
from bridge.tests import test_information_province_trade_power_country_inputs as country_fixtures
from bridge.tests import test_information_province_state as g02


PROVINCE_ID = 183
GATES_FIELD = "G02.province_trade_power_calculation_gates"
GATES_BASIS = "native_province_trade_power_cache_writer_gates"
CALCULATION_REASON = "PROVINCE_TRADE_POWER_CALCULATION_INPUT_UNKNOWN"


def _gates(*, node=True, controller=True, active=True, bonus=50):
    if not node:
        value = {
            "province_node_enabled": False,
            "controller_type_enabled": None,
            "owner_bonus_active": None,
            "owner_bonus_raw": None,
        }
    elif not controller:
        value = {
            "province_node_enabled": True,
            "controller_type_enabled": False,
            "owner_bonus_active": None,
            "owner_bonus_raw": None,
        }
    else:
        value = {
            "province_node_enabled": True,
            "controller_type_enabled": True,
            "owner_bonus_active": active,
            "owner_bonus_raw": bonus,
        }
    return {
        "status": "known",
        "complete": False,
        "period": "current",
        "basis": GATES_BASIS,
        "value": value,
        "raw_inputs": {"private_address": "0x123456789abcdef0", "trace": "private"},
    }


def _report(context, *, gate=None):
    report = country_fixtures._report(context)
    target = report["capture"]["observation"]["backend"]["targets"][0]
    target["fields"][GATES_FIELD] = deepcopy(gate if gate is not None else _gates())
    target["field_consistency"][GATES_FIELD] = {"status": "stable"}
    return report


def _set_numeric(target, *, flat=50000, province_ratio=100,
                 further_ratio=-100, unit_overrides=None):
    values = {
        "G02.province_trade_power_value": (flat, "trade_power"),
        "G02.province_trade_power_modifier": (province_ratio, "ratio"),
        "G02.province_trade_power_further_modifier": (further_ratio, "ratio"),
    }
    unit_overrides = unit_overrides or {}
    for field, (raw, expected_unit) in values.items():
        target["fields"][field] = {
            "status": "known", "complete": False, "period": "current",
            "basis": module._NUMERIC_BASIS,
            "value": {"raw": raw, "scale": 1000,
                      "unit": unit_overrides.get(field, expected_unit)},
            "raw_inputs": {"private_address": "0xabcdef", "trace": "private"},
        }
        target["field_consistency"][field] = {"status": "stable"}


def _set_controller(target, *, raw=300, status="known", country="SWE", unit="ratio"):
    field = "G02.controller_global_province_trade_power_modifier"
    target["fields"][field] = {
        "status": status, "complete": False, "period": "current",
        "basis": module._COUNTRY_BASIS,
        "value": {"country": country, "raw": raw, "scale": 1000, "unit": unit},
        "reason": "LOCAL_PRIVATE_CONTROLLER_FAILURE_0xabcdef",
        "raw_inputs": {"private_address": "0xabcdef"},
    }
    target["field_consistency"][field] = {
        "status": "stable" if status == "known" else "unknown",
    }


def _make_reader(tmp_path, monkeypatch, *, report=None, validator_result=True,
                 capture_override=True, context=None):
    current = deepcopy(context or g02.make_context())
    old, base, calls = fixtures._make_reader(
        tmp_path, monkeypatch,
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
    )
    return reader, base, calls, current


def _read(reader, context):
    return reader.read(PROVINCE_ID, context)


def _calculation(result):
    return result["calculation"]


def test_constructor_requires_numeric_and_country_input_modes(tmp_path):
    context = g02.make_context()
    base = g02.Base(tmp_path, context)
    with pytest.raises(ValueError, match="CALCULATION_OPTION_INVALID"):
        module.NativeProvinceTradePowerReader(base, with_calculation=True)
    with pytest.raises(ValueError, match="COUNTRY_INPUT_OPTION_INVALID"):
        module.NativeProvinceTradePowerReader(base, with_country_inputs=True)


def test_calculation_capture_module_is_selected_and_strictly_replayed(
        tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _base, calls, context = _make_reader(
        tmp_path, monkeypatch, capture_override=False, context=context)
    original = module.import_module
    imported = []

    def importing(name, package):
        imported.append(name)
        return original(name, package)

    monkeypatch.setattr(module, "import_module", importing)
    result = _read(reader, context)

    assert result["status"] == "known"
    assert imported == [".province_trade_power_calculation_capture"]
    assert len(calls["module_capture"]) == 1
    assert len(calls["validate"]) == 1
    assert calls["validate"][0][1:] == (context, g02.CREATION, PROVINCE_ID)


def test_node_false_projects_known_zero_even_when_numeric_inputs_are_unknown(
        tmp_path, monkeypatch):
    context = g02.make_context()
    report = _report(context, gate=_gates(node=False))
    target = report["capture"]["observation"]["backend"]["targets"][0]
    for field in module._NUMERIC_FIELDS:
        target["fields"][field] = {
            "status": "unknown", "reason": "PRIVATE_NUMERIC_0xabcdef",
            "complete": False, "basis": module._NUMERIC_BASIS,
            "period": "current", "raw_inputs": {"secret": "x"},
        }
        target["field_consistency"][field] = {"status": "unknown"}
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    calc = _calculation(result)
    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    assert calc["status"] == "known"
    assert calc["value"] == {"raw": 0, "scale": 1000, "unit": "trade_power"}
    assert calc["matches_cache"] is False
    assert calc["native_function_invoked"] is False
    assert calc["acquisition_delta_evaluated"] is False
    assert calc["argument_mode"] == "cache_writer_zero_additional_inputs"
    assert calc["partial"] is True and calc["complete"] is False
    assert result["numeric_modifiers"]["province_trade_power_value"]["status"] == "unknown"
    assert "PRIVATE_NUMERIC_0xabcdef" not in repr(result)


def test_controller_type_false_projects_known_zero_even_when_children_unknown(
        tmp_path, monkeypatch):
    context = g02.make_context()
    report = _report(context, gate=_gates(controller=False))
    target = report["capture"]["observation"]["backend"]["targets"][0]
    for field in module._NUMERIC_FIELDS:
        target["fields"][field]["status"] = "unknown"
        target["fields"][field]["reason"] = "PRIVATE_NUMERIC_ERROR"
        target["field_consistency"][field] = {"status": "unknown"}
    _set_controller(target, status="unknown")
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert _calculation(result)["status"] == "known"
    assert _calculation(result)["value"]["raw"] == 0
    assert "PRIVATE_NUMERIC_ERROR" not in repr(result)
    assert "LOCAL_PRIVATE_CONTROLLER_FAILURE_0xabcdef" not in repr(result)


def test_supported_inputs_reconstruct_current_value_and_match_cache(tmp_path, monkeypatch):
    context = g02.make_context()
    report = _report(context, gate=_gates(active=True, bonus=50))
    target = report["capture"]["observation"]["backend"]["targets"][0]
    _set_numeric(target, flat=50000, province_ratio=100, further_ratio=-100)
    _set_controller(target, raw=300)
    expected = calculate_current(50000, 100, 300, -100, 50)["raw"]
    main = target["fields"][module.FIELD_PROVINCE_TRADE_POWER]
    main["value"]["raw"] = expected
    main["raw_inputs"] = {"private_address": "0xmaincache", "trace": "private"}
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    calc = _calculation(result)
    assert result["status"] == "known"
    assert result["value"]["raw"] == expected
    assert calc["status"] == "known"
    assert calc["value"] == {"raw": expected, "scale": 1000, "unit": "trade_power"}
    assert calc["matches_cache"] is True
    assert calc["basis"] == "native_province_trade_power_cache_writer_reconstruction"
    assert calc["native_function_invoked"] is False
    assert calc["acquisition_delta_evaluated"] is False
    assert "raw_inputs" not in repr(result)
    assert "0xmaincache" not in repr(result)


def test_cache_mismatch_is_reported_without_withholding_observed_power(tmp_path, monkeypatch):
    context = g02.make_context()
    report = _report(context, gate=_gates(active=True, bonus=-25))
    target = report["capture"]["observation"]["backend"]["targets"][0]
    _set_numeric(target, flat=1200, province_ratio=250, further_ratio=500)
    _set_controller(target, raw=175)
    expected = calculate_current(1200, 250, 175, 500, -25)["raw"]
    assert expected != 1250
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    assert _calculation(result)["status"] == "known"
    assert _calculation(result)["value"]["raw"] == expected
    assert _calculation(result)["matches_cache"] is False


def test_inactive_owner_bonus_requires_zero_bonus_and_reconstructs(tmp_path, monkeypatch):
    context = g02.make_context()
    report = _report(context, gate=_gates(active=False, bonus=0))
    target = report["capture"]["observation"]["backend"]["targets"][0]
    _set_numeric(target, flat=40000, province_ratio=50, further_ratio=20)
    _set_controller(target, raw=75)
    expected = calculate_current(40000, 50, 75, 20, 0)["raw"]
    target["fields"][module.FIELD_PROVINCE_TRADE_POWER]["value"]["raw"] = expected
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert _calculation(result)["status"] == "known"
    assert _calculation(result)["value"]["raw"] == expected
    assert _calculation(result)["matches_cache"] is True


@pytest.mark.parametrize(
    "gate_value",
    [
        {"province_node_enabled": 1, "controller_type_enabled": None,
         "owner_bonus_active": None, "owner_bonus_raw": None},
        {"province_node_enabled": False, "controller_type_enabled": True,
         "owner_bonus_active": None, "owner_bonus_raw": None},
        {"province_node_enabled": True, "controller_type_enabled": False,
         "owner_bonus_active": False, "owner_bonus_raw": 0},
        {"province_node_enabled": True, "controller_type_enabled": True,
         "owner_bonus_active": False, "owner_bonus_raw": 1},
        {"province_node_enabled": True, "controller_type_enabled": True,
         "owner_bonus_active": True, "owner_bonus_raw": True},
        {"province_node_enabled": True, "controller_type_enabled": True,
         "owner_bonus_active": True, "owner_bonus_raw": 1 << 31},
        {"province_node_enabled": True, "controller_type_enabled": True,
         "owner_bonus_active": None, "owner_bonus_raw": None},
        {"province_node_enabled": True, "controller_type_enabled": True,
         "owner_bonus_active": True, "owner_bonus_raw": 50, "extra": 1},
    ],
)
def test_malformed_gate_values_are_local_unknowns(tmp_path, monkeypatch, gate_value):
    context = g02.make_context()
    gate = _gates()
    gate["value"] = gate_value
    report = _report(context, gate=gate)
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    assert _calculation(result)["status"] == "unknown"
    assert _calculation(result)["reason"] == CALCULATION_REASON
    assert _calculation(result)["basis"] == "native_province_trade_power_cache_writer_reconstruction"


@pytest.mark.parametrize(
    ("item_change", "consistency"),
    [
        ({"status": "unknown", "reason": "PRIVATE_GATE_REASON"}, {"status": "unknown"}),
        ({"status": "known", "basis": "wrong"}, {"status": "stable"}),
        ({"status": "known", "period": "forecast"}, {"status": "stable"}),
        ({"status": "known", "complete": True}, {"status": "stable"}),
        ({"status": "known"}, {"status": "changed"}),
    ],
)
def test_gate_envelope_or_field_change_only_withholds_calculation(
        tmp_path, monkeypatch, item_change, consistency):
    context = g02.make_context()
    report = _report(context, gate=_gates())
    target = report["capture"]["observation"]["backend"]["targets"][0]
    target["fields"][GATES_FIELD].update(item_change)
    target["field_consistency"][GATES_FIELD] = consistency
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    assert _calculation(result)["status"] == "unknown"
    assert _calculation(result)["reason"] == CALCULATION_REASON
    assert "PRIVATE_GATE_REASON" not in repr(result)


@pytest.mark.parametrize(
    ("field", "mutate"),
    [
        ("G02.province_trade_power_value", lambda value: value.update(raw=True)),
        ("G02.province_trade_power_modifier", lambda value: value.update(scale=True)),
        ("G02.province_trade_power_further_modifier", lambda value: value.update(unit="ducats")),
    ],
)
def test_bad_numeric_child_only_withholds_calculation(
        tmp_path, monkeypatch, field, mutate):
    context = g02.make_context()
    report = _report(context, gate=_gates(active=True, bonus=0))
    target = report["capture"]["observation"]["backend"]["targets"][0]
    _set_numeric(target)
    mutate(target["fields"][field]["value"])
    target["fields"][field]["reason"] = "PRIVATE_NUMERIC_REASON_0x1234"
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    assert _calculation(result)["status"] == "unknown"
    assert _calculation(result)["reason"] == CALCULATION_REASON
    assert result["numeric_modifiers"][field.removeprefix("G02.")]["status"] == "unknown"
    assert "PRIVATE_NUMERIC_REASON_0x1234" not in repr(result)


def test_unknown_numeric_child_with_both_gates_true_only_withholds_calculation(
        tmp_path, monkeypatch):
    context = g02.make_context()
    report = _report(context, gate=_gates(active=True, bonus=0))
    target = report["capture"]["observation"]["backend"]["targets"][0]
    _set_numeric(target)
    field = "G02.province_trade_power_modifier"
    target["fields"][field].update(
        status="unknown", reason="PRIVATE_UNKNOWN_NUMERIC_0x1234")
    target["field_consistency"][field] = {"status": "unknown"}
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    assert _calculation(result)["status"] == "unknown"
    assert _calculation(result)["reason"] == CALCULATION_REASON
    assert result["numeric_modifiers"]["province_trade_power_modifier"]["status"] == "unknown"
    assert "PRIVATE_UNKNOWN_NUMERIC_0x1234" not in repr(result)


@pytest.mark.parametrize(
    ("status", "raw", "scale", "unit", "consistency"),
    [
        ("unknown", 300, 1000, "ratio", "unknown"),
        ("known", True, 1000, "ratio", "stable"),
        ("known", 300, 1, "ratio", "stable"),
        ("known", 300, 1000, "ducats", "stable"),
        ("known", 300, 1000, "ratio", "changed"),
    ],
)
def test_bad_controller_child_only_withholds_calculation(
        tmp_path, monkeypatch, status, raw, scale, unit, consistency):
    context = g02.make_context()
    report = _report(context, gate=_gates(active=True, bonus=0))
    target = report["capture"]["observation"]["backend"]["targets"][0]
    _set_numeric(target)
    _set_controller(target, raw=raw, status=status, unit=unit)
    target["fields"]["G02.controller_global_province_trade_power_modifier"]["value"]["scale"] = scale
    target["fields"]["G02.controller_global_province_trade_power_modifier"]["reason"] = "PRIVATE_CONTROLLER_REASON"
    target["field_consistency"]["G02.controller_global_province_trade_power_modifier"] = {
        "status": consistency,
    }
    reader, _base, _calls, context = _make_reader(
        tmp_path, monkeypatch, report=report, context=context)

    result = _read(reader, context)

    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    assert _calculation(result)["status"] == "unknown"
    assert result["country_modifiers"]["controller"]["status"] == "unknown"
    assert "PRIVATE_CONTROLLER_REASON" not in repr(result)


def test_strict_capture_replay_failure_withholds_entire_calculation_projection(
        tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _base, calls, context = _make_reader(
        tmp_path, monkeypatch, validator_result=False, context=context)

    result = _read(reader, context)

    assert calls["validate"]
    assert result["status"] == "unknown"
    assert "calculation" not in result
