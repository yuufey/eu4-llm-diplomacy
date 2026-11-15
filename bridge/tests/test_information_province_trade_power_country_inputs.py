"""Public projection tests for the optional country trade-power modifiers."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import province_trade_power as module
from bridge.tests import test_information_province_trade_power as fixtures
from bridge.tests import test_information_province_trade_power_inputs as numeric_fixtures
from bridge.tests import test_information_province_state as g02

PROVINCE_ID = 183


def _report(context):
    report = numeric_fixtures.report_for(context)
    target = report["capture"]["observation"]["backend"]["targets"][0]
    for field, role in module._COUNTRY_FIELDS.items():
        country = "FRA" if role == "observer" else "SWE"
        target["fields"][field] = {
            "status": "known", "complete": False, "period": "current",
            "basis": module._COUNTRY_BASIS,
            "value": {"country": country, "raw": 300 if role == "controller" else 200,
                      "scale": 1000, "unit": "ratio"},
            "raw_inputs": {"country_pointer": "0x123456789abcdef0", "trace": "private"},
        }
        target["field_consistency"][field] = {"status": "stable"}
    return report


def _make_reader(tmp_path, monkeypatch, *, report=None, validator_result=True,
                 capture_override=True, context=None):
    current = deepcopy(context or g02.make_context())
    old, base, calls = fixtures._make_reader(
        tmp_path, monkeypatch, report=report or _report(current),
        validator_result=validator_result, capture_override=capture_override,
        context=current)
    reader = module.NativeProvinceTradePowerReader(
        base, capture=old.capture if capture_override else None,
        with_numeric_inputs=True, with_country_inputs=True)
    return reader, base, calls


def test_country_values_are_published_as_typed_current_annotations_without_raw_trace(
        tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _base, calls = _make_reader(tmp_path, monkeypatch, context=context)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert result["value"] == {"raw": 1250, "scale": 1000, "unit": "trade_power"}
    assert set(result["country_modifiers"]) == {"controller", "observer"}
    assert result["country_modifiers"]["controller"] == {
        "status": "known", "value": {"country": "SWE", "raw": 300,
            "scale": 1000, "unit": "ratio"}, "basis": module._COUNTRY_BASIS,
        "period": "current", "partial": True, "complete": False}
    assert result["country_modifiers"]["observer"]["value"] == {
        "country": "FRA", "raw": 200, "scale": 1000, "unit": "ratio"}
    assert result["partial"] is True and result["complete"] is False
    assert result["acquisition_delta_evaluated"] is False
    assert result["cache_refresh_timing_verified"] is False
    assert len(calls["validate"]) == 1
    assert "raw_inputs" not in repr(result)
    assert "raw_reads" not in repr(result)
    assert "country_pointer" not in repr(result)
    assert "0x123456789abcdef0" not in repr(result)


@pytest.mark.parametrize(("role", "bad_value"), [
    ("controller", {"country": "SWE", "raw": True, "scale": 1000, "unit": "ratio"}),
    ("controller", {"country": "SWE", "raw": 10, "scale": 1000, "unit": "ducats"}),
    ("observer", {"country": "POR", "raw": 10, "scale": 1000, "unit": "ratio"}),
])
def test_invalid_country_child_is_local_and_preserves_main_power(
        tmp_path, monkeypatch, role, bad_value):
    context = g02.make_context()
    report = _report(context)
    field = next(field for field, field_role in module._COUNTRY_FIELDS.items()
                 if field_role == role)
    report["capture"]["observation"]["backend"]["targets"][0]["fields"][field]["value"] = bad_value
    reader, _base, _calls = _make_reader(tmp_path, monkeypatch, report=report, context=context)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    projected = result["country_modifiers"][role]
    assert projected["status"] == "unknown"
    assert projected["reason"] == "PROVINCE_TRADE_POWER_COUNTRY_INPUT_UNKNOWN"
    assert "value" not in projected
    other = "observer" if role == "controller" else "controller"
    assert result["country_modifiers"][other]["status"] == "known"


def test_unknown_country_leaf_does_not_withhold_observed_province_power(tmp_path, monkeypatch):
    context = g02.make_context()
    report = _report(context)
    target = report["capture"]["observation"]["backend"]["targets"][0]
    observer_field = next(field for field, role in module._COUNTRY_FIELDS.items()
                          if role == "observer")
    target["fields"][observer_field] = {
        "status": "unknown", "reason": "PRIVATE_0x123456789", "complete": False,
        "basis": module._COUNTRY_BASIS, "period": "current", "raw_inputs": {"secret": "x"}}
    target["field_consistency"][observer_field] = {"status": "unknown"}
    reader, _base, _calls = _make_reader(tmp_path, monkeypatch, report=report, context=context)

    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert result["value"]["raw"] == 1250
    assert result["country_modifiers"]["observer"]["status"] == "unknown"
    assert result["country_modifiers"]["observer"]["reason"] == (
        "PROVINCE_TRADE_POWER_COUNTRY_INPUT_UNKNOWN")
    assert "PRIVATE_0x123456789" not in repr(result)


def test_strict_capture_replay_failure_withholds_country_projection(tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _base, calls = _make_reader(
        tmp_path, monkeypatch, validator_result=False, context=context)

    result = reader.read(PROVINCE_ID, context)

    assert calls["validate"]
    assert result["status"] == "unknown"
    assert "country_modifiers" not in result
    assert "numeric_modifiers" not in result


def test_reader_selects_the_country_capture_owner_module(tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _base, calls = _make_reader(
        tmp_path, monkeypatch, capture_override=False, context=context)
    original = module.import_module
    names = []

    def importing(name, package):
        names.append(name)
        return original(name, package)

    monkeypatch.setattr(module, "import_module", importing)
    result = reader.read(PROVINCE_ID, context)

    assert result["status"] == "known"
    assert names == [".province_trade_power_country_capture"]
    assert len(calls["module_capture"]) == 1
    assert len(calls["validate"]) == 1


def test_country_inputs_require_numeric_inputs_to_be_enabled(tmp_path):
    context = g02.make_context()
    base = g02.Base(tmp_path, context)

    with pytest.raises(ValueError, match="COUNTRY_INPUT_OPTION_INVALID"):
        module.NativeProvinceTradePowerReader(base, with_country_inputs=True)
