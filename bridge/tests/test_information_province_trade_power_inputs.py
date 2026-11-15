"""Typed numeric inputs must share the validated province capture identity."""
from copy import deepcopy

import pytest

from bridge.information import province_trade_power as module
from bridge.tests import test_information_province_trade_power as fixtures
from bridge.tests import test_information_province_state as g02


def report_for(context):
    report = fixtures._capture_report(context)
    target = report['capture']['observation']['backend']['targets'][0]
    for field, unit in module._NUMERIC_FIELDS.items():
        target['fields'][field] = {'status': 'known', 'complete': False, 'period': 'current',
            'basis': module._NUMERIC_BASIS, 'value': {'raw': 0, 'scale': 1000, 'unit': unit},
            'raw_inputs': {'private_address': '0x123456789', 'read_trace': ['not public']}}
        target['field_consistency'][field] = {'status': 'stable'}
    return report


def make(tmp_path, monkeypatch, report, **options):
    old, base, calls = fixtures._make_reader(tmp_path, monkeypatch, report=report, **options)
    reader = module.NativeProvinceTradePowerReader(base, capture=old.capture, with_numeric_inputs=True)
    return reader, base, calls


def test_numeric_inputs_are_published_only_with_the_main_capture_and_do_not_expose_trace(tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _, calls = make(tmp_path, monkeypatch, report_for(context))
    result = reader.read(183, context)
    assert result['status'] == 'known'
    assert len(calls['capture']) == len(calls['validate']) == 1
    assert set(result['numeric_modifiers']) == {k.removeprefix('G02.') for k in module._NUMERIC_FIELDS}
    for key, item in result['numeric_modifiers'].items():
        assert item['status'] == 'known'
        assert item['value'] == {'raw': 0, 'scale': 1000, 'unit': module._NUMERIC_FIELDS['G02.' + key]}
        assert item['complete'] is False
    assert 'private_address' not in str(result) and 'read_trace' not in str(result)
    assert result['acquisition_delta_evaluated'] is False


@pytest.mark.parametrize('mutation', [
    lambda f, c: f['value'].update(raw=True),
    lambda f, c: f['value'].update(raw=1 << 31),
    lambda f, c: f['value'].update(scale=True),
    lambda f, c: f['value'].update(scale=100),
    lambda f, c: f['value'].update(unit='ducats'),
    lambda f, c: f.update(basis='raw_unqualified_storage'),
    lambda f, c: f.update(complete=True),
    lambda f, c: f.update(period='forecast'),
    lambda f, c: f.update(status='unknown'),
    lambda f, c: c.update(status='changed'),
])
def test_invalid_or_changing_input_stays_unknown_without_losing_current_power(tmp_path, monkeypatch, mutation):
    context = g02.make_context()
    report = report_for(context)
    target = report['capture']['observation']['backend']['targets'][0]
    field = 'G02.province_trade_power_modifier'
    mutation(target['fields'][field], target['field_consistency'][field])
    reader, _, _ = make(tmp_path, monkeypatch, report)
    result = reader.read(183, context)
    assert result['status'] == 'known'
    assert result['value']['raw'] == 1250
    invalid = result['numeric_modifiers']['province_trade_power_modifier']
    assert invalid['status'] == 'unknown' and 'value' not in invalid
    assert result['numeric_modifiers']['province_trade_power_value']['status'] == 'known'


def test_missing_expected_numeric_field_rejects_the_capture(tmp_path, monkeypatch):
    context = g02.make_context()
    report = report_for(context)
    del report['capture']['observation']['backend']['targets'][0]['fields']['G02.province_trade_power_value']
    reader, _, _ = make(tmp_path, monkeypatch, report)
    result = reader.read(183, context)
    assert result['status'] == 'unknown' and 'numeric_modifiers' not in result


def test_valid_numeric_values_cannot_bypass_strict_capture_replay(tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _, calls = make(tmp_path, monkeypatch, report_for(context), validator_result=False)
    result = reader.read(183, context)
    assert calls['validate'] and result['status'] == 'unknown'
    assert 'numeric_modifiers' not in result


def test_numeric_capture_selects_the_new_owner_module(tmp_path, monkeypatch):
    context = g02.make_context()
    reader, _, _ = make(tmp_path, monkeypatch, report_for(context))
    original_import = module.import_module
    names = []

    def importing(name, package):
        names.append(name)
        return original_import(name, package)

    monkeypatch.setattr(module, 'import_module', importing)
    assert reader.read(183, context)['status'] == 'known'
    assert names == ['.province_trade_power_inputs_capture']
