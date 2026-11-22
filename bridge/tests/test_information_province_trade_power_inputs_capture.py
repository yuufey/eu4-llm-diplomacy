"""The numeric capture pins its own profile and the same canonical province."""
from copy import deepcopy

import pytest

from bridge.information import province_trade_power_inputs_capture as module


def test_active_profile_has_all_four_fields_and_current_source_dependencies():
    profile = module._load_profile()
    assert profile['semantics']['supported_fields'] == list(module.FIELDS)
    assert profile['layout']['province_trade_power_inputs'] == module.LAYOUT
    assert profile['limits']['read_bytes'] == 512 * 1024
    assert profile['semantics']['controller_country_modifier_included'] is False


def test_capture_selects_exact_fields_and_reuses_parent_lifecycle(monkeypatch):
    calls = []

    def two_pass(reader, base, province_id, **kwargs):
        calls.append((base, province_id, kwargs))
        return {'status': 'observed'}

    def observe(reader, base, country, profile, *, backend_reader):
        assert country == 'FRA'
        return backend_reader(reader, base, country)

    monkeypatch.setattr(module._province, 'read_two_pass', two_pass)
    monkeypatch.setattr(module._owner, '_observe', observe)
    result = module._observe_for(183)(object(), 0x140000000, 'FRA', {})
    assert result['status'] == 'observed'
    assert calls[0][1] == 183
    assert calls[0][2]['fields'] == module.FIELDS
    assert calls[0][2]['read_fields'] is module._leaf.read_fields


@pytest.mark.parametrize('pid', [True, 0, -1, 65536, '183'])
def test_invalid_province_never_opens_a_capture(monkeypatch, pid):
    def fail(*args, **kwargs):
        pytest.fail('invalid scope opened a process')
    monkeypatch.setattr(module._owner, '_capture_common', fail)
    with pytest.raises(ValueError):
        module.capture('unused', pid)


def test_validator_checks_outer_identity_before_replay_and_requires_access(monkeypatch):
    calls = []
    monkeypatch.setattr(module._owner, '_validate_capture_common',
        lambda *args, **kwargs: calls.append((args, kwargs)) or True)
    report = {'schema': module.SCHEMA, 'observer': 'FRA',
        'object': {'type': 'province', 'province_id': 183}, 'capture': {}}
    assert module.validate_capture(report, {'observer': 'FRA'}, 99, 183)
    assert calls[0][1]['require_access'] is True
    assert calls[0][1]['observer_scoped'] is True
    assert calls[0][1]['load_profile'] is module._load_profile
    altered = deepcopy(report)
    altered['object']['province_id'] = True
    assert not module.validate_capture(altered, {'observer': 'FRA'}, 99, 183)
    assert not module.validate_capture(report, {'observer': 'TUR'}, 99, 183)
    assert len(calls) == 1


def test_profile_tampering_is_rejected_before_a_memory_read(tmp_path, monkeypatch):
    path = tmp_path / 'profile.json'
    path.write_bytes(module.PROFILE_FILE.read_bytes() + b' ')
    monkeypatch.setattr(module, 'PROFILE_FILE', path)
    with pytest.raises(ValueError, match='PROFILE_PIN'):
        module._load_profile()
