"""The self-target packet keeps both-pass guards and a scalar-only projection."""
from copy import deepcopy
import pytest
from bridge.information import relations_capacity_capture as capture

def _field(value):
    return {'status': 'known', 'value': value, 'raw': value,
        'raw_hex': value.to_bytes(4, 'little', signed=True).hex(),
        'unit': 'diplomatic_relation', 'scale': 1, 'period': 'current',
        'partial': True, 'complete': False, 'basis': capture._BASIS,
        'value_origin': capture._ORIGIN, 'raw_inputs': {'private_address': '0x12345678'}}

def _report(observer='FRA'):
    gate = {'status': 'known', 'admitted': True, 'observer_nonplayer_role': {'verified': True}}
    return {'schema': capture.SCHEMA, 'status': 'observed', 'completed': True,
        'request': {'observer': observer, 'country': observer},
        'profile_sha256': capture.PROFILE_SHA256, 'observation': {'stable': True,
        'backend': {'targets': [{'tag': observer, 'admission_by_pass': {
            'pass1': deepcopy(gate), 'pass2': deepcopy(gate)},
            'fields': {'N05.relations_count': _field(5), 'N05.relations_limit': _field(4)},
            'field_consistency': {name: {'status': 'stable'} for name in capture.FIELDS}}]}}}

@pytest.mark.parametrize('observer', ['FRA', 'TUR', 'D01'])
def test_projection_keeps_count_above_capacity_and_strips_private_inputs(observer):
    output = capture.project_fields(_report(observer))
    assert output['relations_count']['value'] == 5
    assert output['relations_limit']['value'] == 4
    assert 'private_address' not in repr(output) and '0x12345678' not in repr(output)

@pytest.mark.parametrize('phase', ['pass1', 'pass2'])
@pytest.mark.parametrize('change', ['role', 'admitted'])
def test_either_pass_role_or_admission_failure_refuses_publication(phase, change):
    report = _report()
    gate = report['observation']['backend']['targets'][0]['admission_by_pass'][phase]
    if change == 'role':
        gate['observer_nonplayer_role']['verified'] = False
    else:
        gate['admitted'] = False
    with pytest.raises(ValueError, match='PUBLICATION_GATE'):
        capture.project_fields(report)

def test_one_unknown_scalar_does_not_remove_the_other():
    report = _report()
    report['observation']['backend']['targets'][0]['fields']['N05.relations_limit'] = {
        'status': 'unknown', 'reason': 'MODIFIER_PROCESSOR_PRESENT'}
    output = capture.project_fields(report)
    assert output['relations_count']['status'] == 'known'
    assert output['relations_limit'] == {'status': 'unknown', 'reason': 'MODIFIER_PROCESSOR_PRESENT'}

@pytest.mark.parametrize('alteration', ['boolean_scale', 'raw_mismatch', 'unstable', 'unsafe_reason'])
def test_bad_scalar_or_unstable_evidence_stays_unknown(alteration):
    report = _report()
    target = report['observation']['backend']['targets'][0]
    field = target['fields']['N05.relations_count']
    if alteration == 'boolean_scale':
        field['scale'] = True
    elif alteration == 'raw_mismatch':
        field['raw_hex'] = '06000000'
    elif alteration == 'unstable':
        target['field_consistency']['N05.relations_count']['status'] = 'mismatch'
    else:
        target['fields']['N05.relations_count'] = {'status': 'unknown', 'reason': 'ADDRESS_0x12345678'}
    output = capture.project_fields(report)
    assert output['relations_count']['status'] == 'unknown'
    assert output['relations_limit']['status'] == 'known'
    assert '0x12345678' not in repr(output)

def test_self_capture_and_validation_explicitly_retain_shared_strict_owner(monkeypatch):
    calls = []
    def fake_capture(installation, country, **kwargs):
        calls.append((installation, country, kwargs))
        return {'fixture': True}
    monkeypatch.setattr(capture._owner, '_capture_common', fake_capture)
    assert capture.capture('installation.json', observer='TUR') == {'fixture': True}
    assert calls[0][1] == 'TUR'
    assert calls[0][2]['observer'] == 'TUR'
    assert calls[0][2]['observer_scoped'] is True
    assert calls[0][2]['allow_observer_target'] is True
    assert calls[0][2]['observe'] is capture._observe
    assert calls[0][2]['load_profile'] is capture._load_profile
    validation = []
    def fake_validate(report, context, creation, country, **kwargs):
        validation.append((country, kwargs))
        return True
    monkeypatch.setattr(capture._owner, '_validate_capture_common', fake_validate)
    assert capture.validate_capture({}, {'observer': 'TUR'}, 123) is True
    assert validation[0][0] == 'TUR'
    assert validation[0][1]['observer_scoped'] is True
    assert validation[0][1]['require_access'] is True
    assert validation[0][1]['allow_observer_target'] is True
    assert validation[0][1]['schema'] == capture.SCHEMA
