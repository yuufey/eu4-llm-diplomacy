"""Exact DTO checks for copied country-modifier membership and scholar mapping."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import religious_scholars_values as values


PINS = {
    'configuration_sha256': '1' * 64,
    'definitions_sha256': '2' * 64,
    'parser_manifest_sha256': '3' * 64,
    'cwt_sha256': '4' * 64,
    'cwt_commit': 'a' * 40,
}


def _instance(key='sunni_scholar_a', *, source='direct', flags=None,
              start_date_raw=-12, date_raw=2147483647):
    if source == 'secondary':
        return {
            'source': source, 'key': key, 'start_date_raw': None,
            'date_raw': None, 'flags': None,
        }
    return {
        'source': source, 'key': key,
        'start_date_raw': start_date_raw, 'date_raw': date_raw,
        'flags': deepcopy(flags if flags is not None else {
            'ruler_modifier': 1, 'parliament_modifier': 0,
            'permanent': 0, 'hidden': 255,
        }),
    }


def _native(*, invited=None, has_school=True):
    return {
        'has_school': has_school,
        'religion_key': 'sunni',
        'religion_group_key': 'muslim',
        'current_school': ({'status': 'known', 'key': 'hanafi_school'} if has_school
                           else {'status': 'none', 'reason': 'NATIVE_SCHOOL_SENTINEL'}),
        'uses_schools': {'status': 'known', 'value': True},
        'invited_scholars': deepcopy(invited if invited is not None else {
            'status': 'unknown', 'reason': 'SCHOLAR_MODIFIERS_UNAVAILABLE',
        }),
        'relations': {'status': 'unknown', 'reason': 'SCHOOL_RELATIONS_NOT_READ'},
    }


def _definition():
    return {
        'relative_file': 'common/religions/eu4_religions.txt',
        'line': 1, 'file_sha256': 'b' * 64, 'source_kind': 'basegame',
    }


def _mapping_row(group='muslim', school='hanafi_school', modifier='sunni_scholar_a'):
    return {
        'religion_group_key': group,
        'school_key': school,
        'modifier_key': modifier,
        'definition': _definition(),
        'source_pins': deepcopy(PINS),
        'conditions_evaluated': False,
        'effects_executed': False,
        'runtime_state_observed': False,
    }


def _mapping(rows=None):
    return {
        'status': 'known',
        'mappings': deepcopy(rows if rows is not None else [_mapping_row()]),
        'source_pins': deepcopy(PINS),
        'conditions_evaluated': False,
        'effects_executed': False,
        'runtime_state_observed': False,
    }


def _known_child(instances=None):
    return {
        'status': 'known', 'membership_complete': True,
        'modifier_instances': deepcopy(instances if instances is not None else []),
    }


def test_native_value_validates_activation_and_copies_modifier_rows():
    original = _native(invited=_known_child([
        _instance(), _instance('has_invited_scholar_recently', source='secondary'),
    ]))
    result = values.native_value(original, 'TUR')
    assert result == original
    assert result is not original
    assert result['invited_scholars'] is not original['invited_scholars']
    result['invited_scholars']['modifier_instances'][0]['flags']['hidden'] = 0
    assert original['invited_scholars']['modifier_instances'][0]['flags']['hidden'] == 255


@pytest.mark.parametrize('reason', [
    'SCHOLAR_MODIFIERS_UNAVAILABLE', 'SCHOLAR_MODIFIERS_CHANGED',
])
def test_unknown_native_scholar_child_is_preserved(reason):
    native = _native(invited={'status': 'unknown', 'reason': reason})
    assert values.native_value(native, 'TUR') == native
    projected = values.public_value(native, 'TUR', {'malformed': True})
    assert projected['invited_scholars'] == {'status': 'unknown', 'reason': reason}


@pytest.mark.parametrize('child', [
    {'status': 'unknown', 'reason': 'UNRECOGNIZED'},
    {'status': 'unknown', 'reason': ['SCHOLAR_MODIFIERS_CHANGED']},
    {'status': 'unknown', 'reason': 'SCHOLAR_MODIFIERS_CHANGED', 'private_address': '0x1234'},
    {'status': 'known', 'membership_complete': 1, 'modifier_instances': []},
    {'status': 'known', 'membership_complete': True, 'modifier_instances': [], 'address': '0x1234'},
    {'status': 'known', 'membership_complete': True, 'modifier_instances': [None]},
])
def test_native_child_unknown_or_exact_shape_is_required(child):
    with pytest.raises((TypeError, ValueError)):
        values.native_value(_native(invited=child), 'TUR')


@pytest.mark.parametrize('bad', [
    {'start_date_raw': True},
    {'date_raw': 1 << 31},
    {'date_raw': -(1 << 31) - 1},
    {'key': 'bad key'},
    {'key': 'x' * 256},
    {'flags': {'ruler_modifier': True, 'parliament_modifier': 0,
               'permanent': 0, 'hidden': 0}},
    {'flags': {'ruler_modifier': 0, 'parliament_modifier': 0,
               'permanent': 0, 'hidden': True}},
    {'flags': {'ruler_modifier': 0, 'parliament_modifier': 0,
               'permanent': 0, 'hidden': 256}},
    {'flags': {'ruler_modifier': 0, 'parliament_modifier': 0,
               'permanent': 0, 'hidden': 0, 'extra': 0}},
    {'source': 'other'},
])
def test_direct_instance_rejects_bad_fields(bad):
    row = _instance()
    row.update(deepcopy(bad))
    with pytest.raises(ValueError):
        values.native_value(_native(invited=_known_child([row])), 'TUR')


@pytest.mark.parametrize('row', [
    {**_instance(source='secondary'), 'date_raw': 0},
    {**_instance(source='secondary'), 'flags': {}},
    {**_instance(source='secondary'), 'start_date_raw': -1},
    {**_instance(source='secondary'), 'private_address': '0x1234'},
])
def test_secondary_instance_has_no_native_date_or_flag_data(row):
    with pytest.raises(ValueError):
        values.native_value(_native(invited=_known_child([row])), 'TUR')


def test_modifier_instance_limit_is_256():
    rows = [_instance(f'modifier_{i}') for i in range(256)]
    assert len(values.native_value(_native(invited=_known_child(rows)), 'TUR')
               ['invited_scholars']['modifier_instances']) == 256
    with pytest.raises(ValueError):
        values.native_value(_native(invited=_known_child(rows + [_instance('too_many')])), 'TUR')


def test_public_value_projects_exact_key_membership_and_keeps_dates_uninterpreted():
    direct = _instance('sunni_scholar_a', flags={
        'ruler_modifier': 0, 'parliament_modifier': 0,
        'permanent': 0, 'hidden': 7,
    }, start_date_raw=123, date_raw=-456)
    secondary = _instance('sunni_scholar_a', source='secondary')
    cooldown = _instance('has_invited_scholar_recently', source='secondary')
    absent = _mapping_row(school='shafii_school', modifier='sunni_scholar_b')
    native = _native(invited=_known_child([direct, secondary, cooldown]))

    projected = values.public_value(native, 'TUR', _mapping([_mapping_row(), absent]))

    assert set(projected) == set(native)
    assert projected['has_school'] is True
    invited = projected['invited_scholars']
    assert set(invited) == {
        'status', 'membership_complete', 'basis', 'scholars',
        'invitation_cooldown', 'invitation_history', 'date_semantics', 'complete',
    }
    assert invited['status'] == 'known' and invited['membership_complete'] is True
    assert invited['basis'] == 'native_country_modifier_key_membership'
    assert invited['scholars'] == [
        {'religion_group_key': 'muslim', 'school_key': 'hanafi_school',
         'modifier_key': 'sunni_scholar_a', 'present': True,
         'instances': [direct, secondary]},
        {'religion_group_key': 'muslim', 'school_key': 'shafii_school',
         'modifier_key': 'sunni_scholar_b', 'present': False, 'instances': []},
    ]
    assert invited['invitation_cooldown'] == {
        'modifier_key': 'has_invited_scholar_recently', 'present': True,
        'instances': [cooldown],
    }
    assert invited['invitation_history'] == {
        'status': 'unknown', 'reason': 'SCHOLAR_INVITATION_HISTORY_NOT_READ',
    }
    assert invited['date_semantics'] == 'copied_raw_dates_expiry_and_timer_unproven'
    assert invited['complete'] is False
    assert invited['scholars'][0]['instances'][0]['date_raw'] == -456


def test_mapping_failure_is_local_and_does_not_retract_other_six_members():
    native = _native(invited=_known_child([_instance()]))
    malformed = deepcopy(_mapping())
    malformed['mappings'][0]['effects_executed'] = True
    projected = values.public_value(native, 'TUR', malformed)
    assert projected['religion_key'] == native['religion_key']
    assert projected['religion_group_key'] == native['religion_group_key']
    assert projected['uses_schools'] == native['uses_schools']
    assert projected['current_school'] == native['current_school']
    assert projected['invited_scholars'] == {
        'status': 'unknown', 'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE',
    }


@pytest.mark.parametrize('mutate', [
    lambda m: m.update(extra=True),
    lambda m: m.update(conditions_evaluated=True),
    lambda m: m.update(runtime_state_observed=True),
    lambda m: m.update(source_pins={**PINS, 'extra': 'pin'}),
    lambda m: m['mappings'].append(deepcopy(m['mappings'][0])),
    lambda m: m['mappings'][0].update(modifier_key='bad modifier'),
    lambda m: m['mappings'][0].update(source_pins={**PINS, 'cwt_sha256': 'bad'}),
    lambda m: m['mappings'][0]['definition'].update(extra=True),
    lambda m: m['mappings'][0]['definition'].update(relative_file='../religions.txt'),
    lambda m: m['mappings'][0]['definition'].update(line=True),
    lambda m: m['mappings'][0]['definition'].update(source_kind='runtime'),
])
def test_malformed_or_ambiguous_mapping_is_unknown(mutate):
    mapping = _mapping()
    mutate(mapping)
    projected = values.public_value(_native(invited=_known_child([_instance()])), 'TUR', mapping)
    assert projected['invited_scholars'] == {
        'status': 'unknown', 'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE',
    }


def test_exact_unknown_mapping_shape_projects_unknown():
    projected = values.public_value(
        _native(invited=_known_child([])), 'TUR',
        {'status': 'unknown', 'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE'},
    )
    assert projected['invited_scholars'] == {
        'status': 'unknown', 'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE',
    }


@pytest.mark.parametrize('relative_file', [
    'common/religions/mod/expanded/religions.txt',
    'common/religions/override.TXT',
])
def test_mapping_definition_accepts_nested_mod_paths_and_casefold_txt(relative_file):
    mapping = _mapping()
    mapping['mappings'][0]['definition']['relative_file'] = relative_file
    projected = values.public_value(_native(invited=_known_child([])), 'TUR', mapping)
    assert projected['invited_scholars']['status'] == 'known'
    assert projected['invited_scholars']['scholars'][0]['present'] is False
