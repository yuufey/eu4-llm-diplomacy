"""Exact DTO checks for current school-pair relation-cache values."""
from __future__ import annotations

from copy import deepcopy

import pytest

from bridge.information import school_relations_values as values


PINS = {
    'configuration_sha256': '1' * 64,
    'definitions_sha256': '2' * 64,
    'parser_manifest_sha256': '3' * 64,
    'cwt_sha256': '4' * 64,
    'cwt_commit': 'a' * 40,
}


def _instance(key='jesuit_scholar_one'):
    return {
        'source': 'direct', 'key': key,
        'start_date_raw': -100, 'date_raw': 200,
        'flags': {'ruler_modifier': 1, 'parliament_modifier': 0,
                  'permanent': 1, 'hidden': 255},
    }


def _school_mapping():
    return {
        'relative_file': 'common/religions/religions.txt',
        'line': 7, 'file_sha256': 'b' * 64, 'source_kind': 'basegame',
    }


def _scholar_mapping():
    row = {
        'religion_group_key': 'christian', 'school_key': 'jesuits',
        'modifier_key': 'jesuit_scholar_one', 'definition': _school_mapping(),
        'source_pins': deepcopy(PINS), 'conditions_evaluated': False,
        'effects_executed': False, 'runtime_state_observed': False,
    }
    return {
        'status': 'known', 'mappings': [row], 'source_pins': deepcopy(PINS),
        'conditions_evaluated': False, 'effects_executed': False,
        'runtime_state_observed': False,
    }


def _known_relation(entries=None, **changes):
    value = {
        'status': 'known', 'religion_group_key': 'christian',
        'source_school_key': 'jesuits', 'symmetric': True,
        'entries': deepcopy(entries if entries is not None else [
            {'school_key': 'dominicans', 'status': 'known',
             'value': -2147483648, 'raw_hex': '00000080'},
            {'school_key': 'augustinians', 'status': 'unknown',
             'reason': 'SCHOOL_RELATION_NOT_FOUND'},
        ]),
        'complete': False, 'basis': 'native_school_pair_relation_cache',
    }
    value.update(changes)
    return value


def _native(*, has_school=True, invited=None, relations=None):
    return {
        'has_school': has_school,
        'religion_key': 'catholic',
        'religion_group_key': 'christian',
        'current_school': ({'status': 'known', 'key': 'jesuits'} if has_school else
                           {'status': 'none', 'reason': 'NATIVE_SCHOOL_SENTINEL'}),
        'uses_schools': {'status': 'known', 'value': False},
        'invited_scholars': deepcopy(invited if invited is not None else {
            'status': 'unknown', 'reason': 'SCHOLAR_MODIFIERS_CHANGED',
        }),
        'relations': deepcopy(relations if relations is not None else _known_relation()),
    }


def test_native_value_preserves_exact_symmetric_relation_entries():
    original = _native()
    result = values.native_value(original, 'ENG')
    assert result == original
    assert result is not original
    assert result['relations'] is not original['relations']
    assert result['relations']['entries'][0]['value'] == -(1 << 31)
    assert result['relations']['entries'][0]['raw_hex'] == '00000080'


@pytest.mark.parametrize('reason', [
    'SCHOOL_RELATIONS_UNAVAILABLE', 'SCHOOL_RELATIONS_CHANGED',
])
def test_unknown_relation_reasons_are_preserved(reason):
    native = _native(relations={'status': 'unknown', 'reason': reason})
    assert values.native_value(native, 'ENG')['relations'] == native['relations']


def test_no_current_school_allows_only_exact_not_applicable_relation():
    native = _native(has_school=False, relations={
        'status': 'not_applicable', 'reason': 'NO_CURRENT_RELIGIOUS_SCHOOL',
    })
    assert values.native_value(native, 'TUR')['relations'] == native['relations']
    with pytest.raises(ValueError):
        values.native_value(_native(relations={
            'status': 'not_applicable', 'reason': 'NO_CURRENT_RELIGIOUS_SCHOOL',
        }), 'ENG')


@pytest.mark.parametrize('changes', [
    {'religion_group_key': 'orthodox'},
    {'source_school_key': 'franciscan'},
    {'symmetric': False},
    {'complete': True},
    {'basis': 'configuration_range'},
    {'address': '0x12345678'},
])
def test_known_relation_requires_exact_parent_binding_and_shape(changes):
    with pytest.raises(ValueError):
        values.native_value(_native(relations=_known_relation(**changes)), 'ENG')


@pytest.mark.parametrize('entry', [
    {'school_key': 'dominicans', 'status': 'known', 'value': 4, 'raw_hex': '05000000'},
    {'school_key': 'dominicans', 'status': 'known', 'value': True, 'raw_hex': '01000000'},
    {'school_key': 'dominicans', 'status': 'known', 'value': 4, 'raw_hex': '0400000A'},
    {'school_key': 'dominicans', 'status': 'known', 'value': 4, 'raw_hex': '0400000'},
    {'school_key': 'dominicans', 'status': 'unknown', 'reason': 'WRONG'},
    {'school_key': 'dominicans', 'status': 'unknown', 'reason': 'SCHOOL_RELATION_NOT_FOUND',
     'raw_hex': '00000000'},
])
def test_relation_entry_raw_i32_pair_is_exact(entry):
    with pytest.raises(ValueError):
        values.native_value(_native(relations=_known_relation([entry])), 'ENG')


@pytest.mark.parametrize('entries', [
    [
        {'school_key': 'dominicans', 'status': 'unknown', 'reason': 'SCHOOL_RELATION_NOT_FOUND'},
        {'school_key': 'Dominicans', 'status': 'unknown', 'reason': 'SCHOOL_RELATION_NOT_FOUND'},
    ],
    [{'school_key': 'jesuits', 'status': 'unknown', 'reason': 'SCHOOL_RELATION_NOT_FOUND'}],
    [{'school_key': 'bad key', 'status': 'unknown', 'reason': 'SCHOOL_RELATION_NOT_FOUND'}],
])
def test_relation_destinations_reject_casefold_duplicates_self_and_bad_keys(entries):
    with pytest.raises(ValueError):
        values.native_value(_native(relations=_known_relation(entries)), 'ENG')


def test_relation_destination_limit_is_63_and_raw_range_is_not_clamped():
    entries = [
        {'school_key': f'school_{i}', 'status': 'known',
         'value': 2147483647, 'raw_hex': 'ffffff7f'}
        for i in range(63)
    ]
    assert len(values.native_value(_native(relations=_known_relation(entries)), 'ENG')
               ['relations']['entries']) == 63
    with pytest.raises(ValueError):
        values.native_value(_native(relations=_known_relation(entries + [
            {'school_key': 'school_extra', 'status': 'unknown',
             'reason': 'SCHOOL_RELATION_NOT_FOUND'},
        ])), 'ENG')


def test_public_value_restores_relations_after_scholar_projection():
    relation = _known_relation()
    raw = _native(invited={'status': 'known', 'membership_complete': True,
                           'modifier_instances': [_instance()]}, relations=relation)
    projected = values.public_value(raw, 'ENG', _scholar_mapping())
    assert projected['relations'] == relation
    assert projected['invited_scholars']['status'] == 'known'
    assert projected['invited_scholars']['scholars'][0]['present'] is True
    assert projected['invited_scholars']['scholars'][0]['instances'] == [_instance()]
    assert set(projected) == set(raw)


def test_bad_scholar_mapping_is_local_to_scholars_not_relation_values():
    relation = _known_relation()
    raw = _native(invited={'status': 'known', 'membership_complete': True,
                           'modifier_instances': []}, relations=relation)
    projected = values.public_value(raw, 'ENG', {'status': 'known', 'unexpected': True})
    assert projected['relations'] == relation
    assert projected['invited_scholars'] == {
        'status': 'unknown', 'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE',
    }
