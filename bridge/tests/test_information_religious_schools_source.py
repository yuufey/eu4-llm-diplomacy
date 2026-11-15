"""Offline source-boundary tests for S02.schools."""
from __future__ import annotations

from copy import deepcopy
from importlib import import_module as import_real_module
from types import SimpleNamespace

import pytest

from bridge.information.model import InformationError
from bridge.information.religious_schools import (
    BACKEND_FIELD, BASIS, FIELD, ORIGIN, UNIT, NativeReligiousSchoolsSource,
)
from bridge.information import religious_schools as schools_module
from bridge.tests import test_information_country_faith as faith_fixture


PROFILE_SHA256 = 'a' * 64
PRIVATE_POINTER = '0x123456789abcdef0'
CONFIG_UNKNOWN = {
    'status': 'unknown', 'reason': 'RELIGIOUS_SCHOOL_DEFINITION_UNAVAILABLE',
}
NO_SCHOOL = {'status': 'not_applicable', 'reason': 'NO_CURRENT_RELIGIOUS_SCHOOL'}
RELATION_UNKNOWN = {'status': 'unknown', 'reason': 'SCHOOL_RELATIONS_UNAVAILABLE'}


def _native_value(*, has_school=True, religion_key='catholic',
                  religion_group_key='christian', school_key='jesuits',
                  uses_schools=None, invited_scholars=None, relations=None):
    if uses_schools is None:
        uses_schools = {
            'status': 'unknown', 'reason': 'RELIGIOUS_SCHOOLS_THREAD_GATE_UNRESOLVED',
        }
    return {
        'has_school': has_school,
        'religion_key': religion_key,
        'religion_group_key': religion_group_key,
        'current_school': (
            {'status': 'known', 'key': school_key} if has_school
            else {'status': 'none', 'reason': 'NATIVE_SCHOOL_SENTINEL'}
        ),
        'uses_schools': deepcopy(uses_schools),
        'invited_scholars': deepcopy(invited_scholars if invited_scholars is not None else {
            'status': 'unknown', 'reason': 'SCHOLAR_MODIFIERS_UNAVAILABLE',
        }),
        'relations': deepcopy(relations if relations is not None else
                              (RELATION_UNKNOWN if has_school else NO_SCHOOL)),
    }


def _school_definition(group='christian', key='jesuits'):
    pins = {
        'configuration_sha256': 'c' * 64,
        'definitions_sha256': 'd' * 64,
        'parser_manifest_sha256': 'e' * 64,
        'cwt_sha256': 'f' * 64,
        'cwt_commit': 'a' * 40,
    }
    return {
        'status': 'known',
        'religion_group_key': group,
        'school_key': key,
        'source': deepcopy(pins),
        'source_pins': deepcopy(pins),
        'syntax': {
            'key': key, 'assignment': '=', 'kind': 'block', 'value': None,
            'children': [], 'line': 1, 'end_line': 1,
        },
        'conditions_evaluated': False,
        'effects_executed': False,
        'active_effects_proven': False,
    }


def _scholar_mapping(group='christian', school='jesuits', modifier='jesuit_scholar_one'):
    pins = {
        'configuration_sha256': '8' * 64,
        'definitions_sha256': '9' * 64,
        'parser_manifest_sha256': 'b' * 64,
        'cwt_sha256': 'c' * 64,
        'cwt_commit': 'd' * 40,
    }
    row = {
        'religion_group_key': group,
        'school_key': school,
        'modifier_key': modifier,
        'definition': {
            'relative_file': 'common/religions/religions.txt',
            'line': 7, 'file_sha256': 'e' * 64, 'source_kind': 'basegame',
        },
        'source_pins': deepcopy(pins),
        'conditions_evaluated': False,
        'effects_executed': False,
        'runtime_state_observed': False,
    }
    return {
        'status': 'known', 'mappings': [row], 'source_pins': pins,
        'conditions_evaluated': False, 'effects_executed': False,
        'runtime_state_observed': False,
    }


class ScholarMappingIndex:
    def __init__(self, *, mode='known'):
        self.mode = mode
        self.calls = 0

    def mapping(self):
        self.calls += 1
        if self.mode == 'raise':
            raise RuntimeError('mapping unavailable')
        if self.mode == 'unknown':
            return {'status': 'unknown', 'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE'}
        result = _scholar_mapping()
        if self.mode == 'malformed':
            result['mappings'][0]['runtime_state_observed'] = True
        return result


def _report(target='ENG', *, value=None, field_status='known', field_basis=BASIS,
            complete=False, admission_status='known', admitted=True,
            item_target=None, reason='SAFE_FIXTURE_REASON'):
    field = {
        'status': field_status, 'complete': complete, 'basis': field_basis,
        'raw_inputs': {'target_pointer': PRIVATE_POINTER,
                       'nested': {'address': PRIVATE_POINTER}},
    }
    if field_status == 'known':
        field['value'] = deepcopy(value if value is not None else _native_value())
    if field_status in ('unknown', 'invisible'):
        field['reason'] = reason
    return {
        'schema': 'information.school_relations_capture.v1',
        'status': 'observed', 'completed': True,
        'observation': {'backend': {
            'observer': {'tag': 'FRA', 'private_pointer': PRIVATE_POINTER},
            'targets': [{
                'tag': item_target if item_target is not None else target,
                'fullref': PRIVATE_POINTER,
                'admission_by_pass': {
                    'pass1': {'status': 'known', 'admitted': admitted},
                    'pass2': {'status': admission_status, 'admitted': admitted},
                },
                'fields': {BACKEND_FIELD: field},
            }],
        }},
        'raw_reads': [{'label': 'private.school', 'address': PRIVATE_POINTER}],
    }


def _query(target='ENG', fields=None, parameters=None):
    return faith_fixture.make_query(
        target, fields=fields if fields is not None else [FIELD],
        parameters=parameters if parameters is not None else {},
    )


class DefinitionIndex:
    def __init__(self, *, mode='known'):
        self.mode = mode
        self.calls = []

    def definition(self, group, school):
        self.calls.append((group, school))
        if self.mode == 'raise':
            raise RuntimeError('definitions unavailable')
        if self.mode == 'unknown':
            return dict(CONFIG_UNKNOWN)
        if self.mode == 'extra_private':
            result = _school_definition(group, school)
            result['private_pointer'] = PRIVATE_POINTER
            return result
        if self.mode == 'wrong_key':
            return _school_definition(group, 'different-school')
        return _school_definition(group, school)


def _make_source(tmp_path, monkeypatch, *, target='ENG', report=None,
                 valid=True, capture_error=None, after_capture=None,
                 definitions=None, scholar_definitions=None):
    base = faith_fixture.Base(tmp_path, faith_fixture.make_context())
    report = deepcopy(report if report is not None else _report(target))
    captures, validations = [], []

    def capture(installation, *, country, observer):
        captures.append((installation, country, observer))
        if after_capture is not None:
            after_capture(base)
        if capture_error is not None:
            raise capture_error
        return deepcopy(report)

    def validate_capture(actual_report, actual_context, creation, actual_target):
        validations.append((deepcopy(actual_report), deepcopy(actual_context), creation, actual_target))
        return valid

    module = SimpleNamespace(
        capture=capture, validate_capture=validate_capture, PROFILE_SHA256=PROFILE_SHA256,
    )
    monkeypatch.setattr(schools_module, 'import_module', lambda _name, _package: module)
    source = NativeReligiousSchoolsSource(
        base, capture=capture, definitions=definitions,
        scholar_definitions=scholar_definitions,
    )
    return source, base, report, captures, validations


def test_catalog_and_native_school_projection_attach_only_matching_group_rule(tmp_path, monkeypatch):
    definitions = DefinitionIndex()
    report = _report('ENG', value=_native_value())
    source, base, _, captures, validations = _make_source(
        tmp_path, monkeypatch, report=report, definitions=definitions,
    )

    spec = source.catalog()[0]['fields'][FIELD]
    assert spec['coverage'] == 'partial' and spec['complete'] is False
    assert spec['unit'] == UNIT and spec['scale'] == 1 and spec['period'] == 'current'
    assert spec['basis'] == BASIS and spec['value_origin'] == ORIGIN
    assert spec['triggers'] == ['query', 'periodic']
    assert spec['supported_observers'] == ['FRA']
    assert spec['source'] == 'bridge.information.school_relations_capture.capture'
    assert spec['runtime_validation'] == 'school_relations_capture.validate_capture'
    assert 'THREAD_GATED_ACTIVATION_PATH_UNRESOLVED' in spec['gaps']
    assert 'RELIGIOUS_SCHOOLS_ACTIVATION_NOT_READ' not in spec['gaps']
    assert 'default-false' in spec['raw_semantics']
    assert 'global bypass count paths' in spec['raw_semantics']
    assert 'thread-gated path' in spec['raw_semantics']
    assert 'SCHOLAR_MODIFIER_KEY_MEMBERSHIP_ONLY' in spec['gaps']
    assert 'SCHOLAR_INVITATION_HISTORY_NOT_READ' in spec['gaps']
    assert 'SCHOLAR_DATE_SEMANTICS_UNPROVEN' in spec['gaps']
    assert 'FULL_TOOLTIP_NOT_READ' in spec['gaps']
    assert 'SCHOOL_RELATION_TOOLTIP_NOT_READ' in spec['gaps']
    assert 'SCHOOL_RELATIONS_NOT_READ' not in spec['gaps']
    assert 'exact keys only' in spec['raw_semantics']
    assert 'school-pair' in spec['raw_semantics']
    assert 'tooltip unknown' in spec['raw_semantics']

    result = source.read(_query('ENG'), base.context())
    field = result['fields'][FIELD]
    assert field == {
        'status': 'known', 'period': 'current', 'unit': UNIT, 'scale': 1,
        'partial': True, 'complete': False, 'basis': BASIS, 'value_origin': ORIGIN,
        'value': {**_native_value(invited_scholars={
            'status': 'unknown', 'reason': 'SCHOLAR_VISIBILITY_UNVERIFIED',
        }), 'configured_rules': _school_definition()},
    }
    assert result['complete'] is False
    assert result['source']['provenance']['observer'] == 'FRA'
    assert result['source']['provenance']['target'] == 'ENG'
    assert result['source']['provenance']['configured_rules_are_applied_effects'] is False
    assert 'capture_report_sha256' not in result['source']['provenance']
    assert len(result['source']['provenance']['public_projection_sha256']) == 64
    assert result['source']['provenance']['profile_sha256'] == PROFILE_SHA256
    assert PRIVATE_POINTER not in repr(result)
    assert captures == [(base.session.directory / 'installation.json', 'ENG', 'FRA')]
    assert validations[0][1]['observer'] == 'FRA'
    assert validations[0][2:] == (faith_fixture.CREATION, 'ENG')
    assert definitions.calls == [('christian', 'jesuits')]


def test_default_capture_import_selects_relation_capture_and_projects_values(tmp_path, monkeypatch):
    capture_module = import_real_module('bridge.information.school_relations_capture')
    old_school_capture = import_real_module('bridge.information.religious_schools_capture')
    old_state_capture = import_real_module('bridge.information.religious_schools_state_capture')
    old_scholar_capture = import_real_module('bridge.information.religious_scholars_capture')
    rejected_old_calls = []

    def old_capture_sentry(*args, **kwargs):
        rejected_old_calls.append((args, kwargs))
        raise AssertionError('obsolete school capture selected')

    for module in (old_school_capture, old_state_capture, old_scholar_capture):
        monkeypatch.setattr(module, 'capture', old_capture_sentry)
        monkeypatch.setattr(module, 'validate_capture', old_capture_sentry)

    base = faith_fixture.Base(tmp_path, faith_fixture.make_context())
    raw_child = {
        'status': 'known', 'membership_complete': True,
        'modifier_instances': [{
            'source': 'direct', 'key': 'jesuit_scholar_one',
            'start_date_raw': -4, 'date_raw': 2147483647,
            'flags': {'ruler_modifier': 1, 'parliament_modifier': 0,
                      'permanent': 0, 'hidden': 255},
        }],
    }
    relation = {
        'status': 'known', 'religion_group_key': 'christian',
        'source_school_key': 'jesuits', 'symmetric': True,
        'entries': [{'school_key': 'dominicans', 'status': 'known',
                     'value': -9, 'raw_hex': 'f7ffffff'}],
        'complete': False, 'basis': 'native_school_pair_relation_cache',
    }
    report = _report('FRA', value=_native_value(
        invited_scholars=raw_child, relations=relation,
    ))
    capture_calls, validation_calls = [], []

    def fake_capture(installation, *, country, observer):
        capture_calls.append((installation, country, observer))
        return deepcopy(report)

    def fake_validate(actual_report, context, creation, country):
        validation_calls.append((actual_report, context, creation, country))
        return True

    monkeypatch.setattr(capture_module, 'capture', fake_capture)
    monkeypatch.setattr(capture_module, 'validate_capture', fake_validate)
    monkeypatch.setattr(capture_module, 'PROFILE_SHA256', PROFILE_SHA256)
    scholar_index = ScholarMappingIndex()
    source = NativeReligiousSchoolsSource(
        base, capture=None, definitions=DefinitionIndex(),
        scholar_definitions=scholar_index,
    )

    result = source.read(_query('FRA'), base.context())

    field = result['fields'][FIELD]
    assert field['status'] == 'known'
    assert field['value']['religion_key'] == 'catholic'
    assert field['value']['invited_scholars']['status'] == 'known'
    assert field['value']['invited_scholars']['scholars'] == [{
        'religion_group_key': 'christian', 'school_key': 'jesuits',
        'modifier_key': 'jesuit_scholar_one', 'present': True,
        'instances': raw_child['modifier_instances'],
    }]
    assert field['value']['relations'] == relation
    assert field['value']['configured_rules'] == _school_definition()
    assert capture_calls == [(base.session.directory / 'installation.json', 'FRA', 'FRA')]
    assert validation_calls[0][2:] == (faith_fixture.CREATION, 'FRA')
    assert scholar_index.calls == 1
    assert rejected_old_calls == []


def test_native_none_sentinel_is_not_treated_as_schools_disabled_and_skips_config(
        tmp_path, monkeypatch):
    definitions = DefinitionIndex()
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, target='TUR',
        report=_report('TUR', value=_native_value(has_school=False)),
        definitions=definitions,
    )
    value = source.read(_query('TUR'), base.context())['fields'][FIELD]['value']
    assert value['has_school'] is False
    assert value['current_school'] == {'status': 'none', 'reason': 'NATIVE_SCHOOL_SENTINEL'}
    assert value['uses_schools'] == {
        'status': 'unknown', 'reason': 'RELIGIOUS_SCHOOLS_THREAD_GATE_UNRESOLVED'
    }
    assert value['invited_scholars'] == {
        'status': 'unknown', 'reason': 'SCHOLAR_VISIBILITY_UNVERIFIED'
    }
    assert value['relations'] == NO_SCHOOL
    assert value['configured_rules'] == NO_SCHOOL
    assert definitions.calls == []


@pytest.mark.parametrize('reason', [
    'SCHOOL_RELATIONS_UNAVAILABLE', 'SCHOOL_RELATIONS_CHANGED',
])
def test_relation_unknown_reason_is_preserved_with_scholar_value(tmp_path, monkeypatch, reason):
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch,
        report=_report('ENG', value=_native_value(relations={
            'status': 'unknown', 'reason': reason,
        })),
        definitions=DefinitionIndex(),
    )
    value = source.read(_query(), base.context())['fields'][FIELD]['value']
    assert value['relations'] == {'status': 'unknown', 'reason': reason}
    assert value['religion_key'] == 'catholic'
    assert value['current_school'] == {'status': 'known', 'key': 'jesuits'}


def test_invalid_relation_dto_fails_closed_without_private_value_leak(tmp_path, monkeypatch):
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch,
        report=_report('ENG', value=_native_value(relations={
            'status': 'unknown', 'reason': 'SCHOOL_RELATION_NOT_FOUND',
        })),
    )
    field = source.read(_query(), base.context())['fields'][FIELD]
    assert field['status'] == 'unknown'
    assert field['reason'] == 'RELIGIOUS_SCHOOLS_CAPTURE_INVALID'
    assert 'value' not in field
    assert PRIVATE_POINTER not in repr(field)


@pytest.mark.parametrize('enabled', [True, False])
def test_known_activation_boolean_is_preserved_with_school_identity(
        tmp_path, monkeypatch, enabled):
    activation = {'status': 'known', 'value': enabled}
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch,
        report=_report('ENG', value=_native_value(uses_schools=activation)),
    )

    field = source.read(_query(), base.context())['fields'][FIELD]
    assert field['status'] == 'known'
    assert field['value']['uses_schools'] == activation
    assert field['value']['current_school'] == {'status': 'known', 'key': 'jesuits'}
    assert field['value']['invited_scholars'] == {
        'status': 'unknown', 'reason': 'SCHOLAR_VISIBILITY_UNVERIFIED',
    }
    assert field['value']['relations'] == {
        'status': 'unknown', 'reason': 'SCHOOL_RELATIONS_UNAVAILABLE',
    }


def test_known_scholar_modifier_membership_projects_static_mapping_only(tmp_path, monkeypatch):
    direct = {
        'source': 'direct', 'key': 'jesuit_scholar_one',
        'start_date_raw': -10, 'date_raw': 2147483647,
        'flags': {'ruler_modifier': 1, 'parliament_modifier': 0,
                  'permanent': 1, 'hidden': 255},
    }
    cooldown = {
        'source': 'secondary', 'key': 'has_invited_scholar_recently',
        'start_date_raw': None, 'date_raw': None, 'flags': None,
    }
    raw_child = {
        'status': 'known', 'membership_complete': True,
        'modifier_instances': [direct, cooldown],
    }
    index = ScholarMappingIndex()
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, target='FRA',
        report=_report('FRA', value=_native_value(invited_scholars=raw_child)),
        definitions=DefinitionIndex(),
        scholar_definitions=index,
    )

    field = source.read(_query('FRA'), base.context())['fields'][FIELD]
    invited = field['value']['invited_scholars']
    assert invited == {
        'status': 'known', 'membership_complete': True,
        'basis': 'native_country_modifier_key_membership',
        'scholars': [{
            'religion_group_key': 'christian', 'school_key': 'jesuits',
            'modifier_key': 'jesuit_scholar_one', 'present': True,
            'instances': [direct],
        }],
        'invitation_cooldown': {
            'modifier_key': 'has_invited_scholar_recently',
            'present': True, 'instances': [cooldown],
        },
        'invitation_history': {
            'status': 'unknown', 'reason': 'SCHOLAR_INVITATION_HISTORY_NOT_READ',
        },
        'date_semantics': 'copied_raw_dates_expiry_and_timer_unproven',
        'complete': False,
    }
    assert field['value']['configured_rules'] == _school_definition()
    assert field['value']['uses_schools'] == {
        'status': 'unknown', 'reason': 'RELIGIOUS_SCHOOLS_THREAD_GATE_UNRESOLVED',
    }
    assert index.calls == 1
    assert PRIVATE_POINTER not in repr(field)


@pytest.mark.parametrize('mode', ['raise', 'unknown', 'malformed'])
def test_bad_mapping_is_local_and_freshness_is_checked_each_read(tmp_path, monkeypatch, mode):
    raw_child = {
        'status': 'known', 'membership_complete': True,
        'modifier_instances': [],
    }
    index = ScholarMappingIndex(mode=mode)
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, target='FRA',
        report=_report('FRA', value=_native_value(invited_scholars=raw_child)),
        definitions=DefinitionIndex(),
        scholar_definitions=index,
    )

    for _ in range(2):
        field = source.read(_query('FRA'), base.context())['fields'][FIELD]
        assert field['status'] == 'known'
        assert field['value']['invited_scholars'] == {
            'status': 'unknown', 'reason': 'RELIGIOUS_SCHOLAR_MAPPING_UNAVAILABLE',
        }
        assert field['value']['religion_key'] == 'catholic'
        assert field['value']['current_school'] == {'status': 'known', 'key': 'jesuits'}
        assert field['value']['configured_rules'] == _school_definition()
    assert index.calls == 2


def test_native_unknown_scholar_child_is_preserved_without_static_lookup(tmp_path, monkeypatch):
    index = ScholarMappingIndex()
    raw_child = {'status': 'unknown', 'reason': 'SCHOLAR_MODIFIERS_CHANGED'}
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, target='FRA',
        report=_report('FRA', value=_native_value(invited_scholars=raw_child)),
        definitions=DefinitionIndex(),
        scholar_definitions=index,
    )
    value = source.read(_query('FRA'), base.context())['fields'][FIELD]['value']
    assert value['invited_scholars'] == raw_child
    assert index.calls == 0


@pytest.mark.parametrize('activation', [
    {'status': 'known', 'value': 0},
    {'status': 'known', 'value': 1},
    {'status': 'known', 'value': None},
    {'status': 'unknown', 'reason': 'UNRECOGNIZED_ACTIVATION_REASON'},
    {'status': 'unknown', 'reason': 'RELIGIOUS_SCHOOLS_THREAD_GATE_UNRESOLVED',
     'private_pointer': PRIVATE_POINTER},
])
def test_invalid_activation_dto_is_rejected_without_value_leak(
        tmp_path, monkeypatch, activation):
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch,
        report=_report('ENG', value=_native_value(uses_schools=activation)),
    )

    field = source.read(_query(), base.context())['fields'][FIELD]
    assert field['status'] == 'unknown'
    assert field['reason'] == 'RELIGIOUS_SCHOOLS_CAPTURE_INVALID'
    assert 'value' not in field
    assert PRIVATE_POINTER not in repr(field)


@pytest.mark.parametrize('mode', ['raise', 'unknown', 'extra_private', 'wrong_key'])
def test_configuration_failure_or_bad_result_does_not_retract_native_identity(
        tmp_path, monkeypatch, mode):
    definitions = DefinitionIndex(mode=mode)
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, definitions=definitions,
    )
    value = source.read(_query(), base.context())['fields'][FIELD]['value']
    assert value['religion_key'] == 'catholic'
    assert value['religion_group_key'] == 'christian'
    assert value['current_school'] == {'status': 'known', 'key': 'jesuits'}
    assert value['configured_rules'] == CONFIG_UNKNOWN
    assert PRIVATE_POINTER not in repr(value)


@pytest.mark.parametrize(('report', 'status', 'reason'), [
    (_report('ENG', admission_status='unknown'), 'unknown', 'RELIGIOUS_SCHOOLS_VIEW_ADMISSION_UNKNOWN'),
    (_report('ENG', admitted=False), 'invisible', 'RELIGIOUS_SCHOOLS_NOT_ADMITTED'),
    (_report('ENG', field_status='unknown'), 'unknown', 'SAFE_FIXTURE_REASON'),
    (_report('ENG', field_status='invisible'), 'invisible', 'SAFE_FIXTURE_REASON'),
])
def test_admission_and_backend_status_never_leak_values(tmp_path, monkeypatch, report, status, reason):
    source, base, _, _, _ = _make_source(tmp_path, monkeypatch, report=report)
    field = source.read(_query(), base.context())['fields'][FIELD]
    assert field['status'] == status and field['reason'] == reason
    assert 'value' not in field
    assert PRIVATE_POINTER not in repr(field)


@pytest.mark.parametrize(('report', 'valid', 'capture_error', 'reason'), [
    (_report('ENG'), False, None, 'RELIGIOUS_SCHOOLS_CAPTURE_INVALID'),
    (_report('FRA'), True, None, 'RELIGIOUS_SCHOOLS_CAPTURE_INVALID'),
    (_report('ENG', field_basis='wrong-basis'), True, None, 'RELIGIOUS_SCHOOLS_CAPTURE_INVALID'),
    (_report('ENG', value={}), True, None, 'RELIGIOUS_SCHOOLS_CAPTURE_INVALID'),
    (_report('ENG'), True, RuntimeError('closed'), 'RELIGIOUS_SCHOOLS_CAPTURE_FAILED:RuntimeError'),
])
def test_invalid_capture_or_native_dto_is_fail_closed(tmp_path, monkeypatch,
                                                      report, valid, capture_error, reason):
    source, base, _, _, _ = _make_source(
        tmp_path, monkeypatch, report=report, valid=valid, capture_error=capture_error,
    )
    field = source.read(_query(), base.context())['fields'][FIELD]
    assert field['status'] == 'unknown' and field['reason'] == reason
    assert 'value' not in field
    assert PRIVATE_POINTER not in repr(field)


def test_context_and_session_drift_during_capture_are_unavailable(tmp_path, monkeypatch):
    def drift_context(base):
        base.current['game_date'] += 1

    source, base, _, _, _ = _make_source(
        tmp_path / 'context', monkeypatch, after_capture=drift_context,
    )
    field = source.read(_query(), base.context())['fields'][FIELD]
    assert field['status'] == 'unavailable'
    assert field['reason'] == 'RELIGIOUS_SCHOOLS_CONTEXT_CHANGED_DURING_CAPTURE'

    def drift_session(base):
        base.session.record['creation_filetime'] += 1

    source, base, _, _, _ = _make_source(
        tmp_path / 'session', monkeypatch, after_capture=drift_session,
    )
    field = source.read(_query(), base.context())['fields'][FIELD]
    assert field['status'] == 'unavailable'
    assert field['reason'] == 'RELIGIOUS_SCHOOLS_SESSION_CHANGED_DURING_CAPTURE'


def test_default_definition_index_is_lazy_and_not_loaded_without_school(tmp_path, monkeypatch):
    constructions = []

    class LazyDefinitions(DefinitionIndex):
        def __init__(self):
            constructions.append(True)
            super().__init__()

    monkeypatch.setattr(schools_module, 'ReligiousSchoolDefinitionIndex', LazyDefinitions)
    source, base, _, _, _ = _make_source(tmp_path, monkeypatch, definitions=None)
    assert constructions == []
    source.read(_query(), base.context())
    assert constructions == [True]

    source, base, _, _, _ = _make_source(
        tmp_path / 'none', monkeypatch, target='TUR', definitions=None,
        report=_report('TUR', value=_native_value(has_school=False)),
    )
    source.read(_query('TUR'), base.context())
    assert constructions == [True]


def test_query_scope_and_field_validation_precede_capture(tmp_path, monkeypatch):
    source, base, _, captures, _ = _make_source(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.read(_query(fields=['schools', 'faith']), base.context())
    with pytest.raises(InformationError):
        source.read(_query(parameters={'unexpected': True}), base.context())
    with pytest.raises(InformationError):
        source.read(_query('ENG'), {**base.context(), 'observer': 'ENG'})
    assert captures == []

