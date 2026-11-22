from copy import deepcopy
from types import SimpleNamespace

import pytest

from bridge.information import InformationService
from bridge.information import subject_pressure as pressure
from bridge.information.composite import CompositeSource
from bridge.information.declaration_roles import DeclarationParticipantRoles
from bridge.information.tools import InformationTools
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests import test_information_foreign_technology_capture as capture_fixture
from bridge.tests.test_information_foreign_technology_memory import MemoryReader


def query(topic='S03', country='NOR', fields=None):
    return {'topic': topic, 'object': {'type': 'country', 'country': country},
            'fields': fields or (['liberty_desire', 'loyalty'] if topic == 'S03' else ['subject_loyalty']),
            'parameters': {}}


def make_source(tmp_path, monkeypatch, *, applicable=True, failure=False, integration_native=None):
    context = {'observer': 'FRA', 'game_date': 100, 'game_version': '1.37.4',
               'game_sha256': pressure._owner.EXE_SHA256, 'session_id': 'subject-session'}
    base = Base(tmp_path, context, 123)
    calls = []

    def inspect(action, actor, recipient, phase, parameters):
        calls.append((action, actor, recipient, phase, parameters))
        if failure:
            raise OSError('native query unavailable')
        return {'actor': actor, 'recipient': recipient, 'recipient_subject_state': {
            'verified': True, 'is_subject': True, 'overlord': 'DAN', 'subject_type': 'personal_union',
            'liberty_desire_raw': 12500, 'scale': 1000, 'integration': integration_native}}

    base.diplomacy_tools = SimpleNamespace(inspect_diplomatic_action=inspect)
    state = {'subject': 'NOR', 'overlord': 'DAN', 'subject_type': 'personal_union',
             'loyalty': {'status': 'known', 'value': 'loyal', 'scale': 1},
             'support_independence': {'status': 'known', 'value': ['BUR', 'ENG']},
             'tribute': {'status': 'known', 'subject_type': 'vassal', 'value': {
                 'vassal_tax_multiplier': {'status': 'known', 'value': 1000, 'scale': 1000},
                 'annual_tribute': False}},
             'levy': {'status': 'known', 'subject_type': 'vassal', 'value': {
                 'land_force_limit_share_percent': {'status': 'known', 'value': 100, 'scale': 10},
                 'manpower_factor': {'status': 'known', 'value': 0, 'scale': 1000},
                 'sailors_factor': {'status': 'known', 'value': 0, 'scale': 1000}}},
             'integration': {'status': 'known', 'complete': False, 'value': {
                 'type_rules': {'union_integration_allowed': True},
                 'in_progress': True,
                 'diplomatic_power_spent': {'status': 'known', 'value': 12500, 'scale': 1000},
                 'can_start': {'status': 'unknown', 'reason': 'INTEGRATION_START_CONDITIONS_UNAVAILABLE'},
                 'total_diplomatic_power': {'status': 'unknown', 'reason': 'INTEGRATION_TOTAL_COST_UNAVAILABLE'}}}}
    report = {'observation': {'backend': {'targets': [{'fields': {
        pressure._BINDING_FIELD: {'status': 'known', 'value': state if applicable else None}}}]}}}
    captures = []

    def capture(installation, request):
        captures.append(deepcopy(request))
        return deepcopy(report)

    monkeypatch.setattr(pressure, 'validate_capture', lambda *args: True)
    source = pressure.NativeSubjectPressureSource(base, capture=capture)
    return source, base, calls, captures


def test_normal_tools_query_exports_effective_value_and_f04_projection(tmp_path, monkeypatch):
    adapter, base, calls, captures = make_source(tmp_path, monkeypatch)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': 'subject-query',
            'queries': [query(), query('F04')]})
        assert result['items'] == [
            {'country': 'NOR', 'liberty_desire': {'current': 12.5, 'min': 0, 'max': 100}, 'loyalty': 'loyal'},
            {'country': 'NOR', 'subject_loyalty': {'overlord': 'DAN',
                'liberty_desire': {'current': 12.5, 'min': 0, 'max': 100}, 'loyalty': 'loyal'}}]
        full = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['items'][0]['fields']['liberty_desire']['raw'] == 12500
        assert len(calls) == len(captures) == 2
        assert calls[0] == ('offer_vassalization', 'FRA', 'NOR', 'initiate', {})
    finally:
        service.close()


def test_loyalty_only_uses_memory_without_native_inspection(tmp_path, monkeypatch):
    source, _, calls, captures = make_source(tmp_path, monkeypatch)
    result = source.read(query(fields=['loyalty']))
    assert result['fields']['loyalty']['value'] == 'loyal'
    assert result['complete'] is True
    assert calls == []
    assert len(captures) == 1


def test_independent_country_is_not_applicable_without_native_inspection(tmp_path, monkeypatch):
    source, _, calls, _ = make_source(tmp_path, monkeypatch, applicable=False)
    result = source.read(query(country='FRA'))
    assert result['complete'] is True
    assert all(field['status'] == 'not_applicable' for field in result['fields'].values())
    assert calls == []


def test_native_failure_keeps_observed_loyalty(tmp_path, monkeypatch):
    source, _, calls, _ = make_source(tmp_path, monkeypatch, failure=True)
    result = source.read(query())
    assert result['fields']['liberty_desire']['status'] == 'unknown'
    assert result['fields']['loyalty']['value'] == 'loyal'
    assert result['complete'] is False
    assert len(calls) == 1


def test_invalid_memory_capture_is_not_used(tmp_path, monkeypatch):
    source, _, calls, _ = make_source(tmp_path, monkeypatch)
    monkeypatch.setattr(pressure, 'validate_capture', lambda *args: False)
    result = source.read(query())
    assert all(field['status'] == 'unknown' for field in result['fields'].values())
    assert calls == []


def test_support_query_uses_existing_memory_without_native_inspection(tmp_path, monkeypatch):
    source, _, calls, captures = make_source(tmp_path, monkeypatch)
    result = source.read(query(fields=['support_independence']))
    assert result['fields']['support_independence']['value'] == ['BUR', 'ENG']
    assert result['complete'] is True
    assert calls == []
    assert len(captures) == 1


def test_obligation_query_uses_loaded_rules_and_concise_values(tmp_path, monkeypatch):
    adapter, base, calls, captures = make_source(tmp_path, monkeypatch)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': 'obligation-query',
            'queries': [query(fields=['tribute', 'levy'])]})
        assert result['items'] == [{'country': 'NOR',
            'tribute': {'vassal_tax_multiplier': 1.0, 'annual_tribute': False},
            'levy': {'land_force_limit_share_percent': 10.0,
                     'manpower_factor': 0.0, 'sailors_factor': 0.0}}]
        full = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['complete'] is True
        assert full['items'][0]['fields']['tribute']['subject_type'] == 'vassal'
        assert calls == []
        assert len(captures) == 1
    finally:
        service.close()


def test_legacy_native_query_keeps_known_progress_and_marks_missing_fields(tmp_path, monkeypatch):
    adapter, base, calls, captures = make_source(tmp_path, monkeypatch)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': 'integration-query',
            'queries': [query(fields=['integration'])]})
        assert result['items'] == [{'country': 'NOR', 'integration': {
            'overlord': 'DAN',
            'type_rules': {'union_integration_allowed': True},
            'in_progress': True, 'diplomatic_power_spent': 12.5,
            'can_start': None, 'total_diplomatic_power': None}}]
        full = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['complete'] is False
        assert len(calls) == 1
        assert len(captures) == 1
    finally:
        service.close()


@pytest.mark.parametrize('can_start', [False, True])
def test_native_integration_merges_conditions_cost_and_existing_progress(tmp_path, monkeypatch, can_start):
    native = {'verified': True, 'applicable': True, 'can_start': can_start,
              'total_diplomatic_power': 160, 'conditions': 'Need 50 years of union'}
    adapter, base, calls, captures = make_source(tmp_path, monkeypatch, integration_native=native)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        result = api.call('information_query', {'request_id': 'native-integration-query',
            'queries': [query(fields=['integration', 'liberty_desire'])]})
        integration = result['items'][0]['integration']
        assert integration['overlord'] == 'DAN'
        assert integration['can_start'] is can_start
        assert integration['total_diplomatic_power'] == 160
        assert integration['diplomatic_power_spent'] == 12.5
        if can_start:
            assert 'conditions' not in integration
        else:
            assert integration['conditions'] == 'Need 50 years of union'
        full = api.call('information_get_result', {'result_id': result['result_id'], 'view': 'full'})
        assert full['complete'] is True
        assert len(calls) == len(captures) == 1
    finally:
        service.close()


def test_ineligible_type_finishes_with_no_start_and_inapplicable_cost():
    captured = {'status': 'known', 'complete': False, 'value': {
        'type_rules': {'annexation_allowed': False, 'union_integration_allowed': False},
        'in_progress': False, 'diplomatic_power_spent': 0,
        'can_start': {'status': 'unknown'}, 'total_diplomatic_power': {'status': 'unknown'}}}
    result = pressure._integration_result(captured, None, 'DAN')
    assert result['complete'] is True
    assert result['value']['can_start'] == {'status': 'known', 'value': False}
    assert result['value']['total_diplomatic_power']['status'] == 'not_applicable'


def test_support_membership_resolves_slots_and_deduplicates_countries():
    reader = MemoryReader()
    spec = pressure._load_profile()['subject_support']
    country, vector = 0x6400000000, 0x6900000000
    reader.put_i32(country + spec['count_offset'], 3)
    reader.put_u64(country + spec['vector_offset'], vector)
    # The native membership branch consumes the slot, leaving the rest opaque.
    reader.put(vector, b''.join(slot.to_bytes(4, 'little') + bytes(12) for slot in (2, 1, 2)))
    rows = {'a': {'slot': 1, 'tag': 'BUR'}, 'b': {'slot': 2, 'tag': 'ENG'}}
    assert pressure._read_support_partners(reader, country, rows, spec) == {
        'status': 'known', 'value': ['BUR', 'ENG']}


@pytest.mark.parametrize('count', [0, -1, 4097])
def test_empty_or_invalid_support_count_does_not_read_a_vector(count):
    reader = MemoryReader()
    spec = pressure._load_profile()['subject_support']
    country = 0x6400000000
    reader.put_i32(country + spec['count_offset'], count)
    if count == 0:
        assert pressure._read_support_partners(reader, country, {}, spec) == {
            'status': 'known', 'value': []}
    else:
        with pytest.raises(ValueError, match='SUBJECT_SUPPORT_COUNT_INVALID'):
            pressure._read_support_partners(reader, country, {}, spec)


def _declaration_subject_report(overlord, *, game_date=None, session_id=None, creation=None, countries=None,
                                observer='FRA'):
    countries = ['ENG'] if countries is None else countries
    profile = pressure._load_profile()
    report, context, captured_creation, fixture = capture_fixture._make_fixture('ENG', profile=profile)
    creation = captured_creation if creation is None else creation
    image, bindings = fixture['image'], fixture['bindings']
    if observer != 'FRA':
        image, bindings, _ = capture_fixture.backend_fixture.make_reader({
            observer: (122, 0x1200, 5), 'POR': (189, 0x5500, 3), 'ENG': (300, 0x4500, 9),
        }, count=310)
        capture_fixture._write_capture_context(image, country='ENG', observer=observer, admitted=True)
        for guard in profile['code_guards']:
            image.put(capture_fixture.MODULE_BASE + int(guard['rva'], 0), bytes.fromhex(guard['bytes']))
    context['observer'] = report['request']['observer'] = observer
    if 'POR' in countries:
        spec = capture_fixture.admission
        slot = bindings['POR']['slot']
        owner, counters = capture_fixture.RELATION_OWNER + 0x1000, capture_fixture.RELATION_COUNTERS + 0x1000
        row = capture_fixture.RELATION_TABLE + slot * spec.RELATION_ROW_STRIDE
        image.put_u64(row + spec.RELATION_ROW_OWNER_OFFSET, owner)
        image.put_u64(row + spec.RELATION_ROW_RECIPIENT_FULLREF_OFFSET, bindings['POR']['fullref'])
        image.put_u64(owner + spec.RELATION_OWNER_COUNTERS_OFFSET, counters)
        image.put_i32(counters + spec.RELATION_COUNTER_FIRST_OFFSET + slot * spec.RELATION_COUNTER_STRIDE, 1)
    if game_date is not None:
        image.put_i32(capture_fixture.WORLD + 0x1dd0, game_date)
        context['game_date'] = game_date
    if session_id is not None:
        context['session_id'] = session_id
    report['request'].update(creation_filetime=creation, session_id=context['session_id'])
    report['identity']['process_creation_filetime'] = creation
    report['identity_after']['process_creation_filetime'] = creation
    for country in countries:
        image.put_u64(bindings[country]['country_pointer'] + 0x18f0, 0)
    image.put_u64(bindings['ENG']['country_pointer'] + 0x18f0,
                  bindings[overlord]['fullref'] if overlord else 0)
    reader = capture_fixture.RecordingReader(image)
    observation = pressure._binding_observation(countries, observer)(
        reader, capture_fixture.MODULE_BASE, countries[0], profile)
    report.update(schema=pressure.BINDING_SCHEMA, profile_sha256=pressure.PROFILE_SHA256,
                  observation=observation, raw_reads=deepcopy(reader.read_log),
                  status='observed', completed=True)
    report['request']['countries'] = countries
    report['access'] = {'read_only': True, 'native_function_invoked': False, 'writes': False,
        'UI_control': False, 'date_advance': False, 'save_or_reload': False,
        'limit_bytes': pressure._owner.MAX_READ_BYTES,
        'calls': reader.calls, 'bytes_requested': reader.bytes_requested}
    assert pressure.validate_binding_capture(report, context, creation, countries)
    return report, context, creation


def test_configured_turkish_overlord_binds_canonical_english_subject():
    report, context, creation = _declaration_subject_report('TUR', observer='TUR')
    binding = report['observation']['backend']['targets'][0]['fields'][pressure._BINDING_FIELD]
    assert binding == {'status': 'known', 'value': {'subject': 'ENG', 'overlord': 'TUR'}}
    assert pressure.validate_binding_capture(report, context, creation, ['ENG'])
    assert not pressure.validate_binding_capture(report, dict(context, observer='FRA'), creation, ['ENG'])


@pytest.mark.parametrize('overlord', ['FRA', 'POR', None])
def test_declaration_subject_roles_reuse_validated_binding_and_known_independence(tmp_path, overlord):
    report, context, creation = _declaration_subject_report(overlord)
    base = Base(tmp_path, context, creation)
    calls = []

    def capture(installation, request):
        calls.append(deepcopy(request))
        return deepcopy(report)

    def inspect(*args):
        raise AssertionError('Subject role binding must not invoke a diplomatic inspector')

    base.diplomacy_tools = SimpleNamespace(inspect_diplomatic_action=inspect)
    adapter = DeclarationParticipantRoles(base, subject_capture=capture)
    candidate = {'country': 'ENG', 'related_country': 'FRA', 'side': 'attacker',
                 'automatic': True, 'selected': False}
    inspection = {'participants': {'called': True, 'enumeration_complete': True, 'candidates': [candidate]}}
    fields = adapter.fields(inspection, base.context(), ['subjects'])
    assert set(fields) == {'subjects'}
    assert fields['subjects']['status'] == 'known'
    assert fields['subjects']['complete'] is True
    assert fields['subjects']['value'] == ([dict(candidate, overlord=overlord)] if overlord else [])
    assert fields['subjects']['source_path'] == 'S03.subject_binding'
    assert calls == [['ENG']]


def test_declaration_subject_roles_reject_modified_binding_before_projection(tmp_path):
    report, context, creation = _declaration_subject_report('FRA')
    report['observation']['backend']['targets'][0]['fields'][pressure._BINDING_FIELD]['value']['overlord'] = 'POR'
    base = Base(tmp_path, context, creation)
    adapter = DeclarationParticipantRoles(base, subject_capture=lambda *_: deepcopy(report))
    candidate = {'country': 'ENG', 'related_country': 'FRA', 'side': 'attacker',
                 'automatic': True, 'selected': False}
    fields = adapter.fields({'participants': {'called': True, 'enumeration_complete': True,
                                             'candidates': [candidate]}}, base.context(), ['subjects'])
    assert fields['subjects']['status'] == 'unknown'
    assert fields['subjects']['unresolved'] == [{'country': 'ENG', 'related_country': 'FRA',
                                               'reason': 'SUBJECT_PRESSURE_CAPTURE_INVALID'}]


def test_binding_batch_replays_two_targets_in_one_country_scan_and_rejects_scope_tampering():
    report, context, creation = _declaration_subject_report('FRA', countries=['ENG', 'POR'])
    targets = {target['tag']: target['fields'][pressure._BINDING_FIELD]
               for target in report['observation']['backend']['targets']}
    assert targets['ENG']['value'] == {'subject': 'ENG', 'overlord': 'FRA'}
    assert targets['POR'] == {'status': 'known', 'value': None}
    assert pressure.validate_binding_capture(report, context, creation, ['ENG', 'POR'])
    assert not pressure.validate_binding_capture(report, context, creation, ['ENG'])
    assert not pressure.validate_binding_capture(report, context, creation, ['POR', 'ENG'])
    tampered = deepcopy(report)
    tampered['observation']['backend']['targets'][0]['fields'][pressure._BINDING_FIELD]['value']['overlord'] = 'POR'
    assert not pressure.validate_binding_capture(tampered, context, creation, ['ENG', 'POR'])


@pytest.mark.parametrize('countries', [[], ['ENG'] * 2, ['bad'], ['C%02d' % index for index in range(9)], None])
def test_binding_batch_invalid_targets_fail_before_capture(monkeypatch, countries):
    def capture(*args, **kwargs):
        raise AssertionError('An invalid binding request must not open a process')

    monkeypatch.setattr(pressure._owner, '_capture_common', capture)
    with pytest.raises(ValueError, match='SUBJECT_BINDING_COUNTRIES_INVALID'):
        pressure.capture_bindings('unused-installation.json', countries)
    assert pressure.validate_binding_capture({}, {}, 123, countries) is False


@pytest.mark.parametrize('failed_second_batch', [False, True])
def test_declaration_subject_roles_partition_nine_candidates_into_two_bounded_batches(tmp_path, monkeypatch, failed_second_batch):
    context = {'observer': 'FRA', 'game_date': 100, 'game_version': '1.37.4',
               'game_sha256': pressure._owner.EXE_SHA256, 'session_id': 'subject-session'}
    base = Base(tmp_path, context, 123)
    countries = ['AMG', 'AUV', 'BOU', 'FOI', 'ORL', 'HES', 'SAV', 'PAP', 'SZO']
    candidates = [{'country': country, 'related_country': 'FRA', 'side': 'attacker',
                   'automatic': country != 'SAV', 'selected': country == 'SAV'} for country in countries]
    calls = []

    def capture(installation, batch):
        calls.append(list(batch))
        if failed_second_batch and batch == countries[8:]:
            raise OSError('second batch unavailable')
        return {'request': {'countries': list(batch)}, 'observation': {'backend': {'targets': [
            {'tag': country, 'fields': {pressure._BINDING_FIELD: {'status': 'known', 'value':
                {'subject': country, 'overlord': 'FRA'} if country == 'HES' else None}}}
            for country in batch]}}}

    monkeypatch.setattr(pressure, 'validate_binding_capture',
                        lambda report, context, creation, batch: report['request']['countries'] == batch)
    adapter = DeclarationParticipantRoles(base, subject_capture=capture)
    field = adapter.fields({'participants': {'called': True, 'enumeration_complete': True,
                                            'candidates': candidates}}, base.context(), ['subjects'])['subjects']
    assert calls == [countries[:8], countries[8:]]
    assert field['value'] == [dict(candidates[5], overlord='FRA')]
    assert field['complete'] is not failed_second_batch
    if failed_second_batch:
        assert field['unresolved'][0]['country'] == 'SZO'
