"""W04 reuses national readers for the selected war's actual participants."""
from copy import deepcopy

import pytest

from bridge.information.composite import CompositeSource
from bridge.information.catalog import get_topic
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.information.tools import InformationTools
from bridge.information.observation_time import sampled_read
from bridge.information.war_exhaustion import NativeWarExhaustionSource
from bridge.tests.test_information_war_exhaustion import _Pressure, _Primary, _field, _query


WAR = 'war_0123456789abcdef_00000101'


def war_query():
    return {'topic': 'W04', 'object': {'type': 'war', 'actor': 'FRA', 'recipient': 'ENG'},
            'fields': ['war_exhaustion'], 'parameters': {}}


class ForeignPressure:
    def __init__(self, pressure):
        self.pressure = pressure
        self.fields = {'SAV': _field(1250), 'ENG': _field(9000)}
        self.calls = []
        self.advance = False

    def validate_query(self, query, context=None):
        assert query['topic'] == 'F04' and query['fields'] == ['war_exhaustion']
        assert query['object']['country'] != 'FRA'
        return deepcopy(query)

    def read(self, query, context):
        self.validate_query(query, context)
        self.calls.append(deepcopy(query))
        if self.advance:
            self.pressure._context['game_date'] += 24
        current = self.pressure.context()
        return {'objects': [deepcopy(query['object'])], 'game_date': current['game_date'],
                'fields': {'war_exhaustion': deepcopy(self.fields[query['object']['country']])},
                'complete': True,
                'source': {'observer': current['observer'], 'session_id': current['session_id']}}


class WarBase(_Primary):
    def __init__(self, pressure):
        super().__init__(pressure)
        self.calls = []
        self.missing = None
        self.reverse = False

    def read(self, query, context):
        assert query['topic'] == 'W01' and query['fields'] == ['war_id', 'participants']
        self.calls.append(deepcopy(query))
        if self.missing:
            return {'fields': {name: deepcopy(self.missing) for name in query['fields']}}
        roster = {'source': 'native_war_side_vectors', 'status': 'available', 'complete': True,
                  'side_a': ['FRA', 'SAV'], 'side_b': ['ENG'],
                  'actor_side': 'side_a', 'recipient_side': 'side_b', 'reason': None}
        if self.reverse:
            roster.update(side_a=['ENG'], side_b=['FRA', 'SAV'],
                          actor_side='side_b', recipient_side='side_a')
        return {'fields': {'war_id': {'status': 'known', 'value': WAR},
                           'participants': {'status': 'known', 'value': roster}}}


def build():
    pressure = _Pressure(field=_field(2500))
    foreign = ForeignPressure(pressure)
    base = WarBase(pressure)
    return NativeWarExhaustionSource(pressure, foreign, base), pressure, foreign, base


def test_country_view_reuses_foreign_reader_and_preserves_own_scalar():
    source, pressure, foreign, _ = build()
    query = _query(country='ENG')
    field = source.read(query, pressure.context())['fields']['war_exhaustion']
    assert field['value'] == 9000 and field['scale'] == 1000
    assert not pressure.read_calls
    assert len(foreign.calls) == 1
    assert source.read(_query(), pressure.context())['fields']['war_exhaustion']['value'] == 2500


@pytest.mark.parametrize('reverse', [False, True])
def test_selected_war_groups_actual_participants_and_echoes_war_id(reverse):
    source, pressure, foreign, base = build()
    base.reverse = reverse
    query = war_query()
    query['object']['war_id'] = WAR
    result = source.read(query, pressure.context())
    assert result['objects'] == [query['object']]
    assert result['complete'] is True
    values = result['fields']['war_exhaustion']['value']
    assert {tag: field['value'] for tag, field in values['our_side'].items()} == {'FRA': 2500, 'SAV': 1250}
    assert values['opposing_side']['ENG']['value'] == 9000
    assert len(base.calls) == 1 and base.calls[0]['object']['war_id'] == WAR
    assert len(pressure.read_calls) == 1
    assert [call['object']['country'] for call in foreign.calls] == ['SAV', 'ENG']


def test_invisible_member_preserves_other_members_and_never_becomes_zero():
    source, pressure, foreign, _ = build()
    foreign.fields['SAV'] = {'status': 'invisible', 'reason': 'TARGET_COUNTRY_NOT_VISIBLE'}
    result = source.read(war_query(), pressure.context())
    field = result['fields']['war_exhaustion']
    assert field['status'] == 'known' and field['complete'] is False
    assert field['value']['our_side']['SAV']['status'] == 'invisible'
    assert field['value']['our_side']['FRA']['value'] == 2500
    assert field['value']['opposing_side']['ENG']['value'] == 9000


@pytest.mark.parametrize('status', ['unknown', 'not_applicable'])
def test_unresolved_war_never_reads_country_values(status):
    source, pressure, foreign, base = build()
    base.missing = {'status': status, 'reason': 'WAR_SELECTION_REQUIRED'}
    result = source.read(war_query(), pressure.context())
    assert result['fields']['war_exhaustion'] == base.missing
    assert not pressure.read_calls and not foreign.calls


def test_observer_mismatch_prevents_discovery_and_sampling_allows_date_progress():
    source, pressure, foreign, base = build()
    current = pressure.context()
    result = source.read(war_query(), dict(current, session_id='different-session'))
    assert result['fields']['war_exhaustion']['status'] == 'unavailable'
    assert not base.calls and not foreign.calls and not pressure.read_calls
    foreign.advance = True
    with sampled_read(war_query(), current):
        result = source.read(war_query(), current)
    assert result['complete'] is True


def test_invalid_observer_side_and_planned_only_queries_do_not_read():
    source, pressure, foreign, base = build()
    query = war_query()
    query['object']['actor'] = 'ENG'
    with pytest.raises(InformationError):
        source.validate_query(query, pressure.context())
    planned = dict(war_query(), fields=['exit_risk'])
    assert source.read(planned, pressure.context())['fields']['exit_risk']['status'] == 'unsupported'
    assert not base.calls and not foreign.calls and not pressure.read_calls


def test_normal_tool_report_change_and_cold_result_keep_ranges(tmp_path):
    source, pressure, foreign, base = build()
    clock = [100.0]
    database = tmp_path / 'participant-pressure.sqlite3'
    service = InformationService(CompositeSource(base, [source]), database, clock=lambda: clock[0])
    try:
        api = InformationTools(service)
        direct = api.call('information_query', {'request_id': 'participant-direct', 'queries': [war_query()]})
        item = direct['items'][0]
        assert item['war_id'] == WAR
        assert item['war_exhaustion']['our_side']['FRA'] == {'current': 2.5, 'min': 0, 'max': 20}
        assert item['war_exhaustion']['opposing_side']['ENG']['current'] == 9.0
        foreign_country = api.call('information_query', {
            'request_id': 'foreign-country-pressure', 'queries': [_query(country='ENG')]})
        assert foreign_country['items'][0]['war_exhaustion'] == {'current': 9.0, 'min': 0, 'max': 20}
        report = service.manage_report('participant-report', 'create', config={
            'name': 'war participant pressure', 'queries': [war_query()]})['report']
        replay = api.call('information_query', {'request_id': 'participant-report-read', 'report_id': report['id']})
        assert replay['items'] == direct['items']
        subscription = service.manage_subscription('participant-change', 'create', config={
            'kind': 'change', 'report_id': report['id'],
            'schedule': {'basis': 'real', 'unit': 'seconds', 'every': 2}})['subscription']
        clock[0] = 102.0
        assert service.tick()['results'] == []
        clock[0] = 104.0
        assert service.tick()['results'] == []
        foreign.fields['ENG'] = _field(10000)
        clock[0] = 106.0
        changed = service.tick()['results']
        assert len(changed) == 1
        assert changed[0]['items'][0]['fields']['war_exhaustion']['value']['opposing_side']['ENG']['value'] == 10000
        service.manage_subscription('participant-cancel', 'cancel', subscription_id=subscription['id'], expected_version=1)
    finally:
        service.close()
    reopened = InformationService(CompositeSource(base, [source]), database)
    try:
        assert InformationTools(reopened).call('information_get_result', {'result_id': direct['result_id']}) == direct
    finally:
        reopened.close()


@pytest.mark.parametrize('conflicting', [False, True])
def test_mixed_war_fields_share_resolved_identity_and_reject_conflicting_owner(conflicting):
    source, pressure, _, base = build()

    class Land:
        calls = []

        def catalog(self):
            entry = get_topic('W04')
            entry.update(supported_versions=['1.37.4'], context_scope='visible_scope')
            entry['fields'] = {'land_commitment': {'coverage': 'available'}}
            return [entry]

        def read(self, query, context):
            self.calls.append(deepcopy(query))
            resolved = dict(query['object'], war_id='war_0123456789abcdef_00000102' if conflicting else WAR)
            return {'objects': [resolved], 'complete': True,
                    'fields': {'land_commitment': {'status': 'known', 'value': [], 'complete': True}}}

    land = Land()
    composite = CompositeSource(base, [source, land])
    query = dict(war_query(), fields=['war_exhaustion', 'land_commitment'])
    result = composite.read(query, pressure.context())
    assert land.calls[0]['object']['war_id'] == WAR
    assert result['objects'] == [dict(query['object'], war_id=WAR)]
    assert result['fields']['war_exhaustion']['status'] == 'known'
    if conflicting:
        assert result['fields']['land_commitment'] == {
            'status': 'unavailable', 'reason': 'resolved_object_mismatch'}
        assert result['complete'] is False
    else:
        assert result['fields']['land_commitment']['value'] == []
        assert result['complete'] is True
