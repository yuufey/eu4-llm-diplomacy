"""W04 land flags through the existing native R07 source and normal tools."""
from contextlib import closing
from copy import deepcopy

import pytest

from bridge.information.catalog import get_topic
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.service import InformationService
from bridge.information.sources import _result, _source_info
from bridge.information.tools import InformationTools
from bridge.information.war_land_commitments import NativeWarLandCommitmentsSource
from bridge.tests import test_information_war_land_commitments as fixture


FIELD = 'land_commitment'


def build(tmp_path, reader=None):
    report, context, creation = fixture._bundle(reader)
    base, upstream, war_id = fixture._source(tmp_path, report, context, creation)
    return base, upstream, NativeWarLandCommitmentsSource(upstream), war_id, context


def query(obj=None, fields=None):
    return {'topic': 'W04', 'object': deepcopy(obj or {'type': 'country', 'country': 'FRA'}),
            'fields': fields or [FIELD], 'parameters': {}}


@pytest.mark.parametrize('country,status,count', [('FRA', 'known', 1), ('ENG', 'known', 0), ('POR', 'unknown', None)])
def test_country_view_uses_public_helper_for_beneficiary_in_current_fra_wars(tmp_path, country, status, count):
    _, upstream, adapter, war_id, context = build(tmp_path)
    calls = []
    original = upstream.read_land_for_country

    def record(selected, current):
        calls.append(selected)
        return original(selected, current)

    upstream.read_land_for_country = record
    sample = adapter.read(query({'type': 'country', 'country': country}), context)
    field = sample['fields'][FIELD]
    assert calls == [country]
    assert field['status'] == status
    if count is not None:
        assert len(field['value']) == count
        assert all(row['beneficiary'] == country for row in field['value'])
    if country == 'FRA':
        assert field['value'][0] == {
            'war_id': war_id, 'beneficiary': 'FRA', 'side': 'our_side', 'war_leader': 'FRA', 'observed_promisor': None}
    assert 'raw_inputs' not in repr(sample)


@pytest.mark.parametrize('country', [None, 'fra', 'FRAX'])
def test_country_helper_rejects_invalid_tag_before_capture(tmp_path, country):
    _, upstream, _, _, context = build(tmp_path)
    upstream.land_capture = lambda *args: pytest.fail('Invalid tag entered capture')
    with pytest.raises(InformationError):
        upstream.read_land_for_country(country, context)


def test_war_query_default_report_and_cold_result_reuse_selected_w01_identity(tmp_path):
    base, upstream, adapter, war_id, _ = build(tmp_path)
    database = tmp_path / 'information.sqlite3'
    selected = query({'type': 'war', 'actor': 'FRA', 'recipient': 'POR'})
    with closing(InformationService(CompositeSource(base, [upstream, adapter]), database)) as service:
        tools = InformationTools(service)
        result = tools.call('information_query', {'request_id': 'w04-land', 'queries': [selected]})
        assert result['items'][0]['war_id'] == war_id
        assert result['items'][0][FIELD] == [
            {'war_id': war_id, 'beneficiary': 'FRA', 'side': 'our_side', 'war_leader': 'FRA', 'observed_promisor': None}]
        configured = tools.call('information_manage_report', {
            'request_id': 'w04-land-report', 'operation': 'create',
            'config': {'name': 'current land flags', 'queries': [selected], 'detail': 'full'}})['report']
        rendered = tools.call('information_query', {'request_id': 'w04-land-report-read',
                                                   'report_id': configured['id']})
        assert rendered['items'] == result['items']
    with closing(InformationService(CompositeSource(base, [upstream, adapter]), database)) as reopened:
        assert InformationTools(reopened).call('information_get_result', {
            'result_id': result['result_id']}) == result


@pytest.mark.parametrize('identity', [
    {'status': 'unknown', 'reason': 'WAR_SELECTION_REQUIRED'},
    {'status': 'not_applicable', 'reason': 'WAR_NOT_FOUND'},
])
def test_w01_selection_state_is_preserved_without_collecting_land(tmp_path, identity):
    base, upstream, adapter, _, context = build(tmp_path)
    base.read = lambda *args: {'fields': {'war_id': deepcopy(identity)}}
    upstream.land_capture = lambda *args: pytest.fail('Unselected war entered capture')
    sample = adapter.read(query({'type': 'war', 'actor': 'FRA', 'recipient': 'POR'}), context)
    field = sample['fields'][FIELD]
    assert field['status'] == identity['status'] and field['reason'] == identity['reason']


def test_explicit_selected_war_id_reaches_r07_unchanged(tmp_path):
    base, _, adapter, war_id, context = build(tmp_path)
    original = base.read
    calls = []

    def read(selected, current):
        calls.append(deepcopy(selected))
        return original(selected, current)

    base.read = read
    sample = adapter.read(query({'type': 'war', 'actor': 'FRA', 'recipient': 'POR', 'war_id': war_id}), context)
    assert calls[0]['object']['war_id'] == war_id
    assert sample['objects'][0]['war_id'] == war_id
    assert sample['fields'][FIELD]['status'] == 'known'


def test_country_view_keeps_missing_public_id_and_original_promiser_unknown(tmp_path):
    _, upstream, adapter, _, context = build(tmp_path)
    row = {'war_id': None, 'beneficiary': 'FRA', 'side': 'our_side',
           'opponents': ['POR'], 'war_leader': None}
    upstream.read_land_for_country = lambda *args: (
        {'status': 'known', 'value': [deepcopy(row)], 'complete': True},
        {'capture_report_sha256': 'a' * 64})
    sample = adapter.read(query(), context)
    assert sample['fields'][FIELD]['value'] == [row]
    assert 'promising_country' not in repr(sample)


def test_known_selected_beneficiary_can_compare_while_other_members_are_unavailable(tmp_path):
    _, _, adapter, _, context = build(tmp_path)
    selected = query()
    sample = adapter.read(selected, context)
    assert sample['fields'][FIELD]['complete'] is False
    assert adapter.change_comparison(selected, sample, context) is not None
    hidden = query({'type': 'country', 'country': 'POR'})
    assert adapter.change_comparison(hidden, adapter.read(hidden, context), context) is None


def test_validation_and_other_requested_fields_do_not_capture(tmp_path):
    _, upstream, adapter, _, context = build(tmp_path)
    upstream.land_capture = lambda *args: pytest.fail('Validation entered capture')
    assert adapter.validate_query(query(), context)['object']['country'] == 'FRA'
    assert adapter.validate_query(query({'type': 'war', 'actor': 'FRA', 'recipient': 'POR'}), context)
    field = adapter.read(query(fields=['contribution']), context)['fields']['contribution']
    assert field['status'] == 'unsupported'
    with pytest.raises(InformationError):
        adapter.validate_query(query({'type': 'country'}), context)


def test_session_change_retracts_the_current_land_value(tmp_path):
    _, upstream, adapter, _, context = build(tmp_path)
    original = upstream.read_land_for_country

    def change(country, current):
        result = original(country, current)
        context['session_id'] = 'other-session'
        return result

    upstream.read_land_for_country = change
    sample = adapter.read(query())
    assert sample['fields'][FIELD]['status'] == 'unavailable'
    assert sample['fields'][FIELD]['reason'] == 'WAR_LAND_COMMITMENTS_CONTEXT_CHANGED_DURING_READ'


class NoPromise(fixture.fixture.parent_fixture.RecordingReader):
    def read(self, address, size, label):
        if label == 'land_commitments.records':
            self.source.put(fixture.RECORDS + 0x90 + 0x1C, b'\x01')
        return super().read(address, size, label)


def test_periodic_and_change_subscriptions_keep_current_flags_and_known_empty(tmp_path):
    base, upstream, adapter, _, _ = build(tmp_path)
    now = [100.0]
    positive = upstream.land_capture
    empty, _, _ = fixture._bundle(NoPromise)
    with closing(InformationService(CompositeSource(base, [adapter]), tmp_path / 'subscriptions.sqlite3',
                                    clock=lambda: now[0])) as service:
        report = service.manage_report('land-report', 'create', config={
            'name': 'current land flags', 'queries': [query()], 'detail': 'full'})['report']
        service.manage_subscription('land-change', 'create', config={
            'kind': 'change', 'report_id': report['id'],
            'schedule': {'basis': 'real', 'unit': 'seconds', 'every': 2}})
        now[0] = 102.0
        assert service.tick()['results'] == []
        upstream.land_capture = lambda *args: deepcopy(empty)
        now[0] = 104.0
        changed = service.tick()['results']
        assert len(changed) == 1
        assert changed[0]['items'][0]['fields'][FIELD]['value'] == []
        now[0] = 106.0
        assert service.tick()['results'] == []
        upstream.land_capture = positive
        periodic = service.manage_subscription('land-periodic', 'create', config={
            'kind': 'periodic', 'report_id': report['id'],
            'schedule': {'basis': 'real', 'unit': 'seconds', 'every': 5}})['subscription']
        now[0] = 111.0
        results = service.tick()['results']
        periodic_results = [row for row in results if row['subscription_id'] == periodic['id']]
        assert len(periodic_results) == 1
        assert periodic_results[0]['items'][0]['fields'][FIELD]['value'][0]['beneficiary'] == 'FRA'


def test_normal_clock_progress_after_capture_keeps_the_field_known(tmp_path):
    base, upstream, adapter, _, context = build(tmp_path)
    original = upstream.read_land_for_country

    def advance(country, current):
        result = original(country, current)
        context['game_date'] += 24
        return result

    upstream.read_land_for_country = advance
    with closing(InformationService(CompositeSource(base, [adapter]), tmp_path / 'clock.sqlite3')) as service:
        result = service.query('land-clock', queries=[query()])
        assert result['items'][0]['fields'][FIELD]['status'] == 'known'


def test_w04_field_ownership_composes_with_other_war_fields(tmp_path):
    base, _, adapter, war_id, context = build(tmp_path)

    class Pressure:
        def catalog(self):
            topic = get_topic('W04')
            topic.update(object_types=['war', 'country'], observer_roles=['actor'],
                         supported_versions=['1.37.4'], context_scope='country_scope')
            topic['fields'] = {'war_exhaustion': {'coverage': 'complete'}}
            return [topic]

        def validate_query(self, selected, current=None):
            return deepcopy(selected)

        def read(self, selected, current):
            fields = {'war_exhaustion': {'status': 'known', 'value': 1000, 'complete': True}}
            return _result(selected, current, fields, True, _source_info('Pressure', current))

    with closing(InformationService(CompositeSource(base, [Pressure(), adapter]), tmp_path / 'mixed.sqlite3')) as service:
        result = service.query('land-mixed', queries=[query(
            {'type': 'war', 'actor': 'FRA', 'recipient': 'POR', 'war_id': war_id},
            ['war_exhaustion', FIELD])])
        fields = result['items'][0]['fields']
        assert fields['war_exhaustion']['value'] == 1000
        assert fields[FIELD]['value'][0]['beneficiary'] == 'FRA'
