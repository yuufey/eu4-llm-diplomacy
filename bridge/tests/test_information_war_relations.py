"""R03 reuses F01's current, partial war index and its privacy projection."""
from copy import deepcopy

import pytest

from bridge.information.catalog import list_topics
from bridge.information.composite import CompositeSource
from bridge.information.country_scale import NativeCountryScaleSource
from bridge.information.country_rivals import NativeCountryRivalsSource
from bridge.information.model import InformationError
from bridge.information.war_relations import NativeWarRelationsSource
from bridge.tests.test_information_country_scale import _wars_raw, _wars_value


def context():
    return dict(status='ready', mode='live', observer='FRA', session_id='test-session',
                game_version='1.37.4', game_sha256='b2' * 32, game_date=56556984,
                world_id='test-world', physical_client_country='POR', dll_sha256='ab' * 32)


def query(country='FRA', fields=None):
    return dict(topic='R03', object={'type': 'country', 'country': country},
                fields=['wars'] if fields is None else fields, parameters={})


class Scale:
    def __init__(self):
        self.current = context()
        self.field = _wars_raw(_wars_value('FRA'))
        self.calls = []
        self.mutate = None
        self.after = None

    def context(self):
        return deepcopy(self.current)

    def catalog(self):
        return NativeCountryScaleSource.catalog(self)

    def validate_query(self, value, context=None):
        return NativeCountryScaleSource.validate_query(self, value, context)

    def read(self, value, context=None):
        self.calls.append(deepcopy(value))
        current = self.context() if context is None else context
        sample = dict(objects=[deepcopy(value['object'])], game_date=current['game_date'],
                      complete=False, fields={'wars': deepcopy(self.field), 'development': 'secret'},
                      source=dict(name='NativeCountryScaleSource', mode=current['mode'],
                                  observer=current['observer'], session_id=current['session_id'],
                                  complete=False, private='secret',
                                  provenance={'capture_report_sha256': 'cd' * 32, 'private': 'secret'}))
        if self.mutate:
            self.mutate(sample)
        if self.after:
            self.current.update(self.after)
        return sample


def test_shared_single_field_read_whitelists_and_preserves_partial_index():
    scale = Scale()
    source = NativeWarRelationsSource(scale)
    result = source.read(query(), context())
    assert source.country_scale_source is scale
    assert scale.calls == [dict(query(), topic='F01')]
    assert result['fields']['wars']['value'] == _wars_value('FRA')
    assert result['complete'] is False
    assert result['fields']['wars']['complete'] is False
    assert result['fields']['wars']['partial'] is True
    assert 'secret' not in repr(result) and 'raw_inputs' not in repr(result)
    assert result['source']['provenance']['capture_report_sha256'] == 'cd' * 32


def test_foreign_country_is_not_replaced_by_physical_client():
    scale = Scale()
    scale.field = _wars_raw(_wars_value('ENG'))
    result = NativeWarRelationsSource(scale).read(query('ENG'), context())
    assert scale.calls[0]['object']['country'] == 'ENG'
    assert result['objects'] == [query('ENG')['object']]
    assert result['source']['observer'] == 'FRA'


def test_redacted_members_and_unknown_war_ids_stay_redacted():
    scale = Scale()
    war = scale.field['value']['wars'][0]
    war['side_b'] = [{'status': 'invisible', 'reason': 'COUNTRY_VIEW_DENIED'}]
    war['identities_complete'] = False
    war['war_id'] = {'status': 'unknown', 'reason': 'NOT_REGISTERED'}
    result = NativeWarRelationsSource(scale).read(query(), context())
    assert result['fields']['wars']['value']['wars'][0] == war


def test_known_empty_index_remains_partial():
    scale = Scale()
    scale.field['value'].update(at_war=False, war_count=0, wars=[])
    result = NativeWarRelationsSource(scale).read(query(), context())
    assert result['fields']['wars']['status'] == 'known'
    assert result['fields']['wars']['value']['wars'] == []
    assert result['complete'] is False


@pytest.mark.parametrize('state', ['unknown', 'unavailable', 'invisible', 'not_applicable', 'stale', 'unsupported'])
def test_unknown_is_not_converted_to_empty_index(state):
    scale = Scale()
    scale.field = {'status': state, 'reason': 'NOT_READY', 'value': ['secret']}
    field = NativeWarRelationsSource(scale).read(query(), context())['fields']['wars']
    assert field == {'status': state, 'reason': 'NOT_READY', 'complete': False}


@pytest.mark.parametrize('change', [
    lambda sample: sample['source'].update(name='wrong'),
    lambda sample: sample['source'].update(observer='POR'),
    lambda sample: sample['source'].update(session_id='other'),
    lambda sample: sample['source'].update(mode='historical'),
    lambda sample: sample.update(game_date=1),
    lambda sample: sample.update(objects=[]),
    lambda sample: sample.update(complete=True),
    lambda sample: sample['source']['provenance'].update(capture_report_sha256='missing'),
    lambda sample: sample['fields']['wars'].update(scale=True),
    lambda sample: sample['fields']['wars']['value'].update(global_membership_verified=True),
    lambda sample: sample['fields']['wars']['value'].update(war_count=2),
    lambda sample: sample['fields']['wars']['value']['wars'][0]['side_b'][0].update(private='secret'),
    lambda sample: sample['fields'].update(wars={'status': 'unknown', 'reason': '0x12345678'}),
])
def test_invalid_upstream_is_unavailable(change):
    scale = Scale()
    scale.mutate = change
    field = NativeWarRelationsSource(scale).read(query(), context())['fields']['wars']
    assert field['status'] == 'unavailable' and 'value' not in field


@pytest.mark.parametrize('key,value', [('session_id', 'other'), ('game_date', 1),
                                      ('observer', 'POR'), ('dll_sha256', '00' * 32),
                                      ('physical_client_country', 'FRA'), ('mode', 'historical')])
def test_context_changes_during_read_remove_values(key, value):
    scale = Scale()
    scale.after = {key: value}
    result = NativeWarRelationsSource(scale).read(query(), context())
    assert result['fields']['wars']['status'] == 'unavailable'
    assert 'value' not in result['fields']['wars']


def test_stale_caller_does_not_read():
    scale = Scale()
    caller = context()
    caller['game_date'] = 1
    assert NativeWarRelationsSource(scale).read(query(), caller)['fields']['wars']['status'] == 'unavailable'
    assert scale.calls == []


def test_pair_and_planned_fields_do_not_read():
    scale = Scale()
    source = NativeWarRelationsSource(scale)
    pair = dict(query(), object={'type': 'country_pair', 'actor': 'FRA', 'recipient': 'ENG'})
    assert source.read(pair, context())['fields']['wars']['status'] == 'unsupported'
    assert source.read(query(fields=['truce_until']), context())['fields']['truce_until']['status'] == 'unsupported'
    assert scale.calls == []


@pytest.mark.parametrize('change', [lambda q: q.update(topic='F01'),
                                    lambda q: q.update(parameters={'extra': 1}),
                                    lambda q: q.update(fields=['unknown']),
                                    lambda q: q['object'].update(country='France')])
def test_invalid_query_rejected_without_read(change):
    scale = Scale()
    value = query()
    change(value)
    with pytest.raises(InformationError):
        NativeWarRelationsSource(scale).read(value, context())
    assert scale.calls == []


class Primary:
    def context(self):
        return context()

    def catalog(self):
        return list_topics()


class Rivals(NativeCountryRivalsSource):
    def __init__(self):
        self.calls = []

    def read(self, value, context=None):
        self.calls.append(deepcopy(value))
        return {'fields': {'rivals': {'status': 'known', 'value': ['BUR']}}, 'complete': True}


def test_composite_routes_mixed_fields_to_distinct_owners():
    scale, rivals = Scale(), Rivals()
    source = CompositeSource(Primary(), [rivals, NativeWarRelationsSource(scale)])
    value = query(fields=['rivals', 'wars', 'truce_until'])
    normalized = source.validate_query(value)
    result = source.read(normalized, context())
    assert len(scale.calls) == len(rivals.calls) == 1
    assert rivals.calls[0]['fields'] == ['rivals']
    assert scale.calls[0]['fields'] == ['wars']
    assert result['fields']['rivals']['value'] == ['BUR']
    assert result['fields']['wars']['status'] == 'known'
    assert result['fields']['truce_until']['status'] == 'unsupported'
    assert result['complete'] is False
    topic = next(item for item in source.catalog() if item['topic_id'] == 'R03')
    assert topic['fields']['wars']['coverage'] == 'partial'
    assert topic['fields']['rivals']['coverage'] == 'available'
    assert topic['fields']['wars']['triggers'] == ['query', 'periodic']
    assert 'change' not in topic['triggers']


def test_factory_shares_live_scale_instance_and_excludes_recorded(tmp_path):
    from tools.serve_information import _build_runtime, build_parser

    args = build_parser().parse_args(['--observer', 'FRA', '--database', str(tmp_path / 'live.sqlite')])
    service, journal = _build_runtime(args)
    try:
        assert journal is None
        scale = next(item for item in service.source.adapters if isinstance(item, NativeCountryScaleSource))
        wars = next(item for item in service.source.adapters if isinstance(item, NativeWarRelationsSource))
        assert wars.country_scale_source is scale
    finally:
        service.close()
    archive = tmp_path / 'archive.json'
    archive.write_text('{}', encoding='utf-8')
    args = build_parser().parse_args(['--recorded-manifest', str(archive),
                                      '--database', str(tmp_path / 'recorded.sqlite')])
    service, _ = _build_runtime(args)
    try:
        assert type(service.source).__name__ == 'RecordedSource'
        assert not any(isinstance(item, NativeWarRelationsSource)
                       for item in getattr(service.source, 'adapters', ()))
    finally:
        service.close()
