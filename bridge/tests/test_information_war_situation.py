from copy import deepcopy

import pytest

from bridge.information import InformationService
from bridge.information.composite import CompositeSource
from bridge.information.model import InformationError
from bridge.information.tools import InformationTools
from bridge.information.war_situation import NativeWarSituationSource
from bridge.information.war_territory import NativeWarTerritorySource
from bridge.information.war_forces import NativeWarForcesSource
from bridge.information import war_situation as module
from bridge.tests.test_information_foreign_technology import Base
from bridge.tests.test_information_foreign_technology_capture import make_valid_capture


WAR = 'war_0123456789abcdef_00000001'


def war_query(fields=None):
    return {'topic': 'W03', 'object': {'type': 'war', 'actor': 'FRA', 'recipient': 'ENG'},
            'fields': fields or ['occupations', 'blockades', 'current_forces']}


def source_fixture(tmp_path, monkeypatch, *, allies=('FRA', 'SAV'), opponents=('ENG',), hidden=()):
    _, context, creation, _ = make_valid_capture()

    class WarBase(Base):
        def read(self, query, current):
            assert query['topic'] == 'W01' and query['fields'] == ['war_id', 'participants']
            return {'objects': [dict(query['object'], war_id=WAR)], 'fields': {
                'war_id': {'status': 'known', 'value': WAR},
                'participants': {'status': 'known', 'value': {
                    'source': 'native_war_side_vectors', 'status': 'available', 'complete': True,
                    'side_a': list(allies), 'side_b': list(opponents),
                    'actor_side': 'side_a', 'recipient_side': 'side_b', 'reason': None}}}}

    base = WarBase(tmp_path, context, creation)
    territory = NativeWarTerritorySource(base)
    forces = NativeWarForcesSource(base, None, None)
    calls = []

    def capture(installation, countries, *, fields):
        calls.append((list(countries), list(fields)))
        targets = []
        for country in countries:
            values = {name: {'status': 'known', 'value': {'count': 1}, 'complete': True}
                      for name in fields}
            if 'current_forces' in values:
                values['current_forces']['value'] = {
                    'army_soldiers': {'status': 'known', 'value': 10000},
                    'navy_ships': {'status': 'known', 'value': 10}}
            if country in hidden:
                values = {name: {'status': 'invisible', 'reason': 'NOT_ADMITTED'} for name in fields}
            targets.append({'tag': country, 'fields': {'W03.' + name: value for name, value in values.items()}})
        return {'observation': {'backend': {'targets': targets}}}

    monkeypatch.setattr(module._capture, 'validate_capture', lambda *args: True)
    adapter = NativeWarSituationSource(base, territory, forces, capture=capture)
    return adapter, base, calls


def test_normal_query_groups_war_members_and_returns_selected_identity(tmp_path, monkeypatch):
    adapter, base, calls = source_fixture(tmp_path, monkeypatch)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        api = InformationTools(service)
        public = api.call('information_query', {'request_id': 'war-summary', 'queries': [war_query()]})
        item = public['items'][0]
        assert item['war_id'] == WAR
        assert item['occupations'] == {'our_side': {'FRA': {'count': 1}, 'SAV': {'count': 1}},
                                       'opposing_side': {'ENG': {'count': 1}}}
        full = api.call('information_get_result', {'result_id': public['result_id'], 'view': 'full'})
        assert full['complete'] is True
        assert calls == [(['FRA', 'SAV', 'ENG'], list(module._capture.FIELDS))]
    finally:
        service.close()


def test_batch_limit_preserves_all_countries_and_hidden_values(tmp_path, monkeypatch):
    allies = ('FRA', 'SAV', 'AMG', 'AUV', 'BOU', 'FOI', 'ORL', 'GNV', 'SCO')
    source, _, calls = source_fixture(tmp_path, monkeypatch, allies=allies, hidden=('SCO',))
    result = source.read(war_query(['blockades']))
    assert [len(countries) for countries, _ in calls] == [8, 2]
    assert result['complete'] is False
    values = result['fields']['blockades']['value']
    assert values['our_side']['SCO']['status'] == 'invisible'
    assert values['opposing_side']['ENG']['status'] == 'known'


def test_actor_side_b_is_projected_as_our_side(tmp_path, monkeypatch):
    source, base, calls = source_fixture(tmp_path, monkeypatch)
    original = base.read

    def read(query, context):
        result = original(query, context)
        members = result['fields']['participants']['value']
        members['side_a'], members['side_b'] = members['side_b'], members['side_a']
        members.update(actor_side='side_b', recipient_side='side_a')
        return result

    base.read = read
    result = source.read(war_query(['blockades']))
    assert set(result['fields']['blockades']['value']['our_side']) == {'FRA', 'SAV'}
    assert calls[0][0] == ['FRA', 'SAV', 'ENG']


def test_country_view_reuses_existing_adapters(tmp_path, monkeypatch):
    source, _, calls = source_fixture(tmp_path, monkeypatch)
    own_calls = []

    def read_country(query, current):
        own_calls.append(query)
        return {'fields': {name: {'status': 'known', 'value': 7} for name in query['fields']}}

    source.territory_source.read = read_country
    source.forces_source.read = read_country
    query = war_query() | {'object': {'type': 'country', 'country': 'FRA'}}
    result = source.read(query)
    assert result['complete'] is True
    assert [call['fields'] for call in own_calls] == [['occupations', 'blockades'], ['current_forces']]
    assert calls == []


@pytest.mark.parametrize('status', ['unknown', 'not_applicable'])
def test_unavailable_war_discovery_skips_country_capture(tmp_path, monkeypatch, status):
    source, base, calls = source_fixture(tmp_path, monkeypatch)
    base.read = lambda query, context: {'fields': {
        'war_id': {'status': status, 'reason': 'NO_MATCHING_WAR'},
        'participants': {'status': status, 'reason': 'NO_MATCHING_WAR'}}}
    result = source.read(war_query())
    assert result['complete'] is (status == 'not_applicable')
    assert calls == []


def test_one_failed_batch_preserves_other_countries(tmp_path, monkeypatch):
    allies = ('FRA', 'SAV', 'AMG', 'AUV', 'BOU', 'FOI', 'ORL', 'GNV', 'SCO')
    source, _, calls = source_fixture(tmp_path, monkeypatch, allies=allies)
    original = source.capture

    def capture(installation, countries, *, fields):
        if 'SCO' in countries:
            raise OSError('fixture capture failure')
        return original(installation, countries, fields=fields)

    source.capture = capture
    result = source.read(war_query(['blockades']))
    assert result['complete'] is False
    values = result['fields']['blockades']['value']
    assert values['our_side']['FRA']['status'] == 'known'
    assert values['our_side']['SCO']['status'] == 'unknown'


@pytest.mark.parametrize('obj', [
    {'type': 'war', 'war_id': WAR},
    {'type': 'war', 'actor': 'ENG', 'recipient': 'FRA'},
    {'type': 'war', 'actor': 'FRA', 'recipient': 'FRA'},
])
def test_unsupported_war_selectors_fail_before_capture(tmp_path, monkeypatch, obj):
    source, _, calls = source_fixture(tmp_path, monkeypatch)
    with pytest.raises(InformationError):
        source.validate_query(war_query() | {'object': obj})
    assert calls == []


def test_force_change_reuses_persisted_current_sizes_and_only_captures_once(tmp_path, monkeypatch):
    adapter, base, calls = source_fixture(tmp_path, monkeypatch)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    adapter.force_history = service.previous_war_forces
    try:
        api = InformationTools(service)
        first = api.call('information_query', {'request_id': 'before',
            'queries': [war_query(['current_forces'])]})
        original = adapter.capture

        def changed(installation, countries, *, fields):
            result = original(installation, countries, fields=fields)
            for target in result['observation']['backend']['targets']:
                sizes = target['fields']['W03.current_forces']['value']
                sizes['army_soldiers']['value'] = 12000 if target['tag'] == 'FRA' else 8000
            return result

        adapter.capture = changed
        base.current['game_date'] += 24
        result = api.call('information_query', {'request_id': 'after',
            'queries': [war_query(['current_forces', 'reinforcement_change'])]})
        item = result['items'][0]
        assert set(item) == {'actor', 'recipient', 'war_id', 'current_forces', 'force_change'}
        change = item['force_change']
        from bridge.information.engine_dates import project_engine_date
        assert change['to_date'] == project_engine_date(base.current['game_date'])['date']
        assert change['net_change']['our_side']['FRA'] == {'army_soldiers': 2000, 'navy_ships': 0}
        assert change['net_change']['opposing_side']['ENG']['army_soldiers'] == -2000
        full = service.get_result(result['result_id'])
        assert full['complete'] is True
        assert full['items'][0]['fields']['reinforcement_change']['baseline_result_id'] == first['result_id']
        assert len(calls) == 2 and all(fields == ['current_forces'] for _, fields in calls)
    finally:
        service.close()


def test_change_only_first_read_stores_snapshot_and_survives_reopen(tmp_path, monkeypatch):
    adapter, base, calls = source_fixture(tmp_path, monkeypatch)
    database = tmp_path / 'information.sqlite3'
    source = CompositeSource(base, [adapter])
    service = InformationService(source, database)
    adapter.force_history = service.previous_war_forces
    first = service.query('first-change', [war_query(['reinforcement_change'])])
    assert first['items'][0]['fields']['reinforcement_change']['reason'] == 'FORCE_COMPARISON_BASELINE_MISSING'
    assert set(first['items'][0]['fields']) == {'reinforcement_change'}
    service.close()
    service = InformationService(source, database)
    adapter.force_history = service.previous_war_forces
    try:
        second = InformationTools(service).call('information_query', {'request_id': 'second-change',
            'queries': [war_query(['reinforcement_change'])]})
        assert second['items'][0]['force_change']['net_change']['our_side']['FRA']['army_soldiers'] == 0
        assert service.get_result(second['result_id'])['complete'] is True
        assert len(calls) == 2
    finally:
        service.close()


@pytest.mark.parametrize('mismatch', ['session_id', 'observer', 'world_id', 'game_version', 'country', 'war_id', 'future', 'owner'])
def test_force_history_ignores_other_identity_object_and_future(tmp_path, monkeypatch, mismatch):
    adapter, base, _ = source_fixture(tmp_path, monkeypatch)
    service = InformationService(CompositeSource(base, [adapter]), tmp_path / 'information.sqlite3')
    try:
        service.query('baseline', [war_query(['current_forces'])])
        context = base.context()
        obj = dict(war_query()['object'], war_id=WAR)
        if mismatch in {'session_id', 'observer', 'world_id', 'game_version'}:
            context[mismatch] = 'different'
        elif mismatch == 'country':
            obj = {'type': 'country', 'country': 'FRA'}
        elif mismatch == 'war_id':
            obj['war_id'] = WAR[:-1] + '2'
        elif mismatch == 'future':
            context['game_date'] -= 24
        else:
            service.owner = 'other'
        assert service.previous_war_forces(context, obj) is None
    finally:
        service.close()


def test_force_change_preserves_missing_new_member_and_metric_units():
    from bridge.information.war_force_change import project_force_change
    before = {'status': 'known', 'value': {'our_side': {
        'FRA': {'status': 'known', 'value': {'army_regiments': {'status': 'known', 'value': 10}}}}}}
    current = {'status': 'known', 'value': {'our_side': {
        'FRA': {'status': 'known', 'value': {'army_soldiers': {'status': 'known', 'value': 10000}}},
        'SAV': {'status': 'known', 'value': {'navy_ships': {'status': 'known', 'value': 2}}}}}}
    result = project_force_change(current,
        {'field': before, 'result_id': 'before', 'context': {'game_date': 1}}, {'game_date': 2})
    assert result['status'] == 'known' and result['complete'] is False
    assert result['value']['net_change']['our_side']['FRA']['value']['army_soldiers']['status'] == 'unknown'
    assert result['value']['net_change']['our_side']['SAV']['status'] == 'unknown'


def test_country_change_keeps_read_failures_and_partial_values():
    from bridge.information.war_force_change import project_force_change
    before = {'status': 'known', 'value': {
        'army_regiments': {'status': 'known', 'value': 56},
        'navy_ships': {'status': 'known', 'value': 22}}}
    current = {'status': 'known', 'value': {
        'army_regiments': {'status': 'unknown', 'reason': 'READ_FAILED'},
        'navy_ships': {'status': 'known', 'value': 21}}}
    result = project_force_change(current,
        {'field': before, 'result_id': 'before', 'context': {'game_date': 56682672}},
        {'game_date': 56682696})
    assert result['complete'] is False
    assert result['value']['from_date'] == '1470.8.17'
    assert result['value']['to_date'] == '1470.8.18'
    assert result['value']['net_change']['army_regiments']['reason'] == 'READ_FAILED'
    assert result['value']['net_change']['navy_ships']['value'] == -1
    failure = {'status': 'unavailable', 'reason': 'CAPTURE_FAILED'}
    assert project_force_change(failure, None, {}) == failure
